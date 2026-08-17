#include "dumper.hpp"
#include "dump_control.hpp"
#include "pe/section_name.hpp"
#include "recovery/section_recovery.hpp"

#include <limits>

using namespace vulkan;
using namespace vulkan::pe;

namespace
{
  template <typename T>
  bool ReadRemoteArray(std::uintptr_t address, std::vector<T> &out, std::size_t count)
  {
    if ( count > std::numeric_limits<std::size_t>::max() / sizeof(T) )
      return false;

    out.resize(count);
    if ( out.empty() )
      return true;

    return Mem::ReadProcessMemory(address, out.data(), out.size() * sizeof(T));
  }

  bool ModuleRangeContains(const Mem::ModuleInfo_t &module, std::uint32_t rva, std::size_t size)
  {
    return module.base && module.size <= std::numeric_limits<std::uintptr_t>::max() - module.base &&
      rva <= module.size && size <= module.size - rva;
  }

  int ImportScanPriority(const IMAGE_SECTION_HEADER &section)
  {
    const auto name = section_name(section);
    if ( name == ".idata" )
      return 0;
    if ( name == ".rdata" || name == "_RDATA" )
      return 1;
    if ( name == ".data" )
      return 2;
    if ( name == ".vulkan" || name == ".rsrc" || name == ".reloc" || name == ".pdata" )
      return 100;
    return 10;
  }

  bool ShouldScanForImportSlots(const IMAGE_SECTION_HEADER &section)
  {
    if ( !section.PointerToRawData || !section.SizeOfRawData )
      return false;

    if ( section.Characteristics & IMAGE_SCN_CNT_CODE )
      return false;

    return ImportScanPriority(section) < 100;
  }

  bool ReadRemoteString(std::uintptr_t address, std::size_t max_length, std::string &out)
  {
    std::string value;
    value.reserve(std::min<std::size_t>(64, max_length));

    for ( std::size_t i = 0; i < max_length; ++i )
    {
      char c = '\0';
      if ( i > std::numeric_limits<std::uintptr_t>::max() - address ||
        !Mem::ReadProcessMemory(address + i, &c, sizeof(c)) )
        return false;

      if ( c == '\0' )
      {
        out = std::move(value);
        return true;
      }

      value.push_back(c);
    }

    return false;
  }

  bool NarrowModuleName(std::wstring_view value, std::string &out)
  {
    if ( value.empty() || value.size() > (std::size_t)INT_MAX )
      return false;

    BOOL used_default_character = FALSE;
    const auto required = ::WideCharToMultiByte(
      CP_ACP,
      WC_NO_BEST_FIT_CHARS,
      value.data(),
      (int)value.size(),
      nullptr,
      0,
      nullptr,
      &used_default_character);
    if ( required <= 0 || used_default_character )
      return false;

    std::string converted((std::size_t)required, '\0');
    used_default_character = FALSE;
    if ( !::WideCharToMultiByte(
      CP_ACP,
      WC_NO_BEST_FIT_CHARS,
      value.data(),
      (int)value.size(),
      converted.data(),
      required,
      nullptr,
      &used_default_character) || used_default_character || converted.find('\0') != std::string::npos )
      return false;

    out = std::move(converted);
    return true;
  }

  bool IsValidUnwindInfo(const std::vector<std::uint8_t> &buffer, std::uint32_t offset)
  {
    constexpr std::size_t fixed_header_size = 4;
    constexpr std::uint8_t handler_flags = 0x03;
    constexpr std::uint8_t chain_info_flag = 0x04;

    if ( offset > buffer.size() || fixed_header_size > buffer.size() - offset )
      return false;

    const auto version = buffer[offset] & 0x07;
    const auto flags = buffer[offset] >> 3;
    if ( (version != 1 && version != 2) ||
      ((flags & chain_info_flag) && (flags & handler_flags)) )
      return false;

    const auto code_count = (std::size_t)buffer[offset + 2];
    const auto code_bytes = code_count * 2;
    const auto unaligned_size = fixed_header_size + code_bytes;
    const auto aligned_size = (unaligned_size + 3) & ~(std::size_t)3;

    std::size_t payload_size = 0;
    if ( flags & chain_info_flag )
      payload_size = sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
    else if ( flags & handler_flags )
      payload_size = sizeof(std::uint32_t);

    return aligned_size <= buffer.size() - offset &&
      payload_size <= buffer.size() - offset - aligned_size;
  }
}

Dumper::Dumper(HMODULE module)
{
  _image = image::create(module);
  if ( !_image )
    Util::Log("[DUMPER] Failed to create PE image for module {:X}", module);
}

std::size_t Dumper::import_patch_stats_t::total() const noexcept
{
  return rip_indirect_call + rip_indirect_jump + rip_indirect_push + rip_load + rip_lea + rip_compare + absolute_load;
}

std::vector<Dumper::import_candidate_t> Dumper::collect_import_candidates(const std::vector<Mem::ModuleInfo_t> &modules) const
{
  std::vector< import_candidate_t > imports;
  std::unordered_map< std::uintptr_t, export_entry_t > export_map;

  for ( const auto &module : modules )
  {
    if ( !module.base )
      continue;

    std::string module_name;
    if ( !NarrowModuleName(module.name, module_name) )
      continue;

    const auto dos = Mem::Read<IMAGE_DOS_HEADER>(module.base);
    if ( dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0 ||
      !ModuleRangeContains(module, (std::uint32_t)dos.e_lfanew, sizeof(IMAGE_NT_HEADERS)) )
      continue;

    const auto nt_headers = Mem::Read<IMAGE_NT_HEADERS>(module.base + (std::uintptr_t)dos.e_lfanew);
    if ( nt_headers.Signature != IMAGE_NT_SIGNATURE || nt_headers.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC )
      continue;

    const auto &directory = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if ( !directory.VirtualAddress || !directory.Size ||
      !ModuleRangeContains(module, directory.VirtualAddress, directory.Size) ||
      !ModuleRangeContains(module, directory.VirtualAddress, sizeof(IMAGE_EXPORT_DIRECTORY)) )
      continue;

    const auto export_directory = Mem::Read<IMAGE_EXPORT_DIRECTORY>(module.base + directory.VirtualAddress);
    if ( !export_directory.NumberOfNames || !export_directory.NumberOfFunctions ||
      !ModuleRangeContains(module, export_directory.AddressOfNames,
        (std::size_t)export_directory.NumberOfNames * sizeof(std::uint32_t)) ||
      !ModuleRangeContains(module, export_directory.AddressOfNameOrdinals,
        (std::size_t)export_directory.NumberOfNames * sizeof(std::uint16_t)) ||
      !ModuleRangeContains(module, export_directory.AddressOfFunctions,
        (std::size_t)export_directory.NumberOfFunctions * sizeof(std::uint32_t)) )
      continue;

    std::vector<std::uint32_t> names;
    std::vector<std::uint16_t> ordinals;
    std::vector<std::uint32_t> functions;

    if ( !ReadRemoteArray(module.base + export_directory.AddressOfNames, names, export_directory.NumberOfNames) ||
      !ReadRemoteArray(module.base + export_directory.AddressOfNameOrdinals, ordinals, export_directory.NumberOfNames) ||
      !ReadRemoteArray(module.base + export_directory.AddressOfFunctions, functions, export_directory.NumberOfFunctions) )
      continue;

    for ( std::uint32_t i = 0; i < export_directory.NumberOfNames; ++i )
    {
      const auto ordinal_index = ordinals[i];
      if ( ordinal_index >= functions.size() )
        continue;

      const auto function_rva = functions[ordinal_index];

      // Forwarded exports point back into the export directory and cannot be used as an IAT target.
      if ( function_rva >= directory.VirtualAddress && function_rva - directory.VirtualAddress < directory.Size )
        continue;

      if ( !ModuleRangeContains(module, function_rva, 1) || !ModuleRangeContains(module, names[i], 1) )
        continue;

      export_entry_t entry{};
      entry.module_name = module_name;
      if ( !ReadRemoteString(
        module.base + names[i],
        std::min<std::size_t>(512, module.size - names[i]),
        entry.name) || entry.name.empty() )
        continue;

      export_map[module.base + function_rva] = std::move(entry);
    }
  }

  std::vector<IMAGE_SECTION_HEADER *> scan_sections;
  for ( std::size_t idx = 0; idx < _image->section_headers()->count(); ++idx )
  {
    const auto section = _image->section_headers()->at(static_cast<std::uint16_t>(idx));
    if ( ShouldScanForImportSlots(*section) )
      scan_sections.push_back(section);
  }

  std::sort(scan_sections.begin(), scan_sections.end(), [](const auto *lhs, const auto *rhs)
  {
    const auto lhs_priority = ImportScanPriority(*lhs);
    const auto rhs_priority = ImportScanPriority(*rhs);
    if ( lhs_priority != rhs_priority )
      return lhs_priority < rhs_priority;

    return lhs->VirtualAddress < rhs->VirtualAddress;
  });

  std::unordered_set< std::uintptr_t > seen;
  const auto runtime_image_base = Mem::base;
  const auto image_size = _image->buffer().size();

  for ( const auto *section : scan_sections )
  {
    const auto start = static_cast<std::size_t>(section->PointerToRawData);
    if ( start >= _image->buffer().size() )
      continue;

    const auto available = _image->buffer().size() - start;
    const auto size = std::min<std::size_t>(section->SizeOfRawData, available);
    const auto data = _image->buffer().data() + start;

    for ( std::size_t offset = 0; offset + sizeof(std::uintptr_t) <= size; offset += sizeof(std::uintptr_t) )
    {
      std::uintptr_t address = 0;
      std::memcpy(&address, data + offset, sizeof(address));

      if ( !address || (runtime_image_base <= std::numeric_limits<std::uintptr_t>::max() - image_size &&
        address >= runtime_image_base && address - runtime_image_base < image_size) )
        continue;

      const auto export_it = export_map.find(address);
      if ( offset > UINT32_MAX - section->VirtualAddress )
        continue;

      const auto slot_rva = (std::uint32_t)(section->VirtualAddress + offset);
      if ( export_it == export_map.end() || !seen.insert(slot_rva).second )
        continue;

      imports.push_back({ slot_rva, export_it->second });
    }
  }

  return imports;
}

std::unique_ptr<image> Dumper::dump()
{
  auto d = std::unique_ptr<Dumper>(new Dumper((HMODULE)Mem::base));
  if ( !d->_image || !d->_image->is_valid() )
  {
    Util::Log("[DUMPER] Cannot dump invalid image");
    return nullptr;
  }

  d->resolve_sections();

  const auto loaded_modules = Mem::GetLoadedModules();
  if ( !d->resolve_imports(loaded_modules) )
  {
    Util::Log("[DUMPER] Import reconstruction failed");
    return nullptr;
  }

  d->resolve_runtime_functions();

  // Refresh the image one last time. This also recalculates the checksum.
  if ( !d->_image->refresh() )
  {
    Util::Log("[DUMPER] Final image validation failed");
    return nullptr;
  }

  return std::move(d->_image);
}

void Dumper::resolve_sections()
{
  vulkan::recovery::partial_dump_store_t partial_store(
    DumpControl::recovery_options.use_partial_store ? DumpControl::recovery_options.partial_store_path : std::string{});

  for ( std::size_t idx = 0; idx < _image->section_headers()->count(); ++idx )
  {
    const auto header = _image->section_headers()->at((std::uint16_t)idx);

    // Skip sections that cannot be represented safely in the output buffer.
    if ( !header->PointerToRawData || !header->SizeOfRawData ||
      header->PointerToRawData > _image->buffer().size() ||
      header->SizeOfRawData > _image->buffer().size() - header->PointerToRawData )
      continue;

    const auto name = section_name(*header);
    if ( name == ".rodata" )
    {
      Util::Log("Skipping section: \"{}\"", name);
      continue;
    }

    if ( header->VirtualAddress > std::numeric_limits<std::uintptr_t>::max() - Mem::base )
      continue;

    const auto absolute_address = Mem::base + header->VirtualAddress;

    Util::Log("Resolving section: \"{}\" @ 0x{:X} - {} bytes", name, absolute_address, header->Misc.VirtualSize);

    const auto make_section_identity = [&]()
    {
      vulkan::recovery::section_identity_t section_identity{};
      section_identity.image_base = Mem::base;
      section_identity.section_rva = header->VirtualAddress;
      section_identity.raw_size = header->SizeOfRawData;
      section_identity.name = name;
      return section_identity;
    };

    if ( header->Characteristics & IMAGE_SCN_CNT_CODE )
    {
      std::fill(
        _image->buffer().begin() + header->PointerToRawData,
        _image->buffer().begin() + header->PointerToRawData + header->SizeOfRawData,
        std::uint8_t{ 0x90 });

      vulkan::recovery::section_recovery_t recovery(
        make_section_identity(),
        absolute_address,
        header->PointerToRawData,
        header->SizeOfRawData,
        _image->buffer(),
        partial_store.enabled() ? &partial_store : nullptr);

      std::uint32_t stalled_passes = 0;
      recovery.log_progress(true);

      while ( !recovery.complete() && !recovery.reached_target_coverage() && !DumpControl::should_stop() )
      {
        if ( !Mem::IsProcessRunning() )
        {
          Util::Log("Stopping section \"{}\": target process exited", name);
          break;
        }

        const auto made_progress = recovery.copy_once(true);
        if ( made_progress )
        {
          stalled_passes = 0;
          continue;
        }

        if ( stalled_passes != UINT32_MAX )
          ++stalled_passes;

        if ( stalled_passes == 1 || stalled_passes % 10 == 0 )
        {
          Util::Log(
            "Waiting for more readable pages in \"{}\" ({}%, stalled passes={})",
            name,
            recovery.percent(),
            stalled_passes);
        }

        if ( DumpControl::recovery_options.max_stalled_passes != 0 && stalled_passes >= DumpControl::recovery_options.max_stalled_passes )
        {
          Util::Log(
            "Stopping section \"{}\" after {} stalled passes",
            name,
            stalled_passes);
          break;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(DumpControl::recovery_options.retry_delay_ms));
      }

      recovery.log_final();
    }
    else
    {
      std::fill(
        _image->buffer().begin() + header->PointerToRawData,
        _image->buffer().begin() + header->PointerToRawData + header->SizeOfRawData,
        std::uint8_t{ 0x00 });

      vulkan::recovery::section_recovery_t recovery(
        make_section_identity(),
        absolute_address,
        header->PointerToRawData,
        header->SizeOfRawData,
        _image->buffer(),
        nullptr);

      recovery.copy_once(false);
      recovery.log_final();
    }
  }

  Util::Log("Resolved all sections");
}


std::unordered_map<std::uint32_t, std::uint32_t> Dumper::rebuild_import_directory(const std::vector<import_candidate_t> &imports)
{
  struct sorted_import_t
  {
    std::string module_name;
    const import_candidate_t *candidate = nullptr;
  };

  std::vector<sorted_import_t> sorted_imports;
  sorted_imports.reserve(imports.size());

  for ( const auto &candidate : imports )
  {
    auto &entry = sorted_imports.emplace_back();
    entry.candidate = &candidate;
    entry.module_name = candidate.export_entry.module_name;
  }

  std::stable_sort(sorted_imports.begin(), sorted_imports.end(), [](const sorted_import_t &lhs, const sorted_import_t &rhs)
  {
    if ( lhs.module_name != rhs.module_name )
      return lhs.module_name < rhs.module_name;

    if ( lhs.candidate->export_entry.name != rhs.candidate->export_entry.name )
      return lhs.candidate->export_entry.name < rhs.candidate->export_entry.name;

    return lhs.candidate->slot_rva < rhs.candidate->slot_rva;
  });

  _image->import_directory()->clear();

  for ( const auto &entry : sorted_imports )
    _image->import_directory()->add(entry.module_name, entry.candidate->export_entry.name, 0);

  Util::Log("Recompiling {} imports into .vulkan", imports.size());
  if ( !_image->import_directory()->recompile(_image.get(), ".vulkan") )
  {
    Util::Log("Failed to rebuild import directory");
    return {};
  }

  _image->import_directory()->clear();
  if ( !_image->refresh() )
  {
    Util::Log("Rebuilt image failed validation");
    return {};
  }

  std::unordered_map<std::uint32_t, std::uint32_t> iat_map;
  const auto rebuilt_imports = _image->import_directory()->imports();
  if ( rebuilt_imports.size() != sorted_imports.size() )
  {
    Util::Log(
      "Rebuilt import count mismatch: expected {}, parsed {}",
      sorted_imports.size(),
      rebuilt_imports.size());
    return {};
  }

  for ( std::size_t index = 0; index < sorted_imports.size(); ++index )
  {
    if ( rebuilt_imports[index].module_name != sorted_imports[index].module_name ||
      rebuilt_imports[index].import_name != sorted_imports[index].candidate->export_entry.name )
    {
      Util::Log("Rebuilt import ordering mismatch at index {}", index);
      return {};
    }

    if ( rebuilt_imports[index].iat_rva > UINT32_MAX )
    {
      Util::Log("Rebuilt IAT RVA exceeds 32-bit range at index {}", index);
      return {};
    }

    iat_map[sorted_imports[index].candidate->slot_rva] = (std::uint32_t)rebuilt_imports[index].iat_rva;
  }

  return iat_map;
}

Dumper::import_patch_stats_t Dumper::patch_import_references(const std::unordered_map<std::uint32_t, std::uint32_t> &iat_map)
{
  struct patch_result_t
  {
    bool matched = false;
    bool patched = false;
    std::uint32_t length = 1;
  };

  import_patch_stats_t stats{};


  const auto is_rex_prefix = [](std::uint8_t value) -> bool
  {
    return value >= 0x40 && value <= 0x4F;
  };

  const auto is_rip_relative_modrm = [](std::uint8_t modrm) -> bool
  {
    return (modrm & 0xC7) == 0x05;
  };

  const auto slot_points_to_import = [&](std::uint32_t slot_rva, std::uint32_t &new_iat_rva) -> bool
  {
    const auto iat_it = iat_map.find(slot_rva);
    if ( iat_it == iat_map.end() )
      return false;

    new_iat_rva = iat_it->second;
    return true;
  };

  const auto patch_rip_relative_slot = [&](std::uint32_t instruction_rva, std::uint32_t instruction_offset, std::uint32_t displacement_offset, std::uint32_t instruction_size) -> bool
  {
    if ( instruction_offset > _image->buffer().size() ||
      displacement_offset > _image->buffer().size() - instruction_offset ||
      sizeof(std::int32_t) > _image->buffer().size() - instruction_offset - displacement_offset )
      return false;

    std::int32_t displacement = 0;
    auto *operand = _image->buffer().data() + instruction_offset + displacement_offset;
    std::memcpy(&displacement, operand, sizeof(displacement));

    const auto next_instruction_rva = (std::int64_t)instruction_rva + instruction_size;
    const auto slot = next_instruction_rva + displacement;
    if ( slot < 0 || slot > UINT32_MAX )
      return false;

    std::uint32_t new_iat_rva = 0;
    if ( !slot_points_to_import((std::uint32_t)slot, new_iat_rva) )
      return false;

    const auto new_displacement = (std::int64_t)new_iat_rva - next_instruction_rva;
    if ( new_displacement < INT32_MIN || new_displacement > INT32_MAX )
      return false;

    const auto encoded_displacement = (std::int32_t)new_displacement;
    std::memcpy(operand, &encoded_displacement, sizeof(encoded_displacement));
    return true;
  };

  const auto patch_absolute_slot = [&](std::uint32_t instruction_offset, std::uint32_t immediate_offset) -> bool
  {
    if ( instruction_offset > _image->buffer().size() ||
      immediate_offset > _image->buffer().size() - instruction_offset ||
      sizeof(std::uint64_t) > _image->buffer().size() - instruction_offset - immediate_offset )
      return false;

    auto *operand = _image->buffer().data() + instruction_offset + immediate_offset;
    std::uint64_t absolute_slot = 0;
    std::memcpy(&absolute_slot, operand, sizeof(absolute_slot));

    const auto runtime_base = (std::uint64_t)Mem::base;
    if ( absolute_slot < runtime_base )
      return false;

    const auto old_slot_rva = absolute_slot - runtime_base;
    if ( old_slot_rva > UINT32_MAX )
      return false;

    std::uint32_t new_iat_rva = 0;
    if ( !slot_points_to_import((std::uint32_t)old_slot_rva, new_iat_rva) )
      return false;

    const auto preferred_base = (std::uint64_t)_image->image_base();
    if ( new_iat_rva > std::numeric_limits<std::uint64_t>::max() - preferred_base )
      return false;

    const auto patched_slot = preferred_base + new_iat_rva;
    std::memcpy(operand, &patched_slot, sizeof(patched_slot));
    return true;
  };

  const auto match_and_patch = [&](const std::uint8_t *data, std::size_t size, std::size_t offset, std::uint32_t instruction_rva, std::uint32_t instruction_offset) -> patch_result_t
  {
    const auto remaining = size - offset;
    const auto bytes = data + offset;

    if ( remaining >= 6 && bytes[0] == 0xFF )
    {
      switch ( bytes[1] )
      {
        case 0x15: return { true, patch_rip_relative_slot(instruction_rva, instruction_offset, 2, 6), 6 };
        case 0x25: return { true, patch_rip_relative_slot(instruction_rva, instruction_offset, 2, 6), 6 };
        case 0x35: return { true, patch_rip_relative_slot(instruction_rva, instruction_offset, 2, 6), 6 };
        default: break;
      }
    }

    if ( remaining >= 7 && is_rex_prefix(bytes[0]) )
    {
      const auto opcode = bytes[1];
      const auto modrm = bytes[2];

      if ( is_rip_relative_modrm(modrm) )
      {
        switch ( opcode )
        {
          case 0x8B:
          case 0x8D:
          case 0x3B:
          case 0x85:
            return { true, patch_rip_relative_slot(instruction_rva, instruction_offset, 3, 7), 7 };
          default:
            break;
        }
      }

      if ( opcode == 0xFF && (modrm == 0x15 || modrm == 0x25) )
        return { true, patch_rip_relative_slot(instruction_rva, instruction_offset, 3, 7), 7 };

      if ( opcode == 0x83 && modrm == 0x3D && remaining >= 8 )
        return { true, patch_rip_relative_slot(instruction_rva, instruction_offset, 3, 8), 8 };

      if ( opcode == 0x81 && modrm == 0x3D && remaining >= 11 )
        return { true, patch_rip_relative_slot(instruction_rva, instruction_offset, 3, 11), 11 };
    }

    if ( remaining >= 10 && bytes[0] == 0x48 && bytes[1] == 0xA1 )
      return { true, patch_absolute_slot(instruction_offset, 2), 10 };

    return {};
  };

  for ( std::size_t idx = 0; idx < _image->section_headers()->count(); ++idx )
  {
    const auto section = _image->section_headers()->at(static_cast<std::uint16_t>(idx));
    if ( !(section->Characteristics & IMAGE_SCN_CNT_CODE) || !section->PointerToRawData || !section->SizeOfRawData )
      continue;

    const auto start = static_cast<std::size_t>(section->PointerToRawData);
    if ( start >= _image->buffer().size() )
      continue;

    const auto size = std::min<std::size_t>(section->SizeOfRawData, _image->buffer().size() - start);
    const auto data = _image->buffer().data() + start;

    for ( std::size_t offset = 0; offset < size; ++offset )
    {
      if ( offset > UINT32_MAX - section->VirtualAddress || start > UINT32_MAX - offset )
        break;

      const auto instruction_rva = (std::uint32_t)(section->VirtualAddress + offset);
      const auto instruction_offset = (std::uint32_t)(start + offset);
      const auto result = match_and_patch(data, size, offset, instruction_rva, instruction_offset);

      if ( !result.matched )
        continue;

      if ( result.patched )
      {
        const auto *bytes = data + offset;
        if ( (bytes[0] == 0xFF && bytes[1] == 0x15) || (is_rex_prefix(bytes[0]) && bytes[1] == 0xFF && bytes[2] == 0x15) )
          ++stats.rip_indirect_call;
        else if ( (bytes[0] == 0xFF && bytes[1] == 0x25) || (is_rex_prefix(bytes[0]) && bytes[1] == 0xFF && bytes[2] == 0x25) )
          ++stats.rip_indirect_jump;
        else if ( bytes[0] == 0xFF && bytes[1] == 0x35 )
          ++stats.rip_indirect_push;
        else if ( is_rex_prefix(bytes[0]) && bytes[1] == 0x8B )
          ++stats.rip_load;
        else if ( is_rex_prefix(bytes[0]) && bytes[1] == 0x8D )
          ++stats.rip_lea;
        else if ( is_rex_prefix(bytes[0]) && (bytes[1] == 0x3B || bytes[1] == 0x85 || bytes[1] == 0x83 || bytes[1] == 0x81) )
          ++stats.rip_compare;
        else if ( bytes[0] == 0x48 && bytes[1] == 0xA1 )
          ++stats.absolute_load;
      }

      offset += result.length - 1;
    }
  }

  return stats;
}

bool Dumper::resolve_imports(const std::vector<Mem::ModuleInfo_t> &modules)
{
  Util::Log("Resolving import directory: \".vulkan\"");
  if ( !_image->refresh() )
  {
    Util::Log("Cannot resolve imports for an invalid image");
    return false;
  }

  const auto imports = collect_import_candidates(modules);
  if ( imports.empty() )
  {
    Util::Log("No import candidates found");
    return true;
  }

  const auto iat_map = rebuild_import_directory(imports);
  Util::Log("Collected {} import candidates and rebuilt {} IAT entries", imports.size(), iat_map.size());
  if ( iat_map.empty() )
    return false;

  const auto stats = patch_import_references(iat_map);
  Util::Log(
    "Patched {} import references (call={}, jmp={}, push={}, load={}, lea={}, cmp={}, abs={})",
    stats.total(),
    stats.rip_indirect_call,
    stats.rip_indirect_jump,
    stats.rip_indirect_push,
    stats.rip_load,
    stats.rip_lea,
    stats.rip_compare,
    stats.absolute_load);
  return true;
}

void Dumper::resolve_runtime_functions()
{
  const auto exception_directory = _image->data_directory(IMAGE_DIRECTORY_ENTRY_EXCEPTION);
  if ( !exception_directory || !exception_directory->VirtualAddress || !exception_directory->Size )
    return;

  std::uint32_t directory_offset = 0;
  if ( !_image->try_rva_to_offset(exception_directory->VirtualAddress, directory_offset) ||
    directory_offset > _image->buffer().size() ||
    exception_directory->Size > _image->buffer().size() - directory_offset )
  {
    Util::Log("Discarding invalid exception directory");
    exception_directory->VirtualAddress = 0;
    exception_directory->Size = 0;
    return;
  }

  const auto entry_count = exception_directory->Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
  std::vector<IMAGE_RUNTIME_FUNCTION_ENTRY> valid_entries;
  valid_entries.reserve(entry_count);

  for ( std::size_t index = 0; index < entry_count; ++index )
  {
    IMAGE_RUNTIME_FUNCTION_ENTRY entry{};
    std::memcpy(
      &entry,
      _image->buffer().data() + directory_offset + index * sizeof(entry),
      sizeof(entry));

    if ( !entry.BeginAddress || entry.BeginAddress >= entry.EndAddress ||
      !entry.UnwindInfoAddress || entry.UnwindInfoAddress % 4 != 0 )
      continue;

    std::uint32_t begin_offset = 0;
    std::uint32_t end_offset = 0;
    std::uint32_t unwind_offset = 0;
    if ( !_image->try_rva_to_offset(entry.BeginAddress, begin_offset) ||
      !_image->try_rva_to_offset(entry.EndAddress - 1, end_offset) ||
      !_image->try_rva_to_offset(entry.UnwindInfoAddress, unwind_offset) ||
      unwind_offset >= _image->buffer().size() )
      continue;

    if ( !IsValidUnwindInfo(_image->buffer(), unwind_offset) )
      continue;

    valid_entries.push_back(entry);
  }

  std::stable_sort(valid_entries.begin(), valid_entries.end(), [](const auto &lhs, const auto &rhs)
  {
    return lhs.BeginAddress < rhs.BeginAddress;
  });

  const auto valid_size = valid_entries.size() * sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
  if ( valid_size )
    std::memcpy(_image->buffer().data() + directory_offset, valid_entries.data(), valid_size);

  std::fill(
    _image->buffer().begin() + directory_offset + valid_size,
    _image->buffer().begin() + directory_offset + exception_directory->Size,
    std::uint8_t{ 0 });

  if ( valid_entries.size() != entry_count )
    Util::Log("Removed {} invalid runtime-function entries", entry_count - valid_entries.size());

  exception_directory->Size = (DWORD)valid_size;
}
