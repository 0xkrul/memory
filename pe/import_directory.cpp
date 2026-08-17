#include "import_directory.hpp"
#include "image.hpp"

#include <algorithm>
#include <cstring>
#include <limits>

namespace vulkan::pe
{
  namespace
  {
    bool contains_range(std::size_t buffer_size, std::size_t offset, std::size_t size) noexcept
    {
      return offset <= buffer_size && size <= buffer_size - offset;
    }

    bool checked_add(std::size_t lhs, std::size_t rhs, std::size_t &result) noexcept
    {
      if ( lhs > std::numeric_limits<std::size_t>::max() - rhs )
        return false;
      result = lhs + rhs;
      return true;
    }

    bool checked_multiply(std::size_t lhs, std::size_t rhs, std::size_t &result) noexcept
    {
      if ( lhs && rhs > std::numeric_limits<std::size_t>::max() / lhs )
        return false;
      result = lhs * rhs;
      return true;
    }

    bool align_offset(std::size_t value, std::size_t alignment, std::size_t &result) noexcept
    {
      if ( !alignment )
        return false;

      const auto remainder = value % alignment;
      return remainder == 0 ? (result = value, true) : checked_add(value, alignment - remainder, result);
    }

    bool bounded_string_view(
      const std::vector< std::uint8_t > &buffer, std::size_t offset, std::string_view &value) noexcept
    {
      if ( offset >= buffer.size() )
        return false;

      const auto begin = reinterpret_cast<const char *>(buffer.data() + offset);
      const auto terminator = static_cast<const char *>(std::memchr(begin, '\0', buffer.size() - offset));
      if ( !terminator )
        return false;

      value = std::string_view(begin, static_cast<std::size_t>(terminator - begin));
      return true;
    }
  }

  import_directory::import_directory() noexcept
  {
  }

  void import_directory::refresh(image *img)
  {
    _imports.clear();
    _import_data_directory = img ? img->data_directory(IMAGE_DIRECTORY_ENTRY_IMPORT) : nullptr;
    _iat_data_directory = img ? img->data_directory(IMAGE_DIRECTORY_ENTRY_IAT) : nullptr;

    if ( !img || !_import_data_directory || !_import_data_directory->VirtualAddress || !_import_data_directory->Size )
      return;

    const auto &buffer = img->buffer();
    std::uint32_t import_offset = 0;
    if ( !img->try_rva_to_offset(_import_data_directory->VirtualAddress, import_offset) ||
      !contains_range(buffer.size(), import_offset, _import_data_directory->Size) )
      return;

    const auto import_end = static_cast<std::size_t>(import_offset) + _import_data_directory->Size;
    auto descriptor_offset = static_cast<std::size_t>(import_offset);

    while ( contains_range(import_end, descriptor_offset, sizeof(IMAGE_IMPORT_DESCRIPTOR)) )
    {
      IMAGE_IMPORT_DESCRIPTOR descriptor{};
      std::memcpy(&descriptor, buffer.data() + descriptor_offset, sizeof(descriptor));
      if ( !descriptor.Name )
        break;

      std::uint32_t name_offset = 0;
      std::string_view module_name;
      if ( !img->try_rva_to_offset(descriptor.Name, name_offset) ||
        !bounded_string_view(buffer, name_offset, module_name) )
        break;

      const auto thunk_rva = descriptor.OriginalFirstThunk ? descriptor.OriginalFirstThunk : descriptor.FirstThunk;
      if ( !thunk_rva || !descriptor.FirstThunk )
        break;

      for ( std::size_t i = 0; ; ++i )
      {
        std::size_t thunk_delta = 0;
        if ( !checked_multiply(i, sizeof(IMAGE_THUNK_DATA), thunk_delta) ||
          thunk_delta > std::numeric_limits<std::uint32_t>::max() - thunk_rva )
          break;

        std::uint32_t lookup_offset = 0;
        if ( !img->try_rva_to_offset(thunk_rva + static_cast<std::uint32_t>(thunk_delta), lookup_offset) ||
          !contains_range(buffer.size(), lookup_offset, sizeof(IMAGE_THUNK_DATA)) )
          break;

        IMAGE_THUNK_DATA thunk{};
        std::memcpy(&thunk, buffer.data() + lookup_offset, sizeof(thunk));
        if ( !thunk.u1.AddressOfData )
          break;
        if ( IMAGE_SNAP_BY_ORDINAL64(thunk.u1.Ordinal) )
          continue;
        if ( thunk.u1.AddressOfData > std::numeric_limits<std::uint32_t>::max() )
          break;

        std::uint32_t import_name_offset = 0;
        if ( !img->try_rva_to_offset(static_cast<std::uint32_t>(thunk.u1.AddressOfData), import_name_offset) ||
          !contains_range(buffer.size(), import_name_offset, sizeof(WORD) + 1) )
          break;

        std::string_view import_name;
        if ( !bounded_string_view(buffer, static_cast<std::size_t>(import_name_offset) + sizeof(WORD), import_name) )
          break;

        if ( thunk_delta > std::numeric_limits<std::uint32_t>::max() - descriptor.FirstThunk )
          break;
        const auto iat_rva = descriptor.FirstThunk + static_cast<std::uint32_t>(thunk_delta);

        auto [module, inserted] = _imports.try_emplace(std::string(module_name));
        module->second.emplace_back(module_name, import_name, iat_rva);
      }

      descriptor_offset += sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }
  }

  PIMAGE_DATA_DIRECTORY import_directory::iat_data_directory() const noexcept
  {
    return _iat_data_directory;
  }

  PIMAGE_DATA_DIRECTORY import_directory::import_data_directory() const noexcept
  {
    return _import_data_directory;
  }

  std::vector< import_directory::import_t > import_directory::imports() const
  {
    std::vector< import_t > result;
    std::size_t import_count = 0;
    for ( const auto &[_, imports] : _imports )
      import_count += imports.size();
    result.reserve(import_count);

    for ( const auto &[_, imports] : _imports )
      result.insert(result.end(), imports.begin(), imports.end());

    std::stable_sort(result.begin(), result.end(), [](const import_t &lhs, const import_t &rhs)
    {
      if ( lhs.module_name != rhs.module_name )
        return lhs.module_name < rhs.module_name;
      if ( lhs.import_name != rhs.import_name )
        return lhs.import_name < rhs.import_name;
      return lhs.iat_rva < rhs.iat_rva;
    });

    return result;
  }

  void import_directory::clear() noexcept
  {
    _imports.clear();
  }

  void import_directory::add(
    const std::string_view module_name, const std::string_view import_name, std::uintptr_t iat_rva)
  {
    auto [module, inserted] = _imports.try_emplace(std::string(module_name));
    module->second.emplace_back(module_name, import_name, iat_rva);
  }

  bool import_directory::recompile(image *img, const std::string_view section_name)
  {
    if ( !img || !img->data_directory(IMAGE_DIRECTORY_ENTRY_IMPORT) ||
      !img->data_directory(IMAGE_DIRECTORY_ENTRY_IAT) )
      return false;

    using import_pool_t = std::pair< std::string, std::vector< import_t > >;
    std::vector< import_pool_t > import_pools(_imports.begin(), _imports.end());
    std::sort(import_pools.begin(), import_pools.end(), [](const import_pool_t &lhs, const import_pool_t &rhs)
    {
      return lhs.first < rhs.first;
    });

    for ( auto &[_, imports] : import_pools )
    {
      std::stable_sort(imports.begin(), imports.end(), [](const import_t &lhs, const import_t &rhs)
      {
        return lhs.import_name < rhs.import_name;
      });
    }

    if ( import_pools.empty() )
      return false;

    struct import_layout_t
    {
      std::size_t descriptor_size = 0;
      std::size_t lookup_offset = 0;
      std::size_t lookup_size = 0;
      std::size_t iat_offset = 0;
      std::size_t iat_size = 0;
      std::size_t names_offset = 0;
      std::size_t total_size = 0;

      [[nodiscard]] bool contains(std::size_t offset, std::size_t size) const noexcept
      {
        return offset <= total_size && size <= total_size - offset;
      }
    } layout{};

    std::size_t descriptor_count = 0;
    if ( !checked_add(import_pools.size(), 1, descriptor_count) ||
      !checked_multiply(descriptor_count, sizeof(IMAGE_IMPORT_DESCRIPTOR), layout.descriptor_size) ||
      !align_offset(layout.descriptor_size, alignof(IMAGE_THUNK_DATA), layout.lookup_offset) )
      return false;

    for ( const auto &[_, imports] : import_pools )
    {
      std::size_t entry_count = 0;
      std::size_t table_size = 0;
      if ( !checked_add(imports.size(), 1, entry_count) ||
        !checked_multiply(entry_count, sizeof(IMAGE_THUNK_DATA), table_size) ||
        !checked_add(layout.lookup_size, table_size, layout.lookup_size) )
        return false;
    }

    std::size_t lookup_end = 0;
    if ( !checked_add(layout.lookup_offset, layout.lookup_size, lookup_end) ||
      !align_offset(lookup_end, alignof(IMAGE_THUNK_DATA), layout.iat_offset) )
      return false;

    layout.iat_size = layout.lookup_size;
    if ( !checked_add(layout.iat_offset, layout.iat_size, layout.names_offset) )
      return false;

    auto names_end = layout.names_offset;
    for ( const auto &[module_name, imports] : import_pools )
    {
      for ( const auto &import : imports )
      {
        std::size_t import_name_size = 0;
        if ( !align_offset(names_end, alignof(WORD), names_end) ||
          !checked_add(sizeof(WORD), import.import_name.size(), import_name_size) ||
          !checked_add(import_name_size, 1, import_name_size) ||
          !checked_add(names_end, import_name_size, names_end) )
          return false;
      }

      std::size_t module_name_size = 0;
      if ( !checked_add(module_name.size(), 1, module_name_size) ||
        !checked_add(names_end, module_name_size, names_end) )
        return false;
    }

    layout.total_size = names_end;
    if ( !layout.total_size || layout.total_size > std::numeric_limits<std::uint32_t>::max() )
      return false;

    const auto section = img->append_section(
      section_name, IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
      static_cast<std::uint32_t>(layout.total_size));
    if ( !section || section->VirtualAddress > std::numeric_limits<DWORD>::max() - layout.total_size ||
      !contains_range(img->buffer().size(), section->PointerToRawData, layout.total_size) )
      return false;

    auto *const data = img->buffer().data() + section->PointerToRawData;
    const auto rva_from_offset = [&](std::size_t offset, DWORD &rva) -> bool
    {
      if ( offset > std::numeric_limits<DWORD>::max() - section->VirtualAddress )
        return false;
      rva = section->VirtualAddress + static_cast<DWORD>(offset);
      return true;
    };

    const auto write_bytes = [&](std::size_t offset, const void *source, std::size_t size) -> bool
    {
      if ( !layout.contains(offset, size) )
        return false;
      std::memcpy(data + offset, source, size);
      return true;
    };

    auto lookup_offset = layout.lookup_offset;
    auto iat_offset = layout.iat_offset;
    auto names_offset = layout.names_offset;
    std::size_t descriptor_offset = 0;

    for ( const auto &[module_name, imports] : import_pools )
    {
      std::size_t table_size = 0;
      if ( !checked_multiply(imports.size() + 1, sizeof(IMAGE_THUNK_DATA), table_size) ||
        !layout.contains(lookup_offset, table_size) || !layout.contains(iat_offset, table_size) )
        return false;

      IMAGE_IMPORT_DESCRIPTOR descriptor{};
      if ( !rva_from_offset(lookup_offset, descriptor.OriginalFirstThunk) ||
        !rva_from_offset(iat_offset, descriptor.FirstThunk) )
        return false;

      for ( std::size_t i = 0; i < imports.size(); ++i )
      {
        const auto &import = imports[i];
        if ( !align_offset(names_offset, alignof(WORD), names_offset) )
          return false;

        std::size_t import_name_size = 0;
        if ( !checked_add(sizeof(WORD), import.import_name.size(), import_name_size) ||
          !checked_add(import_name_size, 1, import_name_size) ||
          !layout.contains(names_offset, import_name_size) )
          return false;

        const WORD hint = 0;
        if ( !write_bytes(names_offset, &hint, sizeof(hint)) ||
          !write_bytes(names_offset + sizeof(hint), import.import_name.c_str(), import.import_name.size() + 1) )
          return false;

        IMAGE_THUNK_DATA lookup_entry{};
        IMAGE_THUNK_DATA iat_entry{};
        DWORD import_name_rva = 0;
        if ( !rva_from_offset(names_offset, import_name_rva) )
          return false;
        lookup_entry.u1.AddressOfData = import_name_rva;
        iat_entry.u1.AddressOfData = import_name_rva;

        if ( !write_bytes(lookup_offset + i * sizeof(lookup_entry), &lookup_entry, sizeof(lookup_entry)) ||
          !write_bytes(iat_offset + i * sizeof(iat_entry), &iat_entry, sizeof(iat_entry)) )
          return false;

        names_offset += import_name_size;
      }

      if ( !rva_from_offset(names_offset, descriptor.Name) ||
        !write_bytes(names_offset, module_name.c_str(), module_name.size() + 1) ||
        !write_bytes(descriptor_offset, &descriptor, sizeof(descriptor)) )
        return false;

      names_offset += module_name.size() + 1;
      lookup_offset += table_size;
      iat_offset += table_size;
      descriptor_offset += sizeof(descriptor);
    }

    _iat_data_directory = img->data_directory(IMAGE_DIRECTORY_ENTRY_IAT);
    _import_data_directory = img->data_directory(IMAGE_DIRECTORY_ENTRY_IMPORT);
    if ( !_iat_data_directory || !_import_data_directory )
      return false;

    _import_data_directory->VirtualAddress = section->VirtualAddress;
    _import_data_directory->Size = static_cast<DWORD>(layout.descriptor_size);
    if ( !rva_from_offset(layout.iat_offset, _iat_data_directory->VirtualAddress) )
      return false;
    _iat_data_directory->Size = static_cast<DWORD>(layout.iat_size);

    return img->refresh();
  }

  import_directory::import_t::import_t(
    const std::string_view module_name, const std::string_view import_name, std::uintptr_t iat_rva)
    : module_name(module_name), import_name(import_name), iat_rva(iat_rva)
  {
  }
}  // namespace vulkan::pe
