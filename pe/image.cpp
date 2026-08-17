#include "image.hpp"

#include "../memory.hpp"
#include "../util.hpp"
#include "utils.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <limits>
#include <string>

namespace vulkan::pe
{
  namespace
  {
    bool contains_range(std::size_t buffer_size, std::size_t offset, std::size_t size) noexcept
    {
      return offset <= buffer_size && size <= buffer_size - offset;
    }

    bool is_power_of_two(std::uint32_t value) noexcept
    {
      return value != 0 && (value & (value - 1)) == 0;
    }

    template< typename T >
    bool read_value(const std::vector< std::uint8_t > &buffer, std::size_t offset, T &value) noexcept
    {
      if ( !contains_range(buffer.size(), offset, sizeof(T)) )
        return false;

      std::memcpy(&value, buffer.data() + offset, sizeof(T));
      return true;
    }

    template< typename T >
    bool write_value(std::vector< std::uint8_t > &buffer, std::size_t offset, const T &value) noexcept
    {
      if ( !contains_range(buffer.size(), offset, sizeof(T)) )
        return false;

      std::memcpy(buffer.data() + offset, &value, sizeof(T));
      return true;
    }
  }

  std::uint32_t image::compute_checksum() const noexcept
  {
    if ( !_nt_headers || _buffer.empty() )
      return 0;

    const auto checksum_offset = static_cast<std::size_t>(
      reinterpret_cast<const std::uint8_t *>(&_nt_headers->OptionalHeader.CheckSum) - _buffer.data());
    if ( !contains_range(_buffer.size(), checksum_offset, sizeof(_nt_headers->OptionalHeader.CheckSum)) )
      return 0;

    std::uint64_t sum = 0;
    std::size_t offset = 0;

    for ( ; offset + 1 < _buffer.size(); offset += sizeof(std::uint16_t) )
    {
      if ( offset < checksum_offset || offset >= checksum_offset + sizeof(std::uint32_t) )
      {
        const auto word = static_cast<std::uint16_t>(_buffer[offset]) |
          (static_cast<std::uint16_t>(_buffer[offset + 1]) << 8);
        sum += word;
        sum = (sum & 0xFFFF) + (sum >> 16);
      }
    }

    if ( offset < _buffer.size() )
      sum += _buffer[offset];

    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum += _buffer.size();

    return static_cast<std::uint32_t>(sum);
  }

  image::image(const std::vector< std::uint8_t > &buffer, bool mapped) : _buffer(buffer)
  {
    _import_directory = std::unique_ptr< pe::import_directory >(new pe::import_directory());

    _is_valid = refresh();

    if ( _is_valid && mapped )
    {
      auto &headers = section_headers();
      const auto file_alignment = _nt_headers->OptionalHeader.FileAlignment;

      for ( std::uint16_t i = 0; i < headers->count(); ++i )
      {
        const auto section = headers->at(i);
        section->PointerToRawData = section->VirtualAddress;
        section->SizeOfRawData = align(section->Misc.VirtualSize, file_alignment);
        if ( section->Misc.VirtualSize && !section->SizeOfRawData )
        {
          _is_valid = false;
          return;
        }
      }

      if ( const auto security_directory = data_directory(IMAGE_DIRECTORY_ENTRY_SECURITY) )
        *security_directory = {};

      _is_valid = refresh();
    }
  }

  std::unique_ptr< image > image::create(HMODULE module)
  {
    if ( !module )
    {
      Util::Log("[PE] Cannot create image from null module");
      return nullptr;
    }

    IMAGE_DOS_HEADER dos_header{};
    const auto module_base = reinterpret_cast<std::uintptr_t>(module);
    if ( !Mem::ReadProcessMemory(module_base, &dos_header, sizeof(dos_header)) || dos_header.e_magic != IMAGE_DOS_SIGNATURE )
    {
      Util::Log("[PE] Invalid DOS signature at {:X}", module);
      return nullptr;
    }

    if ( dos_header.e_lfanew < static_cast<LONG>(sizeof(IMAGE_DOS_HEADER)) ||
      module_base > std::numeric_limits<std::uintptr_t>::max() - static_cast<std::uintptr_t>(dos_header.e_lfanew) )
    {
      Util::Log("[PE] Invalid NT header offset: {}", dos_header.e_lfanew);
      return nullptr;
    }

    const auto nt_address = module_base + static_cast<std::uintptr_t>(dos_header.e_lfanew);
    IMAGE_NT_HEADERS nt_headers{};
    if ( !Mem::ReadProcessMemory(nt_address, &nt_headers, sizeof(nt_headers)) || nt_headers.Signature != IMAGE_NT_SIGNATURE )
    {
      Util::Log("[PE] Invalid NT signature at {:X}", nt_address);
      return nullptr;
    }

    const auto module_size = nt_headers.OptionalHeader.SizeOfImage;
    PIMAGE_OPTIONAL_HEADER optional_header = &nt_headers.OptionalHeader;
    if ( optional_header->Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC )
    {
      Util::Log("[PE] Unsupported optional header magic: {:X}", optional_header->Magic);
      return nullptr;
    }

    if ( !module_size || !optional_header->SizeOfHeaders )
    {
      Util::Log("[PE] Invalid image sizes. SizeOfImage={}, SizeOfHeaders={}", module_size, optional_header->SizeOfHeaders);
      return nullptr;
    }

    std::vector< std::uint8_t > buffer(module_size, 0);

    const auto header_size = std::min<std::size_t>(optional_header->SizeOfHeaders, buffer.size());
    if ( !Mem::ReadProcessMemory(module_base, buffer.data(), header_size) )
    {
      Util::Log("[PE] Failed to read PE headers");
      return nullptr;
    }

    auto img = std::make_unique< image >(buffer, true);
    if ( !img->is_valid() )
    {
      Util::Log("[PE] Failed to initialize PE image");
      return nullptr;
    }

    return img;
  }

  std::vector< std::uint8_t > &image::buffer() const noexcept
  {
    return _buffer;
  }

  std::unique_ptr< section_headers > &image::section_headers() const noexcept
  {
    return _section_headers;
  }

  std::unique_ptr< import_directory > &image::import_directory() const noexcept
  {
    return _import_directory;
  }

  PIMAGE_DATA_DIRECTORY image::data_directory(std::uint32_t id) const noexcept
  {
    if ( !_nt_headers || id >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES || id >= _nt_headers->OptionalHeader.NumberOfRvaAndSizes )
      return nullptr;

    return &_nt_headers->OptionalHeader.DataDirectory[id];
  }

  PIMAGE_SECTION_HEADER image::append_section(
    const std::string_view name, std::uint32_t characteristics, const std::span< std::uint8_t > &data)
  {
    if ( !_nt_headers || !_section_headers || !_section_headers->count() ||
      data.size() > std::numeric_limits<std::uint32_t>::max() ||
      _section_headers->count() == std::numeric_limits<std::uint16_t>::max() )
      return nullptr;

    const auto file_alignment = _nt_headers->OptionalHeader.FileAlignment;
    const auto section_alignment = _nt_headers->OptionalHeader.SectionAlignment;
    if ( !is_power_of_two(file_alignment) || !is_power_of_two(section_alignment) )
      return nullptr;

    const auto data_size = static_cast<std::uint32_t>(data.size());
    const auto aligned_file_size = align(data_size, file_alignment);
    if ( data_size && !aligned_file_size )
      return nullptr;

    const auto nt_offset = static_cast<std::size_t>(reinterpret_cast<std::uint8_t *>(_nt_headers) - _buffer.data());
    const auto section_table_offset = nt_offset + offsetof(IMAGE_NT_HEADERS, OptionalHeader) +
      _nt_headers->FileHeader.SizeOfOptionalHeader;
    const auto new_header_offset = section_table_offset +
      static_cast<std::size_t>(_section_headers->count()) * sizeof(IMAGE_SECTION_HEADER);
    if ( !contains_range(_buffer.size(), new_header_offset, sizeof(IMAGE_SECTION_HEADER)) ||
      new_header_offset + sizeof(IMAGE_SECTION_HEADER) > _nt_headers->OptionalHeader.SizeOfHeaders )
      return nullptr;

    std::uint64_t maximum_virtual_end = _nt_headers->OptionalHeader.SizeOfHeaders;
    std::uint64_t maximum_raw_end = _nt_headers->OptionalHeader.SizeOfHeaders;
    for ( std::uint16_t i = 0; i < _section_headers->count(); ++i )
    {
      const auto section = _section_headers->at(i);
      maximum_virtual_end = std::max(maximum_virtual_end,
        static_cast<std::uint64_t>(section->VirtualAddress) +
          std::max(section->Misc.VirtualSize, section->SizeOfRawData));
      maximum_raw_end = std::max(maximum_raw_end,
        static_cast<std::uint64_t>(section->PointerToRawData) + section->SizeOfRawData);
    }

    if ( maximum_virtual_end > std::numeric_limits<std::uint32_t>::max() ||
      maximum_raw_end > std::numeric_limits<std::uint32_t>::max() )
      return nullptr;

    IMAGE_SECTION_HEADER section_header{};
    std::copy_n(name.begin(), std::min<std::size_t>(name.size(), IMAGE_SIZEOF_SHORT_NAME), section_header.Name);
    section_header.SizeOfRawData = aligned_file_size;
    section_header.Misc.VirtualSize = data_size;
    section_header.Characteristics = characteristics;
    section_header.VirtualAddress = align(static_cast<std::uint32_t>(maximum_virtual_end), section_alignment);
    section_header.PointerToRawData = align(static_cast<std::uint32_t>(maximum_raw_end), file_alignment);

    if ( (maximum_virtual_end && !section_header.VirtualAddress) || (maximum_raw_end && !section_header.PointerToRawData) )
      return nullptr;

    const auto raw_end = static_cast<std::uint64_t>(section_header.PointerToRawData) + aligned_file_size;
    const auto virtual_end = static_cast<std::uint64_t>(section_header.VirtualAddress) + data_size;
    if ( raw_end > std::numeric_limits<std::uint32_t>::max() ||
      virtual_end > std::numeric_limits<std::uint32_t>::max() || raw_end > std::numeric_limits<std::size_t>::max() )
      return nullptr;

    const auto occupied_end = std::min<std::size_t>(static_cast<std::size_t>(raw_end), _buffer.size());
    if ( section_header.PointerToRawData < occupied_end &&
      std::any_of(_buffer.begin() + section_header.PointerToRawData, _buffer.begin() + occupied_end,
        [](std::uint8_t byte) { return byte != 0; }) )
      return nullptr;

    const auto image_size = align(static_cast<std::uint32_t>(virtual_end), section_alignment);
    if ( virtual_end && !image_size )
      return nullptr;

    if ( characteristics & IMAGE_SCN_CNT_CODE )
    {
      if ( _nt_headers->OptionalHeader.SizeOfCode > std::numeric_limits<std::uint32_t>::max() - aligned_file_size )
        return nullptr;
    }

    if ( characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA )
    {
      if ( _nt_headers->OptionalHeader.SizeOfInitializedData >
        std::numeric_limits<std::uint32_t>::max() - aligned_file_size )
        return nullptr;
    }

    if ( characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA )
    {
      if ( _nt_headers->OptionalHeader.SizeOfUninitializedData >
        std::numeric_limits<std::uint32_t>::max() - data_size )
        return nullptr;
    }

    std::vector< std::uint8_t > aligned_data(aligned_file_size, 0);
    std::copy(data.begin(), data.end(), aligned_data.begin());

    const auto required_size = static_cast<std::size_t>(raw_end);
    if ( _buffer.size() < required_size )
    {
      _buffer.resize(required_size, 0);
      _is_valid = refresh();
      if ( !_is_valid )
        return nullptr;
    }

    _section_headers->append(section_header);
    _nt_headers->FileHeader.NumberOfSections += 1;
    _nt_headers->OptionalHeader.SizeOfImage =
          std::max<DWORD>(_nt_headers->OptionalHeader.SizeOfImage, static_cast<DWORD>(image_size));
    if ( characteristics & IMAGE_SCN_CNT_CODE )
      _nt_headers->OptionalHeader.SizeOfCode += aligned_file_size;
    if ( characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA )
      _nt_headers->OptionalHeader.SizeOfInitializedData += aligned_file_size;
    if ( characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA )
      _nt_headers->OptionalHeader.SizeOfUninitializedData += data_size;

    std::copy(aligned_data.begin(), aligned_data.end(), _buffer.begin() + section_header.PointerToRawData);

    Util::Log(
      "[PE] Appended section {} VA=0x{:X} Raw=0x{:X} VSz=0x{:X} RSz=0x{:X}",
      std::string(name),
      section_header.VirtualAddress,
      section_header.PointerToRawData,
      section_header.Misc.VirtualSize,
      section_header.SizeOfRawData);

    _is_valid = refresh();
    return _is_valid ? _section_headers->last() : nullptr;
  }

  PIMAGE_SECTION_HEADER image::append_section(const std::string_view name, std::uint32_t characteristics, std::uint32_t size)
  {
    std::vector< std::uint8_t > data(size, 0);
    return append_section(name, characteristics, data);
  }

  PIMAGE_SECTION_HEADER image::extend_section(const std::string_view name, std::uint32_t size)
  {
    if ( !_nt_headers || !_section_headers )
      return nullptr;

    const auto section = _section_headers->find(name);
    if ( !section )
      return nullptr;
    if ( !size )
      return section;

    const auto file_alignment = _nt_headers->OptionalHeader.FileAlignment;
    const auto section_alignment = _nt_headers->OptionalHeader.SectionAlignment;
    if ( !is_power_of_two(file_alignment) || !is_power_of_two(section_alignment) )
      return nullptr;

    const auto section_index = static_cast<std::uint16_t>(section - _section_headers->first());
    const auto old_raw_end = static_cast<std::uint64_t>(section->PointerToRawData) + section->SizeOfRawData;
    const auto old_virtual_end = static_cast<std::uint64_t>(section->VirtualAddress) +
      std::max(section->Misc.VirtualSize, section->SizeOfRawData);

    for ( std::uint16_t i = 0; i < _section_headers->count(); ++i )
    {
      if ( i == section_index )
        continue;

      const auto other = _section_headers->at(i);
      const auto other_raw_end = static_cast<std::uint64_t>(other->PointerToRawData) + other->SizeOfRawData;
      const auto other_virtual_end = static_cast<std::uint64_t>(other->VirtualAddress) +
        std::max(other->Misc.VirtualSize, other->SizeOfRawData);
      if ( other_raw_end > old_raw_end || other_virtual_end > old_virtual_end )
        return nullptr;
    }

    const auto unaligned_raw_size = static_cast<std::uint64_t>(section->SizeOfRawData) + size;
    const auto new_virtual_size = static_cast<std::uint64_t>(section->Misc.VirtualSize) + size;
    if ( unaligned_raw_size > std::numeric_limits<std::uint32_t>::max() ||
      new_virtual_size > std::numeric_limits<std::uint32_t>::max() )
      return nullptr;

    const auto new_raw_size = align(static_cast<std::uint32_t>(unaligned_raw_size), file_alignment);
    if ( !new_raw_size )
      return nullptr;

    const auto new_raw_end = static_cast<std::uint64_t>(section->PointerToRawData) + new_raw_size;
    const auto new_virtual_end = static_cast<std::uint64_t>(section->VirtualAddress) + new_virtual_size;
    if ( new_raw_end > std::numeric_limits<std::size_t>::max() ||
      new_virtual_end > std::numeric_limits<std::uint32_t>::max() )
      return nullptr;

    if ( old_raw_end > _buffer.size() )
      return nullptr;

    const auto occupied_end = std::min<std::size_t>(static_cast<std::size_t>(new_raw_end), _buffer.size());
    if ( std::any_of(_buffer.begin() + static_cast<std::size_t>(old_raw_end), _buffer.begin() + occupied_end,
      [](std::uint8_t byte) { return byte != 0; }) )
      return nullptr;

    const auto new_image_size = align(static_cast<std::uint32_t>(new_virtual_end), section_alignment);
    if ( !new_image_size )
      return nullptr;

    if ( _buffer.size() < new_raw_end )
    {
      _buffer.resize(static_cast<std::size_t>(new_raw_end), 0);
      _is_valid = refresh();
      if ( !_is_valid )
        return nullptr;
    }

    const auto refreshed_section = _section_headers->at(section_index);
    std::fill(_buffer.begin() + static_cast<std::size_t>(old_raw_end),
      _buffer.begin() + static_cast<std::size_t>(new_raw_end), std::uint8_t{ 0 });
    refreshed_section->SizeOfRawData = new_raw_size;
    refreshed_section->Misc.VirtualSize = static_cast<std::uint32_t>(new_virtual_size);
    _nt_headers->OptionalHeader.SizeOfImage =
          std::max<DWORD>(_nt_headers->OptionalHeader.SizeOfImage, static_cast<DWORD>(new_image_size));

    _is_valid = refresh();
    return _is_valid ? _section_headers->at(section_index) : nullptr;
  }

  bool image::refresh()
  {
    _dos_header = nullptr;
    _nt_headers = nullptr;
    _section_headers.reset();
    _import_directory->clear();
    _import_directory->_import_data_directory = nullptr;
    _import_directory->_iat_data_directory = nullptr;

    if ( _buffer.size() > std::numeric_limits<std::uint32_t>::max() ||
      !contains_range(_buffer.size(), 0, sizeof(IMAGE_DOS_HEADER)) )
      return false;

    IMAGE_DOS_HEADER dos_header{};
    std::memcpy(&dos_header, _buffer.data(), sizeof(dos_header));
    if ( dos_header.e_magic != IMAGE_DOS_SIGNATURE ||
      dos_header.e_lfanew < static_cast<LONG>(sizeof(IMAGE_DOS_HEADER)) )
      return false;

    const auto nt_offset = static_cast<std::size_t>(dos_header.e_lfanew);
    constexpr auto nt_prefix_size = sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    if ( nt_offset % alignof(IMAGE_NT_HEADERS) != 0 ||
      !contains_range(_buffer.size(), nt_offset, nt_prefix_size) )
      return false;

    DWORD signature = 0;
    IMAGE_FILE_HEADER file_header{};
    std::memcpy(&signature, _buffer.data() + nt_offset, sizeof(signature));
    std::memcpy(&file_header, _buffer.data() + nt_offset + sizeof(signature), sizeof(file_header));
    if ( signature != IMAGE_NT_SIGNATURE || !file_header.NumberOfSections ||
      file_header.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER) )
      return false;

    const auto optional_offset = nt_offset + nt_prefix_size;
    if ( !contains_range(_buffer.size(), optional_offset, file_header.SizeOfOptionalHeader) )
      return false;

    IMAGE_OPTIONAL_HEADER optional_header{};
    std::memcpy(&optional_header, _buffer.data() + optional_offset, sizeof(optional_header));
    if ( optional_header.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC ||
      optional_header.NumberOfRvaAndSizes > IMAGE_NUMBEROF_DIRECTORY_ENTRIES ||
      !optional_header.SizeOfHeaders || optional_header.SizeOfHeaders > _buffer.size() ||
      optional_header.SizeOfImage < optional_header.SizeOfHeaders ||
      !is_power_of_two(optional_header.FileAlignment) ||
      !is_power_of_two(optional_header.SectionAlignment) ||
      optional_header.SectionAlignment < optional_header.FileAlignment )
      return false;

    const auto section_table_offset = optional_offset + file_header.SizeOfOptionalHeader;
    const auto section_table_size = static_cast<std::size_t>(file_header.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);
    if ( section_table_offset % alignof(IMAGE_SECTION_HEADER) != 0 ||
      !contains_range(_buffer.size(), section_table_offset, section_table_size) ||
      section_table_offset + section_table_size > optional_header.SizeOfHeaders )
      return false;

    for ( std::uint16_t i = 0; i < file_header.NumberOfSections; ++i )
    {
      IMAGE_SECTION_HEADER section{};
      std::memcpy(&section, _buffer.data() + section_table_offset +
        static_cast<std::size_t>(i) * sizeof(section), sizeof(section));

      if ( section.SizeOfRawData )
      {
        if ( section.PointerToRawData < optional_header.SizeOfHeaders ||
          !contains_range(_buffer.size(), section.PointerToRawData, section.SizeOfRawData) )
          return false;
      }

      const auto virtual_span = std::max(section.Misc.VirtualSize, section.SizeOfRawData);
      const auto virtual_end = static_cast<std::uint64_t>(section.VirtualAddress) + virtual_span;
      if ( virtual_span && (section.VirtualAddress < optional_header.SizeOfHeaders ||
        virtual_end > optional_header.SizeOfImage) )
        return false;
    }

    _dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(_buffer.data());
    _nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(_buffer.data() + nt_offset);
    _section_headers = std::unique_ptr< pe::section_headers >(new pe::section_headers(_nt_headers));

    _import_directory->refresh(this);
    _nt_headers->OptionalHeader.CheckSum = compute_checksum();
    return true;
  }

  bool image::try_rva_to_offset(std::uint32_t rva, std::uint32_t &offset) const noexcept
  {
    offset = 0;
    if ( !_nt_headers || !_section_headers )
      return false;

    if ( rva < _nt_headers->OptionalHeader.SizeOfHeaders )
    {
      if ( rva >= _buffer.size() )
        return false;
      offset = rva;
      return true;
    }

    for ( std::uint16_t i = 0; i < _section_headers->count(); ++i )
    {
      const auto section = _section_headers->at(i);
      const auto virtual_span = std::max(section->Misc.VirtualSize, section->SizeOfRawData);
      const auto section_end = static_cast<std::uint64_t>(section->VirtualAddress) + virtual_span;
      if ( rva < section->VirtualAddress || static_cast<std::uint64_t>(rva) >= section_end )
        continue;

      const auto delta = rva - section->VirtualAddress;
      if ( delta >= section->SizeOfRawData )
        return false;

      const auto file_offset = static_cast<std::uint64_t>(section->PointerToRawData) + delta;
      if ( file_offset >= _buffer.size() || file_offset > std::numeric_limits<std::uint32_t>::max() )
        return false;

      offset = static_cast<std::uint32_t>(file_offset);
      return true;
    }

    return false;
  }

  std::uint32_t image::rva_to_offset(std::uint32_t rva) const noexcept
  {
    std::uint32_t offset = 0;
    return try_rva_to_offset(rva, offset) ? offset : 0;
  }

  bool image::try_offset_to_rva(std::uint32_t offset, std::uint32_t &rva) const noexcept
  {
    rva = 0;
    if ( !_nt_headers || !_section_headers || offset >= _buffer.size() )
      return false;

    if ( offset < _nt_headers->OptionalHeader.SizeOfHeaders )
    {
      rva = offset;
      return true;
    }

    for ( std::uint16_t i = 0; i < _section_headers->count(); ++i )
    {
      const auto section = _section_headers->at(i);
      const auto section_end = static_cast<std::uint64_t>(section->PointerToRawData) + section->SizeOfRawData;
      if ( offset < section->PointerToRawData || static_cast<std::uint64_t>(offset) >= section_end )
        continue;

      const auto converted = static_cast<std::uint64_t>(section->VirtualAddress) +
        (offset - section->PointerToRawData);
      if ( converted > std::numeric_limits<std::uint32_t>::max() )
        return false;

      rva = static_cast<std::uint32_t>(converted);
      return true;
    }

    return false;
  }

  std::uint32_t image::offset_to_rva(std::uint32_t offset) const noexcept
  {
    std::uint32_t rva = 0;
    return try_offset_to_rva(offset, rva) ? rva : 0;
  }

  bool image::save_to_file(std::string_view filepath)
  {
    if ( filepath.empty() || _buffer.size() > static_cast<std::size_t>(std::numeric_limits<std::streamsize>::max()) )
      return false;

    std::ofstream file{ std::string(filepath), std::ios::binary | std::ios::trunc };
    if ( !file )
      return false;

    file.write(reinterpret_cast<const char *>(_buffer.data()), static_cast<std::streamsize>(_buffer.size()));
    if ( !file )
      return false;

    file.close();
    return !file.fail();
  }

  void image::rebase(std::uintptr_t base) const noexcept
  {
    const auto relocation_directory = data_directory(IMAGE_DIRECTORY_ENTRY_BASERELOC);
    if ( !relocation_directory || !relocation_directory->VirtualAddress || !relocation_directory->Size )
      return;

    std::uint32_t relocation_offset = 0;
    if ( !try_rva_to_offset(relocation_directory->VirtualAddress, relocation_offset) ||
      !contains_range(_buffer.size(), relocation_offset, relocation_directory->Size) )
      return;

    const auto relocation_delta = base - image_base();
    std::size_t block_offset = 0;

    while ( block_offset < relocation_directory->Size )
    {
      if ( relocation_directory->Size - block_offset < sizeof(IMAGE_BASE_RELOCATION) )
        return;

      IMAGE_BASE_RELOCATION relocation{};
      if ( !read_value(_buffer, static_cast<std::size_t>(relocation_offset) + block_offset, relocation) )
        return;
      if ( !relocation.VirtualAddress )
        break;
      if ( relocation.SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) ||
        relocation.SizeOfBlock > relocation_directory->Size - block_offset ||
        (relocation.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) % sizeof(std::uint16_t) != 0 )
        return;

      const auto entries_offset = static_cast<std::size_t>(relocation_offset) + block_offset + sizeof(IMAGE_BASE_RELOCATION);
      const auto count = (relocation.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(std::uint16_t);

      for ( std::size_t i = 0; i < count; ++i )
      {
        std::uint16_t entry = 0;
        if ( !read_value(_buffer, entries_offset + i * sizeof(entry), entry) )
          return;

        const auto relocation_type = entry >> 12;
        if ( relocation_type == IMAGE_REL_BASED_ABSOLUTE )
          continue;

        const auto target_rva_value = static_cast<std::uint64_t>(relocation.VirtualAddress) + (entry & 0x0FFF);
        if ( target_rva_value > std::numeric_limits<std::uint32_t>::max() )
          return;

        std::uint32_t target_offset = 0;
        if ( !try_rva_to_offset(static_cast<std::uint32_t>(target_rva_value), target_offset) )
          return;

        switch ( relocation_type )
        {
          case IMAGE_REL_BASED_HIGH:
            {
              std::uint16_t value = 0;
              if ( !read_value(_buffer, target_offset, value) )
                return;
              value = static_cast<std::uint16_t>(value + static_cast<std::uint16_t>(relocation_delta >> 16));
              if ( !write_value(_buffer, target_offset, value) )
                return;
              break;
            }
          case IMAGE_REL_BASED_LOW:
            {
              std::uint16_t value = 0;
              if ( !read_value(_buffer, target_offset, value) )
                return;
              value = static_cast<std::uint16_t>(value + static_cast<std::uint16_t>(relocation_delta));
              if ( !write_value(_buffer, target_offset, value) )
                return;
              break;
            }
          case IMAGE_REL_BASED_HIGHLOW:
            {
              std::uint32_t value = 0;
              if ( !read_value(_buffer, target_offset, value) )
                return;
              value += static_cast<std::uint32_t>(relocation_delta);
              if ( !write_value(_buffer, target_offset, value) )
                return;
              break;
            }
          case IMAGE_REL_BASED_HIGHADJ:
            {
              if ( i + 1 >= count )
                return;

              std::uint16_t next = 0;
              if ( !read_value(_buffer, entries_offset + (++i) * sizeof(next), next) )
                return;

              std::uint16_t value = 0;
              if ( !read_value(_buffer, target_offset, value) )
                return;

              auto adjusted = (static_cast<std::int64_t>(value) << 16) + static_cast<std::int16_t>(next);
              adjusted += static_cast<std::int64_t>(static_cast<std::intptr_t>(relocation_delta));
              adjusted += 0x8000;
              value = static_cast<std::uint16_t>(adjusted >> 16);
              if ( !write_value(_buffer, target_offset, value) )
                return;
              break;
            }
          case IMAGE_REL_BASED_DIR64:
            {
              std::uint64_t value = 0;
              if ( !read_value(_buffer, target_offset, value) )
                return;
              value += static_cast<std::uint64_t>(relocation_delta);
              if ( !write_value(_buffer, target_offset, value) )
                return;
              break;
            }
          default: break;
        }
      }

      block_offset += relocation.SizeOfBlock;
    }

    _nt_headers->OptionalHeader.ImageBase = base;
    _nt_headers->OptionalHeader.CheckSum = compute_checksum();
  }
}  // namespace vulkan::pe
