#include "section_headers.hpp"
#include "section_name.hpp"
#include "utils.hpp"

#include <algorithm>
#include <cstring>

namespace vulkan::pe
{
  section_headers::section_headers(PIMAGE_NT_HEADERS nt_headers) noexcept : _nt_headers(nt_headers)
  {
  }

  void section_headers::realign() const noexcept
  {
    const auto section_alignment = _nt_headers->OptionalHeader.SectionAlignment;
    const auto file_alignment = _nt_headers->OptionalHeader.FileAlignment;

    if ( !section_alignment || !file_alignment )
      return;

    for ( std::uint16_t i = 0; i < count(); ++i )
    {
      auto section = at(i);
      const auto virtual_address = align(section->VirtualAddress, section_alignment);
      const auto raw_size = align(section->SizeOfRawData, file_alignment);

      if ( (section->VirtualAddress && !virtual_address) || (section->SizeOfRawData && !raw_size) )
        return;

      section->VirtualAddress = virtual_address;
      section->SizeOfRawData = raw_size;
    }
  }

  void section_headers::append(IMAGE_SECTION_HEADER &header) const noexcept
  {
    std::memcpy(at(count()), &header, sizeof(header));
  }

  void section_headers::remove(const char *name) const noexcept
  {
    const auto num_sections = count();

    for ( std::uint16_t i = 0; i < num_sections; ++i )
    {
      auto section = at(i);

      if ( section_name_equals(*section, name) )
      {
        remove(i);
        break;
      }
    }
  }

  void section_headers::remove(const std::uint16_t idx) const noexcept
  {
    if ( idx >= count() )
      return;

    // Shift all later section headers one slot up to overwrite this one.
    for ( std::uint16_t j = idx + 1; j < count(); ++j )
    {
      auto src = at(j);
      auto dst = at(j - 1);

      std::memcpy(dst, src, sizeof(IMAGE_SECTION_HEADER));
    }

    // Zero out the now-redundant last section header.
    auto last = at(count() - 1);
    std::memset(last, 0, sizeof(IMAGE_SECTION_HEADER));

    // Update section count.
    _nt_headers->FileHeader.NumberOfSections -= 1;
  }

  PIMAGE_SECTION_HEADER section_headers::find(std::string_view name) const noexcept
  {
    for ( std::uint16_t i = 0; i < count(); ++i )
    {
      const auto section = at(i);

      if ( section_name_equals(*section, name) )
        return section;
    }

    return nullptr;
  }
}  // namespace vulkan::pe