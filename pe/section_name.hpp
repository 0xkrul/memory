#pragma once

#include <Windows.h>

#include <algorithm>
#include <cstring>
#include <string>
#include <string_view>

namespace vulkan::pe
{
  inline std::string section_name(const IMAGE_SECTION_HEADER &section)
  {
    const auto begin = reinterpret_cast<const char *>(section.Name);
    const auto end = std::find(begin, begin + IMAGE_SIZEOF_SHORT_NAME, '\0');
    return std::string(begin, end);
  }

  inline bool section_name_equals(const IMAGE_SECTION_HEADER &section, std::string_view name) noexcept
  {
    if ( name.size() > IMAGE_SIZEOF_SHORT_NAME )
      return false;

    const auto begin = reinterpret_cast<const char *>(section.Name);
    const auto end = std::find(begin, begin + IMAGE_SIZEOF_SHORT_NAME, '\0');
    return name.size() == static_cast<std::size_t>(end - begin) && std::equal(name.begin(), name.end(), begin);
  }
}
