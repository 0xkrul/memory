#pragma once

#include "includes.hpp"

namespace Util
{
  namespace detail
  {
    inline void append_format(std::string &out, std::string_view text)
    {
      out.append(text.data(), text.size());
    }

    template <typename T>
    void append_value(std::string &out, T &&value, bool hexadecimal)
    {
      using value_t = std::remove_cvref_t<T>;

      char buffer[64]{};

      if constexpr ( std::is_same_v<value_t, std::string> )
      {
        out += value;
      }
      else if constexpr ( std::is_convertible_v<T, const char *> )
      {
        const char *text = value;
        out += text ? text : "(null)";
      }
      else if constexpr ( std::is_convertible_v<T, std::string_view> )
      {
        const std::string_view view = value;
        out.append(view.data(), view.size());
      }
      else if constexpr ( std::is_pointer_v<value_t> )
      {
        std::snprintf(buffer, sizeof(buffer), hexadecimal ? "%llX" : "0x%llX", reinterpret_cast<unsigned long long>(value));
        out += buffer;
      }
      else if constexpr ( std::is_integral_v<value_t> || std::is_enum_v<value_t> )
      {
        if ( hexadecimal )
          std::snprintf(buffer, sizeof(buffer), "%llX", static_cast<unsigned long long>(value));
        else if constexpr ( std::is_signed_v<value_t> )
          std::snprintf(buffer, sizeof(buffer), "%lld", static_cast<long long>(value));
        else
          std::snprintf(buffer, sizeof(buffer), "%llu", static_cast<unsigned long long>(value));
        out += buffer;
      }
      else if constexpr ( std::is_floating_point_v<value_t> )
      {
        std::snprintf(buffer, sizeof(buffer), "%.3f", static_cast<double>(value));
        out += buffer;
      }
      else
      {
        out += "<?>";
      }
    }

    template <typename T, typename... Rest>
    void append_format(std::string &out, std::string_view text, T &&value, Rest &&...rest)
    {
      const auto open = text.find('{');
      if ( open == std::string_view::npos )
      {
        append_format(out, text);
        return;
      }

      const auto close = text.find('}', open);
      if ( close == std::string_view::npos )
      {
        append_format(out, text);
        return;
      }

      out.append(text.substr(0, open).data(), open);

      const auto spec = text.substr(open + 1, close - open - 1);
      append_value(out, std::forward<T>(value), spec == ":X" || spec == ":#X" || spec == ":#018x");

      append_format(out, text.substr(close + 1), std::forward<Rest>(rest)...);
    }
  }

  template <typename... Args>
  void Log(std::string_view format, Args &&...args)
  {
    std::string message;
    message.reserve(format.size() + 64);
    detail::append_format(message, format, std::forward<Args>(args)...);
    message += '\n';
    ::OutputDebugStringA(message.c_str());
    std::fputs(message.c_str(), stdout);
  }
}
