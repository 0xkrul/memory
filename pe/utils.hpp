#pragma once

#include <concepts>
#include <cstdint>
#include <limits>

namespace vulkan::pe
{
  /// <summary>
  /// Pages are aligned to 4KB on both x86 and x64.
  /// </summary>
  static constexpr std::uint32_t PAGE_SIZE = 0x1000;

  /// <summary>
  /// Aligns a value to the specified alignment.
  /// </summary>
  /// <typeparam name="T">The type of value to align.</typeparam>
  /// <param name="value">The value to align.</param>
  /// <param name="alignment">The alignment.</param>
  /// <returns>The aligned value.</returns>
  template< typename T >
  constexpr __forceinline T align(T value, std::uint32_t alignment) noexcept
    requires std::unsigned_integral< T >
  {
    if ( alignment == 0 )
      return 0;

    const auto remainder = value % static_cast<T>(alignment);
    if ( remainder == 0 )
      return value;

    const auto adjustment = static_cast<T>(alignment) - remainder;
    if ( value > std::numeric_limits<T>::max() - adjustment )
      return 0;

    return value + adjustment;
  }

}  // namespace vulkan::pe