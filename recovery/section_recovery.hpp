#pragma once

#include "../includes.hpp"

namespace vulkan::recovery
{
  inline constexpr std::size_t page_size = 0x1000;

  struct section_identity_t
  {
    std::uintptr_t image_base = 0;
    std::uint32_t section_rva = 0;
    std::uint32_t raw_size = 0;
    std::string name;
  };

  class partial_dump_store_t
  {
  public:
    explicit partial_dump_store_t(std::string path);

    [[nodiscard]] bool enabled() const noexcept;
    void restore_section(
      const section_identity_t &section,
      std::uint32_t raw_offset,
      std::vector<std::uint8_t> &image_buffer,
      std::vector<std::uint8_t> &pages_read,
      std::size_t &pages_copied) const;

    void save_page(
      const section_identity_t &section,
      std::size_t page_index,
      const std::uint8_t *page_data,
      std::size_t bytes_to_write) const;

  private:
    std::string _path;
  };

  class section_recovery_t
  {
  public:
    section_recovery_t(
      section_identity_t identity,
      std::uintptr_t remote_base,
      std::uint32_t raw_offset,
      std::uint32_t raw_size,
      std::vector<std::uint8_t> &image_buffer,
      const partial_dump_store_t *partial_store);

    [[nodiscard]] bool valid() const noexcept;
    [[nodiscard]] bool complete() const noexcept;
    [[nodiscard]] double percent() const noexcept;
    [[nodiscard]] bool reached_target_coverage() const noexcept;
    bool copy_once(bool code_section);
    void log_progress(bool force) const;
    void log_final() const;

  private:
    [[nodiscard]] bool copy_page(std::size_t page_index, bool code_section);
    void walk_readable_region(const MEMORY_BASIC_INFORMATION &info, bool code_section, bool &made_progress);

    section_identity_t _identity;
    std::uintptr_t _remote_base = 0;
    std::uint32_t _raw_offset = 0;
    std::uint32_t _raw_size = 0;
    std::vector<std::uint8_t> &_buffer;
    const partial_dump_store_t *_partial_store = nullptr;
    bool _valid = false;
    std::size_t _total_pages = 0;
    std::vector<std::uint8_t> _pages_read;
    std::size_t _pages_copied = 0;
    std::size_t _query_failures = 0;
    std::size_t _inaccessible_pages = 0;
    std::size_t _read_failures = 0;
    std::size_t _passes = 0;
    mutable int _last_reported_tenth = -1;
  };
}
