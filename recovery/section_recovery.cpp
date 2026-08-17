#include "section_recovery.hpp"

#include "../dump_control.hpp"
#include "../memory.hpp"
#include "../util.hpp"

#include <limits>

namespace vulkan::recovery
{
  namespace
  {
    constexpr std::uint32_t kPartialMagic = 0x31475056; // VPG1
    constexpr std::uint32_t kPartialVersion = 1;
    constexpr std::size_t kMaxSectionNameSize = 4096;

    struct partial_page_header_t
    {
      std::uint32_t magic = kPartialMagic;
      std::uint32_t version = kPartialVersion;
      std::uint64_t image_base = 0;
      std::uint32_t section_rva = 0;
      std::uint32_t raw_size = 0;
      std::uint32_t page_index = 0;
      std::uint32_t byte_count = 0;
      std::uint32_t section_name_size = 0;
    };

    constexpr std::size_t page_count_for_size(std::size_t byte_count) noexcept
    {
      return byte_count / page_size + (byte_count % page_size != 0 ? 1 : 0);
    }

    bool checked_add(std::size_t left, std::size_t right, std::size_t &result) noexcept
    {
      if ( right > std::numeric_limits<std::size_t>::max() - left )
        return false;

      result = left + right;
      return true;
    }

    bool checked_multiply(std::size_t left, std::size_t right, std::size_t &result) noexcept
    {
      if ( left != 0 && right > std::numeric_limits<std::size_t>::max() / left )
        return false;

      result = left * right;
      return true;
    }

    bool checked_add_address(std::uintptr_t address, std::size_t byte_count, std::uintptr_t &result) noexcept
    {
      if ( byte_count > std::numeric_limits<std::uintptr_t>::max() - address )
        return false;

      result = address + byte_count;
      return true;
    }

    void saturating_increment(std::size_t &value) noexcept
    {
      if ( value != std::numeric_limits<std::size_t>::max() )
        ++value;
    }

    void saturating_add(std::size_t &value, std::size_t amount) noexcept
    {
      if ( amount > std::numeric_limits<std::size_t>::max() - value )
        value = std::numeric_limits<std::size_t>::max();
      else
        value += amount;
    }

    bool read_exact(
      std::ifstream &file,
      void *destination,
      std::size_t byte_count,
      std::uintmax_t &remaining_bytes)
    {
      if ( byte_count > remaining_bytes ||
        byte_count > static_cast<std::size_t>(std::numeric_limits<std::streamsize>::max()) )
        return false;

      if ( byte_count == 0 )
        return true;

      const auto stream_byte_count = static_cast<std::streamsize>(byte_count);
      file.read(static_cast<char *>(destination), stream_byte_count);
      if ( file.gcount() != stream_byte_count )
        return false;

      remaining_bytes -= byte_count;
      return true;
    }

    bool skip_exact(std::ifstream &file, std::size_t byte_count, std::uintmax_t &remaining_bytes)
    {
      std::array<char, 1024> scratch{};
      while ( byte_count != 0 )
      {
        const auto chunk_size = std::min(byte_count, scratch.size());
        if ( !read_exact(file, scratch.data(), chunk_size, remaining_bytes) )
          return false;

        byte_count -= chunk_size;
      }

      return true;
    }

    bool valid_page_layout(
      const partial_page_header_t &header,
      std::size_t &page_offset,
      std::size_t &expected_byte_count) noexcept
    {
      if ( header.raw_size == 0 || header.byte_count == 0 || header.byte_count > page_size )
        return false;

      const auto total_pages = page_count_for_size(header.raw_size);
      if ( header.page_index >= total_pages ||
        !checked_multiply(static_cast<std::size_t>(header.page_index), page_size, page_offset) ||
        page_offset >= header.raw_size )
        return false;

      expected_byte_count = std::min<std::size_t>(page_size, static_cast<std::size_t>(header.raw_size) - page_offset);
      return header.byte_count == expected_byte_count;
    }

    bool is_readable_protection(const MEMORY_BASIC_INFORMATION &info) noexcept
    {
      const auto protection = info.Protect & 0xFF;
      return info.State == MEM_COMMIT && !(info.Protect & PAGE_GUARD) && protection != PAGE_NOACCESS;
    }

    std::uintptr_t region_end(const MEMORY_BASIC_INFORMATION &info) noexcept
    {
      const auto region_begin = reinterpret_cast<std::uintptr_t>(info.BaseAddress);
      std::uintptr_t end = 0;
      if ( !checked_add_address(region_begin, info.RegionSize, end) )
        return std::numeric_limits<std::uintptr_t>::max();

      return end;
    }

    std::uintptr_t advance_by_page(std::uintptr_t address, std::uintptr_t end) noexcept
    {
      const auto remaining = end - address;
      return remaining > page_size ? address + page_size : end;
    }

    bool same_section(const partial_page_header_t &header, const section_identity_t &section, const std::string &name)
    {
      return header.magic == kPartialMagic && header.version == kPartialVersion &&
        header.image_base == static_cast<std::uint64_t>(section.image_base) && header.section_rva == section.section_rva &&
        header.raw_size == section.raw_size && name == section.name;
    }
  }

  partial_dump_store_t::partial_dump_store_t(std::string path)
    : _path(std::move(path))
  {
  }

  bool partial_dump_store_t::enabled() const noexcept
  {
    return !_path.empty();
  }

  void partial_dump_store_t::restore_section(
    const section_identity_t &section,
    std::uint32_t raw_offset,
    std::vector<std::uint8_t> &image_buffer,
    std::vector<std::uint8_t> &pages_read,
    std::size_t &pages_copied) const
  {
    const auto section_size = static_cast<std::size_t>(section.raw_size);
    const auto destination_offset = static_cast<std::size_t>(raw_offset);
    if ( !enabled() || section_size == 0 || destination_offset > image_buffer.size() ||
      section_size > image_buffer.size() - destination_offset ||
      pages_read.size() != page_count_for_size(section_size) || pages_copied > pages_read.size() )
      return;

    std::ifstream file(_path, std::ios::binary);
    if ( !file )
      return;

    file.seekg(0, std::ios::end);
    const auto end_position = file.tellg();
    if ( end_position == std::ifstream::pos_type(-1) )
      return;

    const auto end_offset = static_cast<std::streamoff>(end_position);
    if ( end_offset < 0 )
      return;

    std::uintmax_t remaining_bytes = static_cast<std::uintmax_t>(end_offset);
    file.seekg(0, std::ios::beg);
    if ( !file )
      return;

    std::size_t restored_pages = 0;
    while ( remaining_bytes != 0 )
    {
      partial_page_header_t header{};
      if ( !read_exact(file, &header, sizeof(header), remaining_bytes) )
        break;

      if ( header.magic != kPartialMagic || header.version != kPartialVersion ||
        header.section_name_size > kMaxSectionNameSize || header.byte_count > page_size )
        break;

      std::size_t payload_size = 0;
      if ( !checked_add(
        static_cast<std::size_t>(header.section_name_size),
        static_cast<std::size_t>(header.byte_count),
        payload_size) || payload_size > remaining_bytes )
        break;

      std::size_t page_offset = 0;
      std::size_t expected_byte_count = 0;
      if ( !valid_page_layout(header, page_offset, expected_byte_count) )
      {
        if ( !skip_exact(file, payload_size, remaining_bytes) )
          break;

        continue;
      }

      std::string name(header.section_name_size, '\0');
      std::array<std::uint8_t, page_size> page{};
      if ( !read_exact(file, name.data(), name.size(), remaining_bytes) ||
        !read_exact(file, page.data(), expected_byte_count, remaining_bytes) )
        break;

      const auto page_index = static_cast<std::size_t>(header.page_index);
      if ( !same_section(header, section, name) || page_index >= pages_read.size() )
        continue;

      std::size_t page_destination = 0;
      std::size_t destination_end = 0;
      if ( !checked_add(destination_offset, page_offset, page_destination) ||
        !checked_add(page_destination, expected_byte_count, destination_end) ||
        destination_end > image_buffer.size() )
        continue;

      std::copy_n(page.begin(), expected_byte_count, image_buffer.begin() + page_destination);
      if ( !pages_read[page_index] )
      {
        pages_read[page_index] = 1;
        ++pages_copied;
        ++restored_pages;
      }
    }

    if ( restored_pages )
      Util::Log("Restored {} cached pages for \"{}\"", restored_pages, section.name);
  }

  void partial_dump_store_t::save_page(
    const section_identity_t &section,
    std::size_t page_index,
    const std::uint8_t *page_data,
    std::size_t bytes_to_write) const
  {
    if ( !enabled() || !page_data || section.name.size() > kMaxSectionNameSize ||
      page_index > std::numeric_limits<std::uint32_t>::max() || bytes_to_write > page_size )
      return;

    partial_page_header_t header{};
    header.image_base = section.image_base;
    header.section_rva = section.section_rva;
    header.raw_size = section.raw_size;
    header.page_index = static_cast<std::uint32_t>(page_index);
    header.byte_count = static_cast<std::uint32_t>(bytes_to_write);
    header.section_name_size = static_cast<std::uint32_t>(section.name.size());

    std::size_t page_offset = 0;
    std::size_t expected_byte_count = 0;
    if ( !valid_page_layout(header, page_offset, expected_byte_count) )
      return;

    std::ofstream file(_path, std::ios::binary | std::ios::app);
    if ( !file )
      return;

    file.write(reinterpret_cast<const char *>(&header), sizeof(header));
    file.write(section.name.data(), static_cast<std::streamsize>(section.name.size()));
    file.write(reinterpret_cast<const char *>(page_data), static_cast<std::streamsize>(expected_byte_count));
    file.flush();
    if ( !file )
      Util::Log("Failed to write cached page {} for \"{}\"", page_index, section.name);
  }

  section_recovery_t::section_recovery_t(
    section_identity_t identity,
    std::uintptr_t remote_base,
    std::uint32_t raw_offset,
    std::uint32_t raw_size,
    std::vector<std::uint8_t> &image_buffer,
    const partial_dump_store_t *partial_store)
    : _identity(std::move(identity)),
      _remote_base(remote_base),
      _raw_offset(raw_offset),
      _raw_size(raw_size),
      _buffer(image_buffer),
      _partial_store(partial_store)
  {
    const auto destination_offset = static_cast<std::size_t>(_raw_offset);
    const auto section_size = static_cast<std::size_t>(_raw_size);
    std::uintptr_t section_end = 0;
    if ( section_size == 0 || destination_offset > _buffer.size() ||
      section_size > _buffer.size() - destination_offset ||
      !checked_add_address(_remote_base, section_size, section_end) )
      return;

    _total_pages = page_count_for_size(section_size);
    _pages_read.assign(_total_pages, 0);
    _valid = true;

    if ( _partial_store )
      _partial_store->restore_section(_identity, _raw_offset, _buffer, _pages_read, _pages_copied);
  }

  bool section_recovery_t::valid() const noexcept
  {
    return _valid;
  }

  bool section_recovery_t::complete() const noexcept
  {
    return !_valid || _pages_copied >= _total_pages;
  }

  double section_recovery_t::percent() const noexcept
  {
    if ( !_valid )
      return 0.0;

    if ( !_total_pages )
      return 100.0;

    return static_cast<double>(_pages_copied) * 100.0 / static_cast<double>(_total_pages);
  }

  bool section_recovery_t::reached_target_coverage() const noexcept
  {
    return _valid && percent() >= DumpControl::recovery_options.target_coverage;
  }

  bool section_recovery_t::copy_page(std::size_t page_index, bool code_section)
  {
    if ( !_valid || page_index >= _pages_read.size() || _pages_read[page_index] )
      return false;

    std::size_t page_offset = 0;
    if ( !checked_multiply(page_index, page_size, page_offset) || page_offset >= _raw_size )
      return false;

    const auto bytes_to_read = std::min<std::size_t>(page_size, static_cast<std::size_t>(_raw_size) - page_offset);
    std::size_t destination_offset = 0;
    std::size_t destination_end = 0;
    std::uintptr_t remote_address = 0;
    if ( !checked_add(static_cast<std::size_t>(_raw_offset), page_offset, destination_offset) ||
      !checked_add(destination_offset, bytes_to_read, destination_end) || destination_end > _buffer.size() ||
      !checked_add_address(_remote_base, page_offset, remote_address) )
      return false;

    auto *destination = _buffer.data() + destination_offset;
    if ( !Mem::ReadProcessMemory(remote_address, destination, bytes_to_read) )
    {
      saturating_increment(_read_failures);
      return false;
    }

    _pages_read[page_index] = 1;
    ++_pages_copied;

    if ( _partial_store && code_section )
      _partial_store->save_page(_identity, page_index, destination, bytes_to_read);

    if ( code_section )
      log_progress(false);

    return true;
  }

  void section_recovery_t::walk_readable_region(const MEMORY_BASIC_INFORMATION &info, bool code_section, bool &made_progress)
  {
    if ( !_valid )
      return;

    const auto section_begin = _remote_base;
    std::uintptr_t section_end = 0;
    if ( !checked_add_address(section_begin, _raw_size, section_end) )
      return;

    const auto readable_begin = std::max(section_begin, reinterpret_cast<std::uintptr_t>(info.BaseAddress));
    const auto readable_end = std::min(section_end, region_end(info));
    if ( readable_begin >= readable_end )
      return;

    const auto first_page = static_cast<std::size_t>(readable_begin - section_begin) / page_size;
    const auto last_page = page_count_for_size(static_cast<std::size_t>(readable_end - section_begin));
    const auto page_limit = std::min(last_page, _total_pages);
    for ( auto page = first_page; page < page_limit; ++page )
      made_progress = copy_page(page, code_section) || made_progress;
  }

  bool section_recovery_t::copy_once(bool code_section)
  {
    if ( !_valid )
      return false;

    bool made_progress = false;
    saturating_increment(_passes);

    std::uintptr_t section_end = 0;
    if ( !checked_add_address(_remote_base, _raw_size, section_end) )
      return false;

    for ( auto address = _remote_base; address < section_end; )
    {
      MEMORY_BASIC_INFORMATION info{};
      if ( !Mem::QueryMemory(address, info) )
      {
        saturating_increment(_query_failures);
        address = advance_by_page(address, section_end);
        continue;
      }

      const auto next_page = advance_by_page(address, section_end);
      const auto next_region = std::min(section_end, std::max(next_page, region_end(info)));
      if ( !is_readable_protection(info) )
      {
        const auto inaccessible_begin = std::max(address, reinterpret_cast<std::uintptr_t>(info.BaseAddress));
        const auto inaccessible_end = std::min(section_end, next_region);
        if ( inaccessible_begin < inaccessible_end )
          saturating_add(
            _inaccessible_pages,
            page_count_for_size(static_cast<std::size_t>(inaccessible_end - inaccessible_begin)));

        address = next_region;
        continue;
      }

      walk_readable_region(info, code_section, made_progress);
      address = next_region;
    }

    if ( !code_section && made_progress )
      log_progress(false);

    return made_progress;
  }

  void section_recovery_t::log_progress(bool force) const
  {
    const auto current_percent = percent();
    const auto tenths = static_cast<int>(current_percent * 10.0);
    if ( !force && tenths <= _last_reported_tenth )
      return;

    _last_reported_tenth = tenths;
    Util::Log(
      "{} progress: {}/{} pages ({}%)",
      _identity.name,
      _pages_copied,
      _total_pages,
      current_percent);
  }

  void section_recovery_t::log_final() const
  {
    Util::Log(
      "{} final: {}/{} pages ({}%), query_fail={}, inaccessible={}, read_fail={}, passes={}",
      _identity.name,
      _pages_copied,
      _total_pages,
      percent(),
      _query_failures,
      _inaccessible_pages,
      _read_failures,
      _passes);
  }
}
