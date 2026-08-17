#pragma once
#include "includes.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "memory.hpp"
#include "pe/image.hpp"

class Dumper final
{
public:
  explicit Dumper(HMODULE module);

  static std::unique_ptr<vulkan::pe::image> dump();

private:
  struct export_entry_t
  {
    std::string module_name;
    std::string name;
  };

  struct import_candidate_t
  {
    std::uint32_t slot_rva = 0;
    export_entry_t export_entry;
  };

  struct import_patch_stats_t
  {
    std::size_t rip_indirect_call = 0;
    std::size_t rip_indirect_jump = 0;
    std::size_t rip_indirect_push = 0;
    std::size_t rip_load = 0;
    std::size_t rip_lea = 0;
    std::size_t rip_compare = 0;
    std::size_t absolute_load = 0;

    [[nodiscard]] std::size_t total() const noexcept;
  };

  std::unique_ptr<vulkan::pe::image> _image;

  std::vector<import_candidate_t> collect_import_candidates(const std::vector<Mem::ModuleInfo_t> &modules) const;
  std::unordered_map<std::uint32_t, std::uint32_t> rebuild_import_directory(const std::vector<import_candidate_t> &imports);
  import_patch_stats_t patch_import_references(const std::unordered_map<std::uint32_t, std::uint32_t> &iat_map);
  void resolve_sections();
  bool resolve_imports(const std::vector<Mem::ModuleInfo_t> &modules);
  void resolve_runtime_functions();
};