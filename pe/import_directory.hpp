#pragma once

#include <windows.h>

#include <memory>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <vector>

namespace vulkan::pe
{
  class image;

  /// <summary>
  /// The abstract representation of an import directory in a PE image.
  /// </summary>
  class import_directory final
  {
    friend class image;

  public:
    /// <summary>
    /// An abstract representation of an import in the import directory.
    /// </summary>
    struct import_t
    {
      /// <summary>
      /// Creates a new import.
      /// </summary>
      /// <param name="module_name">The name of the module that the import is from.</param>
      /// <param name="import_name">The name of the import.</param>
      /// <param name="iat_rva">The relative virtual address of the import address table.</param>
      explicit import_t(const std::string_view module_name, const std::string_view import_name, std::uintptr_t iat_rva);

      /// <summary>
      /// The name of the module that the import is from.
      /// </summary>
      std::string module_name;

      /// <summary>
      /// The name of the import.
      /// </summary>
      std::string import_name;

      /// <summary>
      /// The relative virtual address of the import address table.
      /// </summary>
      std::uintptr_t iat_rva;
    };

  private:
    std::unordered_map< std::string, std::vector< import_t > > _imports;


    PIMAGE_DATA_DIRECTORY _import_data_directory = nullptr;
    PIMAGE_DATA_DIRECTORY _iat_data_directory = nullptr;


    /// <summary>
    /// Creates a new import directory class instance.
    /// </summary>
    explicit import_directory() noexcept;

    /// <summary>
    /// Refreshes the import directory.
    /// </summary>
    void refresh(image *img);

  public:
    /// <summary>
    /// Returns the IAT data directory.
    /// </summary>
    PIMAGE_DATA_DIRECTORY iat_data_directory() const noexcept;

    /// <summary>
    /// Gets the import data directory.
    /// </summary>
    PIMAGE_DATA_DIRECTORY import_data_directory() const noexcept;

    /// <summary>
    /// Returns the imports in the import directory.
    /// </summary>
    std::vector< import_t > imports() const;

    /// <summary>
    /// Clears the import directory.
    /// </summary>
    void clear() noexcept;

    /// <summary>
    /// Adds a new import to the import directory.
    /// </summary>
    /// <param name="module_name">The name of the module that the import is from.</param>
    /// <param name="import_name">The name of the import.</param>
    /// <param name="iat_rva">The relative virtual address of the import address table.</param>
    void add(const std::string_view module_name, const std::string_view import_name, std::uintptr_t iat_rva);

    /// <summary>
    /// Recompiles the import directory into a new section.
    /// </summary>
    /// <param name="img">The image the import directory is associated with.</param>
    /// <param name="section_name">The name of the section to recompile to.</param>
    /// <returns>True when the import directory was recompiled successfully.</returns>
    bool recompile(image *img, const std::string_view section_name);
  };
}  // namespace vulkan::pe