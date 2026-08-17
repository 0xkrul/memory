#include "dumper.hpp"

using namespace vulkan;
using namespace vulkan::pe;

void Dump::Setup(std::string _dumpName)
{
  dumpName = _dumpName;
  PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)Mem::base;
  PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((uintptr_t)dos + dos->e_lfanew);
  PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);

  DWORD fileAlignment = nt->OptionalHeader.FileAlignment;
  DWORD sectionAlignment = nt->OptionalHeader.SectionAlignment;
  DWORD headerSize = ALIGN_UP(nt->OptionalHeader.SizeOfHeaders, fileAlignment);

  imageToBuild = std::vector<uint8_t>(nt->OptionalHeader.SizeOfImage);
  std::fill(imageToBuild.begin(), imageToBuild.end(), 0);
  memcpy(imageToBuild.data(), dos, nt->OptionalHeader.SizeOfHeaders);

  dos = (PIMAGE_DOS_HEADER)imageToBuild.data();
  nt = (PIMAGE_NT_HEADERS)((uintptr_t)dos + dos->e_lfanew);
  section = IMAGE_FIRST_SECTION(nt);

  PIMAGE_SECTION_HEADER textSection = nullptr;

  DWORD rawCursor = headerSize;
  for ( int i = 0; i < nt->FileHeader.NumberOfSections; i++ )
  {
    DWORD virtSize = section[i].Misc.VirtualSize;
    DWORD rawSize = ALIGN_UP(virtSize, fileAlignment);

    section[i].PointerToRawData = rawCursor;
    section[i].SizeOfRawData = rawSize;

    if ( strcmp((char *)section[i].Name, ".text") == 0 )
    {
      textSection = &section[i];
    }
    else
    {
      BYTE *src = (BYTE *)Mem::base + section[i].VirtualAddress;
      BYTE *dst = imageToBuild.data() + rawCursor;
      memcpy(dst, src, virtSize);
    }

    rawCursor += rawSize;
  }

  if ( !textSection )
  {
    Util::Log("[DUMP] Failed to find .text section");
    return;
  }

  BYTE *src = (BYTE *)Mem::base + textSection->VirtualAddress;
  BYTE *dst = imageToBuild.data() + textSection->PointerToRawData;
  DWORD textSize = textSection->Misc.VirtualSize;

  bool loadedFromDisk = LoadExistingDump(imageToBuild, textSection);
  if ( !loadedFromDisk )
  {
    Util::Log("[DUMP] No existing dump found, starting fresh");
    WriteDumpToDisk();

    for ( uintptr_t addr = (uintptr_t)src; addr < (uintptr_t)src + textSize; )
    {
      MEMORY_BASIC_INFORMATION mbi;
      if ( VirtualQuery((void *)addr, &mbi, sizeof(mbi)) == 0 )
      {
        addr += 0x1000;
        continue;
      }

      MissingRegion_t region{};
      region.address = (uintptr_t)mbi.BaseAddress;
      region.offset = addr - (uintptr_t)src;
      region.size = mbi.RegionSize;
      missingRegions.push_back(region);
      addr += mbi.RegionSize;
    }
  }
  else
  {
    // kinda optional but split the missing regions by real memory regions (the disk considers only null bytes regions)
    std::vector<MissingRegion_t> newRegions(missingRegions.size());
    for ( MissingRegion_t &region : missingRegions )
    {
      uintptr_t currentAddr = region.address;
      uintptr_t endAddr = region.address + region.size;

      while ( currentAddr < endAddr )
      {
        MEMORY_BASIC_INFORMATION mbi;
        if ( VirtualQuery((void *)currentAddr, &mbi, sizeof(mbi)) == 0 )
        {
          currentAddr += 0x1000;
          continue;
        }

        size_t regionSize = std::min((uintptr_t)mbi.RegionSize, endAddr - currentAddr);
        bool readable = mbi.Protect == PAGE_EXECUTE_READ;
        if ( readable )
        {
          // copy accessible region directly
          uintptr_t offsetFromTextBase = currentAddr - (uintptr_t)src;
          memcpy(dst + offsetFromTextBase, (void *)currentAddr, regionSize);
          Util::Log("[DUMP] Copied accessible region at offset: {:X}, size: {:X}", offsetFromTextBase, regionSize);
        }
        else
        {
          // add non-accessible region to new regions list
          MissingRegion_t newRegion{};
          newRegion.address = currentAddr;
          newRegion.offset = currentAddr - (uintptr_t)src;
          newRegion.size = regionSize;
          newRegions.push_back(newRegion);
        }

        currentAddr += regionSize;
      }
    }

    missingRegions.clear();
    missingRegions = std::move(newRegions);
  }

  WriteDumpToDisk();

  int stableCounter = 0;
  size_t missingCount = missingRegions.size();
  while ( missingRegions.size() > 0 )
  {
    std::vector<MissingRegion_t> failedRegions(missingCount);
    int processedCount = 0;
    size_t totalRegions = missingRegions.size();
    Util::Log("[DUMP] Total regions to process: {}", totalRegions);
    for ( MissingRegion_t &region : missingRegions )
    {
      processedCount++;
      int percent = (int)((processedCount * 100) / totalRegions);

      MEMORY_BASIC_INFORMATION mbi;
      if ( VirtualQuery((void *)region.address, &mbi, sizeof(mbi)) == 0 )
      {
        Util::Log("[DUMP] VirtualQuery failed at offset: {:X}", region.offset);
        continue;
      }

      if ( mbi.Protect == PAGE_NOACCESS )
      {
#ifdef FORCE_DECRYPT
        Util::Log("[DUMP] Decrypting page at offset: {:X} ({}/{})", offset, processedCount, totalRegions);
        if ( !DecryptPage((PVOID)((uintptr_t)mbi.BaseAddress + rand() % 0x1000)) )
        {
          Util::Log("[DUMP] DecryptPage failed");
          failedRegions.push_back(addr);
          continue;
        }

        // Verify if page is decrypted
        MEMORY_BASIC_INFORMATION mbi2;
        VirtualQuery(mbi.BaseAddress, &mbi2, sizeof(mbi2));

        if ( mbi2.Protect == PAGE_EXECUTE_READ )
        {
          try
          {
            memcpy(dst + offset, mbi.BaseAddress, mbi.RegionSize);
            // Write this region to disk immediately
            WriteTextSectionToDisk(dumpFilename, image, textSection, offset, mbi.RegionSize);
            Util::Log("[DUMP] Successfully decrypted and wrote region at offset: {:X}", offset);
          }
          catch ( ... )
          {
            Util::Log("[DUMP] Exception while copying decrypted page at offset: {:X}", offset);
            failedRegions.push_back(addr);
            continue;
          }
        }
        else
        {
          Util::Log("[DUMP] Failed offset: {:X} with protection: {:X}", offset, mbi2.Protect);
          failedRegions.push_back(addr);
        }
#endif
      }
      else
      {
        memcpy(dst + region.offset, (void *)region.address, mbi.RegionSize);
        Util::Log("[DUMP] Success at offset: {:X} ({}%)", region.offset, percent);
        region.size = 0; // mark as success
      }
    }

    std::ranges::remove_if(missingRegions, [](const MissingRegion_t &region) { return region.size == 0; });
    if ( missingRegions.size() == missingCount )
    {
      stableCounter++;
      Util::Log("[DUMP] No progress made in this iteration, stable counter: {}", stableCounter);
      if ( stableCounter >= 10 )
      {
        Util::Log("[DUMP] Stable counter exceeded limit, aborting further attempts");
        break;
      }
    }
    else
    {
      stableCounter = 0;
      missingCount = missingRegions.size();
    }

    Sleep(10000);
  }

  nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0;
  nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0;

  // Write final complete dump
  WriteDumpToDisk();
  Util::Log("[DUMP] Dumping completed");
}

void Dump::WriteDumpToDisk()
{
  std::ofstream outfile(dumpName, std::ios::binary | std::ios::out);
  outfile.write((char *)imageToBuild.data(), imageToBuild.size());
  outfile.close();
  Util::Log("[DUMP] Written dump to disk: {}", dumpName);
}

bool Dump::DecryptPage(PVOID pageAddr, PCONTEXT ctx)
{
  DWORD64 imageBase = 0;
  PVOID handlerData;
  DWORD64 establisherFrame;

  PRUNTIME_FUNCTION functionEntry = RtlLookupFunctionEntry((DWORD64)pageAddr, &imageBase, NULL);
  if ( !functionEntry )
  {
    Util::Log("RtlLookupFunctionEntry failed for pageAddr: {}", pageAddr);
    return false;
  }

  CONTEXT context{};

  if ( ctx )
  {
    context = *ctx;
  }
  else
  {
    RtlCaptureContext(&context);
    // dark magic buffer 
    static PVOID NullBuffer = malloc(0x1000);
    for ( int i = 0; i < 16; ++i )
      *((PVOID *)&context.Rax + i) = NullBuffer;
    context.Rip = (uint64_t)pageAddr;
  }

  try
  {
    RtlVirtualUnwind(UNW_FLAG_NHANDLER, imageBase, context.Rip, functionEntry, &context, &handlerData, &establisherFrame, NULL);
  }
  catch ( ... )
  {
    return false;
  }
  return true;
}

bool Dump::LoadExistingDump(std::vector<uint8_t> &imageToBuild, PIMAGE_SECTION_HEADER memoryTextSection)
{
  std::ifstream infile(dumpName, std::ios::binary | std::ios::in);
  if ( !infile.is_open() )
    return false;

  infile.seekg(0, std::ios::end);
  size_t fileSize = infile.tellg();
  infile.seekg(0, std::ios::beg);

  if ( fileSize != imageToBuild.size() )
  {
    Util::Log("[DUMP] Existing dump size mismatch, recreating");
    infile.close();
    return false;
  }

  std::vector<uint8_t> diskImage(fileSize);
  infile.read((char *)diskImage.data(), fileSize);
  infile.close();

  Util::Log("[DUMP] Loaded existing dump, analyzing missing regions...");

  // find the disk dump .text section 
  PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)diskImage.data();
  PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((uintptr_t)dos + dos->e_lfanew);
  PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
  PIMAGE_SECTION_HEADER textSectionDump = nullptr;
  for ( int i = 0; i < nt->FileHeader.NumberOfSections; i++ )
  {
    if ( strcmp((char *)section[i].Name, ".text") == 0 )
    {
      textSectionDump = &section[i];
      break;
    }
  }

  if ( !textSectionDump )
    return false;

  if ( memoryTextSection->Misc.VirtualSize != textSectionDump->Misc.VirtualSize )
  {
    Util::Log("[DUMP] .text section size mismatch in existing dump, recreating");
    return false;
  }

  size_t textSize = textSectionDump->Misc.VirtualSize;
  uintptr_t memoryTextStart = Mem::base + memoryTextSection->VirtualAddress;
  uintptr_t dumpTextStart = (uintptr_t)diskImage.data() + textSectionDump->PointerToRawData;

  missingRegions.clear();
  // check the dump for 0x1000 or more consecutive 0x00 bytes
  size_t sizeMissing = 0;
  for ( uintptr_t offset = 0; offset < textSize; )
  {
    size_t zeroCount = 0;
    uintptr_t regionStart = offset;
    while ( offset < textSize && *(uint8_t *)(dumpTextStart + offset) == 0x00 )
    {
      zeroCount++;
      offset++;
    }

    if ( zeroCount >= 0x1000 )
    {
      MissingRegion_t region{};
      region.address = memoryTextStart + regionStart;
      region.offset = regionStart;
      region.size = zeroCount;
      sizeMissing += zeroCount;
      missingRegions.push_back(region);
    }

    if ( zeroCount == 0 )
      offset++;
  }

  for ( uintptr_t offset = 0; offset < textSize; offset++ )
  {
    // copy non-missing regions from dump to imageToBuild
    bool isMissing = false;
    for ( const auto &region : missingRegions )
    {
      if ( offset >= region.offset && offset < region.offset + region.size )
      {
        isMissing = true;
        break;
      }
    }
    if ( !isMissing )
      *(uint8_t *)(imageToBuild.data() + textSectionDump->PointerToRawData + offset) = *(uint8_t *)(dumpTextStart + offset);
  }

  int percent = (int)((sizeMissing * 100) / textSize);
  Util::Log("[DUMP] {} missing regions found, total missing size: {} bytes ({}%)", missingRegions.size(), sizeMissing, percent);
  return true;
}

void Dump::WriteTextSectionToDisk(const char *filename, const std::vector<uint8_t> &image, PIMAGE_SECTION_HEADER textSection, uintptr_t offset, size_t size)
{
  std::fstream file(filename, std::ios::binary | std::ios::in | std::ios::out);
  if ( !file.is_open() )
  {
    Util::Log("[DUMP] Failed to open file for writing");
    return;
  }

  file.seekp(textSection->PointerToRawData + offset, std::ios::beg);
  file.write((const char *)(image.data() + textSection->PointerToRawData + offset), size);
  file.flush();
  file.close();

  Util::Log("[DUMP] Written {} bytes at offset {:X} to disk", size, offset);
}

Dumper::Dumper(uintptr_t base)
{
  // basic pe 
  imageBase = base;
  nt = (PIMAGE_NT_HEADERS64)(imageBase + ((PIMAGE_DOS_HEADER)imageBase)->e_lfanew);
  optionalHeader = &nt->OptionalHeader;
  firstSection = IMAGE_FIRST_SECTION(nt);

  // imports
  importDataDir = &optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  iatDataDir = &optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
  exceptionDataDir = &optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

  importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(imageBase + importDataDir->VirtualAddress);
  auto importEnd = (PIMAGE_IMPORT_DESCRIPTOR)(imageBase + importDataDir->VirtualAddress + importDataDir->Size);
  iat = (uintptr_t *)(imageBase + iatDataDir->VirtualAddress);


  for ( ; importDescriptor < importEnd && importDescriptor->Name; ++importDescriptor )
  {
    const char *dllName = (const char *)(imageBase + importDescriptor->Name);
    PIMAGE_THUNK_DATA lookupTable =
      importDescriptor->OriginalFirstThunk
      ? (PIMAGE_THUNK_DATA)(imageBase + importDescriptor->OriginalFirstThunk)
      : (PIMAGE_THUNK_DATA)(imageBase + importDescriptor->FirstThunk);
    PIMAGE_THUNK_DATA addressTable = (PIMAGE_THUNK_DATA)(imageBase + importDescriptor->FirstThunk);

    for ( size_t i = 0; lookupTable[i].u1.AddressOfData; ++i )
    {
      ImportEntry_t entry{};
      entry.dllName = dllName;
      entry.iatRVA = importDescriptor->FirstThunk + i * sizeof(uintptr_t);

      if ( lookupTable[i].u1.Ordinal & IMAGE_ORDINAL_FLAG64 )
      {
        entry.ordinal = IMAGE_ORDINAL64(lookupTable[i].u1.Ordinal);
        entry.isOrdinal = true;
      }
      else
      {
        auto ibn = (PIMAGE_IMPORT_BY_NAME)(imageBase + lookupTable[i].u1.AddressOfData);
        entry.importName = ibn->Name;
        entry.isOrdinal = false;
      }

      imports.push_back(entry);
    }
  }

  // just copy the header 
  image = std::vector<uint8_t>(optionalHeader->SizeOfImage);
  DWORD sizeOfHeader = optionalHeader->SizeOfHeaders;
  std::copy((uint8_t *)imageBase, (uint8_t *)imageBase + sizeOfHeader, image.data());

  // TODO: possibly rebase relocs
}

Dumper::Dumper(HMODULE module)
{
  _image = image::create(module);
}

void Dumper::Run(const std::string &outputFilename)
{
  ResolveSections();
  ResolveImports();
  ResolveRuntimeFunctions();
  CalculateChecksum();

  std::ofstream outfile(outputFilename, std::ios::binary | std::ios::out);
  outfile.write((char *)image.data(), image.size());
  outfile.close();
  Util::Log("[DUMPER] Written dumped image to disk: {}", outputFilename);
}

void Dumper::ResolveSections()
{
  // iterate sections and copy them over
  DWORD fileAlignment = optionalHeader->FileAlignment;

  for ( PIMAGE_SECTION_HEADER section = firstSection; section < firstSection + nt->FileHeader.NumberOfSections; section++ )
  {
    if ( !section->PointerToRawData || !section->SizeOfRawData )
      continue;

    const char *name = reinterpret_cast<const char *>(section->Name);
    uintptr_t absoluteAddress = optionalHeader->ImageBase + section->VirtualAddress;

    Util::Log("[DUMPER] Resolving section: {} @ 0x{:X} - {} bytes", name, absoluteAddress, section->Misc.VirtualSize);

    const bool isCodeSection = (section->Characteristics & IMAGE_SCN_CNT_CODE) != 0;
    if ( !isCodeSection )
    {
      // for non-code sections, just copy the data directly
      std::copy(
        (uint8_t *)absoluteAddress,
        (uint8_t *)absoluteAddress + section->SizeOfRawData,
        image.data() + section->PointerToRawData);
    }
    else
    {
      // more complex handling for code sections 

      // fill with NOPs 
      std::fill(image.data() + section->PointerToRawData, image.data() + section->PointerToRawData + section->SizeOfRawData, 0x90);

      std::unordered_set<uintptr_t> processedPages;
      const auto totalPages = (section->Misc.VirtualSize + 0xFFF) / 0x1000;

      uint32_t stableLimit = 100;
      uint32_t stableCounter = 0;
      while ( stableCounter < stableLimit && processedPages.size() < totalPages )
      {
        size_t processedBefore = processedPages.size();

        for ( uint32_t page = 0; page < totalPages; page++ )
        {
          if ( processedPages.contains(page) )
            continue;

          uint32_t pageOffset = page * 0x1000;

          MEMORY_BASIC_INFORMATION mbi{};
          if ( VirtualQuery((void *)(absoluteAddress + pageOffset), &mbi, sizeof(mbi)) == 0 )
          {
            Util::Log("[DUMPER] VirtualQuery failed for page at section: {} page: {}", name, page);
            continue;
          }

          if ( !(mbi.Protect & PAGE_NOACCESS) )
          {
            const auto percent = (float)processedPages.size() / totalPages * 100.f;
            Util::Log("[DUMPER] Read page @ 0x{:X} ({}/{}) = {:.3f}%", absoluteAddress + pageOffset, processedPages.size(), totalPages, percent);

            std::copy(
              (uint8_t *)(absoluteAddress + pageOffset),
              (uint8_t *)(absoluteAddress + pageOffset + mbi.RegionSize),
              image.data() + section->PointerToRawData + pageOffset);

            // mark all pages of the region as processed
            for ( uint32_t p = 0; p < (mbi.RegionSize + 0xFFF) / 0x1000; p++ )
              processedPages.insert(page + p);
          }
        }

        if ( processedPages.size() == processedBefore )
        {
          stableCounter++;
          if ( stableCounter % 10 == 0 )
          {
            Util::Log("[DUMPER] No progress: {}, stable counter: {}/{}", name, stableCounter, stableLimit);
          }
        }
        else
        {
          stableCounter = 0;
        }

        // add a small delay to avoid busy looping
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
      }
    }
  }

  Util::Log("[DUMPER] Finished resolving sections");
}

void Dumper::ResolveImports()
{
  std::vector<Mem::ModuleInfo_t> loadedModules = Mem::GetLoadedModules();

  std::unordered_map<uintptr_t, ExportEntry_t> exportMap, importMap;

  // load the exports for all loaded modules, disgustingly
  for ( const Mem::ModuleInfo_t &mod : loadedModules )
  {
    HMODULE hMod = (HMODULE)mod.base;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)mod.base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(mod.base + dos->e_lfanew);
    PIMAGE_DATA_DIRECTORY exportDirData = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if ( exportDirData->VirtualAddress == 0 || exportDirData->Size == 0 )
      continue;
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)(mod.base + exportDirData->VirtualAddress);
    DWORD *funcAddresses = (DWORD *)(mod.base + exportDir->AddressOfFunctions);
    WORD *ordinals = (WORD *)(mod.base + exportDir->AddressOfNameOrdinals);
    DWORD *names = (DWORD *)(mod.base + exportDir->AddressOfNames);
    for ( DWORD i = 0; i < exportDir->NumberOfNames; i++ )
    {
      ExportEntry_t entry{};
      entry.module = hMod;
      entry.exportName = (const char *)(mod.base + names[i]);
      WORD ordinalIndex = ordinals[i];
      entry.ordinal = exportDir->Base + ordinalIndex;
      entry.rva = funcAddresses[ordinalIndex];
      exportMap[entry.rva] = entry;
    }
  }

  // find .rdata section to write IAT
  PIMAGE_SECTION_HEADER rdataSection = nullptr;
  for ( PIMAGE_SECTION_HEADER section = firstSection; section < firstSection + nt->FileHeader.NumberOfSections; section++ )
  {
    if ( strcmp((char *)section->Name, ".rdata") == 0 )
    {
      rdataSection = section;
      break;
    }
  }

  if ( !rdataSection )
  {
    Util::Log("[DUMPER] Failed to find .rdata section for IAT writing");
    return;
  }


  // iterate over the section
  uintptr_t rdataStart = optionalHeader->ImageBase + rdataSection->VirtualAddress;
  for ( uintptr_t i = 0; i < rdataSection->Misc.VirtualSize - sizeof(uintptr_t); i += sizeof(uintptr_t) )
  {
    uintptr_t *possibleIATEntry = (uintptr_t *)(rdataStart + i);
    uintptr_t possibleRVA = *possibleIATEntry - optionalHeader->ImageBase;
    if ( exportMap.contains(possibleRVA) )
    {
      ExportEntry_t &exportEntry = exportMap[possibleRVA];
      // find corresponding import entry
      auto it = std::find_if(imports.begin(), imports.end(), [&](const ImportEntry_t &imp)
      {
        if ( imp.isOrdinal )
        {
          return imp.ordinal == exportEntry.ordinal;
        }
        else
        {
          return imp.importName == exportEntry.exportName;
        }
      });

      if ( it != imports.end() )
      {
        // write the IAT entry
        uintptr_t iatRVA = it->iatRVA;
        uintptr_t iatOffset = 0;
        // find the offset in our image
        for ( PIMAGE_SECTION_HEADER section = firstSection; section < firstSection + nt->FileHeader.NumberOfSections; section++ )
        {
          if ( iatRVA >= section->VirtualAddress && iatRVA < section->VirtualAddress + section->SizeOfRawData )
          {
            iatOffset = section->PointerToRawData + (iatRVA - section->VirtualAddress);
            break;
          }
        }
        if ( iatOffset != 0 )
        {
          uintptr_t *iatEntryInImage = (uintptr_t *)(image.data() + iatOffset);
          *iatEntryInImage = optionalHeader->ImageBase + exportEntry.rva;
          Util::Log("[DUMPER] Resolved import: {}!{} at IAT RVA: 0x{:X}", it->dllName, it->importName.empty() ? std::to_string(it->ordinal) : it->importName, it->iatRVA);
        }
      }
    }
  }

  // TODO: add imports to IAT and extend the section 
  // TODO: patch references to exported routines
  // FF 15 ? ? ? ?
  // 48 FF 25 ? ? ? ?
}

void Dumper::ResolveRuntimeFunctions()
{
  if ( !exceptionDataDir->VirtualAddress || !exceptionDataDir->Size )
  {
    Util::Log("[DUMPER] No exception directory found, skipping runtime function resolution");
    return;
  }

  for ( auto rva = exceptionDataDir->VirtualAddress; rva < exceptionDataDir->VirtualAddress + exceptionDataDir->Size; rva += sizeof(RUNTIME_FUNCTION) )
  {
    uint32_t offset = RvaToOffset(rva);
    if ( !offset )
      continue;

    PIMAGE_RUNTIME_FUNCTION_ENTRY entry = (PIMAGE_RUNTIME_FUNCTION_ENTRY)(imageBase + rva);
    if ( entry->UnwindInfoAddress && entry->BeginAddress && entry->EndAddress )
      continue;

    struct unwind_info_t
    {
      std::uint8_t version : 3;
      std::uint8_t flags : 5;

      // No need to implement the rest, as we don't need it.
    };

    unwind_info_t *unwindInfo = (unwind_info_t *)(imageBase + entry->UnwindInfoAddress);
    if ( unwindInfo->version == 1 )
      continue;

    Util::Log("[DUMPER] Found invalid runtime function entry at RVA: 0x{:X}, attempting to resolve", rva);
    std::fill(image.data() + offset, image.data() + offset + sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), 0x00);
  }
}

void Dumper::CalculateChecksum()
{
}

uint32_t Dumper::RvaToOffset(uint32_t rva)
{
  for ( PIMAGE_SECTION_HEADER section = firstSection; section < firstSection + nt->FileHeader.NumberOfSections; section++ )
    if ( rva >= section->VirtualAddress && rva < section->VirtualAddress + section->SizeOfRawData )
      return section->PointerToRawData + (rva - section->VirtualAddress);

  return 0;
}

std::list<std::pair<std::uintptr_t, Dumper::export_t>> Dumper::get_imports(std::vector<Mem::ModuleInfo_t> &modules)
{
  std::list< std::pair< std::uintptr_t, Dumper::export_t > > imports;

  // Export map for resolving addresses
  std::unordered_map< std::uintptr_t, Dumper::export_t > export_map;

  // Populate the export map
  for ( auto &module : modules )
  {
    auto nt_headers = reinterpret_cast<IMAGE_NT_HEADERS *>(module.base + reinterpret_cast<IMAGE_DOS_HEADER *>(module.base)->e_lfanew);
    auto directory_header = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    std::list<export_t> _exports;
    if ( directory_header.VirtualAddress )
    {
      // Define the RVA to offset helper.
      const auto rva_to_offset = [directory_header](std::uintptr_t rva) -> std::uintptr_t
      {
        return rva - directory_header.VirtualAddress;
      };

      auto export_directory = reinterpret_cast<IMAGE_EXPORT_DIRECTORY *>(
        module.base + directory_header.VirtualAddress);

      auto names =
        reinterpret_cast<std::uint32_t *>(module.base + export_directory->AddressOfNames);
      auto ordinals =
        reinterpret_cast<std::uint16_t *>(module.base + export_directory->AddressOfNameOrdinals);
      auto functions =
        reinterpret_cast<std::uint32_t *>(module.base + export_directory->AddressOfFunctions);

      for ( std::uint32_t i = 0; i < export_directory->NumberOfNames; ++i )
      {
        auto ordinal = ordinals[i];
        auto address = functions[ordinal];

        const auto name = reinterpret_cast<const char *>(
          module.base + names[i]);

        // Check if the address is forwarded.
        if ( address >= directory_header.VirtualAddress && address < directory_header.VirtualAddress + directory_header.Size )
        {
          //const std::string forward = reinterpret_cast<const char *>(
          //  reinterpret_cast<std::uintptr_t>(module) + rva_to_offset(address));

          //// Get the module name and the export name.
          //const auto dot = forward.find('.');
          //const auto module_name = forward.substr(0, dot);
          //const auto export_name = forward.substr(dot + 1);

          //if ( !m )
          //  continue;

          //const auto &exp = m->fetch_export(export_name);

          //if ( !exp )
          //  continue;

          //_exports.emplace_back(new export_t{ exp->module(), name, exp->rva, exp->ordinal() });
          continue;
        }

        export_t entry{};
        entry.mod = module;
        entry.rva = address;
        entry.export_name = name;
        entry.ordinal_value = ordinals[i];

        _exports.push_back(entry);
      }
    }

    for ( const auto &e : _exports )
    {
      export_map[(uintptr_t)e.mod.base + e.rva] = e;
    }
  }

  auto nt_headers = reinterpret_cast<const IMAGE_NT_HEADERS *>(Mem::base + reinterpret_cast<const IMAGE_DOS_HEADER *>(Mem::base)->e_lfanew);
  auto section = IMAGE_FIRST_SECTION(nt_headers);
  PIMAGE_SECTION_HEADER rdata_section = nullptr;
  for ( DWORD i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i )
  {
    const auto &name = reinterpret_cast<const char *>(section[i].Name);
    if ( strcmp(name, ".rdata") == 0 )
    {
      rdata_section = &section[i];
      break;
    }
  }

  // Get the .rdata section
  if ( rdata_section )
  {
    const auto rdata_start = Mem::base + rdata_section->VirtualAddress;
    const auto rdata_size = rdata_section->Misc.VirtualSize;
    // Iterate over each address in the section
    for ( std::size_t i = 0; i < rdata_size; ++i )
    {
      const auto &address = *reinterpret_cast<std::uintptr_t *>(rdata_start + i);

      if ( !address )
        continue;

      // Check if the address is in the export map
      if ( const auto &e = export_map.find(address); e != export_map.end() )
        imports.push_back({ address, e->second });
    }
  }

  return imports;
}

std::unique_ptr<image> Dumper::dump(std::stop_token stop_token)
{
  auto loadedModules = Mem::GetLoadedModules();
  std::unique_ptr< Dumper > d(new Dumper((HMODULE)Mem::base));

  d->resolve_sections(stop_token);
  d->resolve_imports(loadedModules);
  d->resolve_runtime_functions();

  // Refresh the image one last time. This will recalculate the checksum.
  d->_image->refresh();

  return std::move(d->_image);
}

void Dumper::resolve_sections(std::stop_token stop_token)
{
  for ( std::size_t idx = 0; idx < _image->section_headers()->count(); ++idx )
  {
    const auto &header = _image->section_headers()->at(idx);

    // Skip invalid sections
    if ( !header->PointerToRawData || !header->SizeOfRawData )
      continue;

    const auto &name = reinterpret_cast<const char *>(header->Name);
    if ( strcmp(name, ".rodata") == 0 )
    {
      Util::Log("Skipping section: \"{}\"", name);
      continue;
    }

    const auto &absolute_address = _image->image_base() + header->VirtualAddress;

    Util::Log("Resolving section: \"{}\" @ 0x{:X} - {} bytes", name, absolute_address, header->Misc.VirtualSize);

    // We need to read code sections page by page.
    if ( header->Characteristics & IMAGE_SCN_CNT_CODE )
    {
      std::unordered_set< std::uintptr_t > pages_read;
      const auto total_pages = (header->SizeOfRawData + 0xFFF) / 0x1000;
      Util::Log("Total pages to read: {} for section: \"{}\"", total_pages, name);

      // Before we do anything, fill the buffer with nop instructions.
      std::fill(
        _image->buffer().begin() + header->PointerToRawData,
        _image->buffer().begin() + header->PointerToRawData + header->SizeOfRawData,
        0x90);

      while ( !stop_token.stop_requested() && (pages_read.size() <= total_pages) )
      {
        for ( auto page = 0; page < total_pages; ++page )
        {
          const auto page_rva = page * 0x1000;
          Util::Log("Processing page {} for section: \"{}\"", page, name);

          // If we've read this page, skip.
          if ( pages_read.find(page) != pages_read.end() )
            continue;

          MEMORY_BASIC_INFORMATION mbi{};
          if ( VirtualQuery((void *)(absolute_address + page_rva), &mbi, sizeof(mbi)) == 0 )
            continue;
          
          const auto percent = static_cast<double>(pages_read.size()) / total_pages * 100.0;
          if ( percent >= 65.f && strcmp(name, ".text") == 0 )
          {
            Util::Log("Stopping section resolution at {:.3f}%", percent);
            return;
          }

          const auto offset = header->PointerToRawData + page_rva;
          // If the page is not accessible, skip.
          if ( !(mbi.Protect & PAGE_NOACCESS) )
          {
            Util::Log("Read page @ 0x{:X} ({}/{}) = {:.3f}%", absolute_address + page_rva, pages_read.size(), total_pages, percent);

            std::copy(
              (uint8_t *)(absolute_address + page_rva),
              (uint8_t *)(absolute_address + page_rva + mbi.RegionSize),
              _image->buffer().begin() + offset);

            Util::Log("Copied page @ 0x{:X} to offset 0x{:X}", absolute_address + page_rva, offset);

            for ( auto p = 0; p < (mbi.RegionSize / 0x1000); ++p )
              pages_read.insert(page + p);
          }
          else
          {
#if 0
            auto gadgetCaller = (uintptr_t(*)(uintptr_t))(Mem::base + 0x15a7b70);
            gadgetCaller(absolute_address + page_rva);

            if ( VirtualQuery((void *)(absolute_address + page_rva), &mbi, sizeof(mbi)) == 0 )
              continue;

            if ( !(mbi.Protect & PAGE_NOACCESS) )
            {
              Util::Log(
                "Decrypted and read page @ 0x{:X} ({}/{}) = {:.3f}%", absolute_address + page_rva, pages_read.size(), total_pages, percent);

              std::copy(
                (uint8_t *)(absolute_address + page_rva),
                (uint8_t *)(absolute_address + page_rva + mbi.RegionSize),
                _image->buffer().begin() + offset);
              // Mark all pages in the region as read.
              for ( auto p = 0; p < (mbi.RegionSize / 0x1000); ++p )
                pages_read.insert(page + p);
            }
            else
            {
              Util::Log("Failed to decrypt page @ 0x{:X}", absolute_address + page_rva);
            }
#endif
          }
        }
      }
    }
    else
    {
      std::copy(
        (uint8_t *)absolute_address,
        (uint8_t *)absolute_address + header->SizeOfRawData,
        _image->buffer().begin() + header->PointerToRawData);

      Util::Log("Copied non-code section: \"{}\"", name);
    }
  }

  Util::Log("Resolved all sections");
}

void Dumper::resolve_imports(std::vector< Mem::ModuleInfo_t > &modules)
{
  Util::Log("Resolving import directory: \".vulkan\"");

  _image->refresh();

  Util::Log("Collecting all exported functions");

  // Get the imports from the modules
  const auto &imports = get_imports(modules);

  // Build the import pools
  for ( const auto &[address, imp] : imports )
  {
    // Add the import to the IAT
    std::string modName;
    std::transform(imp.mod.name.begin(), imp.mod.name.end(), std::back_inserter(modName), [](wchar_t c)
    {
      return (char)c;
    });

    _image->import_directory()->add(modName, imp.export_name, address);
  }

  Util::Log("Recompiling the import directory");

  _image->import_directory()->recompile(_image.get(), ".vulkan");

  // Refresh the image.
  _image->import_directory()->clear();
  _image->refresh();

  // Now we create a map that maps the value of the IAT entries to their IAT entry rva.
  std::unordered_map< std::uintptr_t, std::uintptr_t > iat_map;

  // Iterate over the imports and add them to the map.
  for ( const auto &import : _image->import_directory()->imports() )
  {
    // Read the IAT entry
    const auto &iat_entry = *reinterpret_cast<std::uintptr_t *>(_image->buffer().data() + _image->rva_to_offset(import->iat_rva));

    // Add the IAT entry to the map
    iat_map[iat_entry] = import->iat_rva;
  }

#if 0
  Util::Log("Searching for references to the exported routines");

  struct reference_t
  {
    std::uintptr_t address;
    std::uint32_t offset;
    std::uint32_t len;
  };

  // An immutable list of patterns to search for. The first parameter is the pattern, the second is the offset and length of the relative
  // address. The `address` field is always set to zero, as it gets filled in later.
  const std::list< std::pair< wincpp::patterns::pattern_t, reference_t > > patterns = {
      { wincpp::patterns::pattern_t("\xFF\x15\x00\x00\x00\x00", "xx????"), { 0, 2, 6 } },
      { wincpp::patterns::pattern_t("\x48\xFF\x25\x00\x00\x00\x00", "xx?????"), { 0, 3, 7 } }
  };

  std::vector< reference_t > references;

  for ( const auto &[pattern, reference] : patterns )
  {
    const auto &results =
      wincpp::patterns::scanner::find_all< wincpp::patterns::scanner::algorithm_t::naive_t >(_image->buffer(), pattern);

    for ( const auto &result : results )
      references.push_back({ result, reference.offset, reference.len });
  }

  Util::Log("Processing {} cross references", references.size());

  for ( const auto &reference : references )
  {
    // Extract the relative offset from the instruction
    auto offset = reinterpret_cast<std::uint32_t *>(_image->buffer().data() + reference.address + reference.offset);

    // Compute the absolute address of the call instruction
    const auto next_instruction = reference.address + reference.len;
    const auto &absolute_address = next_instruction + *offset;

    // Dereference the absolute address
    const auto &export_address =
      *reinterpret_cast<std::uintptr_t *>(_image->buffer().data() + _image->rva_to_offset(absolute_address));

    // Quick check to see if the dereferenced address could be a code address
    if ( export_address < 0x00007FF000000000 || export_address > 0x00007FFFFFFFFFFF )
      continue;

    // Check if the old IAT entry is in the IAT map
    if ( const auto &iat_entry = iat_map.find(export_address); iat_entry != iat_map.end() )
    {
      // Get the new IAT entry RVA
      const auto &new_iat_rva = iat_entry->second;

      // Compute the new relative offset
      const auto &new_offset = new_iat_rva - next_instruction;

      // Write the new relative offset
      *offset = new_offset;

      Util::Log("Patched instruction @ 0x{:X} to 0x{:X}", _image->image_base() + reference.address, *offset);
    }
  }
#endif
}

void Dumper::resolve_runtime_functions()
{
  const auto exception_directory = _image->data_directory(IMAGE_DIRECTORY_ENTRY_EXCEPTION);

  if ( !exception_directory->VirtualAddress || !exception_directory->Size )
    return;

  for ( auto rva = exception_directory->VirtualAddress; rva < exception_directory->VirtualAddress + exception_directory->Size;
    rva += sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY) )
  {
    const auto offset = _image->rva_to_offset(rva);

    if ( !offset )
      continue;

    const auto &entry = *reinterpret_cast<PIMAGE_RUNTIME_FUNCTION_ENTRY>(_image->buffer().data() + offset);

    const auto unwind_offset = _image->rva_to_offset(entry.UnwindInfoAddress);

    // Check if the entry is valid
    if ( _image->rva_to_offset(entry.BeginAddress) && _image->rva_to_offset(entry.EndAddress) && unwind_offset )
      continue;

    struct unwind_info_t
    {
      std::uint8_t version : 3;
      std::uint8_t flags : 5;

      // No need to implement the rest, as we don't need it.
    };

    const auto unwind_info = *reinterpret_cast<unwind_info_t *>(_image->buffer().data() + unwind_offset);

    // Check if the unwind info is valid
    if ( unwind_info.version == 1 )
      continue;

    // Remove the entry from the image;
    std::fill(_image->buffer().begin() + offset, _image->buffer().begin() + offset + sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), 0x00);
  }
}
