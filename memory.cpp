#include "memory.hpp"
#include "util.hpp"

#include <cwctype>
#include <filesystem>
#include <fstream>

namespace
{
  struct ProcessBasicInformationData
  {
    PVOID Reserved1 = nullptr;
    PVOID PebBaseAddress = nullptr;
    PVOID Reserved2[2]{};
    ULONG_PTR UniqueProcessId = 0;
    PVOID Reserved3 = nullptr;
  };

  std::wstring ToLower(std::wstring value)
  {
    std::transform(value.begin(), value.end(), value.begin(), [](wchar_t c)
    {
      return static_cast<wchar_t>(std::towlower(c));
    });
    return value;
  }

  std::wstring FileNameOf(const std::wstring &path)
  {
    return ToLower(std::filesystem::path(path).filename().wstring());
  }

  std::wstring CanonicalPath(const std::wstring &path)
  {
    if ( path.empty() )
      return {};

    std::error_code error;
    auto full_path = std::filesystem::absolute(std::filesystem::path(path), error);
    if ( error )
      return {};

    auto canonical_path = std::filesystem::weakly_canonical(full_path, error);
    if ( error )
      canonical_path = full_path.lexically_normal();

    return ToLower(canonical_path.wstring());
  }

  bool SamePath(const std::wstring &lhs, const std::wstring &rhs)
  {
    if ( lhs.empty() || rhs.empty() )
      return false;

    if ( ToLower(lhs) == ToLower(rhs) )
      return true;

    const auto canonical_lhs = CanonicalPath(lhs);
    const auto canonical_rhs = CanonicalPath(rhs);
    return !canonical_lhs.empty() && !canonical_rhs.empty() && canonical_lhs == canonical_rhs;
  }

  bool RangeFits(std::uint64_t offset, std::uint64_t size, std::uint64_t limit)
  {
    return offset <= limit && size <= limit - offset;
  }

  bool ReadRemote(std::uintptr_t image_base, std::uintptr_t offset, void *buffer, size_t size)
  {
    if ( offset > std::numeric_limits<std::uintptr_t>::max() - image_base )
      return false;

    const auto address = image_base + offset;
    if ( size && address > std::numeric_limits<std::uintptr_t>::max() - (size - 1) )
      return false;

    return Mem::ReadProcessMemory(address, buffer, size);
  }

  enum class PeFileStatus
  {
    ValidX64,
    NotFound,
    InvalidPe,
    UnsupportedMachine
  };

  PeFileStatus ValidateInputExecutable(const std::wstring &path)
  {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if ( !file )
      return PeFileStatus::NotFound;

    const auto end = file.tellg();
    if ( end < 0 )
      return PeFileStatus::InvalidPe;

    const auto file_size = static_cast<std::uint64_t>(end);
    if ( !RangeFits(0, sizeof(IMAGE_DOS_HEADER), file_size) )
      return PeFileStatus::InvalidPe;

    file.seekg(0, std::ios::beg);

    IMAGE_DOS_HEADER dos{};
    file.read(reinterpret_cast<char *>(&dos), sizeof(dos));
    if ( !file || dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0 )
      return PeFileStatus::InvalidPe;

    const auto nt_offset = static_cast<std::uint64_t>(dos.e_lfanew);
    const auto file_header_offset = nt_offset + sizeof(DWORD);
    const auto optional_header_offset = file_header_offset + sizeof(IMAGE_FILE_HEADER);
    if ( !RangeFits(nt_offset, sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER), file_size) )
      return PeFileStatus::InvalidPe;

    file.seekg(static_cast<std::streamoff>(nt_offset), std::ios::beg);

    DWORD signature = 0;
    IMAGE_FILE_HEADER file_header{};
    file.read(reinterpret_cast<char *>(&signature), sizeof(signature));
    file.read(reinterpret_cast<char *>(&file_header), sizeof(file_header));

    if ( !file || signature != IMAGE_NT_SIGNATURE )
      return PeFileStatus::InvalidPe;

    if ( file_header.Machine != IMAGE_FILE_MACHINE_AMD64 )
      return PeFileStatus::UnsupportedMachine;

    if ( file_header.NumberOfSections == 0 || file_header.NumberOfSections > 96 ||
      file_header.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64) ||
      !(file_header.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) ||
      !RangeFits(optional_header_offset, file_header.SizeOfOptionalHeader, file_size) )
      return PeFileStatus::InvalidPe;

    IMAGE_OPTIONAL_HEADER64 optional_header{};
    file.read(reinterpret_cast<char *>(&optional_header), sizeof(optional_header));
    if ( !file )
      return PeFileStatus::InvalidPe;

    if ( optional_header.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC )
      return PeFileStatus::UnsupportedMachine;

    if ( !optional_header.SizeOfImage || !optional_header.SizeOfHeaders ||
      optional_header.SizeOfHeaders > optional_header.SizeOfImage ||
      optional_header.SizeOfHeaders > file_size ||
      !optional_header.SectionAlignment || !optional_header.FileAlignment ||
      (optional_header.AddressOfEntryPoint && optional_header.AddressOfEntryPoint >= optional_header.SizeOfImage) )
      return PeFileStatus::InvalidPe;

    const auto section_table_offset = optional_header_offset + file_header.SizeOfOptionalHeader;
    const auto section_table_size = static_cast<std::uint64_t>(file_header.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);
    if ( !RangeFits(section_table_offset, section_table_size, file_size) ||
      !RangeFits(section_table_offset, section_table_size, optional_header.SizeOfHeaders) )
      return PeFileStatus::InvalidPe;

    file.seekg(static_cast<std::streamoff>(section_table_offset), std::ios::beg);
    std::vector<IMAGE_SECTION_HEADER> sections(file_header.NumberOfSections);
    file.read(reinterpret_cast<char *>(sections.data()), static_cast<std::streamsize>(section_table_size));
    if ( !file )
      return PeFileStatus::InvalidPe;

    for ( const auto &section : sections )
    {
      const auto mapped_size = std::max(section.Misc.VirtualSize, section.SizeOfRawData);
      if ( mapped_size && (section.VirtualAddress >= optional_header.SizeOfImage ||
        mapped_size > optional_header.SizeOfImage - section.VirtualAddress) )
        return PeFileStatus::InvalidPe;

      if ( section.SizeOfRawData && !RangeFits(section.PointerToRawData, section.SizeOfRawData, file_size) )
        return PeFileStatus::InvalidPe;
    }

    return PeFileStatus::ValidX64;
  }

  bool IsValidRemoteImage(std::uintptr_t image_base, size_t known_size = 0)
  {
    if ( !image_base )
      return false;

    MEMORY_BASIC_INFORMATION info{};
    if ( !Mem::QueryMemory(image_base, info) || info.State != MEM_COMMIT )
      return false;

    IMAGE_DOS_HEADER dos{};
    if ( !ReadRemote(image_base, 0, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE ||
      dos.e_lfanew <= 0 || dos.e_lfanew > 0x100000 )
      return false;

    const auto nt_offset = static_cast<std::uintptr_t>(dos.e_lfanew);
    DWORD signature = 0;
    IMAGE_FILE_HEADER file_header{};
    if ( !ReadRemote(image_base, nt_offset, &signature, sizeof(signature)) || signature != IMAGE_NT_SIGNATURE ||
      !ReadRemote(image_base, nt_offset + sizeof(signature), &file_header, sizeof(file_header)) )
      return false;

    if ( file_header.Machine != IMAGE_FILE_MACHINE_AMD64 || file_header.NumberOfSections == 0 ||
      file_header.NumberOfSections > 96 || file_header.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64) ||
      !(file_header.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) )
      return false;

    const auto optional_header_offset = nt_offset + sizeof(signature) + sizeof(file_header);
    IMAGE_OPTIONAL_HEADER64 optional_header{};
    if ( !ReadRemote(image_base, optional_header_offset, &optional_header, sizeof(optional_header)) ||
      optional_header.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC || !optional_header.SizeOfImage ||
      !optional_header.SizeOfHeaders || optional_header.SizeOfHeaders > optional_header.SizeOfImage ||
      !optional_header.SectionAlignment || !optional_header.FileAlignment ||
      (optional_header.AddressOfEntryPoint && optional_header.AddressOfEntryPoint >= optional_header.SizeOfImage) )
      return false;

    if ( known_size && optional_header.SizeOfImage > known_size )
      return false;

    if ( image_base > std::numeric_limits<std::uintptr_t>::max() - (optional_header.SizeOfImage - 1) )
      return false;

    const auto section_table_offset = optional_header_offset + file_header.SizeOfOptionalHeader;
    const auto section_table_size = static_cast<size_t>(file_header.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);
    if ( section_table_offset > optional_header.SizeOfHeaders ||
      section_table_size > optional_header.SizeOfHeaders - section_table_offset )
      return false;

    std::vector<IMAGE_SECTION_HEADER> sections(file_header.NumberOfSections);
    if ( !ReadRemote(image_base, section_table_offset, sections.data(), section_table_size) )
      return false;

    for ( const auto &section : sections )
    {
      const auto mapped_size = std::max(section.Misc.VirtualSize, section.SizeOfRawData);
      if ( mapped_size && (section.VirtualAddress >= optional_header.SizeOfImage ||
        mapped_size > optional_header.SizeOfImage - section.VirtualAddress) )
        return false;
    }

    return true;
  }

  std::uintptr_t CurrentProcessImageBase()
  {
    const auto peb = __readgsqword(0x60);
    return peb ? *reinterpret_cast<const std::uintptr_t *>(peb + 0x10) : 0;
  }

  void ResetProcessState()
  {
    Mem::processHandle = ::GetCurrentProcess();
    Mem::targetThread = nullptr;
    Mem::launchedTarget = false;
    Mem::attachedTarget = false;
    Mem::pid = ::GetCurrentProcessId();
    Mem::base = CurrentProcessImageBase();
  }

  void ReleaseProcessState()
  {
    const auto process = Mem::processHandle;
    const auto thread = Mem::targetThread;
    const bool owns_process_handle = (Mem::launchedTarget || Mem::attachedTarget) && process &&
      process != INVALID_HANDLE_VALUE && process != ::GetCurrentProcess();

    if ( Mem::launchedTarget && owns_process_handle )
      ::TerminateProcess(process, 0);

    if ( thread )
      ::CloseHandle(thread);

    if ( owns_process_handle )
      ::CloseHandle(process);

    ResetProcessState();
  }

  std::uintptr_t QueryPebImageBase(HANDLE process)
  {
    const auto ntdll = ::GetModuleHandleW(L"ntdll.dll");
    if ( !ntdll )
      return 0;

    const auto query_information_process = reinterpret_cast<NtQueryInformationProcess_t>(
      ::GetProcAddress(ntdll, "NtQueryInformationProcess"));
    if ( !query_information_process )
      return 0;

    ProcessBasicInformationData info{};
    ULONG returned = 0;
    const auto status = query_information_process(
      process,
      ProcessBasicInformation,
      &info,
      sizeof(info),
      &returned);

    if ( !NT_SUCCESS(status) || !info.PebBaseAddress )
      return 0;

    std::uintptr_t image_base = 0;
    SIZE_T bytes_read = 0;
    const auto image_base_field = reinterpret_cast<std::uintptr_t>(info.PebBaseAddress) + 0x10;
    if ( !::ReadProcessMemory(process, reinterpret_cast<LPCVOID>(image_base_field), &image_base, sizeof(image_base), &bytes_read) ||
      bytes_read != sizeof(image_base) )
      return 0;

    return image_base;
  }

  struct ProcessInfo
  {
    DWORD pid = 0;
    std::wstring image_name;
  };

  std::vector<ProcessInfo> SnapshotProcesses()
  {
    std::vector<ProcessInfo> result;

    const auto snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if ( snapshot == INVALID_HANDLE_VALUE )
      return result;

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);

    if ( ::Process32FirstW(snapshot, &entry) )
    {
      do
      {
        ProcessInfo info{};
        info.pid = entry.th32ProcessID;
        info.image_name = entry.szExeFile;
        result.push_back(std::move(info));
      } while ( ::Process32NextW(snapshot, &entry) );
    }

    ::CloseHandle(snapshot);
    return result;
  }

  std::wstring QueryProcessImagePath(HANDLE process)
  {
    std::wstring path(32768, L'\0');
    DWORD size = static_cast<DWORD>(path.size());

    if ( !::QueryFullProcessImageNameW(process, 0, path.data(), &size) || !size )
      return {};

    path.resize(size);
    return path;
  }

  std::uintptr_t ResolveMainModuleFromSnapshot(const std::wstring &target_path)
  {
    const auto modules = Mem::GetLoadedModules();

    for ( const auto &module : modules )
    {
      if ( !SamePath(module.path, target_path) )
        continue;

      if ( IsValidRemoteImage(module.base, module.size) )
        return module.base;

      Util::Log("Rejected module candidate 0x{:X}: invalid PE header", module.base);
    }

    return 0;
  }

  bool OpenProcessContext(DWORD process_id, const std::wstring &target_path, bool attached)
  {
    const auto handle = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE, FALSE, process_id);
    if ( !handle )
      return false;

    Mem::processHandle = handle;
    Mem::targetThread = nullptr;
    Mem::launchedTarget = false;
    Mem::attachedTarget = attached;
    Mem::pid = process_id;

    Mem::base = ResolveMainModuleFromSnapshot(target_path);
    if ( !Mem::base )
    {
      const auto peb_base = QueryPebImageBase(Mem::processHandle);
      if ( IsValidRemoteImage(peb_base) )
        Mem::base = peb_base;
    }

    if ( !Mem::base )
    {
      ::CloseHandle(Mem::processHandle);
      ResetProcessState();
      return false;
    }

    return true;
  }
}

void Mem::Setup()
{
  Util::Log(__("Mem::Setup"));

  ReleaseProcessState();
  Util::Log(__("Base: 0x{:X}"), base);

  if ( !RWX::Setup(300) )
  {
    Util::Log(__("Failed to setup RWX"));
  }
}

bool Mem::AttachToProcessByExecutable(const std::wstring &path)
{
  const auto target_file_name = FileNameOf(path);
  if ( target_file_name.empty() || CanonicalPath(path).empty() )
    return false;

  for ( const auto &process : SnapshotProcesses() )
  {
    if ( FileNameOf(process.image_name) != target_file_name )
      continue;

    const auto handle = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, process.pid);
    if ( !handle )
      continue;

    const auto image_path = QueryProcessImagePath(handle);
    ::CloseHandle(handle);

    if ( !SamePath(image_path, path) )
      continue;

    if ( OpenProcessContext(process.pid, path, true) )
    {
      Util::Log("Attached to existing target PID: {}", process.pid);
      Util::Log("Image base: 0x{:X}", base);
      return true;
    }
  }

  return false;
}

bool Mem::SetupTargetExecutable(const std::wstring &path)
{
  switch ( ValidateInputExecutable(path) )
  {
    case PeFileStatus::ValidX64:
      break;
    case PeFileStatus::NotFound:
      Util::Log("Target executable does not exist or cannot be opened");
      return false;
    case PeFileStatus::InvalidPe:
      Util::Log("Target file is not a valid PE executable");
      return false;
    case PeFileStatus::UnsupportedMachine:
      Util::Log("Target executable is not a 64-bit PE. This dumper currently supports x64 targets only.");
      return false;
  }

  ReleaseProcessState();

  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);

  if ( AttachToProcessByExecutable(path) )
    return true;

  Util::Log("No running target process found; launching a new process");

  PROCESS_INFORMATION process{};
  if ( !::CreateProcessW(path.c_str(), nullptr, nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr, &startup, &process) )
  {
    Util::Log("Failed to create target process: {}", ::GetLastError());
    return false;
  }

  processHandle = process.hProcess;
  targetThread = process.hThread;
  launchedTarget = true;
  attachedTarget = false;
  pid = process.dwProcessId;
  base = 0;

  base = QueryPebImageBase(processHandle);
  if ( !IsValidRemoteImage(base) )
  {
    if ( base )
      Util::Log("Rejected suspended PEB image base 0x{:X}: invalid PE header", base);

    base = 0;
  }

  if ( ::ResumeThread(targetThread) == static_cast<DWORD>(-1) )
  {
    Util::Log("Failed to resume target process: {}", ::GetLastError());
    Shutdown();
    return false;
  }

  ::WaitForInputIdle(processHandle, 2000);
  ::Sleep(500);

  for ( int attempt = 0; attempt < 50 && !base; ++attempt )
  {
    base = ResolveMainModuleFromSnapshot(path);
    if ( !base )
      ::Sleep(100);
  }

  if ( !IsValidRemoteImage(base) )
  {
    if ( base )
      Util::Log("Rejected resolved image base 0x{:X}: invalid PE header", base);

    base = 0;
  }

  if ( !base )
  {
    Util::Log("Failed to find a valid PE image base for target");
    Shutdown();
    return false;
  }

  Util::Log("Target PID: {}", pid);
  Util::Log("Image base: 0x{:X}", base);
  return true;
}

void Mem::Shutdown()
{
  ReleaseProcessState();
}

bool Mem::IsProcessRunning()
{
  if ( pid == ::GetCurrentProcessId() )
    return true;

  if ( !processHandle || processHandle == INVALID_HANDLE_VALUE )
    return false;

  const auto wait_result = ::WaitForSingleObject(processHandle, 0);
  if ( wait_result == WAIT_FAILED )
  {
    Util::Log("Failed to query target process state: {}", ::GetLastError());
    return true;
  }

  return wait_result == WAIT_TIMEOUT;
}

void Mem::Setup2(std::pair<uintptr_t, size_t> cave)
{
  Util::Log("Mem::Setup()");
  base = CurrentProcessImageBase();

  RWX::whitelistedCave.first = cave.first;
  RWX::whitelistedCave.second = cave.second;
  RWX::free = RWX::whitelistedCave.second;

  //Offsets::wndProcRetAddr = FindPattern((uint8_t *)user32.first, sig<"48 89 44 24 ? 45 85 ED">);
  //Util::Log("WndProcRetAddr offset: {:#018x}", Offsets::wndProcRetAddr);
}

bool Mem::QueryMemory(uintptr_t address, MEMORY_BASIC_INFORMATION &info)
{
  std::memset(&info, 0, sizeof(info));
  return ::VirtualQueryEx(processHandle, reinterpret_cast<LPCVOID>(address), &info, sizeof(info)) == sizeof(info);
}

bool Mem::ReadProcessMemory(uintptr_t address, void *buffer, size_t size)
{
  SIZE_T bytesRead = 0;
  return ::ReadProcessMemory(processHandle, reinterpret_cast<LPCVOID>(address), buffer, size, &bytesRead) && bytesRead == size;
}

bool Mem::WriteProcessMemory(uintptr_t address, const void *buffer, size_t size)
{
  SIZE_T bytesWritten = 0;
  return ::WriteProcessMemory(processHandle, reinterpret_cast<LPVOID>(address), buffer, size, &bytesWritten) && bytesWritten == size;
}

bool Mem::RWX::Setup(size_t size)
{
  whitelistedCave = {};
  free = 0;
  if ( !size )
    return false;

  MEMORY_BASIC_INFORMATION mbi{};
  uintptr_t address = 0;

  while ( VirtualQuery(reinterpret_cast<void *>(address), &mbi, sizeof(mbi)) )
  {
    const auto region_base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
    if ( !mbi.RegionSize || region_base > std::numeric_limits<uintptr_t>::max() - mbi.RegionSize )
      break;

    const uintptr_t region_end = region_base + mbi.RegionSize;
    if ( region_end <= address )
      break;

    address = region_end;

    if ( mbi.RegionSize < size || mbi.RegionSize < 4 || mbi.Protect != PAGE_EXECUTE_READWRITE ||
      mbi.Type != MEM_PRIVATE || mbi.State != MEM_COMMIT )
      continue;

    const uintptr_t cave = region_end - size;
    bool empty = true;
    for ( size_t i = 0; i < size; ++i )
    {
      if ( *reinterpret_cast<const uint8_t *>(cave + i) != 0x00 )
      {
        empty = false;
        break;
      }
    }

    if ( !empty )
      continue;

    // mov QWORD PTR [rsp+??],rbx
    // 48 89 5C 24 ??
    const auto ptr = reinterpret_cast<const uint8_t *>(region_base);
    if ( ptr[0] == 0x48 && ptr[1] == 0x89 && ptr[2] == 0x5C && ptr[3] == 0x24 )
    {
      whitelistedCave.first = cave;
      whitelistedCave.second = size;
      free = size;
      Util::Log("RWX cave found at 0x{:X} with size {}", whitelistedCave.first, whitelistedCave.second);
      return true;
    }
  }

  return false;
}

uintptr_t Mem::RWX::Pop(size_t size)
{
  if ( whitelistedCave.second == 0 || size > free ||
    whitelistedCave.first > std::numeric_limits<uintptr_t>::max() - size )
    return 0;

  const uintptr_t allocation = whitelistedCave.first;
  whitelistedCave.first += size;
  free -= size;
  return allocation;
}

uintptr_t Mem::RWX::Trampoline(void *address)
{
  uint8_t trampoline[] = {
    0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, // jmp QWORD PTR [rip+0x0]
    0xEF, 0xBE, 0xAD, 0xDE, 0xAD, 0xAD, 0xAD, 0xAD
  };

  uintptr_t shellcodeAddress = Pop(sizeof(trampoline));
  if ( !shellcodeAddress )
  {
    Util::Log("Failed to allocate memory for trampoline");
    return shellcodeAddress;
  }

  const auto target = reinterpret_cast<uintptr_t>(address);
  std::memcpy(trampoline + 6, &target, sizeof(target));
  std::memcpy(reinterpret_cast<void *>(shellcodeAddress), trampoline, sizeof(trampoline));

  if ( !::FlushInstructionCache(::GetCurrentProcess(), reinterpret_cast<const void *>(shellcodeAddress), sizeof(trampoline)) )
    Util::Log("Failed to flush trampoline instruction cache: {}", ::GetLastError());

  Util::Log("Trampoline to 0x{:X} ({} bytes) placed at 0x{:X}", target, sizeof(trampoline), shellcodeAddress);

  return shellcodeAddress;
}
