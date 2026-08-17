#pragma once

#include "includes.hpp"
#include "util.hpp"
#include "pe/section_name.hpp"

#include <cstring>
#include <limits>

#define STR_MERGE_IMPL(a, b) a##b
#define STR_MERGE(a, b) STR_MERGE_IMPL(a, b)
#define PAD(size) unsigned char STR_MERGE(_pad, __COUNTER__)[size]
#define MEMBER(Type, name, offset) struct {PAD(offset); Type name;}
#define ALIGN_UP(x, a) (((x) + ((a) - 1)) & ~((a) - 1))

#define ROR(x, y) ((unsigned)(x) >> (y) | (unsigned)(x) << 32 - (y))

typedef enum _MEMORY_INFORMATION_CLASS
{
  MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;

typedef enum _PROCESSINFOCLASS
{
  ProcessBasicInformation = 0,
  ProcessQuotaLimits = 1,
  ProcessIoCounters = 2,
  ProcessVmCounters = 3,
  ProcessTimes = 4,
  ProcessBasePriority = 5,
  ProcessRaisePriority = 6,
  ProcessDebugPort = 7,
  ProcessExceptionPort = 8,
  ProcessAccessToken = 9,
  ProcessLdrInformation = 10,
  ProcessLdtSize = 11,
  ProcessDefaultHardErrorMode = 12,
  ProcessIoPortHandlers = 13,
  ProcessPooledUsageAndLimits = 14,
  ProcessWorkingSetWatch = 15,
  ProcessUserModeIOPL = 16,
  ProcessEnableAlignmentFaultFixup = 17,
  ProcessPriorityClass = 18,
  ProcessWx86Information = 19,
  ProcessHandleCount = 20,
  ProcessAffinityMask = 21,
  ProcessPriorityBoost = 22,
  ProcessDeviceMap = 23,
  ProcessSessionInformation = 24,
  ProcessForegroundInformation = 25,
  ProcessWow64Information = 26,
  ProcessImageFileName = 27,
  ProcessLUIDDeviceMapsEnabled = 28,
  ProcessBreakOnTermination = 29,
  ProcessDebugObjectHandle = 30,
  ProcessDebugFlags = 31,
  ProcessHandleTracing = 32,
  ProcessIoPriority = 33,
  ProcessExecuteFlags = 34,
  ProcessTlsInformation = 35,
  ProcessCookie = 36,
  ProcessImageInformation = 37,
  ProcessCycleTime = 38,
  ProcessPagePriority = 39,
  ProcessInstrumentationCallback = 40,
  ProcessThreadStackAllocation = 41,
  ProcessWorkingSetWatchEx = 42,
  ProcessImageFileNameWin32 = 43,
  ProcessImageFileMapping = 44,
  ProcessAffinityUpdateMode = 45,
  ProcessMemoryAllocationMode = 46,
  ProcessGroupInformation = 47,
  ProcessTokenVirtualizationEnabled = 48,
  ProcessConsoleHostProcess = 49,
  ProcessWindowInformation = 50,
  MaxProcessInfoClass // always last one so no need to add a value manually
} PROCESSINFOCLASS;

typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
{
  ULONG Version;   // must be 0
  ULONG Reserved;  // must be 0
  PVOID Callback;  // address of instrumentation callback
} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;

typedef struct _UNICODE_STRING
{
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY
{
  struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
  struct _LIST_ENTRY InMemoryOrderLinks;                                  //0x10
  struct _LIST_ENTRY InInitializationOrderLinks;                          //0x20
  VOID *DllBase;                                                          //0x30
  VOID *EntryPoint;                                                       //0x38
  ULONG SizeOfImage;                                                      //0x40
  struct _UNICODE_STRING FullDllName;                                     //0x48
  struct _UNICODE_STRING BaseDllName;                                     //0x58
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TALBE_ENTRY;

typedef struct _PEB_LDR_DATA
{
  BYTE       Reserved1[8];
  PVOID      Reserved2[3];
  LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef NTSTATUS(NTAPI *NtQueryInformationProcess_t) (
  HANDLE,
  PROCESSINFOCLASS,
  PVOID,
  ULONG,
  PULONG
);

namespace Mem
{
  inline HANDLE processHandle = GetCurrentProcess();
  inline HANDLE targetThread = nullptr;
  inline bool launchedTarget = false;
  inline bool attachedTarget = false;
  inline uintptr_t base = 0;
  inline DWORD pid = GetCurrentProcessId();

  void Setup();
  bool SetupTargetExecutable(const std::wstring &path);
  bool AttachToProcessByExecutable(const std::wstring &path);
  void Shutdown();
  bool IsProcessRunning();
  void Setup2(std::pair<uintptr_t, size_t> cave);
  bool QueryMemory(uintptr_t address, MEMORY_BASIC_INFORMATION &info);
  bool ReadProcessMemory(uintptr_t address, void *buffer, size_t size);
  bool WriteProcessMemory(uintptr_t address, const void *buffer, size_t size);

  template <typename T>
  struct EPtr
  {
    EPtr() = default;
    EPtr(T ptr) : m_ptr(Cipher((uintptr_t)ptr)) {}
    EPtr(uintptr_t ptr) : m_ptr(Cipher(ptr)) {}

    operator T() const { return (T)Cipher(m_ptr); }
    operator uintptr_t() const { return Cipher(m_ptr); }

    T operator->() const { return (T)Cipher(m_ptr); }
    T operator*() const { return (T)Cipher(m_ptr); }

    uintptr_t m_ptr = 0;

    static uintptr_t Cipher(uintptr_t ptr)
    {
      return ptr;

      //uintptr_t key = HASH_CT(SECRET);
      //return ptr ^ key;
    }
  };

  template <typename T>
  inline static T Read(uintptr_t address)
  {
    T value{};
    ReadProcessMemory(address, &value, sizeof(value));
    return value;
  }

  template <typename T>
  inline static T *Read(uintptr_t address, size_t size)
  {
    if ( size > std::numeric_limits<size_t>::max() / sizeof(T) )
      return nullptr;

    const size_t byte_count = sizeof(T) * size;
    if ( byte_count && address > std::numeric_limits<uintptr_t>::max() - (byte_count - 1) )
      return nullptr;

    auto temp = new T[size];
    if ( !ReadProcessMemory(address, temp, byte_count) )
    {
      delete[] temp;
      return nullptr;
    }
    return temp;
  }



  template <typename T>
  inline static bool Write(uintptr_t address, T value)
  {
    return WriteProcessMemory(address, &value, sizeof(T));
  }

  template <typename T = void *>
  constexpr T GetVirtual(void *base, int index)
  {
    return (*(T **)(base))[index];
  }

  template<typename R = void, size_t index, typename... Args_t>
  constexpr R CallVirtual(void *base, Args_t... args)
  {
    using Fn_t = R(__thiscall *)(void *, Args_t...);
    return GetVirtual<Fn_t>(base, index)(base, std::forward<Args_t>(args)...);
  }

  template<typename R = void, typename... Args_t>
  constexpr R CallSig(void *address, Args_t... args)
  {
    using Fn_t = R(*)(Args_t...);
    return (R)(((Fn_t)address)(std::forward<Args_t>(args)...));
  }

  template <size_t N>
  static inline bool IsSame(const std::array<int, N> &aob, uintptr_t address)
  {
    uint8_t *buffer = Mem::Read<uint8_t>(address, N);
    if ( !buffer )
      return false;

    for ( size_t i = 0; i < N; i++ )
    {
      if ( aob[i] == -1 )
        continue;

      if ( (uint8_t)aob[i] != buffer[i] )
      {
        delete[] buffer;
        return false;
      }
    }

    delete[] buffer;
    return true;
  }

  template<size_t N>
  inline uintptr_t FindPattern(uint8_t *image, const std::array<int, N> &sig)
  {
    if ( !image || N == 0 )
      return 0;

    const auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(image);
    if ( dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 || dos->e_lfanew > 0x100000 )
      return 0;

    const auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(image + dos->e_lfanew);
    if ( nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
      nt->FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64) )
      return 0;

    const size_t image_size = nt->OptionalHeader.SizeOfImage;
    const size_t section_table_offset = static_cast<size_t>(dos->e_lfanew) +
      offsetof(IMAGE_NT_HEADERS, OptionalHeader) + nt->FileHeader.SizeOfOptionalHeader;
    const size_t section_table_size = static_cast<size_t>(nt->FileHeader.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);

    if ( !image_size || section_table_offset > image_size || section_table_size > image_size - section_table_offset )
      return 0;

    uintptr_t textBase = 0;
    size_t textSize = 0;

    const auto section = reinterpret_cast<PIMAGE_SECTION_HEADER>(image + section_table_offset);
    for ( WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i )
    {
      if ( vulkan::pe::section_name_equals(section[i], ".text") )
      {
        textBase = section[i].VirtualAddress;
        textSize = section[i].Misc.VirtualSize;
        break;
      }
    }

    if ( textBase > image_size || textSize > image_size - textBase || textSize < N )
      return 0;

    const size_t last_start = static_cast<size_t>(textBase) + textSize - N;
    for ( size_t i = static_cast<size_t>(textBase); i <= last_start; ++i )
    {
      bool proceed = true;

      for ( size_t j = 0; j < N; ++j )
      {
        if ( image[i + j] != sig[j] && sig[j] != -1 )
        {
          proceed = false;
          break;
        }
      }

      if ( proceed )
        return reinterpret_cast<uintptr_t>(&image[i]);
    }

    return 0;
  }

  inline uintptr_t Relative(uintptr_t address, uint8_t insnSize)
  {
    if ( address > std::numeric_limits<uintptr_t>::max() - insnSize )
      return 0;

    const uintptr_t displacement_address = address + insnSize;
    if ( displacement_address > std::numeric_limits<uintptr_t>::max() - sizeof(int32_t) )
      return 0;

    int32_t relOffset = 0;
    std::memcpy(&relOffset, reinterpret_cast<const void *>(displacement_address), sizeof(relOffset));

    const uintptr_t pastInstruction = displacement_address + sizeof(relOffset);
    if ( relOffset >= 0 )
    {
      const auto offset = static_cast<uintptr_t>(relOffset);
      return pastInstruction <= std::numeric_limits<uintptr_t>::max() - offset ? pastInstruction + offset : 0;
    }

    const auto offset = static_cast<uintptr_t>(-static_cast<int64_t>(relOffset));
    return pastInstruction >= offset ? pastInstruction - offset : 0;
  }

  struct ModuleInfo_t
  {
    std::wstring name;
    std::wstring path;
    uintptr_t base = 0;
    size_t size = 0;
  };

  inline PEB_LDR_DATA *GetLoaderData()
  {
    const auto peb = __readgsqword(0x60);
    if ( !peb )
      return nullptr;

    return *reinterpret_cast<PEB_LDR_DATA **>(peb + 0x18);
  }

  inline std::wstring ModuleNameFromSnapshot(const MODULEENTRY32W &entry)
  {
    if ( entry.szModule[0] )
      return entry.szModule;

    return L"[UNKNOWN]";
  }

  inline std::wstring ReadUnicodeString(const UNICODE_STRING &value)
  {
    if ( !value.Buffer || !value.Length )
      return L"[UNKNOWN]";

    return { value.Buffer, value.Length / sizeof(wchar_t) };
  }

  inline std::vector<ModuleInfo_t> GetLoadedModules()
  {
    std::vector<ModuleInfo_t> modules;
    const DWORD snapshot_pid = pid ? pid : GetCurrentProcessId();

    HANDLE snapshot = INVALID_HANDLE_VALUE;
    for ( int attempt = 0; attempt < 8; ++attempt )
    {
      snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, snapshot_pid);
      if ( snapshot != INVALID_HANDLE_VALUE || GetLastError() != ERROR_BAD_LENGTH )
        break;

      Sleep(1);
    }

    if ( snapshot != INVALID_HANDLE_VALUE )
    {
      MODULEENTRY32W entry{};
      entry.dwSize = sizeof(entry);

      if ( Module32FirstW(snapshot, &entry) )
      {
        do
        {
          ModuleInfo_t info{};
          info.name = ModuleNameFromSnapshot(entry);
          info.path = entry.szExePath;
          info.base = reinterpret_cast<uintptr_t>(entry.modBaseAddr);
          info.size = static_cast<size_t>(entry.modBaseSize);
          modules.push_back(std::move(info));
        } while ( Module32NextW(snapshot, &entry) );
      }

      CloseHandle(snapshot);
      return modules;
    }

    if ( snapshot_pid != GetCurrentProcessId() )
    {
      Util::Log("Failed to enumerate modules for target PID {}: {}", snapshot_pid, GetLastError());
      return modules;
    }

    const auto ldr = GetLoaderData();
    if ( !ldr )
    {
      Util::Log("Failed to get PEB_LDR_DATA");
      return modules;
    }

    for ( auto entry = ldr->InMemoryOrderModuleList.Flink; entry && entry != &ldr->InMemoryOrderModuleList; entry = entry->Flink )
    {
      const auto module = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

      ModuleInfo_t info{};
      info.name = ReadUnicodeString(module->BaseDllName);
      info.path = ReadUnicodeString(module->FullDllName);
      info.base = reinterpret_cast<uintptr_t>(module->DllBase);
      info.size = static_cast<size_t>(module->SizeOfImage);
      modules.push_back(std::move(info));
    }

    return modules;
  }

  inline std::pair<uintptr_t, size_t> GetModule(const wchar_t *module_name)
  {
    const auto ldr = GetLoaderData();
    if ( !ldr || !module_name )
      return { 0, 0 };

    std::wstring wanted = module_name;
    std::transform(wanted.begin(), wanted.end(), wanted.begin(), towlower);

    for ( auto entry = ldr->InMemoryOrderModuleList.Flink; entry && entry != &ldr->InMemoryOrderModuleList; entry = entry->Flink )
    {
      const auto module = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
      auto current = ReadUnicodeString(module->BaseDllName);
      std::transform(current.begin(), current.end(), current.begin(), towlower);

      if ( current != wanted )
        continue;

      return { reinterpret_cast<uintptr_t>(module->DllBase), static_cast<size_t>(module->SizeOfImage) };
    }

    return { 0, 0 };
  }

  namespace RWX
  {
    bool Setup(size_t size);
    uintptr_t Pop(size_t size);

    uintptr_t Trampoline(void *address);

    inline std::pair<uintptr_t, size_t> whitelistedCave;
    inline uintptr_t free = 0;
  }

  inline std::pair<uintptr_t, size_t> user32;
}

#define VCALL(returnType, name, idx, args, argsRaw) \
returnType name args \
{ \
    return Mem::CallVirtual<returnType, idx>argsRaw; \
}

#define OFFSET(name, offset, ...) \
  __VA_ARGS__ name() { return Mem::Read<__VA_ARGS__>(std::uintptr_t(this) + offset); } \
  void name(__VA_ARGS__ value) { Mem::Write<__VA_ARGS__>(std::uintptr_t(this) + offset, value); }


/*
```asm
public GetInstrumentationCallbackSetTrapRet
GetInstrumentationCallbackSetTrapRet dq GetInstrumentationCallbackSetTrap_Ret

public pKiUserExceptionDispatcher, pInstrumentationCallback
pKiUserExceptionDispatcher dq 0
pInstrumentationCallback   dq 0

TheiaFakeException proc

push rbx
push rbp
push rsi
push rdi
push r12
push r13
push r14
push r15
sub rsp, 598h ; Context 4F0h +  EXCEPTION_RECORD 98h

mov rbx, rcx
mov rbp, rdx

; zero init
mov rdi, rsp
xor rax, rax
mov rcx, (588h/8h)
rep stosq

lea rcx, [rsp+4F0h] ; EXCEPTION_RECORD
lea rdx, [rsp]      ; CONTEXT

mov dword ptr [rdx+30h], 10001Fh ; Context.ContextFlags = CONTEXT_ALL

stmxcsr dword ptr [rdx+34h]

mov ax, cs
mov [rdx+38h], ax ; Context.SegCs
mov ax, ds
mov [rdx+3Ah], ax ; Context.SegDs
mov ax, es
mov [rdx+3Ch], ax ; Context.SegEs
mov ax, fs
mov [rdx+3Eh], ax ; Context.SegFs
mov ax, gs
mov [rdx+40h], ax ; Context.SegGs
mov ax, ss
mov [rdx+42h], ax ; Context.SegSs

pushfq
pop rax
;or  eax, 100h
mov [rdx+44h], eax ; Context.EFlags

fxsave  dword ptr [rdx+100h]


lea rax, TheiaFakeException_continue
mov [rsp+590h], rax

lea rax, [rsp+590h]
mov [rdx+98h], rax                  ; Context.Rsp

mov [rdx+0F8h], rbp                 ; Context.Rip = arg2 (bait code)

mov dword ptr [rcx+0h], 0C0000005h  ; ExceptionCode = EXCEPTION_ACCESS_VIOLATION

mov [rcx+10h], rbp ; rbx            ; ExceptionAddress

mov dword ptr[rcx+18h], 2           ; NumberParameters = 2
mov qword ptr[rcx+20h], 0           ; ATTEMPTED READ
mov qword ptr[rcx+28h], rbx         ; ReadAddress = arg1 (bait target-page)


mov r10, pKiUserExceptionDispatcher
jmp qword ptr pInstrumentationCallback

add rsp, 588h

TheiaFakeException_continue:
pop r15
pop r14
pop r13
pop r12
pop rdi
pop rsi
pop rbp
pop rbx
ret

TheiaFakeException endp


end
```
*/