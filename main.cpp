#include "dumper.hpp"
#include "dump_control.hpp"
#include "memory.hpp"
#include "util.hpp"

#include <Windows.h>

#include <charconv>
#include <cmath>

namespace
{
  BOOL WINAPI ConsoleControlHandler(DWORD event)
  {
    if ( event != CTRL_C_EVENT && event != CTRL_BREAK_EVENT && event != CTRL_CLOSE_EVENT )
      return FALSE;

    DumpControl::request_stop();
    return TRUE;
  }

  struct command_line_t
  {
    bool force_self = false;
    bool prompt_clear_cache = false;
    std::wstring target_path;
  };

  struct memory_shutdown_guard_t
  {
    ~memory_shutdown_guard_t()
    {
      Mem::Shutdown();
    }
  };

  bool ParseDouble(std::string_view value, double &out)
  {
    double parsed = 0.0;
    const auto end = value.data() + value.size();
    const auto result = std::from_chars(value.data(), end, parsed, std::chars_format::general);
    if ( result.ec != std::errc{} || result.ptr != end || !std::isfinite(parsed) || parsed < 0.0 )
      return false;

    out = parsed;
    return true;
  }

  bool ParseUInt32(std::string_view value, std::uint32_t &out)
  {
    std::uint32_t parsed = 0;
    const auto end = value.data() + value.size();
    const auto result = std::from_chars(value.data(), end, parsed, 10);
    if ( result.ec != std::errc{} || result.ptr != end )
      return false;

    out = parsed;
    return true;
  }

  void TouchSampleImports()
  {
    char modulePath[MAX_PATH]{};
    ::GetModuleFileNameA(nullptr, modulePath, MAX_PATH);

    const DWORD tick = ::GetTickCount();
    const HMODULE kernel32 = ::GetModuleHandleA("kernel32.dll");

    Util::Log("[TEST] Module: {}", modulePath);
    Util::Log("[TEST] GetTickCount: {}", tick);
    Util::Log("[TEST] kernel32.dll: {:X}", kernel32);
  }

  std::wstring Utf8ToWide(std::string_view value)
  {
    if ( value.empty() )
      return {};

    if ( value.size() > (std::size_t)INT_MAX )
      return {};

    const auto required = ::MultiByteToWideChar(CP_UTF8, 0, value.data(), (int)value.size(), nullptr, 0);
    if ( required <= 0 )
      return {};

    std::wstring result(static_cast<std::size_t>(required), L'\0');
    if ( !::MultiByteToWideChar(CP_UTF8, 0, value.data(), (int)value.size(), result.data(), required) )
      return {};
    return result;
  }

  std::wstring PickExecutable()
  {
    wchar_t path[MAX_PATH]{};

    OPENFILENAMEW dialog{};
    dialog.lStructSize = sizeof(dialog);
    dialog.lpstrFilter = L"Executables\0*.exe\0All files\0*.*\0";
    dialog.lpstrFile = path;
    dialog.nMaxFile = MAX_PATH;
    dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    dialog.lpstrTitle = L"Select executable to dump";

    if ( !::GetOpenFileNameW(&dialog) )
      return {};

    return path;
  }

  std::string OutputNameForTarget(const std::wstring &target_path)
  {
    if ( target_path.empty() )
      return "memorydump_self.exe";

    const auto stem = std::filesystem::path(target_path).stem().string();
    return stem.empty() ? "memorydump_target.exe" : "memorydump_" + stem + ".exe";
  }

  bool AskYesNo(std::string_view question)
  {
    for ( ;; )
    {
      std::fwrite(question.data(), 1, question.size(), stdout);
      std::fputs(" [y/n]: ", stdout);
      std::fflush(stdout);

      char answer[16]{};
      if ( !std::fgets(answer, sizeof(answer), stdin) )
        return false;

      if ( answer[0] == 'y' || answer[0] == 'Y' )
        return true;

      if ( answer[0] == 'n' || answer[0] == 'N' )
        return false;
    }
  }

  void PromptClearPageCache(const std::string &cache_path)
  {
    if ( cache_path.empty() )
      return;

    std::error_code error;
    if ( !std::filesystem::exists(cache_path, error) )
      return;

    const auto message = "Clear existing page cache \"" + cache_path + "\"?";
    if ( !AskYesNo(message) )
    {
      Util::Log("Keeping page cache: {}", cache_path);
      return;
    }

    error.clear();
    if ( std::filesystem::remove(cache_path, error) )
      Util::Log("Cleared page cache: {}", cache_path);
    else if ( error )
      Util::Log("Failed to clear page cache {}: {}", cache_path, error.message());
  }

  bool ParseCommandLine(int argc, char **argv, command_line_t &command_line)
  {
    bool positional_target_seen = false;

    for ( int i = 1; i < argc; ++i )
    {
      const std::string_view arg(argv[i]);

      if ( arg == "--self" )
      {
        command_line.force_self = true;
        continue;
      }

      if ( arg == "--coverage" )
      {
        if ( i + 1 >= argc || !ParseDouble(argv[++i], DumpControl::recovery_options.target_coverage) )
        {
          Util::Log("Invalid --coverage value");
          return false;
        }
        continue;
      }

      if ( arg == "--max-stall" )
      {
        if ( i + 1 >= argc || !ParseUInt32(argv[++i], DumpControl::recovery_options.max_stalled_passes) )
        {
          Util::Log("Invalid --max-stall value");
          return false;
        }
        continue;
      }

      if ( arg == "--retry-delay" )
      {
        if ( i + 1 >= argc || !ParseUInt32(argv[++i], DumpControl::recovery_options.retry_delay_ms) )
        {
          Util::Log("Invalid --retry-delay value");
          return false;
        }
        continue;
      }

      if ( arg == "--no-page-cache" )
      {
        DumpControl::recovery_options.use_partial_store = false;
        continue;
      }

      if ( arg == "--clear-cache" )
      {
        command_line.prompt_clear_cache = true;
        continue;
      }

      if ( arg == "--page-cache" )
      {
        if ( i + 1 >= argc || std::string_view(argv[i + 1]).starts_with("--") )
        {
          Util::Log("Invalid --page-cache value");
          return false;
        }

        DumpControl::recovery_options.partial_store_path = argv[++i];
        continue;
      }

      if ( arg.starts_with("--") )
      {
        Util::Log("Unknown option: {}", arg);
        return false;
      }

      if ( positional_target_seen )
      {
        Util::Log("Multiple target executables were provided");
        return false;
      }

      positional_target_seen = true;
      command_line.target_path = Utf8ToWide(arg);
      if ( command_line.target_path.empty() )
      {
        Util::Log("Invalid target executable path");
        return false;
      }
    }

    if ( command_line.force_self && positional_target_seen )
    {
      Util::Log("--self cannot be combined with a target executable");
      return false;
    }

    DumpControl::recovery_options.target_coverage = std::clamp(DumpControl::recovery_options.target_coverage, 0.0, 100.0);
    return true;
  }
}

int main(int argc, char **argv)
{
  ::SetConsoleCtrlHandler(ConsoleControlHandler, TRUE);

  command_line_t command_line{};
  if ( !ParseCommandLine(argc, argv, command_line) )
    return 1;

  if ( command_line.target_path.empty() && !command_line.force_self )
    command_line.target_path = PickExecutable();

  const bool dumping_target = !command_line.target_path.empty();
  if ( dumping_target )
  {
    Util::Log("[TEST] Starting target dump");
    if ( !Mem::SetupTargetExecutable(command_line.target_path) )
      return 1;
  }
  else
  {
    Util::Log("[TEST] Starting self-dump sample");
    TouchSampleImports();
    Mem::Setup();
  }

  [[maybe_unused]] memory_shutdown_guard_t shutdown_guard;

  const auto outputPath = OutputNameForTarget(command_line.target_path);
  if ( DumpControl::recovery_options.use_partial_store && DumpControl::recovery_options.partial_store_path.empty() )
    DumpControl::recovery_options.partial_store_path = outputPath + ".pages";

  if ( DumpControl::recovery_options.use_partial_store && command_line.prompt_clear_cache )
    PromptClearPageCache(DumpControl::recovery_options.partial_store_path);

  auto image = Dumper::dump();
  if ( !image || !image->is_valid() )
  {
    Util::Log("[TEST] Dump failed");
    return 1;
  }

  if ( !image->save_to_file(outputPath) )
  {
    Util::Log("[TEST] Failed to save dump: {}", outputPath);
    return 1;
  }

  Util::Log("[TEST] Saved dump: {}", outputPath);
  return 0;
}
