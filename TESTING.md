## Command line

```text
memorydump.exe [options] [target.exe]
```

With no target and no `--self`,  it opens a file picker. choose at most one target, and do not combine a target with `--self`.

Options:

- `--self`: dump the current `memorydump.exe` process instead of selecting a target.
- `--coverage <percent>`: stop retrying each code section after reaching this percentage. The default is `100`; finite values above `100` are capped at `100`, while negative, nonnumeric, NaN, and overflowing values are rejected.
- `--max-stall <passes>`: stop a section after this many consecutive passes recover no new pages. The default `0` means no stall limit.
- `--retry-delay <milliseconds>`: delay between stalled recovery passes. The default is `250`.
- `--no-page-cache`: disable restoring and appending recovered code pages.
- `--page-cache <path>`: use a specific page-cache file instead of the generated default.
- `--clear-cache`: if the selected cache exists, ask before deleting it.

Examples:

```powershell
.\x64\Debug\memorydump.exe --self --max-stall 1
.\x64\Debug\memorydump.exe --coverage 95 --retry-delay 100 "C:\path\to\sample.exe"
.\x64\Release\memorydump.exe --no-page-cache "C:\path\to\sample.exe"
```

## Import-reference patterns

The current patcher recognizes IAT references matching these x64 forms:

- `FF 15 disp32`: RIP-relative indirect call.
- `FF 25 disp32`: RIP-relative indirect jump.
- `FF 35 disp32`: RIP-relative indirect push.
- `4x 8B/8D/3B/85 modrm disp32`: REX-prefixed RIP-relative load, LEA, compare, or test when the ModR/M byte uses `mod=00, r/m=101`.
- `4x FF 15/25 disp32`: REX-prefixed RIP-relative indirect call or jump.
- `4x 83 3D disp32 imm8` and `4x 81 3D disp32 imm32`: REX-prefixed RIP-relative compares.
- `48 A1 imm64`: absolute accumulator load.

If an import is missing, confirm that the target data points to a named loaded-module export and that the call site uses one of these forms. Forwarded-only or unmatched references are not patched.

## Read backend swap point

All normal reads go through:

```cpp
Mem::ReadProcessMemory(address, buffer, size)
```

That wrapper currently calls WinAPI `::ReadProcessMemory`. swap only that implementation for read-backend experiments.
