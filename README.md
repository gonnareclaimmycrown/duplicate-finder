# dupfind

`dupfind` is a small **Windows console utility** that finds duplicate files by content. There is no GUI: it takes a directory, walks it with `FindFirstFileW` / `FindNextFileW`, and prints groups of files with identical bytes.

The project is deliberately WinAPI-first. It was written as a portfolio piece for a Junior C++ Developer (Windows) role and is small enough to read in one sitting.

## Features

- Recursive directory scan through `FindFirstFileW` / `FindNextFileW`.
- Size-first filtering: a file with a unique size cannot have a duplicate and is never read.
- SHA-256 through Windows CNG (`BCryptOpenAlgorithmProvider`, `BCryptHashData`, `BCryptFinishHash`).
- Parallel hashing with `std::thread` and an atomic work counter.
- Hard-link detection through `GetFileInformationByHandle` (volume serial + file index).
- Byte-by-byte verification of every SHA-256 match, so a theoretical collision cannot create a false group.
- Unicode paths through the wide command line (`CommandLineToArgvW`) and UTF-8 console output.
- Unit and integration tests wired into CTest.

## Build

Requirements: Windows 10/11, Visual Studio 2022 with **Desktop development with C++**, and CMake 3.20+.

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

The executable is written to `build\Release\dupfind.exe`.

MinGW-w64 also works:

```bash
g++ -std=c++20 -O2 -Wall -Wextra -Wpedantic -Isrc \
    src/main.cpp src/dupfind.cpp \
    -o dupfind.exe -lbcrypt -lshell32
```

## Usage

```text
dupfind <directory> [options]

Options:
  --threads N        Worker threads; 0 = hardware concurrency (default: 0)
  --min-size BYTES   Ignore files smaller than BYTES (default: 0)
  --include-empty    Include zero-byte files (skipped by default)
  -h, --help         Show this help
```

Examples:

```powershell
dupfind C:\Users\me\Downloads
dupfind D:\Photos --threads 8 --min-size 1048576
```

Example output:

```text
Duplicate group 1/2: 2 files x 16.00 KiB (16.00 KiB reclaimable)
  SHA-256: a1f259d4365ed4320c377ce26f5c8c56dcdc9a89e7b641bfd8eabfbbeac86654
  C:\data\photo copy.jpg
  C:\data\фото копия.jpg

Duplicate group 2/2: 3 files x 45 B (90 B reclaimable)
  SHA-256: 22f54567ed79dcf2423e7202a02482ce1406e42152e158ba8e0f44c6bbc6eaf9
  C:\data\a.txt
  C:\data\b.txt
  C:\data\sub\c.txt

Scanned 7 files (32.19 KiB) in 0.01 s
Hashed 6 candidates (32.18 KiB)
Found 2 duplicate groups: 3 redundant files, 16.09 KiB reclaimable
Skipped 1 hard link (same file on disk)
```

## How it works

```text
directory
   |
   v
FindFirstFileW / FindNextFileW  (recursive scan, symlinks skipped)
   |
   v
group by size  ->  unique sizes are dropped
   |
   v
SHA-256 through BCrypt (parallel workers, one result slot per file)
   |
   v
group by digest  ->  skip hard links  ->  byte-by-byte verification
   |
   v
console report
```

1. **Scan.** The walk starts with `FindFirstFileW(directory\*)`. Directories are visited recursively; reparse points (symlinks and junctions) are skipped so a cycle cannot make the scan infinite.
2. **Size filter.** Files are grouped by size. A unique size means the file cannot have a duplicate, so it is never opened.
3. **Hash candidates.** Only files sharing a size are hashed. `BCryptOpenAlgorithmProvider(BCRYPT_SHA256_ALGORITHM)` and `BCryptHashData` compute SHA-256 in 64 KiB chunks.
4. **Parallelize.** A fixed number of `std::thread` workers pulls candidate indices from `std::atomic<std::size_t>`. Each worker writes only to its own slot; the main thread joins before reading the results.
5. **Confirm.** Every digest group is checked byte by byte with `ReadFile`. Hard links are skipped using the file identity returned by `GetFileInformationByHandle`.
6. **Report.** Groups are sorted by reclaimable space and printed to the console.

## Windows APIs used

| API | Why it is there |
| --- | --- |
| `FindFirstFileW`, `FindNextFileW`, `FindClose` | Recursive directory enumeration and file metadata (size, attributes). |
| `CreateFileW`, `ReadFile`, `CloseHandle` | Open files and read them in chunks for hashing and byte comparison. |
| `GetFileSizeEx` | Compare file sizes before reading. |
| `GetFileInformationByHandle` | Get the volume serial number and file index used to recognize hard links. |
| `BCryptOpenAlgorithmProvider`, `BCryptCreateHash`, `BCryptHashData`, `BCryptFinishHash`, `BCryptDestroyHash` | SHA-256 through Windows CNG. |
| `CommandLineToArgvW` | Read the wide command line, so Unicode paths work. |
| `WideCharToMultiByte`, `SetConsoleOutputCP` | Print UTF-8 to the console. |
| `FormatMessageW` | Turn a Windows error code into a readable message. |

Handles and BCrypt objects are wrapped in small RAII classes, so error paths do not leak resources.

## Complexity

Let `F` be the number of files and `B` the bytes in files that share a size with at least one other file.

- Scan: `O(F)`.
- Hashing: `O(B)`, parallelized across worker threads.
- Memory: `O(F)` for the file list and one digest per candidate; file contents are read in fixed 64 KiB buffers.
- Verification only runs inside digest groups.

## Tests

```powershell
ctest --test-dir build -C Release --output-on-failure
```

The test suite covers:

- Known SHA-256 vectors (`"abc"`, `"hello"`, an empty file).
- Byte comparison: equal files, different files, empty files, missing files.
- Duplicate detection, minimum-size and empty-file filters.
- Hard links: they must not be reported as duplicates.
- Unicode directory and file names.
- A missing root: warning and error accounting without a crash.

## Limitations

- Windows-only by design. The algorithm is portable; the file layer is WinAPI.
- Symlinks and junctions are skipped rather than followed.
- Files modified during the scan are not locked; a size or digest may reflect different moments in time.
- The utility scans on demand. A persistent index would be the next step for repeated scans of large trees.
- `--min-size` takes plain bytes; there is no `1M` suffix parser in this version.

## Why this project

It exercises the core requirements of a Windows C++ role on a small, understandable surface:

- C/C++ pointers and buffers (`std::vector<BYTE>`, `ReadFile`, `BCryptHashData`).
- Algorithms and data structures (`std::unordered_map`, sorting, grouping, hashing).
- Windows API (file enumeration, file I/O, CNG, file identity, Unicode).
- Multithreading (`std::thread`, `std::atomic`, one result slot per worker).
- Testing (unit and integration tests through CTest).
