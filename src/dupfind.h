#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace dupfind {

struct Options {
    std::wstring root;
    std::uint64_t min_size = 0;
    bool include_empty = false;
    unsigned threads = 0; // 0 = hardware concurrency
};

struct DuplicateGroup {
    std::uint64_t file_size = 0;
    std::string sha256_hex;
    std::vector<std::wstring> files;

    std::uint64_t reclaimable_bytes() const {
        return files.size() < 2 ? 0 : file_size * static_cast<std::uint64_t>(files.size() - 1);
    }
};

struct Stats {
    std::uint64_t files_scanned = 0;
    std::uint64_t bytes_scanned = 0;
    std::uint64_t files_hashed = 0;
    std::uint64_t bytes_hashed = 0;
    std::uint64_t duplicate_groups = 0;
    std::uint64_t duplicate_files = 0;
    std::uint64_t reclaimable_bytes = 0;
    std::uint64_t hardlinks_skipped = 0;
    std::uint64_t read_errors = 0;
};

struct Result {
    std::vector<DuplicateGroup> groups;
    Stats stats;
    std::vector<std::wstring> warnings;
    double elapsed_seconds = 0.0;
};

struct HashResult {
    bool ok = false;
    std::string hex;
    bool has_identity = false;
    std::uint64_t volume = 0;
    std::uint64_t file_index = 0;
    std::wstring error;
};

// Scans the directory recursively, groups files by size, hashes candidates with
// SHA-256 (Windows CNG), verifies matches byte by byte, and returns duplicate
// groups. Unreadable paths are reported through Result::warnings.
Result find_duplicates(const Options& options);

// Exposed for tests and for the CLI. Hashes a single file with BCrypt.
HashResult hash_file(const std::wstring& path);

// Compares two files through WinAPI file handles.
bool files_equal(const std::wstring& left, const std::wstring& right,
                 bool& equal, std::wstring& error);

std::string to_utf8(const std::wstring& text);

} // namespace dupfind
