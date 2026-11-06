#include "dupfind.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace dupfind {
namespace {

constexpr std::size_t kMaxWarnings = 20;
constexpr std::size_t kReadBufferSize = 64 * 1024;

struct FileEntry {
    std::wstring path;
    std::uint64_t size = 0;
};

class FindHandle {
public:
    explicit FindHandle(HANDLE handle) : handle_(handle) {}
    ~FindHandle() {
        if (handle_ != INVALID_HANDLE_VALUE) {
            FindClose(handle_);
        }
    }

    FindHandle(const FindHandle&) = delete;
    FindHandle& operator=(const FindHandle&) = delete;

    HANDLE get() const { return handle_; }

private:
    HANDLE handle_;
};

class FileHandle {
public:
    explicit FileHandle(HANDLE handle) : handle_(handle) {}
    ~FileHandle() {
        if (handle_ != INVALID_HANDLE_VALUE && handle_ != nullptr) {
            CloseHandle(handle_);
        }
    }

    FileHandle(const FileHandle&) = delete;
    FileHandle& operator=(const FileHandle&) = delete;

    HANDLE get() const { return handle_; }

private:
    HANDLE handle_;
};

class AlgorithmHandle {
public:
    explicit AlgorithmHandle(BCRYPT_ALG_HANDLE handle) : handle_(handle) {}
    ~AlgorithmHandle() {
        if (handle_ != nullptr) {
            BCryptCloseAlgorithmProvider(handle_, 0);
        }
    }

    AlgorithmHandle(const AlgorithmHandle&) = delete;
    AlgorithmHandle& operator=(const AlgorithmHandle&) = delete;

private:
    BCRYPT_ALG_HANDLE handle_;
};

class HashHandle {
public:
    explicit HashHandle(BCRYPT_HASH_HANDLE handle) : handle_(handle) {}
    ~HashHandle() {
        if (handle_ != nullptr) {
            BCryptDestroyHash(handle_);
        }
    }

    HashHandle(const HashHandle&) = delete;
    HashHandle& operator=(const HashHandle&) = delete;

private:
    BCRYPT_HASH_HANDLE handle_;
};

std::wstring windows_error(DWORD code) {
    wchar_t* buffer = nullptr;
    const DWORD length = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, code, 0, reinterpret_cast<LPWSTR>(&buffer), 0, nullptr);

    std::wstring message = L"Windows error " + std::to_wstring(code);
    if (length != 0 && buffer != nullptr) {
        message.assign(buffer, length);
        while (!message.empty()
               && (message.back() == L'\r' || message.back() == L'\n' || message.back() == L' ')) {
            message.pop_back();
        }
    }
    if (buffer != nullptr) {
        LocalFree(buffer);
    }
    return message;
}

std::wstring bcrypt_error(NTSTATUS status) {
    wchar_t buffer[40]{};
    std::swprintf(buffer, 40, L"BCrypt error 0x%08lX", static_cast<unsigned long>(status));
    return std::wstring(buffer);
}

void add_error(Result& result, std::wstring message) {
    ++result.stats.read_errors;
    if (result.warnings.size() < kMaxWarnings) {
        result.warnings.push_back(std::move(message));
    }
}

double seconds_since(const std::chrono::steady_clock::time_point& start) {
    return std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
}

std::wstring join_path(const std::wstring& directory, const wchar_t* name) {
    std::wstring path = directory;
    if (!path.empty() && path.back() != L'\\' && path.back() != L'/') {
        path += L'\\';
    }
    path += name;
    return path;
}

std::wstring lowercase_name(std::wstring text) {
    for (wchar_t& character : text) {
        character = static_cast<wchar_t>(std::towlower(character));
    }
    return text;
}

void scan_directory(const std::wstring& directory, const Options& options,
                    const std::unordered_set<std::wstring>& excluded_directories,
                    Result& result, std::vector<FileEntry>& files) {
    const std::wstring pattern = join_path(directory, L"*");
    WIN32_FIND_DATAW data{};
    FindHandle find(FindFirstFileW(pattern.c_str(), &data));
    if (find.get() == INVALID_HANDLE_VALUE) {
        const DWORD error = GetLastError();
        // An empty directory is not an error.
        if (error != ERROR_FILE_NOT_FOUND) {
            add_error(result, L"cannot list '" + directory + L"': " + windows_error(error));
        }
        return;
    }

    do {
        if (std::wcscmp(data.cFileName, L".") == 0 || std::wcscmp(data.cFileName, L"..") == 0) {
            continue;
        }

        const std::wstring path = join_path(directory, data.cFileName);
        if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
            // Do not follow junctions and directory symlinks: this keeps the
            // walk finite and avoids counting the same file through two paths.
            if ((data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0) {
                const bool excluded = !excluded_directories.empty()
                    && excluded_directories.find(lowercase_name(data.cFileName))
                        != excluded_directories.end();
                if (!excluded) {
                    scan_directory(path, options, excluded_directories, result, files);
                }
            }
            continue;
        }
        if ((data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
            continue;
        }

        const std::uint64_t size =
            (static_cast<std::uint64_t>(data.nFileSizeHigh) << 32)
            | static_cast<std::uint64_t>(data.nFileSizeLow);

        if (size == 0 && !options.include_empty) {
            continue;
        }
        if (size < options.min_size) {
            continue;
        }

        ++result.stats.files_scanned;
        result.stats.bytes_scanned += size;
        files.push_back(FileEntry{path, size});
    } while (FindNextFileW(find.get(), &data) != 0);

    const DWORD error = GetLastError();
    if (error != ERROR_NO_MORE_FILES) {
        add_error(result, L"cannot continue listing '" + directory + L"': " + windows_error(error));
    }
}

std::string digest_to_hex(const BYTE* digest, std::size_t size) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string result(size * 2, '0');
    for (std::size_t index = 0; index < size; ++index) {
        result[index * 2] = kHex[digest[index] >> 4];
        result[index * 2 + 1] = kHex[digest[index] & 0x0fu];
    }
    return result;
}

} // namespace

HashResult hash_file(const std::wstring& path) {
    HashResult result;

    FileHandle file(CreateFileW(path.c_str(), GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                nullptr, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
    if (file.get() == INVALID_HANDLE_VALUE) {
        result.error = L"cannot open '" + path + L"': " + windows_error(GetLastError());
        return result;
    }

    BY_HANDLE_FILE_INFORMATION information{};
    if (GetFileInformationByHandle(file.get(), &information) != 0) {
        result.has_identity = true;
        result.volume = information.dwVolumeSerialNumber;
        result.file_index = (static_cast<std::uint64_t>(information.nFileIndexHigh) << 32)
                          | static_cast<std::uint64_t>(information.nFileIndexLow);
    }

    BCRYPT_ALG_HANDLE algorithm = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status)) {
        result.error = L"cannot open SHA-256 provider for '" + path + L"': " + bcrypt_error(status);
        return result;
    }
    AlgorithmHandle algorithm_guard(algorithm);

    BCRYPT_HASH_HANDLE hash = nullptr;
    status = BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0);
    if (!BCRYPT_SUCCESS(status)) {
        result.error = L"cannot create hash for '" + path + L"': " + bcrypt_error(status);
        return result;
    }
    HashHandle hash_guard(hash);

    std::vector<BYTE> buffer(kReadBufferSize);
    for (;;) {
        DWORD bytes_read = 0;
        if (ReadFile(file.get(), buffer.data(), static_cast<DWORD>(buffer.size()),
                     &bytes_read, nullptr) == 0) {
            result.error = L"cannot read '" + path + L"': " + windows_error(GetLastError());
            return result;
        }
        if (bytes_read == 0) {
            break;
        }
        status = BCryptHashData(hash, buffer.data(), bytes_read, 0);
        if (!BCRYPT_SUCCESS(status)) {
            result.error = L"cannot hash '" + path + L"': " + bcrypt_error(status);
            return result;
        }
    }

    BYTE digest[32]{};
    status = BCryptFinishHash(hash, digest, sizeof(digest), 0);
    if (!BCRYPT_SUCCESS(status)) {
        result.error = L"cannot finish hash for '" + path + L"': " + bcrypt_error(status);
        return result;
    }

    result.hex = digest_to_hex(digest, sizeof(digest));
    result.ok = true;
    return result;
}

bool files_equal(const std::wstring& left, const std::wstring& right,
                 bool& equal, std::wstring& error) {
    equal = false;

    FileHandle left_file(CreateFileW(left.c_str(), GENERIC_READ,
                                     FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                     nullptr, OPEN_EXISTING,
                                     FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
    if (left_file.get() == INVALID_HANDLE_VALUE) {
        error = L"cannot open '" + left + L"': " + windows_error(GetLastError());
        return false;
    }

    FileHandle right_file(CreateFileW(right.c_str(), GENERIC_READ,
                                      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                      nullptr, OPEN_EXISTING,
                                      FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
    if (right_file.get() == INVALID_HANDLE_VALUE) {
        error = L"cannot open '" + right + L"': " + windows_error(GetLastError());
        return false;
    }

    LARGE_INTEGER left_size{};
    LARGE_INTEGER right_size{};
    if (GetFileSizeEx(left_file.get(), &left_size) == 0
        || GetFileSizeEx(right_file.get(), &right_size) == 0) {
        error = L"cannot read size while comparing '" + left + L"' and '" + right
              + L"': " + windows_error(GetLastError());
        return false;
    }

    if (left_size.QuadPart != right_size.QuadPart) {
        return true;
    }
    if (left_size.QuadPart == 0) {
        equal = true;
        return true;
    }

    std::vector<BYTE> left_buffer(kReadBufferSize);
    std::vector<BYTE> right_buffer(kReadBufferSize);
    for (;;) {
        DWORD left_read = 0;
        DWORD right_read = 0;
        if (ReadFile(left_file.get(), left_buffer.data(), static_cast<DWORD>(left_buffer.size()),
                     &left_read, nullptr) == 0
            || ReadFile(right_file.get(), right_buffer.data(), static_cast<DWORD>(right_buffer.size()),
                        &right_read, nullptr) == 0) {
            error = L"cannot read while comparing '" + left + L"' and '" + right
                  + L"': " + windows_error(GetLastError());
            return false;
        }

        if (left_read != right_read) {
            return true;
        }
        if (left_read == 0) {
            equal = true;
            return true;
        }
        if (std::memcmp(left_buffer.data(), right_buffer.data(), left_read) != 0) {
            return true;
        }
    }
}

Result find_duplicates(const Options& options) {
    const auto started = std::chrono::steady_clock::now();
    Result result;

    const DWORD attributes = GetFileAttributesW(options.root.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        add_error(result, L"cannot access '" + options.root + L"': " + windows_error(GetLastError()));
        result.elapsed_seconds = seconds_since(started);
        return result;
    }
    if ((attributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
        add_error(result, L"not a directory: '" + options.root + L"'");
        result.elapsed_seconds = seconds_since(started);
        return result;
    }

    std::unordered_set<std::wstring> excluded_directories;
    excluded_directories.reserve(options.excluded_directory_names.size());
    for (const std::wstring& name : options.excluded_directory_names) {
        excluded_directories.insert(lowercase_name(name));
    }

    std::vector<FileEntry> files;
    scan_directory(options.root, options, excluded_directories, result, files);

    // Files with a unique size cannot have duplicates, so they are never read.
    std::unordered_map<std::uint64_t, std::vector<std::size_t>> by_size;
    for (std::size_t index = 0; index < files.size(); ++index) {
        by_size[files[index].size].push_back(index);
    }

    std::vector<std::size_t> candidates;
    for (const auto& entry : by_size) {
        if (entry.second.size() >= 2) {
            candidates.insert(candidates.end(), entry.second.begin(), entry.second.end());
        }
    }

    if (candidates.empty()) {
        result.elapsed_seconds = seconds_since(started);
        return result;
    }

    unsigned workers = options.threads;
    if (workers == 0) {
        workers = std::thread::hardware_concurrency();
    }
    if (workers == 0) {
        workers = 4;
    }
    workers = std::clamp(workers, 1u, 64u);
    workers = std::min<unsigned>(workers, static_cast<unsigned>(candidates.size()));

    // Each worker writes only to hashes[index], so the atomic counter is the
    // only shared mutable state in this phase.
    std::vector<HashResult> hashes(candidates.size());
    std::atomic<std::size_t> next{0};
    std::vector<std::thread> threads;
    threads.reserve(workers);
    for (unsigned worker = 0; worker < workers; ++worker) {
        threads.emplace_back([&] {
            for (;;) {
                const std::size_t index = next.fetch_add(1, std::memory_order_relaxed);
                if (index >= candidates.size()) {
                    break;
                }
                hashes[index] = hash_file(files[candidates[index]].path);
            }
        });
    }
    for (std::thread& thread : threads) {
        thread.join();
    }

    std::vector<HashResult> hash_by_file(files.size());
    std::unordered_map<std::string, std::vector<std::size_t>> by_hash;
    for (std::size_t index = 0; index < candidates.size(); ++index) {
        const std::size_t file_index = candidates[index];
        if (!hashes[index].ok) {
            add_error(result, hashes[index].error);
            continue;
        }

        ++result.stats.files_hashed;
        result.stats.bytes_hashed += files[file_index].size;
        by_hash[hashes[index].hex].push_back(file_index);
        hash_by_file[file_index] = std::move(hashes[index]);
    }

    for (const auto& entry : by_hash) {
        const std::string& digest = entry.first;
        std::vector<std::size_t> group = entry.second;
        if (group.size() < 2) {
            continue;
        }

        std::sort(group.begin(), group.end(), [&](std::size_t left, std::size_t right) {
            return files[left].path < files[right].path;
        });

        // Hard links point at the same file on disk and must not be reported as
        // duplicates. GetFileInformationByHandle gives us volume + file index.
        std::vector<std::size_t> unique_files;
        std::vector<std::pair<std::uint64_t, std::uint64_t>> identities;
        for (const std::size_t index : group) {
            const HashResult& hash = hash_by_file[index];
            if (hash.has_identity) {
                const std::pair<std::uint64_t, std::uint64_t> identity{hash.volume, hash.file_index};
                if (std::find(identities.begin(), identities.end(), identity) != identities.end()) {
                    ++result.stats.hardlinks_skipped;
                    continue;
                }
                identities.push_back(identity);
            }
            unique_files.push_back(index);
        }

        if (unique_files.size() < 2) {
            continue;
        }

        // Verify SHA-256 matches byte by byte. A theoretical collision then
        // cannot produce a false duplicate group.
        std::vector<std::vector<std::size_t>> clusters;
        for (const std::size_t index : unique_files) {
            bool placed = false;
            for (std::vector<std::size_t>& cluster : clusters) {
                bool equal = false;
                std::wstring error;
                if (!files_equal(files[cluster.front()].path, files[index].path, equal, error)) {
                    add_error(result, std::move(error));
                    continue;
                }
                if (equal) {
                    cluster.push_back(index);
                    placed = true;
                    break;
                }
            }
            if (!placed) {
                clusters.push_back({index});
            }
        }

        for (const std::vector<std::size_t>& cluster : clusters) {
            if (cluster.size() < 2) {
                continue;
            }

            DuplicateGroup duplicate;
            duplicate.file_size = files[cluster.front()].size;
            duplicate.sha256_hex = digest;
            duplicate.files.reserve(cluster.size());
            for (const std::size_t index : cluster) {
                duplicate.files.push_back(files[index].path);
            }
            std::sort(duplicate.files.begin(), duplicate.files.end());

            result.stats.duplicate_groups += 1;
            result.stats.duplicate_files += duplicate.files.size() - 1;
            result.stats.reclaimable_bytes += duplicate.reclaimable_bytes();
            result.groups.push_back(std::move(duplicate));
        }
    }

    std::sort(result.groups.begin(), result.groups.end(),
              [](const DuplicateGroup& left, const DuplicateGroup& right) {
                  if (left.reclaimable_bytes() != right.reclaimable_bytes()) {
                      return left.reclaimable_bytes() > right.reclaimable_bytes();
                  }
                  return left.files.front() < right.files.front();
              });

    result.elapsed_seconds = seconds_since(started);
    return result;
}

std::string to_utf8(const std::wstring& text) {
    if (text.empty()) {
        return {};
    }

    const int size = WideCharToMultiByte(CP_UTF8, 0, text.data(),
                                         static_cast<int>(text.size()),
                                         nullptr, 0, nullptr, nullptr);
    if (size <= 0) {
        return {};
    }

    std::string result(static_cast<std::size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                        result.data(), size, nullptr, nullptr);
    return result;
}

} // namespace dupfind
