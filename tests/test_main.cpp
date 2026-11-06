#include "dupfind.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <set>
#include <stdexcept>
#include <string>

namespace {

int g_checks = 0;
int g_failures = 0;

#define CHECK(condition)                                                                   \
    do {                                                                                   \
        ++g_checks;                                                                        \
        if (!(condition)) {                                                                \
            ++g_failures;                                                                  \
            std::cerr << __FILE__ << ':' << __LINE__ << ": CHECK failed: " #condition "\n"; \
        }                                                                                  \
    } while (false)

void check_u64(std::uint64_t actual, std::uint64_t expected, const char* expression,
               const char* file, int line) {
    ++g_checks;
    if (actual != expected) {
        ++g_failures;
        std::cerr << file << ':' << line << ": CHECK failed: " << expression
                  << " (actual=" << actual << ", expected=" << expected << ")\n";
    }
}

void check_size(std::size_t actual, std::size_t expected, const char* expression,
                const char* file, int line) {
    ++g_checks;
    if (actual != expected) {
        ++g_failures;
        std::cerr << file << ':' << line << ": CHECK failed: " << expression
                  << " (actual=" << actual << ", expected=" << expected << ")\n";
    }
}

void check_string(const std::string& actual, const std::string& expected,
                  const char* expression, const char* file, int line) {
    ++g_checks;
    if (actual != expected) {
        ++g_failures;
        std::cerr << file << ':' << line << ": CHECK failed: " << expression
                  << "\n  actual:   " << actual << "\n  expected: " << expected << '\n';
    }
}

#define CHECK_U64(actual, expected) \
    check_u64((actual), (expected), #actual " == " #expected, __FILE__, __LINE__)
#define CHECK_SIZE(actual, expected) \
    check_size((actual), (expected), #actual " == " #expected, __FILE__, __LINE__)
#define CHECK_STRING(actual, expected) \
    check_string((actual), (expected), #actual " == " #expected, __FILE__, __LINE__)

class TempDir {
public:
    TempDir() {
        wchar_t temp_path[MAX_PATH]{};
        const DWORD length = GetTempPathW(MAX_PATH, temp_path);
        if (length == 0 || length >= MAX_PATH) {
            throw std::runtime_error("GetTempPathW failed");
        }

        static std::atomic<unsigned> counter{0};
        path_ = std::wstring(temp_path) + L"dupfind_test_"
              + std::to_wstring(GetTickCount64()) + L"_"
              + std::to_wstring(counter.fetch_add(1));
        if (CreateDirectoryW(path_.c_str(), nullptr) == 0) {
            throw std::runtime_error("CreateDirectoryW failed");
        }
    }

    ~TempDir() {
        std::error_code error;
        std::filesystem::remove_all(std::filesystem::path(path_), error);
    }

    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;

    const std::wstring& path() const { return path_; }

private:
    std::wstring path_;
};

void create_directory(const std::wstring& path) {
    if (CreateDirectoryW(path.c_str(), nullptr) == 0) {
        const DWORD error = GetLastError();
        if (error != ERROR_ALREADY_EXISTS) {
            throw std::runtime_error("CreateDirectoryW failed");
        }
    }
}

void write_file(const std::wstring& path, const std::string& content) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("CreateFileW failed");
    }

    DWORD written = 0;
    if (!content.empty()) {
        if (WriteFile(file, content.data(), static_cast<DWORD>(content.size()),
                      &written, nullptr) == 0
            || written != content.size()) {
            CloseHandle(file);
            throw std::runtime_error("WriteFile failed");
        }
    }
    CloseHandle(file);
}

bool make_hard_link(const std::wstring& target, const std::wstring& link) {
    return CreateHardLinkW(link.c_str(), target.c_str(), nullptr) != 0;
}

std::wstring file_name(const std::wstring& path) {
    const std::size_t position = path.find_last_of(L"\\/");
    return position == std::wstring::npos ? path : path.substr(position + 1);
}

void test_hash() {
    TempDir directory;
    const std::wstring abc = directory.path() + L"\\abc.txt";
    const std::wstring hello = directory.path() + L"\\hello.txt";
    const std::wstring empty = directory.path() + L"\\empty.txt";

    write_file(abc, "abc");
    write_file(hello, "hello");
    write_file(empty, "");

    const dupfind::HashResult abc_hash = dupfind::hash_file(abc);
    CHECK(abc_hash.ok);
    CHECK(abc_hash.has_identity);
    CHECK_STRING(abc_hash.hex,
                 "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    const dupfind::HashResult hello_hash = dupfind::hash_file(hello);
    CHECK(hello_hash.ok);
    CHECK_STRING(hello_hash.hex,
                 "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");

    const dupfind::HashResult empty_hash = dupfind::hash_file(empty);
    CHECK(empty_hash.ok);
    CHECK_STRING(empty_hash.hex,
                 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    const dupfind::HashResult missing = dupfind::hash_file(directory.path() + L"\\missing.txt");
    CHECK(!missing.ok);
    CHECK(!missing.error.empty());
}

void test_files_equal() {
    TempDir directory;
    const std::wstring same_a = directory.path() + L"\\same_a.txt";
    const std::wstring same_b = directory.path() + L"\\same_b.txt";
    const std::wstring different = directory.path() + L"\\different.txt";
    const std::wstring empty_a = directory.path() + L"\\empty_a.txt";
    const std::wstring empty_b = directory.path() + L"\\empty_b.txt";

    write_file(same_a, "same");
    write_file(same_b, "same");
    write_file(different, "diff");
    write_file(empty_a, "");
    write_file(empty_b, "");

    bool equal = false;
    std::wstring error;

    CHECK(dupfind::files_equal(same_a, same_b, equal, error));
    CHECK(equal);

    CHECK(dupfind::files_equal(same_a, different, equal, error));
    CHECK(!equal);

    CHECK(dupfind::files_equal(empty_a, empty_b, equal, error));
    CHECK(equal);

    CHECK(!dupfind::files_equal(same_a, directory.path() + L"\\missing.txt", equal, error));
    CHECK(!error.empty());
}

void test_basic() {
    TempDir directory;
    create_directory(directory.path() + L"\\sub");
    write_file(directory.path() + L"\\a.txt", "hello");
    write_file(directory.path() + L"\\b.txt", "hello");
    write_file(directory.path() + L"\\sub\\c.txt", "hello");
    write_file(directory.path() + L"\\unique.txt", "world");
    write_file(directory.path() + L"\\empty1.bin", "");
    write_file(directory.path() + L"\\empty2.bin", "");

    dupfind::Options options;
    options.root = directory.path();
    options.threads = 2;

    const dupfind::Result result = dupfind::find_duplicates(options);

    CHECK_SIZE(result.groups.size(), 1);
    CHECK_U64(result.stats.files_scanned, 4);
    CHECK_U64(result.stats.bytes_scanned, 20);
    CHECK_U64(result.stats.files_hashed, 4);
    CHECK_U64(result.stats.bytes_hashed, 20);
    CHECK_U64(result.stats.duplicate_groups, 1);
    CHECK_U64(result.stats.duplicate_files, 2);
    CHECK_U64(result.stats.reclaimable_bytes, 10);
    CHECK_U64(result.stats.read_errors, 0);

    if (!result.groups.empty()) {
        const dupfind::DuplicateGroup& group = result.groups.front();
        CHECK_U64(group.file_size, 5);
        CHECK_SIZE(group.files.size(), 3);
        CHECK_STRING(group.sha256_hex,
                     "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");

        std::set<std::wstring> names;
        for (const std::wstring& file : group.files) {
            names.insert(file_name(file));
        }
        CHECK(names.count(L"a.txt") == 1);
        CHECK(names.count(L"b.txt") == 1);
        CHECK(names.count(L"c.txt") == 1);
    }
}

void test_filters() {
    TempDir directory;
    create_directory(directory.path() + L"\\sub");
    write_file(directory.path() + L"\\a.txt", "hello");
    write_file(directory.path() + L"\\b.txt", "hello");
    write_file(directory.path() + L"\\sub\\c.txt", "hello");
    write_file(directory.path() + L"\\unique.txt", "world");
    write_file(directory.path() + L"\\empty1.bin", "");
    write_file(directory.path() + L"\\empty2.bin", "");

    dupfind::Options options;
    options.root = directory.path();
    options.min_size = 6;

    dupfind::Result result = dupfind::find_duplicates(options);
    CHECK_U64(result.stats.files_scanned, 0);
    CHECK(result.groups.empty());

    options.min_size = 0;
    options.include_empty = true;
    result = dupfind::find_duplicates(options);

    CHECK_U64(result.stats.files_scanned, 6);
    CHECK_U64(result.stats.files_hashed, 6);
    CHECK_SIZE(result.groups.size(), 2);
    CHECK_U64(result.stats.duplicate_files, 3);
    CHECK_U64(result.stats.reclaimable_bytes, 10);

    if (result.groups.size() == 2) {
        CHECK_U64(result.groups[0].file_size, 5);
        CHECK_U64(result.groups[1].file_size, 0);
        CHECK_STRING(result.groups[1].sha256_hex,
                     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }
}

void test_hard_links() {
    TempDir directory;
    const std::wstring target = directory.path() + L"\\a.txt";
    const std::wstring other = directory.path() + L"\\b.txt";
    const std::wstring hard_link = directory.path() + L"\\hard.txt";

    write_file(target, "hello");
    write_file(other, "hello");
    if (!make_hard_link(target, hard_link)) {
        std::cout << "hard-link test skipped: cannot create a hard link here\n";
        return;
    }

    const dupfind::HashResult target_hash = dupfind::hash_file(target);
    const dupfind::HashResult link_hash = dupfind::hash_file(hard_link);
    CHECK(target_hash.has_identity);
    CHECK(link_hash.has_identity);
    CHECK_U64(target_hash.volume, link_hash.volume);
    CHECK_U64(target_hash.file_index, link_hash.file_index);

    dupfind::Options options;
    options.root = directory.path();
    options.threads = 1;

    const dupfind::Result result = dupfind::find_duplicates(options);
    CHECK_U64(result.stats.files_scanned, 3);
    CHECK_U64(result.stats.files_hashed, 3);
    CHECK_U64(result.stats.hardlinks_skipped, 1);
    CHECK_U64(result.stats.duplicate_files, 1);
    CHECK_U64(result.stats.reclaimable_bytes, 5);

    if (!result.groups.empty()) {
        CHECK_SIZE(result.groups.front().files.size(), 2);
        std::set<std::wstring> names;
        for (const std::wstring& file : result.groups.front().files) {
            names.insert(file_name(file));
        }
        CHECK(names.count(L"a.txt") == 1);
        CHECK(names.count(L"b.txt") == 1);
        CHECK(names.count(L"hard.txt") == 0);
    }
}

void test_unicode_paths() {
    TempDir directory;
    const std::wstring sub = directory.path() + L"\\папка";
    create_directory(sub);
    write_file(sub + L"\\копия.txt", "hello");
    write_file(sub + L"\\ещё копия.txt", "hello");

    dupfind::Options options;
    options.root = directory.path();
    options.threads = 1;

    const dupfind::Result result = dupfind::find_duplicates(options);
    CHECK_U64(result.stats.files_scanned, 2);
    CHECK_SIZE(result.groups.size(), 1);
    if (!result.groups.empty()) {
        CHECK_SIZE(result.groups.front().files.size(), 2);
    }
}

void test_missing_root() {
    TempDir directory;
    dupfind::Options options;
    options.root = directory.path() + L"\\missing";

    const dupfind::Result result = dupfind::find_duplicates(options);
    CHECK_U64(result.stats.files_scanned, 0);
    CHECK_U64(result.stats.read_errors, 1);
    CHECK(!result.warnings.empty());
    CHECK(result.groups.empty());
}

} // namespace

int main() {
    SetConsoleOutputCP(CP_UTF8);

    try {
        test_hash();
        test_files_equal();
        test_basic();
        test_filters();
        test_hard_links();
        test_unicode_paths();
        test_missing_root();
    } catch (const std::exception& error) {
        std::cerr << "fatal: " << error.what() << '\n';
        return 2;
    }

    if (g_failures == 0) {
        std::cout << "All tests passed (" << g_checks << " checks)\n";
        return 0;
    }
    std::cerr << g_failures << " of " << g_checks << " checks failed\n";
    return 1;
}
