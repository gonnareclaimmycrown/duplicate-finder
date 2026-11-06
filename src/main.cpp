#include "dupfind.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <shellapi.h>

#include <cerrno>
#include <cstdint>
#include <cwchar>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

namespace {

struct CliOptions {
    dupfind::Options find;
    bool help = false;
};

void print_usage() {
    std::cout
        << "dupfind - find duplicate files by content (Windows console utility)\n\n"
        << "Usage:\n"
        << "  dupfind <directory> [options]\n\n"
        << "Options:\n"
        << "  --threads N        Worker threads; 0 = hardware concurrency (default: 0)\n"
        << "  --min-size BYTES   Ignore files smaller than BYTES (default: 0)\n"
        << "  --include-empty    Include zero-byte files (skipped by default)\n"
        << "  -h, --help         Show this help\n\n"
        << "Examples:\n"
        << "  dupfind C:\\Users\\me\\Downloads\n"
        << "  dupfind D:\\Photos --threads 8 --min-size 1048576\n";
}

bool parse_unsigned(const std::wstring& text, unsigned& value) {
    if (text.empty() || text.front() == L'-' || text.front() == L'+') {
        return false;
    }

    errno = 0;
    wchar_t* end = nullptr;
    const unsigned long parsed = std::wcstoul(text.c_str(), &end, 10);
    if (errno != 0 || end == text.c_str() || *end != L'\0'
        || parsed > std::numeric_limits<unsigned>::max()) {
        return false;
    }
    value = static_cast<unsigned>(parsed);
    return true;
}

bool parse_u64(const std::wstring& text, std::uint64_t& value) {
    if (text.empty() || text.front() == L'-' || text.front() == L'+') {
        return false;
    }

    errno = 0;
    wchar_t* end = nullptr;
    const unsigned long long parsed = std::wcstoull(text.c_str(), &end, 10);
    if (errno != 0 || end == text.c_str() || *end != L'\0') {
        return false;
    }
    value = static_cast<std::uint64_t>(parsed);
    return true;
}

bool parse_args(const std::vector<std::wstring>& args, CliOptions& cli, std::wstring& error) {
    bool end_of_options = false;

    for (std::size_t index = 1; index < args.size(); ++index) {
        const std::wstring& argument = args[index];

        if (!end_of_options && argument == L"--") {
            end_of_options = true;
            continue;
        }
        if (!end_of_options && (argument == L"-h" || argument == L"--help")) {
            cli.help = true;
            continue;
        }
        if (!end_of_options && argument == L"--include-empty") {
            cli.find.include_empty = true;
            continue;
        }
        if (!end_of_options && argument == L"--threads") {
            if (index + 1 >= args.size()) {
                error = L"missing value for --threads";
                return false;
            }
            unsigned value = 0;
            if (!parse_unsigned(args[++index], value)) {
                error = L"invalid --threads value: " + args[index];
                return false;
            }
            cli.find.threads = value;
            continue;
        }
        if (!end_of_options && argument == L"--min-size") {
            if (index + 1 >= args.size()) {
                error = L"missing value for --min-size";
                return false;
            }
            std::uint64_t value = 0;
            if (!parse_u64(args[++index], value)) {
                error = L"invalid --min-size value: " + args[index];
                return false;
            }
            cli.find.min_size = value;
            continue;
        }
        if (!end_of_options && !argument.empty() && argument.front() == L'-') {
            error = L"unknown option: " + argument;
            return false;
        }

        if (!cli.find.root.empty()) {
            error = L"only one directory is supported";
            return false;
        }
        cli.find.root = argument;
    }

    if (!cli.help && cli.find.root.empty()) {
        error = L"no directory specified";
        return false;
    }
    return true;
}

std::string format_bytes(std::uint64_t bytes) {
    static constexpr const char* kUnits[] = {"B", "KiB", "MiB", "GiB", "TiB", "PiB"};

    double value = static_cast<double>(bytes);
    std::size_t unit = 0;
    while (value >= 1024.0 && unit + 1 < std::size(kUnits)) {
        value /= 1024.0;
        ++unit;
    }

    std::ostringstream out;
    if (unit == 0) {
        out << bytes << " B";
    } else {
        out << std::fixed << std::setprecision(2) << value << ' ' << kUnits[unit];
    }
    return out.str();
}

std::string plural(std::uint64_t count, const char* singular, const char* plural_form) {
    return std::to_string(count) + ' ' + (count == 1 ? singular : plural_form);
}

void print_warnings(const dupfind::Result& result) {
    for (const std::wstring& warning : result.warnings) {
        std::cerr << "warning: " << dupfind::to_utf8(warning) << '\n';
    }
    if (result.stats.read_errors > result.warnings.size()) {
        std::cerr << "warning: " << (result.stats.read_errors - result.warnings.size())
                  << " more warnings not shown\n";
    }
}

void print_result(const dupfind::Result& result) {
    if (result.groups.empty()) {
        std::cout << "No duplicate files found.\n";
    } else {
        for (std::size_t index = 0; index < result.groups.size(); ++index) {
            const dupfind::DuplicateGroup& group = result.groups[index];
            std::cout << "Duplicate group " << (index + 1) << '/' << result.groups.size()
                      << ": " << group.files.size() << " files x "
                      << format_bytes(group.file_size) << " ("
                      << format_bytes(group.reclaimable_bytes()) << " reclaimable)\n";
            std::cout << "  SHA-256: " << group.sha256_hex << '\n';
            for (const std::wstring& file : group.files) {
                std::cout << "  " << dupfind::to_utf8(file) << '\n';
            }
            std::cout << '\n';
        }
    }

    std::cout << "Scanned " << plural(result.stats.files_scanned, "file", "files")
              << " (" << format_bytes(result.stats.bytes_scanned) << ") in "
              << std::fixed << std::setprecision(2) << result.elapsed_seconds << " s\n";
    std::cout << "Hashed " << plural(result.stats.files_hashed, "candidate", "candidates")
              << " (" << format_bytes(result.stats.bytes_hashed) << ")\n";

    if (result.groups.empty()) {
        std::cout << "Found no duplicates.\n";
    } else {
        std::cout << "Found "
                  << plural(result.stats.duplicate_groups, "duplicate group", "duplicate groups")
                  << ": " << plural(result.stats.duplicate_files, "redundant file", "redundant files")
                  << ", " << format_bytes(result.stats.reclaimable_bytes) << " reclaimable\n";
    }

    if (result.stats.hardlinks_skipped > 0) {
        std::cout << "Skipped "
                  << plural(result.stats.hardlinks_skipped, "hard link", "hard links")
                  << " (same file on disk)\n";
    }
    if (result.stats.read_errors > 0) {
        std::cout << "Warnings: " << plural(result.stats.read_errors, "path", "paths")
                  << " could not be read\n";
    }
}

} // namespace

int main() {
    SetConsoleOutputCP(CP_UTF8);

    int argument_count = 0;
    LPWSTR* wide_arguments = CommandLineToArgvW(GetCommandLineW(), &argument_count);
    if (wide_arguments == nullptr) {
        std::cerr << "error: cannot read the command line\n";
        return 2;
    }

    std::vector<std::wstring> arguments(wide_arguments, wide_arguments + argument_count);
    LocalFree(wide_arguments);

    CliOptions cli;
    std::wstring error;
    if (!parse_args(arguments, cli, error)) {
        std::cerr << "error: " << dupfind::to_utf8(error) << "\n\n";
        print_usage();
        return 2;
    }

    if (cli.help) {
        print_usage();
        return 0;
    }

    const dupfind::Result result = dupfind::find_duplicates(cli.find);
    print_result(result);
    print_warnings(result);

    if (result.stats.files_scanned == 0 && result.stats.read_errors > 0) {
        return 1;
    }
    return 0;
}
