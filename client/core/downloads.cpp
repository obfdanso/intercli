#include "downloads.h"
#include "common.h"

#include <cstdio>
#include <fstream>

namespace SecureComm {

namespace {

// Creates the file only if nothing by that name exists, even if it appeared
// just now ("x").
std::FILE* create_new(const std::filesystem::path& path) {
#ifdef _WIN32
    return _wfopen(path.wstring().c_str(), L"wbx");
#else
    return std::fopen(path.string().c_str(), "wbx");
#endif
}

// The cleaned name as a path. A name that isn't valid UTF-8 can't be turned
// into one on Windows (it throws), so it falls back to a plain name instead.
std::filesystem::path as_path(const std::string& name) {
    try {
        return std::filesystem::u8path(name);
    } catch (const std::exception&) {
        return std::filesystem::path("received-file");
    }
}

} // namespace

std::filesystem::path save_download(const std::filesystem::path& dir, const std::string& name,
                                    const std::vector<uint8_t>& data) {
    // The name is the sender's choice, so it is cleaned first.
    const std::filesystem::path safe = as_path(safe_file_name(name));
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    std::filesystem::path target = dir / safe;
    std::FILE* file = create_new(target);
    for (int n = 1; !file && n < 1000; ++n) {
        target = dir / (std::to_string(n) + "-");
        target += safe;
        file = create_new(target);
    }
    if (!file) {
        return {};
    }
    bool ok = std::fwrite(data.data(), 1, data.size(), file) == data.size();
    ok = std::fclose(file) == 0 && ok;
    if (!ok) {
        return {};
    }
#ifdef _WIN32
    std::ofstream mark(target.wstring() + L":Zone.Identifier", std::ios::binary);
    mark << "[ZoneTransfer]\r\nZoneId=3\r\n";
#endif
    return target;
}

} // namespace SecureComm
