// Saving a received file: never over another file, and marked as downloaded.

#include "downloads.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

using namespace SecureComm;

static int failures = 0;

static void check(bool condition, const std::string& what) {
    std::cout << (condition ? "  PASS: " : "  FAIL: ") << what << std::endl;
    failures += condition ? 0 : 1;
}

static std::string read(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

int main() {
    const std::filesystem::path dir = std::filesystem::temp_directory_path() / "intercli-test-downloads";
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);

    const std::vector<uint8_t> one = {'o', 'n', 'e'};
    const std::vector<uint8_t> two = {'t', 'w', 'o'};
    const std::filesystem::path first = save_download(dir, "notes.txt", one);
    check(first == dir / "notes.txt", "a file is saved under its own name");
    check(read(first) == "one", "with what was sent");
    const std::filesystem::path second = save_download(dir, "notes.txt", two);
    check(!second.empty() && second != first, "a second file of the same name gets another name");
    check(read(first) == "one" && read(second) == "two", "and the first is left alone");
    const std::filesystem::path sneaky = save_download(dir, "../../escape.txt", one);
    check(sneaky.parent_path() == dir, "a name with folders in it stays in the downloads folder");
    try {
        const std::filesystem::path broken = save_download(dir, std::string("bad\xff\xfe name.txt"), one);
        check(!broken.empty() && broken.parent_path() == dir && read(broken) == "one",
              "a name that isn't valid text is still saved, under a plain name");
    } catch (const std::exception&) {
        check(false, "a name that isn't valid text does not throw");
    }
#ifdef _WIN32
    const std::string mark = read(first.string() + ":Zone.Identifier");
    check(mark.find("ZoneId=3") != std::string::npos, "it is marked as coming from elsewhere");
#endif

    std::filesystem::remove_all(dir, ec);
    std::cout << (failures == 0 ? "All download tests passed" : "Some download tests failed") << std::endl;
    return failures == 0 ? 0 : 1;
}
