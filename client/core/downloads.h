#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace SecureComm {

// Saves a received file in dir under a cleaned-up version of the sender's
// name. Never replaces a file that is already there: the name gets a number
// in front instead. On Windows the file is marked as coming from elsewhere,
// the way a browser marks a download, so Windows warns before running it.
// Returns where it was saved, or an empty path if it could not be.
std::filesystem::path save_download(const std::filesystem::path& dir, const std::string& name,
                                    const std::vector<uint8_t>& data);

} // namespace SecureComm
