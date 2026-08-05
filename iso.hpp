#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include "common.hpp"

struct ISO9660Options {
    std::optional<std::string> label;
    std::vector<AddFile> add_files;
};

void create_iso9660_image(const std::filesystem::path& output_image,
    const std::filesystem::path& system_image, const ISO9660Options& options = {});
