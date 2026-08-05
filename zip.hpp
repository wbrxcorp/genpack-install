#pragma once

#include <filesystem>
#include <vector>

#include "common.hpp"

struct ZipOptions {
    std::vector<AddFile> add_files;
};

void create_zip_archive(const std::filesystem::path& output_zip,
    const std::filesystem::path& system_image, const ZipOptions& options = {});
