#include <sys/stat.h>

#include <minizip/zip.h>

#include <algorithm>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <regex>
#include <stdexcept>

#include "zip.hpp"
#include "image.hpp"

namespace {

// minizip writes plain 32bit ZIP archives here. Every limit a ZIP archive
// without ZIP64 has is checked before anything is written, rather than
// producing something no unpacker can read.
const uint64_t zip_size_limit = 4ULL * 1024 * 1024 * 1024;   // 32bit offsets and sizes
const size_t zip_max_entries = 65535;                        // 16bit entry count in the EOCD record
const size_t zip_max_name_length = 65535;                    // 16bit file name length field

// Sizes of the fixed parts of the ZIP structures, from APPNOTE.TXT.
const uint64_t zip_local_file_header_size = 30;
const uint64_t zip_central_directory_header_size = 46;
const uint64_t zip_end_of_central_directory_size = 22;

const std::string system_image_zip_path = "system.img";

class ZipWriter {
    zipFile zf = nullptr;
    bool entry_open = false;
public:
    ZipWriter(const ZipWriter&) = delete;
    ZipWriter& operator=(const ZipWriter&) = delete;
    explicit ZipWriter(const std::filesystem::path& path) {
        zf = zipOpen(path.c_str(), APPEND_STATUS_CREATE);
        if (!zf) throw std::runtime_error("Cannot open " + path.string() + " as a ZIP archive");
    }
    ~ZipWriter() {
        if (entry_open) zipCloseFileInZip(zf);
        if (zf) zipClose(zf, nullptr);
    }
    void begin(const std::string& name, std::time_t mtime) {
        zip_fileinfo info;
        memset(&info, 0, sizeof(info));
        auto tm = localtime(&mtime);
        info.tmz_date.tm_sec = tm->tm_sec;
        info.tmz_date.tm_min = tm->tm_min;
        info.tmz_date.tm_hour = tm->tm_hour;
        info.tmz_date.tm_mday = tm->tm_mday;
        info.tmz_date.tm_mon = tm->tm_mon;
        info.tmz_date.tm_year = tm->tm_year;
        if (zipOpenNewFileInZip(zf, name.c_str(), &info, nullptr, 0, nullptr, 0, nullptr,
                Z_DEFLATED, Z_DEFAULT_COMPRESSION) != ZIP_OK) {
            throw std::runtime_error("zipOpenNewFileInZip() failed for " + name);
        }
        entry_open = true;
    }
    void write(const void* data, size_t size) {
        if (size == 0) return;
        //else
        if (zipWriteInFileInZip(zf, data, (unsigned)size) != ZIP_OK) {
            throw std::runtime_error("zipWriteInFileInZip() failed");
        }
    }
    void end() {
        entry_open = false;
        if (zipCloseFileInZip(zf) != ZIP_OK) throw std::runtime_error("zipCloseFileInZip() failed");
    }
    void close() {
        auto rst = zipClose(zf, nullptr);
        zf = nullptr;
        if (rst != ZIP_OK) throw std::runtime_error("zipClose() failed");
    }
};

struct ZipEntry {
    enum class Source { LocalFile, ImageFile, Text };
    std::string name;               // entry name in the archive
    Source source;
    std::filesystem::path local;    // LocalFile
    std::string image_path;         // ImageFile
    std::string text;               // Text
    std::time_t mtime;
    uint64_t size;
};

void put(std::vector<ZipEntry>& entries, ZipEntry entry, const char* what)
{
    auto conflict = std::find_if(entries.begin(), entries.end(),
        [&entry](const auto& e) { return e.name == entry.name; });
    if (conflict != entries.end()) {
        std::cerr << "Warning: " << what << " overwrites " << entry.name << " in the ZIP archive." << std::endl;
        *conflict = entry;
    } else {
        entries.push_back(entry);
    }
}

std::time_t file_mtime(const std::filesystem::path& path)
{
    struct stat st;
    if (stat(path.c_str(), &st) < 0) throw std::runtime_error("stat(" + path.string() + ") failed");
    //else
    return st.st_mtime;
}

// The boot partition of a Raspberry Pi image gets its root device rewritten to
// the genpack system image loader.
std::string rewrite_cmdline(const std::string& original)
{
    std::string cmdline = original;
    auto newline = cmdline.find_first_of("\r\n");
    if (newline != std::string::npos) cmdline.erase(newline);
    cmdline = std::regex_replace(cmdline, std::regex(R"((^|\s)root=[^ ]*)"), "$1root=systemimg:auto");
    cmdline = std::regex_replace(cmdline, std::regex(R"((^|\s)rootfstype=[^ ]*)"), "");
    return cmdline;
}

} // namespace

void create_zip_archive(const std::filesystem::path& output_zip,
    const std::filesystem::path& system_image, const ZipOptions& options)
{
    if (!std::filesystem::is_regular_file(system_image)) {
        throw std::runtime_error("System image file " + system_image.string() + " does not exist or is not a regular file");
    }
    if (std::filesystem::exists(output_zip) && !std::filesystem::is_regular_file(output_zip)) {
        throw std::runtime_error(output_zip.string() + " cannot be overwritten");
    }
    if (same_file(output_zip, system_image)) {
        throw std::runtime_error("Output file " + output_zip.string() + " is the system image file itself");
    }
    for (const auto& add_file:options.add_files) {
        if (same_file(output_zip, add_file.src)) {
            throw std::runtime_error("Output file " + output_zip.string() + " is also given as --add source "
                + add_file.src.string());
        }
    }

    SystemImageReader image(system_image);
    check_system_image(image);

    std::vector<ZipEntry> entries;
    put(entries, ZipEntry {
        system_image_zip_path, ZipEntry::Source::LocalFile, system_image, "", "",
        file_mtime(system_image), std::filesystem::file_size(system_image)
    }, "the system image");

    // The EFI bootloaders are deliberately not put into the archive; the boot
    // partition they belong to is created by genpack-install --disk.

    if (image.is_regular_file("boot/bootcode.bin")) {
        std::cout << "Collecting boot files for raspberry pi..." << std::endl;
        image.walk_regular_files("boot", [&image,&entries](const std::string& relative) {
            auto path = "boot/" + relative;
            auto mtime = image.file_mtime(path).value_or(std::time(nullptr));
            if (relative == "cmdline.txt") {
                auto cmdline = rewrite_cmdline(image.read_file(path));
                put(entries, ZipEntry {
                    relative, ZipEntry::Source::Text, {}, "", cmdline, mtime, cmdline.size()
                }, "a raspberry pi boot file");
                return;
            }
            //else
            put(entries, ZipEntry {
                relative, ZipEntry::Source::ImageFile, {}, path, "", mtime,
                image.file_size(path).value_or(0)
            }, "a raspberry pi boot file");
        });
        std::cout << "Done." << std::endl;
    }

    for (const auto& add_file:options.add_files) {
        put(entries, ZipEntry {
            add_file.dest, ZipEntry::Source::LocalFile, add_file.src, "", "",
            file_mtime(add_file.src), std::filesystem::file_size(add_file.src)
        }, "--add");
    }

    std::vector<std::string> destinations;
    for (const auto& entry:entries) destinations.push_back(entry.name);
    check_dest_hierarchy(destinations);

    if (entries.size() > zip_max_entries) {
        throw std::runtime_error("There are " + std::to_string(entries.size())
            + " files to archive, more than the " + std::to_string(zip_max_entries)
            + " a ZIP archive without ZIP64 can index.");
    }
    // The content alone is not the whole archive: each entry carries a local
    // header and a central directory record, and deflate grows data that is
    // already compressed. Bound the worst case rather than the input size.
    // Testing the running total inside the loop keeps it below two entries'
    // worth of the limit, so the addition itself cannot overflow.
    uint64_t worst_case = zip_end_of_central_directory_size;
    for (const auto& entry:entries) {
        if (entry.name.size() > zip_max_name_length) {
            throw std::runtime_error("The name of " + entry.name + " is longer than the "
                + std::to_string(zip_max_name_length) + " bytes a ZIP archive without ZIP64 allows.");
        }
        if (entry.size >= zip_size_limit) {
            throw std::runtime_error(entry.name + " is " + size_str(entry.size)
                + ", which a ZIP archive without ZIP64 cannot hold.");
        }
        worst_case += zip_local_file_header_size + entry.name.size();
        worst_case += zip_central_directory_header_size + entry.name.size();
        worst_case += deflate_bound(entry.size);
        if (worst_case >= zip_size_limit) {
            throw std::runtime_error("The archive could reach " + size_str(worst_case)
                + " in the worst case, which does not fit in a ZIP archive without ZIP64."
                " Refusing to continue.");
        }
    }

    std::cout << "Creating ZIP archive..." << std::endl;

    // The archive is built next to its destination and only moved into place
    // once it is complete.
    TempOutputFile output(output_zip);
    {
        ZipWriter zip(output.path());
        for (const auto& entry:entries) {
            zip.begin(entry.name, entry.mtime);
            switch (entry.source) {
            case ZipEntry::Source::LocalFile: {
                std::ifstream in(entry.local, std::ios::binary);
                if (!in) throw std::runtime_error("Cannot open " + entry.local.string());
                //else
                std::vector<char> buf(1024 * 1024);
                while (in) {
                    in.read(buf.data(), buf.size());
                    if (in.bad()) throw std::runtime_error("Reading " + entry.local.string() + " failed");
                    //else
                    zip.write(buf.data(), in.gcount());
                }
                break;
            }
            case ZipEntry::Source::ImageFile:
                image.read_file(entry.image_path, [&zip](const void* data, size_t size) {
                    zip.write(data, size);
                });
                break;
            case ZipEntry::Source::Text:
                zip.write(entry.text.data(), entry.text.size());
                break;
            }
            zip.end();
        }
        zip.close();
    }
    output.commit();

    std::cout << "Done." << std::endl;
}
