#include <sqfs/compressor.h>
#include <sqfs/data_reader.h>
#include <sqfs/dir.h>
#include <sqfs/dir_reader.h>
#include <sqfs/error.h>
#include <sqfs/inode.h>
#include <sqfs/io.h>
#include <sqfs/super.h>

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>

#include "image.hpp"

namespace {

struct InodeDeleter {
    void operator()(sqfs_inode_generic_t* inode) const { if (inode) sqfs_free(inode); }
};
using Inode = std::unique_ptr<sqfs_inode_generic_t, InodeDeleter>;

bool is_symlink(const sqfs_inode_generic_t* inode)
{
    return inode->base.type == SQFS_INODE_SLINK || inode->base.type == SQFS_INODE_EXT_SLINK;
}

bool is_directory(const sqfs_inode_generic_t* inode)
{
    return inode->base.type == SQFS_INODE_DIR || inode->base.type == SQFS_INODE_EXT_DIR;
}

bool is_regular_file(const sqfs_inode_generic_t* inode)
{
    return inode->base.type == SQFS_INODE_FILE || inode->base.type == SQFS_INODE_EXT_FILE;
}

std::string symlink_target(const sqfs_inode_generic_t* inode)
{
    auto size = (inode->base.type == SQFS_INODE_SLINK)? inode->data.slink.target_size
        : inode->data.slink_ext.target_size;
    return std::string((const char*)inode->extra, size);
}

std::vector<std::string> split_path(const std::string& path)
{
    std::vector<std::string> components;
    for (std::string::size_type i = 0, j; i < path.size(); i = j + 1) {
        j = path.find('/', i);
        if (j == std::string::npos) j = path.size();
        if (j > i) components.emplace_back(path.substr(i, j - i));
    }
    return components;
}

} // namespace

struct SystemImageReader::Impl {
    std::filesystem::path image_path;
    sqfs_file_t* file = nullptr;
    sqfs_super_t super{};
    sqfs_compressor_t* compressor = nullptr;
    sqfs_dir_reader_t* dir_reader = nullptr;
    sqfs_data_reader_t* data_reader = nullptr;

    explicit Impl(const std::filesystem::path& _image_path) : image_path(_image_path) {
        file = sqfs_open_file(image_path.c_str(), SQFS_FILE_OPEN_READ_ONLY);
        if (!file) throw std::runtime_error("Cannot open system image file " + image_path.string());
        try {
            if (sqfs_super_read(&super, file) != 0) {
                throw std::runtime_error(image_path.string() + " is not a SquashFS image");
            }
            sqfs_compressor_config_t config;
            sqfs_compressor_config_init(&config, (SQFS_COMPRESSOR)super.compression_id,
                super.block_size, SQFS_COMP_FLAG_UNCOMPRESS);
            auto rst = sqfs_compressor_create(&config, &compressor);
            if (rst != 0) {
                throw std::runtime_error("Unsupported SquashFS compression in " + image_path.string()
                    + " (error " + std::to_string(rst) + ")");
            }
            if (super.flags & SQFS_FLAG_COMPRESSOR_OPTIONS) {
                if (compressor->read_options(compressor, file) != 0) {
                    throw std::runtime_error("Cannot read SquashFS compressor options of " + image_path.string());
                }
            }
            dir_reader = sqfs_dir_reader_create(&super, compressor, file, 0);
            if (!dir_reader) throw std::runtime_error("sqfs_dir_reader_create() failed");
            data_reader = sqfs_data_reader_create(file, super.block_size, compressor, 0);
            if (!data_reader) throw std::runtime_error("sqfs_data_reader_create() failed");
            if (sqfs_data_reader_load_fragment_table(data_reader, &super) != 0) {
                throw std::runtime_error("sqfs_data_reader_load_fragment_table() failed");
            }
        }
        catch (...) {
            destroy();
            throw;
        }
    }

    ~Impl() { destroy(); }

    void destroy() {
        if (data_reader) { sqfs_destroy(data_reader); data_reader = nullptr; }
        if (dir_reader) { sqfs_destroy(dir_reader); dir_reader = nullptr; }
        if (compressor) { sqfs_destroy(compressor); compressor = nullptr; }
        if (file) { sqfs_destroy(file); file = nullptr; }
    }

    // sqfs_dir_reader_find_by_path() does not follow symlinks, so every path
    // component is walked and resolved here instead.
    Inode lookup(const std::string& path, int depth = 0) const {
        if (depth > 16) throw std::runtime_error("Too many levels of symbolic links: " + path);
        //else
        auto components = split_path(path);
        std::string resolved;
        Inode inode;
        for (size_t i = 0; i < components.size(); i++) {
            auto next = resolved.empty()? components[i] : resolved + "/" + components[i];
            sqfs_inode_generic_t* found = nullptr;
            if (sqfs_dir_reader_find_by_path(dir_reader, nullptr, next.c_str(), &found) != 0) return nullptr;
            //else
            inode.reset(found);
            if (!is_symlink(inode.get())) {
                resolved = next;
                continue;
            }
            //else follow the link and restart the lookup from the resulting path
            auto target = symlink_target(inode.get());
            std::string rest;
            for (size_t j = i + 1; j < components.size(); j++) rest += "/" + components[j];
            if (!target.empty() && target[0] == '/') return lookup(target + rest, depth + 1);
            //else relative target, resolved against the parent of this component
            auto parent = resolved;
            while (target.rfind("../", 0) == 0) {
                target = target.substr(3);
                auto slash = parent.rfind('/');
                parent = (slash == std::string::npos)? "" : parent.substr(0, slash);
            }
            return lookup((parent.empty()? target : parent + "/" + target) + rest, depth + 1);
        }
        return inode;
    }

    Inode lookup_or_throw(const std::string& path) const {
        auto inode = lookup(path);
        if (!inode) throw std::runtime_error("No such file or directory in " + image_path.string() + ": " + path);
        //else
        return inode;
    }

    void read(const sqfs_inode_generic_t* inode, const std::function<void(const void*, size_t)>& sink) const {
        sqfs_u64 size;
        sqfs_inode_get_file_size(inode, &size);
        std::vector<char> buf(1024 * 1024);
        sqfs_u64 offset = 0;
        while (offset < size) {
            auto to_read = (sqfs_u32)std::min<sqfs_u64>(buf.size(), size - offset);
            auto read = sqfs_data_reader_read(data_reader, inode, offset, buf.data(), to_read);
            if (read <= 0) throw std::runtime_error("Reading " + image_path.string() + " failed at offset " + std::to_string(offset));
            //else
            sink(buf.data(), (size_t)read);
            offset += read;
        }
    }
};

SystemImageReader::SystemImageReader(const std::filesystem::path& image)
    : impl(std::make_unique<Impl>(image)) {}

SystemImageReader::~SystemImageReader() = default;

const std::filesystem::path& SystemImageReader::image_path() const { return impl->image_path; }

bool SystemImageReader::exists(const std::string& path) const
{
    return (bool)impl->lookup(path);
}

bool SystemImageReader::is_regular_file(const std::string& path) const
{
    auto inode = impl->lookup(path);
    return inode && ::is_regular_file(inode.get());
}

bool SystemImageReader::is_directory(const std::string& path) const
{
    auto inode = impl->lookup(path);
    return inode && ::is_directory(inode.get());
}

std::optional<uint64_t> SystemImageReader::file_size(const std::string& path) const
{
    auto inode = impl->lookup(path);
    if (!inode || !::is_regular_file(inode.get())) return std::nullopt;
    //else
    sqfs_u64 size;
    sqfs_inode_get_file_size(inode.get(), &size);
    return size;
}

std::optional<std::time_t> SystemImageReader::file_mtime(const std::string& path) const
{
    auto inode = impl->lookup(path);
    if (!inode) return std::nullopt;
    //else
    return (std::time_t)inode->base.mod_time;
}

void SystemImageReader::read_file(const std::string& path, const std::function<void(const void*, size_t)>& sink) const
{
    auto inode = impl->lookup_or_throw(path);
    if (!::is_regular_file(inode.get())) throw std::runtime_error("Not a regular file in system image: " + path);
    //else
    impl->read(inode.get(), sink);
}

std::string SystemImageReader::read_file(const std::string& path) const
{
    std::string content;
    read_file(path, [&content](const void* buf, size_t size) {
        content.append((const char*)buf, size);
    });
    return content;
}

void SystemImageReader::extract(const std::string& path, const std::filesystem::path& dest) const
{
    auto parent = dest.parent_path();
    if (!parent.empty()) std::filesystem::create_directories(parent);
    std::ofstream out(dest, std::ios::binary | std::ios::trunc);
    if (!out) throw std::runtime_error("Cannot open " + dest.string() + " for writing");
    //else
    read_file(path, [&out,&dest](const void* buf, size_t size) {
        out.write((const char*)buf, size);
        if (!out) throw std::runtime_error("Writing " + dest.string() + " failed");
    });
    out.close();
    if (!out) throw std::runtime_error("Writing " + dest.string() + " failed");
}

std::vector<SystemImageReader::DirEntry> SystemImageReader::list_directory(const std::string& path) const
{
    auto inode = impl->lookup_or_throw(path);
    if (!::is_directory(inode.get())) throw std::runtime_error("Not a directory in system image: " + path);
    //else
    if (sqfs_dir_reader_open_dir(impl->dir_reader, inode.get(), 0) != 0) {
        throw std::runtime_error("sqfs_dir_reader_open_dir() failed on " + path);
    }
    std::vector<DirEntry> entries;
    sqfs_dir_entry_t* entry = nullptr;
    while (sqfs_dir_reader_read(impl->dir_reader, &entry) == 0) {
        // sqfs_dir_entry_t::size is stored off-by-one
        std::string name((const char*)entry->name, (size_t)entry->size + 1);
        auto type = entry->type;
        sqfs_free(entry);
        entries.push_back(DirEntry {
            name,
            type == SQFS_INODE_DIR || type == SQFS_INODE_EXT_DIR,
            type == SQFS_INODE_FILE || type == SQFS_INODE_EXT_FILE,
            type == SQFS_INODE_SLINK || type == SQFS_INODE_EXT_SLINK
        });
    }
    return entries;
}

void SystemImageReader::walk_regular_files(const std::string& dir, const std::function<void(const std::string&)>& func) const
{
    // Directory symlinks are not descended into, matching what
    // std::filesystem::recursive_directory_iterator did before.
    std::function<void(const std::string&, const std::string&)> walk =
        [this,&func,&walk](const std::string& absolute, const std::string& relative) {
        for (const auto& entry:list_directory(absolute)) {
            auto child_absolute = absolute + "/" + entry.name;
            auto child_relative = relative.empty()? entry.name : relative + "/" + entry.name;
            if (entry.is_directory) {
                walk(child_absolute, child_relative);
            } else if (entry.is_regular_file || (entry.is_symlink && is_regular_file(child_absolute))) {
                func(child_relative);
            }
        }
    };
    walk(dir, "");
}

SystemImageInfo check_system_image(const SystemImageReader& image)
{
    if (!image.is_directory(".genpack")) {
        throw std::runtime_error("System image file doesn't contain .genpack directory");
    }
    SystemImageInfo info;
    info.raspberrypi = image.exists("boot/bootcode.bin");
    info.uboot_extlinux = image.exists(extlinux_conf_image_path);
    if (!info.raspberrypi) {
        // kernel and initramfs is mandatory unless it's raspberry pi image
        if (!image.exists("boot/kernel")) throw std::runtime_error("System image file doesn't contain kernel image");
        if (!image.exists("boot/initramfs")) throw std::runtime_error("System image file doesn't contain initramfs");
    }
    //else
    auto print_file = [&image](const std::string& filename) {
        if (!image.is_regular_file(".genpack/" + filename)) return;
        //else
        auto content = image.read_file(".genpack/" + filename);
        // the files hold a single word, but be liberal about trailing whitespace
        auto end = content.find_first_of(" \t\r\n");
        if (end != std::string::npos) content.erase(end);
        std::cout << filename << ": " << content << std::endl;
    };
    print_file("artifact");
    print_file("variant");
    return info;
}

std::vector<std::filesystem::path> get_files_referenced_by_extlinux_conf(const SystemImageReader& image)
{
    std::vector<std::filesystem::path> files;
    std::istringstream conf(image.read_file(extlinux_conf_image_path));
    std::string line;
    while (std::getline(conf, line)) {
        std::istringstream tokens(line);
        std::string keyword;
        if (!(tokens >> keyword)) continue;
        //else
        std::transform(keyword.begin(), keyword.end(), keyword.begin(),
            [](unsigned char c) { return std::tolower(c); });
        if (keyword == "kernel" || keyword == "linux" || keyword == "initrd" || keyword == "fdt"
            || keyword == "devicetree" || keyword == "fdtoverlays" || keyword == "devicetree-overlay") {
            std::string path; // FDTOVERLAYS may carry multiple space-separated paths
            while (tokens >> path) {
                auto relative = std::filesystem::path(path).relative_path();
                if (std::find(files.begin(), files.end(), relative) == files.end()) files.push_back(relative);
            }
        } else if (keyword == "fdtdir") {
            throw std::runtime_error("FDTDIR in extlinux.conf is not supported by genpack-install."
                " Use FDT with an explicit path.");
        }
    }
    if (files.empty()) throw std::runtime_error("extlinux.conf doesn't reference any kernel/initrd/fdt files");
    //else
    return files;
}

std::optional<BootloaderFiles> BootloaderFiles::locate(const SystemImageReader& image)
{
    if (image.is_directory("usr/lib/genpack-install")) {
        BootloaderFiles files;
        files.image = &image;
        files.image_dir = "usr/lib/genpack-install";
        return files;
    }
    //else
    for (auto candidate: {"/usr/local/lib/genpack-install", "/usr/lib/genpack-install"}) {
        if (std::filesystem::is_directory(candidate)) {
            BootloaderFiles files;
            files.host_dir = candidate;
            return files;
        }
    }
    return std::nullopt;
}

std::string BootloaderFiles::origin() const
{
    return image? image->image_path().string() + ":/" + image_dir : host_dir.string();
}

bool BootloaderFiles::contains(const std::string& name) const
{
    return image? image->is_regular_file(image_dir + "/" + name)
        : std::filesystem::is_regular_file(host_dir / name);
}

std::vector<std::string> BootloaderFiles::list() const
{
    std::vector<std::string> names;
    if (image) {
        for (const auto& entry:image->list_directory(image_dir)) {
            if (entry.is_regular_file || (entry.is_symlink && contains(entry.name))) names.push_back(entry.name);
        }
    } else {
        for (const auto& entry:std::filesystem::directory_iterator(host_dir)) {
            if (entry.is_regular_file()) names.push_back(entry.path().filename().string());
        }
    }
    std::sort(names.begin(), names.end());
    return names;
}

void BootloaderFiles::copy_to(const std::string& name, const std::filesystem::path& dest) const
{
    if (image) {
        image->extract(image_dir + "/" + name, dest);
    } else {
        std::filesystem::copy_file(host_dir / name, dest, std::filesystem::copy_options::overwrite_existing);
    }
}

std::filesystem::path BootloaderFiles::materialize(const std::string& name, const std::filesystem::path& tmpdir) const
{
    if (!image) return host_dir / name;
    //else
    auto dest = tmpdir / name;
    image->extract(image_dir + "/" + name, dest);
    return dest;
}
