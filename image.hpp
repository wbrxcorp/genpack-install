#pragma once

#include <cstdint>
#include <ctime>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

// Read-only view of a genpack system image (SquashFS), backed by libsquashfs.
// Neither a loopback mount nor root privileges are involved. Paths are given
// relative to the image root; symlinks are resolved on every component, which
// matters because genpack images ship /lib -> usr/lib and /sbin -> usr/bin.
class SystemImageReader {
    struct Impl;
    std::unique_ptr<Impl> impl;
public:
    struct DirEntry {
        std::string name;
        bool is_directory;
        bool is_regular_file;
        bool is_symlink;
    };

    SystemImageReader() = delete;
    SystemImageReader(const SystemImageReader&) = delete;
    SystemImageReader& operator=(const SystemImageReader&) = delete;
    explicit SystemImageReader(const std::filesystem::path& image);
    ~SystemImageReader();

    const std::filesystem::path& image_path() const;

    bool exists(const std::string& path) const;
    bool is_regular_file(const std::string& path) const;
    bool is_directory(const std::string& path) const;
    std::optional<uint64_t> file_size(const std::string& path) const;
    std::optional<std::time_t> file_mtime(const std::string& path) const;

    std::string read_file(const std::string& path) const;
    // Streams the file content out in chunks, so large files never have to be
    // held in memory at once.
    void read_file(const std::string& path, const std::function<void(const void*, size_t)>& sink) const;
    void extract(const std::string& path, const std::filesystem::path& dest) const;

    std::vector<DirEntry> list_directory(const std::string& path) const;
    // Calls func for every regular file below dir, with the path relative to dir.
    void walk_regular_files(const std::string& dir, const std::function<void(const std::string&)>& func) const;
};

// The U-Boot extlinux configuration, inside the system image and on the boot
// partition. The image's boot directory becomes the root of the partition.
inline const std::string extlinux_conf_image_path = "boot/extlinux/extlinux.conf";
inline const std::string extlinux_conf_dest_path = "extlinux/extlinux.conf";

// The artifact definition's git revision, recorded by genpack when the artifact
// sets include_commit_id. Not to be confused with .genpack/timestamp.commit,
// which is the Portage tree's commit.
inline const std::string commit_id_image_path = ".genpack/commit-id";

struct SystemImageInfo {
    // SBC images carry their own boot files and don't boot via EFI/BIOS
    bool raspberrypi = false;
    bool uboot_extlinux = false;
    bool is_sbc() const { return raspberrypi || uboot_extlinux; }
};

// Throws unless the image looks like a genpack system image, and prints the
// artifact and variant names and the commit id it carries.
SystemImageInfo check_system_image(const SystemImageReader& image);

// Whether the content of /.genpack/commit-id says the artifact's working tree
// was clean when the image was built: exactly one whitespace-separated token,
// and that token a hex string the length of a git object id. genpack appends
// " (with local changes)" when it was not, but nothing here interprets that --
// anything other than a lone object id, an unfamiliar format included, reads as
// not clean, so that a format this does not know cannot pass for a clean build.
bool is_clean_commit_id(const std::string& content);

// Throws unless the image records a commit id and that id is clean. An image
// built without include_commit_id carries no such file and does not pass.
void require_clean_commit(const SystemImageReader& image);

// Enumerates the files boot/extlinux/extlinux.conf refers to (KERNEL/LINUX/
// INITRD/FDT/FDTOVERLAYS lines). Paths in extlinux.conf are absolute from the
// boot partition root, so they come back relative, to be resolved against both
// the image's boot directory and the boot partition.
std::vector<std::filesystem::path> get_files_referenced_by_extlinux_conf(const SystemImageReader& image);

// The bootloader files to put into the generated image, taken from
// usr/lib/genpack-install inside the system image when it carries them, or from
// the host otherwise.
class BootloaderFiles {
    const SystemImageReader* image = nullptr;   // null once the files come from the host
    std::string image_dir;
    std::filesystem::path host_dir;
public:
    static std::optional<BootloaderFiles> locate(const SystemImageReader& image);
    // Where the files were found, for diagnostics.
    std::string origin() const;
    bool contains(const std::string& name) const;
    std::vector<std::string> list() const;
    void copy_to(const std::string& name, const std::filesystem::path& dest) const;
    // A path on the local filesystem holding the file, extracted into tmpdir
    // when it lives inside the system image. Needed by libisofs, which reads
    // its input through the local filesystem.
    std::filesystem::path materialize(const std::string& name, const std::filesystem::path& tmpdir) const;
};
