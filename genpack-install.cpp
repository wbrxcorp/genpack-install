#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#include <unistd.h>
#include <glob.h>

#include <iostream>
#include <fstream>
#include <filesystem>
#include <cstring>
#include <regex>
#include <set>

#include <ext/stdio_filebuf.h> // for __gnu_cxx::stdio_filebuf
#include <libmount/libmount.h>
#include <blkid/blkid.h>

#include <argparse/argparse.hpp>

#include "common.hpp"
#include "image.hpp"

static const std::filesystem::path boot_partition("/run/initramfs/boot");
static const std::filesystem::path data_partition("/run/initramfs/rw");

class TempMount {
    std::filesystem::path tmpdir;
public:
    TempMount() = delete;
    TempMount(const TempMount&) = delete;
    TempMount& operator=(const TempMount&) = delete;
    explicit TempMount(const std::string& prefix, const std::filesystem::path& device,
        const std::string& fstype = "auto", int flags = MS_RELATIME, const std::string& data = ""){
        char* tmpdir_rp = (char*)malloc(prefix.length() + 7);
        if (!tmpdir_rp) throw std::runtime_error("malloc() failed");
        strcpy(tmpdir_rp, prefix.c_str());
        strcat(tmpdir_rp, "XXXXXX");
        //else
        auto rst = mkdtemp(tmpdir_rp);
        if (!rst) {
            free(tmpdir_rp);
            throw std::runtime_error("mkdtemp() failed");
        }
        tmpdir = tmpdir_rp;
        free(tmpdir_rp);

        std::shared_ptr<libmnt_context> ctx(mnt_new_context(), mnt_free_context);
        mnt_context_set_source(ctx.get(), device.c_str());
        mnt_context_set_target(ctx.get(), tmpdir.c_str());
        mnt_context_set_fstype(ctx.get(), fstype.c_str());
        mnt_context_set_mflags(ctx.get(), flags);
        mnt_context_set_options(ctx.get(), data.c_str());

        if (mnt_context_mount(ctx.get()) != 0) {
            std::filesystem::remove(tmpdir);
            throw std::runtime_error("mnt_context_mount() failed");
        }
        if (mnt_context_get_status(ctx.get()) != 1) {
            std::filesystem::remove(tmpdir);
            throw std::runtime_error("bad mount status");
        }
    }
    ~TempMount() {
        if (umount(tmpdir.c_str()) < 0) {
            std::cerr << "Warning: umount(" << tmpdir.string() << ") failed: " << strerror(errno) << std::endl;
        }
        std::filesystem::remove(tmpdir);
    }
    const std::filesystem::path& path() const {
        return tmpdir;
    }
    operator std::filesystem::path() const {
        return tmpdir;
    }
    std::filesystem::path operator/(const std::filesystem::path& other) const {
        return tmpdir / other;
    }
    operator std::string() const {
        return tmpdir.string();
    }
};

struct BlockDevice {
    std::filesystem::path path;
    std::string name;
    std::string model;
    std::string type;
    std::optional<std::string> pkname;
    bool ro;
    std::optional<std::string> mountpoint;
    uint64_t size;
    std::string tran;
    uint16_t log_sec;
};

std::list<BlockDevice> lsblk(const std::optional<std::filesystem::path>& device = std::nullopt)
{
    int fd[2];
    if (pipe(fd) < 0) throw std::runtime_error("pipe() failed.");

    pid_t pid = fork();
    if (pid < 0) throw std::runtime_error("fork() failed.");

    int rst;
    std::list<BlockDevice> devices;
    bool failed = false;

    if (pid == 0) { //child
        close(fd[0]);
        dup2(fd[1], STDOUT_FILENO);
        if (execlp("lsblk", "lsblk", "-bnr", "-o", "PATH,NAME,MODEL,TYPE,PKNAME,RO,MOUNTPOINT,SIZE,TRAN,LOG-SEC", device? device.value().c_str() : nullptr, nullptr) < 0) _exit(-1);
    } else { // parent
      close(fd[1]);
      try {
        __gnu_cxx::stdio_filebuf<char> filebuf(fd[0], std::ios::in);
        std::istream f(&filebuf);
        std::string line;
        while (std::getline(f, line)) {
            std::vector<std::string> splitted;
            auto offset = std::string::size_type(0);
            auto unescape = [](const std::string& str) {
                std::regex expr("\\\\x[0-9a-fA-F][0-9a-fA-F]");
                std::smatch m;
                auto s = str;
                std::string result;
                while (std::regex_search(s, m, expr)) {
                    result += m.prefix();
                    const auto& mstr = m[0].str();
                    auto hex2dec = [](int hex) { 
                        if (hex >= '0' && hex <= '9') return hex - '0';
                        //else
                        if (hex >= 'A' && hex <= 'F') return hex - 'A' + 10;
                        //else
                        throw std::runtime_error("Invalida hex char");
                    };
                    result += (char)(hex2dec(std::toupper(mstr[2])) * 16 + hex2dec(std::toupper(mstr[3])));
                    s = m.suffix();
                }
                result += s;
                return result;
            };
            while(true) {
                auto pos = line.find(' ', offset);
                if (pos == std::string::npos) {
                    splitted.push_back(unescape(line.substr(offset)));
                    break;
                }
                //else
                splitted.push_back(unescape(line.substr(offset, pos - offset)));
                offset = pos + 1;
            }
            if (splitted.size() != 10) continue; // line is incomplete
            devices.push_back(BlockDevice {
                splitted[0],
                splitted[1],
                splitted[2],
                splitted[3],
                splitted[4] != ""? std::make_optional(splitted[4]) : std::nullopt,
                std::stoi(splitted[5]) > 0,
                splitted[6] != ""? std::make_optional(splitted[6]) : std::nullopt,
                std::stoull(splitted[7]),
                splitted[8],
                (uint16_t)std::stoi(splitted[9])
            });
            //std::cout << "Debug: found device " << splitted[0] << std::endl;
        }
      }
      catch (const std::runtime_error& ex) { failed = true; }
      close(fd[0]);
    }

    waitpid(pid, &rst, 0);

    if (failed || !WIFEXITED(rst) || WEXITSTATUS(rst) != 0) throw std::runtime_error("lsblk failed");

    return devices;
}

std::filesystem::path get_installed_system_image_path()
{
    if (std::filesystem::is_regular_file(boot_partition / "system.img")) {
        return boot_partition / "system.img";
    }
    //else
    if (std::filesystem::is_regular_file(data_partition / "system")) {
        return data_partition / "system";
    }
    throw std::runtime_error("No installed system image found.");
}

using OptionalSystemImage = std::optional<std::filesystem::path>;

struct OptionalSystemConfig {
    const std::optional<std::filesystem::path>& system_cfg{};
    const std::optional<std::filesystem::path>& system_ini{};
};

using OptionalLabel = std::optional<std::string>;

using OptionalAdditionalBootFiles = std::optional<std::string>;

struct SelfOptions {
    const OptionalSystemConfig& system_config{};
};

void install_bios_bootloader(const BootloaderFiles& bootloader,
    const std::filesystem::path& boot_partition_path, const std::filesystem::path& disk)
{
    auto grub_dir = boot_partition_path / "boot/grub";
    std::filesystem::create_directories(grub_dir);
    bootloader.copy_to("boot.img", grub_dir / "boot.img");
    bootloader.copy_to("core.img", grub_dir / "core.img");
    bootloader.copy_to("grub.cfg", grub_dir / "grub.cfg");
    if (exec("grub-bios-setup", {"-d", grub_dir.string(), disk.string()}) != 0) {
        throw std::runtime_error("grub-bios-setup failed");
    }
    //else
    std::filesystem::remove(grub_dir / "boot.img");
    std::filesystem::remove(grub_dir / "core.img");
}

// extract UUID from root=systemimg:<UUID> in /proc/cmdline (for self-update)
std::optional<std::string> get_running_systemimg_uuid()
{
    std::ifstream f("/proc/cmdline");
    if (!f) return std::nullopt;
    std::string token;
    while (f >> token) {
        if (token.starts_with("root=systemimg:")) {
            auto uuid = token.substr(15);
            if (uuid != "auto" && !uuid.empty()) return uuid;
        }
    }
    return std::nullopt;
}

void install_boot_files(const SystemImageReader& system_image, const std::filesystem::path& boot_partition_path,
    const std::optional<std::filesystem::path>& disk = std::nullopt,
    const std::optional<std::string>& boot_partition_uuid = std::nullopt)
{
    // raspi boot files
    if (system_image.exists("boot/bootcode.bin")) {
        std::cout << "Installing boot files for raspberry pi..." << std::endl;
        // copy all files under "boot" in the system image to boot_partition_path
        system_image.walk_regular_files("boot", [&system_image,&boot_partition_path](const std::string& relative_path) {
            auto dest_path = boot_partition_path / relative_path;
            // special treatment for cmdline.txt
            if (relative_path == "cmdline.txt") {
                if (std::filesystem::exists(dest_path)) return;
                //else
                auto cmdline = system_image.read_file("boot/cmdline.txt");
                auto newline = cmdline.find_first_of("\r\n");
                if (newline != std::string::npos) cmdline.erase(newline);
                // replace "ROOTDEV" to "systemimg:auto"
                cmdline = std::regex_replace(cmdline, std::regex(R"((^|\s)root=[^ ]*)"), "$1root=systemimg:auto");
                // remove "rootfstype=..."
                cmdline = std::regex_replace(cmdline, std::regex(R"((^|\s)rootfstype=[^ ]*)"), "");
                // write modified cmdline.txt to boot partition
                std::ofstream out(dest_path);
                out << cmdline << std::endl;
                return;
            }
            //else special treatment for config.txt
            if (relative_path == "config.txt" && std::filesystem::exists(dest_path)) return;
            //else
            system_image.extract("boot/" + relative_path, dest_path);
        });
        std::cout << "Done." << std::endl;
    }

    // U-Boot extlinux(bootstd) boot files
    if (system_image.is_regular_file(extlinux_conf_image_path)) {
        std::cout << "Installing boot files for U-Boot extlinux..." << std::endl;
        for (const auto& relative: get_files_referenced_by_extlinux_conf(system_image)) {
            auto src = "boot" / relative;
            if (!system_image.is_regular_file(src.generic_string())) {
                throw std::runtime_error(relative.string() + " referenced by extlinux.conf does not exist in system image");
            }
            system_image.extract(src.generic_string(), boot_partition_path / relative);
        }
        // existing extlinux.conf is preserved as it may contain user customizations
        // (kernel/initrd/fdt filenames it points to are stable across updates)
        auto conf_dest = boot_partition_path / extlinux_conf_dest_path;
        if (!std::filesystem::exists(conf_dest)) {
            std::filesystem::create_directories(conf_dest.parent_path());
            // root=systemimg:auto in the image is a generic fallback. bind it to this
            // very boot partition at install time (the extlinux counterpart of grub.cfg's
            // boot-time `probe -u`), so that other disks carrying a system.img don't get
            // picked up by the initramfs's auto-scan.
            auto content = system_image.read_file(extlinux_conf_image_path);
            if (boot_partition_uuid) {
                content = std::regex_replace(content, std::regex(R"(root=systemimg:auto)"),
                    "root=systemimg:" + *boot_partition_uuid);
            }
            std::ofstream out(conf_dest);
            out << content;
        }
        std::cout << "Done." << std::endl;
    }

    // bootloaders
    auto bootloader = BootloaderFiles::locate(system_image);

    if (!bootloader) return;

    // else
    if (debug) std::cerr << "Bootloader files: " << bootloader->origin() << std::endl;
    std::cout << "Installing EFI bootloaders..." << std::endl;
    // copy all boot*.efi files right under the bootloader directory to boot_partition_path / "efi/boot"
    auto efi_boot_path = boot_partition_path / "efi/boot";
    std::filesystem::create_directories(efi_boot_path);
    for (const auto& filename: bootloader->list()) {
        if (filename.size() < 5) continue;
        if (filename.substr(0, 4) != "boot" || filename.substr(filename.size() - 4) != ".efi") continue;
        bootloader->copy_to(filename, efi_boot_path / filename);
        std::cout << "  " << filename << " installed." << std::endl;
    }
    std::cout << "Done." << std::endl;

    if (disk && bootloader->contains("boot.img") && bootloader->contains("core.img")
        && bootloader->contains("grub.cfg") && system("grub-bios-setup --version > /dev/null 2>&1") == 0) {
        std::cout << "Installing BIOS bootloader..." << std::endl;
        install_bios_bootloader(*bootloader, boot_partition_path, *disk);
        std::cout << "Done." << std::endl;
    }
}

void install_self(const std::filesystem::path& system_image, const SelfOptions& options = {})
{
    auto system_image_to_replace = get_installed_system_image_path();
    const std::filesystem::path& system_image_dir = [](const auto& system_image_to_replace) {
        const auto& dir = system_image_to_replace.parent_path();
        if (dir == boot_partition) {
            return boot_partition;
        } else if (dir == data_partition) {
            return data_partition;
        } else {
            throw std::runtime_error("Installed system image is in unknown location.");
        }
    }(system_image_to_replace);
    auto system_image_size = std::filesystem::file_size(system_image);
    //else
    if (system_image_size >= 4 * 1024 * 1024 * 1024ULL && system_image_dir == boot_partition) {
        throw std::runtime_error("Cannot install system image larger than or equal to 4GiB to boot partition.");
    }
    //else
    SystemImageReader system_image_reader(system_image);
    check_system_image(system_image_reader);

    // self-update: normally extlinux.conf already exists and is preserved, but if it
    // has to be (re)created, bind it to the boot partition we are running from
    install_boot_files(system_image_reader, boot_partition, std::nullopt, get_running_systemimg_uuid());

    const std::filesystem::path replaced_system_image = system_image_dir / "system.cur";
    const std::filesystem::path new_system_image = system_image_dir / "system.new";
    const std::filesystem::path old_system_image = system_image_dir / "system.old";

    if (std::filesystem::exists(old_system_image)) {
        std::filesystem::remove(old_system_image);
        std::cout << "Old system image removed to preserve disk space." << std::endl;
    }

    if (get_freespace(system_image_dir) < system_image_size) {
        throw std::runtime_error("Not enough free space to install new system image.");
    }

    std::cout << "Copying new system image..." << std::flush;
    try {
        std::filesystem::copy_file(system_image, new_system_image);
        if (!std::filesystem::exists(replaced_system_image)) {
            std::filesystem::rename(system_image_to_replace, replaced_system_image);
            std::cout << "Present system image preserved..." << std::flush;
        } else {
            std::cout << "Present system image is already preserved..." << std::flush;
        }
        std::filesystem::rename(new_system_image, system_image_to_replace);
        sync();
        std::cout << "New system image installed." << std::endl;
    }
    catch (const std::filesystem::filesystem_error& e) {
        if (!std::filesystem::exists(system_image_to_replace)) {
            if (std::filesystem::exists(replaced_system_image)) {
                std::filesystem::rename(replaced_system_image, system_image_to_replace);
                std::cout << "Original system image restored." << std::endl;
            }
        }
        if (std::filesystem::exists(new_system_image)) std::filesystem::remove(new_system_image);
        throw e;
    }
}

std::tuple<std::filesystem::path,std::optional<std::filesystem::path>,bool/*bios_compatible*/> 
    create_partitions(const BlockDevice& disk, std::optional<size_t> boot_partition_size_in_gib = 4,
        bool gpt = false, bool mark_boot_partition_as_esp = true)
{
    std::vector<std::string> parted_args = {"--script", disk.path.string()};
    bool bios_compatible = !gpt && (disk.size <= 2199023255552L/*2TiB*/ && disk.log_sec == 512);
    parted_args.push_back(bios_compatible? "mklabel msdos" : "mklabel gpt");
    if (boot_partition_size_in_gib) {
        parted_args.push_back("mkpart primary fat32 1MiB " + std::to_string(*boot_partition_size_in_gib) + "GiB");
        parted_args.push_back("mkpart primary btrfs " + std::to_string(*boot_partition_size_in_gib) + "GiB -1");
    } else {
        parted_args.push_back("mkpart primary fat32 1MiB -1");
    }
    parted_args.push_back("set 1 boot on");
    if (bios_compatible && boot_partition_size_in_gib && mark_boot_partition_as_esp) {
        parted_args.push_back("set 1 esp on");
    }
    if (exec("parted", parted_args) != 0) throw std::runtime_error("Creating partition failed");
    exec("udevadm", {"settle"});

    auto get_partition = [](const std::filesystem::path& disk, uint8_t num) -> std::optional<std::filesystem::path> {
        if (!std::filesystem::is_block_file(disk)) throw std::runtime_error("Not a block device");

        struct stat s;
        if (stat(disk.c_str(), &s) < 0) throw std::runtime_error("stat");

        char pattern[128];
        sprintf(pattern, "/sys/dev/block/%d:%d/*/partition",
            major(s.st_rdev), minor(s.st_rdev));

        auto glob = [](const char* pattern, int flags, int errfunc(const char *epath, int eerrno), std::list<std::filesystem::path>& match) -> int {
            glob_t globbuf;
            match.clear();
            int rst = ::glob(pattern, GLOB_NOESCAPE, nullptr, &globbuf);
            if (rst == GLOB_NOMATCH) return 0;
            if (rst != 0) throw std::runtime_error("glob");
            //else
            for (int i = 0; i < globbuf.gl_pathc; i++) {
                match.push_back(std::filesystem::path(globbuf.gl_pathv[i]));
            }
            globfree(&globbuf);
            return match.size();
        };

        std::list<std::filesystem::path> match;
        glob(pattern, GLOB_NOESCAPE, nullptr, match);
        for (auto& path: match) {
            std::ifstream part(path);
            uint16_t partno;
            part >> partno;
            if (partno == num) {
            std::ifstream dev(path.replace_filename("dev"));
            std::string devno;
            dev >> devno;
            std::filesystem::path devblock("/dev/block/");
            auto devspecial = std::filesystem::read_symlink(devblock.replace_filename(devno));
            return devspecial.is_absolute()? devspecial : std::filesystem::canonical(devblock.replace_filename(devspecial));
            }
        }
        return std::nullopt;
    };

    auto boot_partition_path = get_partition(disk.path, 1);
    if (!boot_partition_path) throw std::runtime_error("Unable to determine created boot partition");

    std::optional<std::filesystem::path> data_partition_path = std::nullopt;
    if (boot_partition_size_in_gib) {
        data_partition_path = get_partition(disk.path, 2);
    }

    return std::make_tuple(boot_partition_path.value(), data_partition_path, bios_compatible);
}

std::string format_fat32(const std::filesystem::path& path, bool partition = true, const std::optional<std::string>& label = std::nullopt)
{
    std::vector<std::string> mkfs_args = {
        "-F","32",
        "-s","32"
    };
    if (!partition) {
        mkfs_args.push_back("-I");
    }
    if (label) {
        mkfs_args.push_back("-n");
        mkfs_args.push_back(label.value());
    }
    mkfs_args.push_back(path.string());
    if (exec("mkfs.vfat",mkfs_args) != 0) {
        std::string object = partition? "partition " : "disk ";
        throw std::runtime_error("Unable to format " + object + path.string() + " by FAT32");
    }
    //else
    blkid_cache cache;
    if (blkid_get_cache(&cache, "/dev/null") != 0) throw std::runtime_error("blkid_get_cache() failed");
    if (blkid_probe_all(cache) != 0) {
        blkid_put_cache(cache);
        throw std::runtime_error("blkid_probe_all() failed");
    }
    auto tag_value = blkid_get_tag_value(cache, "UUID", path.c_str());
    std::optional<std::string> uuid = (tag_value)? std::make_optional(tag_value) : std::nullopt;
    blkid_put_cache(cache);
    if (!uuid) throw std::runtime_error("Failed to get UUID of partition " + path.string());
    return uuid.value();
}

void format_btrfs(const std::filesystem::path& path, const std::string& label)
{
    if (exec("mkfs.btrfs", {"-q", "-L", label, "-f", path.string()}) != 0) {
        throw std::runtime_error("Unable to format partition " + path.string() + " by BTRFS");
    }
}

void copy_system_cfg_ini(const std::optional<std::filesystem::path>& system_cfg, 
    const std::optional<std::filesystem::path>& system_ini,
    const std::filesystem::path& dest)
{
    if (system_cfg) {
        if (!std::filesystem::is_regular_file(*system_cfg)) throw std::runtime_error(system_cfg.value().string() + " does not exist or not a regular file");
        std::filesystem::copy_file(system_cfg.value(), dest / "system.cfg");
    }
    if (system_ini) {
        if (!std::filesystem::is_regular_file(*system_ini)) throw std::runtime_error(system_ini.value().string() + " does not exist or not a regular file");
        std::filesystem::copy_file(system_ini.value(), dest / "system.ini");
    }
}

void print_installable_disks()
{
    auto lsblk_result = lsblk();
    std::set<std::string> disks_to_be_excluded;
    for (const auto& d:lsblk_result) {
        if (d.mountpoint) {
            disks_to_be_excluded.insert(d.name);
            if (d.pkname) disks_to_be_excluded.insert(*d.pkname);
        }
        if (d.ro || d.size < 4ULL * 1024 * 1024 * 1024/* at least 4GiB */ || (d.type != "disk" && d.type != "loop")) {
            disks_to_be_excluded.insert(d.name);
        }
    }
    std::cout << "Available disks:" << std::endl;
    for (const auto& d:lsblk_result) {
        if (disks_to_be_excluded.find(d.name) != disks_to_be_excluded.end()) continue;
        std::cout << d.path.string() << '\t' << d.model << '\t' << d.tran << '\t' << size_str(d.size) << std::endl;
    }
}

struct Partitioning {
    const bool prefer_gpt{false};
    const bool mark_boot_partition_as_esp{true};
};

using OptionalPartitioning = std::optional<Partitioning>;

struct DiskOptions {
    const OptionalSystemImage& system_image{};
    const OptionalSystemConfig& system_config{};
    const OptionalLabel& label{};
    const OptionalAdditionalBootFiles& additional_boot_files{};
    const OptionalPartitioning& partition_options = Partitioning{false};
    const bool yes{};
};

void install_to_disk(const std::filesystem::path& disk, const DiskOptions& options = {})
{
    auto system_image = [](const auto& system_image) {
        if (system_image) return *system_image;
        //else
        auto actual_system_image = get_installed_system_image_path();
        std::cerr << "System file image not specified. assuming " << actual_system_image << "." << std::endl;
        return actual_system_image;
    }(options.system_image);

    if (!std::filesystem::exists(system_image)) throw std::runtime_error("System image file " + system_image.string() + " does not exist.");
    if (!std::filesystem::exists(disk)) throw std::runtime_error("No such device");

    auto lsblk_result = lsblk(disk);
    if (lsblk_result.size() == 0) throw std::runtime_error("No such device");

    bool has_mounted_partition = false;
    for (auto d:lsblk_result) {
        if (d.mountpoint) has_mounted_partition = true;
    }

    auto disk_info = *lsblk_result.begin(); // the first one is the disk itself
    if (disk_info.type != "disk" && disk_info.type != "loop") throw std::runtime_error(disk.string() + " is not a disk");
    if (disk_info.ro) throw std::runtime_error(disk.string() + " is read-only device");
    if (has_mounted_partition) throw std::runtime_error(disk.string() + " has mounted partition");
    if (disk_info.pkname) throw std::runtime_error(disk.string() + " belongs to other block device");
    //else
    auto system_image_size = std::filesystem::file_size(system_image);
    auto least_capacity_needed_in_gib = std::max<size_t>(4, (system_image_size * 3) / (1024 * 1024 * 1024ULL) + 1);
    if (disk_info.size < least_capacity_needed_in_gib * 1024 * 1024 * 1024ULL) throw std::runtime_error(disk.string() + " is too small(At least " + std::to_string(least_capacity_needed_in_gib) + "GiB required)");
    //else
    bool system_image_fits_boot_partition = system_image_size < 4 * 1024 * 1024 * 1024ULL;

    if (options.partition_options) {
        if (disk_info.size / (1024 * 1024 * 1024) < least_capacity_needed_in_gib * 3 / 2) {
            std::string msg = "Disk size is too small to create data partition along with boot partition.";
            if (system_image_fits_boot_partition) {
                msg += " Consider using --superfloppy to install without data partition.";
            } else {
                msg += " Consider using a larger disk or a system image smaller than 4GiB.";
            }
            throw std::runtime_error(msg);
        }
    } else {
        // superfloppy mode
        if (!system_image_fits_boot_partition) {
            throw std::runtime_error("Cannot install system image larger than or equal to 4GiB to boot partition.");
        }
        // disk size must not be larger than (uint64_t)17592185872384 (16TiB - 16KiB)
        if (disk_info.size > 17592185872384ULL) {
            throw std::runtime_error("Disk size too large for superfloppy mode.");
        }
    }
    auto boot_partition_size_in_gib = system_image_fits_boot_partition? least_capacity_needed_in_gib : 1; // 1 GiB boot partition for large system image with data partition

    std::cout << "Device path: " << disk << std::endl;
    std::cout << "Disk model: " << disk_info.model << std::endl;
    std::cout << "Disk size: " << size_str(disk_info.size) << std::endl;
    std::cout << "Logical sector size: " << disk_info.log_sec << " bytes" << std::endl;

    if (!options.yes) {
        std::string sure;
        std::cout << "All data present on " << disk << " will be lost. Are you sure? (y/n):" << std::flush;
        std::cin >> sure;
        if (sure != "y" && sure != "yes" && sure != "Y") 
            throw std::runtime_error("User aborted installation");
    }

    std::cout << "Checking system image file..." << std::endl;
    SystemImageReader system_image_reader(system_image);
    auto image_info = check_system_image(system_image_reader);
    std::cout << "Looks OK." << std::endl;

    if (options.partition_options && image_info.is_sbc()) {
        // SBC boot firmwares (RasPi, U-Boot without CONFIG_EFI_PARTITION) can only read plain MBR disks
        if (options.partition_options->prefer_gpt)
            throw std::runtime_error("GPT cannot be used with this system image (its boot firmware requires MBR)");
        if (disk_info.size > 2199023255552L/*2TiB*/ || disk_info.log_sec != 512)
            throw std::runtime_error("This disk requires GPT, which the boot firmware for this system image cannot read. Use a disk <=2TiB with 512-byte sectors.");
    }

    if (options.partition_options) std::cout << "Creating partitions..." << std::flush;
    auto partitions = options.partition_options?
        create_partitions(disk_info, boot_partition_size_in_gib, options.partition_options->prefer_gpt,
            options.partition_options->mark_boot_partition_as_esp && !image_info.is_sbc())
        : std::make_tuple(disk, std::nullopt, false);
    if (options.partition_options) {
        std::cout << "Done." << std::endl;
    } else {
        std::cout << "Superfloppy mode: no partition created." << std::endl;
    }

    auto boot_partition_path = std::get<0>(partitions);
    auto data_partition_path = std::get<1>(partitions);
    auto bios_compatible = std::get<2>(partitions);

    std::cout << "Formatting boot " + std::string(data_partition_path.has_value()? "partition" : "disk") + " with FAT32" << std::endl;
    auto boot_partition_uuid = format_fat32(boot_partition_path, data_partition_path.has_value(), options.label);
    if (data_partition_path) {
        std::cout << "Formatting data partition with BTRFS..." << std::flush;
        format_btrfs(data_partition_path.value(), std::string("data-") + boot_partition_uuid);
        std::cout << "Done." << std::endl;
    }

    {
        std::cout << "Mounting boot " + std::string(data_partition_path.has_value()? "partition" : "disk") + "..." << std::flush;
        auto tempdir = TempMount("/tmp/genpack-install-", boot_partition_path, "vfat", MS_RELATIME, "fmask=177,dmask=077");
        std::cout << "Done." << std::endl;

        install_boot_files(system_image_reader, tempdir, bios_compatible? std::make_optional(disk) : std::nullopt,
            boot_partition_uuid);

        if (options.system_config.system_cfg || options.system_config.system_ini) {
            std::cout << "Copying system config file..." << std::flush;
            copy_system_cfg_ini(options.system_config.system_cfg, options.system_config.system_ini, tempdir);
            std::cout << "Done" << std::endl;
        }
        std::cout << "Copying system image file..." << std::flush;
        if (system_image_fits_boot_partition) {
            std::filesystem::copy_file(system_image, tempdir / "system.img");
        } else {
            TempMount data_part_mount = TempMount("/tmp/genpack-install-", *data_partition_path, "btrfs", MS_RELATIME, "");
            std::filesystem::copy_file(system_image, data_part_mount / "system");
        }
        // do sync
        sync();
        std::cout << "Done" << std::endl;

        if (options.additional_boot_files) {
            std::cout << "Extracting additional boot files..." << std::flush;
            // extract zip archive
            if (exec("unzip", {*options.additional_boot_files, "-d", tempdir}) != 0) {
                std::cout << "Failed" << std::endl;
                throw std::runtime_error("Failed to extract additional boot files.");
            }
            std::cout << "Done" << std::endl;
        }
    }
    std::cout << "Installation completed successfully." << std::endl;
}

void show_examples(const std::string& progname)
{
    std::cout << "Example:" << std:: endl;
    std::cout << ' ' << progname << ' ' << "<system image file>" << std::endl;
    std::cout << "or" << std::endl;
    std::cout << ' ' << progname << ' ' << "--disk=<disk device path> [--label=<label>] [system image file]" << std::endl;
    std::cout << "or" << std::endl;
    std::cout << ' ' << progname << ' ' << "--disk=list" << std::endl;
    std::cout << std::endl;
    std::cout << "To create an ISO9660 image or a ZIP archive, use genpack-mkiso or genpack-mkzip." << std::endl;
}

int main(int argc, char** argv)
{
    const std::string progname = "genpack-install";
    argparse::ArgumentParser program(progname);
    // syatem image file is optional
    program.add_argument("system_image").help("System image file").nargs(argparse::nargs_pattern::optional);
    program.add_argument("--disk").help("Disk device path");
    program.add_argument("--system-cfg").help("Install specified system.cfg file");
    program.add_argument("--system-ini").help("Install specified system.ini file");
    program.add_argument("--label").help("Specify volume label of boot partition");
    program.add_argument("--gpt").help("Always use GPT instead of MBR").default_value(false).implicit_value(true);
    program.add_argument("--superfloppy").help("Use whole disk instead of partitioning").default_value(false).implicit_value(true);
    program.add_argument("--no-esp").help("Don't mark boot partition as ESP (EFI System Partition) as some bootloaders dislike it").default_value(false).implicit_value(true);
    program.add_argument("--additional-boot-files").help("Zip-archived file contains additional boot files");
    program.add_argument("-y").help("Don't ask questions").default_value(false).implicit_value(true);
    program.add_argument("--debug").help("Show debug messages").default_value(false).implicit_value(true);

    try {
        program.parse_args(argc, argv);
    }
    catch (const std::runtime_error& ex) {
        std::cerr << ex.what() << std::endl;
        std::cout << program << std::endl;
        return -1;
    }

    if (!program.present("--disk") && !program.present("system_image")) {
        std::cout << program << std::endl;
        show_examples(progname);
        return -1;
    }
    //else

    debug = program.get<bool>("--debug");

    try {
        if (geteuid() != 0) throw std::runtime_error("You must be root");

        auto disk = program.present("--disk");

        if (!disk) {
            std::filesystem::path system_image = program.get<std::string>("system_image");
            install_self(system_image, {
                .system_config = {
                    .system_cfg = program.present("--system-cfg"),
                    .system_ini = program.present("--system-ini")
                }
            });
            return 0;
        }

        //else
        const auto system_image = program.present("system_image");
        //std::cout << "System image: " << (system_image? program.get<std::string>("system_image") : "not specified") << std::endl;

        auto system_cfg = program.present("--system-cfg")? std::make_optional(std::filesystem::path(program.get<std::string>("--system-cfg"))) : std::nullopt;
        //std::cout << "System cfg: " << (system_cfg? system_cfg.value().string() : "not specified") << std::endl;
        std::optional<std::filesystem::path> system_ini = program.present("--system-ini")? std::make_optional(std::filesystem::path(program.get<std::string>("--system-ini"))) : std::nullopt;
        //std::cout << "System ini: " << (system_ini? system_ini.value().string() : "not specified") << std::endl;
        auto additional_boot_files = program.present("--additional-boot-files");

        //std::cout << "Disk: " << disk << std::endl;
        if (disk == "list") {
            print_installable_disks();
            return 0;
        }

        install_to_disk(disk.value(), {
            .system_image = system_image,
            .system_config = { .system_cfg = system_cfg, .system_ini = system_ini },
            .label = program.present("--label"),
            .additional_boot_files = additional_boot_files,
            .partition_options = program.get<bool>("--superfloppy")? std::nullopt  // no partition options means superfloppy mode
                : std::make_optional<Partitioning>(Partitioning{
                    .prefer_gpt = program.get<bool>("--gpt"),
                    .mark_boot_partition_as_esp = !program.get<bool>("--no-esp")
                }),
            .yes = program.get<bool>("-y"),
        });
        return 0;
    }
    catch (const std::exception& ex) {
        std::cerr << ex.what() << std::endl;
    }

    return 1;
}
