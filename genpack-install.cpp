#include <unistd.h>
#include <string.h>
#include <wait.h>
#include <glob.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/mman.h>

#include <libmount/libmount.h>
#include <blkid/blkid.h>

#include <iostream>
#include <fstream>
#include <filesystem>
#include <optional>
#include <functional>
#include <map>
#include <set>
#include <list>
#include <regex>
#include <mutex>
#include <ext/stdio_filebuf.h> // for __gnu_cxx::stdio_filebuf

#include <argparse/argparse.hpp>

static const std::filesystem::path boot_partition("/run/initramfs/boot");
static const std::filesystem::path installed_system_image(boot_partition / "system.img");
static const std::filesystem::path grub_lib = std::filesystem::path("/usr/lib/grub");

static std::set<std::string> common_grub_modules = {
    "loopback", "xfs", "btrfs", "fat", "ntfs", "ntfscomp", "ext2",  "iso9660","lvm", "squash4",
    "part_gpt", "part_msdos", "blocklist", 
    "normal", "configfile", "linux", "chain", 
    "echo",   "test", "probe",  "search",  "gzio", "minicmd","sleep",
    "all_video", "videotest", "serial", "png", "gfxterm_background", "font", "terminal","videoinfo","gfxterm", "keystatus"
};

static std::set<std::string> arch_specific_grub_modules = {
    "ahci", "efi_gop", "efi_uga", "biosdisk", "cpuid", "multiboot", "multiboot2", "fdt"
};

bool is_dir(const std::filesystem::path& path)
{
    return std::filesystem::exists(path) && std::filesystem::is_directory(path);
}

bool is_file(const std::filesystem::path& path)
{
    return std::filesystem::exists(path) && std::filesystem::is_regular_file(path);
}

const std::vector<std::string> grub_modules(const std::string& arch)
{
    std::vector<std::string> modules(common_grub_modules.begin(), common_grub_modules.end());
    for (const auto& m:arch_specific_grub_modules) {
        if (is_file(grub_lib / arch / (m + ".mod"))) {
            modules.push_back(m);
        }
    }
    return modules;
}

std::string bios_grub_modules_string(const std::vector<std::string>& modules)
{
    std::string str;
    for (const auto& m:modules) {
        str += m + " ";
    }
    // remove last space
    str.pop_back();
    return str;
}

int fork(std::function<int()> func)
{
    pid_t pid = fork();
    if (pid < 0) throw std::runtime_error("fork() failed.");
    int rst;
    if (pid == 0) { //child
        _exit(func());
    }
    //else
    waitpid(pid, &rst, 0);
    return WIFEXITED(rst)? WEXITSTATUS(rst) : -1;
}

int exec(const std::string& cmd, const std::vector<std::string>& args)
{
    return fork([&cmd,&args]() {
        // create argv
        size_t args_len = 0;
        args_len += cmd.length() + 1;
        for (auto arg:args) {
            args_len += arg.length() + 1;
        }
        char* argv_buf = (char*)malloc(args_len);
        char* argv[args.size() + 2];
        char* pt = argv_buf;
        int argc = 0;
        strcpy(pt, cmd.c_str());
        pt[cmd.length()] = '\0';
        argv[argc++] = pt;
        pt += cmd.length() + 1;
        for (auto arg:args) {
            strcpy(pt, arg.c_str());
            pt[arg.length()] = '\0';
            argv[argc++] = pt;
            pt += arg.length() + 1;
        }
        argv[argc] = nullptr;
        auto rst = execvp(cmd.c_str(), argv);
        free(argv_buf);
        return -1;
    });
}

std::shared_ptr<char> create_tempmount(const std::string& prefix, const std::filesystem::path& device,
    const std::string& fstype = "auto", int flags = MS_RELATIME, const std::string& data = "")
{
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
    std::shared_ptr<char> tmpdir(rst, [](char* p) {
        umount(p);
        std::filesystem::remove(p);
        free(p);
    });

    std::shared_ptr<libmnt_context> ctx(mnt_new_context(), mnt_free_context);
    mnt_context_set_source(ctx.get(), device.c_str());
    mnt_context_set_target(ctx.get(), tmpdir.get());
    mnt_context_set_fstype(ctx.get(), fstype.c_str());
    mnt_context_set_mflags(ctx.get(), flags);
    mnt_context_set_options(ctx.get(), data.c_str());

    if (mnt_context_mount(ctx.get()) != 0) throw std::runtime_error("mnt_context_mount() failed");
    if (mnt_context_get_status(ctx.get()) != 1) throw std::runtime_error("bad mount status");

    return tmpdir;
}

void check_system_image(const std::filesystem::path& system_image)
{
    auto tempdir = create_tempmount("/tmp/genpack-install-", system_image, "auto", MS_RDONLY, "loop");
    std::filesystem::path tempdir_path(tempdir.get());
    const auto genpack_dir = tempdir_path / ".genpack";
    if (!std::filesystem::is_directory(genpack_dir)) throw std::runtime_error("System image file doesn't contain .genpack directory");
    if (!std::filesystem::exists(tempdir_path / "boot/kernel")) throw std::runtime_error("System image file doesn't contain kernel image");
    if (!std::filesystem::exists(tempdir_path / "boot/initramfs")) throw std::runtime_error("System image file doesn't contain initramfs");
    //else
    auto print_file = [&genpack_dir](const std::string& filename) {
        std::ifstream i(genpack_dir / filename);
        if (!i) return;
        //else
        std::string content;
        i >> content;
        std::cout << filename << ": " << content << std::endl;
    };
    print_file("profile");
    print_file("artifact");
}

bool is_image_file_loopbacked(const std::filesystem::path& system_image)
{
    int fd[2];
    if (pipe(fd) < 0) throw std::runtime_error("pipe() failed.");

    pid_t pid = fork();
    if (pid < 0) throw std::runtime_error("fork() failed.");

    int rst;
    bool is_loopbacked = false;
    if (pid == 0) { //child
        close(fd[0]);
        dup2(fd[1], STDOUT_FILENO);
        if (execlp("losetup", "losetup", "-j", system_image.c_str(), nullptr) < 0) _exit(-1);
    } else { // parent
      close(fd[1]);
      {
        __gnu_cxx::stdio_filebuf<char> filebuf(fd[0], std::ios::in);
        std::istream f(&filebuf);
        std::string line;
        while (std::getline(f, line)) {
            is_loopbacked = true;
        }
      }
      close(fd[0]);
    }

    waitpid(pid, &rst, 0);

    if (!WIFEXITED(rst) || WEXITSTATUS(rst) != 0) return false;

    return is_loopbacked;
}

struct BlockDevice {
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
        if (execlp("lsblk", "lsblk", "-bnr", "-o", "NAME,MODEL,TYPE,PKNAME,RO,MOUNTPOINT,SIZE,TRAN,LOG-SEC", device? device.value().c_str() : nullptr, nullptr) < 0) _exit(-1);
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
            if (splitted.size() != 9) continue; // line is incomplete
            devices.push_back(BlockDevice {
                splitted[0],
                splitted[1],
                splitted[2],
                splitted[3] != ""? std::make_optional(splitted[3]) : std::nullopt,
                std::stoi(splitted[4]) > 0,
                splitted[5] != ""? std::make_optional(splitted[5]) : std::nullopt,
                std::stoull(splitted[6]),
                splitted[7],
                (uint16_t)std::stoi(splitted[8])
            });
        }
      }
      catch (const std::runtime_error& ex) { failed = true; }
      close(fd[0]);
    }

    waitpid(pid, &rst, 0);

    if (failed || !WIFEXITED(rst) || WEXITSTATUS(rst) != 0) throw std::runtime_error("lsblk failed");

    return devices;
}

const uint64_t MIN_DISK_SIZE = 4ULL * 1024 * 1024 * 1024;
const uint64_t MIN_DISK_SIZE_TO_HAVE_DATA_PARTITION = 6ULL * 1024 * 1024 * 1024;

std::string size_str(uint64_t size)
{
    uint64_t gib = 1024L * 1024 * 1024;
    auto tib = gib * 1024;
    if (size >= tib) {
        char buf[32];
        sprintf(buf, "%.1fTiB", (float)size / tib);
        return buf;
    }
    //else
    char buf[32];
    sprintf(buf, "%.1fGiB", (float)size / gib);
    return buf;
}

int print_installable_disks()
{
    auto lsblk_result = lsblk();
    std::set<std::string> disks_to_be_excluded;
    for (const auto& d:lsblk_result) {
        if (d.mountpoint) {
            disks_to_be_excluded.insert(d.name);
            if (d.pkname) disks_to_be_excluded.insert(d.pkname.value());
        }
        if (d.ro || d.size < MIN_DISK_SIZE || (d.type != "disk" && d.type != "loop")) {
            disks_to_be_excluded.insert(d.name);
        }
    }
    std::cout << "Available disks:" << std::endl;
    for (const auto& d:lsblk_result) {
        if (disks_to_be_excluded.find(d.name) != disks_to_be_excluded.end()) continue;
        std::cout << "/dev/" << d.name << '\t' << d.model << '\t' << d.tran << '\t' << size_str(d.size) << std::endl;
    }
    return 0;
}

std::tuple<std::filesystem::path,std::optional<std::filesystem::path>,bool/*bios_compatibel*/> 
    create_partitions(const BlockDevice& disk, bool data_partition = true, bool gpt = false)
{
    auto disk_path = std::filesystem::path("/dev") / disk.name;
    std::vector<std::string> parted_args = {"--script", disk_path.string()};
    bool bios_compatible = !gpt && (disk.size <= 2199023255552L/*2TiB*/ && disk.log_sec == 512);
    parted_args.push_back(bios_compatible? "mklabel msdos" : "mklabel gpt");
    if (data_partition) {
        parted_args.push_back("mkpart primary fat32 1MiB 4GiB");
        parted_args.push_back("mkpart primary btrfs 4GiB -1");
    } else {
        parted_args.push_back("mkpart primary fat32 1MiB -1");
    }
    parted_args.push_back("set 1 boot on");
    if (bios_compatible && data_partition) {
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

    auto boot_partition_path = get_partition(disk_path, 1);
    if (!boot_partition_path) throw std::runtime_error("Unable to determine created boot partition");

    std::optional<std::filesystem::path> data_partition_path = std::nullopt;
    if (data_partition) {
        data_partition_path = get_partition(disk_path, 2);
    }

    return std::make_tuple(boot_partition_path.value(), data_partition_path, bios_compatible);
}

std::string format_fat32(const std::filesystem::path& path, const std::optional<std::string>& label = std::nullopt)
{
    std::vector<std::string> mkfs_args = {"-F","32"};
    if (label) {
        mkfs_args.push_back("-n");
        mkfs_args.push_back(label.value());
    }
    mkfs_args.push_back(path.string());
    if (exec("mkfs.vfat",mkfs_args) != 0) throw std::runtime_error("Unable to format partition " + path.string() + " by FAT32");
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
        if (!is_file(system_cfg.value())) throw std::runtime_error(system_cfg.value().string() + " does not exist or not a regular file");
        std::filesystem::copy_file(system_cfg.value(), dest / "system.cfg");
    }
    if (system_ini) {
        if (!is_file(system_ini.value())) throw std::runtime_error(system_ini.value().string() + " does not exist or not a regular file");
        std::filesystem::copy_file(system_ini.value(), dest / "system.ini");
    }
}

template <typename T> T with_memfd(const std::string& name, unsigned int flags, std::function<T(const std::filesystem::path&)> func)
{
    int fd = memfd_create(name.c_str(), flags);
    if (fd < 0) throw std::runtime_error("memfd_create() failed.");
    auto rst = func(std::filesystem::path("/proc") / std::to_string(getpid()) / "fd" / std::to_string(fd));
    close(fd);
    return rst;
}

bool generate_efi_bootloader(const std::string& arch, const std::filesystem::path& output)
{
    // create output directory if not exist
    std::filesystem::create_directories(output.parent_path());

    return with_memfd<bool>("grub.cfg", 0, [&arch,&output](const auto& grub_cfg) {
        {
            std::ofstream cfgfile(grub_cfg);
            if (!cfgfile) {
                std::cout << "Writing grub.cfg on memfd failed." << std::endl;
                return false;
            }
            //else
            cfgfile << "set BOOT_PARTITION=$root\n"
                << "loopback loop /system.img\n"
                << "set root=loop\n"
                << "set prefix=($root)/boot/grub\n"
                << std::endl;
        }

        std::vector<std::string> args = {"-p", "/boot/grub", 
            "-c", grub_cfg.string(),
            "-o", output.string(), "-O", arch};
        const auto grub_modules = ::grub_modules(arch);
        args.insert(args.end(), grub_modules.begin(), grub_modules.end());
        auto rst = (exec("grub-mkimage", args) == 0);
        if (exec("grub-mkimage", args) != 0) {
            std::cout << "grub-mkimage(EFI) failed." << std::endl;
            return false;
        }
        // else
        return true;
    });
}

bool install_bios_bootloader(const std::filesystem::path& disk, const std::filesystem::path& boot_partition_dir)
{
    if (exec("grub-install", {"--target=i386-pc", "--recheck", 
        std::string("--boot-directory=") + (boot_partition_dir / "boot").string(),
        "--modules=" + bios_grub_modules_string(grub_modules("i386-pc")),
        disk.string()}) != 0) return false;
    // create boot config file
    auto grub_dir = boot_partition_dir / "boot/grub";
    std::filesystem::create_directories(grub_dir);
    {
        std::ofstream grubcfg(grub_dir / "grub.cfg");
        if (grubcfg) {
            grubcfg << "insmod echo\ninsmod linux\ninsmod serial\n"
                << "set BOOT_PARTITION=$root\n"
                << "loopback loop /system.img\n"
                << "set root=loop\nset prefix=($root)/boot/grub\nnormal"
                << std::endl;
        } else {
            std::cout << "Writing grub.cfg failed." << std::endl;
            return false;
        }
    }
    return true;
}

bool install_bootloader(const std::filesystem::path& disk, const std::filesystem::path& boot_partition_dir, bool bios_compatible = true)
{
    bool some_bootloader_installed = false;
    auto efi_boot = boot_partition_dir / "efi/boot";
    auto grub_lib = std::filesystem::path("/usr/lib/grub");
    auto efi_bootloaders = {
        std::make_pair("x86_64-efi", "bootx64.efi"),
        std::make_pair("i386-efi", "bootia32.efi"),
        std::make_pair("arm64-efi", "bootaa64.efi")
    };
    for (const auto& [arch, filename]:efi_bootloaders) {
        if (is_dir(grub_lib / arch) && generate_efi_bootloader(arch, efi_boot / filename)) {
            std::cout << arch << " bootloader installed." << std::endl;
            some_bootloader_installed = true;
        }
    }

    if (bios_compatible && is_dir(grub_lib / "i386-pc") && install_bios_bootloader(disk, boot_partition_dir)) {
        std::cout << "i386-pc bootloader installed." << std::endl;
        some_bootloader_installed = true;
    }

    if (!some_bootloader_installed) {
        std::cerr << "No bootloader installed." << std::endl;
    }
    return some_bootloader_installed;
}

struct InstallOptions {
    const std::optional<std::filesystem::path>& system_image = installed_system_image;
    const bool data_partition = true;
    const std::optional<std::filesystem::path>& system_cfg = std::nullopt;
    const std::optional<std::filesystem::path>& system_ini = std::nullopt;
    const std::optional<std::string>& label = std::nullopt;
    const std::optional<std::string>& additional_boot_files = std::nullopt;
    const bool yes = false;
    const bool gpt = false;
};

int install_to_disk(const std::filesystem::path& disk, InstallOptions options = {})
{
    if (disk == "list") return print_installable_disks();

    //else
    auto system_image = options.system_image.value_or(installed_system_image);
    if (!options.system_image) {
        std::cerr << "System file image not specified. assuming " << system_image << "." << std::endl;
    }

    if (!std::filesystem::exists(system_image)) throw std::runtime_error("System image file " + system_image.string() + " does not exist.");

    if (!std::filesystem::exists(disk)) throw std::runtime_error("No such device");

    auto lsblk_result = lsblk(disk);
    if (lsblk_result.size() == 0) throw std::runtime_error("No such device");

    bool has_mounted_partition = false;
    for (auto d:lsblk_result) {
        if (d.mountpoint) has_mounted_partition = true;
    }

    auto disk_info = *lsblk_result.begin();

    if (disk_info.type != "disk" && disk_info.type != "loop") throw std::runtime_error(disk.string() + " is not a disk");
    if (disk_info.ro) throw std::runtime_error(disk.string() + " is read-only device");
    if (has_mounted_partition) throw std::runtime_error(disk.string() + " has mounted partition");
    if (disk_info.pkname) throw std::runtime_error(disk.string() + " belongs to other block device");
    if (disk_info.size < MIN_DISK_SIZE) throw std::runtime_error(disk.string() + " is too small(At least " + size_str(MIN_DISK_SIZE) + " required)");

    auto data_partition = options.data_partition;
    if (data_partition && disk_info.size < MIN_DISK_SIZE_TO_HAVE_DATA_PARTITION) {
        std::cout << "Disk size is not large enough to have data partition.  Applying --no-data-partition." << std::endl;
        data_partition = false;
    }

    std::cout << "Device path: " << disk << std::endl;
    std::cout << "Disk model: " << disk_info.model << std::endl;
    std::cout << "Disk size: " << size_str(disk_info.size) << std::endl;
    std::cout << "Logical sector size: " << disk_info.log_sec << " bytes" << std::endl;

    if (!options.yes) {
        std::string sure;
        std::cout << "All data present on " << disk << " will be lost. Are you sure? (y/n):" << std::flush;
        std::cin >> sure;
        if (sure != "y" && sure != "yes" && sure != "Y") return 1;
    }

    std::cout << "Checking system image file..." << std::endl;
    check_system_image(system_image);
    std::cout << "Looks OK." << std::endl;

    std::cout << "Creating partitions..." << std::flush;
    auto partitions = create_partitions(disk_info, data_partition, options.gpt);
    std::cout << "Done." << std::endl;

    auto boot_partition_path = std::get<0>(partitions);
    auto data_partition_path = std::get<1>(partitions);
    auto bios_compatible = std::get<2>(partitions);

    std::cout << "Formatting boot partition with FAT32" << std::endl;
    auto boot_partition_uuid = format_fat32(boot_partition_path, options.label);
    if (data_partition_path) {
        std::cout << "Formatting data partition with BTRFS..." << std::flush;
        format_btrfs(data_partition_path.value(), std::string("data-") + boot_partition_uuid);
        std::cout << "Done." << std::endl;
    }

    {
        std::cout << "Mounting boot partition..." << std::flush;
        auto tempdir = create_tempmount("/tmp/genpack-install-", boot_partition_path, "vfat", MS_RELATIME, "fmask=177,dmask=077");
        std::cout << "Done" << std::endl;
        auto tempdir_path = std::filesystem::path(tempdir.get());

        std::cout << "Installing bootloader..." << std::flush;
        if (!install_bootloader(disk, tempdir_path, bios_compatible)) {
            std::cout << "Failed" << std::endl;
            return 1;
        }
        //else
        std::cout << "Done" << std::endl;
        if (options.system_cfg || options.system_ini) {
            std::cout << "Copying system config file..." << std::flush;
            copy_system_cfg_ini(options.system_cfg, options.system_ini, tempdir_path);
            std::cout << "Done" << std::endl;
        }
        std::cout << "Copying system image file..." << std::flush;
        std::filesystem::copy_file(system_image, tempdir_path / "system.img");

        if (options.additional_boot_files) {
            std::cout << "Extracting additional boot files..." << std::flush;
            // extract zip archive
            if (exec("unzip", {*options.additional_boot_files, "-d", tempdir_path.string()}) != 0) {
                std::cout << "Failed" << std::endl;
                return 1;
            }
            std::cout << "Done" << std::endl;
        }
    }
    std::cout << "Done." << std::endl;

    return 0;
}

int create_iso9660_image(const std::filesystem::path& image, const std::optional<std::filesystem::path>& _system_image,
    const std::optional<std::filesystem::path>& system_cfg = std::nullopt, const std::optional<std::filesystem::path>& system_ini = std::nullopt,
    const std::optional<std::string>& label = std::nullopt, const std::optional<std::string>& additional_boot_files = std::nullopt)
{
    auto system_image = _system_image? _system_image.value() : installed_system_image;
    if (!_system_image) {
        std::cerr << "System file image not specified. assuming " << system_image << "." << std::endl;
    }

    if (!std::filesystem::exists(system_image)) throw std::runtime_error("System image file " + system_image.string() + " does not exist.");
    if (std::filesystem::exists(image) && !std::filesystem::is_regular_file(image))
        throw std::runtime_error(image.string() + " cannot be overwritten");

    auto tempdir = create_tempmount("/tmp/genpack-iso9660-", "tmpfs", "tmpfs");
    auto tempdir_path = std::filesystem::path(tempdir.get());
    auto grubcfg_path = tempdir_path / "grub.cfg";
    { 
        std::ofstream grubcfg(grubcfg_path);
        grubcfg << "set BOOT_PARTITION=$root\n"
        << "loopback loop /system.img\n"
        << "set root=loop\n"
        << "set prefix=($root)/boot/grub" << std::endl;
    }
    std::filesystem::create_directory(tempdir_path / "boot");
    auto boot_img = tempdir_path / "boot" / "boot.img";

    std::vector<std::string> bios_grub_cmdline = {
        "-p", "/boot/grub", "-c", grubcfg_path.string(), "-o", boot_img.string(), "-O", "i386-pc-eltorito"
    };
    const auto bios_grub_modules = ::grub_modules("i386-pc");
    bios_grub_cmdline.insert(bios_grub_cmdline.end(), bios_grub_modules.begin(), bios_grub_modules.end());

    if (exec("grub-mkimage", bios_grub_cmdline) != 0) throw std::runtime_error("grub-mkimage(BIOS) failed");

    auto efi_boot_dir = tempdir_path / "efi/boot";
    std::filesystem::create_directories(efi_boot_dir);
    auto bootx64_efi = efi_boot_dir / "bootx64.efi";
    std::vector<std::string> efi_grub_cmdline = {
        "-p", "/boot/grub", "-c", grubcfg_path.string(), "-o", bootx64_efi.string(), "-O", "x86_64-efi"
    };
    const auto efi_grub_modules = ::grub_modules("x86_64-efi");
    efi_grub_cmdline.insert(efi_grub_cmdline.end(), efi_grub_modules.begin(), efi_grub_modules.end());
    if (exec("grub-mkimage", efi_grub_cmdline) != 0) throw std::runtime_error("grub-mkimage(EFI) failed");

    std::filesystem::remove(grubcfg_path);

    auto efiboot_img = tempdir_path / "boot" / "efiboot.img";
    // create zero filled 1.44MB file (4096 * 360)
    int fd = creat(efiboot_img.c_str(), S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (fd < 0) throw std::runtime_error("creat() failed");
    int rst = ftruncate(fd, 4096 * 360);
    close(fd);
    if (rst < 0) throw std::runtime_error("ftruncate() failed");
    if (exec("mkfs.vfat", { "-F", "12", "-M", "0xf8", efiboot_img.string() }) != 0) throw std::runtime_error("mkfs.vfat failed");
    if (exec("mmd", {"-i", efiboot_img.string(), "/efi", "/efi/boot"}) != 0) throw std::runtime_error("mmd(mtools) failed");
    if (exec("mcopy", {"-i", efiboot_img.string(), bootx64_efi.string(), "::/efi/boot/"}) != 0) throw std::runtime_error("mcopy(mtools) failed");

    copy_system_cfg_ini(system_cfg, system_ini, tempdir_path);
    if (additional_boot_files) {
        if (exec("unzip", {*additional_boot_files, "-d", tempdir_path.string()}) != 0) {
            throw std::runtime_error("Extracting additional boot files failed");
        }
    }

    return exec("xorriso", {
        "-as", "mkisofs", "-f", "-J", "-r", "-no-emul-boot",
        "-boot-load-size", "4", "-boot-info-table", "-graft-points",
        "-b", "boot/boot.img",
        "-eltorito-alt-boot",
        "-append_partition", "2", "0xef", efiboot_img.string()/*"boot/efiboot.img"*/,
        "-e", "--interval:appended_partition_2:all::",
        "-no-emul-boot", "-isohybrid-gpt-basdat",
        "-V", label.value_or("GENPACK-BOOTCD"), "-o", image.string(), tempdir_path.string(),
        "system.img=" + system_image.string()});
}

int install_self(const std::filesystem::path& system_image,
    const std::optional<std::filesystem::path>& system_cfg = std::nullopt, const std::optional<std::filesystem::path>& system_ini = std::nullopt)
{
    static const std::filesystem::path current_system_image(boot_partition / "system.cur");
    static const std::filesystem::path old_system_image(boot_partition / "system.old");
    static const std::filesystem::path new_system_image(boot_partition / "system.new");

    if (!is_dir(boot_partition)) {
        throw std::runtime_error(std::string("Boot partition is not mounted on ") + boot_partition.string());
    }
    check_system_image(system_image);
    if (is_file(old_system_image)) {
        std::filesystem::remove(old_system_image);
        std::cout << "Old system image removed to preserve disk space." << std::endl;
    }
    std::cout << "Copying new system image..." << std::flush;
    try {
        std::filesystem::copy_file(system_image, new_system_image);
        if (is_image_file_loopbacked(installed_system_image)) {
            std::filesystem::rename(installed_system_image, current_system_image);
            std::cout << "Original system image preserved..." << std::flush;
        }
        std::filesystem::rename(new_system_image, installed_system_image);
    }
    catch (const std::filesystem::filesystem_error& e) {
        if (!std::filesystem::exists(installed_system_image)) {
            if (is_file(current_system_image)) {
                std::filesystem::rename(current_system_image, installed_system_image);
                std::cout << "Original system image restored." << std::endl;
            }
        }
        if (is_file(new_system_image)) std::filesystem::remove(new_system_image);
        throw e;
    }

    copy_system_cfg_ini(system_cfg, system_ini, boot_partition);

    sync();

    std::cout << "Done.  Reboot system to take effects." << std::endl;

    return 0;
}

int show_examples(const std::string& progname)
{
    std::cout << "Example:" << std:: endl;
    std::cout << ' ' << progname << ' ' << "<system image file>" << std::endl;
    std::cout << "or" << std::endl;
    std::cout << ' ' << progname << ' ' << "--disk=<disk device path> [--label=<label>] [system image file]" << std::endl;
    std::cout << "or" << std::endl;
    std::cout << ' ' << progname << ' ' << "--disk=list" << std::endl;
    std::cout << "or" << std::endl;
    std::cout << ' ' << progname << ' ' << "--disk=<iso image file> --cdrom [--label=<label>] [system image file]" << std::endl;
    return 1;
}

int _main(int argc, char** argv)
{
    const std::string progname = "genpack-install";
    argparse::ArgumentParser program(progname);
    // syatem image file is optional
    program.add_argument("system_image").help("System image file").nargs(argparse::nargs_pattern::optional);
    program.add_argument("--disk").help("Disk device path");
    program.add_argument("--system-cfg").help("Install specified system.cfg file");
    program.add_argument("--system-ini").help("Install specified system.ini file");
    program.add_argument("--label").help("Specify volume label of boot partition or iso9660 image");
    program.add_argument("--no-data-partition").help("Use entire disk as boot partition").default_value(false).implicit_value(true);
    program.add_argument("--gpt").help("Always use GPT instead of MBR").default_value(false).implicit_value(true);
    program.add_argument("--cdrom").help("Create iso9660 image").default_value(false).implicit_value(true);
    program.add_argument("--additional-boot-files").help("Zip-archived file contains additional boot files");
    program.add_argument("-y").help("Don't ask questions").default_value(false).implicit_value(true);

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

    try {
        if (geteuid() != 0) throw std::runtime_error("You must be root");

        if (program.present("--disk")) {
            std::filesystem::path disk = program.get<std::string>("--disk");
            //std::cout << "Disk: " << disk << std::endl;
            std::filesystem::path system_image = program.present("system_image")? std::filesystem::path(program.get<std::string>("system_image")) : installed_system_image;
            //std::cout << "System image: " << system_image << std::endl;
            std::optional<std::filesystem::path> system_cfg = program.present("--system-cfg")? std::make_optional(std::filesystem::path(program.get<std::string>("--system-cfg"))) : std::nullopt;
            //std::cout << "System cfg: " << (system_cfg? system_cfg.value().string() : "not specified") << std::endl;
            std::optional<std::filesystem::path> system_ini = program.present("--system-ini")? std::make_optional(std::filesystem::path(program.get<std::string>("--system-ini"))) : std::nullopt;
            //std::cout << "System ini: " << (system_ini? system_ini.value().string() : "not specified") << std::endl;
            std::optional<std::string> label = program.present("--label")? std::make_optional(program.get<std::string>("--label")) : std::nullopt;
            //std::cout << "Label: " << (label? label.value() : "not specified") << std::endl;
            std::optional<std::string> additional_boot_files = program.present("--additional-boot-files");
            if (program.get<bool>("--cdrom")) {
                return create_iso9660_image(disk, system_image, system_cfg, system_ini, label, additional_boot_files);
            }
            //else
            return install_to_disk(disk, { 
                system_image: system_image, 
                data_partition: !program.get<bool>("--no-data-partition"), 
                system_cfg: system_cfg, 
                system_ini:system_ini, 
                label:label, 
                additional_boot_files:additional_boot_files,
                yes:program.get<bool>("-y"), 
                gpt:program.get<bool>("--gpt"),
            });
        }
        // else 
        std::filesystem::path system_image = program.get<std::string>("system_image");
        return install_self(system_image, 
            program.present("--system-cfg")? std::make_optional(std::filesystem::path(program.get<std::string>("--system-cfg"))) : std::nullopt,
            program.present("--system-ini")? std::make_optional(std::filesystem::path(program.get<std::string>("--system-ini"))) : std::nullopt);
    }
    catch (const std::exception& ex) {
        std::cerr << ex.what() << std::endl;
    }

    return 1;
}

//#define TEST

#ifdef TEST
int test_main(int argc, char** argv)
{
    generate_efi_bootloader("bootx64.efi");
    return 0;
}
#endif // TEST

int main(int argc, char* argv[])
{
#ifndef TEST
    return _main(argc, argv);
#else
    return test_main(argc, argv);
#endif
}

// g++ -std=c++23 -o genpack-install genpack-install.cpp -lmount -lblkid
