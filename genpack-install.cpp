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
#include <minizip/zip.h>

static const std::filesystem::path boot_partition("/run/initramfs/boot");
static const std::filesystem::path installed_system_image(boot_partition / "system.img");
static const std::filesystem::path grub_lib = std::filesystem::path("/usr/lib/grub");

static const auto efi_bootloaders = {
    std::make_pair("x86_64-efi", "bootx64.efi"),
    std::make_pair("i386-efi", "bootia32.efi"),
    std::make_pair("arm64-efi", "bootaa64.efi")
};

static bool debug = false;

static std::set<std::string> common_grub_modules = {
    "loopback", "xfs", "btrfs", "fat", "exfat", "ntfscomp", "ext2",  "iso9660","lvm", "squash4",
    "part_gpt", "part_msdos", "blocklist", 
    "configfile", "linux", "chain", 
    "echo",   "test", "probe",  "search",  "minicmd","sleep",
    "all_video", "videotest", "serial", "png", "gfxterm_background", "videoinfo", "keystatus"
};

static std::set<std::string> arch_specific_grub_modules = {
    // DO NOT INCLUDE "ahci" HERE.  It makes booting regular PC impossible.
    "ata", "biosdisk", "cpuid", "multiboot", "multiboot2", "fdt"
};

bool is_dir(const std::filesystem::path& path)
{
    return std::filesystem::exists(path) && std::filesystem::is_directory(path);
}

bool is_file(const std::filesystem::path& path)
{
    return std::filesystem::exists(path) && std::filesystem::is_regular_file(path);
}

const std::set<std::string> grub_modules(const std::string& platform)
{
    std::set<std::string> modules;
    for (const auto& m:common_grub_modules) {
        modules.insert(m);
    }
    
    for (const auto& m:arch_specific_grub_modules) {
        if (is_file(grub_lib / platform / (m + ".mod"))) {
            modules.insert(m);
        }
    }
    if (debug) {
        std::cout << "Grub modules for " << platform << ":" << std::endl;
        for (const auto& m:modules) {
            std::cout << m << std::endl;
        }
    }
    return modules;
}

std::string bios_grub_modules_string(const std::set<std::string>& modules)
{
    std::string str;
    for (const auto& m:modules) {
        str += m + " ";
    }
    // remove last space
    str.pop_back();
    if (debug) {
        std::cout << "Grub modules string:" << std::endl;
        std::cout << str << std::endl;
    }
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
    if (!std::filesystem::exists(tempdir_path / "boot/bootcode.bin")) {
        // kernel and initramfs is mandatory unless it's raspberry pi image
        if (!std::filesystem::exists(tempdir_path / "boot/kernel")) throw std::runtime_error("System image file doesn't contain kernel image");
        if (!std::filesystem::exists(tempdir_path / "boot/initramfs")) throw std::runtime_error("System image file doesn't contain initramfs");
    }
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
        if (d.ro || d.size < 4ULL * 1024 * 1024 * 1024/* at least 4GiB */ || (d.type != "disk" && d.type != "loop")) {
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
    create_partitions(const BlockDevice& disk, std::optional<size_t> boot_partition_size_in_gib = 4,
        bool gpt = false)
{
    auto disk_path = std::filesystem::path("/dev") / disk.name;
    std::vector<std::string> parted_args = {"--script", disk_path.string()};
    bool bios_compatible = !gpt && (disk.size <= 2199023255552L/*2TiB*/ && disk.log_sec == 512);
    parted_args.push_back(bios_compatible? "mklabel msdos" : "mklabel gpt");
    if (boot_partition_size_in_gib) {
        parted_args.push_back("mkpart primary fat32 1MiB " + std::to_string(*boot_partition_size_in_gib) + "GiB");
        parted_args.push_back("mkpart primary btrfs " + std::to_string(*boot_partition_size_in_gib) + "GiB -1");
    } else {
        parted_args.push_back("mkpart primary fat32 1MiB -1");
    }
    parted_args.push_back("set 1 boot on");
    if (bios_compatible && boot_partition_size_in_gib) {
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
    if (boot_partition_size_in_gib) {
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
        if (debug) args.push_back("--verbose");
        const auto grub_modules = ::grub_modules(arch);
        args.insert(args.end(), grub_modules.begin(), grub_modules.end());
        if (debug) {
            std::cout << "grub-mkimage(EFI) args:" << std::endl;
            for (const auto& arg:args) {
                std::cout << arg << std::endl;
            }
        }
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

bool install_bootloader(const std::filesystem::path& system_image, const std::filesystem::path& disk, 
    const std::filesystem::path& boot_partition_dir, const std::string& boot_partition_uuid, bool bios_compatible = true)
{
    auto tempdir = create_tempmount("/tmp/genpack-install-", system_image, "auto", MS_RDONLY, "loop");
    std::filesystem::path tempdir_path(tempdir.get());

    if (std::filesystem::exists(tempdir_path / "boot/bootcode.bin")) {
        // raspberry pi
        std::cout << "Installing boot files for raspberry pi..." << std::endl;
        if (exec("cp", {"-a", (tempdir_path / "boot" / ".").string() , boot_partition_dir}) != 0) {
            std::cerr << "Failed to copy boot files." << std::endl;
            return false;
        }
        if (exec("sed", {"-i", "s/ROOTDEV/systemimg:" + boot_partition_uuid + "/", boot_partition_dir / "cmdline.txt"}) != 0) {
            std::cerr << "Failed to modify cmdline.txt." << std::endl;
            return false;
        }
        exec("sed", {"-i", "s/rootfstype=[^ ]* //", boot_partition_dir / "cmdline.txt"});
        std::cout << "Done." << std::endl;
        return true;
    }

    //else

    bool some_bootloader_installed = false;
    auto efi_boot = boot_partition_dir / "efi/boot";
    auto grub_lib = std::filesystem::path("/usr/lib/grub");
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

    auto system_image_size = std::filesystem::file_size(system_image);
    auto boot_partition_size_in_gib = std::max<size_t>(4, (system_image_size * 3) / (1024 * 1024 * 1024) + 1);
    if (disk_info.size < boot_partition_size_in_gib * 1024 * 1024 * 1024) throw std::runtime_error(disk.string() + " is too small(At least " + std::to_string(boot_partition_size_in_gib) + "GiB required)");

    auto data_partition = options.data_partition;
    if (data_partition && disk_info.size / (1024 * 1024 * 1024) < boot_partition_size_in_gib * 3 / 2) {
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
    auto partitions = create_partitions(disk_info, data_partition? std::make_optional(boot_partition_size_in_gib) : std::nullopt, options.gpt);
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
        if (!install_bootloader(system_image, disk, tempdir_path, boot_partition_uuid, bios_compatible)) {
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
    if (exec("xorriso", {"-version"}) != 0) {
        std::cerr << "`xorriso -version` failed. Probably xorriso(libisoburn) is not installed." << std::endl;
        return 1;
    }

    const auto& system_image = _system_image.value_or(installed_system_image);
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

size_t add_file_to_zip(zipFile zf, const std::filesystem::path& file, const std::string& zip_path)
{
    zip_fileinfo zi;
    memset(&zi, 0, sizeof(zi));
    // get system_image timestamp
    struct stat s;
    if (stat(file.c_str(), &s) < 0) throw std::runtime_error("stat() failed");
    // convert file timestamp to tmz_date
    struct tm* t = localtime(&s.st_mtime);
    zi.tmz_date.tm_sec = t->tm_sec;
    zi.tmz_date.tm_min = t->tm_min;
    zi.tmz_date.tm_hour = t->tm_hour;
    zi.tmz_date.tm_mday = t->tm_mday;
    zi.tmz_date.tm_mon = t->tm_mon;
    zi.tmz_date.tm_year = t->tm_year;
    
    auto err = zipOpenNewFileInZip(zf, zip_path.c_str(), &zi, nullptr, 0, nullptr, 0, nullptr, Z_DEFLATED, Z_DEFAULT_COMPRESSION);
    if (err != ZIP_OK) {
        zipClose(zf, nullptr);
        throw std::runtime_error("zipOpenNewFileInZip() failed");
    }
    //else
    std::ifstream f(file, std::ios::binary);
    if (!f) {
        zipClose(zf, nullptr);
        throw std::runtime_error("Failed to open file: " + file.string());
    }
    char buf[4096];
    size_t total_read = 0;
    while (f) {
        f.read(buf, sizeof(buf));
        if (f.bad()) {
            zipClose(zf, nullptr);
            throw std::runtime_error("Failed to read file: " + file.string());
        }
        auto bytes_read = f.gcount();
        total_read += bytes_read;
        if (zipWriteInFileInZip(zf, buf, bytes_read) != ZIP_OK) {
            zipClose(zf, nullptr);
            throw std::runtime_error("zipWriteInFileInZip() failed");
        }
    }
    zipCloseFileInZip(zf);
    return total_read;
}

size_t add_text_to_zip(zipFile zf, const std::string& text, const std::string& zip_path)
{
    zip_fileinfo zi;
    memset(&zi, 0, sizeof(zi));
    // get system_image timestamp
    time_t now = time(nullptr);
    struct tm* t = localtime(&now);
    zi.tmz_date.tm_sec = t->tm_sec;
    zi.tmz_date.tm_min = t->tm_min;
    zi.tmz_date.tm_hour = t->tm_hour;
    zi.tmz_date.tm_mday = t->tm_mday;
    zi.tmz_date.tm_mon = t->tm_mon;
    zi.tmz_date.tm_year = t->tm_year;
    
    auto err = zipOpenNewFileInZip(zf, zip_path.c_str(), &zi, nullptr, 0, nullptr, 0, nullptr, Z_DEFLATED, Z_DEFAULT_COMPRESSION);
    if (err != ZIP_OK) {
        zipClose(zf, nullptr);
        throw std::runtime_error("zipOpenNewFileInZip() failed");
    }
    //else
    if (zipWriteInFileInZip(zf, text.c_str(), text.size()) != ZIP_OK) {
        zipClose(zf, nullptr);
        throw std::runtime_error("zipWriteInFileInZip() failed");
    }
    zipCloseFileInZip(zf);
    return text.size();
}

int create_zip_archive(const std::filesystem::path& archive, 
    const std::optional<std::filesystem::path>& _system_image = std::nullopt,
    const std::optional<std::filesystem::path>& system_cfg = std::nullopt, 
    const std::optional<std::filesystem::path>& system_ini = std::nullopt,
    const std::optional<std::string>& additional_boot_files = std::nullopt)
{
    const auto& system_image = _system_image.value_or(installed_system_image);
    if (!_system_image) {
        std::cerr << "System file image not specified. assuming " << system_image << "." << std::endl;
    }

    auto zf = zipOpen(archive.c_str(), APPEND_STATUS_CREATE);
    if (!zf) throw std::runtime_error("zipOpen() failed");
    //else
    add_file_to_zip(zf, system_image, "system.img");
    if (system_cfg) add_file_to_zip(zf, system_cfg.value(), "system.cfg");
    if (system_ini) add_file_to_zip(zf, system_ini.value(), "system.ini");

    // generate bootloader
    for (const auto& [arch, filename]:efi_bootloaders) {
        if (is_dir(grub_lib / arch)) {
            // create tempfile by memfd_create
            auto rst = with_memfd<bool>("grub.efi", 0, [zf,arch,filename](const auto& tmpfile) {
                if (generate_efi_bootloader(arch, tmpfile)) {
                    add_file_to_zip(zf, tmpfile, std::string("efi/boot/") + filename);
                    return true;
                }
                //else
                return false;
            });
            if (rst) {
                std::cout << arch << " bootloader generated." << std::endl;
            }
        }
    }

    {
        // for raspberry pi, all files under /boot should be copied to boot partition
        auto tempdir = create_tempmount("/tmp/genpack-install-", system_image, "auto", MS_RDONLY, "loop");
        auto tempdir_path = std::filesystem::path(tempdir.get());
        if (is_file(tempdir_path / "boot" / "bootcode.bin")) {
            // raspberry pi
            std::cout << "Installing boot files for raspberry pi..." << std::endl;
            // zip all files under tmpdir_path / "boot" recursively
            auto tempdir_path_boot = tempdir_path / "boot";
            for (const auto& entry: std::filesystem::recursive_directory_iterator(tempdir_path_boot)) {
                if (!entry.is_regular_file()) continue;
                auto relative_path = std::filesystem::relative(entry.path(), tempdir_path_boot).string();
                if (relative_path == "cmdline.txt") {
                    // modify cmdline.txt
                    std::ifstream f(entry.path());
                    std::string cmdline;
                    std::getline(f, cmdline);
                    // replace "ROOTDEV" to "systemimg:auto"
                    cmdline = std::regex_replace(cmdline, std::regex(R"((^|\s)root=[^ ]*)"), "$1root=systemimg:auto");
                    // remove "rootfstype=..."
                    cmdline = std::regex_replace(cmdline, std::regex(R"((^|\s)rootfstype=[^ ]*)"), "");
                    // write modified cmdline.txt to zip
                    add_text_to_zip(zf, cmdline, relative_path);
                    continue;
                }
                // else 
                add_file_to_zip(zf, entry.path(), std::filesystem::relative(entry.path(), tempdir_path_boot).string());
            }
            std::cout << "Done." << std::endl;
        }
    }

    if (additional_boot_files) {
        std::cout << "Extracting additional boot files..." << std::endl;
        throw std::runtime_error("Not implemented yet.");
    }

    zipClose(zf, nullptr);
    return 0;
}

bool are_files_same(const std::filesystem::path& file1, const std::filesystem::path& file2)
{
    if (std::filesystem::file_size(file1) != std::filesystem::file_size(file2)) return false;
    //else
    std::ifstream f1(file1, std::ios::binary);
    std::ifstream f2(file2, std::ios::binary);
    if (!f1 || !f2) {
        if (debug) std::cout << "Failed to open file: " << file1 << " or " << file2 << std::endl;
        return false;
    }
    char buf1[4096], buf2[4096];
    while (true) {
        f1.read(buf1, sizeof(buf1));
        f2.read(buf2, sizeof(buf2));
        std::streamsize bytes_read1 = f1.gcount();
        std::streamsize bytes_read2 = f2.gcount();
        if (bytes_read1 != bytes_read2 || memcmp(buf1, buf2, bytes_read1) != 0) {
            return false;
        }
        if (bytes_read1 < sizeof(buf1)) break; // End of file reached
    }
    return f1.eof() && f2.eof();
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

    {
        // for raspberry pi, all files under /boot should be copied to boot partition
        auto tempdir = create_tempmount("/tmp/genpack-install-", system_image, "auto", MS_RDONLY, "loop");
        auto tempdir_path = std::filesystem::path(tempdir.get());
        if (is_file(tempdir_path / "boot" / "bootcode.bin")) {
            // raspberry pi
            std::cout << "Installing boot files for raspberry pi..." << std::endl;
            // first, enum all files under tmpdir_path / "boot" recursively
            std::vector<std::filesystem::path> files;
            auto tempdir_path_boot = tempdir_path / "boot";
            for (const auto& entry: std::filesystem::recursive_directory_iterator(tempdir_path_boot)) {
                if (entry.is_directory()) {
                    auto dst_dir = boot_partition / std::filesystem::relative(entry.path(), tempdir_path_boot);
                    if (!std::filesystem::create_directories(dst_dir) && debug) {
                        std::cout << "Directory not created: " << dst_dir << std::endl;
                    }
                } else if (entry.is_regular_file()) {
                    files.push_back(entry.path());
                }
            }
            // then, copy all files except config.txt and cmdline.txt to boot partition
            for (const auto& file: files) {
                std::filesystem::path relative_path = std::filesystem::relative(file, tempdir_path_boot);
                if (relative_path == "config.txt" || relative_path == "cmdline.txt") continue;
                auto dst_path = boot_partition / relative_path;
                if (std::filesystem::exists(dst_path) && are_files_same(file, dst_path)) {
                    if (debug) std::cout << "File already exists: " << dst_path << std::endl;
                    continue;
                }
                // else
                // copy file to dst_path + ".new" and then rename it to dst_path
                std::filesystem::copy_file(file, dst_path.string() + ".new");
                std::filesystem::rename(dst_path.string() + ".new", dst_path);
                if (debug) std::cout << file << std::endl;
            }
            std::cout << "Done." << std::endl;
        }
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
    program.add_argument("--cdrom").help("Create iso9660 image");
    program.add_argument("--zip").help("Create zip-archived system directory");
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

         auto [disk, cdrom, zip] = std::make_tuple(
            program.present("--disk"),
            program.present("--cdrom"), 
            program.present("--zip")
        );

        if (!disk && !cdrom && !zip) {
            std::filesystem::path system_image = program.get<std::string>("system_image");
            return install_self(system_image, 
                program.present("--system-cfg"),
                program.present("--system-ini"));
        }

        //else
        const auto& system_image = program.present("system_image").value_or(installed_system_image);

        std::optional<std::filesystem::path> system_cfg = program.present("--system-cfg")? std::make_optional(std::filesystem::path(program.get<std::string>("--system-cfg"))) : std::nullopt;
        //std::cout << "System cfg: " << (system_cfg? system_cfg.value().string() : "not specified") << std::endl;
        std::optional<std::filesystem::path> system_ini = program.present("--system-ini")? std::make_optional(std::filesystem::path(program.get<std::string>("--system-ini"))) : std::nullopt;
        //std::cout << "System ini: " << (system_ini? system_ini.value().string() : "not specified") << std::endl;
        auto additional_boot_files = program.present("--additional-boot-files");

        if (disk) {
            //std::cout << "Disk: " << disk << std::endl;
            auto rst = install_to_disk(disk.value(), { 
                system_image: system_image, 
                data_partition: !program.get<bool>("--no-data-partition"), 
                system_cfg: system_cfg, 
                system_ini:system_ini, 
                label:program.present("--label"), 
                additional_boot_files:additional_boot_files,
                yes:program.get<bool>("-y"), 
                gpt:program.get<bool>("--gpt"),
            });
            if (rst != 0) return rst;
        }
        if (cdrom) {
            auto rst = create_iso9660_image(cdrom.value(), system_image, system_cfg, system_ini, program.present("--label"), additional_boot_files);
            if (rst != 0) return rst;
        }
        if (zip) {
            auto rst = create_zip_archive(zip.value(), system_image, system_cfg, system_ini, additional_boot_files);
            if (rst != 0) return rst;
        }
        return 0;

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
