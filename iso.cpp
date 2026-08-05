#include <cstdint>      // libisofs.h uses uint32_t/uint8_t without including stdint.h itself
#include <cstdlib>
#include <sys/types.h>
#include <libisofs.h>

// libisofs.h only forward-declares ::burn_source. libburn.h cannot be used to
// get the definition because in C++ it wraps everything in "namespace burn",
// which makes burn::burn_source a DIFFERENT type from the ::burn_source that
// iso_image_create_burn_source() hands back. libisofs.h ships a copy of the
// declaration for exactly this purpose (see its tail); this is that copy.
extern "C" {
struct burn_source {
    int refcount;
    int (*read)(struct burn_source*, unsigned char* buffer, int size);
    int (*read_sub)(struct burn_source*, unsigned char* buffer, int size);
    off_t (*get_size)(struct burn_source*);
    int (*set_size)(struct burn_source* source, off_t size);
    void (*free_data)(struct burn_source*);
    struct burn_source* next;
    void* data;
    int version;
    int (*read_xt)(struct burn_source*, unsigned char* buffer, int size);
    int (*cancel)(struct burn_source* source);
};
}

#include <algorithm>
#include <fstream>
#include <iostream>
#include <stdexcept>

#include "iso.hpp"
#include "image.hpp"

namespace {

const std::string system_image_iso_path = "system.img";
const std::string grub_cfg_iso_path = "boot/grub/grub.cfg";
const std::string eltorito_bios_iso_path = "boot/grub/i386-pc/eltorito.img";
// libisofs wants the directory holding the boot catalog to exist already. It
// sits next to the BIOS boot image when there is one, and directly under
// boot/grub otherwise, so that an EFI-only image gets no i386-pc directory.
const std::string bios_boot_catalog_iso_path = "boot/grub/i386-pc/boot.cat";
const std::string efi_only_boot_catalog_iso_path = "boot/grub/boot.cat";

void check(int ret, const char* what)
{
    if (ret < 0) throw std::runtime_error(std::string(what) + ": " + iso_error_to_msg(ret));
}

// Frees the libisofs global state and the image on the way out, whichever way
// create_iso9660_image() returns.
class IsoLibrary {
    IsoImage* img = nullptr;
public:
    IsoLibrary(const IsoLibrary&) = delete;
    IsoLibrary& operator=(const IsoLibrary&) = delete;
    explicit IsoLibrary(const std::string& volume_id) {
        check(iso_init(), "iso_init");
        auto rst = iso_image_new(volume_id.c_str(), &img);
        if (rst < 0) {
            iso_finish();
            check(rst, "iso_image_new");
        }
    }
    ~IsoLibrary() {
        if (img) iso_image_unref(img);
        iso_finish();
    }
    IsoImage* image() const { return img; }
};

class BurnSource {
    struct burn_source* src = nullptr;
public:
    BurnSource(const BurnSource&) = delete;
    BurnSource& operator=(const BurnSource&) = delete;
    BurnSource(IsoImage* image, IsoWriteOpts* opts) {
        check(iso_image_create_burn_source(image, opts, &src), "iso_image_create_burn_source");
    }
    ~BurnSource() {
        if (!src) return;
        //else
        // iso_image_create_burn_source() starts producing right away, so a
        // consumer that stops early has to say so before the source is freed.
        if (!completed && src->cancel) src->cancel(src);
        src->free_data(src);
        free(src);
    }
    int read(unsigned char* buffer, int size) { return src->read_xt(src, buffer, size); }
    uint64_t size() const { return (uint64_t)src->get_size(src); }
    // Called once everything the source announced has been read out of it.
    void mark_completed() { completed = true; }
private:
    bool completed = false;
};

class WriteOpts {
    IsoWriteOpts* opts = nullptr;
public:
    WriteOpts(const WriteOpts&) = delete;
    WriteOpts& operator=(const WriteOpts&) = delete;
    WriteOpts() { check(iso_write_opts_new(&opts, 0), "iso_write_opts_new"); }
    ~WriteOpts() { if (opts) iso_write_opts_free(opts); }
    IsoWriteOpts* get() const { return opts; }
};

std::vector<std::string> split_iso_path(const std::string& iso_path)
{
    std::vector<std::string> components;
    for (std::string::size_type i = 0, j; i < iso_path.size(); i = j + 1) {
        j = iso_path.find('/', i);
        if (j == std::string::npos) j = iso_path.size();
        if (j > i) components.emplace_back(iso_path.substr(i, j - i));
    }
    if (components.empty()) throw std::runtime_error("Bad path in ISO image: " + iso_path);
    //else
    return components;
}

// Walks down to the directory holding the last component, creating the
// intermediate directories that aren't there yet.
IsoDir* make_parent_dirs(IsoImage* image, const std::vector<std::string>& components)
{
    IsoDir* dir = iso_image_get_root(image);
    std::string walked;
    for (size_t i = 0; i + 1 < components.size(); i++) {
        walked += "/" + components[i];
        IsoDir* subdir = nullptr;
        int rst = iso_tree_add_new_dir(dir, components[i].c_str(), &subdir);
        if (rst == (int)ISO_NODE_NAME_NOT_UNIQUE) { // already there: descend into it
            IsoNode* node = nullptr;
            check(iso_dir_get_node(dir, components[i].c_str(), &node), "iso_dir_get_node");
            // check_dest_hierarchy() should have caught this, but casting a
            // non-directory node to IsoDir* would take the process down
            if (iso_node_get_type(node) != LIBISO_DIR) {
                throw std::runtime_error("Cannot create a directory at " + walked
                    + " in the ISO image: something that is not a directory is already there");
            }
            subdir = (IsoDir*)node;
        } else check(rst, "iso_tree_add_new_dir");
        dir = subdir;
    }
    return dir;
}

// The "-map <local file> <iso path>" equivalent: create the intermediate
// directories, then add the file under the requested name. An entry already
// present at that path is replaced.
void map_file(IsoImage* image, const std::filesystem::path& local, const std::string& iso_path)
{
    auto components = split_iso_path(iso_path);
    auto dir = make_parent_dirs(image, components);
    IsoNode* existing = nullptr;
    if (iso_dir_get_node(dir, components.back().c_str(), &existing) == 1) {
        iso_node_remove(existing);
    }
    IsoNode* node = nullptr;
    check(iso_tree_add_new_node(image, dir, components.back().c_str(), local.c_str(), &node),
        "iso_tree_add_new_node");
}

struct IsoEntry {
    std::string iso_path;           // normalized, relative to the ISO root
    std::filesystem::path local;
};

// Puts the --add files on top of what this tool places itself. Overwriting a
// file the ISO needs to boot is the caller's business, so it is only reported.
void apply_add_files(std::vector<IsoEntry>& entries, const std::vector<AddFile>& add_files)
{
    for (const auto& add_file:add_files) {
        auto conflict = std::find_if(entries.begin(), entries.end(),
            [&add_file](const auto& entry) { return entry.iso_path == add_file.dest; });
        if (conflict != entries.end()) {
            std::cerr << "Warning: --add overwrites /" << add_file.dest << " in the ISO image with "
                << add_file.src.string() << "." << std::endl;
            conflict->local = add_file.src;
        } else {
            entries.push_back(IsoEntry { add_file.dest, add_file.src });
        }
    }
}

} // namespace

void create_iso9660_image(const std::filesystem::path& output_image,
    const std::filesystem::path& system_image, const ISO9660Options& options)
{
    if (!std::filesystem::is_regular_file(system_image)) {
        throw std::runtime_error("System image file " + system_image.string() + " does not exist or is not a regular file");
    }
    if (std::filesystem::exists(output_image) && !std::filesystem::is_regular_file(output_image)) {
        throw std::runtime_error(output_image.string() + " cannot be overwritten");
    }
    if (same_file(output_image, system_image)) {
        throw std::runtime_error("Output file " + output_image.string() + " is the system image file itself");
    }
    for (const auto& add_file:options.add_files) {
        if (same_file(output_image, add_file.src)) {
            throw std::runtime_error("Output file " + output_image.string() + " is also given as --add source "
                + add_file.src.string());
        }
    }

    SystemImageReader image(system_image);
    check_system_image(image);

    auto bootloader = BootloaderFiles::locate(image);
    if (!bootloader) throw std::runtime_error("No bootloader files found.");
    //else
    if (debug) std::cerr << "Bootloader files: " << bootloader->origin() << std::endl;
    if (!bootloader->contains("grub.cfg")) throw std::runtime_error("No grub.cfg found among the bootloader files.");

    bool bios = bootloader->contains("eltorito-bios.img");
    bool efi = bootloader->contains("eltorito-efi.img");
    if (!bios && !efi) {
        std::cerr << "Warning: neither eltorito-bios.img nor eltorito-efi.img found. "
            "The generated ISO image will not be bootable." << std::endl;
    }

    // libisofs reads its input through the local filesystem, so whatever lives
    // inside the system image has to be extracted first. The system image
    // itself is handed over by path and never copied.
    TempDirectory tempdir("genpack-mkiso-");

    std::vector<IsoEntry> entries = {
        { grub_cfg_iso_path, bootloader->materialize("grub.cfg", tempdir.path()) },
        { system_image_iso_path, system_image }
    };
    if (bios) {
        entries.push_back(IsoEntry {
            eltorito_bios_iso_path, bootloader->materialize("eltorito-bios.img", tempdir.path())
        });
    }
    auto efi_partition_img = efi? bootloader->materialize("eltorito-efi.img", tempdir.path()) : std::filesystem::path();

    const auto& boot_catalog_iso_path = bios? bios_boot_catalog_iso_path : efi_only_boot_catalog_iso_path;
    if (bios || efi) {
        // Unlike the files above, the boot catalog is generated by libisofs
        // rather than placed by us, so --add cannot take it over.
        for (const auto& add_file:options.add_files) {
            if (add_file.dest == boot_catalog_iso_path) {
                throw std::runtime_error("--add cannot replace /" + boot_catalog_iso_path
                    + ", which is the El Torito boot catalog generated by this tool");
            }
        }
    }
    apply_add_files(entries, options.add_files);

    std::vector<std::string> destinations;
    for (const auto& entry:entries) destinations.push_back(entry.iso_path);
    if (bios || efi) destinations.push_back(boot_catalog_iso_path);
    check_dest_hierarchy(destinations);

    std::cout << "Creating ISO9660 image..." << std::endl;

    const std::string volume_id = options.label? *options.label : "GENPACK";
    IsoLibrary library(volume_id);
    auto iso_image = library.image();

    for (const auto& entry:entries) map_file(iso_image, entry.local, "/" + entry.iso_path);
    iso_image_set_volume_id(iso_image, volume_id.c_str());

    // El Torito. The option values below mirror what xorriso issues for the
    // equivalent command line, captured with an LD_PRELOAD trace of libisofs.
    const auto boot_catalog_path = "/" + boot_catalog_iso_path;
    if (bios || efi) make_parent_dirs(iso_image, split_iso_path(boot_catalog_path));

    ElToritoBootImage* bios_boot = nullptr;
    if (bios) {
        check(iso_image_set_boot_image(iso_image, ("/" + eltorito_bios_iso_path).c_str(),
            ELTORITO_NO_EMUL, boot_catalog_path.c_str(), &bios_boot), "iso_image_set_boot_image");
        iso_image_set_boot_catalog_weight(iso_image, 1000000000);
        el_torito_set_boot_platform_id(bios_boot, 0x00);
        el_torito_set_full_load(bios_boot, 1);                  // load_size=full
        el_torito_set_isolinux_options(bios_boot, 1 << 0, 0);   // boot_info_table=on
    }
    ElToritoBootImage* efi_boot = nullptr;
    if (efi) {
        // The "--interval:" syntax is interpreted by libisofs itself, not by xorriso.
        const char* interval = "--interval:appended_partition_2:all::";
        if (bios) {
            check(iso_image_add_boot_image(iso_image, interval, ELTORITO_NO_EMUL, 0, &efi_boot),
                "iso_image_add_boot_image");
        } else {
            // EFI-only image: the interval entry becomes the default entry
            check(iso_image_set_boot_image(iso_image, interval, ELTORITO_NO_EMUL,
                boot_catalog_path.c_str(), &efi_boot), "iso_image_set_boot_image");
            iso_image_set_boot_catalog_weight(iso_image, 1000000000);
        }
        el_torito_set_boot_platform_id(efi_boot, 0xEF);
        el_torito_set_load_size(efi_boot, 4);
        el_torito_set_isolinux_options(efi_boot, 0, 0);
    }
    iso_image_set_boot_catalog_hidden(iso_image, 0);

    WriteOpts write_opts;
    auto opts = write_opts.get();
    iso_write_opts_set_iso_level(opts, 3);
    iso_write_opts_set_rockridge(opts, 1);
    iso_write_opts_set_joliet(opts, 1);
    iso_write_opts_set_hardlinks(opts, 0);
    iso_write_opts_set_aaip(opts, 0);
    iso_write_opts_set_old_empty(opts, 0);
    iso_write_opts_set_omit_version_numbers(opts, 2);
    iso_write_opts_set_allow_deep_paths(opts, 1);
    iso_write_opts_set_allow_longer_paths(opts, 1);
    iso_write_opts_set_max_37_char_filenames(opts, 0);
    iso_write_opts_set_no_force_dots(opts, 2);
    iso_write_opts_set_allow_lowercase(opts, 0);
    iso_write_opts_set_allow_full_ascii(opts, 0);
    iso_write_opts_set_relaxed_vol_atts(opts, 1);
    iso_write_opts_set_joliet_longer_paths(opts, 0);
    iso_write_opts_set_joliet_long_names(opts, 0);
    iso_write_opts_set_joliet_utf16(opts, 0);
    iso_write_opts_set_always_gmt(opts, 1);
    iso_write_opts_set_rrip_version_1_10(opts, 1);
    iso_write_opts_set_dir_rec_mtime(opts, 7);
    iso_write_opts_set_aaip_susp_1_10(opts, 1);
    iso_write_opts_set_sort_files(opts, 1);
    iso_write_opts_set_record_md5(opts, 0, 0);
    check(iso_write_opts_set_system_area(opts, nullptr, 0, 0), "iso_write_opts_set_system_area");
    iso_write_opts_set_part_offset(opts, 0, 0, 0);
    iso_write_opts_set_tail_blocks(opts, 0);
    if (efi) {
        auto path = efi_partition_img.string();
        check(iso_write_opts_set_partition_img(opts, 2, 0xef, path.data(), 0), "iso_write_opts_set_partition_img");
        iso_write_opts_set_appended_as_gpt(opts, 0);
        iso_write_opts_set_appended_as_apm(opts, 0);
    }
    iso_write_opts_set_part_like_isohybrid(opts, 0);
    iso_write_opts_set_iso_mbr_part_type(opts, -1);

    // The image is built next to its destination and only moved into place once
    // it is complete, so a failure never leaves a half-written ISO behind.
    TempOutputFile output(output_image);
    {
        BurnSource source(iso_image, opts);
        std::ofstream out(output.path(), std::ios::binary | std::ios::trunc);
        if (!out) throw std::runtime_error("Cannot open " + output.path().string() + " for writing");
        //else
        std::vector<unsigned char> buf(2048 * 32);
        // Asking the burn source for more bytes than it has left makes it
        // return 0 and drop that remainder on the floor, so the last request
        // has to be trimmed to exactly what is outstanding.
        const uint64_t announced = source.size();
        uint64_t total = 0;
        while (total < announced) {
            auto read = source.read(buf.data(), (int)std::min<uint64_t>(buf.size(), announced - total));
            if (read <= 0) {
                throw std::runtime_error("Generating the ISO9660 image failed after "
                    + std::to_string(total) + " of " + std::to_string(announced) + " bytes");
            }
            //else
            out.write((const char*)buf.data(), read);
            if (!out) throw std::runtime_error("Writing " + output.path().string() + " failed");
            total += read;
        }
        source.mark_completed();
        out.close();
        if (!out) throw std::runtime_error("Writing " + output.path().string() + " failed");
        if (debug) std::cerr << "Wrote " << total << " bytes (" << total / 2048 << " sectors)." << std::endl;
    }
    output.commit();

    std::cout << "Done." << std::endl;
}
