// libisofs-only ISO builder prototype (no xorriso, no libisoburn, no libburn linkage)
// Reproduces the exact libisofs call sequence that xorriso makes for genpack-install's
// create_iso9660_image() command line (captured via LD_PRELOAD trace).
#include <cstdint>             // libisofs.h uses uint32_t/uint8_t without including stdint.h
#include <cstdlib>
#include <sys/types.h>
#include <libisofs.h>

// libisofs.h only forward-declares ::burn_source. libburn.h cannot be used here because
// in C++ it wraps everything in "namespace burn", which makes burn::burn_source a
// DIFFERENT type from the ::burn_source that iso_image_create_burn_source() expects.
// libisofs.h ships a copy of the declaration for exactly this purpose (see its tail).
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

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <stdexcept>
#include <iostream>
#include <fstream>
#include <filesystem>

// TODO(production): use RAII for IsoImage, IsoWriteOpts, burn_source, output and
// temporary files so every partial-construction and write-error path is cleaned up.
// The Makefile/ebuild must obtain compiler and linker flags through pkg-config and
// complete their conditional build/runtime dependencies for every enabled tool.
static void check(int ret, const char* what) {
    if (ret < 0) throw std::runtime_error(std::string(what) + ": " + iso_error_to_msg(ret));
}

// "-map <local> <isopath>" equivalent: create intermediate dirs, then add the node under a new name
static void map_file(IsoImage* image, const std::filesystem::path& local, const std::string& isopath)
{
    std::vector<std::string> comps;
    for (size_t i = 0, j; i < isopath.size(); i = j + 1) {
        j = isopath.find('/', i);
        if (j == std::string::npos) j = isopath.size();
        if (j > i) comps.emplace_back(isopath.substr(i, j - i));
    }
    if (comps.empty()) throw std::runtime_error("bad iso path: " + isopath);

    IsoDir* dir = iso_image_get_root(image);
    for (size_t k = 0; k + 1 < comps.size(); k++) {
        IsoDir* sub = nullptr;
        int ret = iso_tree_add_new_dir(dir, comps[k].c_str(), &sub);
        if (ret == ISO_NODE_NAME_NOT_UNIQUE) {   // already there: descend into it
            IsoNode* n = nullptr;
            check(iso_dir_get_node(dir, comps[k].c_str(), &n), "iso_dir_get_node");
            sub = (IsoDir*)n;
        } else check(ret, "iso_tree_add_new_dir");
        dir = sub;
    }
    IsoNode* node = nullptr;
    check(iso_tree_add_new_node(image, dir, comps.back().c_str(), local.c_str(), &node),
          "iso_tree_add_new_node");
}

int main(int argc, char** argv)
{
    if (argc < 5) {
        std::cerr << "usage: " << argv[0] << " <out.iso> <bootloader dir> <system image> <volid>\n";
        return 1;
    }
    const std::filesystem::path out = argv[1], bl = argv[2], sysimg = argv[3];
    const std::string volid = argv[4];

    try {
        check(iso_init(), "iso_init");

        IsoImage* image = nullptr;
        check(iso_image_new(volid.c_str(), &image), "iso_image_new");

        // --- tree ---
        map_file(image, bl / "grub.cfg", "/boot/grub/grub.cfg");
        map_file(image, sysimg, "/system.img");
        iso_image_set_volume_id(image, volid.c_str());

        const bool bios = std::filesystem::exists(bl / "eltorito-bios.img");
        const bool efi  = std::filesystem::exists(bl / "eltorito-efi.img");

        // --- El Torito ---
        ElToritoBootImage* biosboot = nullptr;
        if (bios) {
            map_file(image, bl / "eltorito-bios.img", "/boot/grub/i386-pc/eltorito.img");
            check(iso_image_set_boot_image(image, "/boot/grub/i386-pc/eltorito.img",
                                           ELTORITO_NO_EMUL, "/boot/grub/i386-pc/boot.cat",
                                           &biosboot), "iso_image_set_boot_image");
            iso_image_set_boot_catalog_weight(image, 1000000000);
            el_torito_set_boot_platform_id(biosboot, 0x00);
            el_torito_set_full_load(biosboot, 1);                  // load_size=full
            el_torito_set_isolinux_options(biosboot, 1 << 0, 0);   // boot_info_table=on
        }
        ElToritoBootImage* efiboot = nullptr;
        if (efi) {
            if (!bios) {   // EFI-only image: the interval entry becomes the default entry
                check(iso_image_set_boot_image(image, "--interval:appended_partition_2:all::",
                                               ELTORITO_NO_EMUL, "/boot/grub/i386-pc/boot.cat",
                                               &efiboot), "iso_image_set_boot_image(efi)");
                iso_image_set_boot_catalog_weight(image, 1000000000);
            } else {
                check(iso_image_add_boot_image(image, "--interval:appended_partition_2:all::",
                                               ELTORITO_NO_EMUL, 0, &efiboot),
                      "iso_image_add_boot_image");
            }
            el_torito_set_boot_platform_id(efiboot, 0xEF);
            el_torito_set_load_size(efiboot, 4);
            el_torito_set_isolinux_options(efiboot, 0, 0);
        }
        iso_image_set_boot_catalog_hidden(image, 0);

        // --- write options (values as traced from xorriso) ---
        IsoWriteOpts* opts = nullptr;
        check(iso_write_opts_new(&opts, 0), "iso_write_opts_new");
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
        check(iso_write_opts_set_system_area(opts, nullptr, 0, 0), "set_system_area");
        iso_write_opts_set_part_offset(opts, 0, 0, 0);
        iso_write_opts_set_tail_blocks(opts, 0);
        if (efi) {
            auto efipart = (bl / "eltorito-efi.img").string();
            check(iso_write_opts_set_partition_img(opts, 2, 0xef, efipart.data(), 0),
                  "set_partition_img");
            iso_write_opts_set_appended_as_gpt(opts, 0);
            iso_write_opts_set_appended_as_apm(opts, 0);
        }
        iso_write_opts_set_part_like_isohybrid(opts, 0);
        iso_write_opts_set_iso_mbr_part_type(opts, -1);

        // --- generate & write ---
        struct burn_source* src = nullptr;
        check(iso_image_create_burn_source(image, opts, &src), "iso_image_create_burn_source");
        iso_write_opts_free(opts);

        std::ofstream o(out, std::ios::binary);
        if (!o) throw std::runtime_error("cannot open output: " + out.string());
        std::vector<unsigned char> buf(2048 * 32);
        uint64_t total = 0;
        for (;;) {
            int n = src->read_xt(src, buf.data(), (int)buf.size());
            if (n == 0) break;
            if (n < 0) throw std::runtime_error("burn_source read failed");
            o.write((const char*)buf.data(), n);
            total += n;
        }
        o.close();
        src->free_data(src);
        free(src);
        iso_image_unref(image);
        iso_finish();

        std::cout << "wrote " << total << " bytes (" << total / 2048 << " sectors) to " << out << "\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << "\n";
        return 1;
    }
}
