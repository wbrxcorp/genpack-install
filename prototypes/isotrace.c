/* LD_PRELOAD shim: log the libisofs calls xorriso actually makes */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>

static FILE* lg(void) {
    static FILE* f = NULL;
    if (!f) { f = fopen("/tmp/claude-1000/isotrace.log", "w"); setvbuf(f, NULL, _IOLBF, 0); }
    return f;
}

#define REAL(name) static typeof(name)* real; if (!real) real = dlsym(RTLD_NEXT, #name);

/* --- write opts: int value --- */
#define WRAP_INT(name) \
    int name(void* o, int v) { REAL(name); fprintf(lg(), "%s(%d)\n", #name, v); return real(o, v); }

WRAP_INT(iso_write_opts_set_rockridge)
WRAP_INT(iso_write_opts_set_joliet)
WRAP_INT(iso_write_opts_set_iso_level)
WRAP_INT(iso_write_opts_set_relaxed_vol_atts)
WRAP_INT(iso_write_opts_set_appended_as_gpt)
WRAP_INT(iso_write_opts_set_appended_as_apm)
WRAP_INT(iso_write_opts_set_part_like_isohybrid)
WRAP_INT(iso_write_opts_set_iso_mbr_part_type)
WRAP_INT(iso_write_opts_set_hardlinks)
WRAP_INT(iso_write_opts_set_aaip)
WRAP_INT(iso_write_opts_set_allow_deep_paths)
WRAP_INT(iso_write_opts_set_dir_rec_mtime)
WRAP_INT(iso_write_opts_set_omit_version_numbers)
WRAP_INT(iso_write_opts_set_allow_lowercase)
WRAP_INT(iso_write_opts_set_allow_full_ascii)
WRAP_INT(iso_write_opts_set_no_force_dots)
WRAP_INT(iso_write_opts_set_max_37_char_filenames)
WRAP_INT(iso_write_opts_set_allow_longer_paths)
WRAP_INT(iso_write_opts_set_joliet_longer_paths)
WRAP_INT(iso_write_opts_set_joliet_long_names)
WRAP_INT(iso_write_opts_set_joliet_utf16)
WRAP_INT(iso_write_opts_set_rrip_version_1_10)
WRAP_INT(iso_write_opts_set_aaip_susp_1_10)
WRAP_INT(iso_write_opts_set_sort_files)
WRAP_INT(iso_write_opts_set_always_gmt)
WRAP_INT(iso_write_opts_set_old_empty)

int iso_write_opts_set_record_md5(void* o, int s, int f) {
    REAL(iso_write_opts_set_record_md5);
    fprintf(lg(), "iso_write_opts_set_record_md5(session=%d, files=%d)\n", s, f);
    return real(o, s, f);
}

int iso_write_opts_set_system_area(void* o, char* data, int options, int flag) {
    REAL(iso_write_opts_set_system_area);
    fprintf(lg(), "iso_write_opts_set_system_area(data=%s, options=0x%x, flag=%d)\n",
            data ? "<32KB>" : "NULL", options, flag);
    return real(o, data, options, flag);
}

int iso_write_opts_set_partition_img(void* o, int num, uint8_t type, char* path, int flag) {
    REAL(iso_write_opts_set_partition_img);
    fprintf(lg(), "iso_write_opts_set_partition_img(num=%d, type=0x%02x, path=%s, flag=%d)\n",
            num, type, path ? path : "(null)", flag);
    return real(o, num, type, path, flag);
}

int iso_write_opts_set_part_type_guid(void* o, int num, uint8_t* guid, int valid) {
    REAL(iso_write_opts_set_part_type_guid);
    fprintf(lg(), "iso_write_opts_set_part_type_guid(num=%d, valid=%d)\n", num, valid);
    return real(o, num, guid, valid);
}

int iso_write_opts_set_part_offset(void* o, uint32_t off, int secs, int heads) {
    REAL(iso_write_opts_set_part_offset);
    fprintf(lg(), "iso_write_opts_set_part_offset(offset=%u, secs_per_head=%d, heads_per_cyl=%d)\n",
            off, secs, heads);
    return real(o, off, secs, heads);
}

int iso_write_opts_set_tail_blocks(void* o, uint32_t n) {
    REAL(iso_write_opts_set_tail_blocks);
    fprintf(lg(), "iso_write_opts_set_tail_blocks(%u)\n", n);
    return real(o, n);
}

int iso_write_opts_set_efi_bootp(void* o, char* path, int flag) {
    REAL(iso_write_opts_set_efi_bootp);
    fprintf(lg(), "iso_write_opts_set_efi_bootp(path=%s, flag=%d)\n", path ? path : "(null)", flag);
    return real(o, path, flag);
}

int iso_write_opts_set_prep_img(void* o, char* path, int flag) {
    REAL(iso_write_opts_set_prep_img);
    fprintf(lg(), "iso_write_opts_set_prep_img(path=%s, flag=%d)\n", path ? path : "(null)", flag);
    return real(o, path, flag);
}

/* --- volume / boot --- */
void iso_image_set_volume_id(void* img, const char* id) {
    REAL(iso_image_set_volume_id);
    fprintf(lg(), "iso_image_set_volume_id(\"%s\")\n", id ? id : "(null)");
    real(img, id);
}

int iso_image_set_boot_image(void* img, const char* path, int type, const char* cat, void** boot) {
    REAL(iso_image_set_boot_image);
    int r = real(img, path, type, cat, boot);
    fprintf(lg(), "iso_image_set_boot_image(path=%s, type=%d, catalog=%s) -> %d [bootimg=%p]\n",
            path ? path : "(null)", type, cat ? cat : "(null)", r, boot ? *boot : NULL);
    return r;
}

int iso_image_add_boot_image(void* img, const char* path, int type, int flag, void** boot) {
    REAL(iso_image_add_boot_image);
    int r = real(img, path, type, flag, boot);
    fprintf(lg(), "iso_image_add_boot_image(path=%s, type=%d, flag=%d) -> %d [bootimg=%p]\n",
            path ? path : "(null)", type, flag, r, boot ? *boot : NULL);
    return r;
}

void el_torito_set_full_load(void* b, int mode) {
    REAL(el_torito_set_full_load);
    fprintf(lg(), "el_torito_set_full_load(%p, %d)\n", b, mode);
    real(b, mode);
}

void el_torito_set_load_size(void* b, short sectors) {
    REAL(el_torito_set_load_size);
    fprintf(lg(), "el_torito_set_load_size(%p, %d)\n", b, sectors);
    real(b, sectors);
}

void el_torito_set_load_seg(void* b, short seg) {
    REAL(el_torito_set_load_seg);
    fprintf(lg(), "el_torito_set_load_seg(%p, 0x%x)\n", b, (unsigned)(unsigned short)seg);
    real(b, seg);
}

int el_torito_set_boot_platform_id(void* b, uint8_t id) {
    REAL(el_torito_set_boot_platform_id);
    fprintf(lg(), "el_torito_set_boot_platform_id(%p, 0x%02x)\n", b, id);
    return real(b, id);
}

int el_torito_set_isolinux_options(void* b, int options, int flag) {
    REAL(el_torito_set_isolinux_options);
    fprintf(lg(), "el_torito_set_isolinux_options(%p, options=0x%x, flag=%d)\n", b, options, flag);
    return real(b, options, flag);
}

void el_torito_set_no_bootable(void* b) {
    REAL(el_torito_set_no_bootable);
    fprintf(lg(), "el_torito_set_no_bootable(%p)\n", b);
    real(b);
}

int iso_image_set_boot_catalog_weight(void* img, int w) {
    REAL(iso_image_set_boot_catalog_weight);
    fprintf(lg(), "iso_image_set_boot_catalog_weight(%d)\n", w);
    return real(img, w);
}

int iso_image_set_boot_catalog_hidden(void* img, int attrs) {
    REAL(iso_image_set_boot_catalog_hidden);
    fprintf(lg(), "iso_image_set_boot_catalog_hidden(0x%x)\n", attrs);
    return real(img, attrs);
}

/* --- tree --- */
int iso_tree_add_new_node(void* img, void* parent, const char* name, const char* path, void** node) {
    REAL(iso_tree_add_new_node);
    fprintf(lg(), "iso_tree_add_new_node(name=%s, path=%s)\n", name ? name : "(null)", path ? path : "(null)");
    return real(img, parent, name, path, node);
}

int iso_tree_add_node(void* img, void* parent, const char* path, void** node) {
    REAL(iso_tree_add_node);
    fprintf(lg(), "iso_tree_add_node(path=%s)\n", path ? path : "(null)");
    return real(img, parent, path, node);
}

int iso_tree_add_new_dir(void* parent, const char* name, void** dir) {
    REAL(iso_tree_add_new_dir);
    fprintf(lg(), "iso_tree_add_new_dir(name=%s)\n", name ? name : "(null)");
    return real(parent, name, dir);
}
