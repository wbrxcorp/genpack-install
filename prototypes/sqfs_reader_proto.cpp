// libsquashfs (sys-fs/squashfs-tools-ng) feasibility test for genpack-mkiso/mkzip
#include <sqfs/super.h>
#include <sqfs/compressor.h>
#include <sqfs/dir_reader.h>
#include <sqfs/data_reader.h>
#include <sqfs/inode.h>
#include <sqfs/io.h>
#include <sqfs/error.h>
#include <sqfs/dir.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <memory>
#include <iostream>
#include <fstream>
#include <chrono>

// TODO(production): wrap every sqfs object and inode in RAII, including cleanup
// when construction or a read operation throws; also disable copying explicitly.
struct Image {
    sqfs_file_t* file = nullptr;
    sqfs_super_t super{};
    sqfs_compressor_t* cmp = nullptr;
    sqfs_dir_reader_t* dr = nullptr;
    sqfs_data_reader_t* data = nullptr;

    explicit Image(const char* path) {
        file = sqfs_open_file(path, SQFS_FILE_OPEN_READ_ONLY);
        if (!file) throw std::runtime_error("sqfs_open_file failed");
        if (sqfs_super_read(&super, file) != 0) throw std::runtime_error("sqfs_super_read failed");

        sqfs_compressor_config_t cfg;
        sqfs_compressor_config_init(&cfg, (SQFS_COMPRESSOR)super.compression_id,
                                    super.block_size, SQFS_COMP_FLAG_UNCOMPRESS);
        int ret = sqfs_compressor_create(&cfg, &cmp);
        if (ret != 0) throw std::runtime_error("sqfs_compressor_create failed: " + std::to_string(ret));
        if (super.flags & SQFS_FLAG_COMPRESSOR_OPTIONS) {
            if (cmp->read_options(cmp, file) != 0) throw std::runtime_error("read_options failed");
        }
        dr = sqfs_dir_reader_create(&super, cmp, file, 0);
        if (!dr) throw std::runtime_error("sqfs_dir_reader_create failed");
        data = sqfs_data_reader_create(file, super.block_size, cmp, 0);
        if (!data) throw std::runtime_error("sqfs_data_reader_create failed");
        if (sqfs_data_reader_load_fragment_table(data, &super) != 0)
            throw std::runtime_error("load_fragment_table failed");
    }

    // raw lookup: no symlink resolution
    sqfs_inode_generic_t* lookup_raw(const std::string& path, int* err = nullptr) {
        sqfs_inode_generic_t* ino = nullptr;
        int ret = sqfs_dir_reader_find_by_path(dr, nullptr, path.c_str(), &ino);
        if (err) *err = ret;
        return ret == 0 ? ino : nullptr;
    }

    static std::string symlink_target(sqfs_inode_generic_t* ino) {
        if (ino->base.type != SQFS_INODE_SLINK && ino->base.type != SQFS_INODE_EXT_SLINK) return {};
        size_t sz = (ino->base.type == SQFS_INODE_SLINK) ? ino->data.slink.target_size
                                                         : ino->data.slink_ext.target_size;
        return std::string((const char*)ino->extra, sz);
    }

    // lookup with symlink resolution on every path component
    sqfs_inode_generic_t* lookup(const std::string& path, int depth = 0) {
        if (depth > 16) throw std::runtime_error("too many symlink levels: " + path);
        std::vector<std::string> comps;
        for (size_t i = 0, j; i < path.size(); i = j + 1) {
            j = path.find('/', i);
            if (j == std::string::npos) j = path.size();
            if (j > i) comps.emplace_back(path.substr(i, j - i));
        }
        std::string resolved;
        sqfs_inode_generic_t* ino = nullptr;
        for (size_t k = 0; k < comps.size(); k++) {
            std::string next = resolved.empty() ? comps[k] : resolved + "/" + comps[k];
            if (ino) sqfs_free(ino);
            ino = lookup_raw(next);
            if (!ino) return nullptr;
            if (ino->base.type == SQFS_INODE_SLINK || ino->base.type == SQFS_INODE_EXT_SLINK) {
                auto target = symlink_target(ino);
                sqfs_free(ino);
                ino = nullptr;
                std::string rest;
                for (size_t m = k + 1; m < comps.size(); m++) rest += "/" + comps[m];
                if (!target.empty() && target[0] == '/') {          // absolute -> image root
                    return lookup(target + rest, depth + 1);
                }
                // relative: resolve against the parent of the current component
                std::string parent = resolved;
                std::string t = target;
                while (t.rfind("../", 0) == 0) {
                    t = t.substr(3);
                    auto slash = parent.rfind('/');
                    parent = (slash == std::string::npos) ? "" : parent.substr(0, slash);
                }
                std::string joined = parent.empty() ? t : parent + "/" + t;
                return lookup(joined + rest, depth + 1);
            }
            resolved = next;
        }
        return ino;
    }

    void extract(const std::string& path, const std::string& dest) {
        auto ino = lookup(path);
        if (!ino) throw std::runtime_error("not found: " + path);
        sqfs_u64 size; sqfs_inode_get_file_size(ino, &size);
        std::ofstream out(dest, std::ios::binary);
        std::vector<char> buf(1 << 20);
        sqfs_u64 off = 0;
        while (off < size) {
            sqfs_s32 n = sqfs_data_reader_read(data, ino, off, buf.data(),
                                               (sqfs_u32)std::min<sqfs_u64>(buf.size(), size - off));
            if (n <= 0) throw std::runtime_error("read failed at " + std::to_string(off));
            out.write(buf.data(), n);
            off += n;
        }
        sqfs_free(ino);
    }

    std::string cat(const std::string& path) {
        auto ino = lookup(path);
        if (!ino) throw std::runtime_error("not found: " + path);
        sqfs_u64 size; sqfs_inode_get_file_size(ino, &size);
        std::string s(size, '\0');
        sqfs_u64 off = 0;
        while (off < size) {
            sqfs_s32 n = sqfs_data_reader_read(data, ino, off, s.data() + off, (sqfs_u32)(size - off));
            if (n <= 0) break;
            off += n;
        }
        sqfs_free(ino);
        return s;
    }

    std::vector<std::string> listdir(const std::string& path) {
        auto ino = lookup(path);
        if (!ino) throw std::runtime_error("not a dir / not found: " + path);
        std::vector<std::string> names;
        if (sqfs_dir_reader_open_dir(dr, ino, 0) != 0) throw std::runtime_error("open_dir failed");
        sqfs_dir_entry_t* ent = nullptr;
        while (sqfs_dir_reader_read(dr, &ent) == 0) {
            names.emplace_back((const char*)ent->name, ent->size + 1);
            sqfs_free(ent);
        }
        sqfs_free(ino);
        return names;
    }
};

int main(int argc, char** argv)
{
    if (argc < 2) { std::cerr << "usage: " << argv[0] << " <squashfs>\n"; return 1; }
    try {
        auto t0 = std::chrono::steady_clock::now();
        Image img(argv[1]);
        std::cout << "compressor: " << sqfs_compressor_name_from_id((SQFS_COMPRESSOR)img.super.compression_id)
                  << ", block_size: " << img.super.block_size
                  << ", inodes: " << img.super.inode_count << "\n";

        std::cout << "\n[1] existence checks (raw lookup)\n";
        for (auto p : {".genpack", "boot/kernel", "boot/initramfs", "boot/bootcode.bin",
                       "usr/lib/genpack-install"}) {
            int err = 0;
            auto ino = img.lookup_raw(p, &err);
            std::cout << "  " << p << " -> " << (ino ? "found" : ("MISSING (err " + std::to_string(err) + ")")) << "\n";
            if (ino) sqfs_free(ino);
        }

        std::cout << "\n[2] symlink handling\n";
        {
            int err = 0;
            auto ino = img.lookup_raw("lib/genpack-install", &err);
            std::cout << "  raw    lib/genpack-install -> " << (ino ? "found" : ("FAILED (err " + std::to_string(err) + ")")) << "\n";
            if (ino) sqfs_free(ino);
            auto ino2 = img.lookup("lib/genpack-install");
            std::cout << "  resolv lib/genpack-install -> " << (ino2 ? "found" : "FAILED") << "\n";
            if (ino2) sqfs_free(ino2);
            auto ino3 = img.lookup_raw("lib");
            if (ino3) { std::cout << "  /lib symlink target: '" << Image::symlink_target(ino3) << "'\n"; sqfs_free(ino3); }
            auto ino4 = img.lookup("sbin/init");   // sbin -> usr/bin, init may be a symlink too
            std::cout << "  resolv sbin/init -> " << (ino4 ? "found" : "not found") << "\n";
            if (ino4) sqfs_free(ino4);
        }

        std::cout << "\n[3] .genpack metadata\n";
        for (auto p : {".genpack/artifact", ".genpack/variant", ".genpack/profile"}) {
            auto ino = img.lookup(p);
            std::cout << "  " << p << ": " << (ino ? img.cat(p) : std::string("(absent)")) << "\n";
            if (ino) sqfs_free(ino);
        }

        std::cout << "\n[4] bootloader dir listing\n";
        for (auto& n : img.listdir("usr/lib/genpack-install")) std::cout << "  " << n << "\n";

        auto t1 = std::chrono::steady_clock::now();
        std::cout << "\n[5] extracting eltorito-efi.img (32MB) + grub.cfg\n";
        img.extract("usr/lib/genpack-install/eltorito-efi.img", "/tmp/claude-1000/sq-eltorito-efi.img");
        img.extract("usr/lib/genpack-install/grub.cfg", "/tmp/claude-1000/sq-grub.cfg");
        auto t2 = std::chrono::steady_clock::now();
        std::cout << "  open+meta: " << std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count()
                  << "ms, extract: " << std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count() << "ms\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << "\n";
        return 1;
    }
}
