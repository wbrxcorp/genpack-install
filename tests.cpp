// Unit tests for the parts shared by genpack-install, genpack-mkiso and
// genpack-mkzip. Build and run with `make test`.
//
// The SystemImageReader tests need a SquashFS image to read. One is built on
// the fly with gensquashfs(1) from sys-fs/squashfs-tools-ng; the cases that
// need it are skipped when that tool is not installed.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <sys/stat.h>
#include <unistd.h>

#include <fstream>
#include <set>

#include "common.hpp"
#include "image.hpp"

namespace {

void write_file(const std::filesystem::path& path, const std::string& content)
{
    std::filesystem::create_directories(path.parent_path());
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    REQUIRE(out.good());
    out << content;
}

std::string read_whole_file(const std::filesystem::path& path)
{
    std::ifstream in(path, std::ios::binary);
    REQUIRE(in.good());
    return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

bool command_available(const std::string& cmd)
{
    return exec("sh", {"-c", cmd + " --help > /dev/null 2>&1"}) == 0;
}

} // namespace

TEST_CASE("normalize_dest turns user input into an image-relative path")
{
    CHECK(normalize_dest("system.cfg") == "system.cfg");
    CHECK(normalize_dest("/system.cfg") == "system.cfg");
    CHECK(normalize_dest("./system.cfg") == "system.cfg");
    CHECK(normalize_dest("a//b") == "a/b");
    CHECK(normalize_dest("a/./b") == "a/b");
    CHECK(normalize_dest("a/b/../c") == "a/c");
    CHECK(normalize_dest("dir/") == "dir");
    CHECK(normalize_dest("/a/./b/") == "a/b");
    // an absolute path cannot climb above the root, it just stays there
    CHECK(normalize_dest("/../x") == "x");

    CHECK_THROWS(normalize_dest(""));
    CHECK_THROWS(normalize_dest("/"));
    CHECK_THROWS(normalize_dest("."));
    CHECK_THROWS(normalize_dest(".."));
    CHECK_THROWS(normalize_dest("../evil"));
    CHECK_THROWS(normalize_dest("a/../.."));
    CHECK_THROWS(normalize_dest("a/b/../.."));
}

TEST_CASE("parse_add_options")
{
    TempDirectory tempdir("genpack-test-");
    auto src = tempdir / "source.txt";
    write_file(src, "content");
    auto weird = tempdir / "name=with=equals.txt";
    write_file(weird, "content");

    SUBCASE("splits at the first '=' so the source may contain more of them") {
        auto files = parse_add_options({"system.cfg=" + weird.string()});
        REQUIRE(files.size() == 1);
        CHECK(files[0].dest == "system.cfg");
        CHECK(files[0].src == weird);
    }

    SUBCASE("normalizes the destination and keeps the given order") {
        auto files = parse_add_options({"/a/b.txt=" + src.string(), "./c.txt=" + src.string()});
        REQUIRE(files.size() == 2);
        CHECK(files[0].dest == "a/b.txt");
        CHECK(files[1].dest == "c.txt");
    }

    SUBCASE("the last of several specifications for one destination wins") {
        auto files = parse_add_options({"system.cfg=" + src.string(), "./system.cfg=" + weird.string()});
        REQUIRE(files.size() == 1);
        CHECK(files[0].dest == "system.cfg");
        CHECK(files[0].src == weird);
    }

    SUBCASE("rejects malformed specifications") {
        CHECK_THROWS(parse_add_options({"system.cfg"}));            // no '=' at all
        CHECK_THROWS(parse_add_options({"=" + src.string()}));      // empty destination
        CHECK_THROWS(parse_add_options({"system.cfg="}));           // empty source
        CHECK_THROWS(parse_add_options({"../x=" + src.string()}));  // escapes the root
    }

    SUBCASE("rejects sources that are not readable regular files") {
        CHECK_THROWS(parse_add_options({"x=" + (tempdir / "missing").string()}));
        CHECK_THROWS(parse_add_options({"x=" + tempdir.path().string()}));   // a directory
    }

    SUBCASE("makes the source absolute, because libisofs rejects relative paths") {
        auto previous = std::filesystem::current_path();
        std::filesystem::current_path(tempdir.path());
        auto files = parse_add_options({"x=source.txt"});
        std::filesystem::current_path(previous);
        REQUIRE(files.size() == 1);
        CHECK(files[0].src.is_absolute());
        CHECK(same_file(files[0].src, src));
    }
}

TEST_CASE("deflate_bound stays in 64bit where zlib's compressBound would not")
{
    // same values zlib's compressBound() produces, but never truncated: its
    // uLong is 32bit on ILP32 targets
    CHECK(deflate_bound(0) == 13);
    CHECK(deflate_bound(1) == 14);
    CHECK(deflate_bound(4096) == 4110);
    CHECK(deflate_bound(1024ULL * 1024 * 1024) == 1074069549);

    // an entry of exactly 4GiB truncates to a bound of 13 bytes in 32bit
    CHECK(deflate_bound(4ULL * 1024 * 1024 * 1024) == 4296278157ULL);
    CHECK(deflate_bound(4ULL * 1024 * 1024 * 1024) > 4ULL * 1024 * 1024 * 1024);
    // and the bound never comes out below its input
    for (uint64_t size : {0ULL, 1ULL, 65535ULL, 1ULL << 32, 1ULL << 40}) {
        CHECK(deflate_bound(size) >= size);
    }
}

TEST_CASE("check_dest_hierarchy rejects a name used as both file and directory")
{
    CHECK_NOTHROW(check_dest_hierarchy({}));
    CHECK_NOTHROW(check_dest_hierarchy({"system.img", "boot/grub/grub.cfg", "boot/grub/i386-pc/boot.cat"}));
    CHECK_NOTHROW(check_dest_hierarchy({"a/b", "a/c", "ab"}));   // a shared prefix is not a conflict

    CHECK_THROWS(check_dest_hierarchy({"system.img", "system.img/child"}));
    CHECK_THROWS(check_dest_hierarchy({"system.img/child", "system.img"}));   // either order
    CHECK_THROWS(check_dest_hierarchy({"a/b/c", "a"}));                       // not just the direct parent
    CHECK_THROWS(check_dest_hierarchy({"boot/grub/grub.cfg", "boot/grub"}));
}

TEST_CASE("same_file sees through symlinks and hard links")
{
    TempDirectory tempdir("genpack-test-");
    auto original = tempdir / "original";
    auto other = tempdir / "other";
    write_file(original, "a");
    write_file(other, "a");   // same content, different file
    std::filesystem::create_symlink(original, tempdir / "symlink");
    std::filesystem::create_hard_link(original, tempdir / "hardlink");

    CHECK(same_file(original, original));
    CHECK(same_file(original, tempdir / "symlink"));
    CHECK(same_file(original, tempdir / "hardlink"));
    CHECK(same_file(tempdir / "symlink", tempdir / "hardlink"));

    CHECK_FALSE(same_file(original, other));
    CHECK_FALSE(same_file(original, tempdir / "missing"));
    CHECK_FALSE(same_file(tempdir / "missing", tempdir / "missing"));
}

TEST_CASE("size_str")
{
    CHECK(size_str(0) == "0.0GiB");
    CHECK(size_str(1024ULL * 1024 * 1024) == "1.0GiB");
    CHECK(size_str(1536ULL * 1024 * 1024) == "1.5GiB");
    CHECK(size_str(1024ULL * 1024 * 1024 * 1024) == "1.0TiB");
    CHECK(size_str(2048ULL * 1024 * 1024 * 1024) == "2.0TiB");
}

TEST_CASE("fork and exec")
{
    CHECK(fork([]() { return 0; }) == 0);
    CHECK(fork([]() { return 42; }) == 42);
    CHECK(exec("true", {}) == 0);
    CHECK(exec("false", {}) != 0);
    CHECK(exec("no-such-command-hopefully", {}) != 0);
    CHECK(exec("sh", {"-c", "exit 3"}) == 3);
}

TEST_CASE("TempDirectory")
{
    std::filesystem::path remembered;
    {
        TempDirectory tempdir("genpack-test-");
        remembered = tempdir.path();
        CHECK(std::filesystem::is_directory(remembered));
        // it takes its contents with it, not just the empty directory
        write_file(tempdir / "sub/file.txt", "x");
        CHECK((tempdir / "sub/file.txt") == remembered / "sub/file.txt");
    }
    CHECK_FALSE(std::filesystem::exists(remembered));
}

TEST_CASE("TempOutputFile")
{
    TempDirectory tempdir("genpack-test-");
    auto destination = tempdir / "output.iso";

    SUBCASE("builds the file next to its destination under another name") {
        TempOutputFile output(destination);
        CHECK(output.path().parent_path() == tempdir.path());
        CHECK(output.path() != destination);
        CHECK(std::filesystem::exists(output.path()));
        CHECK_FALSE(std::filesystem::exists(destination));
    }

    SUBCASE("without commit the temporary file goes away") {
        std::filesystem::path temp_path;
        {
            TempOutputFile output(destination);
            temp_path = output.path();
            write_file(temp_path, "half written");
        }
        CHECK_FALSE(std::filesystem::exists(temp_path));
        CHECK_FALSE(std::filesystem::exists(destination));
    }

    SUBCASE("an existing destination survives a run that never commits") {
        write_file(destination, "previous contents");
        {
            TempOutputFile output(destination);
            write_file(output.path(), "half written");
        }
        CHECK(read_whole_file(destination) == "previous contents");
    }

    SUBCASE("commit moves the file into place") {
        std::filesystem::path temp_path;
        {
            TempOutputFile output(destination);
            temp_path = output.path();
            write_file(temp_path, "finished");
            output.commit();
        }
        CHECK_FALSE(std::filesystem::exists(temp_path));
        CHECK(read_whole_file(destination) == "finished");
    }

    SUBCASE("commit replaces an existing destination") {
        write_file(destination, "previous contents");
        {
            TempOutputFile output(destination);
            write_file(output.path(), "finished");
            output.commit();
        }
        CHECK(read_whole_file(destination) == "finished");
    }

    SUBCASE("the file is not left readable only by its owner") {
        // mkstemp() creates with 0600; the usual umask should have been applied
        TempOutputFile output(destination);
        struct stat st;
        REQUIRE(stat(output.path().c_str(), &st) == 0);
        auto mask = umask(0);
        umask(mask);
        CHECK((st.st_mode & 07777) == (0666 & ~mask));
    }
}

// --- SystemImageReader --------------------------------------------------
//
// Builds a small SquashFS resembling a genpack system image, including the
// /lib -> usr/lib symlink that makes plain path lookups fail.

namespace {

struct ImageFixture {
    TempDirectory tempdir{"genpack-test-"};
    std::filesystem::path image;

    explicit ImageFixture(bool with_genpack_dir = true, bool with_bootloader = true) {
        auto root = tempdir / "root";
        if (with_genpack_dir) {
            write_file(root / ".genpack/artifact", "myartifact\n");
            write_file(root / ".genpack/variant", "myvariant\n");
        }
        write_file(root / "boot/kernel", "kernel");
        write_file(root / "boot/initramfs", "initramfs");
        write_file(root / "boot/overlays/some.dtbo", "dtbo");
        if (with_bootloader) {
            write_file(root / "usr/lib/genpack-install/grub.cfg", "# grub config\n");
            write_file(root / "usr/lib/genpack-install/bootx64.efi", std::string(1000, 'E'));
        }
        std::filesystem::create_symlink("usr/lib", root / "lib");
        std::filesystem::create_symlink("kernel", root / "boot/kernel-link");

        image = tempdir / "test.squashfs";
        REQUIRE(exec("gensquashfs", {"-q", "-f", "-c", "gzip", "-D", root.string(), image.string()}) == 0);
    }
};

} // namespace

TEST_CASE("SystemImageReader")
{
    if (!command_available("gensquashfs")) {
        MESSAGE("gensquashfs not found, skipping the SystemImageReader tests");
        return;
    }
    ImageFixture fixture;
    SystemImageReader image(fixture.image);

    SUBCASE("reports what the image holds") {
        CHECK(image.image_path() == fixture.image);
        CHECK(image.exists(".genpack"));
        CHECK(image.is_directory(".genpack"));
        CHECK_FALSE(image.is_regular_file(".genpack"));
        CHECK(image.is_regular_file("boot/kernel"));
        CHECK_FALSE(image.is_directory("boot/kernel"));
        CHECK_FALSE(image.exists("boot/bootcode.bin"));
        CHECK_FALSE(image.exists("no/such/path"));
    }

    SUBCASE("resolves symlinks on every path component") {
        // sqfs_dir_reader_find_by_path() alone would fail on both of these
        CHECK(image.is_directory("lib/genpack-install"));
        CHECK(image.is_regular_file("lib/genpack-install/grub.cfg"));
        CHECK(image.is_regular_file("boot/kernel-link"));
        CHECK(image.read_file("boot/kernel-link") == "kernel");
    }

    SUBCASE("reads file contents and sizes") {
        CHECK(image.read_file(".genpack/artifact") == "myartifact\n");
        CHECK(image.read_file("usr/lib/genpack-install/bootx64.efi") == std::string(1000, 'E'));
        CHECK(image.file_size("boot/kernel") == 6);
        CHECK(image.file_size("no/such/path") == std::nullopt);
        CHECK(image.file_size(".genpack") == std::nullopt);   // not a regular file
        CHECK(image.file_mtime("boot/kernel").has_value());
        CHECK_THROWS(image.read_file("no/such/path"));
        CHECK_THROWS(image.read_file(".genpack"));            // not a regular file
    }

    SUBCASE("extracts to the local filesystem, creating parent directories") {
        auto destination = fixture.tempdir / "out/nested/bootx64.efi";
        image.extract("usr/lib/genpack-install/bootx64.efi", destination);
        CHECK(read_whole_file(destination) == std::string(1000, 'E'));
    }

    SUBCASE("lists directories") {
        std::set<std::string> names;
        for (const auto& entry:image.list_directory("boot")) names.insert(entry.name);
        CHECK(names == std::set<std::string>{"kernel", "initramfs", "overlays", "kernel-link"});

        for (const auto& entry:image.list_directory("boot")) {
            if (entry.name == "overlays") CHECK(entry.is_directory);
            if (entry.name == "kernel") CHECK(entry.is_regular_file);
            if (entry.name == "kernel-link") CHECK(entry.is_symlink);
        }
        CHECK_THROWS(image.list_directory("boot/kernel"));    // not a directory
        CHECK_THROWS(image.list_directory("no/such/path"));
    }

    SUBCASE("walks regular files recursively, relative to the starting point") {
        std::set<std::string> found;
        image.walk_regular_files("boot", [&found](const std::string& relative) { found.insert(relative); });
        CHECK(found == std::set<std::string>{"kernel", "initramfs", "kernel-link", "overlays/some.dtbo"});
    }
}

TEST_CASE("check_system_image")
{
    if (!command_available("gensquashfs")) {
        MESSAGE("gensquashfs not found, skipping the check_system_image tests");
        return;
    }
    SUBCASE("accepts an image carrying .genpack, a kernel and an initramfs") {
        ImageFixture fixture;
        SystemImageReader image(fixture.image);
        CHECK_NOTHROW(check_system_image(image));
    }
    SUBCASE("rejects an image without .genpack") {
        ImageFixture fixture(false);
        SystemImageReader image(fixture.image);
        CHECK_THROWS(check_system_image(image));
    }
}

TEST_CASE("BootloaderFiles")
{
    if (!command_available("gensquashfs")) {
        MESSAGE("gensquashfs not found, skipping the BootloaderFiles tests");
        return;
    }
    ImageFixture fixture;
    SystemImageReader image(fixture.image);
    auto bootloader = BootloaderFiles::locate(image);
    REQUIRE(bootloader.has_value());

    SUBCASE("prefers the files carried by the system image") {
        CHECK(bootloader->origin() == fixture.image.string() + ":/usr/lib/genpack-install");
        CHECK(bootloader->contains("grub.cfg"));
        CHECK_FALSE(bootloader->contains("eltorito-bios.img"));
        CHECK(bootloader->list() == std::vector<std::string>{"bootx64.efi", "grub.cfg"});
    }

    SUBCASE("copies a file out of the image") {
        auto destination = fixture.tempdir / "copied/grub.cfg";
        bootloader->copy_to("grub.cfg", destination);
        CHECK(read_whole_file(destination) == "# grub config\n");
    }

    SUBCASE("materializes a file into the given directory for libisofs") {
        TempDirectory workdir("genpack-test-");
        auto path = bootloader->materialize("grub.cfg", workdir.path());
        CHECK(path == workdir / "grub.cfg");
        CHECK(read_whole_file(path) == "# grub config\n");
    }
}
