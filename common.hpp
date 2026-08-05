#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <vector>

extern bool debug;

int fork(std::function<int()> func);
int exec(const std::string& cmd, const std::vector<std::string>& args);

std::string size_str(uint64_t size);
uintmax_t get_freespace(const std::filesystem::path& path);

// True when both paths end up at the very same file, no matter how many
// symlinks or hard links lead there. False when either of them doesn't exist.
bool same_file(const std::filesystem::path& a, const std::filesystem::path& b);

// A file placed into the generated image by --add=DEST=SRC
struct AddFile {
    std::string dest;           // path inside the image, normalized and relative to its root
    std::filesystem::path src;  // local regular file to read the content from, as an absolute path
};

// Turns a user-supplied destination into a normalized image-relative path.
// Throws when the result would be empty or would escape the image root.
std::string normalize_dest(const std::string& dest);

// Parses --add=DEST=SRC specifications. DEST is split off at the first '='
// because a local SRC path may well contain one. Later specifications win over
// earlier ones targeting the same destination, with a warning. SRC is made
// absolute, since libisofs only accepts absolute paths.
std::vector<AddFile> parse_add_options(const std::vector<std::string>& specs);

// Rejects a set of destinations in which one is a directory prefix of another,
// e.g. "system.img" together with "system.img/child". No filesystem can hold
// both, and which of the two to drop is not ours to guess.
void check_dest_hierarchy(const std::vector<std::string>& dests);

// Largest output deflate can produce for an input of the given size. Same
// formula as zlib's compressBound(), but computed in 64bit: zlib takes and
// returns uLong, which is 32bit on ILP32 targets, where an entry of 4GiB would
// wrap around to a bound of 13 bytes.
uint64_t deflate_bound(uint64_t size);

// A directory removed along with its contents when it goes out of scope.
class TempDirectory {
    std::filesystem::path dir;
public:
    TempDirectory(const TempDirectory&) = delete;
    TempDirectory& operator=(const TempDirectory&) = delete;
    explicit TempDirectory(const std::string& prefix = "genpack-install-");
    ~TempDirectory();
    const std::filesystem::path& path() const { return dir; }
    std::filesystem::path operator/(const std::filesystem::path& other) const { return dir / other; }
};

// An output file built under a temporary name next to its destination and moved
// into place by commit() only once it is complete. Without commit() the
// temporary file is removed and the destination is left untouched.
class TempOutputFile {
    std::filesystem::path final_path;
    std::filesystem::path temp_path;
    bool committed = false;
public:
    TempOutputFile(const TempOutputFile&) = delete;
    TempOutputFile& operator=(const TempOutputFile&) = delete;
    explicit TempOutputFile(const std::filesystem::path& final_path);
    ~TempOutputFile();
    const std::filesystem::path& path() const { return temp_path; }
    void commit();
};
