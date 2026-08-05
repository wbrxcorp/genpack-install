#include <sys/stat.h>
#include <sys/wait.h>

#include <unistd.h>

#include <algorithm>
#include <cstring>
#include <iostream>
#include <set>
#include <stdexcept>

#include "common.hpp"

bool debug = false;

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
        execvp(cmd.c_str(), argv);
        free(argv_buf);
        return -1;
    });
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

uintmax_t get_freespace(const std::filesystem::path& path)
{
    std::error_code ec;
    auto space_info = std::filesystem::space(path, ec);
    if (ec) {
        throw std::runtime_error("Failed to get free space of " + path.string() + ": " + ec.message());
    }
    return space_info.available;
}

bool same_file(const std::filesystem::path& a, const std::filesystem::path& b)
{
    struct stat sa, sb;
    if (stat(a.c_str(), &sa) < 0) return false;
    if (stat(b.c_str(), &sb) < 0) return false;
    return sa.st_dev == sb.st_dev && sa.st_ino == sb.st_ino;
}

std::string normalize_dest(const std::string& dest)
{
    if (dest.empty()) throw std::runtime_error("Empty destination path");
    //else
    auto normalized = std::filesystem::path(dest).lexically_normal();
    if (normalized.has_root_path()) normalized = normalized.relative_path();
    auto str = normalized.generic_string();
    while (!str.empty() && str.back() == '/') str.pop_back();
    if (str.empty() || str == ".") throw std::runtime_error("Invalid destination path: " + dest);
    if (str == ".." || str.starts_with("../")) {
        throw std::runtime_error("Destination path escapes the image root: " + dest);
    }
    return str;
}

std::vector<AddFile> parse_add_options(const std::vector<std::string>& specs)
{
    std::vector<AddFile> files;
    for (const auto& spec:specs) {
        auto delimiter = spec.find('=');
        if (delimiter == std::string::npos) {
            throw std::runtime_error("--add must be given as DEST=SRC, got --add=" + spec);
        }
        //else
        auto dest = normalize_dest(spec.substr(0, delimiter));
        std::filesystem::path src = spec.substr(delimiter + 1);
        if (src.empty()) throw std::runtime_error("--add has no source file: --add=" + spec);
        if (std::filesystem::is_directory(src)) {
            throw std::runtime_error("--add source " + src.string() + " is a directory, which is not supported");
        }
        if (!std::filesystem::is_regular_file(src)) {
            throw std::runtime_error("--add source " + src.string() + " does not exist or is not a regular file");
        }
        auto duplicate = std::find_if(files.begin(), files.end(), [&dest](const auto& f) { return f.dest == dest; });
        if (duplicate != files.end()) {
            std::cerr << "Warning: --add destination '" << dest << "' given more than once. "
                << duplicate->src.string() << " is superseded by " << src.string() << "." << std::endl;
            files.erase(duplicate);
        }
        files.push_back(AddFile { dest, std::filesystem::absolute(src) });
    }
    return files;
}

uint64_t deflate_bound(uint64_t size)
{
    return size + (size >> 12) + (size >> 14) + (size >> 25) + 13;
}

void check_dest_hierarchy(const std::vector<std::string>& dests)
{
    std::set<std::string> known(dests.begin(), dests.end());
    for (const auto& dest:dests) {
        // no proper ancestor of a destination may be a destination itself
        for (auto slash = dest.find('/'); slash != std::string::npos; slash = dest.find('/', slash + 1)) {
            auto ancestor = dest.substr(0, slash);
            if (known.contains(ancestor)) {
                throw std::runtime_error("Cannot place both " + ancestor + " and " + dest
                    + ": " + ancestor + " would have to be a file and a directory at the same time");
            }
        }
    }
}

TempDirectory::TempDirectory(const std::string& prefix)
{
    const char* tmp = getenv("TMPDIR");
    auto tmpl = (std::filesystem::path(tmp && *tmp? tmp : "/tmp") / (prefix + "XXXXXX")).string();
    std::vector<char> buf(tmpl.begin(), tmpl.end());
    buf.push_back('\0');
    if (!mkdtemp(buf.data())) {
        throw std::runtime_error(std::string("mkdtemp() failed: ") + strerror(errno));
    }
    // absolute, so that what gets extracted here can be handed to libisofs
    // whatever TMPDIR was set to
    dir = std::filesystem::absolute(buf.data());
}

TempDirectory::~TempDirectory()
{
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
    if (ec) std::cerr << "Warning: failed to remove " << dir.string() << ": " << ec.message() << std::endl;
}

TempOutputFile::TempOutputFile(const std::filesystem::path& _final_path) : final_path(_final_path)
{
    auto dir = final_path.parent_path();
    if (dir.empty()) dir = ".";
    auto tmpl = (dir / ("." + final_path.filename().string() + ".XXXXXX")).string();
    std::vector<char> buf(tmpl.begin(), tmpl.end());
    buf.push_back('\0');
    int fd = mkstemp(buf.data());
    if (fd < 0) {
        throw std::runtime_error("Cannot create a temporary file in " + dir.string() + ": " + strerror(errno));
    }
    // mkstemp() always creates the file with 0600, so apply the usual umask instead
    auto mask = umask(0);
    umask(mask);
    if (fchmod(fd, 0666 & ~mask) < 0) {
        std::cerr << "Warning: fchmod(" << buf.data() << ") failed: " << strerror(errno) << std::endl;
    }
    close(fd);
    temp_path = buf.data();
}

TempOutputFile::~TempOutputFile()
{
    if (committed) return;
    //else
    std::error_code ec;
    std::filesystem::remove(temp_path, ec);
}

void TempOutputFile::commit()
{
    if (committed) return;
    //else
    std::filesystem::rename(temp_path, final_path);
    committed = true;
}
