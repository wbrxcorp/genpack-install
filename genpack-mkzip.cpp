#include <iostream>

#include <argparse/argparse.hpp>

#include "common.hpp"
#include "zip.hpp"

int main(int argc, char** argv)
{
    const std::string progname = "genpack-mkzip";
    argparse::ArgumentParser program(progname);
    program.add_description("Pack a genpack system image and its boot files into a ZIP archive. Root privileges are not needed.");
    program.add_argument("output").help("ZIP archive file to create");
    program.add_argument("system_image").help("System image file(SquashFS)");
    program.add_argument("--add").metavar("DEST=SRC")
        .help("Put local file SRC into the archive as DEST. Can be given more than once")
        .default_value(std::vector<std::string>{}).append();
    program.add_argument("--debug").help("Show debug messages").default_value(false).implicit_value(true);

    try {
        program.parse_args(argc, argv);
    }
    catch (const std::exception& ex) {
        std::cerr << ex.what() << std::endl;
        std::cout << program << std::endl;
        return 1;
    }

    debug = program.get<bool>("--debug");

    try {
        create_zip_archive(program.get<std::string>("output"), program.get<std::string>("system_image"), {
            .add_files = parse_add_options(program.get<std::vector<std::string>>("--add"))
        });
        return 0;
    }
    catch (const std::exception& ex) {
        std::cerr << ex.what() << std::endl;
    }

    return 1;
}
