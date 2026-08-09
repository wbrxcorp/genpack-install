#include <iostream>

#include <argparse/argparse.hpp>

#include "common.hpp"
#include "iso.hpp"

int main(int argc, char** argv)
{
    const std::string progname = "genpack-mkiso";
    argparse::ArgumentParser program(progname);
    program.add_description("Create a bootable ISO9660 image out of a genpack system image. Root privileges are not needed.");
    program.add_argument("output").help("ISO9660 image file to create");
    program.add_argument("system_image").help("System image file(SquashFS)");
    program.add_argument("--label").help("Volume label of the ISO9660 image(default: GENPACK)");
    program.add_argument("--add").metavar("DEST=SRC")
        .help("Put local file SRC into the image as DEST. Can be given more than once")
        .default_value(std::vector<std::string>{}).append();
    program.add_argument("--require-clean-commit").help("Refuse a system image that doesn't record the commit ID of a clean artifact working tree").default_value(false).implicit_value(true);
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
        create_iso9660_image(program.get<std::string>("output"), program.get<std::string>("system_image"), {
            .label = program.present("--label"),
            .add_files = parse_add_options(program.get<std::vector<std::string>>("--add")),
            .require_clean_commit = program.get<bool>("--require-clean-commit")
        });
        return 0;
    }
    catch (const std::exception& ex) {
        std::cerr << ex.what() << std::endl;
    }

    return 1;
}
