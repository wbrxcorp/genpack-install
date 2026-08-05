# genpack-install

Deployment tools for genpack system images (SquashFS).

| Command | Purpose | Root |
|---|---|---|
| `genpack-install` | Install to a physical disk, update the running system in place | required |
| `genpack-mkiso` | Build a bootable ISO9660 image | not needed |
| `genpack-mkzip` | Pack the system image and its boot files into a ZIP archive | not needed |

`genpack-mkiso` and `genpack-mkzip` read the system image through libsquashfs,
so they need neither a loopback mount nor any external command.

```sh
genpack-install --disk=/dev/sdX [--label=NAME] [system image]
genpack-install <system image>                     # self-update
genpack-mkiso [--label=NAME] [--add=DEST=SRC]... <out.iso> <system image>
genpack-mkzip [--add=DEST=SRC]... <out.zip> <system image>
```

See [docs/cli-install.md](https://github.com/wbrxcorp/genpack/blob/main/docs/cli-install.md)
in the genpack repository for the full reference.

## Building

```sh
make                 # all three tools plus the bootloader files
make TOOLS="install" # only genpack-install
make test            # unit tests
```

`TOOLS` selects which tools to build and install, and mirrors the ebuild's
`install` / `iso` / `zip` USE flags.

### Build time

- [argparse](https://github.com/p-ranav/argparse)
- libsquashfs (`sys-fs/squashfs-tools-ng`)
- libisofs (`dev-libs/libisofs`) — for `genpack-mkiso`
- minizip (`sys-libs/zlib[minizip]`) — for `genpack-mkzip`
- libmount, libblkid (`sys-apps/util-linux`) — for `genpack-install`
- pkg-config
- grub, dosfstools, mtools — to generate the bootloader files
- doctest (`dev-cpp/doctest`) — for `make test` only

### Runtime

`genpack-mkiso` and `genpack-mkzip` start no external commands.
`genpack-install` needs:

- parted
- dosfstools, btrfs-progs
- mtools
- grub (`grub-bios-setup`)
- unzip — for `--additional-boot-files`
