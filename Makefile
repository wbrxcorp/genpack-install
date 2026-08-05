PREFIX ?= /usr/local

# Which of the three tools to build and install. Mirrors the ebuild's
# install/iso/zip USE flags, so an artifact that never generates ISO or ZIP
# images does not have to carry libisofs or minizip.
TOOLS ?= install iso zip

CXXFLAGS ?= -std=c++23 -O2

# Deferred on purpose: pkg-config is only run for the libraries the selected
# TOOLS actually need.
ISOFS_CFLAGS = $(shell pkg-config --cflags libisofs-1)
ISOFS_LIBS = $(shell pkg-config --libs libisofs-1)
SQFS_CFLAGS = $(shell pkg-config --cflags libsquashfs1)
SQFS_LIBS = $(shell pkg-config --libs libsquashfs1)

MODULES := part_msdos part_gpt fat
EMBED_MODULES := $(MODULES) normal regexp loopback xfs btrfs exfat ntfscomp ext2 iso9660 lvm squash4 \
       msdospart blocklist configfile linux chain echo test probe search minicmd sleep \
       all_video videotest serial png gfxterm_background videoinfo keystatus

ifeq ($(shell test -d /usr/lib/grub/x86_64-efi && echo yes),yes)
	EFI_TARGETS += bootx64.efi
endif

ifeq ($(shell test -d /usr/lib/grub/i386-efi && echo yes),yes)
	EFI_TARGETS += bootia32.efi
endif

ifeq ($(shell test -d /usr/lib/grub/i386-pc && echo yes),yes)
	BOOTLOADER_TARGETS += core.img boot.img eltorito-bios.img
endif

ifeq ($(shell test -d /usr/lib/grub/arm64-efi && echo yes),yes)
	EFI_TARGETS += bootaa64.efi
endif

ifeq ($(shell test -d /usr/lib/grub/riscv64-efi && echo yes),yes)
	EFI_TARGETS += bootriscv64.efi
endif

# add eltorito-efi.img if any EFI targets are built
ifneq ($(EFI_TARGETS),)
	BOOTLOADER_TARGETS += eltorito-efi.img
endif

BOOTLOADER_TARGETS += $(EFI_TARGETS)

COMMON_OBJS := common.o
IMAGE_OBJS := image.o

TOOL_TARGETS :=
ifneq ($(filter install,$(TOOLS)),)
	TOOL_TARGETS += genpack-install.bin
endif
ifneq ($(filter iso,$(TOOLS)),)
	TOOL_TARGETS += genpack-mkiso.bin
endif
ifneq ($(filter zip,$(TOOLS)),)
	TOOL_TARGETS += genpack-mkzip.bin
endif

TARGETS := $(TOOL_TARGETS) $(BOOTLOADER_TARGETS)

.PHONY: all test install clean

all: $(TARGETS)

%.o: %.cpp
	g++ $(CXXFLAGS) -c -o $@ $<

genpack-install.bin: genpack-install.o $(IMAGE_OBJS) $(COMMON_OBJS)
	g++ -o $@ $^ -lmount -lblkid $(SQFS_LIBS)

genpack-mkiso.bin: genpack-mkiso.o iso.o $(IMAGE_OBJS) $(COMMON_OBJS)
	g++ -o $@ $^ $(ISOFS_LIBS) $(SQFS_LIBS)

genpack-mkzip.bin: genpack-mkzip.o zip.o $(IMAGE_OBJS) $(COMMON_OBJS)
	g++ -o $@ $^ -lminizip $(SQFS_LIBS)

image.o iso.o zip.o genpack-install.o: CXXFLAGS += $(SQFS_CFLAGS)
iso.o: CXXFLAGS += $(ISOFS_CFLAGS)

# Unit tests for the shared code. Not part of `all`, not installed.
tests.bin: tests.o $(IMAGE_OBJS) $(COMMON_OBJS)
	g++ -o $@ $^ $(SQFS_LIBS)

tests.o: CXXFLAGS += $(SQFS_CFLAGS)

test: tests.bin
	./tests.bin

common.o: common.cpp common.hpp
image.o: image.cpp image.hpp
tests.o: tests.cpp common.hpp image.hpp
iso.o: iso.cpp iso.hpp image.hpp common.hpp
zip.o: zip.cpp zip.hpp image.hpp common.hpp
genpack-install.o: genpack-install.cpp image.hpp common.hpp
genpack-mkiso.o: genpack-mkiso.cpp iso.hpp common.hpp
genpack-mkzip.o: genpack-mkzip.cpp zip.hpp common.hpp

bootx64.efi: grub.cfg
	grub-mkstandalone -O x86_64-efi -o $@ --compress=xz --modules="$(MODULES)" "boot/grub/grub.cfg=grub.cfg"

bootia32.efi: grub.cfg
	grub-mkstandalone -O i386-efi -o $@ --compress=xz --modules="$(MODULES)" "boot/grub/grub.cfg=grub.cfg"

bootaa64.efi: grub.cfg
	grub-mkstandalone -O arm64-efi -o $@ --compress=xz --modules="$(MODULES)" "boot/grub/grub.cfg=grub.cfg"

bootriscv64.efi: grub.cfg
	grub-mkstandalone -O riscv64-efi -o $@ --compress=xz --modules="$(MODULES)" "boot/grub/grub.cfg=grub.cfg"

boot.img:
	cp /usr/lib/grub/i386-pc/boot.img .

core.img: boot.img
	grub-mkimage -O i386-pc -o $@ -p '(,msdos1)/boot/grub' biosdisk $(EMBED_MODULES)

eltorito-bios.img:
	grub-mkimage -O i386-pc-eltorito -o $@ -p /boot/grub biosdisk $(EMBED_MODULES)

eltorito-efi.img: $(EFI_TARGETS)
	dd if=/dev/zero of=$@ bs=1M count=31
	mkfs.vfat -F12 $@
	mmd -i $@ ::/EFI ::/EFI/BOOT
	mcopy -i $@ $(EFI_TARGETS) ::/EFI/BOOT/

install: $(TARGETS)
	mkdir -p $(DESTDIR)$(PREFIX)/lib/genpack-install/
	install -m 644 $(BOOTLOADER_TARGETS) grub.cfg $(DESTDIR)$(PREFIX)/lib/genpack-install/
ifneq ($(filter install,$(TOOLS)),)
	install -D -m 755 genpack-install.bin $(DESTDIR)$(PREFIX)/bin/genpack-install
endif
ifneq ($(filter iso,$(TOOLS)),)
	install -D -m 755 genpack-mkiso.bin $(DESTDIR)$(PREFIX)/bin/genpack-mkiso
endif
ifneq ($(filter zip,$(TOOLS)),)
	install -D -m 755 genpack-mkzip.bin $(DESTDIR)$(PREFIX)/bin/genpack-mkzip
endif

# Named explicitly rather than globbed: *.img and *.efi would also take out
# unrelated files people keep in a working copy, such as a scratch disk image.
clean:
	rm -f *.o genpack-install.bin genpack-mkiso.bin genpack-mkzip.bin tests.bin \
	    boot.img core.img eltorito-bios.img eltorito-efi.img \
	    bootx64.efi bootia32.efi bootaa64.efi bootriscv64.efi
