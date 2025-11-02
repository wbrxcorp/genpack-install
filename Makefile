PREFIX ?= /usr/local

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
TARGETS := genpack-install.bin $(BOOTLOADER_TARGETS)

all: $(TARGETS)

genpack-install.bin: genpack-install.cpp
	g++ -std=c++23 -o  $@ $< -lmount -lblkid -lminizip

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
	install -D -m 755 genpack-install.bin $(DESTDIR)$(PREFIX)/bin/genpack-install

clean:
	rm -f *.o *.bin *.efi *.img
