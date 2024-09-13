PREFIX ?= /usr/local

all: genpack-install.bin

genpack-install.bin: genpack-install.cpp
	g++ -std=c++23 -o  $@ $< -lmount -lblkid

install: genpack-install.bin
	install -Dm755 genpack-install.bin $(DESTDIR)$(PREFIX)/bin/genpack-install

clean:
	rm -f *.o *.bin
