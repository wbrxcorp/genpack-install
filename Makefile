PREFIX ?= /usr/local

all: genpack-install.bin

genpack-install.bin: genpack-install.cpp
	g++ -std=c++23 -o  $@ $< -lmount -lblkid

install: genpack-install.bin
	install -m 755 genpack-install.bin $(PREFIX)/bin/genpack-install

clean:
	rm -f *.o *.bin
