all: genpack-install.bin

genpack-install.bin: genpack-install.cpp
	g++ -std=c++23 -o  $@ $< -lmount -lblkid

install: genpack-install.bin
	mkdir -p $(DESTDIR)/usr/bin
	cp -a genpack-install.bin $(DESTDIR)/usr/bin/genpack-install

clean:
	rm -f *.o *.bin
