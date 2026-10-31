NASM    := nasm
NASMFL  := -f elf64 -g -F dwarf -I include/ -w+all
LD      := ld

COMMON := src/tables.o src/util.o src/sha256.o src/chacha20.o src/crc32c.o \
          src/kdf.o src/methods.o src/image.o src/btree.o src/fs.o

.PHONY: all test clean

all: nmglfdfs-selftest mkfs.nmglfdfs nmglfdfs nmglfdfs-ctl

nmglfdfs-selftest: $(COMMON) src/fs_selftest.o src/main_selftest.o
	$(LD) -o $@ $^

mkfs.nmglfdfs: $(COMMON) src/main_mkfs.o
	$(LD) -o $@ $^

nmglfdfs: $(COMMON) src/fuse.o src/main_mount.o
	$(LD) -o $@ $^

nmglfdfs-ctl: $(COMMON) src/main_ctl.o
	$(LD) -o $@ $^

src/%.o: src/%.asm
	$(NASM) $(NASMFL) -o $@ $<

test: all
	sh tests/run_tests.sh

clean:
	rm -f src/*.o nmglfdfs-selftest mkfs.nmglfdfs nmglfdfs nmglfdfs-ctl
