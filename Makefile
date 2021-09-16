.PHONY: rar

AS=nasm
HASH=sha256sum
QEMU=qemu-system-x86_64
UNRAR=unrar
GRUBFILE=grub-file
C64=x64
XXD=xxd
FILENAME=janus

all:
	@mkdir -p bin
	$(AS) -f bin -o bin/$(FILENAME).com src/$(FILENAME).asm
	$(HASH) bin/$(FILENAME).com > bin/sums.txt
	$(XXD) bin/$(FILENAME).com > bin/xxd.txt

qemu:
	$(QEMU) bin/$(FILENAME).com & disown

elf:
	@chmod +x bin/$(FILENAME).com
	-bin/$(FILENAME).com

zip:
	unzip -p bin/$(FILENAME).com

com:
	dosbox bin/$(FILENAME).com

rar:
	$(UNRAR) p -idq bin/$(FILENAME).com

grub-file:
	$(GRUBFILE) --is-x86-multiboot2 bin/$(FILENAME).com

c64:
	$(C64) -basicload bin/$(FILENAME).com
