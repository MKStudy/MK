TEST.ELF : test.asm
	nasm -f elf -o ./test.o ./test.asm
	nasm -f elf -o ./intcall.o ./intcall.asm
	ld -Ttext 0x0 -m elf_i386 -o ./TESTFILE test.o
	ld -Ttext 0x0 -m elf_i386 -o ./TESTCALL intcall.o
