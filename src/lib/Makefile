ASM	= nasm
CC = gcc
CFLAGS = -c -m32 -g  -fno-builtin
LIB=mkcrt.a
LOBJS=exit.o \
	  misc.o \
	  syscall.o \
	  string.o \
	  start.o

all:$(LIB)

$(LIB): $(LOBJS)
	ar -rv $@ $<

misc.o:misc.c
	$(CC) $(CFLAGS) -o $@ $<
syscall.o:syscall.asm
	$(ASM) -f elf -o $@ $<
string.o:string.asm
	$(ASM) -f elf -o $@ $<
exit.o : exit.c
	$(CC) $(CFLAGS) -o $@ $<
	
start.o : start.asm
	$(ASM) -f elf -o $@ $<