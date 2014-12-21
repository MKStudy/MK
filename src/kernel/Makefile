ASM							= nasm
CC								= gcc
LD								= ld

OBJS=kernelex.o start.o global.o kliba.o stringAsm.o protect.o i8259.o klib.o main.o clock.o syscall.o proc.o \
	keyboard.o tty.o printf.o misc.o console.o systask.o vsprintf.o hd.o fs.o mm.o string.o

all : kernelex.elf

kernelex.elf : $(OBJS)
	$(LD) -Ttext 0xA00000  -m elf_i386 -o ./kernelex.elf $(OBJS)

string.o : ./string.c
	$(CC) -fno-stack-protector -c -m32 -g  -fno-builtin -o $@ $<

hd.o : ../hd/hd.c
	$(CC) -fno-stack-protector -c -m32 -g  -fno-builtin -o $@ $<

fs.o : ../fs/fs.c
	$(CC) -fno-stack-protector -c -m32 -g  -fno-builtin -o $@ $<

mm.o : ../mm/mm.c
	$(CC) -fno-stack-protector -c -m32 -g  -fno-builtin -o $@ $<

vsprintf.o : ./vsprintf.c
	$(CC) -fno-stack-protector -c -m32 -g  -fno-builtin -o ./vsprintf.o ./vsprintf.c

systask.o : ./systask.c
	$(CC) -c -m32 -g  -fno-builtin -o ./systask.o ./systask.c

console.o : ./console.c
	$(CC) -c -m32 -g  -fno-builtin -o ./console.o ./console.c

misc.o : ./misc.c
	$(CC) -c -m32 -g  -fno-builtin -o ./misc.o ./misc.c

printf.o : ./printf.c
	$(CC) -c -m32 -g  -fno-stack-protector -fno-builtin -o ./printf.o ./printf.c

tty.o : ./tty.c
	$(CC) -c -m32 -g -fno-stack-protector  -fno-builtin -o ./tty.o ./tty.c

keyboard.o : ./keyboard.c
	$(CC) -c -fno-stack-protector  -m32 -g  -fno-builtin -o ./keyboard.o ./keyboard.c

proc.o : ./proc.c
	$(CC) -c -m32 -g  -fno-stack-protector -fno-builtin -o ./proc.o ./proc.c

syscall.o : ./syscall.asm
	$(ASM) -f elf -o ./syscall.o ./syscall.asm

clock.o : ./clock.c
	$(CC) -c -m32 -g  -fno-builtin -o ./clock.o ./clock.c

main.o : ./main.c
	$(CC) -fno-stack-protector -c -m32 -g  -fno-builtin -o ./main.o ./main.c

kernelex.o : ./kernelex.asm
	$(ASM) -f elf -o ./kernelex.o ./kernelex.asm

start.o : ./start.c
	$(CC) -c -m32 -g -fno-builtin -o ./start.o ./start.c

global.o : ./global.c
	$(CC) -c -m32 -g -fno-builtin -o ./global.o ./global.c

kliba.o : ./kliba.asm
	$(ASM) -f elf -o ./kliba.o ./kliba.asm

stringAsm.o : ./string.asm
	$(ASM) -f elf -o ./stringAsm.o ./string.asm

protect.o : ./protect.c
	$(CC) -c -m32 -g -o ./protect.o ./protect.c

i8259.o : ./i8259.c
	$(CC) -c -m32 -g -fno-builtin -o ./i8259.o ./i8259.c

klib.o : ./klib.c
	$(CC) -fno-stack-protector -fno-builtin -c -m32 -g -o ./klib.o ./klib.c
