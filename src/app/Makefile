ASM	= nasm
LD = ld
CC = gcc
CFLAGS = -c -m32 -g  -fno-builtin
TARGET = ECHO
OBJS = echo.o \
	   ../lib/start.o \
	   ../lib/exit.o \
	   ../lib/misc.o \
	   ../lib/syscall.o \
	   ../lib/string.o
	   
all:$(TARGET)

$(TARGET) : $(OBJS)
	$(LD) -Ttext 0x1400000 -m elf_i386 -o $(TARGET) $(OBJS)

echo.o : echo.c
	$(CC) $(CFLAGS) -o $@ $<