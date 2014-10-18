[SECTION text]
[BITS	32]
global _start
_start:
push eax;
push gs

mov eax,27
and eax,0xFFFC
or eax,3
mov gs,eax
mov ah,0ch
mov  byte al,[_ch]
mov [gs:((80*15+75)*2)],ax

pop gs
pop eax

jmp $

[SECTION .data]
ALIGN	32
DataString:				db		"THIS IS DATA!"
_ch:                                 db       'Z'
times   1024                    db "11"
