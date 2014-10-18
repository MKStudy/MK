
/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
                            start.c
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
                                                    Forrest Yu, 2005
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

#include "../include/type.h"
#include "../include/const.h"
#include "../include/protect.h"
#include "../include/string.h"
#include "../include/proc.h"
#include "../include/tty.h"
#include "../include/console.h"
#include "../include/global.h"
#include "../include/proto.h"

typedef struct Color{
    unsigned char red;
    unsigned char green;
    unsigned char blue;
}Color;

void drawRect(int x1, int y1, int x2, int y2, Color color) ;
void writeVRAM(int , int, int , int);
void initGui();

void drawRect(int x1, int y1, int x2, int y2, Color color) {
/*
	int i;
	for(i = 0xa0000; i <= 0xaffff; i++)
	{
		writeVRAM(i, i &0xF);
	}
	return;
	*/
   if (x2>x1 && y2>y1) {
     int x=0,y=0;
     for (y=y1;y<y2;++y) {
       for (x=x1;x<x2;++x) {
        //disp_str("Bfore writeRAM\n");
        writeVRAM((y*800+x)*3, color.blue, color.green, color.red);
       }
     }
   }
}

/*======================================================================*
                            cstart
 *======================================================================*/
PUBLIC void cstart()
{
	//Color startColor = {240,240,240};
    //Color endColor = {160,160,160};

    //initGui();
    //drawRect(0,0, 10, 10, endColor);
	disp_str("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n-----\"cstart\" begins-----\n");

	/* 将 LOADER 中的 GDT 复制到新的 GDT 中 */
	memcpy(	&gdt,				   /* New GDT */
		(void*)(*((u32*)(&gdt_ptr[2]))),   /* Base  of Old GDT */
		*((u16*)(&gdt_ptr[0])) + 1	   /* Limit of Old GDT */
		);
	/* gdt_ptr[6] 共 6 个字节：0~15:Limit  16~47:Base。用作 sgdt 以及 lgdt 的参数。 */
	u16* p_gdt_limit = (u16*)(&gdt_ptr[0]);
	u32* p_gdt_base  = (u32*)(&gdt_ptr[2]);
	*p_gdt_limit = GDT_SIZE * sizeof(struct descriptor) - 1;
	*p_gdt_base  = (u32)&gdt;

	/* idt_ptr[6] 共 6 个字节：0~15:Limit  16~47:Base。用作 sidt 以及 lidt 的参数。 */
	u16* p_idt_limit = (u16*)(&idt_ptr[0]);
	u32* p_idt_base  = (u32*)(&idt_ptr[2]);
	*p_idt_limit = IDT_SIZE * sizeof(struct gate) - 1;
	*p_idt_base  = (u32)&idt;

	init_prot();

	disp_str("-----\"cstart\" finished-----\n");
}