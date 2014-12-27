
/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
                            main.c
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
                                                    Forrest Yu, 2005
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/

#include "../include/type.h"
#include "../include/const.h"
#include "../include/fs.h"
#include "../include/protect.h"
#include "../include/string.h"
#include "../include/proc.h"
#include "../include/tty.h"
#include "../include/console.h"
#include "../include/global.h"
#include "../include/proto.h"
#include "../include/elf32.h"


PUBLIC void StartShell();

void *kmalloc(unsigned int len);

/*======================================================================*
                            kernel_main
 *======================================================================*/
PUBLIC int kernel_main()
{


    disp_str("-----\"kernel_main\" begins-----\n");



	struct task* p_task;
	struct proc* p_proc;
	char* p_task_stack = task_stack + STACK_SIZE_TOTAL;
	u16   selector_ldt = SELECTOR_LDT_FIRST;
        u8    privilege;
        u8    rpl;
	int   eflags;
	int   i;
	int   prio;
	for (i = 0; i < NR_TASKS+NR_PROCS; i++) {
			//printf("i:%d\n",i);
			p_proc = &proc_table_task[i];// = (struct proc*)kmalloc(sizeof(struct proc));
			/*
			memset(p_proc, 0, sizeof(struct proc));
			p_proc->ldt_sel = SELECTOR_LDT_FIRST + (i << 3);
			init_desc(&gdt[INDEX_LDT_FIRST + i],
						  makelinear(SELECTOR_KERNEL_DS, p_proc->ldts),
						  LDT_SIZE * sizeof(struct descriptor) - 1,
						  DA_LDT);
			*/


            if( i >= NR_TASKS + NR_NATIVE_PROCS)
            {
                    //proc_table[i]->p_flags = FREE_SLOT;
                    continue;
            }
            proc_table[i] = p_proc;

	        if (i < NR_TASKS) {     /* 任务 */
                        p_task    = task_table + i;
                        privilege = PRIVILEGE_TASK;
                        rpl       = RPL_TASK;
                        eflags    = 0x1202; /* IF=1, IOPL=1, bit 2 is always 1 */
			prio      = 1;
                }
                else {                  /* 用户进程 */
                        p_task    = user_proc_table + (i - NR_TASKS);
                        privilege = PRIVILEGE_USER;
                        rpl       = RPL_USER;
                        eflags    = 0x202; /* IF=1, bit 2 is always 1 */
			prio      = 1;
                }

		strcpy(p_proc->name, p_task->name);	/* name of the process */
		p_proc->p_parent = NO_TASK;
		//p_proc->pid = i;			/* pid */

        if(strcmp(p_proc->name, "INIT") == 0)
        {
               //p_proc->ldt_sel = selector_ldt;
                memcpy(&p_proc->ldts[0], &gdt[SELECTOR_KERNEL_CS >> 3],
                       sizeof(struct descriptor));
                p_proc->ldts[0].attr1 = DA_C | privilege << 5;
                memcpy(&p_proc->ldts[1], &gdt[SELECTOR_KERNEL_DS >> 3],
                       sizeof(struct descriptor));
                p_proc->ldts[1].attr1 = DA_DRW | privilege << 5;
        }
        else
        {
                //p_proc->ldt_sel = selector_ldt;
                memcpy(&p_proc->ldts[0], &gdt[SELECTOR_KERNEL_CS >> 3],
                       sizeof(struct descriptor));
                p_proc->ldts[0].attr1 = DA_C | privilege << 5;
                memcpy(&p_proc->ldts[1], &gdt[SELECTOR_KERNEL_DS >> 3],
                       sizeof(struct descriptor));
                p_proc->ldts[1].attr1 = DA_DRW | privilege << 5;
        }




		p_proc->regs.cs	= (0 & SA_RPL_MASK & SA_TI_MASK) | SA_TIL | rpl;
		p_proc->regs.ds	= (8 & SA_RPL_MASK & SA_TI_MASK) | SA_TIL | rpl;
		p_proc->regs.es	= (8 & SA_RPL_MASK & SA_TI_MASK) | SA_TIL | rpl;
		p_proc->regs.fs	= (8 & SA_RPL_MASK & SA_TI_MASK) | SA_TIL | rpl;
		p_proc->regs.ss	= (8 & SA_RPL_MASK & SA_TI_MASK) | SA_TIL | rpl;
		p_proc->regs.gs	= (SELECTOR_KERNEL_GS & SA_RPL_MASK) | rpl;

        p_proc->regs.eip = (u32)p_task->initial_eip;
		p_proc->regs.esp = (u32)p_task_stack;
		p_proc->regs.eflags = eflags;

		p_proc->nr_tty		= 0;

		p_proc->p_flags = 0;
		p_proc->p_msg = 0;
		p_proc->p_recvfrom = NO_TASK;
		p_proc->p_sendto = NO_TASK;
		p_proc->has_int_msg = 0;
		p_proc->q_sending = 0;
		p_proc->next_sending = 0;

		p_proc->ticks = p_proc->priority = prio;

		p_proc->pageDirBase = PAGE_DIR_BASE;

		p_task_stack -= p_task->stacksize;
		//p_proc++;
		p_task++;
		selector_ldt += 1 << 3;
	}

        //proc_table[USER_INIT].nr_tty = 3;


	k_reenter = 0;
	ticks = 0;

	p_proc_ready = proc_table[0];


	init_clock();

    init_keyboard();

    disp_str("-----\"kernel_main\" finished-----\n");
	restart();

	while(1){}
}

/*****************************************************************************
 *                                get_ticks
 *****************************************************************************/
PUBLIC int get_ticks()
{
	MESSAGE msg;
	reset_msg(&msg);
	msg.type = GET_TICKS;
	send_recv(BOTH, TASK_SYS, &msg);
	return msg.RETVAL;
}

PUBLIC int wait(int * status)
{
    MESSAGE msg;
    msg.type = WAIT;
    send_recv(BOTH, TASK_MM, &msg);
    *status = msg.STATUS;
    return (msg.PID == NO_TASK ? -1 : msg.PID);
}

void Init()
{
    int pid;
    StartShell();
    while(1)
    {
        //printf("ss:%d",pid);
    }
}



 PRIVATE char szShellStack[STACK_SIZE_DEFAULT];
void Shell()
{
	MESSAGE msg;


	while (1)
	{

		printf("$:");
		send_recv(BOTH, TASK_TTY, &msg);
		if (msg.type == TTY_ENTER)
		{
			char* pFileName = (char*) msg.u.m2.m2p1;
			printf("%s\n", pFileName);
			if (strcmp(pFileName, "TESTFILE") == 0
					|| strcmp(pFileName, "TESTCALL") == 0
					|| strcmp(pFileName, "ECHO") == 0)
			{
				char szFileName[128] =
				{ 0 };

				memcpy(szFileName, pFileName, strlen(pFileName));
				reset_msg(&msg);
				msg.type = EXEC;
				msg.u.m2.m2p1 = (void*) szFileName;
				send_recv(BOTH, TASK_MM, &msg);
			}
			//printf(msg.u.m2.m2p1);
			//printf("\n");
		}
		//printf("<Ticks:%d>", get_ticks());
		//milli_delay(200);
	}
}

void TestA()
{
    MESSAGE msg;
	while (1) {
        printf("$:");
        send_recv(RECEIVE, TASK_TTY, &msg);
        if(msg.type == TTY_ENTER)
        {
            printf("%s\n", msg.u.m2.m2p1);
            //printf(msg.u.m2.m2p1);
            //printf("\n");
        }
		//printf("<Ticks:%d>", get_ticks());
		//milli_delay(200);
	}
}

/*======================================================================*
                               TestB
 *======================================================================*/
void TestB()
{
	while(1){
		//printf("B");
		//milli_delay(200);
	}
}

/*======================================================================*
                               TestB
 *======================================================================*/
void TestC()
{

    u32 addrStart = 0xAA0000;

    char szFileName[] = "TESTFILE";
    char szBuffer[512] = {0};

    MESSAGE msg;
	reset_msg(&msg);
	msg.type = READ_FILE;
	msg.u.m2.m2p1 = szFileName;
	msg.u.m2.m2p2 = (void*)(addrStart);
	send_recv(BOTH, TASK_FS, &msg);


    printf("TESTFILE READ END!\n");

	while(1){
		//printf("C1");
		//printf("C2");
		//milli_delay(200);
	}
}

PRIVATE int getNewProcId()
{
    int i ;
    for(i = NR_TASKS + NR_NATIVE_PROCS; i < NR_TASKS + NR_PROCS; ++i)
    {
        if(proc_table[i] == 0)
            return i;
    }
    return -1;
}
PUBLIC void StartShell()
{
    u8    privilege;
    u8    rpl;
	int   eflags;
	int   prio;
    struct proc* p_proc;
    int pid;

    pid = getNewProcId();
    if(pid == -1)
        panic("getNewProcId failed,pid:%d\n", pid);

    privilege = PRIVILEGE_USER;
    rpl       = RPL_USER;
    eflags    = 0x202; /* IF=1, bit 2 is always 1 */
    prio      = 2;
    p_proc = proc_table[pid] = &proc_table_task[pid];//(struct proc*)kmalloc(sizeof(struct proc));
    strcpy(p_proc->name, "SHELL");	/* name of the process */
    p_proc->p_parent = NO_TASK;
		//p_proc->pid = i;			/* pid */


                //p_proc->ldt_sel = selector_ldt;
                memcpy(&p_proc->ldts[0], &gdt[SELECTOR_KERNEL_CS >> 3],
                       sizeof(struct descriptor));
                p_proc->ldts[0].attr1 = DA_C | privilege << 5;
                memcpy(&p_proc->ldts[1], &gdt[SELECTOR_KERNEL_DS >> 3],
                       sizeof(struct descriptor));
                p_proc->ldts[1].attr1 = DA_DRW | privilege << 5;

        p_proc->regs.cs	= (0 & SA_RPL_MASK & SA_TI_MASK) | SA_TIL | rpl;
		p_proc->regs.ds	= (8 & SA_RPL_MASK & SA_TI_MASK) | SA_TIL | rpl;
		p_proc->regs.es	= (8 & SA_RPL_MASK & SA_TI_MASK) | SA_TIL | rpl;
		p_proc->regs.fs	= (8 & SA_RPL_MASK & SA_TI_MASK) | SA_TIL | rpl;
		p_proc->regs.ss	= (8 & SA_RPL_MASK & SA_TI_MASK) | SA_TIL | rpl;
		p_proc->regs.gs	= (SELECTOR_KERNEL_GS & SA_RPL_MASK) | rpl;

		p_proc->regs.eip = (u32)Shell;
		p_proc->regs.esp = (u32)(szShellStack + STACK_SIZE_DEFAULT);
		p_proc->regs.eflags = eflags;

		p_proc->nr_tty		= 0;

		p_proc->p_flags = 0;
		p_proc->p_msg = 0;
		p_proc->p_recvfrom = NO_TASK;
		p_proc->p_sendto = NO_TASK;
		p_proc->has_int_msg = 0;
		p_proc->q_sending = 0;
		p_proc->next_sending = 0;

		p_proc->ticks = p_proc->priority = prio;

		p_proc->pageDirBase = PAGE_DIR_BASE;
}

void TestNewProc()
{
    printf("TestNewProc Run!\n");
    while(1)
    {
    }
}
/*****************************************************************************
 *                                panic
 *****************************************************************************/
PUBLIC void panic(const char *fmt, ...)
{
	int i;
	char buf[256];

	/* 4 is the size of fmt in the stack */
	va_list arg = (va_list)((char*)&fmt + 4);

	i = vsprintf(buf, fmt, arg);

	printl("%c !!panic!! %s", MAG_CH_PANIC, buf);

	/* should never arrive here */
	__asm__ __volatile__("ud2");
}

