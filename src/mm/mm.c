#include "../include/type.h"
#include "../include/const.h"
#include "../include/fs.h"
#include "../include/protect.h"
#include "../include/proc.h"
#include "../include/tty.h"
#include "../include/console.h"
#include "../include/global.h"
#include "../include/string.h"
#include "../include/proto.h"
#include "../include/elf32.h"

#define PAGE_COUNTS		1048576
#define USER_ADDR		(5*1024)		//用户可用的物理页从5＊1024个页处开始,即20M处

#define PG_P			1	//; 页存在属性位
#define PG_RWR			0	//; R/W 属性位值, 读/执行
#define PG_RWW			2	//; R/W 属性位值, 读/写/执行
#define PG_USS			0	//; U/S 属性位值, 系统级
#define PG_USU			4	//; U/S 属性位值, 用户级

int memory_size = 1024*1024*100;

PRIVATE u32 user_proc_pid = USER_PROC_PID_START;
PRIVATE u32 mem_map[PAGE_COUNTS] = {0};					//用4M的空间存储所有物理页分配情况
PRIVATE u8	mm_buffer[4*1024] = {0};


PRIVATE void mm_init();
PRIVATE void do_exec(MESSAGE* pMsg);
PUBLIC int do_fork();
PRIVATE u32 get_free_page(void);
PRIVATE void free_page(u32 addr);
PRIVATE void do_exec_for_Page(MESSAGE* pMsg);
PRIVATE void do_exec_for_Page_Ex(MESSAGE* pMsg);


MESSAGE mm_msg;
PUBLIC void task_mm()
{
	printf("mm run!\n");
	mm_init();

	while(1){
            send_recv(RECEIVE, ANY, &mm_msg);
            int src = mm_msg.source;
            int reply = 1;

            int msgtype = mm_msg.type;

            switch (msgtype) {
            case FORK:
                mm_msg.RETVAL = do_fork();
                break;
            case EXEC:
                //do_exec(&mm_msg);
            	do_exec_for_Page_Ex(&mm_msg);
                reply = 1;
                break;
            case EXIT:
                //do_exit(mm_msg.STATUS);
                reply = 0;
                break;
            case WAIT:
                //do_wait();
                reply = 0;
                break;
            default:
                dump_msg("MM::unknown msg", &mm_msg);
                assert(0);
                break;
            }

            if (reply) {
                mm_msg.type = SYSCALL_RET;
                send_recv(SEND, src, &mm_msg);
            }
        }
}

PRIVATE void mm_init()
{
	int i;

	//内核占用的物理空间不参与分配
	for(i = 0; i < USER_ADDR; ++i)
		mem_map[i] = 1;

	//内核以外的物理空间，最大4GB，实际可能没有那么大
	for(i = USER_ADDR; i < PAGE_COUNTS; ++i)
		mem_map[i] = 0;
}

//
//获取一个可用的物理页，返回这个物理页的物理地址，4KB对齐
//
PRIVATE u32 get_free_page(void)
{
	int i = 0;
	//从内核空间外分配物理页
	for(i = USER_ADDR; i < PAGE_COUNTS; ++i)
	{
		if(!mem_map[i])
		{
			mem_map[i]++;
			return 4*1024*i;
		}
	}
}

//
//释放页，addr为物理地址,必须4KB对齐
//
PRIVATE void free_page(u32 pAddr)
{
	//物理地址必须4KB对齐
	if(pAddr & 0xFFFF)
		panic("free_page error, pAddr:0x%x\n", pAddr);

	//释放的物理地址不能属于内核空间
	pAddr >>=12;
	if(pAddr < USER_ADDR)
		panic("free_page error,page:0x%x\n", pAddr);
	mem_map[pAddr]--;
}

//
//为新进程设置分页
//
PRIVATE void setupProgramPage(u32 pageDirBase, u32 vAddr, u32 pageCount)
{
	int i;
	u32 dirIndex = vAddr >> 22;
	u32 pageIndex = (vAddr >> 12) & 0x3FF;	//get middle 10bit
	u32 pageTable;
	if(!(*(u32*)(pageDirBase + dirIndex*4)))
	{
		pageTable = get_free_page();
		for(i = 0; i < 1024; ++i)
			*(u32*)(pageTable + i*4) = 0;
		*(u32*)(pageDirBase + dirIndex*4) = pageTable | PG_P | PG_USU | PG_RWW;
	}

	pageTable = *(u32*)(pageDirBase + dirIndex*4) & 0xFFFFF000;
	for(i = 0; i < pageCount; ++i)
		*((u32*)(pageTable + (pageIndex + i)*4)) = get_free_page() | PG_P | PG_USU | PG_RWW;
}

//
//将新进程的执行映像从磁盘读到物理内存中
//
PRIVATE void readFile(u32 flip, u32 pageDirBase, u32 vAddr, u32 offsetInFile, u32 memSize)
{
	u32 pageCount = (memSize >> 12) + 1;
	u32 dirIndex = vAddr >> 22;
	u32 pageIndex = (vAddr >> 12) & 0x3FF;	//get middle 10bit
	u32 pageTable = *(u32*)(pageDirBase + dirIndex*4) & 0xFFFFF000;
	MESSAGE msg;
	int i;
	u32 uCount;
	int nGoon = 1;

	for(i = 0; i < pageCount & nGoon; i++)
	{
		if(memSize <= 0)
			return;
		u32 pAddr = *((u32*)(pageTable + (pageIndex + i)*4))  & 0xFFFFF000;	//physical address
		uCount = 4096;
		if(memSize <= 4096)
		{
			nGoon = 0;
			uCount = memSize;
		}

		reset_msg(&msg);
		msg.type = READ;
		msg.u.m3.m3p1 = (void*)pAddr;
		msg.u.m3.m3i1 = uCount;
		msg.u.m3.m3i2 = offsetInFile;
		msg.u.m3.m3i3 = flip;
		send_recv(BOTH, TASK_FS, &msg);

		memSize -= uCount;
	}
}

//
//为新进程分配栈空间
//
PRIVATE void AllocStack(u32 pageDirBase, u32 vAddr, u32 stackSize)
{
	int i;
	u32 pageCount = stackSize >> 12;
	u32 dirIndex = vAddr >> 22;
	u32 pageIndex = (vAddr >> 12) & 0x3FF;	//get middle 10bit
	u32 pageTable;
	if (!(*(u32*) (pageDirBase + dirIndex * 4)))
	{
		pageTable = get_free_page();
		for (i = 0; i < 1024; ++i)
			*(u32*) (pageTable + i * 4) = 0;
		*(u32*) (pageDirBase + dirIndex * 4) = pageTable | PG_P | PG_USU
				| PG_RWW;
	}

	pageTable = *(u32*) (pageDirBase + dirIndex * 4) & 0xFFFFF000;
	for (i = 0; i < pageCount; ++i)
		*((u32*) (pageTable + (pageIndex + i) * 4)) =
				get_free_page() | PG_P | PG_USU | PG_RWW;
}
PRIVATE u32	FindEmpyProcessID()
{
	int i;
	for(i = 0; i < NR_ALL_PROCS; ++i)
	{
		if(FREE_SLOT == proc_table[i].p_flags)
			return i;
	}
	panic("Can't find a empty Process ID\n");
	return 0;
}

PRIVATE void do_exec_for_Page_Ex(MESSAGE* pMsg)
{
	u8 privilege;
	u8 rpl;
	int eflags;
	int prio;
	int i;

	u32 pageTable;

	u32 pid = FindEmpyProcessID();

	u32 fileSize = 0;
	u32 bufferSize = 4 * 1024;
	u32 uStackBase = 0;

	//u32     uProgramEntry = 20*1024*1024;
	//u32     uDataBase = uAddrStart;
	//u32     uDataLimit = 0xFFFFFFFF;
	struct proc* p_proc;
	Elf32_Ehdr * pHdr;
	Elf32_Phdr* pPHdr;
	//Elf32_Shdr*        pSHdr;

	char* pFileName = (char*) pMsg->u.m2.m2p1;
	MESSAGE msg;

	privilege = PRIVILEGE_USER;
	rpl = RPL_USER;
	eflags = 0x202; /* IF=1, bit 2 is always 1 */
	prio = 2;
	p_proc = &proc_table[pid];
	strcpy(proc_table[pid].name, pFileName); /* name of the process */
	p_proc->p_parent = NO_TASK;

	memcpy(&p_proc->ldts[0], &gdt[SELECTOR_KERNEL_CS >> 3],
			sizeof(struct descriptor));
	p_proc->ldts[0].attr1 = DA_C | privilege << 5;

	memcpy(&p_proc->ldts[1], &gdt[SELECTOR_KERNEL_DS >> 3],
			sizeof(struct descriptor));
	p_proc->ldts[1].attr1 = DA_DRW | privilege << 5;

	//init_desc(&p_proc->ldts[2], uDataBase, uDataLimit, DA_32 | DA_LIMIT_4K | DA_DRW | privilege << 5);

	p_proc->regs.cs = (0 & SA_RPL_MASK & SA_TI_MASK) | SA_TIL | rpl;
	p_proc->regs.ds = (8 & SA_RPL_MASK & SA_TI_MASK) | SA_TIL | rpl;
	p_proc->regs.es = (8 & SA_RPL_MASK & SA_TI_MASK) | SA_TIL | rpl;
	p_proc->regs.fs = (8 & SA_RPL_MASK & SA_TI_MASK) | SA_TIL | rpl;
	p_proc->regs.ss = (8 & SA_RPL_MASK & SA_TI_MASK) | SA_TIL | rpl;
	p_proc->regs.gs = (SELECTOR_KERNEL_GS & SA_RPL_MASK) | rpl;

	//p_proc->regs.eip =  uProgramEntry;
	//p_proc->regs.esp = (u32) (task_stack + STACK_SIZE_DEFAULT);
	p_proc->regs.eflags = eflags;

	p_proc->nr_tty = 0;

	p_proc->p_flags = 1;
	p_proc->p_msg = 0;
	p_proc->p_recvfrom = NO_TASK;
	p_proc->p_sendto = NO_TASK;
	p_proc->has_int_msg = 0;
	p_proc->q_sending = 0;
	p_proc->next_sending = 0;

	p_proc->ticks = p_proc->priority = prio;

	p_proc->pageDirBase = get_free_page();
	//复制内核页目录
	for (i = 0; i < 1024; ++i)
	{
		if (i < 5)
			*(u32*) (p_proc->pageDirBase + i * 4) = *((u32*) (PAGE_DIR_BASE
					+ i * 4));
		else
			*(u32*) (p_proc->pageDirBase + i * 4) = 0;
	}
	/*
	 pageTable = get_free_page();

	 *(u32*)(p_proc->pageDirBase + i*4) = pageTable | PG_P | PG_USU | PG_RWW;

	 //初始化页表
	 for(i = 0; i < 1024; ++i)
	 {
	 *((u32*)(pageTable + i*4)) = (24*1024*1024 + i*4096) | PG_P | PG_USU | PG_RWW;
	 }
	 */

	reset_msg(&msg);
	msg.type = OPEN;
	msg.u.m2.m2p1 = pFileName;
	send_recv(BOTH, TASK_FS, &msg);
	fileSize = msg.u.m3.m3i1;
	int flip = msg.u.m3.m3i2;
	printf("file size:0x%x\n", fileSize);

	bufferSize = fileSize > bufferSize ? bufferSize : fileSize;

	reset_msg(&msg);
	msg.type = READ;
	msg.u.m3.m3i1 = fileSize;
	msg.u.m3.m3p1 = (void*) mm_buffer;
	send_recv(BOTH, TASK_FS, &msg);

	pHdr = (Elf32_Ehdr*) (void*) mm_buffer;
	printf("program entry:0x%x\n", pHdr->e_entry);

	p_proc->regs.eip = pHdr->e_entry;

	for (i = 0; i < pHdr->e_phnum; ++i)
	{
		u32 vAddr;
		u32 pageCount;
		pPHdr = (Elf32_Phdr*) (void*) (mm_buffer + pHdr->e_phoff
				+ i * pHdr->e_phentsize);
		vAddr = pPHdr->p_vaddr;
		pageCount = (pPHdr->p_memsz >> 12) + 1;

		setupProgramPage(p_proc->pageDirBase, vAddr, pageCount);
		readFile(flip, p_proc->pageDirBase, vAddr, pPHdr->p_offset, pPHdr->p_memsz);

		printf("program head,entry:0x%x, size:0x%x\n",pPHdr->p_vaddr, pPHdr->p_memsz);

		if(i == pHdr->e_phnum - 1 && pPHdr->p_vaddr != 0)
			uStackBase = ((pPHdr->p_vaddr + pPHdr->p_memsz) + 4*1024) & 0xFFFFF000;
	}

	reset_msg(&msg);
	msg.type = CLOSE;
	msg.u.m3.m3i1 = flip;
	send_recv(BOTH, TASK_FS, &msg);

	AllocStack(p_proc->pageDirBase, uStackBase, 4*1024);
	p_proc->regs.esp = (u32) (uStackBase + 4*1024);

	printf("program stack top:0x%x\n", uStackBase + 4*1024);
	//p_flags=0，此进程即可被调度运行
	p_proc->p_flags = 0;

}

PRIVATE void do_exec_for_Page(MESSAGE* pMsg)
{
    u8    privilege;
    u8    rpl;
	int   eflags;
	int   prio;
	int i;

	u32 pageTable;

	u32 pid = user_proc_pid++;
    u32 uAddrStart = 24*1024*1024;


	u32     uProgramEntry = 20*1024*1024;
	u32     uDataBase = uAddrStart;
	u32     uDataLimit = 0xFFFFFFFF;
    struct proc* p_proc;
    Elf32_Ehdr *      pHdr;
    Elf32_Phdr*       pPHdr;
    Elf32_Shdr*        pSHdr;

    char* pFileName = (char*)pMsg->u.m2.m2p1;
    MESSAGE msg;


	reset_msg(&msg);
	msg.type = READ_FILE;
	msg.u.m2.m2p1 = pFileName;
	msg.u.m2.m2p2 = (void*)(uAddrStart);
	send_recv(BOTH, TASK_FS, &msg);


    pHdr = (Elf32_Ehdr*)(void*)uAddrStart;


    for(i = 0; i < pHdr->e_phnum; ++i)
    {

        pPHdr = (Elf32_Phdr*)(void*)(uAddrStart + pHdr->e_phoff + i*pHdr->e_phentsize);
        //pPHdr->p_paddr += uAddrStart;
        //pPHdr->p_vaddr += uAddrStart;

        if(i == 0)
            uProgramEntry = uProgramEntry + pPHdr->p_offset;
    }



    for(i = 0; i < pHdr->e_shnum; ++i)
    {
        if(i == 0)
            continue;
        pSHdr = (Elf32_Shdr*)(void*)(uAddrStart + pHdr->e_shoff + i*pHdr->e_shentsize);
        //pSHdr->sh_addr += uAddrStart;


    }


    privilege = PRIVILEGE_USER;
    rpl       = RPL_USER;
    eflags    = 0x202; /* IF=1, bit 2 is always 1 */
    prio      = 2;
    p_proc = &proc_table[pid];
    strcpy(proc_table[pid].name, pFileName);	/* name of the process */
    p_proc->p_parent = NO_TASK;




                memcpy(&p_proc->ldts[0], &gdt[SELECTOR_KERNEL_CS >> 3],sizeof(struct descriptor));
                p_proc->ldts[0].attr1 = DA_C | privilege << 5;

                memcpy(&p_proc->ldts[1], &gdt[SELECTOR_KERNEL_DS >> 3], sizeof(struct descriptor));
                p_proc->ldts[1].attr1 = DA_DRW | privilege << 5;

               //init_desc(&p_proc->ldts[2], uDataBase, uDataLimit, DA_32 | DA_LIMIT_4K | DA_DRW | privilege << 5);


        p_proc->regs.cs	= (0 & SA_RPL_MASK & SA_TI_MASK) | SA_TIL | rpl;
		p_proc->regs.ds	= (8 & SA_RPL_MASK & SA_TI_MASK) | SA_TIL | rpl;
		p_proc->regs.es	= (8 & SA_RPL_MASK & SA_TI_MASK) | SA_TIL | rpl;
		p_proc->regs.fs	= (8 & SA_RPL_MASK & SA_TI_MASK) | SA_TIL | rpl;
		p_proc->regs.ss	= (8 & SA_RPL_MASK & SA_TI_MASK) | SA_TIL | rpl;
		p_proc->regs.gs	= (SELECTOR_KERNEL_GS & SA_RPL_MASK) | rpl;

		p_proc->regs.eip =  uProgramEntry;
		p_proc->regs.esp = (u32)(task_stack + STACK_SIZE_DEFAULT);
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

		p_proc->pageDirBase = get_free_page();
		//复制内核页目录
		for(i = 0; i < 5; ++i)
		{
			*(u32*)(p_proc->pageDirBase + i*4) = *((u32*)(PAGE_DIR_BASE + i*4));
		}

		pageTable = get_free_page();

		*(u32*)(p_proc->pageDirBase + i*4) = pageTable | PG_P | PG_USU | PG_RWW;

		//初始化页表
		for(i = 0; i < 1024; ++i)
		{
			*((u32*)(pageTable + i*4)) = (24*1024*1024 + i*4096) | PG_P | PG_USU | PG_RWW;
		}


		reset_msg(&msg);
		msg.type = READ_FILE;
		msg.u.m2.m2p1 = pFileName;
		msg.u.m2.m2p2 = (void*)(uAddrStart);
		send_recv(BOTH, TASK_FS, &msg);



}

PRIVATE void do_exec(MESSAGE* pMsg)
{
    u8    privilege;
    u8    rpl;
	int   eflags;
	int   prio;
	int i;

	u32 pid = user_proc_pid++;
    u32 uAddrStart = 10*1024*1024 + (pid -10)*1024*1024;


	u32     uProgramEntry;
	u32     uDataBase = uAddrStart;
	u32     uDataLimit = 0xFFFFFFFF;
    struct proc* p_proc;
    Elf32_Ehdr *      pHdr;
    Elf32_Phdr*       pPHdr;
    Elf32_Shdr*        pSHdr;

     char* pFileName = (char*)pMsg->u.m2.m2p1;
    MESSAGE msg;


	reset_msg(&msg);
	msg.type = READ_FILE;
	msg.u.m2.m2p1 = pFileName;
	msg.u.m2.m2p2 = (void*)(uAddrStart);
	send_recv(BOTH, TASK_FS, &msg);


    pHdr = (Elf32_Ehdr*)(void*)uAddrStart;


    for(i = 0; i < pHdr->e_phnum; ++i)
    {

        pPHdr = (Elf32_Phdr*)(void*)(uAddrStart + pHdr->e_phoff + i*pHdr->e_phentsize);
         pPHdr->p_paddr += uAddrStart;
        pPHdr->p_vaddr += uAddrStart;

        if(i == 0)
            uProgramEntry = uAddrStart + pPHdr->p_offset;
    }

    for(i = 0; i < pHdr->e_shnum; ++i)
    {
        if(i == 0)
            continue;
        pSHdr = (Elf32_Shdr*)(void*)(uAddrStart + pHdr->e_shoff + i*pHdr->e_shentsize);
        pSHdr->sh_addr += uAddrStart;


    }

    privilege = PRIVILEGE_USER;
    rpl       = RPL_USER;
    eflags    = 0x202; /* IF=1, bit 2 is always 1 */
    prio      = 2;
    p_proc = &proc_table[pid];
    strcpy(proc_table[pid].name, pFileName);	/* name of the process */
    p_proc->p_parent = NO_TASK;
		//p_proc->pid = i;			/* pid */


                //p_proc->ldt_sel = selector_ldt;
                memcpy(&p_proc->ldts[0], &gdt[SELECTOR_KERNEL_CS >> 3],sizeof(struct descriptor));
                p_proc->ldts[0].attr1 = DA_C | privilege << 5;

                memcpy(&p_proc->ldts[1], &gdt[SELECTOR_KERNEL_DS >> 3], sizeof(struct descriptor));
                p_proc->ldts[1].attr1 = DA_DRW | privilege << 5;

               init_desc(&p_proc->ldts[2], uDataBase, uDataLimit, DA_32 | DA_LIMIT_4K | DA_DRW | privilege << 5);


        p_proc->regs.cs	= (0 & SA_RPL_MASK & SA_TI_MASK) | SA_TIL | rpl;
		p_proc->regs.ds	= (16 & SA_RPL_MASK & SA_TI_MASK) | SA_TIL | rpl;
		p_proc->regs.es	= (8 & SA_RPL_MASK & SA_TI_MASK) | SA_TIL | rpl;
		p_proc->regs.fs	= (8 & SA_RPL_MASK & SA_TI_MASK) | SA_TIL | rpl;
		p_proc->regs.ss	= (8 & SA_RPL_MASK & SA_TI_MASK) | SA_TIL | rpl;
		p_proc->regs.gs	= (SELECTOR_KERNEL_GS & SA_RPL_MASK) | rpl;

		p_proc->regs.eip =  uProgramEntry;
		p_proc->regs.esp = (u32)(task_stack + STACK_SIZE_DEFAULT);
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

		p_proc->pageDirBase = 5*1024*1024;

}
/*****************************************************************************
 *                                alloc_mem
 *****************************************************************************/
/**
 * Allocate a memory block for a proc.
 *
 * @param pid  Which proc the memory is for.
 * @param memsize  How many bytes is needed.
 *
 * @return  The base of the memory just allocated.
 *****************************************************************************/
PUBLIC int alloc_mem(int pid, int memsize)
{
	assert(pid >= (NR_TASKS + NR_NATIVE_PROCS));
	if (memsize > PROC_IMAGE_SIZE_DEFAULT) {
		panic("unsupported memory request: %d. "
		      "(should be less than %d)",
		      memsize,
		      PROC_IMAGE_SIZE_DEFAULT);
	}

	int base = PROCS_BASE +
		(pid - (NR_TASKS + NR_NATIVE_PROCS)) * PROC_IMAGE_SIZE_DEFAULT;

	if (base + memsize >= memory_size)
		panic("memory allocation failed. pid:%d,%d", pid,base + memsize);

	return base;
}

/*****************************************************************************
 *                                free_mem
 *****************************************************************************/
/**
 * Free a memory block. Because a memory block is corresponding with a PID, so
 * we don't need to really `free' anything. In another word, a memory block is
 * dedicated to one and only one PID, no matter what proc actually uses this
 * PID.
 *
 * @param pid  Whose memory is to be freed.
 *
 * @return  Zero if success.
 *****************************************************************************/
PUBLIC int free_mem(int pid)
{
	return 0;
}

PUBLIC void SetNewProc(int pid)
{

    u8    privilege;
    u8    rpl;
	int   eflags;
	int   prio;
    struct proc* p_proc;

    privilege = PRIVILEGE_USER;
    rpl       = RPL_USER;
    eflags    = 0x202; /* IF=1, bit 2 is always 1 */
    prio      = 5;
    p_proc = &proc_table[pid];
    strcpy(proc_table[pid].name, "NEWP");	/* name of the process */
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

		p_proc->regs.eip = (u32)TestNewProc;
		p_proc->regs.esp = (u32)(task_stack + STACK_SIZE_DEFAULT);
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


}


/*****************************************************************************
 *                                do_fork
 *****************************************************************************/
/**
 * Perform the fork() syscall.
 *
 * @return  Zero if success, otherwise -1.
 *****************************************************************************/
PUBLIC int do_fork()
{
    SetNewProc(9);
    mm_msg.PID = 9;
    return 0;
//dump_proc(&proc_table[mm_msg.source]);
	/* find a free slot in proc_table */
	struct proc* p = proc_table;
	int i;
	for (i = 0; i < NR_TASKS + NR_PROCS; i++,p++)
		if (p->p_flags == FREE_SLOT)
			break;

	int child_pid = i;
	assert(p == &proc_table[child_pid]);
	assert(child_pid >= NR_TASKS + NR_NATIVE_PROCS);
	if (i == NR_TASKS + NR_PROCS) /* no free slot */
		return -1;
	assert(i < NR_TASKS + NR_PROCS);

	/* duplicate the process table */
	int pid = mm_msg.source;
	u16 child_ldt_sel = p->ldt_sel;
	*p = proc_table[pid];
	p->ldt_sel = child_ldt_sel;
	p->p_parent = pid;
	sprintf(p->name, "%s_%d", proc_table[pid].name, child_pid);

	/* duplicate the process: T, D & S */
	struct descriptor * ppd;

	/* Text segment */
	ppd = &proc_table[pid].ldts[INDEX_LDT_C];
	/* base of T-seg, in bytes */
	int caller_T_base  = reassembly(ppd->base_high, 24,
					ppd->base_mid,  16,
					ppd->base_low);

	/* limit of T-seg, in 1 or 4096 bytes,
	   depending on the G bit of descriptor */

	int caller_T_limit = reassembly(0, 0,
					(ppd->limit_high_attr2 & 0xF), 16,
					ppd->limit_low);

	/* size of T-seg, in bytes */

	int caller_T_size  = ((caller_T_limit + 1) *
			      ((ppd->limit_high_attr2 & (DA_LIMIT_4K >> 8)) ?
			       4096 : 1));

	/* Data & Stack segments */
	ppd = &proc_table[pid].ldts[INDEX_LDT_RW];
	/* base of D&S-seg, in bytes */

	int caller_D_S_base  = reassembly(ppd->base_high, 24,
					  ppd->base_mid,  16,
					  ppd->base_low);
	/* limit of D&S-seg, in 1 or 4096 bytes,
	   depending on the G bit of descriptor */

	int caller_D_S_limit = reassembly((ppd->limit_high_attr2 & 0xF), 16,
					  0, 0,
					  ppd->limit_low);
	/* size of D&S-seg, in bytes */

	int caller_D_S_size  = ((caller_T_limit + 1) *
				((ppd->limit_high_attr2 & (DA_LIMIT_4K >> 8)) ?
				 4096 : 1));

	/* we don't separate T, D & S segments, so we have: */

	assert((caller_T_base  == caller_D_S_base ) &&
	       (caller_T_limit == caller_D_S_limit) &&
	       (caller_T_size  == caller_D_S_size ));

//panic("xx:%d,%d,%d",caller_T_base,caller_T_limit,caller_T_size);

	/* base of child proc, T, D & S segments share the same space,
	   so we allocate memory just once */
	int child_base = alloc_mem(child_pid, caller_T_size);

	/* child is a copy of the parent */
	phys_copy((void*)child_base, (void*)caller_T_base, caller_T_size);



	/* child's LDT */

	init_desc(&p->ldts[INDEX_LDT_C],
		  child_base,
		  (PROC_IMAGE_SIZE_DEFAULT - 1) >> LIMIT_4K_SHIFT,
		  DA_LIMIT_4K | DA_32 | DA_C | PRIVILEGE_USER << 5);
	init_desc(&p->ldts[INDEX_LDT_RW],
		  child_base,
		  (PROC_IMAGE_SIZE_DEFAULT - 1) >> LIMIT_4K_SHIFT,
		  DA_LIMIT_4K | DA_32 | DA_DRW | PRIVILEGE_USER << 5);


	/* tell FS, see fs_fork() */
	MESSAGE msg2fs;
	msg2fs.type = FORK;
	msg2fs.PID = child_pid;
	send_recv(BOTH, TASK_FS, &msg2fs);


	/* child PID will be returned to the parent proc */
	mm_msg.PID = child_pid;

	/* birth of the child */

	MESSAGE m;
	m.type = SYSCALL_RET;
	m.RETVAL = 0;
	m.PID = 0;
	send_recv(SEND, child_pid, &m);
	printf("fork end\n");

	//dump_proc(&proc_table[child_pid]);
    //panic("ss");

	return 0;
}

