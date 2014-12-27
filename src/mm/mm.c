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

int memory_size = 1024*1024*100;

PRIVATE u8 mem_map[PAGE_COUNTS] = {0};					//用1M的空间存储所有物理页分配情况


PRIVATE void mm_init();
u32 get_free_page(unsigned int pageCount);
void free_page(u32 addr,unsigned int pageCount);
static void freeProcMemery(struct proc* p);
PRIVATE void do_exec(MESSAGE* pMsg);

PRIVATE void do_exit(MESSAGE* pMsg);

MESSAGE mm_msg;
PUBLIC void task_mm()
{
	printf("mm run!\n");
	//while(1);
	mm_init();

	while(1){
            send_recv(RECEIVE, ANY, &mm_msg);
            int src = mm_msg.source;
            int reply = 1;

            int msgtype = mm_msg.type;

            switch (msgtype) {
            //case FORK:
            //    mm_msg.RETVAL = do_fork();
            //    break;
            case EXEC:
            	do_exec(&mm_msg);
                reply = 1;
                break;
            case EXIT:
                do_exit(&mm_msg);
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
	unsigned int i;
	unsigned int pageCount;
	//测试内存大小
	unsigned int memEnd = memtest_sub(0x100000,0xFFFFFFFF);
	printf("memSize:%dM\n",(memEnd >> 20));
	memory_size = memEnd;
	pageCount = memory_size >> 12;

	//内核占用的物理空间不参与分配
	for(i = 0; i < USER_ADDR; ++i)
		mem_map[i] = 1;

	//内核以外的物理空间，最大4GB，实际可能没有那么大
	for(i = USER_ADDR; i < pageCount; ++i)
		mem_map[i] = 0;
}

PRIVATE void do_exit(MESSAGE* pMsg)
{
	int status = pMsg->u.m1.m1i1;
	int i;
	int pid = pMsg->source;
	struct proc* p = proc_table[pid];

	//TODO 通知文件系统，进程退出

	//TODO 释放进程的内存
	freeProcMemery(p);

	proc_table[pid] = 0;
	printf("pid:%d exit!\n", pid);
}
//
//获取pageCount个连续可用的物理页，返回首个物理页的物理地址，4KB对齐
//
u32 get_free_page(unsigned int pageCount)
{
	unsigned int i,j,index;
	unsigned int count;
	unsigned int allPageCount = memory_size >> 12;

	//从内核空间外分配物理页
	for(i = USER_ADDR; i < allPageCount; ++i)
	{
		if(!mem_map[i])
		{
			for(count = 1; count < pageCount; ++count)
			{
				if(mem_map[i+count])
					break;
			}
			if(count == pageCount)
			{
				for(j = 0; j < pageCount; ++j)
					mem_map[i+j]++;
				return i << 12;
			}
		}
	}
	panic("Can't get %d pages\n",pageCount);
}


//
//释放连续的物理页，addr为物理地址,必须4KB对齐,pageCount为物理页数量
//
void free_page(u32 pAddr, unsigned int pageCount)
{
	int i;
	//物理地址必须4KB对齐
	if(pAddr & 0xFFF)
		panic("free_page error, pAddr:0x%x\n", pAddr);

	//释放的物理地址不能属于内核空间
	pAddr >>=12;
	if(pAddr < USER_ADDR)
		panic("free_page error,page:0x%x\n", pAddr);

	for(i = 0; i < pageCount; ++i)
	{
		if(!mem_map[pAddr+i])
			panic("can't free free page!");

		mem_map[pAddr+i]--;
	}
}


static void freeProcMemery(struct proc* p)
{
	u32 pageDirBase = p->pageDirBase;
	u32 i,j;
	for(i = 5; i < 1024; ++i)
	{
		u32 pageTable = *((u32*)(pageDirBase + i*4)) & 0xFFFFF000;
		if(pageTable != 0)
		{
			for(j = 0; j < 1024; ++j)
			{
				u32 page = *((u32*)(pageTable + j*4)) & 0xFFFFF000;
				if(page != 0)
					free_page(page,1);
			}
			free_page(pageTable,1);
		}
	}
	free_page(pageDirBase,1);

}
//
//为新进程设置分页
//
PRIVATE void setupProgramPage(u32 pageDirBase, u32 vAddr, u32 pageCount)
{
	//TODO 可能有BUG
	int i;
	u32 dirIndex = vAddr >> 22;
	u32 pageIndex = (vAddr >> 12) & 0x3FF;	//get middle 10bit
	u32 pageTable;
	if(!(*(u32*)(pageDirBase + dirIndex*4)))
	{
		pageTable = get_free_page(1);
		for(i = 0; i < 1024; ++i)
			*(u32*)(pageTable + i*4) = 0;
		*(u32*)(pageDirBase + dirIndex*4) = pageTable | PG_P | PG_USU | PG_RWW;
	}

	pageTable = *(u32*)(pageDirBase + dirIndex*4) & 0xFFFFF000;
	for(i = 0; i < pageCount; ++i)
		*((u32*)(pageTable + (pageIndex + i)*4)) = get_free_page(1) | PG_P | PG_USU | PG_RWW;
}

//
//将新进程的执行映像从磁盘读到物理内存中
//
PRIVATE void readFile(u32 flip, u32 pageDirBase, u32 vAddr, u32 offsetInFile, u32 memSize)
{
	//TODO 可能有BUG
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

		u32 offsetInPage = vAddr & 0xFFF;
		u32 pAddr = *((u32*)(pageTable + (pageIndex + i)*4))  & 0xFFFFF000;	//physical address




		uCount = 4096;
		if(memSize <= 4096)
		{
			nGoon = 0;
			uCount = memSize;
		}

		reset_msg(&msg);
		msg.type = READ;
		msg.u.m3.m3p1 = (void*)(pAddr + offsetInPage);
		msg.u.m3.m3i1 = uCount;
		msg.u.m3.m3i2 = offsetInFile;
		msg.u.m3.m3i3 = flip;
		send_recv(BOTH, TASK_FS, &msg);

		//
		printf("@vAddr:0x%x,pAddr:0x%x\n",vAddr, pAddr);
		//printf("#%s\n", pAddr+offsetInPage);
		//

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
		pageTable = get_free_page(1);
		for (i = 0; i < 1024; ++i)
			*(u32*) (pageTable + i * 4) = 0;
		*(u32*) (pageDirBase + dirIndex * 4) = pageTable | PG_P | PG_USU
				| PG_RWW;
	}

	pageTable = *(u32*) (pageDirBase + dirIndex * 4) & 0xFFFFF000;
	for (i = 0; i < pageCount; ++i)
		*((u32*) (pageTable + (pageIndex + i) * 4)) =
				get_free_page(1) | PG_P | PG_USU | PG_RWW;
}
PRIVATE u32	FindEmpyProcessID()
{
	int i;
	for(i = 0; i < NR_ALL_PROCS; ++i)
	{
		if(0 == proc_table[i])
			return i;
	}
	panic("Can't find a empty Process ID\n");
	return 0;
}
void *kmalloc(unsigned int len);
void kfree_s(void *obj, int size);
void updateGDT();
PRIVATE void do_exec(MESSAGE* pMsg)
{
	u8 privilege;
	u8 rpl;
	int eflags;
	int prio;
	int i;

	u32 pageTable;

	u32 pid = FindEmpyProcessID();

	u32 fileSize = 0;
	u32 uStackBase = 0;

	struct proc* p_proc;
	Elf32_Ehdr * pHdr;
	Elf32_Phdr* pPHdr;
	//Elf32_Shdr*        pSHdr;

	char* pFileName = (char*) pMsg->u.m2.m2p1;
	MESSAGE msg;

	void* mm_buffer;

	privilege = PRIVILEGE_USER;
	rpl = RPL_USER;
	eflags = 0x202; /* IF=1, bit 2 is always 1 */
	prio = 2;
	p_proc = proc_table[pid] = &proc_table_task[pid];//(struct proc*)kmalloc(sizeof(struct proc));


	strcpy(p_proc->name, pFileName); /* name of the process */
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

	p_proc->pageDirBase = get_free_page(1);
	//复制内核页目录
	for (i = 0; i < 1024; ++i)
	{
		if (i < 5)
			*(u32*) (p_proc->pageDirBase + i * 4) = *((u32*) (PAGE_DIR_BASE
					+ i * 4));
		else
			*(u32*) (p_proc->pageDirBase + i * 4) = 0;
	}

	reset_msg(&msg);
	msg.type = OPEN;
	msg.u.m2.m2p1 = pFileName;
	send_recv(BOTH, TASK_FS, &msg);
	fileSize = msg.u.m3.m3i1;
	int flip = msg.u.m3.m3i2;
	printf("file size:0x%x\n", fileSize);


	mm_buffer = kmalloc(fileSize);

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

		printf("program head,entry:0x%x, offset:0x%0x, size:0x%x\n",pPHdr->p_vaddr,pPHdr->p_offset, pPHdr->p_memsz);

		if(i == pHdr->e_phnum - 1 && pPHdr->p_vaddr != 0)
			uStackBase = ((pPHdr->p_vaddr + pPHdr->p_memsz) + 4*1024) & 0xFFFFF000;
	}

	reset_msg(&msg);
	msg.type = CLOSE;
	msg.u.m3.m3i1 = flip;
	send_recv(BOTH, TASK_FS, &msg);

	AllocStack(p_proc->pageDirBase, uStackBase, 4*1024);
	p_proc->regs.esp = (u32) (uStackBase + 4*1024);

	//printf("program stack top:0x%x\n", uStackBase + 4*1024);

	//p_flags=0，此进程即可被调度运行
	p_proc->p_flags = 0;

	kfree_s(mm_buffer, fileSize);
}
