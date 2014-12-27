/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 clock.c
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

/*======================================================================*
 clock_handler
 *======================================================================*/
PUBLIC void clock_handler(int irq) {
	char buffer[10];
	ticks++;
	p_proc_ready->ticks--;

	if (k_reenter != 0) {
		return;
	}

	if (p_proc_ready->ticks > 0) {
		return;
	}

	schedule();

}

/*======================================================================*
 milli_delay
 *======================================================================*/
PUBLIC void milli_delay(int milli_sec) {
	int t = get_ticks();

	while (((get_ticks() - t) * 1000 / HZ) < milli_sec) {
	}
}

/*======================================================================*
 init_clock
 *======================================================================*/
PUBLIC void init_clock() {

	/* 初始化 8253 PIT */
	out_byte(TIMER_MODE, RATE_GENERATOR);
	out_byte(TIMER0, (u8) (TIMER_FREQ / HZ));
	out_byte(TIMER0, (u8) ((TIMER_FREQ / HZ) >> 8));

	put_irq_handler(CLOCK_IRQ, clock_handler); /* 设定时钟中断处理程序 */
	enable_irq(CLOCK_IRQ); /* 让8259A可以接收时钟中断 */
}

