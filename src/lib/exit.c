/*
 * exit.c
 *
 *  Created on: 2014年12月11日
 *      Author: zxb
 */

#include "../include/type.h"
#include "../include/const.h"
#include "../include/protect.h"
#include "../include/string.h"
#include "../include/fs.h"
#include "../include/proc.h"
#include "../include/tty.h"
#include "../include/console.h"
#include "../include/global.h"

#include "../include/proto.h"

void exit(int status)
{
	MESSAGE msg;
	msg.type = EXIT;
	msg.u.m1.m1i1 = status;
	send_recv(BOTH, TASK_MM, &msg);
	//assert(msg.type == SYSCALL_RET);
}



