#ifndef __EVENT_H__
#define __EVENT_H__

#include <linux/types.h>

struct event {
	__u32 pid;
	char comm[16];
	char type; // 'F' (fork) or 'E' (exit)
};

#endif
