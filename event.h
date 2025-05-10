#ifndef __EVENT_H__
#define __EVENT_H__

struct event {
	__u32 pid;
	char comm[16];
	char type; // 'F' (fork) or 'E' (exit)
};

#endif
