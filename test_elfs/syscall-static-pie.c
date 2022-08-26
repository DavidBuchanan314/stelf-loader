static int _errno;
#define SYS_ERRNO _errno
#include "linux_syscall_support.h"

static char msg[] = "Hello, static-pie elf with direct syscalls!\n";

void _start(void)
{
	sys_write(1, msg, sizeof(msg) - 1);
	sys__exit(0);
}
