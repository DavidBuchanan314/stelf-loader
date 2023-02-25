#include <stdio.h>

int main(int argc, char *argv[], char *envp[])
{
	printf("Hello, glibc static-pie ELF!\n");

	printf("I have %d args:\n", argc);
	for (int i=0; i<argc; i++) {
		printf("arg %d: %s\n", i, argv[i]);
	}
}
