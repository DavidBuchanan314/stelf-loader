import os
import tempfile

def nasm(source):
	asm_source_file = tempfile.NamedTemporaryFile("w+")
	asm_source_file.write(source)
	asm_source_file.flush()

	out_file = tempfile.NamedTemporaryFile("rb+")
	os.system(f"nasm {asm_source_file.name} -o {out_file.name}")
	return out_file.read()

ASM_HEADER = """\
BITS 64

sys_mprotect equ 10

PROT_NONE  equ 0x0
PROT_READ  equ 0x1
PROT_WRITE equ 0x2
PROT_EXEC  equ 0x4

MAP_FIXED     equ	0x10		;/* Interpret addr exactly */
MAP_ANONYMOUS equ	0x20		;/* don't use a file */
MAP_PRIVATE   equ	0x02

AT_NULL    equ 0	;/* end of vector */
AT_PHDR    equ 3	;/* program headers for program */
AT_PHENT   equ 4	;/* size of program header entry */
AT_PHNUM   equ 5	;/* number of program headers */
AT_ENTRY   equ 9	;/* entry point of program */
AT_RANDOM  equ 25	;/* address of 16 random bytes */


global _start
section .text
"""
