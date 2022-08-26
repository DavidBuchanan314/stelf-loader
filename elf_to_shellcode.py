from elftools.elf.elffile import ELFFile
from functools import reduce
import operator
import io
import tempfile
import os


class Mapper():
	def __init__(self, base=0, align=0x1000):
		self.mem = bytearray()
		self.flags = []
		self.align = align
		self.base = 0
	
	def map(self, start, data, flags):
		start -= self.base

		# pre-extend the storage arrays, if necessary
		if start + len(data) > len(self.mem):
			extra_needed = start + len(data) - len(self.mem)
			self.mem += bytearray(extra_needed)
			self.flags += [0] * extra_needed
		
		# map the data
		self.mem[start:start+len(data)] = data
		self.flags[start:start+len(data)] = [flags] * len(data)

		# pad up to page boundary
		self.mem += bytearray(-len(self.mem) % self.align)
		self.flags += [0] * (-len(self.mem) % self.align)
	
	def get_page_maps(self): # returns iterator of (start, length, perms)
		map_start = 0
		prev_flags = None

		for page_start in range(0, len(self.mem), self.align):
			page_flags = reduce(
				operator.or_,
				self.flags[page_start:page_start+self.align]
			)

			if prev_flags is not None and page_flags != prev_flags:
				map_len = page_start - map_start
				yield (map_start + self.base, map_len, prev_flags)
				map_start = page_start
			
			prev_flags = page_flags
		
		if prev_flags is not None:
			yield (map_start + self.base, len(self.mem) - map_start, prev_flags)


def flags_to_string(flags):
	return ('r' if flags & 4 else '-') \
	     + ('w' if flags & 2 else '-') \
	     + ('x' if flags & 1 else '-')

def flags_to_prot(flags):
	words = []
	if flags & 4: words.append("PROT_READ")
	if flags & 2: words.append("PROT_WRITE")
	if flags & 1: words.append("PROT_EXEC")
	
	if not words:
		return "PROT_NONE"

	return " | ".join(words)

def elf_to_shellcode(elf_file, shellcode_out_file, verbose=True):
	elf = ELFFile(elf_file)
	asm_source = io.StringIO()

	asm_source.write("""\
BITS 64

sys_mprotect equ 10

PROT_NONE  equ 0x0
PROT_READ  equ 0x1
PROT_WRITE equ 0x2
PROT_EXEC  equ 0x4

AT_NULL    equ 0	;/* end of vector */
AT_PHDR    equ 3	;/* program headers for program */
AT_PHENT   equ 4	;/* size of program header entry */
AT_PHNUM   equ 5	;/* number of program headers */
AT_ENTRY   equ 9	;/* entry point of program */
AT_RANDOM  equ 25	;/* address of 16 random bytes */


global _start
section .text
_start:
""")

	if verbose:
		print("[+] ELF Entry: ", hex(elf.header.e_entry))
		print()
		print("[+] ELF segments:")
		print("\tType             Offset     VAddr      FileSize   MemSize    Prot")
	
	mapper = Mapper()

	for seg in elf.iter_segments():
		if verbose:
			print(f"\t{seg.header.p_type:<16} "\
			      f"0x{seg.header.p_offset:08x} "\
			      f"0x{seg.header.p_vaddr:08x} "\
			      f"0x{seg.header.p_filesz:08x} "\
			      f"0x{seg.header.p_memsz:08x} "\
			      f"{flags_to_string(seg.header.p_flags)}")

		# We only actually care about PT_LOAD segments
		if seg.header.p_type != "PT_LOAD":
			continue

		padded_data = seg.data() + bytes(seg.header.p_memsz - seg.header.p_filesz)
		mapper.map(seg.header.p_vaddr, padded_data, seg.header.p_flags)

	if verbose:
		print()
		print("[+] Page mappings:")
		print("\tStart      Length     Prot")
	
	for start, length, flags in mapper.get_page_maps():
		if verbose:
			print(f"\t0x{start:08x} 0x{length:08x} {flags_to_string(flags)}")
		
		asm_source.write(f"""
	xor	eax, eax
	mov	al, sys_mprotect
	lea	rdi, [rel imagebase + 0x{start:x}]
	mov	rsi, 0x{length:x}
	mov	rdx, {flags_to_prot(flags)}
	syscall
""")

	image_file = tempfile.NamedTemporaryFile("wb+")
	image_file.write(mapper.mem)
	image_file.flush()

	asm_source.write(f"""

	push	0 ; possibly unnecessary stack alignment

	push	0
	push	AT_NULL

	push	0x{elf.header.e_phentsize:x}
	push	AT_PHENT

	lea	rax, [rel imagebase] ; ideally this should point to some random bytes... TODO: use rdrand
	push	rax
	push	AT_RANDOM

	lea	rax, [rel imagebase + 0x{elf.header.e_entry:x}]
	push	rax
	push	AT_ENTRY

	push	0x{elf.header.e_phnum:x}
	push	AT_PHNUM

	lea	rax, [rel imagebase + 0x{elf.header.e_phoff:x}]
	push	rax
	push	AT_PHDR

	push	0 ; end envp
	push	0 ; end argv
	push	0 ; argc

	xor	eax, eax
	xor	edi, edi
	xor	esi, esi
	xor	edx, edx

	jmp	imagebase + 0x{elf.header.e_entry:x}



align	0x1000
imagebase:
incbin "{image_file.name}"
""")

	if verbose:
		print()
		print("[+] Shellcode asm source:")
		print()
		print(asm_source.getvalue())

	asm_source_file = tempfile.NamedTemporaryFile("w+")
	asm_source_file.write(asm_source.getvalue())
	asm_source_file.flush()

	out_file = tempfile.NamedTemporaryFile("rb+")
	os.system(f"nasm {asm_source_file.name} -o {out_file.name}")
	shellcode_out_file.write(out_file.read())

	# useful for testing
	#os.system(f"nasm {asm_source_file.name} -f elf64 -o shellcode.o && gcc shellcode.o -o shellcode.elf -nostdlib -static-pie")


if __name__ == "__main__":
	import sys

	elf_to_shellcode(open(sys.argv[1], "rb"), open(sys.argv[2], "wb"))
