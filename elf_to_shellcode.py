from elftools.elf.elffile import ELFFile
from assembler import nasm, ASM_HEADER
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
		self.base = base
	
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
		pad_len = -len(self.mem) % self.align
		self.mem += bytearray(pad_len)
		self.flags += [0] * (pad_len)
	
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

def elf_to_shellcode(elf_file, argv=[b"X"], raw_entry=False, verbose=True):
	argv_buf = b""
	argv_offsets = []
	for arg in argv:
		argv_offsets.append(len(argv_buf))
		argv_buf += arg + b"\0"

	elf = ELFFile(elf_file)
	asm_source = io.StringIO()
	asm_source.write(ASM_HEADER + "\n_start:\n")

	image_base = min(seg.header.p_vaddr for seg in elf.iter_segments() if seg.header.p_type == "PT_LOAD")

	if verbose:
		print("[+] ELF Image base: ", hex(image_base))
		print("[+] ELF Entry: ", hex(elf.header.e_entry))
		print()
		print("[+] ELF segments:")
		print("\tType             Offset     VAddr      FileSize   MemSize    Prot")
	
	mapper = Mapper(base=image_base)

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
		
		# TODO: have the loop in ASM, reading from a table?
		asm_source.write(f"""
	xor	eax, eax
	mov	al, sys_mprotect
	lea	rdi, [rel imagebase + 0x{start - image_base:x}]
	mov	rsi, 0x{length:x}
	mov	rdx, {flags_to_prot(flags)}
	syscall
""")

	image_file = tempfile.NamedTemporaryFile("wb+")
	image_file.write(mapper.mem)
	image_file.flush()

	if not raw_entry:
		asm_source.write(f"""

	;push	0 ; possibly unnecessary stack alignment
	;push	0x41 ; argv[0]
	;mov		r15, rsp
	push	0 ;alignment

	push	0
	push	AT_NULL

	push	0x{elf.header.e_phentsize:x}
	push	AT_PHENT

	lea	rax, [rel imagebase] ; ideally this should point to some random bytes... TODO: use rdrand
	push	rax
	push	AT_RANDOM

	lea	rax, [rel imagebase + 0x{elf.header.e_entry - image_base:x}]
	push	rax
	push	AT_ENTRY

	push	0x{elf.header.e_phnum:x}
	push	AT_PHNUM

	lea	rax, [rel imagebase + 0x{elf.header.e_phoff:x}]
	push	rax
	push	AT_PHDR

	push	0 ; end envp
	push	0 ; end argv
""")
		if argv:
			asm_source.write(f"""
	lea	rax, [rel argv + {argv_offsets[-1]}]
	push	rax
""")
		for a, b in zip(argv_offsets[-2::-1], argv_offsets[-1::-1]):
			asm_source.write(f"""
	sub	rax, {b - a}
	push	rax
""")
		asm_source.write(f"""
	push	{len(argv)} ; argc

	xor	eax, eax
	xor	edi, edi
	xor	esi, esi
	xor	edx, edx
""")

	asm_source.write(f"""

	jmp	imagebase + 0x{elf.header.e_entry - image_base:x}

""")

	if argv:
		asm_source.write(f"""
argv:
db {', '.join(str(x) for x in argv_buf)}

""")
	
	asm_source.write(f"""
align	0x1000
imagebase:
incbin "{image_file.name}"
""")

	if verbose:
		print()
		print("[+] Shellcode asm source:")
		print()
		print(asm_source.getvalue())

	image = nasm(asm_source.getvalue())

	# useful for testing
	#os.system(f"nasm {asm_source_file.name} -f elf64 -o shellcode.o && gcc shellcode.o -o shellcode.elf -nostdlib -static-pie")

	whole_image_base = image_base + len(mapper.mem) - len(image) if image_base else None

	return image, whole_image_base


if __name__ == "__main__":
	import argparse

	parser = argparse.ArgumentParser("elf_to_shellcode")
	parser.add_argument("elf")
	parser.add_argument("dest")
	parser.add_argument("-r", "--raw_entry", action="store_true", help="Do not put argv/env/auxv on the stack before calling the entrypoint")
	parser.add_argument("-v", "--verbose", action="store_true")
	parser.add_argument("-a", "--argv", action="append", default=[], help="args to be passed to argv (can be repeated)")

	args = parser.parse_args()

	with open(args.elf, "rb") as elf:
		image, image_base = elf_to_shellcode(elf, argv=[x.encode() for x in args.argv], raw_entry=args.raw_entry, verbose=args.verbose)
		with open(args.dest, "wb") as out_file:
			out_file.write(image)
