from elf_to_shellcode import elf_to_shellcode
from assembler import nasm, ASM_HEADER
import base64
import gzip
import io


def multiline_b64(data):
	return base64.encodebytes(data).decode()

def b64(data):
	return base64.b64encode(data).decode()

def elf_to_stelf(elf_file, out_file, argv=[b"X"], oneliner=False, raw_entry=False, verbose=True):
	image, image_base = elf_to_shellcode(elf_file, argv=argv, raw_entry=raw_entry, verbose=verbose)

	primary_shellcode_src = ASM_HEADER + f"""
_start:
	xor	eax, eax
	mov	al, 0x9    ; mmap(
	{f"mov	rdi, 0x{image_base:x}" if image_base else "xor	edi, edi   ; NULL,"}
	mov	rsi, 0x{len(image):x},
	xor	edx, edx
	mov	dl, PROT_READ | PROT_WRITE
	xor	r10, r10
	mov	r10b, MAP_ANONYMOUS | MAP_PRIVATE{" | MAP_FIXED" if image_base else ""}
	xor	r8, r8
	not	r8,        ; fd=-1,
	xor	r9, r9     ; offset=0 )
	syscall

	mov r15, rax
	mov r14, rsi
	mov	rdx, rsi
	mov rsi, rax

	xor	edi, edi
	mov	dil, 4 ; fd=4

readloop:
	xor	eax, eax   ; read(rdx=4, rsi=buf, rdx=len)
	syscall

	test	rax, rax
	js	readloop

	add	rsi, rax
	sub	rdx, rax
	jnz	readloop

readloop_done:
	xor	eax, eax
	mov	al, sys_mprotect
	mov	rdi, r15
	mov	rsi, r14
	xor	edx, edx
	mov	dl, PROT_READ | PROT_EXEC
	syscall

	jmp	r15
"""

	#open("tmp.asm", "w").write(primary_shellcode_src)
	primary_shellcode = nasm(primary_shellcode_src)
	compressed_secondary_shellcode = gzip.compress(b"X" + image)

	result = f"""\
#!/bin/sh

read a </proc/self/syscall
exec 3>/proc/self/mem 4<<EOF 5>/dev/null
A
EOF
tail -c+$(($(echo $a|cut -d\  -f9)+1)) <&3 2>&5
base64 -d<<EOF|gunzip >/dev/fd/4 &
{multiline_b64(compressed_secondary_shellcode)}EOF
head -c3 <&4 >&5
base64 -d<<EOF >&3
{multiline_b64(primary_shellcode)}EOF
"""

	if oneliner:
		result = f"echo {b64(gzip.compress(result.encode()))}|base64 -d|gunzip|/bin/sh\n"

	#print(result)

	out_file.write(result)

if __name__ == "__main__":
	import argparse

	parser = argparse.ArgumentParser("elf_to_stelf")
	parser.add_argument("elf")
	parser.add_argument("dest")
	parser.add_argument("-r", "--raw_entry", action="store_true")
	parser.add_argument("-o", "--oneliner", action="store_true", help="wrap everything as a oneliner")
	parser.add_argument("-v", "--verbose", action="store_true")
	parser.add_argument("-a", "--argv", action="append", default=[], help="args to be passed to argv (can be repeated)")

	args = parser.parse_args()

	with open(args.elf, "rb") as elf:
		with open("/dev/stdout" if args.dest == "-" else args.dest, "w") as dest:
			elf_to_stelf(elf, dest, argv=[x.encode() for x in args.argv], oneliner=args.oneliner, raw_entry=args.raw_entry, verbose=args.verbose)
