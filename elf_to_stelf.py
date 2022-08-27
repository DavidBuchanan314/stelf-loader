from elf_to_shellcode import elf_to_shellcode
from assembler import nasm, ASM_HEADER
import base64
import gzip
import io



def multiline_b64(data):
	return base64.encodebytes(data).decode().replace("\n", "\\\n")

def b64(data):
	return base64.b64encode(data).decode()

def elf_to_stelf(elf_file, out_file, oneliner=False):
	secondary_shellcode = io.BytesIO()
	image_base = elf_to_shellcode(elf_file, secondary_shellcode)
	secondary_shellcode = secondary_shellcode.getvalue()
	sc_base = image_base - 0x1000

	# TODO: simplify this shellcode - we already know the length in advance
	primary_shellcode_src = ASM_HEADER + f"""
_start:
	xor	eax, eax
	mov	al, 0x9    ; mmap(
	{f"mov	rdi, 0x{sc_base:x}" if image_base else "xor	edi, edi   ; NULL,"}
	mov	esi, 1<<30 ; 1GiB,
	xor	edx, edx   ; PROT_NONE,
	xor	r10, r10
	mov	r10b, 0x{0x32 if image_base else 0x22 :x}  ; MAP_ANONYMOUS | MAP_PRIVATE,
	xor	r8, r8
	not	r8,        ; fd=-1,
	xor	r9, r9     ; offset=0 )
	syscall

	mov	r15, rax  ; r15 stores the buffer base pointer
	mov	r14, rax  ; r14 stores the write pointer
	mov	r12, 0x1000 ; constant 0x1000

mainloop:
	xor	eax, eax
	mov	al, 0x9   ; mmap(
	mov	rdi, r14
	mov	rsi, r12
	mov	dl, PROT_READ | PROT_WRITE
	mov	r10b, 0x32  ; MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,
	syscall

	xor	r13, r13 ; r13 tracks bytes read out of the 0x1000 byte block

readloop:
	xor	eax, eax   ; read(
	xor	edi, edi   ;
	mov	dil, 4 ; fd=4
	mov	rsi, r14   ; buf,
	add	rsi, r13
	mov	rdx, r12   ; len
	sub	rdx, r13
	syscall

	add	r13, rax
	and	eax, eax
	jz	done

	cmp	r13, r12
	jne	readloop

readloop_done:
	add	r14, r13
	jmp	mainloop

done:
	xor	eax, eax
	mov	al, sys_mprotect
	mov	rdi, r15
	mov	rsi, r12
	mov	rdx, PROT_READ | PROT_EXEC
	syscall

	jmp	r15
"""

	primary_shellcode = nasm(primary_shellcode_src)
	compressed_secondary_shellcode = gzip.compress(secondary_shellcode)

	if oneliner:
		result = "#!/bin/sh\n"
		result += "bash -c 'read a</proc/self/syscall;"
		result += f"exec 3>/proc/self/mem 4< <(echo {b64(compressed_secondary_shellcode)}|base64 -d|gunzip -);"
		result += f"base64 -d<<<{b64(primary_shellcode)}|dd status=none bs=1 seek=$[`cut -d\  -f9<<<$a`] >&3'\n"
	else:
		result = f"""\
#!/bin/bash

read a </proc/self/syscall
exec 3>/proc/self/mem 4< <(echo \\
{multiline_b64(compressed_secondary_shellcode)} | base64 -d | gunzip -)
echo \\
{multiline_b64(primary_shellcode)} | base64 -d | dd status=none bs=1 seek=$[`cut -d\  -f9<<<$a`] >&3
"""

	#print(result)

	out_file.write(result)

if __name__ == "__main__":
	import sys

	elf_to_stelf(open(sys.argv[1], "rb"), open(sys.argv[2], "w"), len(sys.argv) == 4 and sys.argv[3] == "oneliner")
