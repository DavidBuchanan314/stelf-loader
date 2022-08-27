from elf_to_shellcode import elf_to_shellcode
from assembler import nasm, ASM_HEADER
import base64
import gzip
import io

"""
def read_n_bytes(buf, len):
	while len:
		x = read(buf, len)
		buf += x
		len -= x

"""

def multiline_b64(data):
	return base64.encodebytes(data).decode()

def b64(data):
	return base64.b64encode(data).decode()

def elf_to_stelf(elf_file, out_file, oneliner=False):
	secondary_shellcode = io.BytesIO()
	image, image_base = elf_to_shellcode(elf_file, secondary_shellcode)

	primary_shellcode_src = ASM_HEADER + f"""
_start:
	xor	eax, eax
	mov	al, 0x9    ; mmap(
	{f"mov	rdi, 0x{image_base:x}" if image_base else "xor	edi, edi   ; NULL,"}
	mov	rsi, 0x{len(image):x},
	xor	edx, edx
	mov	dl, PROT_READ | PROT_WRITE
	xor	r10, r10
	mov	r10b, MAP_ANONYMOUS | MAP_PRIVATE {"| MAP_FIXED" if image_base else ""}
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
	compressed_secondary_shellcode = gzip.compress(image)

	if oneliner:
		raise Exception("This used to work but I broke it when trying to make it more portable")
		result = "#!/bin/sh\n"
		result += "sh -c $'read a</proc/self/syscall;"
		result += r"exec 3>/proc/self/mem 4<<EOF\nblah\nEOF\n"
		result += "cat /dev/fd/4 >/dev/null;"
		result += f"echo {b64(compressed_secondary_shellcode)}|base64 -d|gunzip - >/dev/fd/4 & "
		result += f"echo {b64(primary_shellcode)}|base64 -d|dd status=none bs=1 seek=$(($(echo $a|cut -d\  -f9)))>&3'\n"
	else:
		result = f"""\
#!/bin/sh

read a </proc/self/syscall
exec 3>/proc/self/mem 4<<EOF
blah
EOF
cat /dev/fd/4 >/dev/null
(base64 -d <<EOF | gunzip -) >/dev/fd/4 &
{multiline_b64(compressed_secondary_shellcode)}EOF
base64 -d <<EOF | dd status=none bs=1 seek=$(($(echo $a|cut -d\  -f9))) >&3
{multiline_b64(primary_shellcode)}EOF
"""

	#print(result)

	out_file.write(result)

if __name__ == "__main__":
	import sys

	elf_to_stelf(open(sys.argv[1], "rb"), open(sys.argv[2], "w"), len(sys.argv) == 4 and sys.argv[3] == "oneliner")
