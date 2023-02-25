# stelf-loader
A stealthy ELF loader - no files, no execve, no RWX

See also: [arget13/DDexec](https://github.com/arget13/DDexec), which is a similar idea to this but probably more flexible - I wrote most of `stelf-loader` before I realised that `DDexec` existed!

Here's a simple "hello world" ELF (`test_elfs/syscall-static-pie.c`), packed using stelf-loader:

```sh
$ python3 elf_to_stelf.py test_elfs/syscall-static-pie - -r
#!/bin/sh

read a </proc/self/syscall
exec 3>/proc/self/mem 4<<EOF 5>/dev/null
A
EOF
cat /dev/fd/4 >&5
tail -c+$(($(echo $a|cut -d\  -f9)+1)) <&3 2>&5
base64 -d<<EOF|gunzip >/dev/fd/4 &
H4sIAMd7+mMC/+3ZP0vDQBjH8SdtEkqX9B30dG6pHQQH/y1KBhdfQkkjBgKKCYiTr6DQd+Bb6Fg6
qODgu3Bz0L2z5pqeXASLi6jw/Qx5eH7ccwe3HenfT5rhaGceiNxKS2TmiEjg9cv4qW1iz44feyYW
O57smbi+iF9uivExAAAAAAD4bdcHR4c1Rz/6S3XZlUXXKvv9ZR6qjyVFtiV+8XWL1XqtK18bO9Vq
9tWtZ/Wf67pUqz3n2vspWc2a8+31G9XalWo1czUzZ47rrT6usazHz/nQl+9rCAAAAAAAP2eqH8Z3
+jPr6Gf+aPO1rf/dT7eLrv8WeA/cEQAAAAAAAAAAAAAAf10Yp+lZR2X5IE+i7nkSqzg9UZdJfqqG
yUUc5Sq7yqJBmmZrTW4LAAAAAID/6R2QbjDaAFAAAA==
EOF
base64 -d<<EOF >&3
McCwCTH/vgBQAAAx0rIDTTHSQbIiTTHASffQTTHJDwVJicdJifZIifJIicYx/0C3BDHADwVIhcB4
90gBxkgpwnXvMcCwCkyJ/0yJ9jHSsgUPBUH/5w==
EOF
```

You could put this in a file and execute it, but that would slightly defeat the
purpose (of being file-less). The intended usage scenario is to paste it directly into a terminal,
or perhaps even `curl | sh` or `nc | sh`. The aim is to be as portable as possible between different shell implementations. So far I've tested it against `bash`, `zsh`, `dash`, and `busybox ash`.

This implementation currently relies on some hand-written x86-64 shellcode, but the
general approach should be applicable cross-architecture.

It works on both `static` and `static-pie` ELFs. However, dynamic ELFs are out of scope for this project.

`static-pie` ELFs are recommended, to ensure that the address space does not collide with that of the loader process.

## Shell-based self-injecting shellcode loader

This technique has a slightly complicated history, with some "multiple discovery" going on - multiple people working independently had similar ideas, with improvements over time. I will try to present the concepts in chronological order, with attribution where possible.

Before ASLR/PIE was widely implemented, somebod{y,ies} realised that the `dd` binary could be used to inject code into its own address space, by writing to `/proc/self/mem`, making use of the `seek` argument to seek to the correct offset within the `mem` file to point into some executable code, which would subsequently be executed.

An example of this can be seen in brainsmoke's [tweet](https://twitter.com/brainsmoke/status/399558997994668033) here:

```sh
base64 -d<<<aExPTApUXmoEagFqAl9YWg8F|dd seek=1 bs=$((`objdump -d /*/dd|grep ll.*\<w|sed 's/\([0-9a-f]\+\):.*/0x\1+5/'`)) of=/proc/self/mem
```

### Parallel idea 1:

To account for PIE, `brainsmoke` came up with the idea of injecting into the shell process, as opposed to `dd` itself. Since the shell process stays running for the duration, we can dynamically "leak" pointers from various `/proc/<pid>/*` entries, and use that to know where to inject the code, thus "bypassing" ASLR. `dd` does not have permission to open the parent shell's `mem` file, and so clever fd redirection was used to get the shell itself to open the fd, to be passed into `dd`.

Example ([source](https://twitter.com/brainsmoke/status/1258875830014480386))

```sh
cd /proc/$$;exec 3>mem;(base64 -d<<<MdtoL2JpbkiJ54FvBNGMl/9qLcZH+WNIieBTSIni6w5QSI1ADVBIieaNQzsPBejt////L2Jpbi9iYXNoAADrwA==;yes $'\xeb\xfc'|tr -d '\n')|dd bs=1 seek=$((0x$(grep vdso -m1 maps|cut -f1 -d-)))>&3
```

### Parallel idea 2:

Independently, `arget13` had the idea of using `dd` to do something similar to the base technique which he called [DDexec](https://github.com/arget13/DDexec). However, not realising that `mem` allows writing to read-only pages, he came up with a wonderfully complex mechanism for injecting a ROP payload, all implemented through shell scripting.

### Parallel idea 3:

I was vaguely aware of `brainsmoke`'s technique, having seen it mentioned on IRC several years prior. However, I couldn't remember how it worked exactly, and so I tried to reinvent it myself. I came up with [this](https://twitter.com/David3141593/status/1386438123647868930)

```sh
dd of=/proc/$$/mem bs=1 seek=$(($(cut -d" " -f9</proc/$$/syscall))) if=<(base64 -d<<<utz+IUO+aRkSKL+t3uH+McCwqQ8F) conv=notrunc
```

Rather than parsing objdump output to find a good place to inject, I read from `/proc/<pid>/syscall` and parsed out the value of the program counter register - which is inevitably pointing into some executable code.

As-is, this technique was suboptimal, since it requires `dd` to be allowed to open the `mem` file of the parent process (which only happens if `dd` is run as root, or Yama is disabled).

### Merging of the streams

After I posted about my variant of the technique, brainsmoke pointed out his fd redirection trick, which I was able to incorporate back into my technique, giving the "best of both worlds" - no need for parsing `objdump` output, and no need for root or disabled Yama.

`arget13` saw the conversation, and incorporated the `syscall` technique into his `DDexec` tool. He also ditched his complex ROP generation code in favour of directly overwriting executable code.

I wasn't aware of `DDexec` at the time, and I started writing my own tool along the same lines, which I called `stelf-loader` (this tool!) - but at this point in time I hadn't published it.

After writing most of `stelf-loader`, I found `DDexec` and facepalmed - it was basically everything I set out to do with `stelf-loader`, and more. However, `stelf-loader` still does something that `DDexec` doesn't - `stelf-loader` is written in Python as opposed to shell scripting, and instead *generates* shell scripts (or one-liners) as output. The generated shell scripts are potentially very compact and can be pasted directly into a terminal session, whereas `DDexec` requires the (relatively) large ddexec shell script to be dropped onto the system first (you could work around this, but it would still take up more space).

Around 12/12/2022, `arget13` discovered that several other common utilities other than `dd` could be used to seek the file descriptor, one of those alternatives being `less`. `less` is of course more commonly installed and executed than `dd`, making the overall technique more portable and less eyebrow-raising.

After noticing this change to `DDexec`, I updated `stelf-loader` to also use `less` for seeking.

In its current form, `stelf-loader` combines:

- "The" `/proc/<pid>/mem` shellcode injection.
- brainsmoke's fd redirection technique.
- My own `/proc/<pid>/syscall` program counter "leak" technique.
- arget13's `less`-seeking technique (as a sneakier alternative to `dd`)

## `elf_to_shellcode.py`

This is usable as a standalone script. It flattens a static
ELF into a piece of shellcode. This is very similar to what [gamozolabs/elfloader](https://github.com/gamozolabs/elfloader) does,
except it also generates a shellcode stub that sets up the correct page permissions. (If I was rewriting this project today, I'd use `elfloader` to do the ELF parsing, but writing my own was an interesting educational exercise.)
This avoids needing RWX mappings.

## `elf_to_stelf.py`

This script ties together all the aforementioned tricks. It takes a static-pie ELF as input, and outputs a (potentially extremely long) sequence of shell commands.

## TODO

- argv passthru
- mmap and pivot to a fresh stack
- add more options to `elf_to_shellcode.py`
