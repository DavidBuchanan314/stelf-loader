# stelf-loader
A stealthy ELF loader - no files, no execve, no RWX

Here's a simple "hello world" ELF (`test_elfs/syscall-static-pie.c`), packed using stelf-loader:

```sh
#!/bin/sh

read a </proc/self/syscall
exec 3>/proc/self/mem 4<<EOF
blah
EOF
cat /dev/fd/4 >/dev/null
(base64 -d <<EOF | gunzip -) >/dev/fd/4 &
H4sIAAxYCmMC/+3bz2vTYBgH8Ddts83OrgUrTCYzggeF6dbbQPejaGcGMuakeHHi6Co2FCZr5y8U
PYlh1M2/QC+iN3dRxsRtMHAeRQ/Oi/Qy3GDiQKZj4uLzJm9cEi0WfxzE76ekT97nfd73LUkuaUhs
eiyoFlpWwoxNsghjExJjLCzHrPSbHXZadqZnG39YPdbG0wql/WZai3fqbzVmfpq1gFqQb9Iy3do2
2tui8L1NWrUmU+uRmffzyvhxTYpNx4zYx9iLxXe0/igAAAAAAAAA/KariSMdPonfxlv8rJXx1kjE
areLfLHpWwnlmlk1fdewkFkbYKXt8bsjE/PycbKj7Y1PmDs6x5nrKSLviXeYOzrHVfCyRlHe5o4h
cQhqJfc430/GFZk7VokYENt9n9X2Ru/P9457Juq8cRdzR/vYH5vP9//Ket1iXKnjWWq9ozSugpXP
Pr09Yr1yj6fkWDcirpnDXUl+XqYD5vW60R8Vbd5/clJ6fLfy3uCNvpe++PrD24da15rs+STHvAAA
AAAAAP+LpKrP61eWhhNLaur5+AHKqPqrsKzqiVV1mLYWtmwY56J8/9OcLn+h2zZ1NrFqEJ7rnRET
qPpQUdWTc+ZENHSoOM5vsdTh5Fzp2R58N9uHcP0an3GigQ8uyL28Qn86xedauEVlU/xHL3TQ3mjv
DE4fAAAAAAAAQFmkOv9+/mzXfI5KN+ftFOIUT1EcoXhN1EXt+ks9TLoQkeo2V1aN0l35dmZt4+8N
I84L4jWR676DoYrLVCD6+L8Kr6m/y9nv6zQLeP8J2ipprX28PyH609Z4AAAAAAAAAAAAAAAAAACA
P2Fl3RjgcVm8Ry2L/G7x4rH9DnREtIOibb9fXC1irYhbPfPXi2g/6/5sWOtJG6m/Sk1nswMNSi7f
l8+k9p7NpJV09rRyPpM/o/RnBtOpvJK7mEv1ZbO5nUFcDQAAAAAAAAD/pq/zmqTTAGAAAA==
EOF
base64 -d <<EOF | dd status=none bs=1 seek=$(($(echo $a|cut -d\  -f9))) >&3
McCwCTH/vgBgAAAx0rIDTTHSQbIiTTHASffQTTHJDwVJicdJifZIifJIicYx/0C3BDHADwVIAcZI
KcJ19DHAsApMif9MifYx0rIFDwVB/+c=
EOF
```

You could put this in a file and execute it, but that would slightly defeat the
purpose. The intended usage scenario is to paste it directly into a terminal,
or perhaps even `curl | sh` or `nc | sh`.

This implementation currently relies on some hand-written x86-64 shellcode, but the
general approach should be applicable cross-architecture.

It works on both `static` and `static-pie` ELFs. However, dynamic ELFs are out of scope for this project.

## Bash self-injecting shellcode loader

Using some clever tricks (TODO: explain), we instruct Bash to
load some shellcode into itself, ultimately using `dd` to write to `/proc/self/mem`.
We inject a small fragment of shellcode, which in turn loads a much larger piece
of shellcode. The larger shellcode is generated by...

## `elf_to_shellcode.py`

This is usable as a standalone script. It flattens a static-pie
elf into a piece of shellcode. This is similar to what [gamozolabs/elfloader](https://github.com/gamozolabs/elfloader) does,
except it also generates a shellcode stub that sets up the correct page permissions.
This avoids needing RWX mappings.

## `elf_to_stelf.py`

This script ties together all the aforementioned tricks. It takes a static-pie ELF as input, and outputs a (potentially extremely long) bash one-liner.

## TODO

- mmap and pivot to a fresh stack
- add more options to `elf_to_shellcode.py`
