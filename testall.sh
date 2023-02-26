#!/bin/bash

set -euo pipefail

echo
echo
echo === syscall-static-pie ===
python3 elf_to_stelf.py test_elfs/syscall-static-pie out.sh -r
echo

echo sh:
sh ./out.sh
echo
echo ash:
ash ./out.sh
echo
echo bash:
bash ./out.sh
echo
echo dash:
dash ./out.sh
echo
echo zsh:
zsh ./out.sh
echo

echo
echo === glibc-static-pie ===
python3 elf_to_stelf.py test_elfs/glibc-static-pie out.sh -a hello -a world
echo

echo sh:
sh ./out.sh
echo
echo ash:
ash ./out.sh
echo
echo bash:
bash ./out.sh
echo
echo dash:
dash ./out.sh
echo
echo zsh:
zsh ./out.sh
echo

echo
echo === oneliner === 
python3 elf_to_stelf.py test_elfs/syscall-static-pie out.sh -r -o
echo
wc -c out.sh
echo
./out.sh
echo