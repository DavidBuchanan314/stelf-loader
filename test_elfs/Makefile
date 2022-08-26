all: glibc-static-pie syscall-static-pie rust_helloworld

glibc-static-pie: glibc-static-pie.c
	gcc glibc-static-pie.c -o glibc-static-pie -static-pie -s

syscall-static-pie: syscall-static-pie.c
	gcc syscall-static-pie.c -o syscall-static-pie -nostdlib -static-pie -s

rust_helloworld: rust_helloworld.c
	rustc --target x86_64-unknown-linux-musl rust_helloworld.rs
