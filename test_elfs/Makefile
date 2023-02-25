all: glibc-static-pie glibc-static syscall-static-pie rust_helloworld

glibc-static-pie: glibc-static-pie.c
	gcc glibc-static-pie.c -o glibc-static-pie -static-pie -s

glibc-static: glibc-static.c
	gcc glibc-static.c -o glibc-static -static -s

syscall-static-pie: syscall-static-pie.c
	gcc syscall-static-pie.c -o syscall-static-pie -nostdlib -static-pie -s -Os -fcf-protection=none -Wl,--build-id=none -fno-exceptions -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-ident
	strip \
		--remove-section=.gnu.hash \
		--remove-section=.dynsym \
		--remove-section=.dynstr \
		--remove-section=.dynamic \
		--remove-section=.eh_frame \
		syscall-static-pie


rust_helloworld: rust_helloworld.rs
	rustc --target x86_64-unknown-linux-musl rust_helloworld.rs
