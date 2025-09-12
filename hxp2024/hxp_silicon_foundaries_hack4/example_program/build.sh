#!/bin/sh

nasm -f elf64 ai.s -o ai.o
#gcc -static -Os -o example main.c ai.o
#gcc -static -Os -o exploit exploit.c ai.o -Wl,-Tscript.ld

zig build-exe -O ReleaseSmall -fstrip -fsingle-threaded -target x86_64-linux-musl --library c ai.o exploit.c
zig build-exe -O ReleaseSmall -fstrip -fsingle-threaded -target x86_64-linux-musl --library c ai.o crash.c
