### Make ROP Great Again

Challenge source:

```c
// gcc mrga.c -fno-stack-protector -fno-pic -no-pie -Wl,-z,now -o chall
#include <stdio.h>

void show_prompt(void);

__attribute__((constructor))
static int init(){
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);
	return 0;
}

int main(void){
	char buf[0x10];

	show_prompt();
	gets(buf);

	return 0;
}

void show_prompt(void){
	puts(">");
}
```

checksec output:

```
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x3fe000)
```

The challenge clearly contains a visible buffer overflow, but unfortunately, there are no useful `pop; ret`-type gadgets in the binary, making it difficult to leak the libc address. However, there is a gadget that allows us to write to the memory pointed to by the `rbp` address:
```
lea     rax, [rbp+var_10]
mov     rdi, rax
mov     eax, 0
call    _gets
```

`pop rbp; ret` gadget is also available:
```
pop     rbp
retn
```

First thing we do is a stack pivot to bss. Then we call `gets` which internally calls: `_IO_getline`. We overwrote lower 2B of return address from `_IO_getline` to call one-gadget. It was possible because stack was in bss section and we controlled address where `gets` writes to. Such approach needed 1/16 bruteforce on remote.

The first step is a stack pivot to the `.bss` section. Next, we call `gets`, which internally invokes `_IO_getline`. We overwrite the lower 2 bytes of the return address from `_IO_getline` to call a one-gadget. This was possible because the stack was located in the `.bss` section and we had control over the address where `gets` writes.

This approach requires a 1/16 brute-force attempt on the remote server.

[solve.py source](https://github.com/rivit98/ctf-writeups/blob/master/2024/seccon/Make_ROP_Great_Again/solve.py)
