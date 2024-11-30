### Paragraph

Challenge code:

```c
#include <stdio.h>

int main() {
  char name[24];
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);

  printf("\"What is your name?\", the black cat asked.\n");
  scanf("%23s", name);
  printf(name);
  printf(" answered, a bit confused.\n\"Welcome to SECCON,\" the cat greeted %s warmly.\n", name);

  return 0;
}
```

checksec output:
```
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
```

There is an obvious format string vulnerability.

We overwrote GOT entry `printf` with scanf, so next `printf` is going to load our payload to the `name` variable which lives on stack. All we need to do is to ensure that our payload message matches format that `scanf` expets. This allowed us to perform a ROP to leak libc address and call main again. Using the same technique we did ROP to call `system` with `/bin/sh` as an argument.

We overwrote the GOT entry for `printf` with `scanf`, so the next call to `printf` will load our payload into the name variable, which resides on the stack. All we need to do is ensure that our payload matches the format expected by `scanf`. This allowed us to perform a ROP attack to leak the libc address and call main again. Using the same technique, we performed another ROP attack to call `system` with `/bin/sh` as an argument.

[solve.py source](https://github.com/rivit98/ctf-writeups/blob/master/2024/seccon/Paragraph/solve.py)
