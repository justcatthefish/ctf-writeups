# hxp_silicon_foundaries_hack4 from hXP 2024

This is disconnect3d's solution to the hxp\_silicon\_foundaries\_hack4 challenge from HXP 2024 CTF created by sisu.

**The original challenge was hosted in [here](https://2024.ctf.link/internal/challenge/6b7ff9d7-efc9-47fc-a06e-4ab9ae6d9eaa/). The authors/organizers solution writeup can be found at [https://hxp.io/blog/120/hxp-38C3-CTF-hack4/](https://hxp.io/blog/120/hxp-38C3-CTF-hack4/).**

**The raw challenge files can be found here: [../raw-challenge-files-hxp_silicon_foundaries_hack4-7786be6f6ac42883.tar.xz](../raw-challenge-files-hxp_silicon_foundaries_hack4-7786be6f6ac42883.tar.xz).**

I (disconnect3d) gave a talk about this challenge. Slides can be found [here](https://docs.google.com/presentation/d/1u0koAAJ5ssjVOY-DLt2h9GOqInNxfFHZ98Ld8nti_O4).

To see our exploit in action, do `./run.sh` and then `nc localhost 8010` -> and run `./e` to run the exploit.

Please modify the `example_program/exploit.c` before that. This also requires `zig` installed since the exploit is build using zig.

TL;DR in this challenge they added a "scratch space" memory and new instructions (JITted by QEMU TCG) to operate on "slices" located in this scratch space memory. The scratch space addresses are translated from virtual to physical in the modified `x86_cpu_tlb_fill` function when a special added `access_enabled` cpu bit is on. This bit is enabled only for the execution of special instructions. The user can also set the virtual address for the scratch space.


## Bugs

There are at least two bugs here:

1. The scratch memory space initialization in QEMU sets it so that a `scratch` buffer located on the stack is set up as a backing memory for the scratch space:
```c
uint16_t scratch[AI1337_SCRATCH_SIZE];
...
memory_region_init_ram_ptr(env->scratch_region, NULL, "ai1337-scratch", AI1337_SCRATCH_SIZE, scratch);
```
Since a stack pointer is set as a backing store, this is a kind of "use after free" situation (just on the stack). However, the initial size of the scratch space (its slices num and size) is too small for us to actually overwrite the part of stack QEMU is using when emulating our VM (after initialization). Simply, the QEMU stack (RSP register) is far away from `scratch[...]` buffer we can overwrite with the size limitation.

2. The newly added instructions do not restore the `access_enabled` bit if they crash in the middle of execution. And we can trigger a crash by executing those instructions on an address that is unmapped. This segfaults our process, but `access_enabled` is not restored.

## Exploit TL;DR

Stage 1:
- Enable the "access enabled" scratch space bit
- Set scratch virtual address to busybox address
- Crash process => so busybox executes its code and our shellcode

Stage 2:
- We are now uid=0
- Use MSR to increase scratch space
- Read stack memory to leak some addresses
- Overwrite stack memory to pwn the QEMU return address and prepare ROP payload with `system(our_command)` call
- Trigger an exit of QEMU to execute arbitrary code and get out the flag

Note: Busybox - pid 1 process that runs as root (uid 0) has no PIE, so we know the address it runs on:

```
user@user:~/hxp/hxp_silicon_foundaries_hack4/unpacked/bin$ pwn checksec busybox
[*] '/home/user/hxp/hxp_silicon_foundaries_hack4/unpacked/bin/busybox'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
```
