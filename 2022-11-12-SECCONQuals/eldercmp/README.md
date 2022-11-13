# eldercmp

Description: `baby_mode = 0`

Download: https://drive.google.com/file/d/1aFLFMNiTRElH5hOOq8wIFg8gXWsjQIEm/view?usp=drivesdk

## Decompilation

The difference between this challenge and `babycmp` in theory is only a single byte, but it's actually a flag, that completely changes what the binary does. There is a function called `_detect_debugger` in the init method table, which is called before the `main` function begins execution.

This function looks as follows (decompilation using IDA Pro):
```
unsigned __int64 _detect_debugger()
{
  signed __int64 v1; // rax
  signed __int64 v2; // rax
  struct sigaction v3; // [rsp+0h] [rbp-A8h] BYREF
  unsigned __int64 v4; // [rsp+98h] [rbp-10h]

  v4 = __readfsqword(0x28u);
  if ( !baby_mode )
  {
    v3.sa_flags = 4;
    sigemptyset(&v3.sa_mask);
    v3.sa_handler = (__sighandler_t)trampoline;
    sigaction(11, &v3, 0LL);
    v1 = sys_arch_prctl((struct task_struct *)(unsigned int)&loc_1012, 0, (unsigned __int64 *)&loc_1012);
    v2 = sys_arch_prctl(
           (struct task_struct *)((unsigned int)init_proc + 1),
           (int)heart,
           (unsigned __int64 *)((char *)init_proc + 1));
  }
  return v4 - __readfsqword(0x28u);
}
```

It sets a signal handler, followed by `arch_prctl(0x1012, 0)` and `arch_prctl(0x1001, heart)`. IDA unfortunately incorrectly specifies the type of the first parameter, so the numbers were taken out of assembly. The relevant PRCTL numbers can be found in the `arch/x86/include/uapi/asm/prctl.h` file in the kernel and the meaning of these can be found in `arch_prctl(2)` manpage (online version: https://man7.org/linux/man-pages/man2/arch_prctl.2.html).

The codes we will need in this challenge map to the following names:
- `0x1012` - `prctl(ARCH_SET_CPUID, enabled)` - sets whether the process can use the CPUID instruction
- `0x1001` - `prctl(ARCH_SET_GS, addr)` - sets the `gs` register for the current process
- `0x1004` - `prctl(ARCH_GET_GS, addr)` - retrieves the `gs` register for the current process and saves it into `*addr`

`_detect_debugger` therefore sets the SIGSEGV signal handler to `trampoline`, disables the CPUID instruction for the process and sets `gs` to the address of the heart function. The `main` function used a `cpuid` instruction immediately loading the input flag parameter into `rdi`, therefore this `trampoline` signal handler will be invoked at that point.

The annotated decompilation for `trampoline` is as follows:
```
char *__fastcall trampoline(__int64 a1, __int64 a2, ucontext_t *a3)
{
  unsigned __int64 *v4; // rdx
  char *result; // rax
  signed __int64 v6; // rax
  __int64 v7; // rdx
  _QWORD *v8; // rax
  const char *v9; // r14
  _QWORD *v10; // r13
  size_t v11; // rbp
  size_t v12; // r12
  char *v13; // rax

  v4 = (unsigned __int64 *)a3->uc_mcontext.gregs[16];// RIP
  result = (char *)*(unsigned __int8 *)v4;
  if ( (_BYTE)result == 0xF4 )                  // Instruction: F4 hlt
  {
    a3->uc_mcontext.gregs[16] = (greg_t)v4 + 1;
    return result;
  }
  if ( (_BYTE)result != 0xF )
    goto LABEL_11;
  a3->uc_mcontext.gregs[15] &= 0xFFFFFFFFFFFFFFF0LL;// RSP
  v6 = sys_arch_prctl((struct task_struct *)&loc_1004, (int)a3 + 168, v4);// ARCH_GET_GS
  result = (char *)*(unsigned __int8 *)(v7 + 1);
  if ( (_BYTE)result != 0xA2 )
  {
    if ( (_BYTE)result == 6 )                   // Instruction: 0F 06 clts
      return result;
LABEL_11:
    exit(1);
  }
  v8 = malloc(0x1A0uLL);                        // Instruction: 0F A2 cpuid
  v9 = (const char *)a3->uc_mcontext.gregs[8];  // RDI
  v10 = v8;
  v11 = strlen(v9);
  v12 = (unsigned __int8)(v11 + 8) & 0xF8;
  v13 = (char *)malloc(v12);
  *v10 = v13;
  result = strcpy(v13, v9);
  if ( v11 < v12 )
  {
    result[v11] = v12 - v11;
    result = (char *)(v11 + 1);
    if ( v12 > v11 + 1 )
    {
      do
        (result++)[*v10] = v12 - v11;
      while ( (char *)v12 != result );
    }
  }
  v10[1] = v12;
  a3->uc_mcontext.gregs[8] = (greg_t)v10;       // RDI
  return result;
}
```

This function handles three instructions:
- `hlt` - simply skips it by setting `rip = rip + 1` and continues execution
- `clts` - aligns the stack and sets `rip = gs`
- `cpuid` - aligns the stack, sets `rip = gs`, pads the string in `rdi` using PKCS-like padding (n bytes, each with the value set to n), and sets `rdi` to a 0x1A0 structure containing the padded string in `+0` and the string length in `+8`.

This means that the `cpuid` instruction diverts the control flow into the value of `gs` register, which is set to the `heart` method. Which in turn doesn't decompile as it ends with a `clts` instruction, which is not allowed in user mode! This means these first two handled instructions are used for obfuscation and need to be replaced.

I switched to Binary Ninja at this point, as I prefer it to IDA for this sort of challenges and started patching.
