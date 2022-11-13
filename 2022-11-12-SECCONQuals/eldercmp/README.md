# eldercmp

Description: `baby_mode = 0`

Download: https://drive.google.com/file/d/1aFLFMNiTRElH5hOOq8wIFg8gXWsjQIEm/view?usp=drivesdk

## Initial decompilation

The difference between this challenge and `babycmp` in theory is only a single byte, but it's actually a flag that completely changes what the binary does. There is a function called `_detect_debugger` in the init method table, which is called before the `main` function begins execution.

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

## Patching the obfuscation out

I switched to Binary Ninja at this point, as I prefer it to IDA for this sort of challenges and started patching.

The heart function's disassembly looks as follows:
```
000014a0  f30f1efa           endbr64 
000014a4  4157               push    r15 {var_8}
000014a6  4156               push    r14 {var_10}
000014a8  4155               push    r13 {var_18}
000014aa  4154               push    r12 {var_20}
000014ac  55                 push    rbp {var_28}
000014ad  4889fd             mov     rbp, rdi
000014b0  53                 push    rbx {var_30}
000014b1  4881ec98000000     sub     rsp, 0x98
000014b8  64488b0425280000â€¦  mov     rax, qword [fs:0x28]
000014c1  4889842488000000   mov     qword [rsp+0x88 {var_40}], rax
000014c9  31c0               xor     eax, eax  {0x0}
000014cb  488d1536030000     lea     rdx, [rel sub_1808]
000014d2  e9f0020000         jmp     sub_17c7
```

It seems that the code at `0x17c7` is shared and used to do these jumps. It seems to be roughly equivalent to the following assembly (although it obviously has more side effects):
```
mov  rdi, rbp
and  rsp, 0xFFFFFFFFFFFFFFF0
jmp  rdx
```
The `rbp` register is set to `rdi` in the very beggining of `heart`. Therefore for the initial jump it can be omitted. The stack is probably already aligned, so I think the stack aligning instruction can be skipped.

This means we can replace the code at `000014d2` with a direct jump to the target code (`jmp 0x1808`) and the function that Binary Ninja originally defined at that address can be undefined. Afterwards further use of the `0x17c7` jumping code can be patched the same way with one exception I'll mention later.

Next we encounter a `hlt` instruction at `14e4`. We know these are no-ops, so we can replace all of the `hlt` instructions we encounter with a `nop`.

After performing these replacements I managed to get a decompilation in Binary Ninja, however something was off. There was a `lea  rdi, [rdi+0x196]` instruction at `165e` which I missed and caused further usages of `rdi` to be incorrect. To fix this I did a replacement at address `17c7` to `mov rdi, rbp` (followed by a `jmp 187b` from the earlier patching). The same needs to be done for the `mov rdi` instruction at `1915`, with the `mov rdi, rbp` being added at `1dae`.

This gave us a correct looking decompilation of the entire `heart` function, however the binary seems to crash. This is a non-issue for me however, as we can run the original binary instead and the addresses will still match.

## Code analysis

It is clear that `rdi` holds some sort of structure that holds all the relevant data for this code. We know it's size is `0x1A0` from the trampoline function. I created a structure and started filling out fields.

First of all, at the end of this function we an spot two calls to `puts`. We can notice that the call at `1e83` does `(rdi + 0x21) ^ 0x101010101010101`, and as the value for `rdi + 0x21` is initialized above, we can decode this to be the `Correct!` text. The `puts` at `1e41` prints the `Wrong` (based on `rdi + 0x18`).

This leaves us with a constant table (with a weird zero gap) starting at `0x2a`. The loop at `176a` looks very much like key expansion, since the only data we control in this structure from the flag are the first `16 bytes` (string pointer and string length). Therefore we can deduce that there is a `0x54` byte key at offset `0x2a`, and an expanded key of size `0x120` at offset `0x7e`. I originally wasn't sure if the expanded key isn't of size `0x118` instead, and there being some sort of a checksum or a collapsed key of size `8` at offset `0x196`, however after some more analysis this didn't make that much sense.

This leaves us with only the field at `0x10` being unknown and it's some sort of index for the large loop at the end of the function. Therefore the structure analysis is done:
```
struct MainS __packed
{
    int64_t flag;
    int64_t flagLen;
    int64_t flagOff;
    int64_t wrongText;
    char wrongTextNull;
    int64_t correctText;
    char correctTextNull;
    uint8_t key[0x54];
    uint8_t keyExpanded[0x120];
};
```

This allows us to have a more prettier decompilation:
```
000014a0  int64_t heart(struct MainS* arg1)

000014a4      int64_t r15
000014a4      int64_t var_8 = r15
000014a6      int64_t r14
000014a6      int64_t var_10 = r14
000014a8      int64_t r13
000014a8      int64_t var_18 = r13
000014aa      int64_t r12
000014aa      int64_t var_20 = r12
000014ac      int64_t rbp
000014ac      int64_t var_28 = rbp
000014b0      int64_t rbx
000014b0      int64_t var_30 = rbx
000014c1      void* fsbase
000014c1      int64_t var_40 = *(fsbase + 0x28)
0000180c      int32_t zmm0[0x4] = data_3100.o
00001814      arg1->wrongTextNull = 0
00001829      arg1->wrongText = 0x2f2f2f666f6e7356
00001837      arg1->key[0x10] = zmm0[0].b
00001837      arg1->key[0x11] = zmm0[0]:1.b
00001837      arg1->key[0x12] = zmm0[0]:2.b
00001837      arg1->key[0x13] = zmm0[0]:3.b
00001837      arg1->key[0x14] = zmm0[1].b
00001837      arg1->key[0x15] = zmm0[1]:1.b
00001837      arg1->key[0x16] = zmm0[1]:2.b
00001837      arg1->key[0x17] = zmm0[1]:3.b
00001837      arg1->key[0x18] = zmm0[2].b
00001837      arg1->key[0x19] = zmm0[2]:1.b
00001837      arg1->key[0x1a] = zmm0[2]:2.b
00001837      arg1->key[0x1b] = zmm0[2]:3.b
00001837      arg1->key[0x1c] = zmm0[3].b
00001837      arg1->key[0x1d] = zmm0[3]:1.b
00001837      arg1->key[0x1e] = zmm0[3]:2.b
00001837      arg1->key[0x1f] = zmm0[3]:3.b
0000183b      zmm0 = data_3110.o
00001843      arg1->flagOff = 0
0000184b      arg1->key[0] = zmm0[0].b
0000184b      arg1->key[1] = zmm0[0]:1.b
0000184b      arg1->key[2] = zmm0[0]:2.b
0000184b      arg1->key[3] = zmm0[0]:3.b
0000184b      arg1->key[4] = zmm0[1].b
0000184b      arg1->key[5] = zmm0[1]:1.b
0000184b      arg1->key[6] = zmm0[1]:2.b
0000184b      arg1->key[7] = zmm0[1]:3.b
0000184b      arg1->key[8] = zmm0[2].b
0000184b      arg1->key[9] = zmm0[2]:1.b
0000184b      arg1->key[0xa] = zmm0[2]:2.b
0000184b      arg1->key[0xb] = zmm0[2]:3.b
0000184b      arg1->key[0xc] = zmm0[3].b
0000184b      arg1->key[0xd] = zmm0[3]:1.b
0000184b      arg1->key[0xe] = zmm0[3]:2.b
0000184b      arg1->key[0xf] = zmm0[3]:3.b
0000184f      zmm0 = data_3120.o
00001857      arg1->correctText = 0x2075626473736e42
0000185b      arg1->key[0x30] = zmm0[0].b
0000185b      arg1->key[0x31] = zmm0[0]:1.b
0000185b      arg1->key[0x32] = zmm0[0]:2.b
0000185b      arg1->key[0x33] = zmm0[0]:3.b
0000185b      arg1->key[0x34] = zmm0[1].b
0000185b      arg1->key[0x35] = zmm0[1]:1.b
0000185b      arg1->key[0x36] = zmm0[1]:2.b
0000185b      arg1->key[0x37] = zmm0[1]:3.b
0000185b      arg1->key[0x38] = zmm0[2].b
0000185b      arg1->key[0x39] = zmm0[2]:1.b
0000185b      arg1->key[0x3a] = zmm0[2]:2.b
0000185b      arg1->key[0x3b] = zmm0[2]:3.b
0000185b      arg1->key[0x3c] = zmm0[3].b
0000185b      arg1->key[0x3d] = zmm0[3]:1.b
0000185b      arg1->key[0x3e] = zmm0[3]:2.b
0000185b      arg1->key[0x3f] = zmm0[3]:3.b
0000185f      zmm0 = data_3130.o
00001867      arg1->correctTextNull = 0
0000186b      arg1->key[0x50] = 9
0000186b      arg1->key[0x51] = 0x12
0000186b      arg1->key[0x52] = 0x24
0000186b      arg1->key[0x53] = 0xb
00001872      arg1->key[0x40] = zmm0[0].b
00001872      arg1->key[0x41] = zmm0[0]:1.b
00001872      arg1->key[0x42] = zmm0[0]:2.b
00001872      arg1->key[0x43] = zmm0[0]:3.b
00001872      arg1->key[0x44] = zmm0[1].b
00001872      arg1->key[0x45] = zmm0[1]:1.b
00001872      arg1->key[0x46] = zmm0[1]:2.b
00001872      arg1->key[0x47] = zmm0[1]:3.b
00001872      arg1->key[0x48] = zmm0[2].b
00001872      arg1->key[0x49] = zmm0[2]:1.b
00001872      arg1->key[0x4a] = zmm0[2]:2.b
00001872      arg1->key[0x4b] = zmm0[2]:3.b
00001872      arg1->key[0x4c] = zmm0[3].b
00001872      arg1->key[0x4d] = zmm0[3]:1.b
00001872      arg1->key[0x4e] = zmm0[3]:2.b
00001872      arg1->key[0x4f] = zmm0[3]:3.b
000014d7      uint32_t rax_2 = zx.d(arg1->key[0x10])
000014e3      int32_t var_c4 = rax_2 & 0xf
000014ea      uint32_t var_c8 = zx.d(rax_2.b u>> 4)
000014ee      uint32_t rax_4 = zx.d(arg1->key[0x11])
000014f4      int32_t rax_5 = rax_4 & 0xf
000014fe      uint32_t rdx_3 = zx.d(rax_4.b u>> 4)
00001506      uint32_t rax_6 = zx.d(arg1->key[0x12])
00001512      int32_t var_b4 = rax_6 & 0xf
00001519      uint32_t var_b8 = zx.d(rax_6.b u>> 4)
0000151e      uint32_t rax_8 = zx.d(arg1->key[0x13])
0000152a      int32_t var_ac = rax_8 & 0xf
00001531      uint32_t var_b0 = zx.d(rax_8.b u>> 4)
00001536      uint32_t rax_10 = zx.d(arg1->key[0x14])
00001542      int32_t var_a4 = rax_10 & 0xf
00001549      uint32_t var_a8 = zx.d(rax_10.b u>> 4)
0000154e      uint32_t rax_12 = zx.d(arg1->key[0x15])
0000155a      int32_t var_9c = rax_12 & 0xf
00001561      uint32_t var_a0 = zx.d(rax_12.b u>> 4)
00001566      uint32_t rax_14 = zx.d(arg1->key[0x16])
00001572      int32_t var_94 = rax_14 & 0xf
00001579      uint32_t var_98 = zx.d(rax_14.b u>> 4)
0000157e      uint8_t rax_16 = arg1->key[0x17]
00001584      uint8_t rax_17 = rax_16 & 0xf
00001591      uint32_t var_90 = zx.d(rax_16 u>> 4)
00001596      uint8_t rax_18 = arg1->key[0x18]
0000159c      uint8_t rax_19 = rax_18 & 0xf
000015a9      uint32_t var_88 = zx.d(rax_18 u>> 4)
000015ae      uint32_t rax_20 = zx.d(arg1->key[0x19])
000015b7      uint8_t rdx_18 = rax_20.b u>> 4
000015ba      int32_t var_7c = rax_20 & 0xf
000015c6      uint32_t rax_22 = zx.d(arg1->key[0x1a])
000015d2      int32_t var_74 = rax_22 & 0xf
000015d9      uint32_t var_78 = zx.d(rax_22.b u>> 4)
000015de      uint32_t rax_24 = zx.d(arg1->key[0x1b])
000015ea      int32_t var_6c = rax_24 & 0xf
000015f1      uint32_t var_70 = zx.d(rax_24.b u>> 4)
000015f6      uint32_t rax_26 = zx.d(arg1->key[0x1c])
00001602      int32_t var_64 = rax_26 & 0xf
00001609      uint32_t var_68 = zx.d(rax_26.b u>> 4)
0000160e      uint32_t rax_28 = zx.d(arg1->key[0x1d])
0000161a      int32_t var_5c = rax_28 & 0xf
00001621      uint32_t var_60 = zx.d(rax_28.b u>> 4)
00001626      uint32_t rax_30 = zx.d(arg1->key[0x1e])
00001632      int32_t var_54 = rax_30 & 0xf
00001639      uint32_t var_58 = zx.d(rax_30.b u>> 4)
0000163e      uint8_t rax_32 = arg1->key[0x1f]
00001644      uint8_t rax_33 = rax_32 & 0xf
0000164e      uint32_t rdx_31 = zx.d(rax_32 u>> 4)
00001656      uint8_t (* rax_34)[0x120] = &arg1->keyExpanded
0000165a      uint8_t* rsi = &arg1->key[0x30]
0000165e      uint8_t* rdi = &arg1->keyExpanded[0x118]
0000176a      do
00001e76          (rax_34 - 0x7e)->keyExpanded[0] = rax_33
00001e76          (rax_34 - 0x7e)->keyExpanded[1] = var_58.b
00001e76          (rax_34 - 0x7e)->keyExpanded[2] = rdx_18
00001e76          (rax_34 - 0x7e)->keyExpanded[3] = rax_19
00001e76          (rax_34 - 0x7e)->keyExpanded[4] = rax_17
00001e76          (rax_34 - 0x7e)->keyExpanded[5] = var_98.b
00001e76          (rax_34 - 0x7e)->keyExpanded[6] = rax_5.b
00001e76          (rax_34 - 0x7e)->keyExpanded[7] = rdx_3.b
000016a9          var_c4 = var_c4 ^ zx.d(arg1->key[sx.q(rdx_31)])
000016b7          var_b8 = var_b8 ^ zx.d(arg1->key[sx.q(var_88)])
000016c4          var_6c = var_6c ^ zx.d(arg1->key[sx.q(var_c8)])
000016c8          uint32_t rdx_46 = zx.d((rsi - 0x5a)->key[0x30])
000016d6          var_7c = var_7c ^ zx.d(rdx_46.b u>> 3)
000016da          var_ac = var_ac ^ (rdx_46 & 7)
000016e5          uint32_t rcx_3 = var_c8
000016f8          var_c8.o = var_b8.o
00001703          var_b8.o = var_a8.o
0000170f          var_a8.o = var_98.o
0000171b          var_98.o = var_88.o
00001727          var_88.o = var_78.o
00001733          var_78.o = var_68.o
0000173f          var_68.o = var_58.o
00001755          int32_t temp0_3[0x4] = _mm_unpacklo_epi64(_mm_unpacklo_epi32(var_c4, rdx_3.q), _mm_unpacklo_epi32(rax_5, rcx_3.q)[0].q)
00001759          var_58.o = temp0_3
0000175f          rax_34 = &(*rax_34)[8]
00001763          rsi = &rsi[1]
00001763      while (rax_34 != rdi)
0000177b      arg1->keyExpanded[0x118] = rax_5.b
00001785      arg1->keyExpanded[0x119] = rdx_3.b
0000178f      arg1->keyExpanded[0x11a] = rax_17
00001799      arg1->keyExpanded[0x11b] = var_98.b
000017a3      arg1->keyExpanded[0x11c] = rdx_18
000017ad      arg1->keyExpanded[0x11d] = rax_19
000017b7      arg1->keyExpanded[0x11e] = rax_33
000017c1      arg1->keyExpanded[0x11f] = var_58.b
000017c7      struct MainS* rdi_1 = arg1
00001883      while (true)
00001883          int64_t r13_2 = rdi_1->flagOff + rdi_1->flag
00001888          uint8_t rax_43 = *r13_2
00001895          int64_t rdx_51
00001895          rdx_51.b = rax_43 u>> 4
00001897          rdx_51:1.b = rax_43 & 0xf
0000189a          uint32_t rax_45 = zx.d(*(r13_2 + 1))
000018d7          uint32_t rax_48 = zx.d(*(r13_2 + 2))
00001910          uint32_t rax_51 = zx.d(*(r13_2 + 3))
0000193b          int64_t rdx_63 = (((((((((((rdx_51 & 0xffffffffff00ffff) | zx.q(rax_45.b u>> 4) << 0x10) & 0xffffffff00ffffff) | zx.q(rax_45 & 0xf) << 0x18) & 0xffffff00ffffffff) | zx.q(rax_48.b u>> 4) << 0x20) & 0xffff00ffffffffff) | zx.q(rax_48 & 0xf) << 0x28) & 0xff00ffffffffffff) | zx.q(rax_51.b u>> 4) << 0x30) & 0xffffffffffffff) | zx.q(rax_51 & 0xf) << 0x38
0000193f          uint8_t rax_54 = *(r13_2 + 4)
0000194f          int64_t rcx_14
0000194f          rcx_14.b = rax_54 u>> 4
00001952          rcx_14:1.b = rax_54 & 0xf
00001955          uint32_t rax_56 = zx.d(*(r13_2 + 5))
00001980          uint32_t rax_59 = zx.d(*(r13_2 + 6))
000019a7          uint32_t rax_62 = zx.d(*(r13_2 + 7))
000019ca          int64_t rcx_26 = (((((((((((rcx_14 & 0xffffffffff00ffff) | zx.q(rax_56.b u>> 4) << 0x10) & 0xffffffff00ffffff) | zx.q(rax_56 & 0xf) << 0x18) & 0xffffff00ffffffff) | zx.q(rax_59.b u>> 4) << 0x20) & 0xffff00ffffffffff) | zx.q(rax_59 & 0xf) << 0x28) & 0xff00ffffffffffff) | zx.q(rax_62.b u>> 4) << 0x30) & 0xffffffffffffff) | zx.q(rax_62 & 0xf) << 0x38
000019d8          uint8_t (* rsi_11)[0x120] = &arg1->keyExpanded
000019dc          uint8_t* r12_1 = &arg1->keyExpanded[0x118]
00001bd7          do
000019fb              rdx_63:1.b = rdx_63:1.b ^ arg1->key[zx.q((rsi_11 - 0x7e)->keyExpanded[0] ^ rdx_63.b)]
00001a23              int64_t rdx_65 = (rdx_63 & 0xffffffff00ffffff) | zx.q((rdx_63 u>> 0x18).b ^ arg1->key[zx.q((rdx_63 u>> 0x10).b ^ (rsi_11 - 0x7e)->keyExpanded[1])]) << 0x18
00001a4e              int64_t rdx_67 = (rdx_65 & 0xffff00ffffffffff) | zx.q((rdx_65 u>> 0x28).b ^ arg1->key[zx.q((rdx_65 u>> 0x20).b ^ (rsi_11 - 0x7e)->keyExpanded[2])]) << 0x28
00001a66              uint64_t rdx_68
00001a66              rdx_68.b = (rdx_67 u>> 0x38).b ^ arg1->key[zx.q((rdx_67 u>> 0x30).b ^ (rsi_11 - 0x7e)->keyExpanded[3])]
00001a77              int64_t final1 = (rdx_67 & 0xffffffffffffff) | rdx_68 << 0x38
00001a8f              rcx_26:1.b = rcx_26:1.b ^ arg1->key[zx.q((rsi_11 - 0x7e)->keyExpanded[4] ^ rcx_26.b)]
00001ab6              int64_t rcx_28 = (rcx_26 & 0xffffffff00ffffff) | zx.q((rcx_26 u>> 0x18).b ^ arg1->key[zx.q((rcx_26 u>> 0x10).b ^ (rsi_11 - 0x7e)->keyExpanded[5])]) << 0x18
00001ae5              int64_t rax_89 = (rcx_28 & 0xffff00ffffffffff) | zx.q((rcx_28 u>> 0x28).b ^ arg1->key[zx.q((rcx_28 u>> 0x20).b ^ (rsi_11 - 0x7e)->keyExpanded[6])]) << 0x28
00001b02              uint64_t rcx_31
00001b02              rcx_31.b = (rax_89 u>> 0x38).b ^ arg1->key[zx.q((rax_89 u>> 0x30).b ^ (rsi_11 - 0x7e)->keyExpanded[7])]
00001b0b              int64_t final2 = rcx_31 << 0x38 | (rax_89 & 0xffffffffffffff)
00001b20              uint64_t rax_92
00001b20              rax_92.w = (final1 u>> 8).w
00001b67              uint64_t rax_98
00001b67              rax_98.b = (final1 u>> 0x38).b
00001b8d              int64_t rax_100
00001b8d              rax_100:1.b = (final2 u>> 0x10).b
00001bc6              rdx_63 = zx.q((final2 u>> 8).d & 0xff0000) | final1 u>> 0x20 << 0x38 | (rax_92 & 0xffffff00ffffffff) | zx.q((final1 u>> 0x18).b) << 0x20 | zx.q((final1 u>> 0x18).d & 0xff000000) | zx.q(final2:1.b) << 0x30
00001bcc              rcx_26 = final2 u>> 0x38 << 0x30 | (((((rax_100 & 0xffffffffffffff) | final2 u>> 0x20 << 0x38) & 0xffffffff0000ffff) | zx.q((final2 u>> 0x18).d & 0xffff0000)) & 0xff00ffffffffffff)
00001bd0              rsi_11 = &(*rsi_11)[8]
00001bd0          while (rsi_11 != r12_1)
00001bf1          rdx_63:1.b = rdx_63:1.b ^ arg1->key[zx.q(arg1->keyExpanded[0x118] ^ rdx_63.b)]
00001c1b          int64_t rax_111 = zx.q((rdx_63 u>> 0x18).b ^ arg1->key[zx.q((rdx_63 u>> 0x10).b ^ arg1->keyExpanded[0x119])]) << 0x18 | (rdx_63 & 0xffffffff00ffffff)
00001c46          int64_t rax_113 = (rax_111 & 0xffff00ffffffffff) | zx.q((rax_111 u>> 0x28).b ^ arg1->key[zx.q((rax_111 u>> 0x20).b ^ arg1->keyExpanded[0x11a])]) << 0x28
00001c66          uint64_t rdx_86
00001c66          rdx_86.b = (rax_113 u>> 0x38).b ^ arg1->key[zx.q((rax_113 u>> 0x30).b ^ arg1->keyExpanded[0x11b])]
00001c6e          int64_t rdx_88 = rdx_86 << 0x38 | (rax_113 & 0xffffffffffffff)
00001c86          rcx_26:1.b = rcx_26:1.b ^ arg1->key[zx.q(arg1->keyExpanded[0x11c] ^ rcx_26.b)]
00001cb0          int64_t rax_120 = zx.q((rcx_26 u>> 0x18).b ^ arg1->key[zx.q((rcx_26 u>> 0x10).b ^ arg1->keyExpanded[0x11d])]) << 0x18 | (rcx_26 & 0xffffffff00ffffff)
00001cdb          int64_t rax_122 = (rax_120 & 0xffff00ffffffffff) | zx.q((rax_120 u>> 0x28).b ^ arg1->key[zx.q((rax_120 u>> 0x20).b ^ arg1->keyExpanded[0x11e])]) << 0x28
00001cfb          uint64_t rcx_41
00001cfb          rcx_41.b = (rax_122 u>> 0x38).b ^ arg1->key[zx.q((rax_122 u>> 0x30).b ^ arg1->keyExpanded[0x11f])]
00001d03          int64_t rax_124 = (rax_122 & 0xffffffffffffff) | rcx_41 << 0x38
00001d11          *r13_2 = (rdx_88.d << 4).b | rdx_88:1.b
00001d29          *(r13_2 + 1) = ((rdx_88 u>> 0x10).d << 4).b | (rdx_88 u>> 0x18).b
00001d41          *(r13_2 + 2) = ((rdx_88 u>> 0x20).d << 4).b | (rdx_88 u>> 0x28).b
00001d56          *(r13_2 + 3) = (rdx_88 u>> 0x38).b | ((rdx_88 u>> 0x30).d << 4).b
00001d65          *(r13_2 + 4) = (rax_124.d << 4).b | rax_124:1.b
00001d7d          *(r13_2 + 5) = ((rax_124 u>> 0x10).d << 4).b | (rax_124 u>> 0x18).b
00001d95          *(r13_2 + 6) = ((rax_124 u>> 0x20).d << 4).b | (rax_124 u>> 0x28).b
00001daa          *(r13_2 + 7) = (rax_124 u>> 0x38).b | ((rax_124 u>> 0x30).d << 4).b
00001dae          rdi_1 = arg1
00001dbf          int64_t rax_127 = rdi_1->flagOff
00001dc6          int64_t rsi_41 = *(rdi_1->flag + rax_127)
00001dce          if (rax_127 u> 0x30)
00001dce              break
00001dd7          void* const rdx_108
00001dd7          switch (rax_127)
00001ecb              case 0
00001ecb                  rdx_108 = 0x5894a5af7f7693b7
00001dde              case 1, 2, 3, 4, 5, 6, 7, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
00001dde                  break
00001edf              case 8
00001edf                  rdx_108 = 0x94706b86ce8e1cce
00001ebc              case 0x10
00001ebc                  rdx_108 = 0x98ba6f1ff3cc98
00001ead              case 0x18
00001ead                  rdx_108 = 0xae6575961af354c
00001e9e              case 0x20
00001e9e                  rdx_108 = d853f981df45ab41
00001e8f              case 0x28
00001e8f                  rdx_108 = e1fefd554e662f7f
00001de1              case 0x30
00001de1                  rdx_108 = 0x3ca11fb09e498ab4
00001dee          if (rdx_108 != rsi_41)
00001dee              break
00001df0          int64_t rax_128 = rax_127 + 8
00001dfb          arg1->flagOff = rax_128
00001e03          if (rax_128 u>= arg1->flagLen)
00001e14              if (rax_128 == 0x38)
00001e76                  rdi_1->correctText = rdi_1->correctText ^ 0x101010101010101
00001e83                  return puts(str: &rdi_1->correctText)
00001e10              break
00001e34      rdi_1->wrongText = rdi_1->wrongText ^ 0x101010101010101
00001e41      return puts(str: &rdi_1->wrongText)
```

The expanded key can be dumped at runtime using `gdb`, the only thing that has to be done to use a debugger with this binary is configuring it to not pause at SIGSEGV, which can be done using `handle SIGSEGV nostop`. The structure is conveniently available at `rbp` at any point in this function.

At `1dd7` we have a switch with the expected encrypted values for each block of the flag. Therefore we will need to inverse this cipher in order to get the plaintext for these values.

After the CTF, it has been revealed that this is a TWINE Cipher, and that this information could have been found by searching for the constants. I tried to search for the constants during the CTF but did not manage to find this cipher unfortunately. As such I assumed this is a custom cipher, and proceeded to reverse engineer it.

As scary as this code looks, if we think of the operations as if they were done to a 16 byte array instead of the two 64-bit values, they are much simpler. Here is the code that I wrote that performs the same operations (which I verifed using a debugger):
```cpp
void encBlock(const uint8_t* input, uint8_t* output) {
    uint8_t f[16];
    uint8_t f2[16];
    for (int i = 0; i < 8; i++) {
        f[2 * i] = input[i] >> 4;
        f[2 * i + 1] = input[i] & 0xf;
    }

    for (int i = 0; i < 36; i++) {
        f[1] ^= key[keyExpanded[8 * i + 0] ^ f[0]];
        f[3] ^= key[keyExpanded[8 * i + 1] ^ f[2]];
        f[5] ^= key[keyExpanded[8 * i + 2] ^ f[4]];
        f[7] ^= key[keyExpanded[8 * i + 3] ^ f[6]];

        f[8+1] ^= key[keyExpanded[8 * i + 4] ^ f[8+0]];
        f[8+3] ^= key[keyExpanded[8 * i + 5] ^ f[8+2]];
        f[8+5] ^= key[keyExpanded[8 * i + 6] ^ f[8+4]];
        f[8+7] ^= key[keyExpanded[8 * i + 7] ^ f[8+6]];

        if (i != 35) {
            for (int j = 0; j < 16; j++)
                f2[j] = f[keyShuffle[j]];
            memcpy(f, f2, 16);
        }
    }

    for (int i = 0; i < 8; i++) {
        output[i] = (f[2 * i] << 4) | f[2 * i + 1];
    }
}
```

## Reversing the cipher

The operations can be simply ran in reverse to get the flag. Additionally, the shuffle tab needs to be reversed. The final code to retrieve the flag can be found in `solve.cpp`. The code ignored the flag padding and prints a few unneccessary bytes at the end but these can simply be ignored.

