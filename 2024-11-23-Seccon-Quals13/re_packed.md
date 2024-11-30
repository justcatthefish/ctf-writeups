# packed #

## Task description: ##
> Packer is one of the most common technique malwares are using.

> packed.tar.gz 320fa70af76e54f2b6aec55be4663103d199a4a5

## Solution ##

The binary is packed with an UPX and we can unpack it, but there's no flag in the unpacked code. The flag is hidden in the code that's executed after the
binary is unpacked.

If we load that packed binary into Ghidra and follow the code from the entry point we can reach the following part:

```asm
0044ede1        MOV          RDX,0x202021585055
0044edeb        MOV          RAX,0x1a66191c13                                                       FLAG
0044edf5        XOR          RAX,RDX
0044edf8        MOV          qword ptr [RSP + 0x0]=>local_30,RAX
0044edfd        PUSH         RSP=>local_38
0044edfe        POP          RSI
0044edff        MOV          EDX,0x1
0044ee04        PUSH         RDX
0044ee05        PUSH         RDX
0044ee06        MOV          EDX,0x6
0044ee0b        POP          RDI
0044ee0c        POP          RAX
0044ee0d        SYSCALL                                                                             sys_write
```

What it des it that it load values into `RDX` and `RAX` and xors them. That produces that value for the string `FLAG: `,
that later is passed onto the stack and and address to that location is passed to syscall 0x1 to write it on the screen.

```asm
0044ee0f        PUSH         RSP=>local_38
0044ee10        POP          RSI
0044ee11        MOV          EDX,0x80
0044ee16        SUB          RSI,RDX
0044ee19        XOR          EDI,EDI
0044ee1b        XOR          EAX,EAX
0044ee1d        SYSCALL                                                                             sys_read
```
The above code, sets up the READ syscall. The data will be stored on the stack.

```asm
0044ee1f        CMP          EAX,0x31
0044ee22        JNZ          LAB_0044eec3
0044ee28        MOV          ECX,EAX
0044ee2a        POP          RDX
0044ee2b        POP          RSI
0044ee2c        LEA          RDI=>local_b0,[RSP + -0x90]
```

Here we check if we were able to read `0x31` characters and if not we exit further checks. The `rdi` points to the input flag on the stack.

```asm
LAB_0044ee34:
    0044ee34         LODSB        RSI
    0044ee35         XOR          byte ptr [RDI]=>local_b0,AL
    0044ee37         INC          RDI
    0044ee3a         LOOPNZ       LAB_0044ee34
    0044ee3c         CALL         check
```

In this loop, we `xor` the bytes located at `RSI` with the data at `RDI` -> the input, and after that we jump to the `check` call.

Here following the code get's a little confused but we can always support ourself with the debugger. If we put a breakpoint at the `0x44ee34`
and we query the memory at `$rsi` we will the the following bytes:

The `RSI` points to the following data:

```
0xe8,   0x4a,   0x00,   0x00,   0x00,   0x83,   0xf9,   0x49,
0x75,   0x44,   0x53,   0x57,   0x48,   0x8d,   0x4c,   0x37,
0xfd,   0x5e,   0x56,   0x5b,   0xeb,   0x2f,   0x48,   0x39,
0xce,   0x73,   0x32,   0x56,   0x5e,   0xac,   0x3c,   0x80,
0x72,   0x0a,   0x3c,   0x8f,   0x77,   0x06,   0x80,   0x7e,
0xfe,   0x0f,   0x74,   0x06,   0x2c,   0xe8,   0x3c,   0x01,
0x77
```

Then we jump to check method to verify that our input is correct comparing the result of the xoring with the following.

```
0xbb,    0x0f,    0x43,    0x43,    0x4f,    0xcd,    0x82,    0x1c,
0x25,    0x1c,    0x0c,    0x24,    0x7f,    0xf8,    0x2e,    0x68,
0xcc,    0x2d,    0x09,    0x3a,    0xb4,    0x48,    0x78,    0x56,
0xaa,    0x2c,    0x42,    0x3a,    0x6a,    0xcf,    0x0f,    0xdf,
0x14,    0x3a,    0x4e,    0xd0,    0x1f,    0x37,    0xe4,    0x17,
0x90,    0x39,    0x2b,    0x65,    0x1c,    0x8c,    0x0f,    0x7c,
0x7d
```

passing the two tables into a simple `xor` operation (`''.join([chr(x^y) for x,y in zip(a,b)])`) yields us the flag: `SECCON{UPX_s7ub_1s_a_g0od_pl4c3_f0r_h1din6_c0d3}`
