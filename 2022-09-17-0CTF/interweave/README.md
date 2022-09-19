# Interweave challenge

In this task we got a link to a webpage (called platform penguin) where we could request the creation or destruction of a container to which we could then connect and interact with a binary, that was also provided.

The challenge had 4 "levels", each one being a flag printed under some conditions by this binary. Therefore this challenge starts from reverse engineering this binary.

## Reverse engineering

I have opened the binary in IDA for disassembly and decompilation.

The binary consists primarily of a single large main() function. I started my analysis by looking at the code at the top (minimal fixed were applied in IDA, such as changing decimals to hex numbers, changing types/names and fixing IDA adding the addresses of two globals together):
```c
  setvbuf(stdin, 0LL, 1, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  s2 = (uint8_t *)&unk_15100;
  v3 = (uint8_t *)&unk_15100 + 0x2C240;
  v4 = (uint8_t *)&unk_15100;
  do
  {
    *((_DWORD *)v4 + 0xB00) = 0;
    for ( i = 0; i <= 0xBFF; i += v6 )
    {
      v6 = getrandom(&v4[i], 0xC00 - i, 0LL);
      if ( v6 <= 0 )
        goto lbl_exit_1;
    }
    if ( i != 0xC00 )
      goto lbl_exit_1;
    v4 += 0x2C24;
  }
  while ( v3 != v4 );

  v7 = (uint8_t *)unk_15100;
  do
  {
    v8 = b64buf;
    v9 = v7;
    do
    {
      v10 = *v9;
      v8 += 4;
      v9 += 3;
      *(v8 - 4) = base64_table[v10 >> 2];
      v11 = *(v9 - 2);
      *(v8 - 3) = base64_table[(v11 >> 4) | (16 * v10) & 0x30];
      v12 = *(v9 - 1) & 0x3F;
      *(v8 - 2) = base64_table[(*(v9 - 1) >> 6) | (4 * v11) & 0x3C];
      *(v8 - 1) = base64_table[v12];
    }
    while ( v143 != v8 ); // v143 is the next variable after b64buf, this would be more appropriate to write as &b64buf[4096]
    v7 += 0x2C24;
    v143[0] = 0;
    puts(b64buf);
  }
  while ( v3 != v7 );
```

The code seems to generate 16 blocks of 0xC00 random values, store each of these blocks in parts of a global structure (`unk_15100`), convert them to base64 and print them.
Looking at the code around it seems that `unk_15100` is used later as well and seems to be an array of 16 elements, each one sized 0x2C24.

It's a good idea to define a structure in IDA for these elements (using Local Types):
```c
struct Element {
  uint8_t  random_data[0xC00];
  uint8_t  filler_C00[0x2000];
  uint32_t unknown_2000;
  uint8_t  filler_2C04[0x20];
};
```

With the type now created, we can set the type of the global to `Element stru_15100[16]` and also set the revelant usages.

Following we encounter a large `for` loop that looks roughly like this:
```c
  do
  {
    for ( j = 0LL; j != 0x2AA8; ++j )
    {
      v16 = getc(stdin);
      if ( v16 == -1 || v16 == '\n' )
      {
        if ( (_DWORD)j )
        {
          j = (int)j;
          v36 = (int)j - 1LL;
          if ( b64buf[(int)j - 1] == '=' )
          {
            j = (int)j - 2LL;
            if ( b64buf[j] != '=' )
              goto LABEL_230;
          }
          goto LABEL_65;
        }
lbl_exit_1:
        exit(1);
      }
      b64buf[j] = v16;
    }
    v17 = 0x2AA8LL;
    if ( v143[0x1AA7] != '=' )
      goto LABEL_17;
    if ( v143[0x1AA6] == '=' )
      ...
    ...

    v37 = j & 3;
    if ( v37 == 2 )
    {
      v41 = b64buf[v20];
      v42 = v41 - 'A';
      if ( (unsigned __int8)(v41 - 'A') > 0x19u )
      {
        if ( (unsigned __int8)(v41 - 'a') > 0x19u )
        {
          if ( (unsigned __int8)(v41 - '0') <= 9u )
          {
            v42 = v41 + 4;
          }
          else if ( v41 == '+' )
          {
            v42 = 0x3E;
          }
          else
          {
            v42 = 0x3F;
            if ( v41 != '/' )
              v42 = b64buf[v20];
          }
        }
        else
        {
          v42 = v41 - 0x47;
        }
      }
      v43 = (unsigned __int8)b64buf[v20 + 1];
      v44 = 4 * v42;
      ...   // Omitted code that read a char the same way into v45
      filler_C00[v19] = v44 | (v45 >> 4) & 3;
      LODWORD(v19) = v19 + 1;
    }
    else if ( v37 == 3 )
    {
      ...
    }
    else if ( v37 == 3 )
    {
    ...
    }
    if ( (unsigned int)(v19 - 1) > 0x2AA7 )
      goto lbl_exit_1;
    *((_DWORD *)filler_C00 + 0x800) = v19;  // This actually writes to unknown_2000
    filler_C00 += 0x2C24;
    v13 += (int)v19 < 4097;
  }
```

I omitted a significant part of this code for brevity. However this loop appears to do base64 decoding. Maximal user input length seems to be 0x2AA8 characters. We see that this code overrides data in `filler_C00` with presumably decoded base64, and also stores a number into `unknown_2000`.

During the challenge at this point I have exported the entire program into a C file and recompiled it to make debugging more easy (could add print statements, etc.). However this is probably not the best idea overall (I did not have the structures properly typed yet and had to fix stack usages), and I would recommend just using the IDA's integrated debugger. 

Due to the length of the code, I verified this aforementioned theory using a debugger and it turned out that `filler_C00` was indeed the decoded base64 and `unknown_2000` was the length of the user input. This code seems not to be vulnerable to any buffer overflows and the maximal decoded length is 0x1FFE bytes. Let's update the structure:
```c
struct Element {
  uint8_t  random_data[0xC00];
  uint8_t  user_data[0x2000];
  uint32_t user_data_length;
  uint8_t  filler_2C04[0x20];
};
```

The next code block is the following:
```c
  v121 = v13;
  v38 = (Elf64_Ehdr *)stru_15100[0].user_data;
  v39 = 0x1003E0000LL;
  do
  {
    v40 = *(_DWORD *)v38[128].e_ident;
    if ( v40 <= 0x77
      || *(_DWORD *)v38->e_ident != 'FLE\x7F'
      || *(_DWORD *)&v38->e_ident[4] != 0x10102
      || v38->e_ident[8]
      || *(_DWORD *)&v38->e_ident[9]
      || *(_WORD *)&v38->e_ident[13]
      || v38->e_ident[15]
      || (v122 = 0, (unsigned __int16)(v38->e_type - 2) > 1u)
      || (v46 = *(_QWORD *)&v38->e_type, LOWORD(v46) = 0, v46 != 0x1003E0000LL)
      || v38->e_phoff != 64
      || v38->e_shoff > v40
      || *(_QWORD *)&v38->e_flags != 0x38004000000000LL
      || v38->e_phnum > 0x7Fu
      || (v38->e_shentsize & 0xFFBF) != 0
      || v38->e_shnum > 0x7Fu
      || v40 < v38->e_shstrndx )
    {
lbl_exit_0:
      exit(0);
    }
    v38 = (Elf64_Ehdr *)((char *)v38 + 0x2C24);
  }
  while ( v38 != (Elf64_Ehdr *)0x41F40 );
```

which checks some data members against some values. The data this checks is fields in the ELF header. The conditions are as follows:
* Must start from a valid ELF magic
* `e_ident[EI_CLASS] == 2` (64-bit)
* `e_ident[EI_DATA] == 1` (little endian)
* `e_ident[EI_VERSION] == 1`
* `e_ident[EI_OSABI] == 0` (System-V ABI, almost all Linux ELFs use this ABI)
* `e_ident[EI_ABIVERSION] == 0`
* `e_ident[EI_PAD]` filled with zeros
* `e_type == ET_EXEC`
* `e_machine == 0x3E` (AMD x86-64)
* `e_version == 1`
* `e_phoff == 64`
* `e_shoff <= user_data_length`
* `e_flags == 0`
* `e_ehsize == 64`
* `e_phentsize == 56`
* `e_phnum < 0x80`
* `(e_shentsize & ~0x40) == 0`
* `e_shnum < 0x80`
* `e_shstrndx <= user_data_length` (???)

Seems almost any valid ELF will match this criteria.

The next part of the function looks as follows:
```c
  hashp = stru_15100[0].filler_2C04;
  while ( 2 )
  {
    v48 = *((int *)hashp - 1);
    LODWORD(v136) = 0;
    v138 = 0xBB67AE856A09E667LL;
    v139 = 0xA54FF53A3C6EF372LL;
    v140 = 0x9B05688C510E527FLL;
    v137 = 0LL;
    v141 = 0x5BE0CD191F83D9ABLL;
    if ( v48 )
    {
      v49 = *(hashp - 8196);
      v50 = 0LL;
      LODWORD(v136) = 1;
      v51 = 1LL;
      LOBYTE(v131) = v49;
      v52 = 1LL;
      v53 = 1;
      v54 = 2LL;
      if ( v48 > 1 )
      {
        do
        {
          v55 = hashp[v51 - 8196];
          *((_BYTE *)&v131 + v52) = v55;
          LODWORD(v136) = v54;
          if ( (_DWORD)v54 == 64 )
          {
            v50 += 512LL;
            sub_25A0(&v131, &v131, v55, v39, v20);
            v137 = v50;
            LODWORD(v136) = 0;
            v52 = 0LL;
            
    ... a significant amount of code omitted ...

    v66 = hashp;
    ...
    do
    {
      *v66++ = v65 >> v39;
      v66[3] = v67 >> v39;
      v66[7] = v68 >> v39;
      v66[11] = v69 >> v39;
      v66[15] = v70 >> v39;
      v66[19] = (unsigned int)v20 >> v39;
      v66[23] = v71 >> v39;
      v73 = v72 >> v39;
      v39 = (unsigned int)(v39 - 8);
      v66[27] = v73;
    }
    while ( (_DWORD)v39 != -8 );
    hashp += 0x2C24;
    if ( hashp != (uint8_t *)0x43F44 )
      continue;
    break;
  }
...
```

The constant `0xBB67AE856A09E667` gives away that we are dealing with SHA256. Looking at `sub_25A0`, we find another constant: `0x428A2F98`, which also matches up with SHA256.
The implementation seems to match up with https://github.com/B-Con/crypto-algorithms/blob/master/sha256.c#L44

This suggests this code probably hashes each of the inputs using SHA256. This gives us the following structure:
```c
struct Element {
  uint8_t  random_data[0xC00];  // 0x0C00
  uint8_t  user_data[0x2000];   // 0x2C00
  uint32_t user_data_length;    // 0x2C04
  uint8_t  hash[0x20];          // 0x2C24
};
```

I confirmed using a debugger that the `hash` value is the SHA256 digest of the input data (`user_data[:user_data_length]`).

The next code block ensures that there are no two inputs with the same hash:
```c
  it_hash = (_BYTE *)(stru_15100 + 0x2C24 + 0x2C04);
  for ( k = 0LL; k != 15; ++k )
  {
    it2_hash = it_hash;
    do
    {
      if ( *(_OWORD *)(it_hash - 0x2C24) == *(_OWORD *)it2_hash && *((_OWORD *)it2_hash + 1) == *(_OWORD *)(it_hash - 0x2c14) )
        goto lbl_exit_0;
      it2_hash += 0x2C24;
    }
    while ( stru_15100[k + 2 + (unsigned int)(14 - k)].hash != it2_hash );
    it_hash += 11300;
  }
```

The remaining code seems to start the program in question using a combination of `memfd_create` and `execveat`, set up some resource limits, syscall filtering, and then do something with the results.

The first thing we notice is the use of another global, to which data read from a pipe connected to the process's stdout and the process's exit code is written. This structure looks as follows:
```c
struct RetData {
  int32_t index;
  int32_t retval;
  uint8_t data[4096];
  int32_t dataLen;
};
```

I have cleaned this code up quite a bit, and manually disassembled the BPF syscall filter:
```c
    v118 = 0LL;
    v99 = stru_5040;
    v119 = stru_15100;
    while ( 2 )
    {
        user_prog_len = (int)v119->user_data_length;
        if (pipe(stdin_pipe) < 0 || pipe(stdout_pipe) < 0 )
            exit(1);
        pid = fork();
        if ( !pid )
        {
            prctl(PR_SET_PDEATHSIG, 9LL);
            close(stdin_pipe[1]);
            close(stdout_pipe[0]);

            dup2(stdin_pipe[0], 0); //stdin
            if ( stdin_pipe[0] )
                close(stdin_pipe[0]);
            dup2(stdout_pipe[1], 1); //stdout
            if (stdout_pipe[1] != 1 )
                close(stdout_pipe[1]);


            v112 = 0LL;
            mfd = memfd_create("", 1LL);
            while (v112 < user_prog_len )
            {
                v114 = write(mfd, &stru_15100[v118].user_data[v112], user_prog_len - v112);
                if ( v114 <= 0 )
                    break;
                v112 += v114;
            }
            if ( (mfd <= 2 || !(unsigned int)close_range(2LL, (unsigned int)(mfd - 1), 0LL))
                 && !(unsigned int)close_range((unsigned int)(mfd + 1), 2147483646LL, 0LL)
                 && !close(0) )
            {
                rlimits.rlim_cur = 1LL;
                rlimits.rlim_max = 1LL;
                if ( setrlimit(RLIMIT_CPU, &rlimits) < 0 )
                    exit(-1);
                rlimits.rlim_cur = 0x8000000LL;
                rlimits.rlim_max = 0x8000000LL;
                if ( setrlimit(RLIMIT_AS, &rlimits) < 0 )
                    exit(-1);
                sock_filter filters[] = {
                        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (offsetof(struct seccomp_data, arch))),
                        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, AUDIT_ARCH_X86_64, 0, 6),
                        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (offsetof(struct seccomp_data, nr))),
                        BPF_JUMP(BPF_JMP + BPF_JGE + BPF_K, 0x40000000, 4, 0),
                        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_write, 4, 0),
                        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_exit, 3, 0),
                        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_exit_group, 2, 0),
                        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_execveat, 1, 0),
                        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL_PROCESS),
                        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
                };
                sock_fprog prog = {10, filters};
                if ( prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) || prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) )
                    exit(-1);
                execveat((unsigned int)mfd, "", 0LL, 0LL, 4096LL);
            }
            exit(1);
        }
        if (pid < 0 )
            exit(1);
        v102 = 0LL;
        close(stdin_pipe[0]);
        close(stdout_pipe[1]);
        close(stdin_pipe[1]);
        v103 = stdout_pipe[0];
        while ( 1 )
        {
            v104 = read(v103, &v99->data[v102], 0x1000 - v102);
            v105 = v104;
            if ( v104 <= 0 )
                break;
            v102 += v104;
            if ( v102 > 0xFFF )
                goto LABEL_199;
        }
        if ( v102 )
            LABEL_199:
            v105 = v102;
        v123 = v105;
        int stat_loc;
        waitpid(-1, &stat_loc, 0);
        v99++;
        close(stdout_pipe[0]);
        ++v118;
        ++v119;
        v99[-1].retval = stat_loc;
        v99[-1].dataLen = v123;
        if ( v118 != 16 )
            continue;
        break;
    }

    mainInfo = stru_15100;
    retInfo = stru_5040;
    matchingHashes = 0;
    matchingOutputs = 0;

    do
    {
        if ( !(retInfo->retval & 0x7F | (unsigned __int8)BYTE1(retInfo->retval)) )
        {
            ++completedPrograms;
            if ( retInfo->dataLen == 0xE00 )
            {
                matchingOutputs += memcmp(retInfo->data, mainInfo->random_data, 0xC00uLL) == 0;

                for (int i = 0; i < 16; i++)
                {
                    matchingHashes += memcmp(retInfo->data[0xc00 + 32 * i], stru_15100[i].hash, 0x20uLL) == 0;
                }
            }
        }
        ++mainInfo;
        ++retInfo;
    }
    while ( retInfo != &retdata[16] );

    if ( matchingOutputs == 16 && completedPrograms == 16 )
    {
        sub_27C0("flag1.txt");
        if ( matchingHashes > 135 )
        {
            sub_27C0("flag2.txt");
            if ( matchingHashes == 256 )
            {
                sub_27C0("flag3.txt");
                if ( v121 == 16 )
                    sub_27C0("flag4.txt");
            }
        }
    }
    return 0LL;
```

Now we know that:
* to get flag1, we need to make 16 ELF files that fit within the file size limit that print the provided 0xC00 random byte arrays (then 0x200 bytes of padding so the program prints 0xE00 bytes in total) and exit with code 0.
* to get flag2 and flag3, we need to make these ELF files print the SHA256 hashes of each of the programs after the 0xC00 random byte array.
  - for flag2 it is enough that only 136 of these are correct. I did not attempt to get flag2 directly and went straight for flag3 after flag1.
* to get flag4, all of the programs must be <= 0x1000 bytes in size.

In addition our ELF may only use the write, exit, exit_group and execveat syscalls.

This concludes the reverse engineering part.


## Getting flag1

In order to get the executable to print any flags, we have to create the text files first:
```
echo flag1 > flag1.txt
echo flag2 > flag2.txt
echo flag3 > flag3.txt
echo flag4 > flag4.txt
```

I found this web page that contained an example of an ELF printing hello world: https://nathanotterness.com/2021/10/tiny_elf_modernized.html

I took the example from "Removing Section Information" as the base program and minimally modified it (replaced the string 'Hello, world!\n' with 'replaceme' and hardcoded the length to 0xC00). The modified asm program is named flag1.asm and can be compiled using:
```
nasm -f bin -o flag1 flag1.asm
```
Then I wrote a simple Python script that executes the binary, reads the provided random data blobs, then replaces the replaceme text with the blob and passes the encoded base64 programs to the binary.
This script is named flag1.py and is executed as follows (required the `flag1` executable to be created using nasm first):
```
python3 flag1.py
```
The contents of flag1.txt should be printed on the screen.


## Getting flag2 and flag3

The difficulty is raised a little bit. We do not have enough space to embed all the data blobs to self-compute the SHA256 the straightforward way.

Instead we will need to embed the partial SHA256 state for the ELFs. We obviously can't hash the part of the executable that contains the hashes, so we will need to put it at the end of the ELF executable and align it to 64 bytes to simplify the implementation.

The sufficient SHA256 state is eight 32-bit numbers. Therefore we will need 0x200 bytes to store the states of all the 16 executables.

First of all, we will need to compute the SHA256 state to embed. To do this I found a SHA256 implementation in Python: https://github.com/keanemind/Python-SHA-256. The implementation was modified a bit in order to remove the final padding block and to instead encode the numbers in little endian. The modified implementation is in a file called sha256.py. We can then use it as follows:

```python
hashes_offset = 0x1000  # I decided to locate the hashes at file offset 0x1000 / VA 0x29000

# pad the elf files to hashes_offset bytes
elfs = [b + b'\x00'*(hashes_offset-len(b)) for b in elfs]

# generate the hash states for all the elf files and merge them together
hashes = b''.join([sha256.generate_hash(b) for b in elfs])

# append the hashes to the elf files
elfs = [b + hashes for b in elfs]
```

Now we need to create code in the .asm file that will compute the final SHA256 checksum.

I did this by copying a C SHA256 implementation's transform block function (from: https://github.com/B-Con/crypto-algorithms/blob/master/sha256.c#L44) and changing it slightly so it does not keep a temporary array with bytes that are not flushed to a block.

We will then need to iterate though all the embedded states, then update a copy of each state and output the hash to stdout. We first call `sha256_transform` for the remaining byte blocks in the ELF executable (which are the hash data). Then we call `sha256_transform` for the final block, which needs to start from 0x80 (data terminator) and the last 8 bytes are a big endian integer specifying the total number of bits that were hashed (in our case the entire binary is 0x1200 bytes as the hashes start at 0x1000, therefore we need to set it to 0x9000).
```c++
void compute_final_hash() {
    uint8_t *hashes = (uint8_t*)0x29000;

    uint8_t finalblock[0x40] = {0x80, 0};
    finalblock[0x40 - 2] = 0x90;

    for (int i = 0; i < 16; i++) {
        SHA256_CTX ctx = *(SHA256_CTX*)&hashes[0x20*i];
        for (int j = 0; j < 16 * 0x20; j += 0x40)
            sha256_transform(&ctx, &hashes[j]);
        sha256_transform(&ctx, finalblock);

        for (int j = 0; j < 8; j++)
            ctx.state[j] = __builtin_bswap32(ctx.state[j]);

        // write() syscall
        long ret;
        asm volatile (
        "syscall"
        : "=a" (ret)
        : "0"(1), "D"(1), "S"(ctx.state), "d"(0x20)
        : "rcx", "r11", "memory"
        );
    }
}

```

I then compiled it with the following command:
```
clang -S -masm=intel -Os -fno-stack-protector -fno-tree-vectorize -fno-asynchronous-unwind-tables -fno-builtin flag3_tmpcode.c
```
This created a `.s` file I used as a base, fixed the syntax so it works with nasm and then manually optimized the code. The resulting .asm file is named flag3.asm.

Finally:
```
nasm -f bin -o flag3 flag3.asm
python3 flag3.py
```
The contents of flag1.txt, flag2.txt and flag3.txt should be printed on the screen.


## Getting flag4

According to the challenge author, the intended solution to getting the flag4 was to use the SHA256 ni instructions.
However, I was unable to get my code below 0x200 bytes (I needed 0xC00 for the random data blob and 0x200 for the hashes, so to meet the target of 0x1000 bytes I only had 0x200 bytes left), so I was looking for a different solution.

Compressing code was unlikely to net a significant benefit considering the decompressor would have to be a part of the ELF.

The program was not able to read files directly. The parent process had a sha256 function, but due to the execvat call the parent process memory was gone. But what if we could set the dynamic linker to another executable?

I tried setting the `PT_INTERP` on our ELF to the original binary. By modifying the decompiled binary I was able to observe the return status and it exited with a SIGSEGV as opposed to a permission error. When running the process outside with gdb I observed the error was happening in `main` as it tried to invoke `__libc_start_main_ptr` from libc.so, which honestly makes perfect sense. I looked at the ELF handling code in Linux to see whether there maybe isn't another way to load another file into memory somehow, but the interpreter was the only way.

This means we would need to somehow place another executable on the system, as I find it very unlikely we would be able to find a linker-behaving executable that would assist us in computing SHA256 already present on the system. (attempts to load the normal linker are useless as the linker will fail somewhere with a blacklisted syscall).

So, this leaves us with one idea. `/proc/{pid}/exe` for the processes spawned by the challenge points to something Linux considers a valid file. We could use the challenge to spawn an executable that would hang, then create another connection that would guess the PID of that process and use the `/proc/{pid}/exe` executable as the "linker".
The "linker" executable would contain all of the relevant code, and then the ELFs sent later would only point at it as the dynamic linker and contain the random data plus hashes. 

The first problem was figuring out why our minimal executables cannot be used as a linker (cause SIGSEGV before you can attach gdb to the process). This is apparently because a PHDR with a LOAD for RW segment is required for the linker. I figured this out by compiling a minimal random executable. Then I removed the SHDR info from the header, and the executable still functioned as a linker. Afterwards I decremented the number of PHDRs until it no longer worked and managed to narrow it down to that LOAD PHDR.  

The second problem was checking whether we are running as a linker - we want the linker executable PID to stay as constant as possible, therefore immediately crashing would not be optimal.
This can be done by finding the value for the aux vector AT_ENTRY and checking whether it lower than the load address of the linker (the main binary has a load address of 0x28000 and the linker 0x50000). If we are running standalone, the code enters a loop and runs for ~1s before it is killed due to exhausting a resource limit.

The code of this "linker" can be found in flag4_interp.asm and the code of the "main" executable stub in flag4_main.asm. Locally this setup can be tested quite easily:
```
nasm -f bin -o flag4_interp flag4_interp.asm
nasm -f bin -o flag4_main flag4_main.asm
```
Then we can run `python3 flag4_interp.py` in one terminal, and `python3 flag4_main.py $(pgrep ^3$)` in another.

Now we get to the last and bigger challenge, which is guessing the PID on remote. I tried to have a loop guessing the PID but due to the amount of processes spawning I was not able to guess it this way.
I ended up recreating the container in which the challenge was running via the web page and bruteforcing the PIDs manually expecting them to be low. I ended up with a successful run at PID 8, with this following badly written script:
```py
from flag4_interp import do_interp
from flag4_main import do_main
from threading import Thread

CRED = b'<redacted>'

def t1():
    while True:
        do_interp(CRED)

def t2():
    import time
    time.sleep(0.05)
    do_main(8, CRED)


Thread(target=t1).start()
Thread(target=t2).start()
```