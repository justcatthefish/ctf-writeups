# Devil Hunter challenge

Decription: Clam Devil; Asari no Akuma

Download: https://drive.google.com/file/d/1u02Rvm3UNyzRgQABExgc4GnFAjMvZqDj/view?usp=drivesdk

## Tooling

We have a ClamAV bytecode file and we need to somehow disassemble it. ClamAV comes with a tool called `clambc` that can do just that.

```
$ clambc
 

                       Clam AntiVirus: Bytecode Testing Tool 0.105.1
           By The ClamAV Team: https://www.clamav.net/about.html#credits
           (C) 2022 Cisco Systems, Inc.

    clambc <file> [function] [param1 ...]

    --help                 -h         Show this help
    --version              -V         Show version
    --debug                           Show debug
    --force-interpreter    -f         Force using the interpreter instead of the JIT
    --trust-bytecode       -t         Trust loaded bytecode (default yes)
    --info                 -i         Print information about bytecode
    --printsrc             -p         Print bytecode source
    --printbcir            -c         Print IR of bytecode signature
    --input                -c         Input file to run the bytecode on
    --trace <level>        -T         Set bytecode trace level 0..7 (default 7)
    --no-trace-showsource  -s         Don't show source line during tracing
    --statistics=bytecode             Collect and print bytecode execution statistics
    file                              File to test

**Caution**: You should NEVER run bytecode signatures from untrusted sources.
Doing so may result in arbitrary code execution.

```

So naturally, the first thing to try is to use `-printsrc`. Unfortunately...

```
$ clambc --printsrc flag.cbc
not so easy :P
```

Alright, `-printbcir` it is then. This generated a pretty long file. It can be found in `bcir.txt`.

## Analyzing the bytecode

I had trouble understanding this bytecode at first. Also, the constants are unfortunately not automatically extracted from the table and need to be manually referenced. I had copied over some of the constants over to the text file so that I don't get lost.

To understand the meaning of the instruction I referenced the VM source code (https://github.com/Cisco-Talos/clamav/blob/317153435e3190cc997fdf032518c68d4408c35c/libclamav/bytecode_vm.c) and the decoding code in the parseBB function in bytecode.c (https://github.com/Cisco-Talos/clamav/blob/317153435e3190cc997fdf032518c68d4408c35c/libclamav/bytecode.c).

Here are some instructions and the meaning I deduced based on the source code and what made sense to me:
- `OP_BC_GEPZ` - `rD = gepz p.rA + (rB)` - `rD = rA + rB`, where `A` has to be a pointer (similar to `ldr D, [A+B]`)
- `OP_BC_GEP1` - `rD = gep1 p.rA + (rB * C)` - `rD = rA + rB * C` where `A` has to be a pointer (similar to `ldr D, [A+B*C]`), however I'm not quite sure why `C` is `65` in most places where it should be `1`.
- `OP_BC_COPY` - `cp rA -> rD` - `rD = rA` (similar to `mov A, D`)
- `OP_BC_TRUNC` - `rD = rA & MASK` (can be used to move a value from a larger "register", to a smaller one, eg. from int64 -> int32)

There are no real "registers", however I still call them as such, as that's the closest name I know. By a register, I am referring to the indexes that refer to a parameter, local or constant (that are dumped before the function body).
It is important that the intructions can operate on varying data sizes, and the size of the data being operated on depends on the "register" size.

As the function code was rather short, I decided to deal with this annoying repesentation and not to make my own tool for it. I manually wrote a rough psuedocode:
```
def F1:
seek(7, 0);
for (int i = 0; i < 36; i++)
  assert read(p4[i], 1) == 1
# bb3
assert read(p3, 1) > 0 and p3 == '}'
# bb4
assert not (read(p3, 1) > 0)
# bb5
for (int i = 0; i < 36; i += 4)
  ((uint32_t*)p7)[i] = F2(((uint32_t*)p4)[i])
# bb6
assert p7[0] == 0x739e80a2
...

def F2:
// i - 2, j - 1
int64 j = 0xacab3c0;
for (int i = 0; i < 25; i++) {
  v9 = (arg >> (i * 8)) & 0xff;
  j = ((v9 ^ j) << 8) | (j >> 24);
}
return j
```

My modified version of the bcir can be found in `bcir_modified.txt`.

## Figuring out the flag

F2 does some sort of a hash, but as it works on a 32-bit integer it can be bruteforced rather fast.
I rewrote the pseudocode in C++ and managed to get it to print out the flag. An important fact is that the code starts reading at index 7 which means the flag doesn't start with "SECCON{" which needs to be manually prepended.

The code to bruteforce can be found in solve.cpp.
