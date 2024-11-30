# qrackv #

We get two binaries: `qrackv`, which is a simple risc-v binary, and `qemu-riscv`, a custom version of qemu userspace risc-v emulator. 

After decompilation of `qrackv`, we can see that it performs a flag format validation - expecting usual flag format with 64 hex digits as an actual flag. It then proceeds to verify the flag, which amounts to calling three custom instructions (four times: c1, c2, c1, c3) on the input loaded to a5 register in 8-digit chunks. Relevant disassembly:

```     00010656 ba 97           c.add      a5,a4
        00010658 9c 63           c.ld       a5,0x0(a5)
        0001065a 8b 87 07 00     custom0
        0001065e 23 34 f4 fc     sd         a5,-0x38=>local_38(s0)
        00010662 83 27 44 fe     lw         a5,-0x1c=>local_1c(s0)
        00010666 8e 07           c.slli     a5,0x3
        00010668 03 37 04 fd     ld         a4,-0x30=>local_30(s0)
        0001066c ba 97           c.add      a5,a4
        0001066e 98 63           c.ld       a4,0x0(a5)
        00010670 83 37 84 fc     ld         a5,-0x38=>local_38(s0)
        00010674 8b 97 e7 00     custom0
        00010678 23 30 f4 fc     sd         a5,-0x40=>local_40(s0)
        0001067c 83 37 04 fc     ld         a5,-0x40=>local_40(s0)
        00010680 8b 87 07 00     custom0
        00010684 23 3c f4 fa     sd         a5,-0x48=>local_48(s0)
        00010688 83 37 84 fb     ld         a5,-0x48=>local_48(s0)
        0001068c 03 27 44 fe     lw         a4,-0x1c=>local_1c(s0)
        00010690 8b a7 e7 00     custom0.   a5
```

In order to understand the validation, we need to dig into qemu binary, to explore what these instructions resolve to when emulated. After some binary patching with random qemu binaries did not yield much results in uncovering the added functionality, we noticed that qemu provided does have a capability of dumping the code which is a result of its jit execution. 

After executing `qemu-riscv64 -jitdump  qrackv` with some sane input, we get a file which turns out to be in jitdump format. The format is documented in the linux source: https://github.com/torvalds/linux/blob/master/tools/perf/Documentation/jitdump-specification.txt, and quickly we can write a simple parser to extract the parts of the code we need.

```python
import struct

f = open("jit-33205.dump", 'rb')
r = f.read()

jit_header_format = "IIIIIIQQ"
jit_header = struct.unpack( jit_header_format, r[:struct.calcsize(jit_header_format)])

records = []

curr_cursor = struct.calcsize(jit_header_format)
while curr_cursor < len(r):
    record_header = struct.unpack( "IIQ", r[curr_cursor:curr_cursor + struct.calcsize("IIQ")])
    records.append((record_header, r[curr_cursor:curr_cursor+record_header[1]]))
    curr_cursor += record_header[1]
    
r0f = "IIQQQQ"

name_to_code = {}

for r in records:
    if r[0][0] == 0:
        temp_header = struct.unpack(r0f, r[1][struct.calcsize("IIQ"):struct.calcsize("IIQ")+struct.calcsize(r0f)])
        zero_split = r[1][struct.calcsize(r0f)+struct.calcsize("IIQ"):].find(b'\x00')
        name = r[1][struct.calcsize(r0f)+struct.calcsize("IIQ"):struct.calcsize(r0f)+struct.calcsize("IIQ") + zero_split]
        code = r[1][struct.calcsize(r0f)+struct.calcsize("IIQ") + zero_split:]
        name_to_code[int(name[6:], 16)] = (code, temp_header)
```


The jit of the part of the binary that we are interested in start at risc-v address of `0x1064c`, so we can dump the code corresponding to that emulation chunk to a file and load it in ghidra (we also get a rellocation address from jitdump file). 

After fair amount of analysis of the code, two of the custom instructions are equivalent to following rust code:

```rust
const Q: u64 = 0xffffffffffffffc5;

fn awcm(a: u64, b: u64) -> u64 {
    let (res, carry) = a.overflowing_add(b);
    return ((res % Q) + if carry { 0x3b } else { 0 }) % Q;
}

fn c1(a: u64) -> u64 {
    let mut x80 = 0x9282f38fd9de6bb;
    let mut x88 = a;
    let mut x90 = 0;

    while x80 != 0 {
        x90 = awcm(x90, x88 * (x80 & 1));
        x88 = awcm(x88, x88);

        x80 = x80 >> 1;
    }
    awcm(x90, 0x9a10a8b923ac8bf)
}

fn c2(a: u64, b: u64) -> u64 {
    let mut xb0 = a;
    let mut xd8 = 0;

    for xb8 in 0..0x10 {
        let xc0 = xb8 << 2;
        let xc8 = (b >> xc0) & 0b111;
        xd8 = 0;
        for xd0 in 0..8 {
            let r12 = {
                if xd0 == 0 {
                    xc8
                } else if xd0 == xc8 {
                    0
                } else {
                    xd0
                }
            };
            xd8 = xd8 | (((xb0 >> (r12 << 3)) & 0xff) << (xd0 << 3));
        }
        xb0 = xd8;
    }
    return xd8;
}
```

Here, `c1` accepts an arguemnt in `a5` register, while `c2` accepts one in the `a4` and `a5`. Effectively, the validation part performs operation equivalent to calling `c1(c2(c1(a5), a5))`.

The last custom instructions is a little bit trickier, since it calls a functions which lives outside of jited code. We were able to locate it statically by searching for a bytes that result from encoding the first chunk of an input, since we knew these are passing the validation. We found a snipped that uses some sort of random number generator to find the adressess of chunks with which encoded flag is compared. Python equivalent goes like this:
```python
rdx = 3
rcx = 0
rsi = 0
r8 = 0x469ee58469ee5847
for _ in range(10):
    rcx = rdx * 3
    rax = rcx
    tmp = rax * r8
    rdx = tmp >> 64
    rax = rcx
    rax = rax >> 0x3f
    rdx = rdx >> 0x3
    rdx = rdx - rax
    rax = rdx * 8
    rax = rax - rdx
    rax = rdx + rax * 4
    rcx = rcx - rax
    rdx = rcx
    print(hex(0x002edb00 + rcx * 8))
```

Now, to wrap this up, we need to find the blocks in memory corresponding to these addresses, brute-force the inputs that gives these values (using previous rust code), and compile all of the together to give us the final answer:

```
0x2edb48 0xC41F9CE7C6CA8EBA 6631363438613131
0x2edbd8 0xB701B9064B5BBD38 6531323637643135
0x2edbb8 0x0B55228F811AA127 3334646265383566
0x2edb58 0xE424883534B75239 3432396165613564
0x2edb20 0x34968CD63F4D48D8 3863333864383663
0x2edb60 0x104A93F53BC6EFA1 3533626365303861
0x2edb38 0x21D302F1CE581E42 6530383965643665
0x2edba8 0xEED6FE5FC72EE54D 7d33366330613131
```

```python
s = b"SECCON{5"
for x in ["6631363438613131", "6531323637643135", "3334646265383566", "3432396165613564", "3863333864383663", "3533626365303861", "6530383965643665", "7d33366330613131"]:
    s += bytes.fromhex(x)[::-1]
```
 
`SECCON{511a8461f51d7621ef58ebd43d5aea924c68d83c8a80ecb35e6de980e11a0c63}`



