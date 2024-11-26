# jump #

## Task description ##

> Who would have predicted that ARM would become so popular?

> ※ We confirmed the binary of Jump accepts multiple flags. The SHA-1 of the correct flag is c69bc9382d04f8f3fbb92341143f2e3590a61a08 We're sorry for your patience and inconvenience

> Jump.tar.gz 2040eea8d701ec57a9f38b204b443487e482c5fe


> [!NOTE]
> Initially this note was not available.

## Solution ##

Loading file into Ghidra allows us to get the general sense of the ARM assembly.

From the strings 'Correct' and 'Incorrect' we can trace our way back to the at address `00400c40` where we can locate the following code:

```assembly
            00400a3c      adr          x8,0x400a3c
            00400a40      ldrsw        x9,[x10, x11, LSL #0x2]=>switchD_00400a48::sth_interesting
            00400a44      add          x8,x8,x9
            00400a48      br           x8
```

Where we load the address of `0x400a3c` to `x8`. Next we load an offset by `x11` value from `x10` to `x9`. We add the two together and we jump there.
If we check the values defined at `sth_interesting` we can see the following:

```
switchD_00400a48::sth_interesting               XREF[1]:     flag_start:00400a40(*)
            00400ea0 ddw  E8h
            00400ea4 ddw  198h
            00400ea8 ddw  198h
            00400eac ddw  198h
            00400eb0 ddw  40h
            00400eb4 ddw  198h
            00400eb8 ddw  198h
            00400ebc ddw  198h
            00400ec0 ddw  7Ch
            00400ec4 ddw  198h
            00400ec8 ddw  198h
            00400ecc ddw  198h
            00400ed0 ddw  11Ch
            00400ed4 ddw  198h
            00400ed8 ddw  198h
            00400edc ddw  198h
            00400ee0 ddw  178h
            00400ee4 ddw  198h
            00400ee8 ddw  198h
            00400eec ddw  198h
            00400ef0 ddw  B8h
            00400ef4 ddw  198h
            00400ef8 ddw  198h
            00400efc ddw  198h
            00400f00 ddw  10h
            00400f04 ddw  198h
            00400f08 ddw  198h
            00400f0c ddw  198h
            00400f10 ddw  148h
```

The `198h` are a bit mysterious, but if we navigate to the address of `0x400a3c` plus every 4th value in that list (i.e. `0xe8`, `0x40`, etc.) and follow the jumps, we can get the rules that define the charts of the flag.

For example for the first value, going to an address of `0x400a3c+0xE8` and following the jumps we can end up in the following code:

```
undefined FUN_0040090c()
0040090c sub          sp,sp,#0x10
00400910 str          x30,[sp, #local_8]
00400914 ldr          x30,[sp, #local_8]
00400918 add          sp,sp,#0x10
0040091c sub          sp,sp,#0x10
00400920 str          w0,[sp, #local_8+0x4]
00400924 ldr          w8,[sp, #local_8+0x4]
00400928 mov          w9,#0x4553
0040092c movk         w9,#0x4343, LSL #16
00400930 subs         w8,w8,w9
00400934 cset         w8,eq
...
```
This is just a part of the code, but in the above part we set the value of `w8` based on the subtraction of value from `w8` with the value build from `0x4553` and `0x4343` which gives us `SECC` in reverse.
From the above code it's not clear but we can only assume it's the first 4 characters of the pass.

Following the other offsets we can extract more characters of the flag:

`0xdeadbeef ^ 0xebd6f0a0 = 0x357b4e4f`

and converting it to string

`bytes.fromhex(hex(0xdeadbeef ^ 0xebd6f0a0)[2:])[::-1] = b'ON{5'`

`bytes.fromhex(hex(0xcafebabe ^ 0xf9958ed6)[2:])[::-1] = b'h4k3'`

`bytes.fromhex(hex(0xc0ffee ^ 0x5fb4ceb1)[2:])[::-1] =  b'_1t_'`

The next sections (offsets: `0x178`, `0xB8`, `0x10`). Analyzing those we can conclude that the check for the flag is the following:

`previous_flag_section + flag_part - constant == 0`

To get the next flag values we need to revert the equations and pass the right values:

`bytes.fromhex(hex(0x94d3a1d4 - 0x5f74315f)[2:])[::-1] = b'up_5'`

`bytes.fromhex(hex(0x9d949ddd - 0x355f7075)[2:])[::-1] = b'h-5h'`

`bytes.fromhex(hex(0x9d9d6295 - 0x68352d68)[2:])[::-1] = b'-5h5'`

That gives us the almost every part of the flag - `SECCON{5h4k3_1t_up_5h-5h-5h5`.

The last part of the check, at offset `0x148`, although similar to the previous 3 checks, does not want to produce printable characters. But if we would add extra 3 characters to the flag plus `}` at the end, binary would print "Correct". There's some missing piece in the binary itself and it does not validate the last part correctly.

Here where's the extra note is handy. With the SHA-1 of the correct pass we can brute force the missing chars with the following script:

```python
import hashlib
import itertools
right = 'c69bc9382d04f8f3fbb92341143f2e3590a61a08'

alpha = range(0x20,0x7f)

for c1,c2,c3 in itertools.product(alpha, repeat=3):
    test = bytearray(b'SECCON{5h4k3_1t_up_5h-5h-5h5')
    test.append(c1)
    test.append(c2)
    test.append(c3)
    test.append(ord('}'))
    d = hashlib.sha1(test).hexdigest()
    if right == d:
        print('got it')
        print(test)
        break
```
That will quickly generate correct one for us: `SECCON{5h4k3_1t_up_5h-5h-5h5hk3}`.