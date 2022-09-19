import base64
import struct
from pwn import *
import sha256

proc = process('./interweave')
# On the CTF, the following code was neccessary to connect to the challenge server:
# proc = remote('101.132.105.41.nip.io',22022)
# proc.send('CONNECT <redacted> HTTP/1.1\r\n\r\n')
# print(proc.recvline())
# print(proc.recvline())
# print(proc.recvline())

blobs = [base64.b64decode(proc.recvline()) for i in range(16)]

hashes_offset = 0x1000
code = open('flag3', 'rb').read()
code = code[:-9]  # remove the replaceme string
elfs = [code + blobs[i] for i in range(16)]
elfs = [b + b'\x00'*(hashes_offset-len(b)) for b in elfs]
hashes = b''.join([sha256.generate_hash(b) for b in elfs])
elfs = [b + hashes for b in elfs]

for b in elfs:
    proc.send(base64.b64encode(b).replace(b'=', b'') + b'\n')

proc.interactive()
