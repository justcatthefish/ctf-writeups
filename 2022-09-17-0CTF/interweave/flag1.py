import base64
import struct
from pwn import *

proc = process('./interweave')
# On the CTF, the following code was neccessary to connect to the challenge server:
# proc = remote('101.132.105.41.nip.io',22022)
# proc.send('CONNECT <REDACTED> HTTP/1.1\r\n\r\n')
# print(proc.recvline())
# print(proc.recvline())
# print(proc.recvline())

blobs = [base64.b64decode(proc.recvline()) for i in range(16)]

code = open('flag1', 'rb').read()
code = code[:-9]  # remove the replaceme string

for blob in blobs:
    b = code + blob
    proc.send(base64.b64encode(b).replace(b'=', b'') + b'\n')

proc.interactive()
