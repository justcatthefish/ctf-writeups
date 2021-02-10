"""
Send a file to the challenge server
"""
from pwn import *

FNAME = args.FNAME
with remote('localhost', 31337) as p:
    # Enter your username
    x = p.recv()

    p.sendline('abcdefgh123456799')

    # What would you like to do?
    p.recv()
    p.sendline('1')  # Start new session

    # Session name:
    p.recv()
    p.sendline(FNAME)

    payload = read(FNAME)
    lines = payload.split(b'\n')

    for l in lines:
        p.recv()
        p.sendline(l)

    p.sendline('')

p.interactive()

