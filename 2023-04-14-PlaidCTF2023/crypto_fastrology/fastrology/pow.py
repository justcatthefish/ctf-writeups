#!/usr/bin/env python3

import hashlib
import itertools
import string


alphabet = bytes(string.ascii_letters + string.digits, 'ascii')


def calc_pow(pref, length, hsh_fun, hsh_suf):
    try:
        pref = pref.encode()
    except AttributeError:
        pass
    try:
        hsh_fun = hsh_fun.decode()
    except AttributeError:
        pass
    try:
        hsh_suf = hsh_suf.decode()
    except AttributeError:
        pass

    assert hsh_fun == 'sha256sum'
    assert len(pref) < length
    assert all(c in string.hexdigits for c in hsh_suf)

    len_suf = length - len(pref)
    m = hashlib.sha256()
    m.update(pref)
    for suf_ in itertools.product(alphabet, repeat=len_suf):
        suf = bytes(suf_)
        mc = m.copy()
        mc.update(suf)
        digest = mc.hexdigest()
        if digest.endswith(hsh_suf):
            return (pref + suf).decode()

def do_pow(io):
    io.recvuntil(b'Give me a string starting with ')
    pref = io.recvuntil(b' ', drop=True)
    io.recvuntil(b'of length ')
    length = int(io.recvuntil(b' ', drop=True), 10)
    io.recvuntil(b'so its ')
    hsh_fun = io.recvuntil(b' ', drop=True)
    io.recvuntil(b'ends in ')
    hsh_suf = io.recvuntil(b'.', drop=True)
    sol = calc_pow(pref, length, hsh_fun, hsh_suf)
    io.sendline(sol.encode())


if __name__ == '__main__':
    from pwn import *

    io = remote('fastrology.chal.pwni.ng', 1337)

    do_pow(io)
    io.interactive()
