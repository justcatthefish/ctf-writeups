#!/usr/bin/env python3

import hashlib
import itertools
import multiprocessing

from pow import do_pow

from pwn import *
context.encoding = 'utf8'

from fast_calc import calc


alphabet = '♈♉♊♋♌♍♎♏♐♑♒♓⛎'

class BitVec(list):
    '''A list of integers, implementing bitwise xor and shifts

    Represents a vector of bits, with each bit being a xor
    of some set of variables, represented by a python int.
    e.g.
        b4      --> 0b1000
        b2 + b0 --> 0b0101

    A bit vector equal to 0b(b63)(b62)...(b1)(b0)
    can gradually become sth like 0b(b20^b15^b7)(b6)(0)(b123^b54)...(b8)
    after several xorshift rounds.
    '''
    def __lshift__(self, sh):
        return BitVec([0] * sh + self[:-sh])

    def __rshift__(self, sh):
        return BitVec(self[sh:] + [0] * sh)

    def __xor__(self, sh):
        return BitVec(map(operator.xor, self, sh))

def encode_zodiac(l):
    return ''.join(alphabet[i] for i in l)

def decode_zodiac(s):
    return [alphabet.index(c) for c in s]

def XORSHIFT_STEP(XORSHIFT0, XORSHIFT1):
    X0 = XORSHIFT1
    X1 = XORSHIFT0
    XORSHIFT0 = X0
    X1 ^= X1 << 23
    X1 ^= X1 >> 17
    X1 ^= X0
    X1 ^= X0 >> 26
    XORSHIFT1 = X1
    return XORSHIFT0, XORSHIFT1

def XORSHIFT_GEN(XORSHIFT0, XORSHIFT1):
    while True:
        yield XORSHIFT0 >> 12
        XORSHIFT0, XORSHIFT1 = XORSHIFT_STEP(XORSHIFT0, XORSHIFT1)

def xorshift_step(xorshift0, xorshift1):
    x0 = xorshift1
    x1 = xorshift0
    xorshift0 = x0
    x1 ^= (x1 << 23) & 0xffffffffffffffff
    x1 ^= x1 >> 17
    x1 ^= x0
    x1 ^= x0 >> 26
    xorshift1 = x1
    return xorshift0, xorshift1

def xorshift_gen(xorshift0, xorshift1):
    while True:
        yield xorshift0 >> 12
        xorshift0, xorshift1 = xorshift_step(xorshift0, xorshift1)

def do_v8_order_mangle(g):
    while True:
        yield from reversed(list(itertools.islice(g, 64)))

def solve_offset(offset, prefix, md5hsh):
    prefix = decode_zodiac(prefix)
    assert len(prefix) == 250

    XORSHIFT0 = BitVec([2 ** i for i in range(0, 64)])
    XORSHIFT1 = BitVec([2 ** i for i in range(64, 128)])

    GEN = do_v8_order_mangle(XORSHIFT_GEN(XORSHIFT0, XORSHIFT1))
    for _ in range(offset):
        next(GEN)

    V_backup = [next(GEN) for _ in range(250+128)]

    eqs = []
    vals = []
    for idx in range(250):
        V = next(GEN)

        v = prefix[idx]

        # minimum and maximum possible values of the relevant seed bits
        vmin = (2 ** 52) * v // len(alphabet)
        vmax = (2 ** 52) * (v+1) // len(alphabet) - 1

        eqs_correct = []
        for i in range(51, -1, -1):
            if vmin & (2**i) == vmax & (2**i):
                eqs_correct.append((V[i], bool(vmin & (2**i))))
            else:
                break

        # minimum and maximum possible values of the relevant seed bits
        vmin = (2 ** 52) * 12 // len(alphabet)
        vmax = (2 ** 52) * (12+1) // len(alphabet) - 1

        eqs_backup = []
        for i in range(51, -1, -1):
            if vmin & (2**i) == vmax & (2**i):
                eqs_backup.append((V[i], bool(vmin & (2**i))))
            else:
                break

        # minimum and maximum possible values of the relevant seed bits
        vmin = (2 ** 52) * v // 12
        vmax = (2 ** 52) * (v+1) // 12 - 1

        for i in range(51, -1, -1):
            if vmin & (2**i) == vmax & (2**i):
                eqs_backup.append((V_backup[idx][i], bool(vmin & (2**i))))
            else:
                break

        for eq in (set(eqs_correct) & set(eqs_backup)):
            eqs.append(eq[0])
            vals.append(eq[1])

    try:
        xorshift0, xorshift1 = calc(eqs, vals)
    except ValueError:
        return None

    expected = []
    gen = do_v8_order_mangle(xorshift_gen(xorshift0, xorshift1))
    for _ in range(offset):
        next(gen)
    backup = []
    for idx in range(250+128):
        v = (next(gen) * 12) >> 52
        backup.append(v)
    for idx in range(250+128):
        v = (next(gen) * len(alphabet)) >> 52
        if v == 12:
            v = backup[idx]
        if idx < 250:
            if v != prefix[idx]:
                return None
        else:
            expected.append(v)

    assert len(expected) == 128
    expected = encode_zodiac(expected)
    m = hashlib.md5(expected.encode('utf8'))
    digest = m.hexdigest()

    if digest == md5hsh:
        return expected
    else:
        return None

def worker(t):
    return solve_offset(*t)

def solve(prefix, md5hsh):
    P = 4
    tasks = [(offset, prefix, md5hsh) for offset in range(64)]
    with multiprocessing.Pool(processes=P) as pool:
        for i in range(0, len(tasks), P):
            result = pool.map(worker, tasks[i:i+P])
            for r in result:
                if r is not None:
                    return r


io = remote('fastrology.chal.pwni.ng', 1337)
do_pow(io)
io.sendline('waxing gibbous')

context.log_level = 'debug'
for ii in range(50):
    io.recvuntil('waxing gibbous: trial ')
    io.recvline()
    with context.local(log_level='warn'):
        prefix = io.recvlineS(keepends=False)
        md5hsh = io.recvlineS(keepends=False)
        io.sendline(solve(prefix, md5hsh).encode('utf8'))
        io.recvline()
        io.recvline()

io.interactive()
