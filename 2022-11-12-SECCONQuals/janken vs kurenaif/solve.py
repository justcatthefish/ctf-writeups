#!/usr/bin/env python3
# Author: MrQubo

import os
import random
import gzip
import numpy as np


class MT19937():
    """MT19937 iterator. Inputs are internal state"""

    def __init__(self, state=None, ind=0):
        '''
        Init MT19937 constants

        If state is given, MT19937.state will be assigned said state
            state is a list of 624 32-bit numbers
        '''

        self.NBIT, self.N, self.M, self.R = (32, 624, 397, 31)
        self.A = 0x9908B0DF
        self.U, self.D = (11, 0xFFFFFFFF)
        self.S, self.B = (7, 0x9D2C5680)
        self.T, self.C = (15, 0xEFC60000)
        self.L = 18

        self.NBIT2 = 2**self.NBIT

        self.lower_mask = (1 << self.R) - 1
        self.upper_mask = (self.NBIT2 - self.lower_mask - 1) % self.NBIT2

        self.untwist_mat = None

        self.ind = ind

        if not state:
            state = [0] * self.N
        self.state = state

    def init_genrand(self, s, *, is_z3=False, verbose=False):
        N = self.N
        mt = self.state
        mt[0] = s
        if is_z3:
            for mti in range(1, N):
                mt[mti] = (1812433253 * (mt[mti-1] ^ z3.LShR(mt[mti-1], 30))) + mti
        else:
            for mti in range(1, N):
                mt[mti] = (1812433253 * (mt[mti-1] ^ (mt[mti-1] >> 30)) % self.NBIT2) + mti
                mt[mti] %= self.NBIT2

        # Some debugging stuff.
        if verbose:
            if is_z3:
                print('init_genrand:', *(z3.simplify(x) for x in mt[:10]))
            else:
                print('init_genrand:', *(x for x in mt[:10]))

        self.ind = 0

    def init_by_array(self, key, *, is_z3=False, verbose=False):
        N = self.N
        mt = self.state
        if is_z3:
            self.init_genrand(z3.BitVecVal(19650218, 32), is_z3=True, verbose=verbose)
        else:
            self.init_genrand(19650218, verbose=verbose)
        i = 1
        j = 0
        k = max(N, len(key))
        while k:
            if is_z3:
                mt[i] = (mt[i] ^ (((mt[i-1] ^ z3.LShR(mt[i-1], 30)) * 1664525))) + key[j] + j
            else:
                mt[i] = (mt[i] ^ (((mt[i-1] ^ (mt[i-1] >> 30)) * 1664525) % self.NBIT2)) + key[j] + j
                mt[i] %= self.NBIT2
            i += 1
            j += 1
            if i >= N:
                mt[0] = mt[N-1]
                i = 1
            if j >= len(key):
                j = 0
            k -= 1

        # Some debugging stuff.
        if verbose:
            if is_z3:
                print('init_by_array_1:', *(z3.simplify(x) for x in mt[:10]))
            else:
                print('init_by_array_1:', *(x for x in mt[:10]))

        k = N - 1
        while k:
            if is_z3:
                mt[i] = (mt[i] ^ (((mt[i-1] ^ z3.LShR(mt[i-1], 30)) * 1566083941))) - i
            else:
                mt[i] = (mt[i] ^ (((mt[i-1] ^ (mt[i-1] >> 30)) * 1566083941) % self.NBIT2)) - i
                mt[i] %= self.NBIT2
            i += 1
            if i >= N:
                mt[0] = mt[N-1]
                i = 1
            k -= 1

        # Some debugging stuff.
        if verbose:
            if is_z3:
                print('init_by_array_2:', *(z3.simplify(x) for x in mt[:10]))
            else:
                print('init_by_array_2:', *(x for x in mt[:10]))

        if is_z3:
            mt[0] = z3.BitVecVal(0x80000000, 32)
        else:
            mt[0] = 0x80000000

    def twist(self, state, *, is_z3=False):
        '''twist the states'''

        for i in range(self.N):
            # x = states[(i+1) % n] (except highest bit) + states[i] (highest bit)
            x = (state[i] & self.upper_mask) + (state[(i+1) % self.N] & self.lower_mask)

            if is_z3:
                xA = z3.LShR(x, 1)
                xA ^= z3.If((x & 1) == 1, z3.BitVecVal(self.A, 32), z3.BitVecVal(0, 32))
                #  s.add((x & 1) == 0)
                #  xA ^= self.A
            else:
                xA = x >> 1
                if (x % 2) != 0: # invokes if states[(i+1) % n] has 0-th bit set
                    xA = xA ^ self.A

            state[i] = state[(i + self.M) % self.N] ^ xA

        return state

    def generate(self, ind, states, *, skip_twist=False):
        '''generate random number from states'''

        if not skip_twist and ind == 0:
            states = self.twist(states)

        y = states[ind]
        y = y ^ ((y >> self.U) & self.D)
        y = y ^ ((y << self.S) & self.B)
        y = y ^ ((y << self.T) & self.C)
        y = y ^  (y >> self.L)

        return y % 2**self.NBIT, states

    def __call__(self, *, skip_twist=False):
        '''Returns random number and updates index'''

        y, self.state = self.generate(self.ind, self.state, skip_twist=skip_twist)
        self.ind = self.ind + 1
        self.ind %= self.N
        return y


from pwn import *
context.encoding = 'UTF-8'

io = remote('janken-vs-kurenaif.seccon.games', 8080)
io.recvuntil('My spell is ')
witch_spell = io.recvuntil('.', drop=True)
witch_rand = random.Random()
witch_rand.seed(int(witch_spell, 16))

expected = [(witch_rand.randint(0, 2) + 1) % 3 for _ in range(666)]
#  expected = [(random.randint(0, 2) + 1) % 3 for _ in range(666)]

# Generate state from which we can win all hands.
# We initialize our state with just expected bits on the last two bits
# position. This will generate expected resuults for the first 624 numbers.
state = [expected[i] << 30 for i in range(624)]
my_rng = MT19937()
# After 624 outputs twist will happen. We need to affect the generated numbers
# after twist, without changing generated numbers before twist.
# B_31 ^ B_24 ^ B_16 ^ B_27
# B_30 ^ B_15 ^ B_26
for i in reversed(range(666-624)):
    act = my_rng.generate(i, my_rng.twist(list(state)), skip_twist=True)[0] >> 30
    exp = expected[i+624]
    if ((act ^ exp) >> 1) == 1:
        # Setting last bit on the next state will trigger xor with `A` in twist.
        state[i+1] |= 1
        act2 = my_rng.generate(i, my_rng.twist(list(state)), skip_twist=True)[0] >> 30
        assert act2 == act ^ 0b11, (act2, act)
        act = act2
    if ((act ^ exp) & 1) == 1:
        # Here I change bits 31 and 16 so it doesn't affect results before
        # twist.
        state[i] ^= 0x80000000 | (1 << (32-my_rng.T-1))
    act2 = my_rng.generate(i, my_rng.twist(list(state)), skip_twist=True)[0] >> 30
    assert act2 == exp, (act2, exp)

#  untwisted_state = my_rng.untwist(list(state))
#  my_rng.state = untwisted_state
#  assert state == my_rng.twist(list(my_rng.state)), "Couldn't untwist, try again."
#
#  for i in range(666):
#      assert (my_rng() >> 30) == expected[i], (i, expected[i])


import z3

# At first, I didn't separate untwist and unkey steps into two solvers. I waited
# for long and it couldn't find any solution.
# My theory is that it was searching very long for possible solutions when it
# wasn't able to untwist the state. By limiting it to finding any solution for
# untwist and then trying to unkey it was able to find out that it's not
# possible to untwist much faster. That's just a theory though.

# Untwist state. This only works from time to time.
UNTWISTED_STATE = [z3.BitVec(f'STATE_{i}', 32) for i in range(624)]
s = z3.Solver()
my_rng = MT19937()
my_rng.state = my_rng.twist(list(UNTWISTED_STATE), is_z3=True)
assert len(my_rng.state) == len(state)
for x, y in zip(my_rng.state, state):
    y = z3.BitVecVal(y, 32)
    # Only these bits are used to generate last two bits of MT19937 outputs.
    # Maybe not all of them, not 100% sure.
    for bi in [31, 30, 28, 27, 26, 25, 24, 17, 16, 15, 0]:
        s.add(z3.simplify(z3.Extract(bi, bi, x) == z3.Extract(bi, bi, y)))
s.add(UNTWISTED_STATE[0] == 0x80000000)
res = s.check()
print('untwist:', res)
if res == z3.unsat:
    s2 = z3.Solver()
    s2.check(s.assertions())
    print(s2.unsat_core())
    print('Bad luck this time. Try rerunning.')
    exit(1)
m = s.model()
untwisted_state = [m[x].as_long() for x in UNTWISTED_STATE]

# Find seed which produces untwisted_state. This worked every time.
KEY = [z3.BitVec(f'KEY_{i}', 32) for i in range(624)]
s = z3.Solver()
my_rng = MT19937()
my_rng.init_by_array(KEY, is_z3=True)
assert len(my_rng.state) == len(untwisted_state)
for x, y in zip(my_rng.state, untwisted_state):
    s.add(x == y)
res = s.check()
print('unkey:', res)
if res == z3.unsat:
    s2 = z3.Solver()
    s2.check(s.assertions())
    print(s2.unsat_core())
    exit(1)
m = s.model()
key = [m[x].as_long() for x in KEY]

key_bytes = bytearray()
for i in range(len(key)):
    key_bytes.append(key[~i] >> 24 & 0xFF)
    key_bytes.append(key[~i] >> 16 & 0xFF)
    key_bytes.append(key[~i] >> 8 & 0xFF)
    key_bytes.append(key[~i] & 0xFF)

# Check that it works.
rand = random.Random(int(key_bytes.hex(), 16))
for i in range(666):
    assert rand.getrandbits(2) == expected[i]

context.log_level = 'debug'
io.sendlineafter('your spell: ', key_bytes.hex())
io.interactive()

# Some debugging stuff.
#  print('expected:\n', *expected[:20])
#  print('pyrand:\n', *(rand.getrandbits(2) for _ in range(20)))
#  my_rng = MT19937()
#  my_rng.init_by_array(key)
#  print('key:\n', *(my_rng() >> 30 for _ in range(20)))
#  my_rng = MT19937()
#  my_rng.state = list(untwisted_state)
#  print('untwisted_state:\n', *(my_rng() >> 30 for _ in range(20)))
#  my_rng = MT19937()
#  my_rng.state = list(state)
#  print('state:\n', *(my_rng(skip_twist=True) >> 30 for _ in range(20)))
#
#  my_rng = MT19937()
#  my_rng.init_by_array(key, verbose=True)
#  my_rng = MT19937()
#  my_rng.init_by_array([z3.BitVecVal(x, 32) for x in key], is_z3=True, verbose=True)
