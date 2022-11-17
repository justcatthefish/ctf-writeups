#!/usr/bin/env python3
# Author: MrQubo

# This handy scripts prints which bits of state are used to generate the last
# two bits of MT19937 output.

import z3

bits = [z3.BitVec(f'B_{i}', 1) for i in range(32)]

NBIT, N, M, R = (32, 624, 397, 31)
A = 0x9908B0DF
U, D = (11, 0xFFFFFFFF)
S, B = (7, 0x9D2C5680)
T, C = (15, 0xEFC60000)
L = 18
y = z3.Concat(*reversed(bits))
y = y ^ (z3.LShR(y, U) & D)
y = y ^ ((y << S) & B)
y = y ^ ((y << T) & C)
y = y ^ (z3.LShR(y, L))
print(z3.simplify(z3.Extract(31, 31, y)))
print(z3.simplify(z3.Extract(30, 30, y)))
