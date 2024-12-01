# dual_summon
# Solver: MrQubo

In AES-GCM single nonce reuse is enough to recover hash key and forge tags for arbitrary messages.

Xoring bit of plaintext is the same as xoring bit of ciphertext, which corresponds to addition/substraction (it's the same) in GF(2^256).
Finding two plaintexts with equal tags boils down to solving set of linear equations in GF(2).

Our solver:

```py
from sage.all import *

from pwn import *

from Crypto.Cipher import AES
import secrets
import os

# p = process('./server.py')
p = remote('dual-summon.seccon.games', 2222)

# keys = [secrets.token_bytes(16) for _ in range(2)]
# nonce = secrets.token_bytes(16)

def xor(a, b):
    return bytes(x^y for x, y in zip(a, b, strict=True))

def xe(n):
    return (2**n).to_bytes(16, 'big')


def summon(number, plaintext):
    p.sendlineafter(b"[1] summon, [2] dual summon >", b'1')
    p.sendlineafter(b"summon number (1 or 2) >", str(number).encode())
    p.sendlineafter(b"name of sacrifice (hex) >", plaintext.hex().encode())
    p.recvuntil(b"tag(hex) = ")
    tag = bytes.fromhex(p.recvlineS(keepends=False))
    print(f"{tag = }")
    return tag


F = PolynomialRing(GF(2), 'x')
F.inject_variables()
K = GF((2, 128), name='t', modulus=x**128 + x**7 + x**2 + x + 1)
K.inject_variables()

def to_bits(H, bn):
    n = int.from_bytes(H)
    assert n in range(2**bn)
    return tuple(map(int, bin(n + 2**bn)[-bn:]))

def bits_to_bytes(bb):
    return int(''.join(reversed(''.join(map(str, bb)))), 2).to_bytes((len(bb)+7)//8, 'big')

def bytes_to_field(b):
    return K(to_bits(b, 128))

# H0 = AES.new(key=keys[0], mode=AES.MODE_ECB).encrypt(bytes(16))
# H0 = bytes_to_field(H0)

# H1 = AES.new(key=keys[1], mode=AES.MODE_ECB).encrypt(bytes(16))
# H1 = bytes_to_field(H1)

plaintext = bytes(16)
diff = bytes_to_field(summon(1, plaintext)) - bytes_to_field(summon(1, xor(plaintext, xe(127))))
# assert H0 == sqrt(diff)
H0 = sqrt(diff)

plaintext = bytes(16)
diff = bytes_to_field(summon(2, plaintext)) - bytes_to_field(summon(2, xor(plaintext, xe(127))))
# assert H1 == sqrt(diff)
H1 = sqrt(diff)

R = PolynomialRing(GF(2), 128, 'X')
X = R.gens()

c0 = bytes_to_field(summon(1, plaintext))
c1 = bytes_to_field(summon(2, plaintext))
ai = [(H0**2 - H1**2)*t**(127-i) for i in range(128)]
c = c1-c0
eqns = []
for i in range(128):
    eqn = (sum(list(ai[j])[i]*X[j] for j in range(128)), list(c)[i])
    eqns.append(eqn)
M = matrix([[eq[0].coefficient(u) for u in X] for eq in eqns])
Y = vector([eq[1] for eq in eqns])
x = M.solve_right(Y)
assert sum(x[i]*ai[i] for i in range(128)) == c

print(summon(1, xor(plaintext, bits_to_bytes(x))))
print(summon(2, xor(plaintext, bits_to_bytes(x))))

plaintext = xor(plaintext, bits_to_bytes(x))

p.sendlineafter(b"[1] summon, [2] dual summon >", b'2')
p.sendlineafter(b"name of sacrifice (hex) >", plaintext.hex().encode())
p.interactive()

# SECCON{Congratulation!_you are_master_of_summonor!_you_can_summon_2_monsters_in_one_turn}

print(summon(1, xor(plaintext, bits_to_bytes(x))))
print(summon(2, xor(plaintext, bits_to_bytes(x))))
```
