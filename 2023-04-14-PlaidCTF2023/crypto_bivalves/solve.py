#!/usr/bin/env python3

import z3

from handout import iv, ct


def bitstr_to_bitvecvallist(s):
    return [z3.BitVecVal('01'.index(v), 1) for v in s]

def bits_to_bitvecvallist(s):
    return [z3.BitVecVal(v, 1) for v in s]

def bytes_to_bitstr(b):
    return ''.join(f'{x:08b}' for x in b)

def bytes_to_bits(b):
    return ['01'.index(v) for v in bytes_to_bitstr(b)]

def bytes_to_bitvecvallist(b):
    return bitstr_to_bitvecvallist(bytes_to_bits(b))


KEY = [z3.BitVec(f'K{i}', 1) for i in range(8*10)]
IV = bitstr_to_bitvecvallist(iv)

STATE = KEY + bitstr_to_bitvecvallist('0101000001010') + IV + bitstr_to_bitvecvallist('0'*4)

def STEP():
    ret = z3.simplify(STATE[65] ^ STATE[92])
    t1 = z3.simplify(STATE[65] ^ STATE[92] ^ (STATE[90] & STATE[91]) ^ STATE[170])
    t2 = z3.simplify(STATE[161] ^ STATE[176] ^ (STATE[174] & STATE[175]) ^ STATE[68])
    for i in range(92, 0, -1):
        STATE[i] = STATE[i-1]
    STATE[0] = t2
    for i in range(176, 93, -1):
        STATE[i] = STATE[i-1]
    STATE[93] = t1
    return ret

def step():
    ret = state[65] ^ state[92]
    t1 = state[65] ^ state[92] ^ (state[90] & state[91]) ^ state[170]
    t2 = state[161] ^ state[176] ^ (state[174] & state[175]) ^ state[68]
    for i in range(92, 0, -1):
        state[i] = state[i-1]
    state[0] = t2
    for i in range(176, 93, -1):
        state[i] = state[i-1]
    state[93] = t1
    return ret

INIT_STATE = [z3.BitVec(f'S{i}', 1) for i in range(len(STATE))]
STATE = list(INIT_STATE)
print(f'{len(STATE) = }')
#  for _ in range(708):
#      STEP()


ct = bytes_to_bits(ct)
CT = bits_to_bitvecvallist(ct)
pt = bytes_to_bits('''There once was a ship that put to sea
The name of the ship was the Billy O' Tea
The winds blew up, her bow dipped down
Oh blow, my bully boys, blow (huh)

Soon may the Wellerman come
To bring us sugar and tea and rum
One day, when the tonguing is done
We'll take our leave and go

She'd not been two weeks from shore
When down on her right a whale bore
The captain called all hands and swore
He'd take that whale in tow (huh)

Soon may the Wellerman come
To bring us sugar and tea and rum
One day, when the tonguing is done
We'll take our leave and go

- '''.encode('utf-8'))
PT = bits_to_bitvecvallist(pt)
assert len(ct) > len(PT), (len(ct), len(PT))
FLAG = [z3.BitVec(f'F{i}', 1) for i in range(len(ct) - len(PT))]
PT += FLAG
assert len(ct) == len(PT)


s = z3.Solver()

N = 200
for i in range(N):
    print(f'{i}/{N}')
    s.add(z3.simplify(STEP() ^ PT[i]) == ct[i])


print('[*] solving...')
def all_smt(s, initial_terms):
    """
    yielding all satisfying models over `initial_terms` on a
    z3.Solver() instance `s` containing constraints
    """

    from z3 import sat

    def block_term(s, m, t):
        s.add(t != m.eval(t))

    def fix_term(s, m, t):
        s.add(t == m.eval(t))

    def all_smt_rec(terms):
        while sat == s.check():
            m = s.model()
            yield m
            for i in range(1, len(terms)):
                s.push()
                block_term(s, m, terms[i])
                for j in range(i):
                    fix_term(s, m, terms[j])
                yield from all_smt_rec(terms[i:])
                s.pop()
            block_term(s, m, terms[0])
    yield from all_smt_rec(list(initial_terms))

for mi, m in enumerate(all_smt(s, INIT_STATE)):
    print(f'model {mi}')
    state = [m[S].as_long() for S in INIT_STATE]
    flag_bits = []
    for i in range(len(ct)):
        if i < len(pt):
            assert step() ^ pt[i] == ct[i]
        else:
            flag_bits.append(step() ^ ct[i])
    print(int(''.join(map(str, flag_bits)), 2).to_bytes(44, 'big'))
