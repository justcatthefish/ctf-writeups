def bits_to_n(bits):
    n = int(0)
    for b in reversed(bits):
        n <<= int(1)
        n |= int(b)
    return int(n)

def calc(eqs, vals):
    K = Zmod(2)
    M = matrix(K, len(eqs), 128)
    for i, eq in enumerate(eqs):
        for j in range(128):
            if eq & (2**j):
                M[i,j] = 1
    vals = map(K, vals)
    res = list(M.solve_right(vector(K, vals)))
    assert len(res) == 128
    xorshift0 = bits_to_n(res[:64])
    xorshift1 = bits_to_n(res[64:])
    return xorshift0, xorshift1
