p = gcd(int( Zmod(n)(c1+c2)/2), n)
q = gcd(int( Zmod(n)(c2-c1)/2), n)
for i in [-1, 1]:
    for j in [-1, 1]:
        for k in [-1, 1]:
            xxs = [int(Zmod(xx)(solsq).sqrt())*yy for xx, yy in zip([p, q, r], [i, j, k])] 
            print(int(crt(xxs, [p, q, r])).to_bytes(260, 'big'))

