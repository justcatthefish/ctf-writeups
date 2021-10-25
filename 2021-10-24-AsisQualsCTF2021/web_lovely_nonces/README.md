# Lovely nonces (ASIS CTF Quals 2021): the unintended way

## The quasi-crypto part

*by [Arusekk](//Arusekk.github.io)*

The first thing I noticed in this task was unsafe random nonce generation.
Unpredictable random values in Node.js should be generated using
[`crypto.random*()`](https://nodejs.org/api/crypto.html#cryptorandombytessize-callback)
and not `Math.random()`, which is designed to be fast, not safe.

So while the others were working on an XSS payload that would work,
I searched v8 (the JavaScript engine used by Node.js) sources for
the implementation behind `Math.random()`.
It turned out to be xorshift128, which is a wonderful algorithm,
passing strict randomness tests, while still being very fast.
But since it only uses bitwise xor and shift operations, it is trivial
to predict.

Since the internal state of xorshift128 is 128 bits
(actually `2 ** 128 - 1` possible values),
I counted how many nonces (one nonce = 16 independent chars from a set of 36,
`36 ** 16` possible values) are necessary to reconstruct the xorshift128 rng
internal state, which would allow us to reconstruct all nonces generated
in the challenge (and so be able to predict them):
```py
>>> import math
>>> math.log((2 ** 128 - 1), 36 ** 16)
1.5474112289381663
```
Meaning that slightly more than one and a half nonce would be enough.

So I wrote a simple Z3-based SAT solver for two consecutive nonces:
```py
import z3

nonce0 = "zyovm6kz13cmhb7f"
nonce1 = "fgfleffuh9n5nz67"

xorshift0 = z3.BitVec('state0', 64)
xorshift1 = z3.BitVec('state1', 64)
s = z3.Solver()

for x in nonce0 + nonce1:
    v = 'abcdefghijklmnopqrstuvwxyz0123456789'.index(x)
    s.add((z3.LShR(xorshift0, 12) * 36) >> 52 == v)

    x0 = xorshift1
    x1 = xorshift0
    xorshift0 = x0
    x1 ^= x1 << 23
    x1 ^= z3.LShR(x1, 17)
    x1 ^= x0
    x1 ^= z3.LShR(x0, 26)
    xorshift1 = x1

print(s.check())
mod = s.model()

print('%016x' % mod.evaluate(xorshift0).as_long())
print('%016x' % mod.evaluate(xorshift1).as_long())
```

(wasting 1h on figuring out that `a >> b` is an [arithmetic shift] by default,
and it is necessary to use `z3.LShR(a, b)` to bypass that)

[arithmetic shift]: https://en.wikipedia.org/wiki/Arithmetic_shift

Then I wasted another hour debugging, just to find out that v8 uses [caching]
and returns the values in partially reverse order, so if xorshift were to return
all the integers in order, Math.random() would return such a sequence:
```
63, 62, 61, ..., 1, 0, 127, 126, 125, ..., 65, 64, 191, 190, ..., 129, 128, ...
```

[caching]: https://github.com/v8/v8/blob/17a99fec258bcc07ea9fc5e4fabcce259751db03/src/numbers/math-random.cc

But then I found out that z3 is gravely slow, too slow for this task for sure
(running it for an hour in the background did not find a single solution).

So I decided to write a custom implementation using basic linear algebra,
you can find the whole code in fake-http-server.py (there are comments with explanation).

It turned out that with my algorithm, 3 nonces were needed to fully recover the
random state. Not sure if this was 100% necessary, it could probably be
reduced back to 2.

In order to minimize the chance of someone getting a nonce between our nonces,
we just sent the string
`GET / HTTP/1.1<CRLF><CRLF>GET / HTTP/1.1<CRLF><CRLF>GET / HTTP/1.1<CRLF><CRLF>`
over a TCP connection to the server, taking advantage of request pipelining.
It works quite well, and gives the correct results once in 4 times on average.

## The web part

*by [haqpl](//haqpl.github.io)*

to be filled in
