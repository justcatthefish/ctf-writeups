# Secret
## Chall Author: lyc

## Description

![](./description_screenshot.png "Description")

Too many secrets ...

[secret-e35f5c21e032b74b1ab8110722c593847c2534cb.zip](./secret.zip)

URLs

Attachments

<br />

## Solution

I've immediately though I known how to solve this as this seemed like a standard
problem. I've started writing a solution and that's when I noticed I'm not given
`n`! So I need to recover is somehow.

<br />

### Recovering `n`

Because I'm given some numbers modulo `n` usually the way to reciver `n` is to
find some equations that are equal to 0 mod `n`. If I calculate the value of
such equation in integers I will get some multiplicity of `n`. Notice that this
multiplicity must be not equal to 0, otherwise it's not helpful. Once you have
some multiplicity of `n`, you can try iterating over it's divisors, but that
might take too much time if the number is too big. The problem can be made much
easier by finding multiple different mupltiplicities of `n` and calculating gcd
of these.

<br />

To find some non-0 multiplicity of `n` I've decided to calculate two different
combinations of ciphertexts that yields the same power of `m`. Let's denote the
exponents as `e_0, ..., e_63` and ciphertexts as `c_0, ..., c_63`, i.e. `c_i :=
m^{p + e_i}  (mod n)`. I want to find two different sequences `a_0, ..., a_63`
and `b_0, ..., b_63`, such that `Prod c_i^{a_i} === Prod c_i^{b_i}  (mod n)`.
(By `Prod c_i^{a_i}` I mean `c_0^{a_0} * ... * c_63^{a_63}`.) This way the
difference of those two products is 0 modulo `n`, and so it is some multiplicity
of `n`. The sequences must be different otherwise the difference is trivially
equal to 0. Also, the exponents must be positive as I can't calculate the
modular inverse without knowning `n`.

I can rewrite `Prod c_i^{a_i}` as `m^{Sum a_i (p + e_i)}` and so I can change my
equation to `Sum a_i (p + e_i) === Sum b_i (p + e_i)  (mod n)`. I don't know `p`
and `n`, but I can ensure that this equation is satisfied for any `p` and `n` by
ensuring those two conditions:
```
Sum a_i == Sum b_i`
```
```
Sum a_i e_i == Sum b_i e_i`
```

<br />

There might be some smart way to find sequences that satisfy those two
conditions, but I simply used the power of Wolfram Engine (can be used for free
with some limitations on
[https://www.wolframcloud.com/](https://www.wolframcloud.com/)) to solve this
for me.
Note: After the CTF I've found out this can be solved easily with LLL (Thanks to
Robin for the idea). You can skip the remaining section if you want to read
about that other solutions (it's more educative).

#### Using Wolfram Engine

I've used
[FindInstance](https://reference.wolfram.com/language/ref/FindInstance.html) to
find the solutions. I've written the script to generate the wolfram language
code, which I copy-pasted on wolfram cloud website. Here's the script:
[gen\_eqns\_for\_wolfram.py](./gen_eqns_for_wolfram.py). Here's the script that
will parse the solutions copy-pasted from wolfram:
[parse\_res\_from\_wolfram.py](./parse_res_from_wolfram.py).

I've added bounds like `0 ≤ a0 < 2^31`. This is because I will have to calculate
the products exactly, so the exponents cannot be too big.

To find multiple different solutions I've added inequalities like `a0 - b0 ≠
3304`. Simply using the last parameter of FindInstance[] function probably won't
work, as it would find equivalent solutions, more on this later.

<br />

#### Using LLL

I want
```
Sum a_i - Sum b_i == 0
```
```
Sum a_i e_i - Sum b_i e_i == 0
```
I can treat these as equations with 128 unknowns `a_i`, `b_i`. I can put these
equations into matrix. With three ciphertexts it would look like this:
```
1 0 0 0 0 0  1  e_0
0 1 0 0 0 0  1  e_1
0 0 1 0 0 0  1  e_2
0 0 0 1 0 0 -1 -e_0
0 0 0 0 1 0 -1 -e_1
0 0 0 0 0 1 -1 -e_2
```
and with 64 ciphertexts:
```
1 0                  1  e_0
0 1                  1  e_1
    ...              ...
        1 0          1  e_63
        0 1         -1 -e_0
            ...      ...
                1 0 -1 -e_62
                0 1 -1 -e_63
```

Let's denote this matrix by M. If `a_i`, `b_i` is a solution to the problem I
want to solve then
```
(a_0, ..., a_63, b_0, ..., b_63) M == (a_0, ..., a_63, b_0, ..., b_63, 0, 0)
```

I want absolute values of `a_i` and `b_i` to be small, and 0 is also has a
fairly small absolute value. I can therefore use LLL to find the solutions for
me. Too make sure that LLL won't find solutions where the last to values aren't
0 but some different small values e.g. 1, I must scale the last two columns of
the matrix. I must scale these to be at least an order of magnitude bigger than
the values `a_i`, `b_i`. I don't know how big these can be, so I just picked
some number I consider big.


<br />

Once I got some solution, it can be simplified to make exponents smaller. If
`c^x == c^y` then also `c^{x-z} == c^{y-z}`. I can therefore simplify by taking
`z = min(x, y)` to keep exponents positive. Making expontent smaller simply
gives you a smaller multiplicity of `n` as you divide the difference by `c^z`.
That's why two different pair of sequences `a_i`, `b_i` won't give you any
additional information if they are equal after performing this simplification.

Thanks to the solutions I've found I can take the gcd of different
multiplicities of `n` to calculate some smaller multiplicity of `n`. As `n =
p*q`, where `p` and `q` are big primes I can also divide this multiplicity by
small primes (2, 3, 5, 7, ...) as these for sure aren't part of `n`. After that
I checked log2 of the number. I know that `n` has about 2048 bits, so if log2 is
smaller than 2048, and I divided all 2s from the number, this confirms that the
number I've recovered is not just a multiplicity of `n`, it's exactly `n`.

<br />

### Recovering the message

Once I know `n` this is almost the standard problem. I don't know `p` so I don't
know what are the exponents. But dividing `c_0` by `c_1` cancels out `p`.
```
c_0 / c_1 === m^{e_0 - e_1}  (mod n)
```

<br />

I can therefore generate multiple different powers of `m`, with known exponents
amd modulo the same `n`.

From `m^a  (mod n)` and `m^b  (mod n)` I can calculate `m^{gcd(a, b)}  (mod n)`.
Here's how it's done.

Denote `g := gcd(a, b)`, `v := m^a  (mod n)`, and `u := m^b  (mod n)`. By using
extended euclidian algorithm
([xgcd()](https://doc.sagemath.org/html/en/thematic_tutorials/group_theory.html#extended-greatest-common-divisor)
in SageMath) I can find `x` and `y`, such that `x*a + y*b == g`. Thereforce, I
calculate
```
v^x * w^y ===  (mod n)
m^{x*a} * m^{y*b} ===  (mod n)
m^{x*a + y*b} ===  (mod n)
m^g.
```
If `g` is 1 this just gives us `m`. NB: xgcd, and so this technique, also works
for more than two exponents.

<br />

Here are the implementations in SageMath:

This one uses solutions computed with wolfram: [solve.sage](./solve.sage)

This one computes solutions using LLL: [solve\_lll.sage](./solve_lll.sage)

<br />

### Writeup Author: MrQubo
