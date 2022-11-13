# BBB

In the task, we get a prime number `p`, a number `a` and we're allowed to input a number `b`.
This constructs a simple RNG
$$
rng(x) = (x^2 + ax + b) % p
$$

Next, we construct five RSA public keys from five seeds from the user, and receive the flag (padded) encrypted with them.
```
def generate_key(rng, seed):
    e = rng(seed)
    while True:
        for _ in range(randint(10,100)):
            e = rng(e)
        p = getPrime(1024)
        q = getPrime(1024)
        phi = (p-1)*(q-1)
        if gcd(e, phi) == 1:
            break

    n = p*q
    return (n, e)
```

`n` in the public keys is out of our control. On the other hand, `e` equals to rng iterated at least 11 times to `seed`. It also cannot be lower than 11.

From an assert on the length of FLAG, we learn that data we encrypt is at most 115 bytes (=920 bits) long.

My goal was to set all public exponents `ei` to the same value. If this is possible, we could use CRT on `[flag^e % n[0], flag^e % n[1], ...]` and moduli `[n[0], n[1], ...]` to receive `flag^e % (n[0]*n[1]*...)`. If we can guarantee that flag^e is less than the product of `n`s, then we can take an integer `e`-th root to receive flag in full. As it turns out, it is possible only with `e=11`, since `920*11 = 10120 < 10240 = 2048*5`. How to set all the public exponents to 11? Given that we don't know how many times we iterate `rng`, an obvious thought is to select `b` so that 11 is a fixed point of `rng`. Let's solve equation:
```
11 = 11^2 + a*11 + b
```
```
b = 11 - 11^2 - a*11
```

However, the seeds we pass shall be unique. This is not an issue, since the rng is iterated at least 11 times first. So, we can create a set of five numbers such that their eleventh iterate of rng is equal to 11. This can be done by repeatedly solving quadratic equations:
```
11 = x^2 + a*x + b
```
this gives some solution `x0` (different than 11). Now continue with finding the solution to `x0 = rng(x)`, and so on.
Quadratic equations modulo are solved the same way as regular quadratic equations, with the exception that instead of real square root, you calculate modular square root, which can be done in Sage with `Zmod(p)(x).sqrt()`.
