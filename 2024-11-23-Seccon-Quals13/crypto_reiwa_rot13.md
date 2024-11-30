# reiwa_rot13

For each byte rot13 either adds or substracts 13*2^(8*i). There are only 10 bytes so we can bruteforce the difference
$$ k = `bytes_to_long(rot13_key)` - `bytes_to_long(key)` $$

With known difference the problems boils down to solving this set of equations in unknown X:
$$ X^e == c1  (mod n) $$
$$ (X + k)^e == c2  (mod n) $$
We can treat these equations symbolically, i.e. as elements of Z/nZ[X]. By calculating gcd of two polynomials
$$ X^e - c1 $$
$$ (X + k)^e - c2 $$
we will be left with non-constant polynomial, because we know that these two polynomials share a common root.
In fact, we are left with linear polynomial, which can be easily solved to obtain value of `bytes_to_long(key)`.

