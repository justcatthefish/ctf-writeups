# reiwa_rot13

For each byte rot13 either adds or substracts `13*2^(8*i)`. There are only 10 bytes so we can bruteforce the difference

```
k = bytes_to_long(rot13_key) - bytes_to_long(key)
```

With known difference the problems boils down to solving this set of equations in unknown X:

```
X^e == c1  (mod n)
(X + k)^e == c2  (mod n)
```

We can treat these equations symbolically, i.e. as elements of `Z/nZ[X]`. By calculating gcd of two polynomials

```
X^e - c1
(X + k)^e - c2
```

we will be left with non-constant polynomial, because we know that these two polynomials share a common root.
In fact, we are left with linear polynomial, which can be easily solved to obtain value of `bytes_to_long(key)`.


Solver:
```py
from sage.all import *
from Crypto.Util.number import *
import codecs
import string
import random
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

n = 105270965659728963158005445847489568338624133794432049687688451306125971661031124713900002127418051522303660944175125387034394970179832138699578691141567745433869339567075081508781037210053642143165403433797282755555668756795483577896703080883972479419729546081868838801222887486792028810888791562604036658927
e = 137
c1 = 16725879353360743225730316963034204726319861040005120594887234855326369831320755783193769090051590949825166249781272646922803585636193915974651774390260491016720214140633640783231543045598365485211028668510203305809438787364463227009966174262553328694926283315238194084123468757122106412580182773221207234679
c2 = 54707765286024193032187360617061494734604811486186903189763791054142827180860557148652470696909890077875431762633703093692649645204708548602818564932535214931099060428833400560189627416590019522535730804324469881327808667775412214400027813470331712844449900828912439270590227229668374597433444897899112329233

encrypted_flag =  b"\xdb'\x0bL\x0f\xca\x16\xf5\x17>\xad\xfc\xe2\x10$(DVsDS~\xd3v\xe2\x86T\xb1{xL\xe53s\x90\x14\xfd\xe7\xdb\xddf\x1fx\xa3\xfc3\xcb\xb5~\x01\x9c\x91w\xa6\x03\x80&\xdb\x19xu\xedh\xe4"

import itertools

Zn = Zmod(n)
Pr = PolynomialRing(Zn, 'X')
Pr.inject_variables()

def mygcd(f,g):
    while g != 0:
        r = g
        g = f % g
        f = r
    return f/f.lc()

for diffs in itertools.product([False, True], repeat=10):
    k = 0
    coef = 1
    for d in diffs:
        k = (k + (13 * coef if d else -13 * coef)) % n
        coef = (coef * 256) % n
    poly = mygcd((X**e - c1), ((X + k)**e - c2))
    key = long_to_bytes(int(-poly.constant_coefficient()))
    key = hashlib.sha256(key).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    flag = cipher.decrypt(encrypted_flag)
    try:
        print(flag.decode())
    except:
        pass
```
