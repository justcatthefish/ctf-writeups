import matplotlib.pyplot as plt
from math import pi
from scipy import optimize
import numpy as np


def snap_x0(v):
    closest = None
    closest_diff = 1000000
    dbg = -1
    for i in range(-12, 13):
        iv = i % (2*pi)
        diff = min(abs(v - iv), abs(v - iv - 2 * pi), abs(v - iv + 2 * pi))
        if diff < closest_diff:
            closest = iv
            dbg = i
            closest_diff = diff
    return closest, dbg


rettab = [None] * 8

def compute(arr, t, segments, tweaks, show=False):
    xs = np.zeros(segments)
    ys = np.zeros(segments)
    counts = np.zeros(segments)

    for i in range(128):
        x = i / 128 * 2 * t
        y = arr[i]
        seg = int(x / 2 * segments) % segments

        counts[seg] += 1
        xs[seg] += (x % 2) * 3.141592653589793
        ys[seg] += y

    xs /= counts
    ys /= counts
    # print(counts)



    def form(x, scale, x0, offset):
        return scale * np.cos(x + x0) + offset

    param, covariance = optimize.curve_fit(form, xs, ys)
    scale = abs(round(param[0]))
    if t in tweaks:
        scale += tweaks[t]
    param, covariance = optimize.curve_fit((lambda x, x0, offset: form(x, scale, x0, offset)), xs, ys)
    x0, x0dbg = snap_x0(param[0])
    param, covariance = optimize.curve_fit((lambda x, offset: form(x, scale, x0, offset)), xs, ys)
    offset = param[0]
    # print(scale, x0dbg)


    if show:
        plt.scatter(xs, ys, label='data')
        plt.ylim(ys.min(), ys.max())
        plt.plot(xs, form(xs, scale, x0, offset), 'b-')
        plt.show()

    for i in range(128):
        arr[i] -= form(i / 128 * 2 * t * 3.141592653589793, scale, x0, *param)

    rettab[t - 1] = (scale, x0dbg)


def try_guess(inarr, tweaks):
    try:
        arr = np.array(inarr)
        compute(arr, 8, 16, tweaks)
        compute(arr, 4, 32, tweaks)
        compute(arr, 6, 64, tweaks)
        compute(arr, 2, 64, tweaks)
        compute(arr, 5, 30, tweaks)
        compute(arr, 3, 24, tweaks)
        compute(arr, 7, 40, tweaks)
        compute(arr, 1, 32, tweaks)

        return abs(max(arr) - min(arr) - 4) <= 0.001
    except RuntimeError:
        return False



def brute(arr):
    global rettab

    precheck = try_guess(arr, {})
    if precheck:
        return True
    saved_rettab = list(rettab)

    for tweak_7 in [0, -1, 1]:
        for tweak_5 in [0, -1, 1, -2, 2, -3, 3, -4, 4, -5, 5, -6, 6, -7, 7, -8, 8, -9, 9, -10, 10]:
            if try_guess(arr, {5: tweak_5, 7: tweak_7}):
                return True
    rettab = saved_rettab
    return False



from pwn import *

use_remote = False
if use_remote:
    conn = remote('202.120.7.212', 20001)
    conn.recvline()
    pow_exp, _, pow_mod = conn.recvline().partition(b'2^(2^')[2].partition(b') mod ')
    pow_mod = pow_mod.partition(b' ')[0]
    pow_exp, pow_mod = int(pow_exp), int(pow_mod)
    
    pow_res = 2
    print(pow_exp)
    for i in range(0, pow_exp):
        pow_res = (pow_res*pow_res) % pow_mod
    print('pow computed')
    conn.send(f'{pow_res}\n'.encode())
    print(conn.recvline())
else:
    conn = process('./chal')


print(conn.recvline())

blob = conn.recvuntil(b'=========END========', drop=True)
arr = np.frombuffer(blob, dtype=np.double)

sendbuf = bytearray([0] * 0x40)
for i in range(8):
    if not brute(arr[128*i:128*i+128]):
        print('rip', i)
        exit(1)
    for j in range(8):
        sendbuf[i * 8 + j] = rettab[j][0]
conn.send(bytes(sendbuf))
conn.interactive()

