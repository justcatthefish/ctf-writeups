#!/usr/bin/env python3
import subprocess
import string

char_map = {}
flag_enc = [8930, 15006, 8930, 10302, 11772, 13806, 13340, 11556, 12432, 13340, 10712, 10100, 11556, 12432, 9312, 10712, 10100, 10100, 8930, 10920, 8930, 5256, 9312, 9702, 8930, 10712, 15500, 9312]
reorder = [19, 4, 14, 3, 10, 17, 24, 22, 8, 2, 5, 11, 7, 26, 0, 25, 18, 6, 21, 23, 9, 13, 16, 1, 12, 15, 27, 20]
flag = [None] * 28 # empty list with fixed size

for c in string.printable:
    output = (subprocess.getoutput('sbcl --script bilith.lisp %i 2>/dev/null' % ord(c))).strip()
    output = int(output[2:-1])
    char_map[output] = c

flag_reord = ''

for l in flag_enc:
    flag_reord += char_map[l]

for i in range(len(flag_reord)):
    flag[reorder[i]] = flag_reord[i] 

print(''.join(flag))
