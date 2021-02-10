"""
TLDR: fix co_filename in a pyc file
(needs adjusting some vars below)
"""
from pwn import *

p = read('./a')

current_name = b'a.py'

assert p.count(current_name) == 1

idx = p.index(current_name)
# Byte before this stores the length

new_name = b'f3V0zx987FMoRCQC70L7'

# Copy until the length byte
new_pyc = bytearray(p[:idx-1])
# Add length byte
new_pyc += bytes([len(new_name)])
# Add new name
new_pyc += new_name
# Add all rest
new_pyc += p[idx+len(current_name):]

with open('new.pyc', 'wb') as f:
    f.write(new_pyc)

