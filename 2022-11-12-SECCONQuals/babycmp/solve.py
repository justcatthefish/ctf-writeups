flag = bytes.fromhex('04202f2020231e59441a7f3575362d2b11175a036d503607153c090104472b36410a38')
key = b'Welcome to SECCON 2022'

from itertools import cycle

print(''.join([chr(x ^ y) for (x,y) in zip(flag, cycle(key))]))
