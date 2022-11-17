from z3 import *
s = Solver()
first_num = BitVec('first_num', 64)
second_num = BitVec('second_num', 64)
third_num = BitVec('third_num', 64)
fourth_num = BitVec('fourth_num', 64)

s.add(first_num + second_num == 0x8b228bf35f6a)
s.add(third_num + second_num == 0xe78241)
s.add(fourth_num + third_num == 0xfa4c1a9f)
s.add(first_num + fourth_num == 0x8b238557f7c8)
s.add(third_num ^ second_num ^ fourth_num == 0xf9686f4d)
s.check()

m = s.model()

print(f'SECCON{{{m[first_num].as_long():x}-{m[second_num].as_long():x}-{m[third_num].as_long():x}-{m[fourth_num].as_long():x}}}')
