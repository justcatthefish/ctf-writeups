from capstone import *

result = bytes.fromhex('9650cf2ceb9baafb53ab73dd6c9edbbceeab23d616fdf1f0b975c328a2747de327d5955cf57675c98cfb420ebd51a298')
calls = []
data = open('meow_way.exe','rb').read()
start = 0x835
while True:

    if data[start] == 0x6a and (data[start+2] == 0x68 or data[start+2] == 0x6a):
        calls.append(data[start+3])
        if len(calls) == 0x30:
            break

    start += 1

j = 0
flag = []
start = 0
functions = []
while True:
    if data[start:start+5] == b'\x83\x04\x24\x05\xcb':
        functions.append(start+5)
        if len(functions) == 0x30:
            break
    start += 1

md = Cs(CS_ARCH_X86, CS_MODE_64)
for addr in functions:
    CODE = data[addr:addr+0x44]
    opcodes = []
    for i in md.disasm(CODE,0x1000):
        opcodes.append(format("%s\t%s" %(i.mnemonic, i.op_str)))

    op = next(filter(lambda x: 'byte ptr [esi]' in x, opcodes), None)
    xor = next(filter(lambda x: 'xor\tcl' in x, opcodes), None)
    secret = int(xor.replace('xor\tcl, ',''),16)
    if 'add' in op:
        flag.append(((result[j] ^ secret) - calls[j]) & 0xff)
    if 'sub' in op:
        flag.append((calls[j] - (result[j] ^ secret) ) & 0xff)
    j += 1


print(''.join([chr(x) for x in flag]))