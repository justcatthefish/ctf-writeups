#!/usr/bin/env python3
# Author: MrQubo

import functools

import Crypto.Cipher
from Crypto.Cipher import AES
from Crypto.Util.py3compat import _copy_bytes, is_native_int
from Crypto.Util.number import long_to_bytes
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

from pwn import *
context.encoding = 'UTF-8'


#  io = process('./problem.py')
io = remote('witches-symmetric-exam.seccon.games', 8080)
#  context.log_level = 'debug'

io.recvuntil('ciphertext: ')
secret_spell_ct = bytes.fromhex(io.recvlineS(keepends=False))


# Send multiple ciphertexts in one network round-trip.
def ofb_padding_oracle_multiple(iv, datas):
    assert len(iv) == 16, iv
    buf = bytearray()
    l = 0
    for data in datas:
        assert len(data) == 16, data
        buf += (iv.hex() + data.hex() + '\n').encode()
        l += 1
    io.send(buf)
    outs = []
    for _ in range(l):
        io.recvuntil('ciphertext: ')
        line = io.recvline(keepends=False)
        if line == b"b'ofb error'":
            outs.append(False)
        elif line == b"b'gcm error'":
            outs.append(True)
        else:
            assert False, line
    return outs

def ofb_padding_oracle(iv, data):
    return ofb_padding_oracle_multiple(iv, [data])[0]

@functools.cache
def encrypt_oracle(pt):
    iv = bytes(pt)
    data = bytearray(16)
    for idx in reversed(range(16)):
        padi = 16 - idx
        def gen_data():
            for x in range(256):
                data[idx] = x
                yield data
        outs = ofb_padding_oracle_multiple(iv, gen_data())
        for out, x in zip(outs, range(256)):
            data[idx] = x
            if out:
                if idx == 15:
                    data[idx-1] ^= 1
                    if not ofb_padding_oracle(iv, data):
                        continue
                break
        else:
            assert False, idx
        for idx2 in range(idx, 16):
            data[idx2] ^= padi ^ (padi + 1)
    return bytes(x ^ 0x11 for x in data)


class My_AES_ECB:
    def encrypt(self, data):
        assert len(data) == 16
        return encrypt_oracle(data)

# Copied from https://github.com/Legrandin/pycryptodome/blob/7e59254350d4ca0dc6566a12d6c48154e8542926/lib/Crypto/Cipher/_mode_ecb.py#L205-L220
def create_ecb_cipher(factory, **kwargs):
    """Instantiate a cipher object that performs ECB encryption/decryption.
    :Parameters:
      factory : module
        The underlying block cipher, a module from ``Crypto.Cipher``.
    All keywords are passed to the underlying block cipher.
    See the relevant documentation for details (at least ``key`` will need
    to be present"""

    if kwargs:
        raise TypeError("Unknown parameters for ECB: %s" % str(kwargs))
    return My_AES_ECB()


class My_AES_CTR:
    # Copied from https://github.com/Legrandin/pycryptodome/blob/7e59254350d4ca0dc6566a12d6c48154e8542926/lib/Crypto/Cipher/_mode_ctr.py#L89-L149
    def __init__(self, initial_counter_block, prefix_len, counter_len, little_endian):
        if len(initial_counter_block) == prefix_len + counter_len:
            self.nonce = _copy_bytes(None, prefix_len, initial_counter_block)
            """Nonce; not available if there is a fixed suffix"""
        self.block_size = len(initial_counter_block)
        assert self.block_size == 16

        self.cur_ctr_block = bytearray(initial_counter_block)

    def update_ctr_block(self):
        for idx in reversed(range(8, 16)):
            self.cur_ctr_block[idx] += 1
            if self.cur_ctr_block[idx] != 0:
                break

    def encrypt(self, data, output=None):
        if output is None:
            ciphertext = bytearray(len(data))
        else:
            ciphertext = output

        ciphertext.clear()
        for bi in range(0, len(data), 16):
            block = data[bi:bi+16]
            ciphertext.extend(xor(block, encrypt_oracle(bytes(self.cur_ctr_block)), cut='left'))
            self.update_ctr_block()

        if output is None:
            return bytes(ciphertext)
        else:
            return None

    decrypt = encrypt

# Copied from https://github.com/Legrandin/pycryptodome/blob/7e59254350d4ca0dc6566a12d6c48154e8542926/lib/Crypto/Cipher/_mode_ctr.py#L280-L393
def create_ctr_cipher(factory, **kwargs):
    """Instantiate a cipher object that performs CTR encryption/decryption.
    :Parameters:
      factory : module
        The underlying block cipher, a module from ``Crypto.Cipher``.
    :Keywords:
      nonce : bytes/bytearray/memoryview
        The fixed part at the beginning of the counter block - the rest is
        the counter number that gets increased when processing the next block.
        The nonce must be such that no two messages are encrypted under the
        same key and the same nonce.
        The nonce must be shorter than the block size (it can have
        zero length; the counter is then as long as the block).
        If this parameter is not present, a random nonce will be created with
        length equal to half the block size. No random nonce shorter than
        64 bits will be created though - you must really think through all
        security consequences of using such a short block size.
      initial_value : posive integer or bytes/bytearray/memoryview
        The initial value for the counter. If not present, the cipher will
        start counting from 0. The value is incremented by one for each block.
        The counter number is encoded in big endian mode.
      counter : object
        Instance of ``Crypto.Util.Counter``, which allows full customization
        of the counter block. This parameter is incompatible to both ``nonce``
        and ``initial_value``.
    Any other keyword will be passed to the underlying block cipher.
    See the relevant documentation for details (at least ``key`` will need
    to be present).
    """

    #  cipher_state = factory._create_base_cipher(kwargs)

    counter = kwargs.pop("counter", None)
    nonce = kwargs.pop("nonce", None)
    initial_value = kwargs.pop("initial_value", None)
    if kwargs:
        raise TypeError("Invalid parameters for CTR mode: %s" % str(kwargs))

    if counter is not None and (nonce, initial_value) != (None, None):
        raise TypeError("'counter' and 'nonce'/'initial_value'"
                        " are mutually exclusive")

    if counter is None:
        # Crypto.Util.Counter is not used
        if nonce is None:
            if factory.block_size < 16:
                raise TypeError("Impossible to create a safe nonce for short"
                                " block sizes")
            nonce = get_random_bytes(factory.block_size // 2)
        else:
            if len(nonce) >= factory.block_size:
                raise ValueError("Nonce is too long")

        # What is not nonce is counter
        counter_len = factory.block_size - len(nonce)

        if initial_value is None:
            initial_value = 0

        if is_native_int(initial_value):
            if (1 << (counter_len * 8)) - 1 < initial_value:
                raise ValueError("Initial counter value is too large")
            initial_counter_block = nonce + long_to_bytes(initial_value, counter_len)
        else:
            if len(initial_value) != counter_len:
                raise ValueError("Incorrect length for counter byte string (%d bytes, expected %d)" %
                                 (len(initial_value), counter_len))
            initial_counter_block = nonce + initial_value

        return My_AES_CTR(initial_counter_block,
                          len(nonce),                     # prefix
                          counter_len,
                          False)                          # little_endian

    # Crypto.Util.Counter is used

    # 'counter' used to be a callable object, but now it is
    # just a dictionary for backward compatibility.
    _counter = dict(counter)
    try:
        counter_len = _counter.pop("counter_len")
        prefix = _counter.pop("prefix")
        suffix = _counter.pop("suffix")
        initial_value = _counter.pop("initial_value")
        little_endian = _counter.pop("little_endian")
    except KeyError:
        raise TypeError("Incorrect counter object"
                        " (use Crypto.Util.Counter.new)")

    # Compute initial counter block
    words = []
    while initial_value > 0:
        words.append(struct.pack('B', initial_value & 255))
        initial_value >>= 8
    words += [b'\x00'] * max(0, counter_len - len(words))
    if not little_endian:
        words.reverse()
    initial_counter_block = prefix + b"".join(words) + suffix

    if len(initial_counter_block) != factory.block_size:
        raise ValueError("Size of the counter block (%d bytes) must match"
                         " block size (%d)" % (len(initial_counter_block),
                                               factory.block_size))

    return CtrMode(cipher_state, initial_counter_block,
                   len(prefix), counter_len, little_endian)


class My_AES_OFB:
    # Copied from https://github.com/Legrandin/pycryptodome/blob/7e59254350d4ca0dc6566a12d6c48154e8542926/lib/Crypto/Cipher/_mode_ofb.py#L73-L119
    def __init__(self, iv):
        """Create a new block cipher, configured in OFB mode.
        :Parameters:
          block_cipher : C pointer
            A smart pointer to the low-level block cipher instance.
          iv : bytes/bytearray/memoryview
            The initialization vector to use for encryption or decryption.
            It is as long as the cipher block.
            **The IV must be a nonce, to to be reused for any other
            message**. It shall be a nonce or a random value.
            Reusing the *IV* for encryptions performed with the same key
            compromises confidentiality.
        """

        self.block_size = len(iv)
        """The block size of the underlying cipher, in bytes."""
        assert self.block_size == 16

        self.iv = _copy_bytes(None, None, iv)
        self.cur_state = self.iv

    def encrypt(self, data, output=None):
        if output is None:
            ciphertext = bytearray(len(data))
        else:
            ciphertext = output

        ciphertext.clear()
        for bi in range(0, len(data), 16):
            block = data[bi:bi+16]
            next_state = encrypt_oracle(self.cur_state)
            ciphertext.extend(xor(block, next_state, cut='left'))
            self.cur_state = next_state

        if output is None:
            return bytes(ciphertext)
        else:
            return None

    decrypt = encrypt

# Copied from https://github.com/Legrandin/pycryptodome/blob/7e59254350d4ca0dc6566a12d6c48154e8542926/lib/Crypto/Cipher/_mode_ofb.py#L244-L282
def create_ofb_cipher(factory, **kwargs):
    """Instantiate a cipher object that performs OFB encryption/decryption.
    :Parameters:
      factory : module
        The underlying block cipher, a module from ``Crypto.Cipher``.
    :Keywords:
      iv : bytes/bytearray/memoryview
        The IV to use for OFB.
      IV : bytes/bytearray/memoryview
        Alias for ``iv``.
    Any other keyword will be passed to the underlying block cipher.
    See the relevant documentation for details (at least ``key`` will need
    to be present).
    """

    iv = kwargs.pop("IV", None)
    IV = kwargs.pop("iv", None)

    if (None, None) == (iv, IV):
        iv = get_random_bytes(factory.block_size)
    if iv is not None:
        if IV is not None:
            raise TypeError("You must either use 'iv' or 'IV', not both")
    else:
        iv = IV

    if len(iv) != factory.block_size:
        raise ValueError("Incorrect IV length (it must be %d bytes long)" %
                factory.block_size)

    if kwargs:
        raise TypeError("Unknown parameters for OFB: %s" % str(kwargs))

    return My_AES_OFB(iv)


# Copied from https://github.com/Legrandin/pycryptodome/blob/7e59254350d4ca0dc6566a12d6c48154e8542926/lib/Crypto/Cipher/AES.py#L231-L232
def create_gcm_cipher(factory, **kwargs):
    kwargs['add_aes_modes'] = True
    return Crypto.Cipher._create_cipher(factory, bytes(16), factory.MODE_GCM, **kwargs)


class My_AES_factory:
    MODE_ECB = AES.MODE_ECB
    MODE_CTR = AES.MODE_CTR
    MODE_OFB = AES.MODE_OFB
    MODE_GCM = AES.MODE_GCM

    block_size = AES.block_size
    key_size = AES.key_size

    def new(factory, key, mode, **kwargs):
        if mode == factory.MODE_ECB:
            return create_ecb_cipher(factory, **kwargs)
        elif mode == factory.MODE_CTR:
            return create_ctr_cipher(factory, **kwargs)
        elif mode == factory.MODE_OFB:
            return create_ofb_cipher(factory, **kwargs)
        elif mode == factory.MODE_GCM:
            return create_gcm_cipher(factory, **kwargs)
        assert False


factory = My_AES_factory()
# `key` isn't used anyway, but we need to pass some argument to `factory.new()`.
key = None

def encrypt(data):
    # `nonce` can be anything, and we don't care about generating a secure one.
    gcm_cipher = factory.new(key, factory.MODE_GCM, nonce=bytes(16))
    gcm_ciphertext, gcm_tag = gcm_cipher.encrypt_and_digest(data)

    print(f'{gcm_tag=}')
    ofb_input = pad(gcm_tag + gcm_cipher.nonce + gcm_ciphertext, 16)

    ofb_iv = bytes(16)  # Same as with `nonce`.
    ofb_cipher = factory.new(key, factory.MODE_OFB, iv=ofb_iv)
    ciphertext = ofb_cipher.encrypt(ofb_input)
    return ofb_iv + ciphertext

def decrypt(data):
    ofb_iv = data[:16]
    ofb_ciphertext = data[16:]
    ofb_cipher = factory.new(key, factory.MODE_OFB, iv=ofb_iv)

    m = ofb_cipher.decrypt(ofb_ciphertext)
    temp = unpad(m, 16)

    gcm_tag = temp[:16]
    gcm_nonce = temp[16:32]
    print(f'{gcm_tag=}')
    print(f'{gcm_nonce=}')
    gcm_ciphertext = temp[32:]
    gcm_cipher = factory.new(key, factory.MODE_GCM, nonce=gcm_nonce)

    plaintext = gcm_cipher.decrypt_and_verify(gcm_ciphertext, gcm_tag)

    return plaintext

secret_spell = decrypt(secret_spell_ct)
print(f'{secret_spell=}')
give_mey_key_ct = encrypt(b"give me key")
print(f'{give_mey_key_ct=}')
#  print(f'{decrypt(give_mey_key_ct)=}')
context.log_level = 'debug'
io.sendlineafter('ciphertext: ', give_mey_key_ct.hex())
io.sendlineafter('ok, please say secret spell:', secret_spell)
io.interactive()
