During the time of CTF, we solved only part A.

This concerned the "online" part of the challenge.

Here, we can ask the web service to send us the decrypted drive. But before that, we need to authenticate:

```python
		# host issues player 16-byte challenge
		host_challenge = await self._read_or_fail(rw, 16)
		challenge_key = host_challenge[:8]
		encrypted_host_nonce = host_challenge[8:]
		cipher = Cipher(authentication_key, Mode.Authentication)
		host_mangling_key = cipher.encrypt(challenge_key)
		response = mangle(host_mangling_key, encrypted_host_nonce)
		await self._write(rw, response)

		cipher = Cipher(authentication_key, Mode.Authentication)
		host_nonce = cipher.decrypt(encrypted_host_nonce)

		# player issues host 16-byte challenge
		player_challenge_key = token_bytes(8)
		player_nonce = token_bytes(8)
		cipher = Cipher(authentication_key, Mode.Authentication)
		encrypted_player_nonce = cipher.encrypt(player_nonce)
		await self._write(rw, player_challenge_key + encrypted_player_nonce)

		cipher = Cipher(authentication_key, Mode.Authentication)
		player_mangling_key = cipher.encrypt(player_challenge_key)
		response = await self._read_or_fail(rw, 8)
		cipher = Cipher(authentication_key, Mode.Authentication)
		if cipher.decrypt(unmangle(player_mangling_key, response)) != player_nonce:
			await rw.write_eof()
			raise Exception("Authentication failed")
```

Cipher here is a combination of two LFSRs, first one has 43 bit state, the second one 25 bit state.
Mangle is a simple permutation/substitution cipher:
```python
def mangle(key_bytes: bytes, value_bytes: bytes) -> bytes:
	key = list(key_bytes)
	value = list(value_bytes)

	value = mix(key, value)
	value = shift(value)
	value = mix(key, value)
	value = shift(value)
	value = mix(key, value)
	value = tabulate(value)
	value = shift(value)
	value = mix(key, value)
	value = tabulate(value)
	value = shift(value)
	value = mix(key, value)
	value = shift(value)
	value = mix(key, value)

	return bytes(value)

def mix(key: list[int], value: list[int]) -> list[int]:
	last = 0
	ret: list[int] = value.copy()
	for i in range(len(value)):
		ret[i] ^= key[i]
		ret[i] ^= last
		last = value[i]
	return ret

def shift(value: list[int]) -> list[int]:
	ret = value.copy()
	ret[0] ^= ret[-1]
	return ret

def tabulate(value: list[int]) -> list[int]:
	ret = value.copy()
	for i in range(len(value)):
		ret[i] = table[ret[i]]
	return ret
```

The condition we need to meet is following:
```python
cipher.decrypt(unmangle(player_mangling_key, response)) == player_nonce
```

Equivalently, 

```python
unmangle(player_mangling_key, response) == cipher.encrypt(player_nonce)
response == mangle(player_mangling_key, cipher.encrypt(player_nonce))
response == mangle(player_mangling_key, encrypted_player_nonce)
```

`encrypted_player_nonce` is given to us. So, if we learn the `player_mangling_key`, we're done. `player_mangling_key` is encrypted `player_challenge_key`, which we know. Therefore, if we learn what is the keystream, we can compute the correct response. To do that, we'll focus on the first part:

```python
host_challenge = await self._read_or_fail(rw, 16)
challenge_key = host_challenge[:8]
encrypted_host_nonce = host_challenge[8:]
cipher = Cipher(authentication_key, Mode.Authentication)
host_mangling_key = cipher.encrypt(challenge_key)
response = mangle(host_mangling_key, encrypted_host_nonce)
await self._write(rw, response)
```

Let's just send `challenge_key` and `encrypted_host_nonce` comprised of 0 bytes. Then, we can retreive `host_mangling_key` from the equation
```
response = mangle(keystream, b'\0'*8)
```

Mangling function is pretty weak. I translated the mangle function into Z3. Subsequent bytes of `response` are
```
A[A[k7 ^ k6 ^ k0] ^ A[k6 ^ k7 ^ k5] ^ k0] ^ k7 ^ A[A[k5 ^ k6 ^ k4] ^ k6 ^ A[k4 ^ k5 ^ k3]]
A[A[k0 ^ k1 ^ k6] ^ k1 ^ A[k7 ^ k6 ^ k0] ^ A[k6 ^ k7 ^ k5]] ^ A[A[k6 ^ k7 ^ k5] ^ k7 ^ A[k5 ^ k6 ^ k4]] ^ k0 ^ k7 ^ A[A[k5 ^ k6 ^ k4] ^ k6 ^ A[k4 ^ k5 ^ k3]]
A[A[k1 ^ k2 ^ k0 ^ k7] ^ k2 ^ A[k0 ^ k1 ^ k6]] ^ k1 ^ A[A[k7 ^ k6 ^ k0] ^ A[k6 ^ k7 ^ k5] ^ k0] ^ A[A[k6 ^ k7 ^ k5] ^ k7 ^ A[k5 ^ k6 ^ k4]]
A[A[k2 ^ k3 ^ k1] ^ k3 ^ A[k1 ^ k2 ^ k0 ^ k7]] ^ k2 ^ A[A[k0 ^ k1 ^ k6] ^ k1 ^ A[k7 ^ k6 ^ k0] ^ A[k6 ^ k7 ^ k5]]
A[A[k3 ^ k4 ^ k2] ^ k4 ^ A[k2 ^ k3 ^ k1]] ^ k3 ^ A[A[k1 ^ k2 ^ k0 ^ k7] ^ k2 ^ A[k0 ^ k1 ^ k6]]
A[A[k4 ^ k5 ^ k3] ^ k5 ^ A[k3 ^ k4 ^ k2]] ^ k4 ^ A[A[k2 ^ k3 ^ k1] ^ k3 ^ A[k1 ^ k2 ^ k0 ^ k7]]
A[A[k5 ^ k6 ^ k4] ^ k6 ^ A[k4 ^ k5 ^ k3]] ^ k5 ^ A[A[k3 ^ k4 ^ k2] ^ k4 ^ A[k2 ^ k3 ^ k1]]
A[A[k6 ^ k7 ^ k5] ^ k7 ^ A[k5 ^ k6 ^ k4]] ^ k6 ^ A[A[k4 ^ k5 ^ k3] ^ k5 ^ A[k3 ^ k4 ^ k2]]
```
where A is the substitution table, and k0-7 are the bytes of the keystream.

Notice, that the second to last of the bytes comprises of only 6 of the key bytes. I wrote a C++ program to brute force 5 bytes of the key, substitute them into that formula, and derive the last one based on the response byte. After they are derived, I use other formulas to derive the rest of the bytes, and cross check with all other equations. The expected runtime was about 40 minutes on my 16 core machine, but after about 10, I got the key. Now that I think of that, I could have asked for output for `challenge_key[1] = 1` as well. Then,
```python
response0[6] = A[A[k5 ^ k6 ^ k4] ^ k6 ^ A[k4 ^ k5 ^ k3]] ^ k5 ^ A[A[k3 ^ k4 ^ k2] ^ k4 ^ A[k2 ^ k3 ^ k1]]
response1[6] = A[A[k5 ^ k6 ^ k4] ^ k6 ^ A[k4 ^ k5 ^ k3]] ^ k5 ^ A[A[k3 ^ k4 ^ k2] ^ k4 ^ A[k2 ^ k3 ^ k1 ^ 1]]
```
therefore,
```python
response0[6] ^ response1[6] = A[A[k3 ^ k4 ^ k2] ^ k4 ^ A[k2 ^ k3 ^ k1]] ^ A[A[k3 ^ k4 ^ k2] ^ k4 ^ A[k2 ^ k3 ^ k1 ^ 1]]
```
The next step would be to enumerate all pairs of values where `A[x]^A[y] = response0[6]^response1[6]` and split the equation even more. Or even at this point, just use Z3. Anyway, this approach worked.

After we have the keystream, we just xor it with `player_challenge_key` and follow with the protocol, to finally reach the flag, which is at the end of the movie that was on the encrypted drive.
