# Icthyo (re, 130pts, 79 solves)

Provided files:
* `icthyo` - ELF64 program
* `out.png` - an image in which the flag is hidden

The `icthyo` program expects an 8-bit 256x256 PNG file which it uses to hide the input string. 

The most interesting part of the file is the `encode` function. It consists of a loop over all previously read rows of the image, in which it does the following:
* Overwrite least significant bits of all RGB tuples in the row with a random value
* Encode the current string (`plaintext`) character bit by bit in the LSB of the blue component of every 32nd pixel


```c
  for ( i = 0; i <= 255; ++i )
  {
    c_row = rows[i];
    for ( j = 0; j <= 255; ++j )
    {
      v2 = &c_row[j];                           // shuffle all LSB
      v2->r ^= rand() & 1;
      v2->g ^= rand() & 1;
      v2->b ^= rand() & 1;
    }
    for ( k = 0; k <= 7; ++k )
    {
      pixel_32nd = &c_row[32 * k];
      kth_plain_bit = (plaintext[i] >> k) & 1;
      if ( pixel_32nd->b & 1 )
        pixel_32nd->b ^= 1u;
      pixel_32nd->b |= (pixel_32nd->r ^ pixel_32nd->g) & 1 ^ (unsigned __int8)kth_plain_bit;
    }
  }
 ```

Effectively, the last assignment implements the following equation of the LSBs (bitwise):
```
b = r ^ g ^ flag
```
Which can be manipulated into
```
flag = r ^ g ^ b
```

Combining this with the loop logic we can develop a simple python decoder

```python
from PIL import Image

img = Image.open("out.png").convert("RGB")

flag = ""

for crow in range(256):
	c_flag_char = 0
	for k in range(7,-1,-1):
		r,g,b = img.getpixel((32*k,crow))
		plain_bit = (b ^ r ^ g) & 1
		c_flag_char = (c_flag_char * 2) | plain_bit;
	flag += chr(c_flag_char)

print(flag)
```
Resulting flag is `actf{lurking_in_the_depths_of_random_bits}`.
