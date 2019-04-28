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

