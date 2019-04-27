import re
import zlib
import sys

pdf = open("paper_cut.pdf", "rb").read()
stream = re.compile(rb'.*?FlateDecode.*?stream(.*?)endstream', re.S)

for s in stream.findall(pdf):
    s = s.strip(b'\r\n')
    dcmp = zlib.decompressobj()
    sys.stdout.buffer.write(dcmp.decompress(s))

