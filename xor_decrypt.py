import binascii

data = binascii.unhexlify("1129232c31232023011604393a72301d73311d30713471303173202e711d72323f")

for key in range(256):
    out = ''.join(chr(b ^ key) for b in data)
    if all(32 <= ord(c) < 127 for c in out):   # filter printable
        print(key, hex(key), out)
