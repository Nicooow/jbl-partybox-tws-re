"""Decode the app-event dispatch tables in the BESAUD event loop (BES payload_1).

- outer TBH at 0x3C012EAE -> event id (1..0x1B) -> handler
- inner table at 0x3C012F44 (action code 5..9) -> handler
"""
import struct

PATH = "extracted/payload_1.bin"
BASE = 0x3C000000
d = open(PATH, "rb").read()


def hw(va):
    o = va - BASE
    return d[o] | (d[o + 1] << 8)


def word(va):
    return struct.unpack_from("<I", d, va - BASE)[0]


def byts(va, n):
    o = va - BASE
    return d[o:o + n]


TBH = 0x3C012EAE
print("outer TBH @ 0x%08X" % TBH)
for base in (0x3C012EB0, 0x3C012EB2):
    print("  base=0x%08X" % base)
    for i in range(27):
        e = hw(base + 2 * i)
        print("    event 0x%02X -> 0x%08X" % (i + 1, base + 2 * e))
    print()

print("inner table @ 0x3C012F44 (action 5..9, ldr.w pc)")
for i in range(5):
    print("    action %d -> 0x%08X" % (5 + i, word(0x3C012F44 + 4 * i)))
print()
print("raw table bytes 0x3C012F44..0x3C012F58:", byts(0x3C012F44, 0x14).hex(" "))
print("raw outer table 0x3C012EB0..0x3C012EE8:", byts(0x3C012EB0, 0x38).hex(" "))
