#!/usr/bin/env python3
"""make_elf.py — wrappe les payloads bruts en ELF ARM pour Ghidra.
Usage: python3 make_elf.py <payload.bin> <load_addr_hex> <out.elf>
Exemples:
  python3 make_elf.py payload_1.bin 3C000000 payload1.elf
  python3 make_elf.py payload_4.bin 08002000 payload4.elf
"""
import struct, sys

data = open(sys.argv[1], "rb").read()
load = int(sys.argv[2], 16)
out = sys.argv[3]

ehsize, phentsize, phnum = 52, 32, 1
data_off = ehsize + phentsize * phnum
pad = (4 - data_off % 4) % 4
data_off += pad

eh = struct.pack("<4sBBBBB7sHHIIIIIHHHHHH",
    b"\x7fELF", 1, 1, 1, 0, 0, b"\x00" * 7,
    2,      # ET_EXEC
    40,     # EM_ARM
    1,
    load,   # entry
    ehsize, 0, 0, ehsize, phentsize, phnum, 40, 0, 0)

ph = struct.pack("<IIIIIIII",
    1, load, load, load, len(data), len(data), 7, 4)

open(out, "wb").write(eh + ph + b"\x00" * pad + data)
print(f"{out}: {len(data)} octets chargés à {load:#x}")
