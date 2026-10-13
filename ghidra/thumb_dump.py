"""Disassemble a Thumb region of a payload linked at a known base.

usage: python thumb_dump.py <bin> <base_hex> <start_hex> <end_hex>
"""
import sys
import capstone

path, base, start, end = sys.argv[1], int(sys.argv[2], 16), int(sys.argv[3], 16), int(sys.argv[4], 16)
data = open(path, "rb").read()
BASE = base

md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
md.detail = False

off = start - BASE
n = end - start
code = data[off:off + n]

addr = start
for ins in md.disasm(code, start):
    # fill gaps (bytes capstone skipped) with .word
    while ins.address > addr:
        o = addr - BASE
        print("0x%08X  .hword 0x%04X" % (addr, data[o] | (data[o + 1] << 8)))
        addr += 2
    print("0x%08X  %-8s %s" % (ins.address, ins.mnemonic, ins.op_str))
    addr = ins.address + ins.size
while addr < end:
    o = addr - BASE
    print("0x%08X  .hword 0x%04X" % (addr, data[o] | (data[o + 1] << 8)))
    addr += 2
