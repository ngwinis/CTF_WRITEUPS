#!/usr/bin/env python3
import struct

PE = "Lawer.exe"
TAG = b"[CTF] FLAG: "
PREFIX = b"PTITCTF{"

def ror8(x, r): r &= 7; return ((x >> r) | ((x & 0xff) << (8 - r))) & 0xff

# PE .rdata reader
with open(PE, "rb") as f: blob = f.read()
e_lfanew = int.from_bytes(blob[0x3c:0x40], "little")
nsec     = int.from_bytes(blob[e_lfanew+6:e_lfanew+8], "little")
optsz    = int.from_bytes(blob[e_lfanew+20:e_lfanew+22], "little")
tab      = e_lfanew + 24 + optsz
rdata = None
for i in range(nsec):
    off = tab + 40*i
    name = blob[off:off+8].rstrip(b"\x00")
    roff = int.from_bytes(blob[off+20:off+24], "little")
    rsz  = int.from_bytes(blob[off+16:off+20], "little")
    if name == b".rdata":
        rdata = blob[roff:roff+rsz]; break

p = rdata.find(TAG); q = p + len(TAG)
while rdata[q] == 0: q += 1
enc = bytearray(rdata[q:q+64])  # 64 bytes

# brute v16_seed (0..255) để khôi phục 4 byte v13 từ PREFIX
def try_seed(seed):
    k2 = [None]*4
    for i, want in enumerate(PREFIX):
        k1  = (seed + 7*i) & 0xFF
        rot = i % 5
        val = want ^ ror8(enc[i], rot) ^ k1
        j = i & 3
        if k2[j] is None: k2[j] = val
        elif k2[j] != val: return None
    return seed, k2

candidate = next((res for s in range(256) if (res:=try_seed(s))), None)
seed, k2 = candidate

# giải toàn bộ
plain = bytes(ror8(c, i%5) ^ ((seed + 7*i) & 0xFF) ^ k2[i&3] for i, c in enumerate(enc))
print(plain.decode("utf-8", "replace"))

# Flag: PTITCTF{This_1snot_m4lware_don't_worry}