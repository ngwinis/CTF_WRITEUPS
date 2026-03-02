# solve.py
from z3 import *
from Crypto.Cipher import AES
from Crypto.Hash import SHA256, MD5

# -----------------------------
# Targets extracted from binary
# -----------------------------
PRINT_MIN, PRINT_MAX = 0x20, 0x7E

# 8 blocks of 4 bytes: xor == tag
targetTag = [0x6C, 0x75, 0x3A, 0x01, 0x7E, 0x2F, 0x34, 0x00]

# 4 rows of 8 bytes: xor( (hi_nibble xor lo_nibble) ) == target
targetNibble = [0x08, 0x08, 0x04, 0x07]

# 8 columns: sum of 4 bytes (one per row) mod 97 == target
targetColSums = [12, 39, 8, 0, 55, 33, 50, 96]

# 12 pair constraints: (x[i] + x[j]) % mod == rem
pairs = [
    (0, 31, 127, 104),
    (3, 28, 131, 17),
    (7, 24, 113, 53),
    (11, 20, 109, 58),
    (1, 15, 103, 52),
    (5, 27, 97, 88),
    (9, 22, 107, 20),
    (13, 18, 101, 64),
    (2, 29, 127, 81),
    (6, 25, 131, 118),
    (10, 21, 113, 40),
    (14, 17, 109, 83),
]

# AES S-box (standard)
SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]

# sbox xor (even positions) == 0x66
targetSboxXor = 0x66

# LFSR/CRC final target
targetLFSR = 0x4358

# encrypted flag (32 bytes)
enc = bytes.fromhex("0037a8858c84fd73233ee93571d82bde4f1846e81241af6df95ed4bd156a8999")
flagPrefix = b"crackme{"

# -----------------------------
# Helpers
# -----------------------------
def f_nibble(b8):
    # returns 8-bit: (hi_nibble XOR lo_nibble)
    return LShR(b8, 4) ^ (b8 & 0x0F)

def sbox_lookup(v8):
    # v8 is 8-bit BitVec; build a total If-chain mapping 0..255
    out = BitVecVal(0, 8)
    for k, val in enumerate(SBOX):
        out = If(v8 == BitVecVal(k, 8), BitVecVal(val, 8), out)
    return out

def add_lfsr16_constraint(slv, xbytes):
    """
    Implements binary's func3:
      bx = 0xACE1
      for each byte b:
        repeat 8 times:
          t = (b XOR bx) & 1
          bx >>= 1
          if t == 1: bx ^= 0xB400
          b >>= 1
      require bx == 0x4358
    """
    bx = BitVecVal(0xACE1, 16)

    for bi in range(32):
        b = xbytes[bi]  # 8-bit
        for _ in range(8):
            b16 = ZeroExt(8, b)                 # to 16-bit
            t = Extract(0, 0, b16 ^ bx)         # 1-bit
            bx_shift = LShR(bx, 1)
            bx = If(t == 1, bx_shift ^ BitVecVal(0xB400, 16), bx_shift)
            b = LShR(b, 1)

    slv.add(bx == BitVecVal(targetLFSR, 16))

# -----------------------------
# Build solver
# -----------------------------
x = [BitVec(f"x{i}", 8) for i in range(32)]
s = Solver()

# printable
for i in range(32):
    s.add(x[i] >= PRINT_MIN, x[i] <= PRINT_MAX)

# (B) tag xor per 4 bytes
for b in range(8):
    i = 4 * b
    s.add(x[i] ^ x[i+1] ^ x[i+2] ^ x[i+3] == BitVecVal(targetTag[b], 8))

# (C) nibble xor per 8 bytes (4 rows)
for r in range(4):
    acc = BitVecVal(0, 8)
    for c in range(8):
        acc = acc ^ f_nibble(x[r*8 + c])
    s.add(acc == BitVecVal(targetNibble[r], 8))

# (D) col sums mod 97
for c in range(8):
    sm = Sum([ZeroExt(24, x[r*8 + c]) for r in range(4)])  # Int-like sum, still works with %
    s.add(sm % 97 == targetColSums[c])

# (E) pair constraints
for i, j, modv, rem in pairs:
    s.add((ZeroExt(24, x[i]) + ZeroExt(24, x[j])) % modv == rem)

# (F) sbox xor even positions
sx = BitVecVal(0, 8)
for i in range(0, 32, 2):
    sx = sx ^ sbox_lookup(x[i])
s.add(sx == BitVecVal(targetSboxXor, 8))

# (G) LFSR/CRC constraint (the missing piece!)
add_lfsr16_constraint(s, x)

# -----------------------------
# Solve + decrypt
# -----------------------------
print("[*] Solving...")
if s.check() != sat:
    raise SystemExit("No solution (unsat). Check extracted constants/constraints.")

m = s.model()
key_bytes = bytes([m.evaluate(x[i]).as_long() for i in range(32)])
key = key_bytes.decode("ascii", errors="replace")
print("KEY  =", key)

# AES pipeline from binary:
# aes_key = SHA256(key[:16])
# iv      = MD5(key[16:])
aes_key = SHA256.new(key_bytes[:16]).digest()
iv = MD5.new(key_bytes[16:]).digest()

pt = AES.new(aes_key, AES.MODE_CBC, iv).decrypt(enc)
print("PT   =", pt)
try:
    print("PT(str) =", pt.decode())
except:
    pass

if pt.startswith(flagPrefix):
    print("FLAG =", pt.decode(errors="ignore"))
else:
    print("[!] Decrypt does not start with prefix. Something is still wrong.")
    print("    Expected prefix:", flagPrefix)