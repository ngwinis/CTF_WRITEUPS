from __future__ import annotations
from dataclasses import dataclass
from typing import Iterable, List
import argparse

# ---- Constants lifted from the binary ----

ALPH = b"QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm0123456789-_"
A_N0_DBG = b"n0_dbg^_^"

C = [
    0x87, 0xA4, 0x55, 0x21, 0xAC, 0x4B, 0x57, 0xAE, 0x13, 0xAB,
    0x5D, 0x97, 0x5C, 0xFD, 0xF0, 0xB5, 0xCA, 0x5D, 0x22, 0xCF,
    0xE7, 0xE0, 0x3F, 0x98, 0x49, 0x58, 0x06, 0xAF, 0x87, 0x90,
    0x50, 0xBC, 0xE3, 0xA9, 0x30, 0xFC, 0xE0, 0xB3, 0x8F, 0xAE,
    0x4C, 0x04, 0x56, 0x39, 0x76, 0xC0, 0x39, 0x93, 0xDC, 0x08,
    0x21, 0xF7, 0xC2, 0xE2, 0x56, 0xFC, 0xFE, 0x16, 0xDE, 0x43,
]
C_BYTES = bytes(C)  # 60 bytes


# ---- Bit helpers ----

def ror8(x: int, r: int) -> int:
    """Rotate-right 8-bit value by r (0..7)."""
    r &= 7
    return ((x >> r) | ((x << (8 - r)) & 0xFF)) & 0xFF


def ror_block4(block: bytes, s: int) -> bytes:
    """
    Right-rotate a 4-byte block by s positions at byte granularity.
    s in {0,1,2,3}. Inverse of a left-rotate-by-s done in the binary.
    """
    s &= 3
    if s == 0:
        return block
    return block[-s:] + block[:-s]


# ---- Hash & PRNG (as reconstructed) ----

def fnv1a32(data: bytes) -> int:
    """FNV-1a 32-bit hash."""
    h = 0x811C9DC5
    for b in data:
        h = ((h ^ b) * 0x01000193) & 0xFFFFFFFF
    return h


def prng60(seed_tag: bytes = A_N0_DBG) -> List[int]:
    v = (fnv1a32(seed_tag) ^ 0x9E377985) & 0xFFFFFFFF
    out: List[int] = []

    for j in range(60):
        # xorshift-like update with extra (32*u) feedback:
        a = ((v ^ ((v << 13) & 0xFFFFFFFF)) >> 17) & 0xFFFFFFFF
        b = (v << 13) & 0xFFFFFFFF
        u = (a ^ v ^ b) & 0xFFFFFFFF
        v = (v ^ a ^ b ^ ((32 * u) & 0xFFFFFFFF)) & 0xFFFFFFFF

        idx = j % 9  # same as the binary's weird arithmetic
        out.append((v + seed_tag[idx]) & 0xFF)

    return out
    
@dataclass(frozen=True)
class CustomB64:
    alphabet: bytes
    pad_byte: int = ord('.')

    def decode(self, data: bytes) -> bytes:
        inv = {self.alphabet[i]: i for i in range(64)}
        out = bytearray()

        if len(data) % 4 != 0:
            raise ValueError("Input length must be a multiple of 4.")

        for i in range(0, len(data), 4):
            chunk = data[i:i + 4]
            pad = chunk.count(self.pad_byte)
            vals = [(0 if b == self.pad_byte else inv[b]) for b in chunk]
            v = (vals[0] << 18) | (vals[1] << 12) | (vals[2] << 6) | vals[3]

            b1, b2, b3 = (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF
            if pad == 0:
                out += bytes([b1, b2, b3])
            elif pad == 1:
                out += bytes([b1, b2])
            elif pad == 2:
                out += bytes([b1])
            else:
                raise ValueError("Invalid padding in custom base64.")
        return bytes(out)

def undo_xor(cipher: bytes, mask: Iterable[int]) -> bytes:
    """XOR each cipher byte with corresponding mask byte."""
    return bytes(c ^ m for c, m in zip(cipher, mask))


def undo_block_rotations(data: bytes) -> bytes:
    """
    Data length must be multiple of 4.
    Each 4-byte block is right-rotated by s = v31 & 3,
    where v31 starts at 1 and increases by +3 per block.
    """
    if len(data) % 4 != 0:
        raise ValueError("Length must be a multiple of 4.")
    out = bytearray()
    v31 = 1
    for i in range(0, len(data), 4):
        s = v31 & 3
        out += ror_block4(data[i:i + 4], s)
        v31 += 3
    return bytes(out)


def rebuild_flag(verbose: bool = False) -> str:
    # 1) PRNG mask
    mask = prng60(A_N0_DBG)
    if verbose:
        print(f"[+] PRNG bytes (len={len(mask)}): {bytes(mask).hex()}")

    # 2) Undo XOR
    eperm = undo_xor(C_BYTES, mask)
    if verbose:
        print(f"[+] After XOR/undo (eperm, len={len(eperm)}): {eperm.hex()}")

    # 3) Undo per-4-byte rotation
    enc = undo_block_rotations(eperm)
    if verbose:
        print(f"[+] After undo rotations (enc, len={len(enc)}): {enc.hex()}")

    # 4) Custom base64 decode to get the flag bytes
    b64 = CustomB64(ALPH)
    flag_bytes = b64.decode(enc)
    flag = flag_bytes.decode(errors="strict")

    if verbose:
        print(f"[+] Flag bytes: {flag_bytes!r}")
    return flag

def main():
    parser = argparse.ArgumentParser(description="Rebuild flag from CarnivalShow constants.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print intermediate stages")
    args = parser.parse_args()

    flag = rebuild_flag(verbose=args.verbose)
    print(flag)


if __name__ == "__main__":
    main()

# Flag: PTITCTF{Y0u_c4n_bypass_4ll_types_0f_4nt1!!!}