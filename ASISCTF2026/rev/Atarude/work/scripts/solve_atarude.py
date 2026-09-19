#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

from Crypto.Cipher import AES


ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "work" / "evidence" / "archive_contents" / "Atarude" / "Atarude"
FLAG_ENC = ROOT / "work" / "evidence" / "archive_contents" / "Atarude" / "flag.enc"

MASK64 = (1 << 64) - 1
TABLE_OFF = 0x5064
TABLE_SPAN = 0xC0FFE0
TARGET_GATE = bytes.fromhex("10fe0df1471d48b5226d8b3b9e3559f3")


def xor_bytes(*parts: bytes) -> bytes:
    return bytes(__import__("functools").reduce(lambda x, y: x ^ y, column) for column in zip(*parts))


def rol8(value: int, count: int) -> int:
    count &= 7
    if count == 0:
        return value & 0xFF
    return ((value << count) | (value >> (8 - count))) & 0xFF


def derive_base(data: bytes) -> bytes:
    table = data[TABLE_OFF : TABLE_OFF + TABLE_SPAN + 0x11]
    state = bytearray(16)
    x = 0x9E3779B97F4A7C15
    add = 0
    multiplier = 0xA9C8666E28DBE1A3

    for i in range(0x1800):
        t = ((x << 13) & MASK64) ^ x
        t ^= t >> 7
        x = (((t << 17) & MASK64) ^ t) & MASK64

        y = (x ^ add) & MASK64
        q = (((y * multiplier) >> 64) & MASK64) >> 0x17
        idx = y - q * TABLE_SPAN
        if not 0 <= idx < TABLE_SPAN:
            raise ValueError("bad reciprocal reduction")

        pos = i & 15
        state[pos] = rol8(state[pos], i) ^ table[idx] ^ table[idx + 0x11] ^ ((x >> 41) & 0xFF)
        add = (add + 0x9E37) & MASK64

    return bytes(state)


def c24570(data: bytes, seed: int, blocks: bytes) -> bytes:
    if len(blocks) % 16 != 0:
        raise ValueError("c24570 input must be block-aligned")

    base = derive_base(data)
    state = base
    aes_base = AES.new(base, AES.MODE_ECB)
    offsets = [(11 * i) & 0xFF for i in range(16)]
    counter = 0

    for off in range(0, len(blocks), 16):
        tweak = bytes(((seed + x + counter) & 0xFF) for x in offsets)
        state = aes_base.encrypt(xor_bytes(blocks[off : off + 16], state, tweak))
        counter = (counter + 0x1D) & 0xFF

    return AES.new(state, AES.MODE_ECB).encrypt(base)


def const(data: bytes, off: int) -> bytes:
    return data[off : off + 16]


def derive_flag_key(data: bytes, gate: bytes) -> bytes:
    base = derive_base(data)

    s1 = AES.new(base, AES.MODE_ECB).encrypt(const(data, 0x3210))
    s1 = AES.new(base, AES.MODE_ECB).encrypt(xor_bytes(s1, const(data, 0x3600)))
    k1 = AES.new(s1, AES.MODE_ECB).encrypt(base)

    s2 = AES.new(base, AES.MODE_ECB).encrypt(const(data, 0x3430))
    s2 = AES.new(base, AES.MODE_ECB).encrypt(xor_bytes(s2, const(data, 0x33E0)))
    k2 = AES.new(s2, AES.MODE_ECB).encrypt(base)

    s3 = AES.new(base, AES.MODE_ECB).encrypt(xor_bytes(gate, base, const(data, 0x34F0)))
    s3 = AES.new(base, AES.MODE_ECB).encrypt(xor_bytes(k1, s3, const(data, 0x3270)))
    s3 = AES.new(base, AES.MODE_ECB).encrypt(xor_bytes(k2, s3, const(data, 0x32C0)))
    return AES.new(s3, AES.MODE_ECB).encrypt(base)


def parse_flag_blob(blob: bytes) -> tuple[bytes, bytes]:
    if len(blob) < 20 or blob[:2] != b"\xA6\x3C":
        raise ValueError("bad flag.enc header")
    ct_len = int.from_bytes(blob[2:4], "big")
    expected_len = 4 + ct_len + 16
    if len(blob) != expected_len:
        raise ValueError(f"bad flag.enc length: got {len(blob)}, expected {expected_len}")
    return blob[4 : 4 + ct_len], blob[4 + ct_len :]


def verify_flag_tag(data: bytes, key: bytes, ciphertext: bytes, tag: bytes) -> None:
    mac_input = key + (0).to_bytes(8, "big") + len(ciphertext).to_bytes(8, "big")
    for off in range(0, len(ciphertext), 16):
        block = ciphertext[off : off + 16]
        mac_input += block + bytes(16 - len(block))
    calc = c24570(data, 0x3C, mac_input)
    if calc != tag:
        raise ValueError(f"flag tag mismatch: {calc.hex()} != {tag.hex()}")


def decrypt_flag(key: bytes, ciphertext: bytes) -> bytes:
    out = bytearray()
    for off in range(0, len(ciphertext), 16):
        counter_block = bytes(8) + (off // 16).to_bytes(8, "big")
        stream = AES.new(key, AES.MODE_ECB).encrypt(counter_block)
        out.extend(x ^ y for x, y in zip(ciphertext[off : off + 16], stream))
    return bytes(out)


def main() -> int:
    data = ELF.read_bytes()
    ciphertext, tag = parse_flag_blob(FLAG_ENC.read_bytes())
    key = derive_flag_key(data, TARGET_GATE)
    verify_flag_tag(data, key, ciphertext, tag)
    flag = decrypt_flag(key, ciphertext)
    print(flag.decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
