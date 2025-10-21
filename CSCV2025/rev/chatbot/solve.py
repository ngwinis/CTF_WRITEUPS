#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Rebuild key from recover_key() logic, then decrypt flag.enc (IV||CT).

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# --- raw arrays (dùng vừa đủ) ---
OBF_KEY = bytes([
    0xEE, 0x50, 0xD1, 0xAA, 0xE0, 0x97, 0x5F, 0x43, 0xDD, 0xA8,
    0xAC, 0x83, 0xF0, 0x05, 0xF3, 0xFF, 0x62, 0x08, 0xF4, 0x44,
    0x4B, 0x2C, 0x55, 0xEC, 0xB9, 0x65, 0x23, 0xCC, 0x25, 0x65,
    0xEE, 0x70,
    # nếu bạn có copy thừa thì cũng kệ: ta chỉ dùng 32 byte đầu
][:32])

MASK = bytes([
    0x2A, 0x2A, 0x0A, 0x9A,
    # có thêm số nào phía sau cũng bỏ qua, chỉ dùng 4 byte đầu
][:4])

def recover_key_like_so() -> bytes:
    key = bytearray(32)
    key[0] = (256 - 60) & 0xFF  # -60 => 0xC4
    for i in range(1, 32):
        key[i] = OBF_KEY[i] ^ MASK[i & 3]
    return bytes(key)

def solve(path="flag.enc", out="flag.dec"):
    data = open(path, "rb").read()
    if len(data) <= 16:
        raise SystemExit("flag.enc quá ngắn (<=16B).")

    iv, ct = data[:16], data[16:]
    key = recover_key_like_so()

    print("[i] Key (hex):", key.hex())
    print("[i] IV  (hex):", iv.hex())

    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), 16)

    # lưu và in
    open(out, "wb").write(pt)
    try:
        print("[+] Flag:", pt.decode().strip())
    except UnicodeDecodeError:
        print("[+] Flag (bytes):", pt)
    print(f"[+] Đã lưu plaintext → {out}")

if __name__ == "__main__":
    solve()

# Flag: CSCV2025{reversed_vip*_chatbot_bypassed}