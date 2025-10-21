# solve_xmm_aa.py
# Recover 32-byte input from:
# inp[0:16]^=0xAA..AA == xmmword_7FF667EC9000
# v10[0:16]^=0xAA..AA  == xmmword_7FF667EC9010

import argparse
from pwn import process

XMM1 = "9A CB CF 9E 98 C9 C8 9D C9 98 99 9B 9C CF 9F 93"
XMM2 = "CF CF CF 9D CF 98 9A 99 9B 9A 98 CB 9D 9D 9D 9F"

def unxor_aa(hexstr: str) -> bytes:
    b = bytes.fromhex(hexstr.replace(" ", ""))
    return bytes(x ^ 0xAA for x in b)

def build_input() -> bytes:
    p1 = unxor_aa(XMM1)  # b"sorry_this_is_fa"
    p2 = unxor_aa(XMM2)  # b"ke_flag!!!!!!!!!"  (9 dấu '!')
    flag_inp = p1 + p2
    assert len(flag_inp) == 32
    return flag_inp

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", metavar="BIN", help="Chạy binary local để xác nhận")
    args = ap.parse_args()

    val = build_input()
    print(val.decode("ascii"))
    if args.run:
        io = process(args.run)
        io.recvuntil(b"Enter flag:")
        io.sendline(val)
        print(io.recvall(timeout=2).decode("utf-8", errors="ignore"))

if __name__ == "__main__":
    main()

# flag: CSCV2025{0ae42cb7c2316e59eee7e203102a7775}