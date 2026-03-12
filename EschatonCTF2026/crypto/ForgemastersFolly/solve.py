#!/usr/bin/env sage -python
# -*- coding: utf-8 -*-

import re
import argparse
import urllib.request

from sage.all import Integer, PolynomialRing, Zmod, gcd, inverse_mod, power_mod

try:
    from Crypto.Util.number import long_to_bytes
except Exception:
    def long_to_bytes(n: int) -> bytes:
        if n == 0:
            return b"\x00"
        out = []
        while n:
            out.append(n & 0xff)
            n >>= 8
        return bytes(reversed(out))

RE_HEX_LINE = re.compile(r'^\s*([A-Za-z]+)\s*=\s*0x([0-9a-fA-F]+)\s*$', re.M)
RE_DEC_LINE = re.compile(r'^\s*([A-Za-z]+)\s*=\s*([0-9]+)\s*$', re.M)

def fetch(url: str, timeout: int = 15) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "sage-solve/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="replace")

def parse_instance(text: str):
    d = {}

    # hex fields
    for key, hexv in RE_HEX_LINE.findall(text):
        d[key] = int(hexv, 16)

    # decimal fields (e, k, maybe others)
    for key, decv in RE_DEC_LINE.findall(text):
        # đừng overwrite hex nếu key trùng (hiếm)
        if key not in d:
            d[key] = int(decv, 10)

    needed = ["N", "A", "c", "k", "e"]
    missing = [x for x in needed if x not in d]
    if missing:
        # debug nhỏ: in các key đã parse được
        raise ValueError(f"Missing fields: {missing}. Parsed keys={sorted(d.keys())}")
    return d

def factor_known_highbits(N: Integer, A: Integer, k: int):
    # assume q = (A << k) + x with |x| < 2^k (LSB unknown)
    qbar = A << k

    R = PolynomialRing(Zmod(N), names=("x",))
    x = R.gen()

    # try both conventions
    polys = [
        ("plus",  x + qbar),   # q = qbar + x
        ("minus", qbar - x),   # q = qbar - x
    ]

    for pname, f in polys:
        # robust params
        for beta in [0.50, 0.49, 0.51, 0.45]:
            for Xpow in [k, k + 1, k + 2]:
                X = Integer(1) << Xpow
                roots = f.small_roots(X=X, beta=beta)
                if not roots:
                    continue

                for r in roots:
                    r = Integer(r)
                    for qcand in (qbar + r, qbar - r):
                        g = gcd(N, qcand)
                        if 1 < g < N:
                            q = Integer(g)
                            p = Integer(N // q)
                            meta = {"poly": pname, "beta": float(beta), "Xpow": int(Xpow), "root": int(r)}
                            return p, q, meta

    raise ValueError("Failed to factor: no valid gcd from Coppersmith roots")

def rsa_decrypt(N, e, p, q, c):
    phi = (p - 1) * (q - 1)
    d = inverse_mod(Integer(e), phi)
    m = power_mod(Integer(c), d, Integer(N))
    pt = long_to_bytes(int(m))
    return int(m), pt

def extract_flag(pt: bytes):
    # common CTF flag patterns
    m = re.search(rb"[A-Za-z0-9_+-]{0,30}\{[^{}]{5,200}\}", pt)
    if m:
        return m.group(0)
    # fallback: printable run
    m = re.search(rb"[ -~]{10,}", pt)
    return m.group(0) if m else pt

def solve_url(url: str, verbose: bool = True):
    txt = fetch(url)
    inst = parse_instance(txt)

    N = Integer(inst["N"])
    A = Integer(inst["A"])
    c = Integer(inst["c"])
    k = int(inst["k"])
    e = int(inst["e"])

    if verbose:
        print(f"[+] fetched {url}")
        print(f"[+] bitlen(N)={N.nbits()}  bitlen(A)={Integer(A).nbits()}  k={k}  e={e}")

    p, q, meta = factor_known_highbits(N, A, k)

    if verbose:
        print("[+] factored!")
        print("[+] meta:", meta)
        print("[+] p =", p)
        print("[+] q =", q)

    _, pt = rsa_decrypt(N, e, p, q, c)
    print("[+] plaintext(raw) =", pt)
    try:
        print("[+] plaintext(utf8) =", pt.decode())
    except Exception:
        pass
    print("[+] extracted =", extract_flag(pt))

def main():
    ap = argparse.ArgumentParser(description="ForgemastersFolly multi-instance solver")
    ap.add_argument("url", help="e.g. http://node-2.mcsc.space:11543/")
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args()
    solve_url(args.url, verbose=(not args.quiet))

if __name__ == "__main__":
    main()
