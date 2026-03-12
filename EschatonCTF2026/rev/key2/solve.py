#!/usr/bin/env python3
import re
import socket
import sys
from typing import Optional, Tuple

MASK32 = 0xFFFFFFFF

def rol32(x, r):
    x &= MASK32
    return ((x << r) | (x >> (32 - r))) & MASK32

def ror32(x, r):
    x &= MASK32
    return ((x >> r) | (x << (32 - r))) & MASK32

def gf_hash(data: bytes) -> int:
    eax = 0x4E7F2A19
    for i, b in enumerate(data):
        shift = (i & 3) * 8
        esi = ((b & 0xFF) << shift) & MASK32
        esi ^= eax
        esi = rol32(esi, 5)
        edx = (esi + 0x3C91E6B7) & MASK32
        eax = (ror32(edx, 11) ^ edx) & MASK32
    return eax

def F0(seed): return (rol32(seed, 7) ^ 0x8D2F5A1C) & MASK32
def F1(seed):
    lo = seed & 0xFFFF
    hi = (seed >> 16) & 0xFFFF
    lo ^= 0x6B3E
    hi ^= 0x1FA9
    return (((lo & 0xFFFF) << 16) | (hi & 0xFFFF)) & MASK32
def F2(seed): return (ror32(seed, 13) + 0x47C83D2E) & MASK32

def keygen(username: str, hwid_hex: str) -> str:
    hw = int(hwid_hex, 16)
    seed0 = hw ^ gf_hash(username.encode())

    s1 = F0(seed0); k1 = s1 & 0xFFFF
    s2 = F1(s1);    k2 = s2 & 0xFFFF
    s3 = F2(s2);    k3 = s3 & 0xFFFF

    data6 = bytes([
        k1 & 0xFF, (k1 >> 8) & 0xFF,
        k2 & 0xFF, (k2 >> 8) & 0xFF,
        k3 & 0xFF, (k3 >> 8) & 0xFF,
    ])
    k4 = (gf_hash(data6) & 0xFFFF) ^ 0x52B1
    return f"A1B2-{k1:04X}-{k2:04X}-{k3:04X}-{k4:04X}"

# --------- Net helpers ----------
USER_RE = re.compile(r"Username:\s*([A-Za-z0-9_]{1,64})")
HWID_RE = re.compile(r"(?:HWID|Hardware\s*ID)\s*:\s*([0-9a-fA-F]{8})")
FLAG_RE = re.compile(r"(flag\{.*?\}|MCSC\{.*?\}|CTF\{.*?\})", re.IGNORECASE)

def recv_some(sock: socket.socket) -> str:
    data = sock.recv(4096)
    if not data:
        return ""
    return data.decode(errors="replace")

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <host> <port>")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])

    s = socket.create_connection((host, port), timeout=10)
    s.settimeout(10)

    buf = ""
    cur_user: Optional[str] = None
    cur_hwid: Optional[str] = None

    while True:
        chunk = recv_some(s)
        if chunk == "":
            # connection closed
            break

        buf += chunk
        # print everything as it arrives (nice for debugging)
        sys.stdout.write(chunk)
        sys.stdout.flush()

        # Try to extract username/hwid from the accumulated buffer
        m = USER_RE.search(buf)
        if m:
            cur_user = m.group(1)

        m = HWID_RE.search(buf)
        if m:
            cur_hwid = m.group(1)

        # Some servers just print an 8-hex HWID without label -> try fallback
        if cur_hwid is None:
            m2 = re.search(r"\b([0-9a-fA-F]{8})\b", buf)
            # Only accept fallback if buffer has hint words (avoid grabbing random hex in banners)
            if m2 and re.search(r"\b(hwid|hardware)\b", buf, re.IGNORECASE):
                cur_hwid = m2.group(1)

        # If prompted for key, answer when we have the needed data
        if "Enter key" in buf or "Enter Key" in buf or "Enter license" in buf:
            if not cur_user:
                raise RuntimeError("Saw key prompt but couldn't parse Username")
            if not cur_hwid:
                raise RuntimeError("Saw key prompt but couldn't parse HWID (expected 8 hex chars)")

            k = keygen(cur_user, cur_hwid)
            s.sendall((k + "\n").encode())
            # reset buffer so we don't re-trigger on the same prompt text
            buf = ""
            cur_user = None
            cur_hwid = None
            continue

        # If flag appears, print it clearly then exit
        fm = FLAG_RE.search(buf)
        if fm:
            print("\n[+] FLAG:", fm.group(1))
            break

    s.close()

if __name__ == "__main__":
    main()
