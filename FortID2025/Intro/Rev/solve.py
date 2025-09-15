#!/usr/bin/env python3
# FortID Rev-100 "search for the flag" solver
# The binary stores a '<', '>', '=' trace of a binary search on a byte (0..255)
# for each flag character. We invert that trace to recover the flag.

from pathlib import Path

def extract_trace(data: bytes) -> str:
    # Longest run consisting solely of '<', '>' and '=' in the file
    start = best = 0
    best_span = (0, 0)
    i = 0
    while i < len(data):
        if data[i] in (0x3c, 0x3e, 0x3d):  # '<', '>', '='
            j = i
            while j < len(data) and data[j] in (0x3c, 0x3e, 0x3d):
                j += 1
            if j - i > best:
                best = j - i
                best_span = (i, j)
            i = j
        else:
            i += 1
    s, e = best_span
    if best == 0:
        raise RuntimeError("no '<', '>', '=' run found")
    return data[s:e].decode()

def decode_from_trace(trace: str, lo0=0, hi0=255) -> str:
    # Replay the exact comparisons; every '=' ends a character.
    out = []
    lo, hi = lo0, hi0
    for step in trace:
        mid = (lo + hi) // 2  # mirrors 'sar' mid = (lo+hi)>>1
        if step == '=':
            out.append(chr(mid))
            lo, hi = lo0, hi0
        elif step == '<':
            hi = mid - 1
        elif step == '>':
            lo = mid + 1
        else:
            raise ValueError("unexpected symbol in trace")
    return "".join(out)

def main(path="chall"):
    data = Path(path).read_bytes()
    trace = extract_trace(data)
    flag = decode_from_trace(trace, 0, 255)
    print(flag)

if __name__ == "__main__":
    import sys
    main(sys.argv[1] if len(sys.argv) > 1 else "chall")


# Flag: FortID{3a7_Y0ur_V3gg1e5_4nd_L3rn_Y0ur_Fund4m3n741_S3arch_Alg0r17hm5}