MASK = 0xffffffff

TARGET = [
    0xc173350a, 0xb43450f5, 0xf7241b94, 0xe2df5dbb,
    0xcfd87cca, 0x2035c083, 0xd26cda5b, 0x6d1f7f8e,
    0x4fce0a8a, 0xefa6dc81, 0xb1477f05, 0x1d078f3e,
    0xe0ae01db, 0x89b60f8a, 0x0bb4e3f8, 0x83b07cdf,
]

def rol(x, n):
    return ((x << n) & MASK) | ((x & MASK) >> (32 - n))

def ror(x, n):
    return ((x & MASK) >> n) | ((x << (32 - n)) & MASK)

def inv_qr(a, b, c, d):
    # reverse:
    # a += b; d ^= a; d <<< 7
    # c += d; b ^= c; b <<< 9
    # a += b; d ^= a; d <<< 13
    # c += d; b ^= c; b <<< 18

    b1 = ror(b, 18) ^ c
    c1 = (c - d) & MASK
    d1 = ror(d, 13) ^ a
    a1 = (a - b1) & MASK

    b0 = ror(b1, 9) ^ c1
    c0 = (c1 - d1) & MASK
    d0 = ror(d1, 7) ^ a1
    a0 = (a1 - b0) & MASK

    return a0 & MASK, b0 & MASK, c0 & MASK, d0 & MASK

def inv_round(state):
    s = state[:]

    # reverse order của 8 quarter-round trong 1 loop
    groups = [
        (3,4,9,14), (2,7,8,13), (1,6,11,12), (0,5,10,15),
        (3,7,11,15), (2,6,10,14), (1,5,9,13), (0,4,8,12),
    ]

    for g in groups:
        a, b, c, d = [s[i] for i in g]
        a, b, c, d = inv_qr(a, b, c, d)
        for idx, val in zip(g, [a, b, c, d]):
            s[idx] = val

    return s

state = TARGET[:]
for _ in range(8):
    state = inv_round(state)

flag_inner = b"".join(x.to_bytes(4, "little") for x in state).decode()
print(flag_inner)
print(f"codegate2026{{{flag_inner}}}")