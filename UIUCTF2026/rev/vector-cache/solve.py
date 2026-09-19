#!/usr/bin/env python3
"""
Solver for UIUCTF vector-cache.
Usage:  python3 solve_vector_cache.py ./vector-cache
No external dependency is required.
"""
import struct
import sys
from itertools import product
from pathlib import Path

MASK = (1 << 64) - 1
PHI = 0x9E3779B97F4A7C15


def rol(x, n, w=64):
    n %= w
    return ((x << n) | (x >> (w - n))) & ((1 << w) - 1)


def ror(x, n, w=64):
    n %= w
    return ((x >> n) | (x << (w - n))) & ((1 << w) - 1)


def rol8(x, n):
    return rol(x & 0xFF, n, 8)


def splitmix(x):
    x &= MASK
    x ^= x >> 30
    x = (x * 0xBF58476D1CE4E5B9) & MASK
    x ^= x >> 27
    x = (x * 0x94D049BB133111EB) & MASK
    x ^= x >> 31
    return x & MASK


def splitmix_pre_final(x):
    # The VM accumulator uses splitmix without the last xor, then xors x >> 31
    # together with the previous accumulator.
    x &= MASK
    x ^= x >> 30
    x = (x * 0xBF58476D1CE4E5B9) & MASK
    x ^= x >> 27
    x = (x * 0x94D049BB133111EB) & MASK
    return x & MASK


class ELF:
    def __init__(self, path):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        if self.data[:4] != b"\x7fELF" or self.data[4] != 2 or self.data[5] != 1:
            raise SystemExit("expected a 64-bit little-endian ELF")

        eh = struct.unpack_from("<16sHHIQQQIHHHHHH", self.data, 0)
        (_, _, _, _, _, phoff, shoff, _, ehsize, phentsize, phnum,
         shentsize, shnum, shstrndx) = eh

        self.loads = []
        for i in range(phnum):
            p = struct.unpack_from("<IIQQQQQQ", self.data, phoff + i * phentsize)
            p_type, _, p_offset, p_vaddr, _, p_filesz, _, _ = p
            if p_type == 1:  # PT_LOAD
                self.loads.append((p_vaddr, p_vaddr + p_filesz, p_offset))

        # Parse .rela.dyn so RELATIVE pointer entries in .data.rel.ro work in PIE.
        shdrs = []
        for i in range(shnum):
            shdrs.append(struct.unpack_from("<IIQQQQIIQQ", self.data, shoff + i * shentsize))
        shstr = shdrs[shstrndx]
        shstrtab = self.data[shstr[4]: shstr[4] + shstr[5]]

        self.reloc = {}
        for sh in shdrs:
            name_off, sh_type, _, _, sh_offset, sh_size, _, _, _, sh_entsize = sh
            end = shstrtab.find(b"\x00", name_off)
            name = shstrtab[name_off:end].decode(errors="ignore")
            if name == ".rela.dyn":
                entsize = sh_entsize or 24
                for off in range(sh_offset, sh_offset + sh_size, entsize):
                    r_offset, r_info, r_addend = struct.unpack_from("<QQq", self.data, off)
                    r_type = r_info & 0xFFFFFFFF
                    if r_type == 8:  # R_X86_64_RELATIVE
                        self.reloc[r_offset] = r_addend & MASK

    def off(self, va):
        for start, end, foff in self.loads:
            if start <= va < end:
                return foff + (va - start)
        raise KeyError(f"virtual address not mapped: {va:#x}")

    def u8(self, va):
        return self.data[self.off(va)]

    def u64(self, va):
        return struct.unpack_from("<Q", self.data, self.off(va))[0]

    def ptr(self, va):
        return self.reloc.get(va, self.u64(va))

    def blob(self, va, n):
        o = self.off(va)
        return self.data[o:o + n]


E = None


def h1850(buf, n, seed, salt):
    # Function at 0x1850, used to chain the three VM stages.
    st = 0
    for i in range(n):
        x = ((buf[i] + 0x41 + 0x11 * i) * 0x100000001B3) & MASK
        if i == 0:
            x ^= seed ^ salt ^ 0xA4093822299F31D0
        else:
            x ^= st
        st = splitmix((rol(x, 7 + i) + PHI) & MASK)
    return splitmix(((n * 0xD1B54A32D192ED03) & MASK) ^ st)


def xorshift64(x):
    x &= MASK
    if x == 0:
        return 0xDC1B77AE0BF34DAD
    x ^= (x << 13) & MASK
    x ^= x >> 7
    x ^= (x << 17) & MASK
    return x & MASK


def setup_vm(mode, seed):
    # Rebuild the context prepared by function 0x2620 before it starts UD2/SIGILL VM steps.
    q = [E.u64(0x7D00 + 24 * mode + 8 * i) for i in range(3)]
    selector = splitmix(rol(q[1], mode * 9 + 7) ^ ((0xD6E8FEB86659FD93 + q[2]) & MASK) ^ q[0])
    variant = (selector >> E.u8(0x7CE0 + mode)) & 3

    program = E.ptr(0x9D20 + 8 * (mode * 4 + variant))
    opmap = E.ptr(0x9D00 + 8 * mode)

    q = [E.u64(0x7DC0 + mode * 96 + variant * 24 + 8 * i) for i in range(3)]
    rng = (((mode + 1) * 0xC2B2AE3D27D4EB4F) & MASK) ^ seed
    rng ^= (((variant + 3) * 0x165667B19E3779F9) & MASK)
    rng ^= (0xE7037ED1A0B428DB + q[1]) & MASK
    rng ^= ror(q[2], 11)
    rng ^= rol(0xA0761D6478BD642F ^ q[0], 17)

    q = [E.u64(0x7D60 + 24 * mode + 8 * i) for i in range(3)]
    srng = ror(q[2], 7) ^ q[1] ^ rol(0x8EBC6AF09C88C6E3 ^ q[0], 23)
    sbox = list(E.blob(0x7F40, 0x100))
    for pos in range(255, 0, -1):
        srng = xorshift64((pos + PHI + srng) & MASK)
        j = srng % (pos + 1)
        sbox[pos], sbox[j] = sbox[j], sbox[pos]

    return {
        "mode": mode,
        "variant": variant,
        "program": program,
        "opmap": opmap,
        "rng": rng,
        "pc": 0,
        "count": 0,
        "last": (mode * 0x31 ^ variant * 0x17 ^ 0xA5) & 0xFF,
        "acc0": (mode * PHI ^ 0x243F6A8885A308D3) & MASK,
        "acc1": 0,
        "sbox": sbox,
    }


def decode_16(ctx):
    pc = ctx["pc"]
    mul = (pc * 0xD1342543DE82EF95) & MASK
    rng = ctx["rng"]
    last = ctx["last"]
    out = []
    for i in range(16):
        old = last
        enc = E.u8(ctx["program"] + pc + i)
        rng = xorshift64((old + mul + PHI + rng) & MASK)
        last = enc
        out.append((rol8(old, (pc + i) % 7 + 1) ^ enc ^ ((rng >> (((pc + i) & 7) * 8)) & 0xFF)) & 0xFF)
        mul = (mul + 0xD1342543DE82EF95) & MASK
    ctx["rng"] = rng
    ctx["last"] = last
    return out


def checksum_ok(d, mode, variant, count):
    x = (mode * 0x2311) & 0xFFFF
    c = count & 0xFF
    c = c + c * 4
    c = c + c * 4
    x ^= c & 0xFFFF
    x ^= d[0]
    x ^= (variant * 0x4513) & 0xFFFF
    x ^= 0x6D5A
    x = rol(x, 5, 16)

    x = rol((((d[1] + 0x3D) & 0xFF) ^ ((d[0] + x - 0x61C9) & 0xFFFF)) & 0xFFFF, 5, 16)
    x = rol((((x + d[1] * 2 - 0x61C9) & 0xFFFF) ^ ((d[2] + 0x7A) & 0xFF)) & 0xFFFF, 5, 16)
    x = rol((((x + d[2] * 4 - 0x61C9) & 0xFFFF) ^ ((d[3] + 0xB7) & 0xFF)) & 0xFFFF, 5, 16)
    x = rol((((x + d[3] * 8 - 0x61C9) & 0xFFFF) ^ ((d[4] + 0xF4) & 0xFF)) & 0xFFFF, 5, 16)
    x = rol((((x + d[4] - 0x61C9) & 0xFFFF) ^ ((d[5] + 0x131) & 0xFF)) & 0xFFFF, 5, 16)
    x = rol((((x + d[5] * 2 - 0x61C9) & 0xFFFF) ^ ((d[6] + 0x16E) & 0xFF)) & 0xFFFF, 5, 16)
    x = rol((((x + d[6] * 4 - 0x61C9) & 0xFFFF) ^ ((d[7] + 0x1AB) & 0xFF)) & 0xFFFF, 5, 16)
    x = rol((((x + d[7] * 8 - 0x61C9) & 0xFFFF) ^ ((d[8] + 0x1E8) & 0xFF)) & 0xFFFF, 5, 16)
    x = rol((((x + d[8] - 0x61C9) & 0xFFFF) ^ ((d[9] + 0x225) & 0xFF)) & 0xFFFF, 5, 16)
    x = rol((((x + d[9] * 2 - 0x61C9) & 0xFFFF) ^ ((d[10] + 0x262) & 0xFF)) & 0xFFFF, 5, 16)
    x = rol((((x + d[10] * 4 - 0x61C9) & 0xFFFF) ^ ((d[11] + 0x29F) & 0xFF)) & 0xFFFF, 5, 16)
    x = (x + d[11] * 8 - 0x61C9) & 0xFFFF
    return x == (d[12] | (d[13] << 8))


def eval_op(op, d, tok, sbox):
    # Decoded instruction uses token[d2], token[d1], token[d3].
    x = tok[d[2]]
    y = tok[d[1]]
    z = tok[d[3]]
    c4, c5, c6, c7, c8, c9, c10, c11 = d[4], d[5], d[6], d[7], d[8], d[9], d[10], d[11]

    if op == 0:
        return (rol8(c7 ^ z, c5) ^ c8 ^ sbox[(rol8(x, c4) + c6 + y) & 0xFF]) & 0xFF
    if op == 1:
        return (rol8((c7 + z) & 0xFF, c5) + c8 + sbox[(rol8((c6 + x) & 0xFF, c4) ^ y) & 0xFF]) & 0xFF
    if op == 2:
        return (c8 ^ sbox[(z + c7) & 0xFF] ^ sbox[(y + c6 - x) & 0xFF]) & 0xFF
    if op == 3:
        return (rol8(sbox[(y ^ c6) & 0xFF], c4) ^ (((c9 * x + c7) & 0xFF) ^ rol8(z, c5) ^ c8)) & 0xFF
    if op == 4:
        return (((((z + c7) & 0xFF) * c9) ^ c8 ^ sbox[(y + c6 + sbox[x]) & 0xFF]) & 0xFF)
    if op == 5:
        return (sbox[(rol8(x, c4) + (c6 ^ y)) & 0xFF] + c8 - rol8(z ^ c7, c5)) & 0xFF
    if op == 6:
        return (sbox[(y + c6) & 0xFF] ^ c7) & 0xFF
    raise ValueError(op)


def decode_constraints(mode, seed):
    ctx = setup_vm(mode, seed)
    constraints = []
    limit = mode * 8 + 8
    while ctx["count"] < 0x60:
        d = decode_16(ctx)
        if not checksum_ok(d, mode, ctx["variant"], ctx["count"]):
            raise RuntimeError("VM decode failed: checksum mismatch")
        op = E.u8(ctx["opmap"] + d[0])
        if op > 6 or d[1] >= limit or d[2] >= limit or d[3] >= limit:
            raise RuntimeError("VM decode failed: bad opcode/index")
        constraints.append((op, d, ctx["count"]))
        ctx["count"] += 1
        ctx["pc"] += 16
    return constraints, ctx


def holds(con, vals, ctx, limit):
    op, d, _ = con
    tok = [0] * limit
    for k, v in vals.items():
        tok[k] = v
    return eval_op(op, d, tok, ctx["sbox"]) == d[10]


def propagate_domains(constraints, ctx, domains, limit, max_product=1_000_000):
    changed = True
    while changed:
        changed = False
        for con in constraints:
            # Only d[1], d[2], d[3] are token indexes. Repeated indexes are OK.
            vars_ = sorted(set(con[1][1:4]))
            prod_size = 1
            for v in vars_:
                prod_size *= len(domains[v])
            if prod_size > max_product:
                continue

            support = {v: set() for v in vars_}
            for combo in product(*(domains[v] for v in vars_)):
                vals = dict(zip(vars_, combo))
                if holds(con, vals, ctx, limit):
                    for v, value in vals.items():
                        support[v].add(value)

            for v in vars_:
                new_domain = domains[v] & support[v]
                if not new_domain:
                    raise RuntimeError("empty domain; translation bug or wrong binary")
                if new_domain != domains[v]:
                    domains[v] = new_domain
                    changed = True


def update_acc(acc, count, op, d, result):
    packed = (result | (d[10] << 8) | (op << 16) | (d[1] << 24) |
              ((count & 0xFFFFFFFF) << 32) | (d[11] << 48)) & MASK
    z = splitmix_pre_final((packed + ((acc + 0xD6E8FEB86659FD93) & MASK)) & MASK)
    return rol((acc ^ z ^ (z >> 31)) & MASK, (count % 23) + 5)


def run_vm(mode, seed, token):
    constraints, ctx = decode_constraints(mode, seed)
    for op, d, count in constraints:
        result = eval_op(op, d, token, ctx["sbox"])
        if result != d[10]:
            raise RuntimeError("internal VM check failed")
        ctx["acc"] = ctx["acc0"] = update_acc(ctx["acc0"], count, op, d, result)
    return ctx["acc0"]


def solve_stage(mode, seed, known):
    constraints, ctx = decode_constraints(mode, seed)
    limit = mode * 8 + 8
    domains = []
    for i in range(limit):
        domains.append({known[i]} if i in known else set(range(256)))

    propagate_domains(constraints, ctx, domains, limit)

    if any(len(d) != 1 for d in domains):
        left = [(i, len(d)) for i, d in enumerate(domains) if len(d) != 1]
        raise RuntimeError(f"not fully solved: {left}")
    return bytes(next(iter(domains[i])) for i in range(limit))


def main():
    global E
    binary = sys.argv[1] if len(sys.argv) > 1 else "./vector-cache"
    E = ELF(binary)

    known = {}
    seed = 0
    token = b""

    # Stage 0 solves bytes 0..7.
    token = solve_stage(0, seed, known)
    acc0 = run_vm(0, seed, token + b"\x00" * 16)
    known.update({i: token[i] for i in range(8)})
    seed = h1850(token + b"\x00" * 16, 8, acc0, 0x13579BDF2468ACE0)

    # Stage 1 solves bytes 8..15.
    token = solve_stage(1, seed, known)
    acc1 = run_vm(1, seed, token + b"\x00" * 8)
    known.update({i: token[i] for i in range(16)})
    seed = h1850(token + b"\x00" * 8, 16, rol(acc1, 17) ^ acc0, 0x0F1E2D3C4B5A6978)

    # Stage 2 solves bytes 16..23.
    token = solve_stage(2, seed, known)
    run_vm(2, seed, token)

    print(f"uiuctf{{{token.hex()}}}")


if __name__ == "__main__":
    main()
