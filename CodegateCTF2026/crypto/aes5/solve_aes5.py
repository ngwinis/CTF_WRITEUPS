#!/usr/bin/env python3
import os, sys, random, socket, subprocess, argparse, tempfile, time
from collections import defaultdict
from typing import List, Tuple, Optional

# AES tables from challenge
SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]
INV_SBOX = [
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
]

MUL2 = [0] * 256
MUL3 = [0] * 256
GF_INV = [0] * 256

def xtime(x: int) -> int:
    return (((x << 1) ^ 0x1B) & 0xFF) if (x & 0x80) else ((x << 1) & 0xFF)

def gf_mul(x: int, y: int) -> int:
    z = 0
    while y:
        if y & 1:
            z ^= x
        x = xtime(x)
        y >>= 1
    return z

for x in range(256):
    MUL2[x] = gf_mul(x, 2)
    MUL3[x] = gf_mul(x, 3)
for a in range(1, 256):
    for b in range(1, 256):
        if gf_mul(a, b) == 1:
            GF_INV[a] = b
            break


def idx(r: int, c: int) -> int:
    return r + 4 * c

def xor_block(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def bytes_to_state(block: bytes) -> List[List[int]]:
    return [[block[r + 4 * c] for c in range(4)] for r in range(4)]

def state_to_bytes(state: List[List[int]]) -> bytes:
    return bytes(state[r][c] for c in range(4) for r in range(4))

def sub_bytes(state: List[List[int]]) -> None:
    for r in range(4):
        for c in range(4):
            state[r][c] = SBOX[state[r][c]]

def inv_sub_bytes(state: List[List[int]]) -> None:
    for r in range(4):
        for c in range(4):
            state[r][c] = INV_SBOX[state[r][c]]

def shift_rows(state: List[List[int]]) -> None:
    for r in range(1, 4):
        state[r] = state[r][r:] + state[r][:r]

def inv_shift_rows(state: List[List[int]]) -> None:
    for r in range(1, 4):
        state[r] = state[r][-r:] + state[r][:-r]

def mix_columns(state: List[List[int]]) -> None:
    for c in range(4):
        a0, a1, a2, a3 = state[0][c], state[1][c], state[2][c], state[3][c]
        state[0][c] = MUL2[a0] ^ MUL3[a1] ^ a2 ^ a3
        state[1][c] = a0 ^ MUL2[a1] ^ MUL3[a2] ^ a3
        state[2][c] = a0 ^ a1 ^ MUL2[a2] ^ MUL3[a3]
        state[3][c] = MUL3[a0] ^ a1 ^ a2 ^ MUL2[a3]

def inv_mix_columns(state: List[List[int]]) -> None:
    for c in range(4):
        a0, a1, a2, a3 = state[0][c], state[1][c], state[2][c], state[3][c]
        state[0][c] = gf_mul(a0, 14) ^ gf_mul(a1, 11) ^ gf_mul(a2, 13) ^ gf_mul(a3, 9)
        state[1][c] = gf_mul(a0, 9) ^ gf_mul(a1, 14) ^ gf_mul(a2, 11) ^ gf_mul(a3, 13)
        state[2][c] = gf_mul(a0, 13) ^ gf_mul(a1, 9) ^ gf_mul(a2, 14) ^ gf_mul(a3, 11)
        state[3][c] = gf_mul(a0, 11) ^ gf_mul(a1, 13) ^ gf_mul(a2, 9) ^ gf_mul(a3, 14)

def add_round_key(state: List[List[int]], round_key: bytes) -> None:
    for c in range(4):
        for r in range(4):
            state[r][c] ^= round_key[idx(r, c)]

def SB_bytes(block: bytes) -> bytes:
    s = bytes_to_state(block)
    sub_bytes(s)
    return state_to_bytes(s)

def InvSB_bytes(block: bytes) -> bytes:
    s = bytes_to_state(block)
    inv_sub_bytes(s)
    return state_to_bytes(s)

def SR_bytes(block: bytes) -> bytes:
    s = bytes_to_state(block)
    shift_rows(s)
    return state_to_bytes(s)

def InvSR_bytes(block: bytes) -> bytes:
    s = bytes_to_state(block)
    inv_shift_rows(s)
    return state_to_bytes(s)

def MC_bytes(block: bytes) -> bytes:
    s = bytes_to_state(block)
    mix_columns(s)
    return state_to_bytes(s)

def InvMC_bytes(block: bytes) -> bytes:
    s = bytes_to_state(block)
    inv_mix_columns(s)
    return state_to_bytes(s)


def set_byte(block: bytes, pos: int, val: int) -> bytes:
    b = bytearray(block)
    b[pos] = val
    return bytes(b)

def col_tuple(block: bytes, c: int) -> Tuple[int, int, int, int]:
    return tuple(block[idx(r, c)] for r in range(4))

def pack_vals(vals: List[int]) -> int:
    out = 0
    for i, v in enumerate(vals):
        out |= v << (8 * i)
    return out


def swap_first_differing_column(x: bytes, y: bytes) -> Tuple[bytes, bytes]:
    bx = bytearray(x)
    by = bytearray(y)
    z = -1
    for c in range(4):
        if any(bx[idx(r, c)] != by[idx(r, c)] for r in range(4)):
            z = c
            break
    if z == -1:
        return bytes(bx), bytes(by)
    for r in range(4):
        i = idx(r, z)
        bx[i], by[i] = by[i], bx[i]
    return bytes(bx), bytes(by)


class RetryThisConnection(Exception):
    pass


class DirectOracle:
    def __init__(self, round_keys: List[bytes], aes5_module, max_queries: int = 4096):
        self.round_keys = round_keys
        self.mod = aes5_module
        self.max_queries = max_queries
        self.queries = 0
    def _use(self) -> None:
        if self.queries >= self.max_queries:
            raise RetryThisConnection('query budget exhausted')
        self.queries += 1
    def encrypt(self, pt: bytes) -> bytes:
        self._use()
        return self.mod.aes5_encrypt_block(pt, self.round_keys)
    def decrypt(self, ct: bytes) -> bytes:
        self._use()
        return self.mod.aes5_decrypt_block(ct, self.round_keys)
    def remaining(self) -> int:
        return self.max_queries - self.queries


# ---------- oracle wrappers ----------

def super_encrypt(oracle, block: bytes) -> bytes:
    return InvSR_bytes(oracle.encrypt(InvSR_bytes(block)))

def super_decrypt(oracle, block: bytes) -> bytes:
    return SR_bytes(oracle.decrypt(SR_bytes(block)))


def yoyo_next_pair(oracle, p1: bytes, p2: bytes) -> Tuple[bytes, bytes]:
    p1 = super_encrypt(oracle, p1)
    p2 = super_encrypt(oracle, p2)
    p1, p2 = swap_first_differing_column(p1, p2)
    p1 = super_decrypt(oracle, p1)
    p2 = super_decrypt(oracle, p2)
    p1, p2 = swap_first_differing_column(p1, p2)
    return p1, p2


def yoyo_initial_pair(i: int, z: int = 123) -> Tuple[bytes, bytes]:
    p1 = bytes(16)
    p2 = bytes(16)
    p1 = set_byte(p1, idx(1, 0), i)
    p2 = set_byte(p2, idx(0, 0), z)
    p2 = set_byte(p2, idx(1, 0), z ^ i)
    return p1, p2


def column_condition(pair: Tuple[bytes, bytes], col: Tuple[int, int, int, int]) -> bool:
    p1, p2 = pair
    d0 = SBOX[p1[idx(0, 0)] ^ col[0]] ^ SBOX[p2[idx(0, 0)] ^ col[0]]
    d1 = SBOX[p1[idx(1, 0)] ^ col[1]] ^ SBOX[p2[idx(1, 0)] ^ col[1]]
    d2 = SBOX[p1[idx(2, 0)] ^ col[2]] ^ SBOX[p2[idx(2, 0)] ^ col[2]]
    d3 = SBOX[p1[idx(3, 0)] ^ col[3]] ^ SBOX[p2[idx(3, 0)] ^ col[3]]
    return (d0 ^ d1 ^ MUL2[d2] ^ MUL3[d3]) == 0


def recover_first_column_candidates(pairs: List[Tuple[bytes, bytes]], i: int) -> List[Tuple[int, int, int, int]]:
    n = len(pairs)
    row0 = [0] * 256
    row1 = [0] * 256
    row2 = [0] * 256
    row3 = [0] * 256
    a10 = [p1[idx(0, 0)] for p1, _ in pairs]
    a20 = [p2[idx(0, 0)] for _, p2 in pairs]
    a11 = [p1[idx(1, 0)] for p1, _ in pairs]
    a21 = [p2[idx(1, 0)] for _, p2 in pairs]
    a12 = [p1[idx(2, 0)] for p1, _ in pairs]
    a22 = [p2[idx(2, 0)] for _, p2 in pairs]
    a13 = [p1[idx(3, 0)] for p1, _ in pairs]
    a23 = [p2[idx(3, 0)] for _, p2 in pairs]
    for k in range(256):
        row0[k] = pack_vals([SBOX[a10[t] ^ k] ^ SBOX[a20[t] ^ k] for t in range(n)])
        row1[k] = pack_vals([SBOX[a11[t] ^ k] ^ SBOX[a21[t] ^ k] for t in range(n)])
        row2[k] = pack_vals([MUL2[SBOX[a12[t] ^ k] ^ SBOX[a22[t] ^ k]] for t in range(n)])
        row3[k] = pack_vals([MUL3[SBOX[a13[t] ^ k] ^ SBOX[a23[t] ^ k]] for t in range(n)])
    lhs = defaultdict(list)
    for k1 in range(256):
        lhs[row0[k1 ^ i] ^ row1[k1]].append(k1)
    rhs = defaultdict(list)
    for k2 in range(256):
        base = row2[k2]
        for k3 in range(256):
            rhs[base ^ row3[k3]].append((k2, k3))
    out: List[Tuple[int, int, int, int]] = []
    for sig, k1s in lhs.items():
        if sig not in rhs:
            continue
        for k1 in k1s:
            for k2, k3 in rhs[sig]:
                out.append((k1 ^ i, k1, k2, k3))
    return out


def recover_full_super_k0(oracle, first_col: Tuple[int, int, int, int]) -> bytes:
    cand = bytearray(16)
    for r in range(4):
        cand[idx(r, 0)] = first_col[r]
    p1 = bytes(16)
    p2 = bytes(16)
    p1 = set_byte(p1, idx(0, 0), 1)
    p1 = InvSR_bytes(p1)
    p2 = InvSR_bytes(p2)
    p1 = InvMC_bytes(p1)
    p2 = InvMC_bytes(p2)
    p1 = InvSB_bytes(p1)
    p2 = InvSB_bytes(p2)
    p1 = xor_block(p1, bytes(cand))
    p2 = xor_block(p2, bytes(cand))
    pairs: List[Tuple[bytes, bytes]] = []
    for _ in range(5):
        pairs.append((p1, p2))
        p1, p2 = yoyo_next_pair(oracle, p1, p2)

    beta = [0x0B, 0x0E, 0x09, 0x0D]
    for z in range(1, 4):
        # precompute row signatures for this column
        row_sig = [[(0, 0, 0, 0, 0)] * 256 for _ in range(4)]
        for r in range(4):
            a1 = [p1[idx(r, z)] for p1, _ in pairs]
            a2 = [p2[idx(r, z)] for _, p2 in pairs]
            for k in range(256):
                row_sig[r][k] = tuple(SBOX[a1[t] ^ k] ^ SBOX[a2[t] ^ k] for t in range(5))
        found = False
        coef0 = GF_INV[beta[(1 - z) % 4]]
        coef1 = GF_INV[beta[(2 - z) % 4]]
        coef2 = GF_INV[beta[(3 - z) % 4]]
        coef3 = GF_INV[beta[(4 - z) % 4]]
        row1_map = defaultdict(list)
        row2_map = defaultdict(list)
        row3_map = defaultdict(list)
        for k in range(256):
            row1_map[tuple(gf_mul(coef1, v) for v in row_sig[1][k])].append(k)
            row2_map[tuple(gf_mul(coef2, v) for v in row_sig[2][k])].append(k)
            row3_map[tuple(gf_mul(coef3, v) for v in row_sig[3][k])].append(k)
        for k0 in range(256):
            tgt = tuple(gf_mul(coef0, v) for v in row_sig[0][k0])
            c1 = row1_map.get(tgt)
            c2 = row2_map.get(tgt)
            c3 = row3_map.get(tgt)
            if not c1 or not c2 or not c3:
                continue
            cand[idx(0, z)] = k0
            cand[idx(1, z)] = c1[0]
            cand[idx(2, z)] = c2[0]
            cand[idx(3, z)] = c3[0]
            found = True
            break
        if not found:
            raise RetryThisConnection('failed to extend super K0')
    return bytes(cand)


def recover_k0(oracle, reserve_after: int = 700) -> bytes:
    for i in range(1, 256):
        if oracle.remaining() < reserve_after + 20:
            raise RetryThisConnection('not enough queries left for middle attack')
        p1, p2 = yoyo_initial_pair(i)
        pairs: List[Tuple[bytes, bytes]] = []
        for _ in range(4):
            pairs.append((p1, p2))
            p1, p2 = yoyo_next_pair(oracle, p1, p2)
        # the current pair is the 5th stored pair and costs no extra query
        pairs.append((p1, p2))
        cands = recover_first_column_candidates(pairs, i)
        if not cands:
            continue
        # one extra yoyo pair is enough in my local tests to reject spurious i values
        pv1, pv2 = yoyo_next_pair(oracle, p1, p2)
        kept = [cand for cand in cands if column_condition((pv1, pv2), cand)]
        if not kept:
            continue
        super_k0 = recover_full_super_k0(oracle, kept[0])
        return InvSR_bytes(super_k0)
    raise RetryThisConnection('failed to recover K0 on this connection')


# ---------- middle-round recovery ----------

def pt_from_A(A: bytes, K0: bytes) -> bytes:
    return xor_block(InvSB_bytes(InvSR_bytes(InvMC_bytes(A))), K0)


def sr_positions_of_column(q: int) -> List[int]:
    return [idx(r, (q - r) % 4) for r in range(4)]


def peel_to_Z(ct: bytes, K5: bytes) -> bytes:
    return InvMC_bytes(InvSB_bytes(InvSR_bytes(xor_block(ct, K5))))


def peel_to_V(ct: bytes, K5: bytes, K4p: bytes) -> bytes:
    z = peel_to_Z(ct, K5)
    return InvMC_bytes(InvSB_bytes(InvSR_bytes(xor_block(z, K4p))))


def peel_to_S2(ct: bytes, K5: bytes, K4p: bytes, K3p: bytes) -> bytes:
    v = peel_to_V(ct, K5, K4p)
    return InvSB_bytes(InvSR_bytes(xor_block(v, K3p)))


def make_lambda_set(oracle, K0: bytes, active_pos: int = 0, base: Optional[bytes] = None) -> List[bytes]:
    if base is None:
        b = bytearray(os.urandom(16))
        b[active_pos] = 0
        base = bytes(b)
    out = []
    for val in range(256):
        A = bytearray(base)
        A[active_pos] = val
        pt = pt_from_A(bytes(A), K0)
        out.append(oracle.encrypt(pt))
    return out


def make_rectangle(oracle, K0: bytes, positions: Tuple[int, int], base: Optional[bytes] = None) -> List[bytes]:
    if base is None:
        b = bytearray(os.urandom(16))
        b[positions[0]] = 0
        b[positions[1]] = 0
        base = bytes(b)
    z1 = random.randrange(256)
    z2 = random.randrange(256)
    while z2 == z1:
        z2 = random.randrange(256)
    w1 = random.randrange(256)
    w2 = random.randrange(256)
    while w2 == w1:
        w2 = random.randrange(256)
    vals = [(z1, w1), (z2, w2), (z1, w2), (z2, w1)]
    out = []
    for a, b in vals:
        A = bytearray(base)
        A[positions[0]] = a
        A[positions[1]] = b
        pt = pt_from_A(bytes(A), K0)
        out.append(oracle.encrypt(pt))
    return out


def recover_byte_by_balance(value_sets: List[List[int]]) -> List[int]:
    good = set(range(256))
    for values in value_sets:
        cur = set()
        for k in range(256):
            x = 0
            for v in values:
                x ^= INV_SBOX[v ^ k]
            if x == 0:
                cur.add(k)
        good &= cur
    return sorted(good)


def recover_k5(oracle, K0: bytes) -> bytes:
    sets = [make_lambda_set(oracle, K0, 0), make_lambda_set(oracle, K0, 0)]
    out = bytearray(16)
    for j in range(16):
        values = [[ct[j] for ct in cts] for cts in sets]
        cand = recover_byte_by_balance(values)
        if len(cand) != 1:
            # add a third set only if needed
            sets.append(make_lambda_set(oracle, K0, 0))
            values = [[ct[j] for ct in cts] for cts in sets]
            cand = recover_byte_by_balance(values)
        if len(cand) != 1:
            raise RetryThisConnection(f'failed to recover K5 byte {j}: {cand}')
        out[j] = cand[0]
    return bytes(out)


def recover_k4p(oracle, K0: bytes, K5: bytes) -> bytes:
    rects = [make_rectangle(oracle, K0, (idx(0, 0), idx(1, 0))) for _ in range(2)]
    out = bytearray(16)
    for j in range(16):
        values = [[peel_to_Z(ct, K5)[j] for ct in rect] for rect in rects]
        cand = recover_byte_by_balance(values)
        if len(cand) != 1:
            rects.append(make_rectangle(oracle, K0, (idx(0, 0), idx(1, 0))))
            values = [[peel_to_Z(ct, K5)[j] for ct in rect] for rect in rects]
            cand = recover_byte_by_balance(values)
        if len(cand) != 1:
            raise RetryThisConnection(f'failed to recover K4p byte {j}: {cand}')
        out[j] = cand[0]
    return bytes(out)


def recover_k3p(oracle, K0: bytes, K5: bytes, K4p: bytes) -> bytes:
    out = bytearray(16)
    for q in range(4):
        positions = (idx(0, q), idx(1, (q + 1) % 4))
        rects = [make_rectangle(oracle, K0, positions) for _ in range(2)]
        for j in sr_positions_of_column(q):
            values = [[peel_to_V(ct, K5, K4p)[j] for ct in rect] for rect in rects]
            cand = recover_byte_by_balance(values)
            if len(cand) != 1:
                rects.append(make_rectangle(oracle, K0, positions))
                values = [[peel_to_V(ct, K5, K4p)[j] for ct in rect] for rect in rects]
                cand = recover_byte_by_balance(values)
            if len(cand) != 1:
                raise RetryThisConnection(f'failed to recover K3p byte {j}: {cand}')
            out[j] = cand[0]
    return bytes(out)


def recover_k1_k2(oracle, K0: bytes, K5: bytes, K4p: bytes, K3p: bytes) -> Tuple[bytes, bytes]:
    cands = [set(range(256)) for _ in range(16)]
    saved = None
    for _ in range(4):
        Aa = os.urandom(16)
        Ab = os.urandom(16)
        Pa = pt_from_A(Aa, K0)
        Pb = pt_from_A(Ab, K0)
        Ca = oracle.encrypt(Pa)
        Cb = oracle.encrypt(Pb)
        S2a = peel_to_S2(Ca, K5, K4p, K3p)
        S2b = peel_to_S2(Cb, K5, K4p, K3p)
        delta = InvSR_bytes(InvMC_bytes(xor_block(S2a, S2b)))
        for j in range(16):
            cur = set(k for k in range(256) if (SBOX[Aa[j] ^ k] ^ SBOX[Ab[j] ^ k]) == delta[j])
            cands[j] &= cur
        if saved is None:
            saved = (Aa, S2a)
    if any(len(s) != 1 for s in cands):
        raise RetryThisConnection('failed to recover K1')
    K1 = bytes(next(iter(s)) for s in cands)
    assert saved is not None
    Aa, S2a = saved
    K2 = xor_block(S2a, MC_bytes(SR_bytes(SB_bytes(xor_block(Aa, K1)))))
    return K1, K2


def recover_all_keys(oracle) -> List[bytes]:
    K0 = recover_k0(oracle)
    K5 = recover_k5(oracle, K0)
    K4p = recover_k4p(oracle, K0, K5)
    K3p = recover_k3p(oracle, K0, K5, K4p)
    K1, K2 = recover_k1_k2(oracle, K0, K5, K4p, K3p)
    K3 = MC_bytes(K3p)
    K4 = MC_bytes(K4p)
    return [K0, K1, K2, K3, K4, K5]


# ---------- self-test helpers ----------


def load_local_module(path: str):
    import importlib.util, types
    spec = importlib.util.spec_from_file_location('aes5mod', path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules['flag'] = types.SimpleNamespace(flag='dummy')
    spec.loader.exec_module(mod)
    return mod


# ---------- interactive menu oracles ----------

class BufferedTransport:
    def __init__(self):
        self.buf = bytearray()
    def _recv_some(self) -> bytes:
        raise NotImplementedError
    def _send_all(self, data: bytes) -> None:
        raise NotImplementedError
    def close(self) -> None:
        pass
    def sendline(self, data: bytes) -> None:
        self._send_all(data + b'\n')
    def recvuntil(self, token: bytes) -> bytes:
        while True:
            idx = self.buf.find(token)
            if idx != -1:
                end = idx + len(token)
                out = bytes(self.buf[:end])
                del self.buf[:end]
                return out
            chunk = self._recv_some()
            if not chunk:
                raise EOFError('connection closed while waiting for token')
            self.buf.extend(chunk)
    def recvline(self) -> bytes:
        while True:
            idx = self.buf.find(b'\n')
            if idx != -1:
                end = idx + 1
                out = bytes(self.buf[:end])
                del self.buf[:end]
                return out
            chunk = self._recv_some()
            if not chunk:
                if self.buf:
                    out = bytes(self.buf)
                    self.buf.clear()
                    return out
                raise EOFError('connection closed while waiting for line')
            self.buf.extend(chunk)


class SocketTransport(BufferedTransport):
    def __init__(self, host: str, port: int, timeout: float = 5.0):
        super().__init__()
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
    def _recv_some(self) -> bytes:
        return self.sock.recv(4096)
    def _send_all(self, data: bytes) -> None:
        self.sock.sendall(data)
    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


class ProcessTransport(BufferedTransport):
    def __init__(self, argv: List[str], cwd: Optional[str] = None, env: Optional[dict] = None):
        super().__init__()
        self.proc = subprocess.Popen(
            argv,
            cwd=cwd,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
        )
        assert self.proc.stdin is not None and self.proc.stdout is not None
        self.stdin = self.proc.stdin
        self.stdout_fd = self.proc.stdout.fileno()
    def _recv_some(self) -> bytes:
        return os.read(self.stdout_fd, 4096)
    def _send_all(self, data: bytes) -> None:
        self.stdin.write(data)
        self.stdin.flush()
    def close(self) -> None:
        try:
            self.proc.kill()
        except Exception:
            pass


class MenuOracle:
    def __init__(self, transport: BufferedTransport, max_queries: int = 4096):
        self.t = transport
        self.max_queries = max_queries
        self.queries = 0
        self.t.recvuntil(b'> ')
    def close(self) -> None:
        self.t.close()
    def remaining(self) -> int:
        return self.max_queries - self.queries
    def _query(self, choice: bytes, prompt: bytes, block: bytes) -> bytes:
        if self.queries >= self.max_queries:
            raise RetryThisConnection('query budget exhausted')
        self.t.sendline(choice)
        self.t.recvuntil(prompt)
        self.t.sendline(block.hex().encode())
        line = self.t.recvline().strip()
        self.queries += 1
        # the service returns to the menu prompt even on errors
        try:
            self.t.recvuntil(b'> ')
        except EOFError:
            pass
        if len(line) != 32:
            raise RetryThisConnection(f'unexpected oracle response: {line!r}')
        try:
            return bytes.fromhex(line.decode())
        except ValueError as exc:
            raise RetryThisConnection(f'non-hex oracle response: {line!r}') from exc
    def encrypt(self, pt: bytes) -> bytes:
        return self._query(b'1', b'pt> ', pt)
    def decrypt(self, ct: bytes) -> bytes:
        return self._query(b'2', b'ct> ', ct)
    def submit(self, keys: List[bytes]) -> str:
        self.t.sendline(b'3')
        self.t.recvuntil(b'k0> ')
        for i, key in enumerate(keys):
            self.t.sendline(key.hex().encode())
            if i < 5:
                self.t.recvuntil(f'k{i+1}> '.encode())
        verdict = self.t.recvline().decode(errors='replace').strip()
        return verdict


# ---------- self-tests and CLI ----------

def test_direct(trials: int = 1) -> None:
    mod = load_local_module('/mnt/data/extracted/aes5.py')
    success = 0
    for t in range(trials):
        rk = mod.generate_random_round_keys()
        oracle = DirectOracle(rk, mod)
        try:
            got = recover_all_keys(oracle)
            ok = got == rk
            success += int(ok)
            print(f'trial {t}: ok={ok} queries={oracle.queries}')
        except RetryThisConnection as exc:
            print(f'trial {t}: retry {exc} queries={oracle.queries}')
        finally:
            pass
    print(f'successes: {success}/{trials}')


def test_process_once() -> None:
    workdir = tempfile.mkdtemp(prefix='aes5local-')
    src = '/mnt/data/extracted/aes5.py'
    with open(src, 'rb') as fsrc, open(os.path.join(workdir, 'aes5.py'), 'wb') as fdst:
        fdst.write(fsrc.read())
    with open(os.path.join(workdir, 'flag.py'), 'w', encoding='utf-8') as f:
        f.write("flag='codegate2026{dummy-local-flag}'\n")
    oracle = MenuOracle(ProcessTransport([sys.executable, 'aes5.py'], cwd=workdir))
    try:
        keys = recover_all_keys(oracle)
        verdict = oracle.submit(keys)
        print('queries=', oracle.queries)
        print('verdict=', verdict)
    finally:
        oracle.close()


def solve_endpoint(host: str, port: int, attempts: int) -> bool:
    for attempt in range(1, attempts + 1):
        oracle = None
        try:
            print(f'[*] connecting to {host}:{port} (attempt {attempt}/{attempts})', file=sys.stderr, flush=True)
            oracle = MenuOracle(SocketTransport(host, port, timeout=5.0))
            keys = recover_all_keys(oracle)
            print(f'[*] recovered keys using {oracle.queries} queries, submitting...', file=sys.stderr, flush=True)
            verdict = oracle.submit(keys)
            print(verdict)
            return 'codegate2026{' in verdict
        except RetryThisConnection as exc:
            q = oracle.queries if oracle is not None else 'n/a'
            print(f'[!] restarting connection: {exc} (queries used: {q})', file=sys.stderr, flush=True)
        except (OSError, EOFError, socket.timeout) as exc:
            print(f'[!] connection error on {host}:{port}: {exc}', file=sys.stderr, flush=True)
        finally:
            if oracle is not None:
                oracle.close()
    return False


def main() -> None:
    ap = argparse.ArgumentParser(description='Best-effort solver for Codegate 2026 aes5')
    ap.add_argument('--test-direct', type=int, default=0, help='run direct local tests with random keys')
    ap.add_argument('--test-process', action='store_true', help='run one end-to-end test against a local subprocess')
    ap.add_argument('--host', default=None)
    ap.add_argument('--port', type=int, default=13337)
    ap.add_argument('--attempts', type=int, default=4, help='reconnects per endpoint')
    args = ap.parse_args()

    if args.test_direct:
        test_direct(args.test_direct)
        return
    if args.test_process:
        test_process_once()
        return

    endpoints: List[Tuple[str, int]]
    if args.host:
        endpoints = [(args.host, args.port)]
    else:
        endpoints = [
            ('54.181.1.253', 13337),
            ('3.38.204.195', 13337),
            ('15.164.176.103', 13337),
        ]
    for host, port in endpoints:
        if solve_endpoint(host, port, args.attempts):
            return
    raise SystemExit('all attempts failed')


if __name__ == '__main__':
    main()

# codegate2026{236895be4f699013c404340174ceb3d8}