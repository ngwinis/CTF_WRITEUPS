#!/usr/bin/env python3
import argparse
from collections import deque

# ===== Constants (từ binary) =====
RODATA_MAP_OFF = 0x2020
MAP_LEN = 100
TARGET_HASH = 0x86BA520C
H_INIT = 0xDEADBEEF

# (dx, dy, seed_out, seed_in, valid)
DIR_SEEDS = {
    "N": (-1, 0, 0xA2, 0xA7, 1),
    "S": ( 1, 0, 0x8C, 0x89, 1),
    "E": ( 0, 1, 0xE9, 0xE3, 1),
    "W": ( 0,-1, 0x69, 0x63, 1),
}

def key_i(i: int) -> int:
    # (i*31 + 0x11) ^ (i<<3) ^ 0xFFFFFFA5
    return ((i * 31 + 0x11) ^ (i << 3) ^ 0xFFFFFFA5) & 0xFFFFFFFF

def decode_map(elf: bytes) -> list[int]:
    enc = elf[RODATA_MAP_OFF:RODATA_MAP_OFF + MAP_LEN]
    if len(enc) != MAP_LEN:
        raise ValueError("Map bytes not found (wrong offset / truncated file).")
    return [(enc[i] ^ (key_i(i) & 0xFF)) & 0xFF for i in range(MAP_LEN)]

def dir_masks(ch: str) -> tuple[int, int, int, int]:
    dx, dy, seed0, seed1, valid = DIR_SEEDS[ch]
    if not valid:
        raise ValueError("Invalid direction.")
    t = (ord(ch) * 0x6B) & 0xFF
    out_mask = (seed0 ^ t ^ 0x3C) & 0xFF
    in_mask  = (seed1 ^ t ^ 0x3C) & 0xFF
    return dx, dy, out_mask, in_mask

DIRS = {ch: dir_masks(ch) for ch in "NSEW"}

def rol32(v: int, r: int) -> int:
    v &= 0xFFFFFFFF
    return ((v << r) | (v >> (32 - r))) & 0xFFFFFFFF

def hash_update(h: int, ch: str) -> int:
    h ^= ord(ch)
    h = rol32(h, 13)
    h = (h * 0x045D9F3B) & 0xFFFFFFFF
    return h

def hash_finalize(h: int) -> int:
    h ^= (h >> 16)
    h = (h * 0x85EBCA6B) & 0xFFFFFFFF
    h ^= (h >> 13)
    return h & 0xFFFFFFFF

def can_move(grid: list[int], pos: int, ch: str) -> int | None:
    x, y = divmod(pos, 10)
    dx, dy, out_mask, in_mask = DIRS[ch]
    nx, ny = x + dx, y + dy
    if nx < 0 or nx > 9 or ny < 0 or ny > 9:
        return None
    npos = nx * 10 + ny
    if ((grid[pos] & out_mask) | (grid[npos] & in_mask)) == 0:
        return None
    return npos

def bfs_shortest_path(grid: list[int]) -> str:
    start, goal = 0, 99
    prev = [-1] * 100
    prev_ch = ["\0"] * 100

    q = deque([start])
    prev[start] = start

    while q:
        u = q.popleft()
        if u == goal:
            break
        for ch in "NSEW":
            v = can_move(grid, u, ch)
            if v is None:
                continue
            if prev[v] != -1:
                continue
            prev[v] = u
            prev_ch[v] = ch
            q.append(v)

    if prev[goal] == -1:
        raise RuntimeError("No path from start to goal.")

    # reconstruct
    path = []
    cur = goal
    while cur != start:
        path.append(prev_ch[cur])
        cur = prev[cur]
    path.reverse()
    return "".join(path)

def rle_encode(s: str) -> str:
    out = []
    i = 0
    n = len(s)
    while i < n:
        j = i + 1
        while j < n and s[j] == s[i]:
            j += 1
        run = j - i
        if run > 1:
            out.append(str(run))
        out.append(s[i])
        i = j
    return "".join(out)

def main():
    ap = argparse.ArgumentParser(description="Solve pathfinder (optimized)")
    ap.add_argument("bin", nargs="?", default="./pathfinder", help="path to ELF")
    args = ap.parse_args()

    elf = open(args.bin, "rb").read()
    grid = decode_map(elf)

    path = bfs_shortest_path(grid)

    # Verify hash y hệt binary
    h = H_INIT
    for ch in path:
        h = hash_update(h, ch)
    if hash_finalize(h) != TARGET_HASH:
        raise RuntimeError("Path reaches goal but hash mismatch (would need extended search).")

    flag = f"EHAX{{{rle_encode(path)}}}"
    print("[*] PATH:", path)
    print("[*] FLAG:", flag)

if __name__ == "__main__":
    main()