import struct
from pathlib import Path

blob = Path("bike").read_bytes()

# .data: file offset 0x3000, freqs ở VA 0x4020 => off 0x3020
freq_off = 0x3020
expected = blob[0x3420:0x3443]

entries = []
for i in range(128):
    ch = blob[freq_off + i*8]
    freq = struct.unpack_from("<f", blob, freq_off + i*8 + 4)[0]
    entries.append((ch, freq))

def f32(x):
    return struct.unpack("<f", struct.pack("<f", float(x)))[0]

class Node:
    def __init__(self, ch, freq, left=None, right=None):
        self.ch = ch
        self.freq = freq
        self.left = left
        self.right = right

def build(lo, hi):
    if lo == hi:
        ch, fr = entries[lo]
        return Node(ch, fr)

    # QUAN TRỌNG: binary cộng từ lo tới hi-1, không phải hi
    total = f32(0.0)
    i = lo
    while i < hi:
        total = f32(total + entries[i][1])
        i += 1

    acc = f32(0.0)
    split = lo
    i = lo
    while i <= hi:
        x = f32(acc + entries[i][1])
        half = f32(total / f32(2.0))
        if x > half:
            break
        acc = x
        split = i
        i += 1

    return Node(0, total, build(lo, split), build(split + 1, hi))

root = build(0, 127)

codes = {}
def dfs(node, path=""):
    if node.left is None and node.right is None:
        codes[node.ch] = path
        return
    dfs(node.left, path + "0")
    dfs(node.right, path + "1")

dfs(root)

bits = "".join(codes[b] for b in expected)

# thêm 2 bit cuối để đủ byte; chọn 01 để ra '}'
bits += "01"

flag = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))
print(flag.decode("latin1"))

# bctf{now_you_can_bike_around:)}