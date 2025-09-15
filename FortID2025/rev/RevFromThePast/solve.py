# solve_rev_from_the_past.py
# Python 3.x – không cần thư viện ngoài
# Đọc CHAL.COM, tái tạo S-box, đảo XLAT và in ra flag.

from pathlib import Path

def build_sbox(seed):
    # khởi tạo S = [0..255], rồi Fisher-Yates với PRNG LFSR(poly 0xB400)
    S = list(range(256))
    state = seed & 0xFFFF
    for i in range(0xFF, -1, -1):
        lsb = state & 1
        state = (state >> 1) & 0xFFFF
        if lsb:
            state ^= 0xB400
        j = state % (i + 1)
        S[i], S[j] = S[j], S[i]
    return S

def invert_box(S):
    inv = [0]*256
    for i, v in enumerate(S):
        inv[v] = i
    return inv

def solve(path="CHAL.COM"):
    data = Path(path).read_bytes()

    # mapping file <-> memory: COM load tại 0x100
    # seed ở DS:0x0254 => file offset = 0x0254 - 0x100 = 0x0154
    seed = int.from_bytes(data[0x0154:0x0156], "little")  # 0xB4C1 trong file
    sbox = build_sbox(seed)
    inv = invert_box(sbox)

    # ciphertext tại DS:0x037e => file offset = 0x037e - 0x100 = 0x027e
    ct = data[0x027e:0x027e + 0x21]
    xor_const = (seed & 0xFF) ^ 0xA5  # BL = AL ^ 0xA5

    pt_bytes = bytes(inv[b ^ xor_const] for b in ct)
    flag = "FortID{" + pt_bytes.decode("ascii") + "}"
    return flag

if __name__ == "__main__":
    print(solve("CHAL.COM"))

# Flag: FortID{N0w_S4v3_S3t71ng5_4nd_L4unch_D00M}