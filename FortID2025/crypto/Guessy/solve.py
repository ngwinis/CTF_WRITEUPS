#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import remote, context, log
from math import gcd

# ====== cấu hình ======
HOST = "0.cloud.chals.io"
PORT = 32957

# Bật mức log của pwntools:
#   "info"  : gọn gàng (mặc định ở đây)
#   "debug" : in toàn bộ dữ liệu gửi/nhận (siêu chi tiết)
context.log_level = "info"

# ====== tham số bài ======
DELTA = 0xD3ADC0DE      # server mã hoá (secret + DELTA) bằng Paillier
SECRET_MAX = 2048       # secret ∈ [0..2047]
Q = 7                   # có 7 câu hỏi

# ---------------- tiện ích nhỏ ----------------
def to_base3(x, digits=Q):
    """Trả về list 7 trits theo thứ tự little-endian: trit[0] cho câu #0."""
    t = []
    for _ in range(digits):
        t.append(x % 3)
        x //= 3
    return t

def parse_two_bigints(line):
    """Thử parse 1 dòng thành 2 big int; trả về tuple hoặc None."""
    s = line.strip()
    parts = s.split()
    if len(parts) != 2:
        return None
    try:
        a = int(parts[0], 10)
        b = int(parts[1], 10)
        return a, b
    except ValueError:
        return None

# ---------------- dựng 7 câu hỏi ----------------
def build_queries(n):
    """
    Tạo 7 dòng truy vấn theo mã hóa base-3.
    Mỗi dòng gồm 2 nửa (trái/phải) có số phần tử bằng nhau,
    trong cùng 1 dòng không trùng phần tử.
    """
    g = n + 1
    n2 = n * n

    log.info("Build queries với g = n+1, mod n^2 có %d bits", n2.bit_length())

    # Precompute x_s = g^(-(DELTA+s)) mod n^2 cho mọi s
    xs = []
    for s in range(SECRET_MAX):
        k = (- (DELTA + s)) % n     # lưu ý mod n
        x = pow(g, k, n2)
        xs.append((s, k, x))

    left = [[] for _ in range(Q)]
    right = [[] for _ in range(Q)]

    for s, k, x in xs:
        trits = to_base3(s, Q)      # 7 trits cho 7 câu
        for i, t in enumerate(trits):
            if t == 1:
                left[i].append(x)
            elif t == 2:
                right[i].append(x)
            # t == 0 -> không đưa vào câu i

    # Cân 2 nửa và chèn "rác" khác biệt để không trùng trong mỗi dòng
    queries = []
    junk_exp = 1  # dùng g^junk_exp (mod n) để sinh ciphertext rác
    for i in range(Q):
        L = left[i][:]
        R = right[i][:]

        used = set(L + R)  # theo giá trị ciphertext để tránh trùng trong dòng

        # Cân độ dài 2 nửa
        g = n + 1
        n2 = n * n
        while len(L) < len(R):
            junk = pow(g, junk_exp % n, n2)
            junk_exp += 1
            if junk in used:
                continue
            used.add(junk)
            L.append(junk)
        while len(R) < len(L):
            junk = pow(g, junk_exp % n, n2)
            junk_exp += 1
            if junk in used:
                continue
            used.add(junk)
            R.append(junk)

        line = L + R
        queries.append(line)

        # ---- LOG chi tiết cho từng câu hỏi ----
        # in vài phần tử mẫu để đỡ dài
        def preview(arr, k=3):
            show = [str(arr[j]) for j in range(min(k, len(arr)))]
            if len(arr) > k:
                show.append("...")
            return ", ".join(show)

        log.info(
            "[Q%d] left=%d, right=%d, total=%d | left: [%s] | right: [%s]",
            i, len(L), len(R), len(line), preview(L), preview(R)
        )

    return queries

# ---------------- giải 1 test ----------------
def solve_one_test(io):
    # Nhận tới khi thấy 'n = '
    io.recvuntil(b"n = ")
    n = int(io.recvline().strip())
    log.info("Nhận n (%d bits): %d", n.bit_length(), n)

    # Server in 'You can ask 7 questions:' -> sẵn sàng nhận 7 dòng
    io.recvuntil(b"You can ask 7 questions:")
    log.info("Server đã sẵn sàng nhận 7 câu hỏi.")

    queries = build_queries(n)

    # Gửi 7 dòng
    for i, line in enumerate(queries):
        payload = " ".join(str(v) for v in line)
        io.sendline(payload.encode())
        log.info("[SEND Q%d] %d phần tử (độ dài chuỗi: %d)", i, len(line), len(payload))

    # Nhận 7 cặp kết quả
    pairs = []
    while len(pairs) < Q:
        raw = io.recvline(timeout=10)
        if raw is None:
            log.failure("Timeout khi chờ cặp số thứ %d!", len(pairs))
            break
        s = raw.decode(errors="ignore").strip()
        got = parse_two_bigints(s)
        if got is None:
            log.debug("[SKIP] %s", s)
            continue
        pairs.append(got)
        log.info("[RECV %d] L=%s | R=%s", len(pairs)-1, got[0], got[1])

    if len(pairs) != Q:
        log.failure("Không nhận đủ 7 cặp! Nhận được: %d", len(pairs))
        return "bad"

    # Giải trits từ các cặp
    trits = []
    for i, (lval, rval) in enumerate(pairs):
        if lval == 0:
            trits.append(1)
            where = "LEFT"
        elif rval == 0:
            trits.append(2)
            where = "RIGHT"
        else:
            trits.append(0)
            where = "NONE"
        log.info("[PAIR %d] zero at: %s -> trit=%d", i, where, trits[-1])

    # Khôi phục s từ base-3 little-endian
    s = 0
    p = 1
    for t in trits:
        s += t * p
        p *= 3

    base3_str = "".join(str(t) for t in trits[::-1])  # big-endian để đọc cho đẹp
    log.success("Trits (big-endian) = %s  =>  secret s = %d", base3_str, s)

    # Trả lời
    io.recvuntil(b"Can you guess my secret?")
    io.sendline(str(s).encode())

    verdict = io.recvline(timeout=5)
    if verdict:
        verdict = verdict.decode().strip()
        if "Correct" in verdict or "correct" in verdict:
            log.success("Server: %s", verdict)
        else:
            log.warning("Server: %s", verdict)
    else:
        verdict = ""
        log.warning("Không nhận được verdict ngay sau khi trả lời.")

    return verdict

# ---------------- main ----------------
def main():
    log.info("Kết nối tới %s:%d ...", HOST, PORT)
    io = remote(HOST, PORT)

    # Theo mô tả, cần qua 10 test rồi mới in flag
    for t in range(10):
        log.info("====== Test #%d ======", t)
        verdict = solve_one_test(io)
        # không dừng, vì đôi khi server vẫn cho tiếp dù một test fail

    log.info("Đọc phần còn lại (có thể là flag) ...")
    # đọc đến khi server đóng kết nối
    try:
        while True:
            chunk = io.recvline(timeout=3)
            if not chunk:
                break
            s = chunk.decode(errors="ignore").rstrip()
            if s:
                print(s)
    except EOFError:
        pass

    log.info("Xong.")

if __name__ == "__main__":
    main()
