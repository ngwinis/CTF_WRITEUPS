# Free Candy

## [1] TỔNG QUAN
- Đề bài:



## [2] PHÂN TÍCH
Trên server:

- Mỗi vé "free ticket" có `ticket_id = RNG.gen()` và được ký ECDSA bởi server. 
- ECDSA signer cũng lấy nonce `k` từ cùng một RNG (nhưng là một bản copy) rồi `k := RNG.gen()` mỗi khi ký. 
- Hai RNG này được tạo bằng `rng_ticket = RNG(n)` và `rng_signer = copy(rng_ticket)`, sau đó seed riêng rẽ — nghĩa là chúng dùng cùng tham số ẩn `q` nhưng khác seed ban đầu. 
- Khi nhận một ticket chẵn, server lập tức "tặng thêm ticket mới" (tức lại gọi `fresh()` → lại phát `ticket_id` mới → lại ký). Cứ chẵn là lại có ticket tiếp, nên ta có thể xâu chuỗi 4 ticket liên tiếp nếu may mắn ra chẵn 3 lần liền.
- Server sẽ đưa flag nếu `ticket_id == sha256("I'd like the flag please")` (giải thích vì sao ta forge đúng id này). 
- Bên verify là ECDSA chuẩn: `w=s**(-1)`, `V=u1*G + u2*Q`, so sánh `x(V) mod n == r`.

Điểm yếu toán học: RNG → tuyến tính bậc 2

RNG tạo ra

	retn =−1/2 * Trred(i*(q**n))

với q trong quaternion algebra `H(Fn; -1, -1)`

"Reduced trace" của quaternion thực chất là hai lần phần thực (nên công thức trên là một ánh xạ tuyến tính).

Vì −1 là bình phương bậc hai khi `n≡1(mod4)` (đúng với order của secp256k1), quaternion algebra ở đây "tách" và có biểu diễn ma trận 2×2. Khi đó q thỏa định lý Cayley–Hamilton bậc 2, nên mọi chuỗi dạng f(q**t) với f tuyến tính sẽ tuân theo hệ thức truy hồi bậc 2:

	a[t+2] = T.a[t+1] - N.a[t]
	
trong đó T là "(reduced) trace" và N là "(reduced) norm". Tóm lại: output RNG là tuyến tính bậc 2 theo chỉ số t. 

Liên hệ hai RNG (cùng q, khác seed):<br>
Gọi x[t] là dãy `ticket_id` và y[t] là dãy nonce k dùng để ký ở cùng lượt phát ticket t. Cả hai dãy cùng obey cùng truy hồi bậc 2, chỉ khác dịch pha. Với truy hồi bậc 2, dịch pha cố định δ luôn cho ta:

	y[t] = A.x[t] + B.x[t+1]

trong đó A,B là hằng số (phụ thuộc δ, nhưng không phụ thuộc t). Đây là hệ quả trực tiếp từ việc biểu diễn dịch pha bằng lũy thừa ma trận đồng hành. (Nếu đã từng chơi Chebyshev / companion matrix, bạn sẽ thấy quen.)

Bẻ khóa ECDSA bằng 3 chữ ký liên tiếp:

Với ECDSA: `st​≡kt−1​(zt​+rt​d)(modn)⇒zt​+rt​d≡st​kt​(modn)`. Mà `kt​=Axt​+Bxt+1​`. Thế vào được 3 phương trình tuyến tính theo 3 ẩn `rt​d−st​xt​A−st​xt+1​B≡−zt​(modn),t=0,1,2`.

Chỉ cần 4 vé liên tiếp (để biết x0​,x1​,x2​,x3​), ta giải được d — private key của server. Script ở trên lấy 4 ticket bằng cách "claim nếu chẵn" cho tới khi đủ; xác suất có chuỗi 3 lần chẵn ~ 1/8, cứ reconnect là được. (Server phát vé mới đúng như code "even → brand new ticket"). 

Có d rồi thì ta ký offline bất cứ `ticket_id` nào — cụ thể là `sha256("I'd like the flag please")` — và nộp. Server verify ECDSA chuẩn, nên pass.

## [3] SOLVE
```python
from pwn import *
import json, re, hashlib, secrets

HOST = "0.cloud.chals.io"
PORT = 19521
context.log_level = "info"
TIMEOUT = 12.0

def modinv(a, n):
    return pow(a, -1, n)

def sha256_int(m: bytes) -> int:
    return int.from_bytes(hashlib.sha256(m).digest(), "big")

P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
A  = 0
B  = 7
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G  = (Gx, Gy)
O  = (None, None)

def is_inf(Pt): return Pt[0] is None
def ec_inv(Pt):  return Pt if is_inf(Pt) else (Pt[0], (-Pt[1]) % P)

def ec_add(P1, P2):
    if is_inf(P1): return P2
    if is_inf(P2): return P1
    x1, y1 = P1; x2, y2 = P2
    if x1 == x2 and (y1 + y2) % P == 0: return O
    if P1 == P2:
        lam = ((3 * x1 * x1 + A) * modinv(2 * y1 % P, P)) % P
    else:
        lam = ((y2 - y1) * modinv((x2 - x1) % P, P)) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)

def ec_mul(k, Pt):
    if k % N == 0 or is_inf(Pt): return O
    if k < 0: return ec_mul(-k, ec_inv(Pt))
    res, add = O, Pt
    while k:
        if k & 1: res = ec_add(res, add)
        add = ec_add(add, add)
        k >>= 1
    return res

def ecdsa_sign(d, msg_bytes, k=None):
    z = sha256_int(msg_bytes) % N
    while True:
        k = k or (secrets.randbelow(N-1) + 1)
        R = ec_mul(k, G)
        r = R[0] % N
        if r == 0: k = None; continue
        s = (modinv(k, N) * (z + r * d)) % N
        if s == 0: k = None; continue
        return r, s

MENU_MARKERS = [b"Choose an action:", b"1) Get a free ticket", b"Claim your prize"]
B64_RE = re.compile(rb"[A-Za-z0-9+/=]{40,}")

def recv_until_any(io, markers, timeout=TIMEOUT):
    """Đọc đến khi gặp 1 trong các marker (nới timeout rộng)."""
    buf = b""
    while True:
        chunk = io.recv(4096, timeout=timeout)
        if not chunk:
            break
        buf += chunk
        if any(m in buf for m in markers):
            break
    return buf

def get_menu(io):
    recv_until_any(io, MENU_MARKERS, timeout=TIMEOUT)

def collect_last_b64(buf: bytes):
    matches = B64_RE.findall(buf)
    return matches[-1].decode() if matches else None

def sendline(io, s: str):
    io.sendline(s.encode())

def get_free_ticket(io) -> str:
    sendline(io, "1")
    buf = recv_until_any(io, MENU_MARKERS, timeout=TIMEOUT)
    b64 = collect_last_b64(buf)
    if not b64:
        log.error("Không tìm thấy base64 ticket trong output:\n%s", buf.decode(errors="ignore"))
        raise EOFError("no ticket")
    return b64

def claim(io, ticket_b64: str):
    sendline(io, "2")
    io.recvuntil(b"Enter your ticket", timeout=TIMEOUT)
    sendline(io, ticket_b64)
    buf = recv_until_any(io, MENU_MARKERS + [b"You won a brand new ticket:"], timeout=TIMEOUT)
    nxt = collect_last_b64(buf)
    return buf.decode(errors="ignore"), nxt

def parse_ticket(b64):
    raw = base64.b64decode(b64)
    obj = json.loads(raw.decode())
    tid = int(obj["payload"]["ticket_id"])
    sig = bytes.fromhex(obj["signature"])
    r = int.from_bytes(sig[:32], "big") % N
    s = int.from_bytes(sig[32:], "big") % N
    msg = json.dumps({"ticket_id": tid}, separators=(',', ':'), sort_keys=True).encode()
    z = sha256_int(msg) % N
    return {"b64": b64, "tid": tid % N, "r": r, "s": s, "z": z, "msg": msg}

def solve_three_equations(rows):
    M = [[0]*4 for _ in range(3)]
    for i, (r, s, xt, xt1, z) in enumerate(rows):
        M[i][0] = r % N
        M[i][1] = (-s * xt) % N
        M[i][2] = (-s * xt1) % N
        M[i][3] = (-z) % N
    m = 3
    for col in range(m):
        pivot = None
        for r in range(col, m):
            if M[r][col] % N != 0:
                pivot = r; break
        if pivot is None:
            raise RuntimeError("Singular system; thử lại lần khác")
        if pivot != col:
            M[col], M[pivot] = M[pivot], M[col]
        inv = modinv(M[col][col] % N, N)
        for j in range(col, m+1):
            M[col][j] = (M[col][j] * inv) % N
        for r in range(m):
            if r == col: continue
            f = M[r][col] % N
            if f:
                for j in range(col, m+1):
                    M[r][j] = (M[r][j] - f * M[col][j]) % N
    d, Acoef, Bcoef = M[0][3] % N, M[1][3] % N, M[2][3] % N
    return d, Acoef, Bcoef

def forge_ticket(d, target_tid: int) -> str:
    msg = json.dumps({"ticket_id": int(target_tid)}, separators=(',', ':'), sort_keys=True).encode()
    r, s = ecdsa_sign(d, msg)
    sig_hex = r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex()
    ticket = {"payload": {"ticket_id": int(target_tid)}, "signature": sig_hex}
    return base64.b64encode(json.dumps(ticket, separators=(',', ':'), sort_keys=True).encode()).decode()

def main():
    target_tid = sha256_int(b"I'd like the flag please")
    while True:
        try:
            io = remote(HOST, PORT, timeout=TIMEOUT)
            get_menu(io)

            tickets = []
            t0 = get_free_ticket(io)
            tickets.append(parse_ticket(t0))

            while len(tickets) < 4 and tickets[-1]["tid"] % 2 == 0:
                out, nxt = claim(io, tickets[-1]["b64"])
                if nxt:
                    tickets.append(parse_ticket(nxt))
                else:
                    break

            if len(tickets) < 4:
                io.close()
                log.info("Chưa đủ 4 vé liên tiếp (được %d). Thử lại ...", len(tickets))
                continue

            rows = []
            for i in range(3):
                rows.append((tickets[i]["r"], tickets[i]["s"],
                             tickets[i]["tid"], tickets[i+1]["tid"], tickets[i]["z"]))
            d, Acoef, Bcoef = solve_three_equations(rows)
            log.success(f"Khôi phục private key d = {hex(d)}")

            forged = forge_ticket(d, target_tid)
            out, _ = claim(io, forged)
            print(out)  # flag sẽ xuất hiện trong output
            io.close()
            break

        except EOFError:
            try: io.close()
            except: pass
            log.warning("EOF/timeout, reconnect...")
            continue

if __name__ == "__main__":
    import base64
    main()
```

> **Flag:** `FortID{W1nn3r_Winn3r_Ch1ck3n_D1nn3r_64277d4d7650896a}`