#!/usr/bin/env python3
import argparse
import gzip
import re
import socket
import ssl
from pathlib import Path

BLOCK_SIZE = 582


def rol8(x: int, k: int) -> int:
    k &= 7
    return ((x << k) | (x >> (8 - k))) & 0xFF if k else x & 0xFF


def ror8(x: int, k: int) -> int:
    k &= 7
    return ((x >> k) | (x << (8 - k))) & 0xFF if k else x & 0xFF


def load_code(path: str) -> bytes:
    p = Path(path)
    data = p.read_bytes()
    if p.suffix == ".gz":
        data = gzip.decompress(data)
    return data


def extract_rounds(code: bytes):
    if len(code) < 1 or code[-1] != 0x60:
        raise ValueError("expected final RTS byte (0x60) at end of code")
    if (len(code) - 1) % BLOCK_SIZE != 0:
        raise ValueError("unexpected code size")

    rounds = []
    for i in range((len(code) - 1) // BLOCK_SIZE):
        b = code[i * BLOCK_SIZE : (i + 1) * BLOCK_SIZE]
        rounds.append(
            (
                b[3],             # add0
                (-b[38]) & 7,     # rot1
                b[167],           # xor1
                b[232],           # add2
                (-b[263]) & 7,    # rot2
                b[396],           # xor2
                (-b[451]) & 7,    # rot3
                b[580],           # xor3
            )
        )
    return rounds


def forward(rounds, A: int, X: int, Y: int):
    for add0, k1, c1, c2, k2, c3, k3, c4 in rounds:
        s = (A + X + add0) & 0xFF
        rs = rol8(s, k2)
        rx = rol8(X, k1)
        t = (Y ^ rx ^ c1)
        t = (t + s + c2) & 0xFF
        Y = rol8(t, k3)
        X = rx ^ rs ^ c3
        A = rs ^ Y ^ c4
    return A, X, Y


def inverse(rounds, A: int, X: int, Y: int):
    for add0, k1, c1, c2, k2, c3, k3, c4 in reversed(rounds):
        t = ror8(Y, k3)
        rs = A ^ Y ^ c4
        s = ror8(rs, k2)
        rx = X ^ rs ^ c3
        X = ror8(rx, k1)
        A = (s - X - add0) & 0xFF
        Y = ((t - s - c2) & 0xFF) ^ rx ^ c1
    return A, X, Y


def recv_until(sock, marker: bytes) -> bytes:
    buf = b""
    while marker not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf


def solve_remote(host: str, port: int, rounds, timeout: float = 10.0):
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as sock:
            banner = recv_until(sock, b"> ")
            print(banner.decode(errors="replace"), end="")
            sock.sendall(b"R\n")

            data = recv_until(sock, b"Now tell me all 20 inputs:")
            text = data.decode(errors="replace")
            print(text, end="")

            triples = re.findall(r"Final output #(\d+): A=(\d+) X=(\d+) Y=(\d+)", text)
            if len(triples) != 20:
                raise RuntimeError(f"expected 20 output triples, got {len(triples)}")

            answers = []
            for _, a, x, y in triples:
                ai, xi, yi = inverse(rounds, int(a), int(x), int(y))
                answers.append((ai, xi, yi))

            for i, (a, x, y) in enumerate(answers, 1):
                line = f"{a},{x},{y}\n"
                print(f"[+] sending input #{i}: {line.strip()}")
                sock.sendall(line.encode())

            rest = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                rest += chunk
            print(rest.decode(errors="replace"), end="")


def main():
    ap = argparse.ArgumentParser(description="Solver for Favorite Potato")
    ap.add_argument("--code", default="code.bin.gz", help="path to code.bin or code.bin.gz")
    ap.add_argument("--host", default="favorite-potato.opus4-7.b01le.rs")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--check", nargs=3, type=int, metavar=("A", "X", "Y"), help="run forward locally")
    ap.add_argument("--invert", nargs=3, type=int, metavar=("A", "X", "Y"), help="invert locally")
    ap.add_argument("--remote", action="store_true", help="connect to remote service and solve it")
    args = ap.parse_args()

    code = load_code(args.code)
    rounds = extract_rounds(code)
    print(f"[*] loaded {len(rounds)} rounds")

    if args.check is not None:
        a, x, y = args.check
        print(forward(rounds, a, x, y))
    if args.invert is not None:
        a, x, y = args.invert
        print(inverse(rounds, a, x, y))
    if args.remote:
        solve_remote(args.host, args.port, rounds)


if __name__ == "__main__":
    main()

# bctf{Nev3r_underst00d_why_we_n33d_TSX_and_TXS_unt1l_n0w..:D}