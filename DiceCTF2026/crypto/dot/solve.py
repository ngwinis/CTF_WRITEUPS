import re
import socket

from fastecdsa.curve import P256
from fastecdsa.point import Point
from fastecdsa.encoding.sec1 import SEC1Encoder

import snarg
from add import build_adder, int_to_bits

HOST = "dot.chals.dicec.tf"
PORT = 1337

TRACE_LEN = 636
BOUND1 = 2**8
B = TRACE_LEN * BOUND1 + 1  # 162817


def recv_until(sock: socket.socket, marker: bytes) -> bytes:
    buf = b""
    while marker not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise EOFError("connection closed")
        buf += chunk
    return buf


def recv_prompt(sock: socket.socket) -> tuple[int, int]:
    data = recv_until(sock, b"answer: ")
    text = data.decode()
    print(text, end="")
    m = re.search(r"what is (\d+) \+ (\d+)\? \(mod 2\^64\)", text)
    if not m:
        raise ValueError("cannot parse prompt")
    return int(m.group(1)), int(m.group(2))


def send_one(sock: socket.socket, c: int, h1: Point, h2: Point) -> str:
    proof_bytes = (
        SEC1Encoder.encode_public_key(h1, compressed=True)
        + SEC1Encoder.encode_public_key(h2, compressed=True)
    )

    sock.sendall(f"{c}\n".encode())
    recv_until(sock, b"proof: ")
    sock.sendall(proof_bytes.hex().encode() + b"\n")

    line = recv_until(sock, b"\n").decode().strip()
    return line


def honest_proof(a: int, b: int) -> tuple[int, Point, Point]:
    n = 64
    c = (a + b) % (1 << n)
    circuit = build_adder(n)
    inputs = int_to_bits(a, n) + int_to_bits(b, n) + int_to_bits(c, n)

    with open("crs.bin", "rb") as f:
        h1, h2 = snarg.prove(circuit, inputs, f)

    return c, h1, h2


def candidate_ks():
    # actual k support in vk table:
    # {-13179, ..., -1, 0, 1, ..., 13179, 13180}
    yield 0
    for i in range(1, 13180):
        yield i
        yield -i
    yield 13180


def delta_for_guess(x: int) -> int:
    # Prefer x -> x+1 when possible
    if x < 13180:
        return 1 + B * (2 * x + 1)
    # edge case x = 13180, step backwards to 13179
    return -1 + B * (-2 * x + 1)


def recover_k(sock: socket.socket, c: int, h1: Point, h2: Point) -> int:
    base = send_one(sock, c, h1, h2)
    print("[+] base reply:", base)

    tried = 0
    for x in candidate_ks():
        tried += 1
        if tried % 200 == 0:
            print(f"[+] tried {tried} guesses, current x={x}")

        m = delta_for_guess(x)
        h2x = h2 + m * P256.G
        line = send_one(sock, c, h1, h2x)

        if line.startswith("correct!"):
            print(f"[+] found k = {x}")
            return x

    raise RuntimeError("k not found")


def main():
    sock = socket.create_connection((HOST, PORT))
    sock.settimeout(20)

    a, b = recv_prompt(sock)

    c, h1, h2 = honest_proof(a, b)
    print(f"[+] correct answer = {c}")

    k = recover_k(sock, c, h1, h2)
    print(f"[+] recovered k = {k}")

    sock.close()


if __name__ == "__main__":
    main()