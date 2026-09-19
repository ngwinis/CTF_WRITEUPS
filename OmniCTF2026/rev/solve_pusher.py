#!/usr/bin/env python3
import argparse
import socket
import ssl
import subprocess
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TARGET = "OMNICTF{G3T_R3A1_0N_R3M0TE_B0z0_TH1S_1S_NOT_A_HAND0UT}"
DUMMY = "X"


def push(seq: list[str], ch: str) -> None:
    seq.extend(["1", ch])


def pop(seq: list[str]) -> None:
    seq.append("2")


def full_cycle(seq: list[str], kept: str) -> None:
    """Run one DFS-like cycle; only `kept` remains on the stack afterward."""
    for _ in range(3):
        push(seq, DUMMY)
        pop(seq)

    push(seq, kept)

    for _ in range(3):
        push(seq, DUMMY)
        pop(seq)

    for _ in range(3):
        push(seq, DUMMY)

    for _ in range(3):
        pop(seq)


def final_cycle(seq: list[str], tail4: str) -> None:
    """Stop at the transient depth where the compared buffer equals target."""
    assert len(tail4) == 4
    for _ in range(3):
        push(seq, DUMMY)
        pop(seq)

    push(seq, tail4[0])

    push(seq, DUMMY)
    pop(seq)
    push(seq, DUMMY)
    pop(seq)
    push(seq, DUMMY)
    pop(seq)

    push(seq, tail4[1])
    push(seq, tail4[2])
    push(seq, tail4[3])


def build_payload(target: str = TARGET) -> str:
    if len(target) < 4:
        raise ValueError("target must be at least 4 bytes")

    seq: list[str] = []
    for ch in target[:-4]:
        full_cycle(seq, ch)
    final_cycle(seq, target[-4:])
    return "\n".join(seq) + "\n"


def run_local(payload: bytes, flag_text: str | None) -> bytes:
    run_dir = ROOT / "work" / "outputs" / "local_run"
    run_dir.mkdir(parents=True, exist_ok=True)
    if flag_text is not None:
        (run_dir / "flag.txt").write_text(flag_text + "\n", encoding="ascii")

    proc = subprocess.run(
        [
            "qemu-i386",
            "-L",
            str((ROOT / "work" / "dumps" / "i386-rootfs").resolve()),
            str((ROOT / "work" / "evidence" / "challenge").resolve()),
        ],
        cwd=run_dir,
        input=payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=90,
    )
    return proc.stdout


def run_remote(payload: bytes, host: str, port: int, timeout: float, use_ssl: bool, send_delay: float) -> bytes:
    with socket.create_connection((host, port), timeout=timeout) as raw:
        if use_ssl:
            ctx = ssl.create_default_context()
            s = ctx.wrap_socket(raw, server_hostname=host)
        else:
            s = raw
        s.settimeout(timeout)
        if send_delay:
            for line in payload.splitlines(keepends=True):
                s.sendall(line)
                time.sleep(send_delay)
        else:
            s.sendall(payload)
        chunks = []
        while True:
            try:
                data = s.recv(4096)
            except socket.timeout:
                break
            if not data:
                break
            chunks.append(data)
        s.close()
    return b"".join(chunks)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default=TARGET)
    ap.add_argument("--out", default="work/outputs/pusher_payload.txt")
    ap.add_argument("--local", action="store_true", help="Run local qemu validation")
    ap.add_argument("--flag-text", default="OMNICTF{LOCAL_VALIDATION_FLAG}")
    ap.add_argument("--host")
    ap.add_argument("--port", type=int)
    ap.add_argument("--ssl", action="store_true", help="Use TLS, equivalent to ncat --ssl")
    ap.add_argument("--send-delay", type=float, default=0.0, help="Delay between sent lines")
    ap.add_argument("--timeout", type=float, default=30.0)
    args = ap.parse_args()

    payload = build_payload(args.target).encode("ascii")
    out = ROOT / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(payload)
    print(f"wrote {out} ({len(payload.splitlines())} input lines)")

    if args.local:
        data = run_local(payload, args.flag_text)
        local_out = ROOT / "work" / "outputs" / "local_validation_output.txt"
        local_out.write_bytes(data)
        print(data.decode("latin1", errors="replace")[-500:])
        print(f"wrote {local_out}")

    if args.host and args.port:
        data = run_remote(payload, args.host, args.port, args.timeout, args.ssl, args.send_delay)
        print(data.decode("latin1", errors="replace"))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
