#!/usr/bin/env python3
import argparse
import os
import re
import subprocess
import sys
import time
from pathlib import Path


def eprint(msg: str) -> None:
    print(msg, file=sys.stderr)


def wait_for_file(path: Path, timeout: float = 10.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if path.exists() and path.stat().st_size > 0:
            return True
        time.sleep(0.05)
    return False


def solve_binary(solver: Path, binary: Path) -> str:
    proc = subprocess.run(
        [sys.executable, str(solver), str(binary)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if proc.stderr:
        sys.stderr.write(proc.stderr)
        sys.stderr.flush()
    if proc.returncode != 0:
        raise RuntimeError(f"solver failed with code {proc.returncode}")

    answer = proc.stdout.strip().splitlines()
    if not answer:
        raise RuntimeError("solver không in ra đáp án")
    ans = answer[-1].strip()
    if len(ans) != 64 or any(c not in "0123456789abcdef" for c in ans):
        raise RuntimeError(f"đáp án solver không hợp lệ: {ans!r}")
    return ans


def resolve_binary_path(raw_path: str | None, outdir: Path, prob_index: int | None) -> Path:
    if raw_path:
        p = Path(raw_path)
        if not p.is_absolute():
            p = (Path.cwd() / p).resolve()
        return p
    if prob_index is not None:
        return (outdir / f"prob{prob_index}.bin").resolve()
    raise RuntimeError("Không xác định được đường dẫn probX.bin")


def main() -> int:
    ap = argparse.ArgumentParser(description="Auto-solve OldSchool client")
    ap.add_argument("--server", default="16.184.16.74", help="host hoặc host:port cho ./client")
    ap.add_argument("--out", default=".", help="thư mục để client ghi probX.bin")
    ap.add_argument("--client", default="./client", help="đường dẫn client binary")
    ap.add_argument("--solver", default="./solve_oldschool.py", help="đường dẫn solve_oldschool.py")
    args = ap.parse_args()

    client = Path(args.client).resolve()
    solver = Path(args.solver).resolve()
    outdir = Path(args.out).resolve()
    outdir.mkdir(parents=True, exist_ok=True)

    if not client.exists():
        eprint(f"Không thấy client: {client}")
        return 1
    if not solver.exists():
        eprint(f"Không thấy solver: {solver}")
        return 1

    os.chmod(client, 0o755)

    cmd = [str(client), "-server", args.server, "-out", str(outdir)]
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0,
    )

    buf = ""
    current_hash = None
    current_path = None
    current_index = None

    try:
        while True:
            ch = proc.stdout.read(1)
            if not ch:
                break

            sys.stdout.buffer.write(ch)
            sys.stdout.buffer.flush()

            s = ch.decode("utf-8", errors="ignore")
            buf += s

            while "\n" in buf:
                line, buf = buf.split("\n", 1)
                m = re.search(r"prob_index=(\d+)", line)
                if m:
                    current_index = int(m.group(1))
                m = re.search(r"binary_hash=([0-9a-f]{64})", line)
                if m:
                    current_hash = m.group(1)
                m = re.search(r"binary_path=(.+)", line)
                if m:
                    current_path = m.group(1).strip()

            if buf.endswith("answer>"):
                try:
                    bin_path = resolve_binary_path(current_path, outdir, current_index)
                    if not wait_for_file(bin_path):
                        raise RuntimeError(f"prob binary chưa xuất hiện kịp: {bin_path}")

                    eprint(f"\n[auto] solving {bin_path.name} hash={current_hash or 'unknown'}")
                    answer = solve_binary(solver, bin_path)
                    eprint(f"[auto] answer = {answer}")

                    proc.stdin.write((answer + "\n").encode())
                    proc.stdin.flush()

                    buf = ""
                    current_path = None
                    current_hash = None
                except Exception as exc:
                    eprint(f"\n[auto] lỗi: {exc}")
                    proc.kill()
                    return 1

        return proc.wait()
    except KeyboardInterrupt:
        proc.kill()
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
