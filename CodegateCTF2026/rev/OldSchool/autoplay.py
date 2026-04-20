#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from solver import solve_file


PROMPT = b"answer> "


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("server")
    args = parser.parse_args()

    proc = subprocess.Popen(
        ["./client", "-server", args.server],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    assert proc.stdin is not None
    assert proc.stdout is not None

    current_path: Path | None = None
    line = bytearray()
    stream = bytearray()

    while True:
        chunk = proc.stdout.read(1)
        if not chunk:
            break
        sys.stdout.buffer.write(chunk)
        sys.stdout.buffer.flush()
        stream += chunk
        line += chunk

        if chunk == b"\n":
            text = line.decode("utf-8", errors="replace").rstrip("\n")
            if text.startswith("binary_path="):
                current_path = Path(text.split("=", 1)[1])
            line.clear()

        if stream.endswith(PROMPT):
            if current_path is None:
                raise RuntimeError("saw answer prompt before binary_path")
            answer = solve_file(current_path)
            proc.stdin.write(answer + b"\n")
            proc.stdin.flush()
            print(f"\n[solver] sent {current_path} {answer.hex()}")
            stream.clear()

    return proc.wait()


if __name__ == "__main__":
    raise SystemExit(main())
