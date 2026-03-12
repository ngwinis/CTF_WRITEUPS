#!/usr/bin/env python3
import argparse
import os
import re
import select
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

GDB_PROMPT = b"(gdb)"
TEXT_BASE = 0x400000
TEXT_END_GUESS = 0x800000

PROLOGUE_RE = re.compile(
    rb"\x0f\x28\x0d....\x48\xc7\xc0\xf0\xff\xff\xff\x0f\x28\x15",
    re.DOTALL,
)


def p16(x: int) -> bytes:
    return struct.pack("<H", x & 0xFFFF)


def hexb(x: int) -> str:
    return f"0x{x:x}"


class GDBError(RuntimeError):
    pass


class GDB:
    def __init__(self, binary: str, fifo_path: str):
        self.binary = binary
        self.fifo_path = fifo_path

        gdb_path = shutil.which("gdb")
        if gdb_path is None:
            raise SystemExit(
                "gdb not found. Install it with:\n"
                "  sudo apt update && sudo apt install gdb"
            )

        self.p = subprocess.Popen(
            [gdb_path, "-q", "--nx", "--args", binary],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
            start_new_session=True,
        )

        self._read_until_prompt(timeout=10.0)
        self.cmd("set pagination off")
        self.cmd("set confirm off")
        self.cmd("set breakpoint pending on")
        self.cmd("set print elements 0")
        self.cmd("set disassemble-next-line off")
        self.cmd("set debuginfod enabled off")
        self.cmd("set detach-on-fork off")

    def _read_until_prompt(self, timeout: float = 5.0) -> bytes:
        if self.p.stdout is None:
            raise GDBError("gdb stdout closed")

        deadline = time.time() + timeout
        out = bytearray()
        fd = self.p.stdout.fileno()

        while time.time() < deadline:
            remaining = max(0.0, deadline - time.time())
            r, _, _ = select.select([fd], [], [], remaining)
            if not r:
                raise GDBError("timeout waiting for gdb prompt")

            ch = os.read(fd, 1)
            if not ch:
                raise GDBError("gdb terminated unexpectedly")

            out += ch
            if out.endswith(GDB_PROMPT):
                return bytes(out)

        raise GDBError("timeout waiting for gdb prompt")

    def send_raw(self, s: str) -> None:
        if self.p.stdin is None:
            raise GDBError("gdb stdin closed")
        self.p.stdin.write(s.encode() + b"\n")
        self.p.stdin.flush()

    def cmd(self, s: str, timeout: float = 5.0) -> str:
        self.send_raw(s)
        out = self._read_until_prompt(timeout=timeout)
        return out.decode("utf-8", errors="replace")

    def run_nowait(self) -> None:
        self.send_raw(f"run < {self.fifo_path}")

    def interrupt(self, timeout: float = 5.0) -> str:
        if self.p.pid is None:
            raise GDBError("gdb has no pid")
        os.killpg(self.p.pid, signal.SIGINT)
        out = self._read_until_prompt(timeout=timeout)
        return out.decode("utf-8", errors="replace")

    def cont(self, timeout: float = 5.0) -> str:
        return self.cmd("continue", timeout=timeout)

    def get_pid(self) -> int:
        out = self.cmd("info inferior")
        m = re.search(r"\*\s+1\s+process\s+(\d+)", out)
        if not m:
            raise GDBError(f"could not parse inferior pid from:\n{out}")
        return int(m.group(1))

    def parse_rsp_and_ret(self) -> tuple[int, int]:
        out = self.cmd("x/gx $rsp")
        m = re.search(r"0x([0-9a-fA-F]+):\s+0x([0-9a-fA-F]+)", out)
        if not m:
            raise GDBError(f"could not parse rsp/ret from:\n{out}")
        rsp = int(m.group(1), 16)
        ret = int(m.group(2), 16)
        return rsp, ret

    def checkpoint(self) -> int:
        out = self.cmd("checkpoint", timeout=10.0)
        m = re.search(r"checkpoint\s+(\d+)", out, re.IGNORECASE)
        if not m:
            raise GDBError(f"could not parse checkpoint id from:\n{out}")
        return int(m.group(1))

    def restart_checkpoint(self, ckpt_id: int) -> str:
        return self.cmd(f"restart {ckpt_id}", timeout=10.0)

    def delete_breakpoints(self) -> None:
        try:
            self.cmd("delete breakpoints", timeout=5.0)
        except Exception:
            pass

    def break_spec(self, spec: str) -> int:
        out = self.cmd(f"break {spec}", timeout=10.0)
        m = re.search(r"Breakpoint\s+(\d+)", out)
        if not m:
            raise GDBError(f"could not parse breakpoint number from:\n{out}")
        return int(m.group(1))

    def ignore_breakpoint(self, bpnum: int, count: int) -> None:
        self.cmd(f"ignore {bpnum} {count}", timeout=5.0)

    def select_live_inferior(self) -> int:
        out = self.cmd("info inferiors", timeout=5.0)

        live = []
        for line in out.splitlines():
            m = re.match(r"^\s*(\*?)\s*(\d+)\s+process\s+(\d+)\s+", line)
            if m:
                cur = bool(m.group(1))
                inf_id = int(m.group(2))
                pid = int(m.group(3))
                live.append((cur, inf_id, pid))

        if not live:
            raise GDBError(f"no live inferior found after restart:\n{out}")

        for cur, inf_id, pid in live:
            if cur:
                return inf_id

        inf_id = live[0][1]
        self.cmd(f"inferior {inf_id}", timeout=5.0)
        return inf_id

    def restart_checkpoint_and_select(self, ckpt_id: int) -> int:
        out = self.restart_checkpoint(ckpt_id)
        if "No checkpoint number" in out:
            raise GDBError(f"checkpoint {ckpt_id} missing:\n{out}")
        return self.select_live_inferior()

    def quit(self) -> None:
        try:
            if self.p.pid is not None:
                os.killpg(self.p.pid, signal.SIGTERM)
        except Exception:
            pass
        try:
            self.p.kill()
        except Exception:
            pass


def read_mem(pid: int, addr: int, size: int) -> bytes:
    with open(f"/proc/{pid}/mem", "rb", buffering=0) as f:
        f.seek(addr)
        return f.read(size)


def find_stage_start(code: bytes, code_base: int, ret_addr: int) -> int:
    upto = ret_addr - code_base
    if upto <= 0:
        raise RuntimeError("return address below code base")

    candidates = [m.start() for m in PROLOGUE_RE.finditer(code[:upto])]
    if not candidates:
        raise RuntimeError("could not locate stage prologue")

    return code_base + candidates[-1]


def stage_snapshot(binary: str, prefix: bytes, fifo_path: str, fifo_wfd: int):
    g = GDB(binary, fifo_path)
    g.run_nowait()

    if prefix:
        nw = os.write(fifo_wfd, prefix)
        if nw != len(prefix):
            raise RuntimeError(f"short write of prefix: wrote {nw} / {len(prefix)}")

    time.sleep(0.2)
    intr = g.interrupt(timeout=10.0)

    pid = g.get_pid()
    rsp, ret = g.parse_rsp_and_ret()

    text = read_mem(pid, TEXT_BASE, TEXT_END_GUESS - TEXT_BASE)
    stage_start = find_stage_start(text, TEXT_BASE, ret)

    return g, pid, rsp, ret, stage_start, intr


def looks_like_read_break(out: str) -> bool:
    if "Breakpoint" not in out:
        return False
    needles = [
        " read ",
        "read (",
        "__GI___libc_read",
        "__libc_read",
        " in read ",
        " in __GI___libc_read ",
        " in __libc_read ",
    ]
    return any(n in out for n in needles)


def brute_stage(
    g: GDB,
    base_ckpt_id: int,
    fifo_wfd: int,
    verbose: bool = True,
) -> int:
    g.delete_breakpoints()
    bpnum = g.break_spec("read")

    for cand in range(0x10000):
        g.restart_checkpoint_and_select(base_ckpt_id)

        # We are currently stopped inside the first read() of this stage.
        # After feeding 2 bytes, the stage will hit its own second read().
        # Ignore that one; the next hit should be the next stage's read() if correct.
        g.ignore_breakpoint(bpnum, 1)

        nw = os.write(fifo_wfd, p16(cand))
        if nw != 2:
            raise RuntimeError(f"short write for candidate {cand:04x}: wrote {nw}")

        try:
            out = g.cont(timeout=5.0)
        except GDBError as e:
            if verbose and cand % 0x400 == 0:
                print(f"    tried {cand:04x} -> timeout ({e})", file=sys.stderr)
            continue

        if verbose and cand % 0x400 == 0:
            lines = out.strip().splitlines()
            preview = lines[0] if lines else ""
            print(f"    tried {cand:04x} -> {preview}", file=sys.stderr)

        if looks_like_read_break(out):
            return cand

    raise RuntimeError("stage brute force failed")


def run_binary_for_token(binary: str, key: bytes) -> str:
    p = subprocess.run(
        [binary],
        input=key,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    return p.stdout.decode("utf-8", errors="replace")


def main() -> int:
    ap = argparse.ArgumentParser(description="another-onion generic solver framework")
    ap.add_argument("binary", help="path to target binary")
    ap.add_argument("--prefix-hex", default="", help="resume from partial key")
    ap.add_argument("--stages", type=int, default=256, help="number of 2-byte stages")
    args = ap.parse_args()

    binary = os.path.abspath(args.binary)
    if not os.path.isfile(binary):
        raise SystemExit(f"binary not found: {binary}")

    prefix = bytes.fromhex(args.prefix_hex) if args.prefix_hex else b""
    if len(prefix) % 2:
        raise SystemExit("--prefix-hex must contain an even number of bytes")

    work = Path("solver_work")
    work.mkdir(exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="onion_") as td:
        fifo_path = os.path.join(td, "stdin.fifo")
        os.mkfifo(fifo_path)

        fifo_wfd = os.open(fifo_path, os.O_RDWR)

        try:
            solved = bytearray(prefix)
            start_stage = len(solved) // 2

            for stage_idx in range(start_stage, args.stages):
                print(f"[*] stage {stage_idx}/{args.stages - 1}")

                g, pid, rsp, ret, stage_start, intr = stage_snapshot(
                    binary, bytes(solved), fifo_path, fifo_wfd
                )

                try:
                    print(f"    interrupt: {intr.strip()}")
                    print(f"    pid={pid} rsp={hexb(rsp)} ret={hexb(ret)}")
                    print(f"    stage_start={hexb(stage_start)}")

                    ckpt_id = g.checkpoint()
                    chunk = brute_stage(g, ckpt_id, fifo_wfd)
                    print(f"[+] found chunk: {chunk:04x}")

                    solved += p16(chunk)
                    (work / "key.bin").write_bytes(solved)
                    (work / "key.hex").write_text(solved.hex() + "\n")
                finally:
                    g.quit()

            print(f"[+] key recovered: {solved.hex()}")

            out = run_binary_for_token(binary, bytes(solved))
            print(out)

        finally:
            os.close(fifo_wfd)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())