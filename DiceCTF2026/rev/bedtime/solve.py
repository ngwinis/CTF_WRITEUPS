#!/usr/bin/env python3
import argparse
import ctypes
import ctypes.util
import os
import signal
import struct
import sys
from typing import List, Tuple

# Linux ptrace constants
PTRACE_TRACEME = 0
PTRACE_PEEKDATA = 2
PTRACE_POKEDATA = 5
PTRACE_CONT = 7
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_DETACH = 17

# Breakpoint chosen right after the challenge finishes building the 384-entry table
# and right before it starts printing/reading stdin.
INIT_DONE_OFFSET = 0x21C47
TABLE_SIZE = 0x3000  # 384 * 32 bytes
ENTRY_COUNT = 384
ENTRY_SIZE = 32

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
libc.ptrace.restype = ctypes.c_longlong


class UserRegsStruct(ctypes.Structure):
    _fields_ = [
        ("r15", ctypes.c_ulonglong),
        ("r14", ctypes.c_ulonglong),
        ("r13", ctypes.c_ulonglong),
        ("r12", ctypes.c_ulonglong),
        ("rbp", ctypes.c_ulonglong),
        ("rbx", ctypes.c_ulonglong),
        ("r11", ctypes.c_ulonglong),
        ("r10", ctypes.c_ulonglong),
        ("r9", ctypes.c_ulonglong),
        ("r8", ctypes.c_ulonglong),
        ("rax", ctypes.c_ulonglong),
        ("rcx", ctypes.c_ulonglong),
        ("rdx", ctypes.c_ulonglong),
        ("rsi", ctypes.c_ulonglong),
        ("rdi", ctypes.c_ulonglong),
        ("orig_rax", ctypes.c_ulonglong),
        ("rip", ctypes.c_ulonglong),
        ("cs", ctypes.c_ulonglong),
        ("eflags", ctypes.c_ulonglong),
        ("rsp", ctypes.c_ulonglong),
        ("ss", ctypes.c_ulonglong),
        ("fs_base", ctypes.c_ulonglong),
        ("gs_base", ctypes.c_ulonglong),
        ("ds", ctypes.c_ulonglong),
        ("es", ctypes.c_ulonglong),
        ("fs", ctypes.c_ulonglong),
        ("gs", ctypes.c_ulonglong),
    ]


def ptrace(req: int, pid: int, addr: int = 0, data: int = 0) -> int:
    ctypes.set_errno(0)
    res = libc.ptrace(req, pid, ctypes.c_void_p(addr), ctypes.c_void_p(data))
    err = ctypes.get_errno()
    if res == -1 and err != 0:
        raise OSError(err, os.strerror(err))
    return res


def read_process_memory(pid: int, addr: int, size: int) -> bytes:
    out = bytearray()
    for cur in range(addr, addr + size, 8):
        ctypes.set_errno(0)
        word = libc.ptrace(PTRACE_PEEKDATA, pid, ctypes.c_void_p(cur), 0)
        err = ctypes.get_errno()
        if word == -1 and err != 0:
            raise OSError(err, f"ptrace PEEKDATA failed at {hex(cur)}: {os.strerror(err)}")
        out += struct.pack("<Q", word & 0xFFFFFFFFFFFFFFFF)
    return bytes(out[:size])


def get_base_address(pid: int, binary_path: str) -> int:
    real = os.path.realpath(binary_path)
    with open(f"/proc/{pid}/maps", "r", encoding="utf-8") as f:
        for line in f:
            parts = line.split()
            if len(parts) < 6:
                continue
            perms = parts[1]
            offset = int(parts[2], 16)
            path = parts[-1]
            if path == real and "r-xp" in perms:
                start = int(parts[0].split("-")[0], 16)
                return start - offset
    raise RuntimeError("Could not locate PIE base address from /proc/<pid>/maps")


def wait_for_stop(pid: int) -> int:
    _, status = os.waitpid(pid, 0)
    if os.WIFSTOPPED(status):
        return os.WSTOPSIG(status)
    raise RuntimeError(f"Process did not stop as expected (status={hex(status)})")


def launch_and_break(binary_path: str) -> Tuple[int, UserRegsStruct, bytes]:
    pid = os.fork()
    if pid == 0:
        libc.ptrace(PTRACE_TRACEME, 0, None, None)
        os.execl(binary_path, binary_path)
        raise SystemExit(1)

    wait_for_stop(pid)  # initial SIGTRAP after execve
    base = get_base_address(pid, binary_path)
    bp_addr = base + INIT_DONE_OFFSET

    original = read_process_memory(pid, bp_addr, 8)
    patched = bytearray(original)
    patched[0] = 0xCC  # int3
    ptrace(PTRACE_POKEDATA, pid, bp_addr, struct.unpack("<Q", patched)[0])

    try:
        ptrace(PTRACE_CONT, pid, 0, 0)
        wait_for_stop(pid)  # hit breakpoint

        regs = UserRegsStruct()
        ptrace(PTRACE_GETREGS, pid, 0, ctypes.addressof(regs))
        if regs.rip != bp_addr + 1:
            raise RuntimeError(f"Unexpected RIP at breakpoint: {hex(regs.rip)}")

        # Restore original instruction and rewind RIP.
        ptrace(PTRACE_POKEDATA, pid, bp_addr, struct.unpack("<Q", original)[0])
        regs.rip = bp_addr
        ptrace(PTRACE_SETREGS, pid, 0, ctypes.addressof(regs))

        table_blob = read_process_memory(pid, regs.rbx, TABLE_SIZE)
        return pid, regs, table_blob
    except Exception:
        try:
            ptrace(PTRACE_DETACH, pid, 0, 0)
        except Exception:
            pass
        try:
            os.kill(pid, signal.SIGKILL)
        except Exception:
            pass
        raise


def cleanup_child(pid: int) -> None:
    try:
        ptrace(PTRACE_DETACH, pid, 0, 0)
    except Exception:
        pass
    try:
        os.kill(pid, signal.SIGKILL)
    except Exception:
        pass


def parse_entries(table_blob: bytes) -> List[Tuple[int, int, int, int]]:
    if len(table_blob) != TABLE_SIZE:
        raise ValueError(f"Expected {TABLE_SIZE} bytes, got {len(table_blob)}")
    entries = []
    for i in range(ENTRY_COUNT):
        entry = struct.unpack_from("<QQQQ", table_blob, i * ENTRY_SIZE)
        entries.append(entry)
    return entries


def decode_flag_from_entries(pid: int, entries: List[Tuple[int, int, int, int]]) -> str:
    bits: List[int] = []
    for idx, (length, ptr, length2, m) in enumerate(entries):
        if length != length2:
            raise RuntimeError(f"Entry {idx}: unexpected shape ({length} != {length2})")
        raw = read_process_memory(pid, ptr, length * 8)
        arr = struct.unpack("<" + "Q" * length, raw)

        x = 0
        mod = m + 1
        for v in arr:
            x ^= (v % mod)

        bits.append(1 if x == 0 else 0)

    if len(bits) % 8 != 0:
        raise RuntimeError("Bitstream length is not a multiple of 8")

    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for b in bits[i : i + 8]:
            byte = (byte << 1) | b
        out.append(byte)
    return out.decode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Solve the bedtime reverse challenge")
    parser.add_argument("binary", nargs="?", default="./bedtime", help="Path to the challenge binary")
    args = parser.parse_args()

    binary_path = os.path.realpath(args.binary)
    if not os.path.exists(binary_path):
        print(f"[-] Binary not found: {binary_path}", file=sys.stderr)
        return 1
    if not os.access(binary_path, os.X_OK):
        try:
            st = os.stat(binary_path)
            os.chmod(binary_path, st.st_mode | 0o111)
        except OSError as e:
            print(f"[-] Could not mark binary executable: {e}", file=sys.stderr)
            return 1

    pid = None
    try:
        pid, _regs, table_blob = launch_and_break(binary_path)
        entries = parse_entries(table_blob)
        flag = decode_flag_from_entries(pid, entries)
        print(flag)
        return 0
    finally:
        if pid is not None:
            cleanup_child(pid)


if __name__ == "__main__":
    raise SystemExit(main())
