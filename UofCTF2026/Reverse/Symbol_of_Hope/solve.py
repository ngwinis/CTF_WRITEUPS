#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UofTCTF "checker" auto-solver (x86_64, Linux)

What it does (end-to-end):
1) Launches ./checker and keeps it blocked on fgets (stdin stays open)
2) ptrace-attaches, dumps the in-memory r-xp (text) and r--p (rodata) of the binary
3) Disassembles text.bin using (llvm-)objdump WITH raw bytes so we know instruction length
4) Extracts the long call-chain of tiny byte-transform functions
5) Finds the memcmp(..., CONST, 0x2a) and resolves the RIP-relative CONST pointer into rodata
6) For each tiny function: emulates it on all 256 byte inputs to build a bijection, then inverts it
7) Applies inverse maps in reverse order to recover the 42-byte input (expected uoftctf{...})
8) Verifies by running ./checker with the recovered input

Requirements:
- Linux x86_64
- ptrace allowed (Yama ptrace_scope may block)
- llvm-objdump OR GNU objdump installed in PATH
"""

import os
import re
import sys
import time
import ctypes
import ctypes.util
import subprocess
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

BIN = "./checker"
INPUT_LEN = 42

# -------------------- misc helpers --------------------

def which(name: str) -> Optional[str]:
    for p in os.environ.get("PATH", "").split(os.pathsep):
        cand = os.path.join(p, name)
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None

def run_cmd(cmd: List[str]) -> str:
    cp = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if cp.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{cp.stderr}")
    return cp.stdout

def hexdump(b: bytes) -> str:
    return " ".join(f"{x:02x}" for x in b)

# -------------------- ptrace + dump memory mappings --------------------

libc_path = ctypes.util.find_library("c")
if not libc_path:
    raise RuntimeError("Could not find libc")
libc = ctypes.CDLL(libc_path, use_errno=True)

PTRACE_ATTACH = 16
PTRACE_DETACH = 17
PTRACE_GETREGS = 12

class user_regs_struct(ctypes.Structure):
    _fields_ = [
        ("r15", ctypes.c_ulonglong), ("r14", ctypes.c_ulonglong),
        ("r13", ctypes.c_ulonglong), ("r12", ctypes.c_ulonglong),
        ("rbp", ctypes.c_ulonglong), ("rbx", ctypes.c_ulonglong),
        ("r11", ctypes.c_ulonglong), ("r10", ctypes.c_ulonglong),
        ("r9", ctypes.c_ulonglong),  ("r8", ctypes.c_ulonglong),
        ("rax", ctypes.c_ulonglong), ("rcx", ctypes.c_ulonglong),
        ("rdx", ctypes.c_ulonglong), ("rsi", ctypes.c_ulonglong),
        ("rdi", ctypes.c_ulonglong), ("orig_rax", ctypes.c_ulonglong),
        ("rip", ctypes.c_ulonglong), ("cs", ctypes.c_ulonglong),
        ("eflags", ctypes.c_ulonglong),
        ("rsp", ctypes.c_ulonglong), ("ss", ctypes.c_ulonglong),
        ("fs_base", ctypes.c_ulonglong), ("gs_base", ctypes.c_ulonglong),
        ("ds", ctypes.c_ulonglong), ("es", ctypes.c_ulonglong),
        ("fs", ctypes.c_ulonglong), ("gs", ctypes.c_ulonglong),
    ]

def ptrace(req: int, pid: int, addr=0, data=0):
    res = libc.ptrace(req, pid, ctypes.c_void_p(addr), ctypes.c_void_p(data))
    if res != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))

def wait_stopped(pid: int) -> None:
    while True:
        wpid, status = os.waitpid(pid, 0)
        if wpid != pid:
            continue
        if os.WIFSTOPPED(status):
            return

@dataclass
class MapEntry:
    start: int
    end: int
    perms: str
    offset: int
    dev: str
    inode: int
    path: str

def parse_maps(pid: int) -> List[MapEntry]:
    out: List[MapEntry] = []
    with open(f"/proc/{pid}/maps", "r", encoding="utf-8") as f:
        for line in f:
            parts = line.strip().split()
            rng, perms, off, dev, inode = parts[:5]
            path = parts[5] if len(parts) >= 6 else ""
            a, b = rng.split("-")
            out.append(MapEntry(
                start=int(a, 16), end=int(b, 16), perms=perms,
                offset=int(off, 16), dev=dev, inode=int(inode), path=path
            ))
    return out

def dump_region(pid: int, start: int, end: int, outpath: str) -> None:
    size = end - start
    with open(f"/proc/{pid}/mem", "rb", buffering=0) as mem, open(outpath, "wb") as out:
        mem.seek(start)
        remaining = size
        chunk = 1 << 20
        while remaining > 0:
            n = chunk if remaining > chunk else remaining
            data = mem.read(n)
            if not data:
                raise RuntimeError(f"Short read dumping {hex(start)}-{hex(end)}")
            out.write(data)
            remaining -= len(data)

def attach_and_dump() -> Tuple[int, int, str, str]:
    """
    Returns: (text_base, ro_base, text_path, ro_path)
    """
    if not os.path.exists(BIN):
        raise FileNotFoundError(BIN)

    # Start checker; keep stdin open so it blocks on fgets.
    p = subprocess.Popen([BIN], stdin=subprocess.PIPE,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    pid = p.pid
    time.sleep(0.12)

    try:
        ptrace(PTRACE_ATTACH, pid)
        wait_stopped(pid)

        regs = user_regs_struct()
        libc.ptrace(PTRACE_GETREGS, pid, 0, ctypes.byref(regs))
        rip = regs.rip

        maps = parse_maps(pid)
        bin_real = os.path.realpath(BIN)

        # text = r-xp mapping containing RIP
        text = next((m for m in maps if m.start <= rip < m.end and m.perms.startswith("r-x")), None)
        if not text:
            text = next((m for m in maps
                         if m.perms.startswith("r-x") and m.path and os.path.realpath(m.path) == bin_real), None)
        if not text:
            raise RuntimeError("Cannot locate text mapping (r-xp)")

        # rodata-like mapping for same file (r--p)
        ro_candidates = [m for m in maps
                         if m.perms.startswith("r--") and m.path and os.path.realpath(m.path) == bin_real]
        if not ro_candidates:
            raise RuntimeError("Cannot locate rodata mapping (r--p) for binary")
        ro = max(ro_candidates, key=lambda m: m.end - m.start)

        text_path = "text.bin"
        ro_path = "rodata.bin"
        dump_region(pid, text.start, text.end, text_path)
        dump_region(pid, ro.start, ro.end, ro_path)
        return text.start, ro.start, text_path, ro_path

    finally:
        try:
            ptrace(PTRACE_DETACH, pid)
        except Exception:
            pass
        try:
            p.terminate()
            p.wait(timeout=0.3)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass

# -------------------- disassembly parsing (objdump raw bytes -> insn length) --------------------

@dataclass
class Insn:
    addr: int
    size: int
    mnem: str
    ops: str
    raw: str

def disassemble_text(text_bin: str, text_base: int) -> List[Insn]:
    objdump = which("llvm-objdump") or which("objdump")
    if not objdump:
        raise RuntimeError("Need llvm-objdump or objdump in PATH")

    # Use raw bytes output so we can compute instruction size accurately.
    # llvm-objdump:
    #   llvm-objdump -D -b binary -m i386:x86-64 --adjust-vma=... --show-raw-insn --print-imm-hex text.bin
    cmd = [
        objdump,
        "-D",
        "-b", "binary",
        "-m", "i386:x86-64",
        f"--adjust-vma={text_base}",
        "--show-raw-insn",
        "--print-imm-hex",
        text_bin,
    ]
    out = run_cmd(cmd)
    lines = out.splitlines()

    insns: List[Insn] = []

    # Typical llvm-objdump line:
    #  0x555555554f10:  55                pushq %rbp
    #  0x...:          48 89 e5          movq %rsp,%rbp
    rx = re.compile(r"^\s*(0x[0-9a-fA-F]+):\s*([0-9a-fA-F]{2}(?:\s+[0-9a-fA-F]{2})*)\s+(\S+)(?:\s+(.*))?$")
    for line in lines:
        m = rx.match(line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        bstr = m.group(2)
        mnem = m.group(3)
        ops = (m.group(4) or "").strip()
        size = len(bstr.split())
        insns.append(Insn(addr=addr, size=size, mnem=mnem, ops=ops, raw=line))

    if not insns:
        raise RuntimeError("No instructions parsed from objdump output (format mismatch?)")
    return sorted(insns, key=lambda x: x.addr)

# -------------------- extract call chain and CONST pointer --------------------

def extract_long_call_chain(insns: List[Insn], text_lo: int, text_hi: int, min_len: int = 1000) -> List[int]:
    """
    Finds the longest contiguous run of call/callq targets into text range.
    Returns list of target addresses (in order).
    """
    best: List[int] = []
    cur: List[int] = []
    call_rx = re.compile(r"^(0x[0-9a-fA-F]+)$")

    for ins in insns:
        if ins.mnem.lower() in ("call", "callq"):
            op = ins.ops.strip()
            m = call_rx.match(op)
            if m:
                tgt = int(m.group(1), 16)
                if text_lo <= tgt < text_hi:
                    cur.append(tgt)
                    continue
        if len(cur) > len(best):
            best = cur
        cur = []

    if len(cur) > len(best):
        best = cur

    if len(best) < min_len:
        raise RuntimeError(f"Long call chain not found (best={len(best)})")
    return best

def find_const_addr_via_memcmp(insns: List[Insn], ro_lo: int, ro_hi: int) -> int:
    """
    Heuristic: locate pattern that sets EDX=0x2a (len) and uses a RIP-relative LEA into RSI/RDI.
    Resolve RIP-relative: addr = ins.addr + ins.size + disp
    """
    def riprel_target(ins: Insn) -> Optional[int]:
        # match [rip + 0x123] or [rip - 0x123]
        m = re.search(r"\[rip\s*([\+\-])\s*(0x[0-9a-fA-F]+|\d+)\]", ins.ops)
        if not m:
            return None
        sign = m.group(1)
        disp = int(m.group(2), 0)
        if sign == "-":
            disp = -disp
        return (ins.addr + ins.size + disp) & 0xFFFFFFFFFFFFFFFF

    # Normalize mov edx,0x2a variants
    def is_len_mov(ins: Insn) -> bool:
        if ins.mnem.lower() != "mov":
            return False
        s = ins.ops.replace(" ", "").lower()
        return s in ("edx,0x2a", "rdx,0x2a")

    for i, ins in enumerate(insns):
        if not is_len_mov(ins):
            continue
        # look ahead a bit for lea rsi/rdi, [rip + disp] that points into rodata
        for j in range(1, 30):
            if i + j >= len(insns):
                break
            w = insns[i + j]
            if w.mnem.lower() != "lea":
                continue
            tgt = riprel_target(w)
            if tgt is None:
                continue
            if ro_lo <= tgt < ro_hi:
                return tgt

    raise RuntimeError("Failed to resolve CONST address near memcmp(len=0x2a)")

# -------------------- tiny emulator (byte-focused) --------------------

def mask8(x: int) -> int: return x & 0xFF
def rol8(v: int, r: int) -> int:
    r &= 7
    v &= 0xFF
    return ((v << r) | (v >> (8 - r))) & 0xFF
def ror8(v: int, r: int) -> int:
    r &= 7
    v &= 0xFF
    return ((v >> r) | (v << (8 - r))) & 0xFF

REG8 = {
    "al": "rax", "bl": "rbx", "cl": "rcx", "dl": "rdx",
    "sil": "rsi", "dil": "rdi",
    "r8b": "r8", "r9b": "r9", "r10b": "r10", "r11b": "r11",
    "r12b": "r12", "r13b": "r13", "r14b": "r14", "r15b": "r15",
}
REG32 = {
    "eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx",
    "esi": "rsi", "edi": "rdi",
    "r8d": "r8", "r9d": "r9", "r10d": "r10", "r11d": "r11",
    "r12d": "r12", "r13d": "r13", "r14d": "r14", "r15d": "r15",
}
REG64 = {
    "rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp",
    "r8","r9","r10","r11","r12","r13","r14","r15"
}

IMM_RX = re.compile(r"^(-?0x[0-9a-fA-F]+|-?\d+)$")
MEM_RSP_RX = re.compile(r"^\[rsp(?:\s*([\+\-])\s*(0x[0-9a-fA-F]+|\d+))?\]$")

def parse_imm(s: str) -> int:
    s = s.strip()
    if not IMM_RX.match(s):
        raise ValueError(f"not imm: {s}")
    return int(s, 0)

def parse_rsp_mem(op: str) -> Optional[int]:
    op = op.strip().lower()
    m = MEM_RSP_RX.match(op)
    if not m:
        return None
    if not m.group(1):
        return 0
    sign = m.group(1)
    val = int(m.group(2), 0)
    return -val if sign == "-" else val

def get_reg(regs: Dict[str, int], name: str) -> int:
    name = name.lower()
    if name in REG8:
        return regs.get(REG8[name], 0) & 0xFF
    if name in REG32:
        return regs.get(REG32[name], 0) & 0xFFFFFFFF
    if name in REG64:
        return regs.get(name, 0) & 0xFFFFFFFFFFFFFFFF
    raise KeyError(f"unknown reg {name}")

def set_reg(regs: Dict[str, int], name: str, val: int) -> None:
    name = name.lower()
    if name in REG8:
        base = REG8[name]
        cur = regs.get(base, 0)
        regs[base] = (cur & ~0xFF) | (val & 0xFF)
        return
    if name in REG32:
        base = REG32[name]
        regs[base] = val & 0xFFFFFFFF  # zero-extend
        return
    if name in REG64:
        regs[name] = val & 0xFFFFFFFFFFFFFFFF
        return
    raise KeyError(f"unknown reg {name}")

def emulate_func(func: List[Insn], x: int) -> int:
    regs: Dict[str, int] = {r: 0 for r in REG64}
    stack: Dict[int, int] = {}  # byte-addressed
    regs["rsp"] = 0x7000_0000_0000

    # seed common arg regs with x
    set_reg(regs, "al", x)
    set_reg(regs, "dil", x)
    set_reg(regs, "sil", x)
    set_reg(regs, "cl", x)
    set_reg(regs, "dl", x)

    for ins in func:
        m = ins.mnem.lower()
        ops = ins.ops.strip()

        if m in ("ret", "retq"):
            break
        if m == "nop":
            continue

        # remove size keywords
        ops = ops.replace("BYTE PTR", "").replace("byte ptr", "").strip()

        # split operands
        if "," in ops:
            dst, src = [p.strip() for p in ops.split(",", 1)]
        else:
            dst, src = ops.strip(), ""

        dst_l = dst.lower()
        src_l = src.lower()

        # stack frame noise
        if m == "push":
            v = get_reg(regs, dst_l)
            regs["rsp"] = (regs["rsp"] - 8) & 0xFFFFFFFFFFFFFFFF
            a = regs["rsp"]
            for i in range(8):
                stack[a + i] = (v >> (8*i)) & 0xFF
            continue

        if m == "pop":
            a = regs["rsp"]
            v = 0
            for i in range(8):
                v |= (stack.get(a + i, 0) & 0xFF) << (8*i)
            regs["rsp"] = (regs["rsp"] + 8) & 0xFFFFFFFFFFFFFFFF
            set_reg(regs, dst_l, v)
            continue

        if m == "leave":
            regs["rsp"] = regs.get("rbp", regs["rsp"])
            # pop rbp
            a = regs["rsp"]
            v = 0
            for i in range(8):
                v |= (stack.get(a + i, 0) & 0xFF) << (8*i)
            regs["rsp"] = (regs["rsp"] + 8) & 0xFFFFFFFFFFFFFFFF
            regs["rbp"] = v
            continue

        # mov/movzx/movsx
        if m == "mov":
            # mem forms: [rsp + off]
            off_src = parse_rsp_mem(src_l)
            off_dst = parse_rsp_mem(dst_l)
            if off_src is not None:
                a = (regs["rsp"] + off_src) & 0xFFFFFFFFFFFFFFFF
                b = stack.get(a, 0) & 0xFF
                set_reg(regs, dst_l, b)
            elif off_dst is not None:
                a = (regs["rsp"] + off_dst) & 0xFFFFFFFFFFFFFFFF
                b = get_reg(regs, src_l) & 0xFF
                stack[a] = b
            elif IMM_RX.match(src_l):
                set_reg(regs, dst_l, parse_imm(src_l))
            else:
                set_reg(regs, dst_l, get_reg(regs, src_l))
            continue

        if m in ("movzx", "movsx"):
            off_src = parse_rsp_mem(src_l)
            if off_src is not None:
                a = (regs["rsp"] + off_src) & 0xFFFFFFFFFFFFFFFF
                v = stack.get(a, 0) & 0xFF
                set_reg(regs, dst_l, v)
            else:
                v = get_reg(regs, src_l) & 0xFF
                set_reg(regs, dst_l, v)
            continue

        # lea: support lea eax, [rax + imm]
        if m == "lea":
            mm = re.search(r"\[(\w+)\s*([\+\-])\s*(0x[0-9a-fA-F]+|\d+)\]", ops.lower())
            if not mm:
                raise RuntimeError(f"Unsupported lea: {ins.raw}")
            base = mm.group(1)
            sign = mm.group(2)
            imm = int(mm.group(3), 0)
            if sign == "-":
                imm = -imm
            v = (get_reg(regs, base) + imm) & 0xFFFFFFFFFFFFFFFF
            set_reg(regs, dst_l, v)
            continue

        # unary ops
        if m == "not":
            v = get_reg(regs, dst_l)
            if dst_l in REG8:
                set_reg(regs, dst_l, (~v) & 0xFF)
            elif dst_l in REG32:
                set_reg(regs, dst_l, (~v) & 0xFFFFFFFF)
            else:
                set_reg(regs, dst_l, (~v) & 0xFFFFFFFFFFFFFFFF)
            continue

        if m == "neg":
            v = get_reg(regs, dst_l)
            if dst_l in REG8:
                set_reg(regs, dst_l, (-v) & 0xFF)
            elif dst_l in REG32:
                set_reg(regs, dst_l, (-v) & 0xFFFFFFFF)
            else:
                set_reg(regs, dst_l, (-v) & 0xFFFFFFFFFFFFFFFF)
            continue

        # xchg (sometimes appears)
        if m == "xchg":
            a = get_reg(regs, dst_l)
            b = get_reg(regs, src_l)
            set_reg(regs, dst_l, b)
            set_reg(regs, src_l, a)
            continue

        # shifts/rotates
        if m in ("rol", "ror", "shl", "shr", "sar"):
            v = get_reg(regs, dst_l) & 0xFF
            cnt = parse_imm(src_l) if IMM_RX.match(src_l) else get_reg(regs, src_l)
            c = cnt & 0xFF
            if m == "rol":
                out = rol8(v, c)
            elif m == "ror":
                out = ror8(v, c)
            elif m == "shl":
                out = mask8(v << (c & 7))
            elif m == "shr":
                out = mask8(v >> (c & 7))
            else:  # sar
                vv = v
                if vv & 0x80:
                    out = ((vv | 0xFFFFFF00) >> (c & 7)) & 0xFF
                else:
                    out = (vv >> (c & 7)) & 0xFF
            set_reg(regs, dst_l, out)
            continue

        # add/sub/xor/and/or
        if m in ("add", "sub", "xor", "and", "or"):
            a = get_reg(regs, dst_l)
            b = parse_imm(src_l) if IMM_RX.match(src_l) else get_reg(regs, src_l)
            if dst_l in REG8:
                a &= 0xFF; b &= 0xFF
                if m == "add": out = (a + b) & 0xFF
                elif m == "sub": out = (a - b) & 0xFF
                elif m == "xor": out = (a ^ b) & 0xFF
                elif m == "and": out = (a & b) & 0xFF
                else: out = (a | b) & 0xFF
                set_reg(regs, dst_l, out)
            elif dst_l in REG32:
                a &= 0xFFFFFFFF; b &= 0xFFFFFFFF
                if m == "add": out = (a + b) & 0xFFFFFFFF
                elif m == "sub": out = (a - b) & 0xFFFFFFFF
                elif m == "xor": out = (a ^ b) & 0xFFFFFFFF
                elif m == "and": out = (a & b) & 0xFFFFFFFF
                else: out = (a | b) & 0xFFFFFFFF
                set_reg(regs, dst_l, out)
            else:
                a &= 0xFFFFFFFFFFFFFFFF; b &= 0xFFFFFFFFFFFFFFFF
                if m == "add": out = (a + b) & 0xFFFFFFFFFFFFFFFF
                elif m == "sub": out = (a - b) & 0xFFFFFFFFFFFFFFFF
                elif m == "xor": out = (a ^ b) & 0xFFFFFFFFFFFFFFFF
                elif m == "and": out = (a & b) & 0xFFFFFFFFFFFFFFFF
                else: out = (a | b) & 0xFFFFFFFFFFFFFFFF
                set_reg(regs, dst_l, out)
            continue

        # inc/dec
        if m in ("inc", "dec"):
            v = get_reg(regs, dst_l)
            if dst_l in REG8:
                out = (v + 1) & 0xFF if m == "inc" else (v - 1) & 0xFF
            elif dst_l in REG32:
                out = (v + 1) & 0xFFFFFFFF if m == "inc" else (v - 1) & 0xFFFFFFFF
            else:
                out = (v + 1) & 0xFFFFFFFFFFFFFFFF if m == "inc" else (v - 1) & 0xFFFFFFFFFFFFFFFF
            set_reg(regs, dst_l, out)
            continue

        # imul common forms
        if m == "imul":
            parts = [p.strip().lower() for p in ops.split(",")]
            if len(parts) == 3:
                dst2, s1, imm = parts
                a = get_reg(regs, s1)
                b = int(imm, 0)
                out = (a * b) & 0xFFFFFFFF
                set_reg(regs, dst2, out)
            elif len(parts) == 2:
                dst2, s1 = parts
                a = get_reg(regs, dst2)
                b = get_reg(regs, s1)
                out = (a * b) & 0xFFFFFFFF
                set_reg(regs, dst2, out)
            else:
                raise RuntimeError(f"Unsupported imul: {ins.raw}")
            continue

        # harmless compares/tests (ignore)
        if m in ("cmp", "test"):
            continue

        raise RuntimeError(f"Unsupported instruction: {ins.raw}")

    return get_reg(regs, "al") & 0xFF

def slice_function(insns: List[Insn], start: int, max_insns: int = 64) -> List[Insn]:
    idx = {ins.addr: i for i, ins in enumerate(insns)}
    if start not in idx:
        raise RuntimeError(f"Function start not found in disasm: {hex(start)}")
    i = idx[start]
    out: List[Insn] = []
    for _ in range(max_insns):
        ins = insns[i]
        out.append(ins)
        if ins.mnem.lower() in ("ret", "retq"):
            break
        i += 1
        if i >= len(insns):
            break
    return out

def build_inverse_map(func_insns: List[Insn]) -> List[int]:
    fwd = [0] * 256
    for x in range(256):
        fwd[x] = emulate_func(func_insns, x)

    inv = [-1] * 256
    for x, y in enumerate(fwd):
        if inv[y] != -1:
            raise RuntimeError("Non-bijective mapping (emulator missing an instruction?)")
        inv[y] = x
    if any(v == -1 for v in inv):
        raise RuntimeError("Inverse map incomplete (non-bijective)")
    return inv

# -------------------- solve pipeline --------------------

def solve():
    print("[*] Attaching + dumping in-memory text/rodata ...")
    text_base, ro_base, text_bin, ro_bin = attach_and_dump()
    text_size = os.path.getsize(text_bin)
    ro_size = os.path.getsize(ro_bin)
    text_hi = text_base + text_size
    ro_hi = ro_base + ro_size
    print(f"[+] text  : {hex(text_base)} - {hex(text_hi)}  ({text_size} bytes)")
    print(f"[+] rodata: {hex(ro_base)} - {hex(ro_hi)}  ({ro_size} bytes)")

    print("[*] Disassembling text.bin ...")
    insns = disassemble_text(text_bin, text_base)
    print(f"[+] Parsed {len(insns)} instructions")

    print("[*] Extracting long call-chain ...")
    chain = extract_long_call_chain(insns, text_base, text_hi, min_len=1000)
    print(f"[+] Chain length: {len(chain)}")

    # many of these challenges have ~4200 calls; if chain is longer, trim to first 4200-ish
    if len(chain) > 5000:
        chain = chain[:4200]
        print(f"[+] Trimmed chain to {len(chain)}")

    print("[*] Locating CONST[42] address (memcmp len=0x2a) ...")
    const_addr = find_const_addr_via_memcmp(insns, ro_base, ro_hi)
    const_off = const_addr - ro_base
    with open(ro_bin, "rb") as f:
        f.seek(const_off)
        const = f.read(INPUT_LEN)
    if len(const) != INPUT_LEN:
        raise RuntimeError("Failed reading CONST bytes")
    print(f"[+] CONST @ {hex(const_addr)}: {hexdump(const)}")

    print("[*] Building inverse maps for each transform function ...")
    func_cache: Dict[int, List[Insn]] = {}
    inv_maps: List[List[int]] = []

    for i, faddr in enumerate(chain):
        if faddr not in func_cache:
            func_cache[faddr] = slice_function(insns, faddr, max_insns=64)
        inv_maps.append(build_inverse_map(func_cache[faddr]))
        if (i + 1) % 250 == 0:
            print(f"    ... {i+1}/{len(chain)}")

    print("[*] Reversing chain on 42 output bytes ...")
    cur = list(const)
    for inv in reversed(inv_maps):
        cur = [inv[b] for b in cur]

    recovered = bytes(cur)
    print("[+] Recovered bytes:", recovered)
    print("[+] Recovered (ascii-ish):", recovered.decode("utf-8", errors="replace"))

    print("[*] Verifying with ./checker ...")
    cp = subprocess.run([BIN], input=recovered + b"\n",
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print("[+] checker stdout:", cp.stdout.decode(errors="replace").strip())
    if cp.stderr:
        print("[+] checker stderr:", cp.stderr.decode(errors="replace").strip())

    if b"uoftctf{" in recovered:
        print("[✅] FLAG:", recovered.decode(errors="replace"))

if __name__ == "__main__":
    try:
        solve()
    except Exception as e:
        print(f"[!] Error: {e}")

        print("\nCommon fixes:")
        print(" - ptrace 'Operation not permitted': Yama ptrace_scope đang chặn; chạy trong VM/CTF env cho phép ptrace.")
        print(" - 'Unsupported instruction': copy vài dòng objdump quanh instruction đó để mình thêm opcode vào emulator.")
        sys.exit(1)
