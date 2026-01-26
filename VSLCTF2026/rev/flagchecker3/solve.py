#!/usr/bin/env python3
from dataclasses import dataclass

SO_PATH = "app-release/lib/x86_64/libveilcore.so"

BYTECODE_OFF = 0x23B0
BYTECODE_LEN = 0x0DE9

# opcode indices (từ dispatch table đã được init trong VM)
OP_JCC           = 8
OP_ADD           = 19
OP_AND           = 31
OP_PUSH_IMM32    = 42
OP_OR            = 62
OP_PUSH_INP_BYTE = 94
OP_ROL8          = 98
OP_PUSH_INP_LEN  = 109
OP_SUB           = 113
OP_XOR           = 156
OP_NOP1          = 153
OP_DUP           = 168
OP_CMP           = 178
OP_JMP           = 209
OP_NOP2          = 227
OP_HALT          = 254

OPS = {
    OP_JCC, OP_ADD, OP_AND, OP_PUSH_IMM32, OP_OR, OP_PUSH_INP_BYTE,
    OP_ROL8, OP_PUSH_INP_LEN, OP_SUB, OP_XOR, OP_NOP1, OP_DUP, OP_CMP,
    OP_JMP, OP_NOP2, OP_HALT
}

def rol8(x, r):
    x &= 0xFF
    r &= 7
    return ((x << r) | (x >> (8 - r))) & 0xFF

def sign16(n):
    n &= 0xFFFF
    return n - 0x10000 if (n & 0x8000) else n

class NeedByte(Exception):
    def __init__(self, idx): self.idx = idx

def load_bytecode():
    with open(SO_PATH, "rb") as f:
        blob = f.read()
    bc = blob[BYTECODE_OFF:BYTECODE_OFF + BYTECODE_LEN]
    if len(bc) != BYTECODE_LEN:
        raise RuntimeError("Bytecode slice failed (wrong offsets / wrong .so?)")
    return bc

BYTECODE = load_bytecode()

def vm_step(state):
    pc, key, cond, fail, stack, inp = state
    if pc >= len(BYTECODE):
        return ("eof", state)

    oldpc = pc
    b = BYTECODE[pc]
    pc += 1

    op = b ^ (key & 0xFF)
    if op not in OPS:
        return ("badop", (oldpc, op))

    kb = key & 0xFF

    if op == OP_PUSH_IMM32:
        imm_bytes = [BYTECODE[pc+i] ^ kb for i in range(4)]
        pc += 4
        imm = imm_bytes[0] | (imm_bytes[1] << 8) | (imm_bytes[2] << 16) | (imm_bytes[3] << 24)
        stack.append(imm & 0xFFFFFFFF)

    elif op == OP_PUSH_INP_LEN:
        stack.append(len(inp) & 0xFFFFFFFF)

    elif op == OP_PUSH_INP_BYTE:
        idx = (BYTECODE[pc] ^ kb) & 0xFF
        pc += 1
        if idx >= len(inp):
            return ("badidx", (oldpc, idx))
        v = inp[idx]
        if v is None:
            raise NeedByte(idx)
        stack.append(v & 0xFF)

    elif op == OP_DUP:
        if not stack:
            return ("stack_under", oldpc)
        stack.append(stack[-1])

    elif op == OP_ADD:
        b = stack.pop(); a = stack.pop()
        stack.append((a + b) & 0xFFFFFFFF)

    elif op == OP_SUB:
        b = stack.pop(); a = stack.pop()
        stack.append((a - b) & 0xFFFFFFFF)

    elif op == OP_XOR:
        b = stack.pop(); a = stack.pop()
        stack.append((a ^ b) & 0xFFFFFFFF)

    elif op == OP_OR:
        b = stack.pop(); a = stack.pop()
        stack.append((a | b) & 0xFFFFFFFF)

    elif op == OP_AND:
        b = stack.pop(); a = stack.pop()
        stack.append((a & b) & 0xFFFFFFFF)

    elif op == OP_ROL8:
        cnt = stack.pop() & 0xFF
        val = stack.pop() & 0xFF
        stack.append(rol8(val, cnt))

    elif op == OP_CMP:
        b = stack.pop(); a = stack.pop()
        cond = 1 if ((a & 0xFFFFFFFF) == (b & 0xFFFFFFFF)) else 0
        if cond == 0:
            fail |= 1

    elif op == OP_JMP:
        lo = BYTECODE[pc] ^ kb
        hi = BYTECODE[pc+1] ^ kb
        pc = oldpc + 3 + sign16(lo | (hi << 8))

    elif op == OP_JCC:
        lo = BYTECODE[pc] ^ kb
        hi = BYTECODE[pc+1] ^ kb
        pc = oldpc + 3
        if cond != 0:
            pc = pc + sign16(lo | (hi << 8))

    elif op in (OP_NOP1, OP_NOP2):
        pass

    elif op == OP_HALT:
        return ("halt", (fail == 0))

    # key update (đúng theo logic dưới đáy loop)
    stacklen8 = len(stack) & 0xFF
    key = ((key >> 3) ^ cond ^ stacklen8 ^ 0xA5A5A5A5) & 0xFFFFFFFF
    return ("ok", (pc, key, cond, fail, stack, inp))

def run_until_need(inp, max_steps=500000):
    state = (0, 0x64390CE0, 0, 0, [], inp)
    for steps in range(max_steps):
        try:
            status, out = vm_step(state)
        except NeedByte as e:
            return ("need", e.idx, steps)
        if status == "ok":
            state = out
            continue
        return (status, out, steps)
    return ("timeout", None, max_steps)

def solve():
    inp = [None] * 0x4B  # 75 bytes
    solved = {}

    while True:
        status, info, steps = run_until_need(inp)
        if status == "halt":
            # done
            flag = bytes(inp)
            print(flag.decode("utf-8", errors="replace"))
            return

        if status != "need":
            raise RuntimeError(f"VM ended unexpectedly: {status}, info={info}, steps={steps}")

        idx = info
        best = None

        for v in range(256):
            inp[idx] = v
            st2, info2, steps2 = run_until_need(inp)
            if st2 in ("need", "halt"):
                # pick the one that goes farthest
                score = steps2
                cand = (score, st2, v)
                if best is None or cand > best:
                    best = cand

        if best is None:
            raise RuntimeError(f"No candidate works for idx={idx}")

        _, _, chosen = best
        inp[idx] = chosen
        solved[idx] = chosen

if __name__ == "__main__":
    solve()
