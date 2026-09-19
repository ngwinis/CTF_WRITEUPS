import argparse
import struct

from unicorn import UcError
from unicorn.arm64_const import (
    UC_ARM64_REG_LR,
    UC_ARM64_REG_SP,
    UC_ARM64_REG_W1,
    UC_ARM64_REG_W2,
    UC_ARM64_REG_X0,
)

from solve_neon import (
    ACTION_NAMES,
    DATA,
    FIRST16,
    NeonHarness,
    RET,
    STACK,
    STACK_SIZE,
    obs_for,
)


STATE = DATA + 0x80000


KEY_TO_ACTION = {v: k for k, v in ACTION_NAMES.items()}


def read_std_string(h: NeonHarness, ptr: int) -> str:
    data_ptr, size = struct.unpack("<QQ", bytes(h.uc.mem_read(ptr, 16)))
    try:
        raw = bytes(h.uc.mem_read(data_ptr, min(size, 512)))
    except UcError:
        raw = b""
    return raw.decode("ascii", "replace")


def call_func(h: NeonHarness, addr: int, *args: int, count: int = 80_000_000):
    h.stop_reason = None
    h.uc.reg_write(UC_ARM64_REG_SP, STACK + STACK_SIZE // 2)
    h.uc.reg_write(UC_ARM64_REG_LR, RET)
    regs = [UC_ARM64_REG_X0, UC_ARM64_REG_W1, UC_ARM64_REG_W2]
    for reg, val in zip(regs, args):
        h.uc.reg_write(reg, val)
    h.uc.emu_start(addr, RET, count=count)
    if h.stop_reason:
        raise RuntimeError(f"{addr:#x} stopped: {h.stop_reason}")


def dump_state(h: NeonHarness, label: str):
    cur_room = struct.unpack("<Q", bytes(h.uc.mem_read(STATE, 8)))[0]
    x, y = struct.unpack("<II", bytes(h.uc.mem_read(STATE + 0x20, 8)))
    msg = read_std_string(h, STATE + 0x28)
    acc = struct.unpack("<i", bytes(h.uc.mem_read(STATE + 0x4C, 4)))[0]
    f50, f51, f52, f53, f54, f55 = bytes(h.uc.mem_read(STATE + 0x50, 6))
    tick = struct.unpack("<I", bytes(h.uc.mem_read(STATE + 0x8C, 4)))[0]
    epoch = struct.unpack("<H", bytes(h.uc.mem_read(STATE + 0x90, 2)))[0]
    extra = bytes(h.uc.mem_read(STATE + 0x149C, 24)).hex()
    replay_begin, replay_end, replay_cap = struct.unpack(
        "<QQQ", bytes(h.uc.mem_read(STATE + 0xA0, 24))
    )
    roll_begin, roll_end, roll_cap = struct.unpack(
        "<QQQ", bytes(h.uc.mem_read(STATE + 0xB8, 24))
    )
    serialized = read_std_string(h, STATE + 0xD0)
    print(
        f"{label:<18} room={cur_room} pos=({x},{y}) "
        f"acc={acc} z={f50} carry={f51} stored={f52} ret={f53} obj={f54} done={f55} "
        f"tick={tick} epoch={epoch} replay={(replay_end - replay_begin)//2} roll={(roll_end - roll_begin)//8} "
        f"ser={len(serialized)} extra={extra} msg={msg!r}"
    )


def parse_actions(text: str) -> list[int]:
    if not text:
        return FIRST16
    out = []
    for tok in text.replace(",", " ").split():
        up = tok.upper()
        if up in KEY_TO_ACTION:
            out.append(KEY_TO_ACTION[up])
            continue
        if up.isdigit():
            val = int(up)
            if val in ACTION_NAMES:
                out.append(val)
                continue
        raise ValueError(f"unknown action token {tok!r}")
    return out


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--actions", default="")
    parser.add_argument("--room", type=int, default=0)
    args = parser.parse_args()
    actions = parse_actions(args.actions)

    h = NeonHarness()
    call_func(h, 0x3000)
    call_func(h, 0xD378, STATE)
    if args.room:
        call_func(h, 0xD9CC, STATE, args.room)
    dump_state(h, "init")
    for idx, action in enumerate(actions):
        call_func(h, 0xE198, STATE, action, obs_for(action))
        dump_state(h, f"{idx:02d}:{ACTION_NAMES[action]}")


if __name__ == "__main__":
    main()
