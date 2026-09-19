import struct

from unicorn.arm64_const import UC_ARM64_REG_LR, UC_ARM64_REG_SP

from solve_neon import NeonHarness, RET, STACK, STACK_SIZE


ROOM_BASE = 0x40018
ROOM_SIZE = 0x40


def read_cstr(harness: NeonHarness, ptr: int) -> str:
    if ptr == 0:
        return ""
    out = bytearray()
    for i in range(512):
        b = harness.uc.mem_read(ptr + i, 1)[0]
        if b == 0:
            break
        out.append(b)
    return out.decode("ascii", "replace")


def read_string_obj(harness: NeonHarness, ptr: int) -> str:
    data_ptr, size = struct.unpack("<QQ", bytes(harness.uc.mem_read(ptr, 16)))
    return bytes(harness.uc.mem_read(data_ptr, size)).decode("ascii", "replace")


def main():
    h = NeonHarness()
    h.uc.reg_write(UC_ARM64_REG_SP, STACK + STACK_SIZE // 2)
    h.uc.reg_write(UC_ARM64_REG_LR, RET)
    h.uc.emu_start(0x3000, RET, count=80_000_000)

    for idx in range(7):
        base = ROOM_BASE + ROOM_SIZE * idx
        p0, p1, p2, p3 = struct.unpack("<QQQQ", bytes(h.uc.mem_read(base, 32)))
        room_id = h.uc.mem_read(base + 0x20, 1)[0]
        begin, end, cap = struct.unpack("<QQQ", bytes(h.uc.mem_read(base + 0x28, 24)))
        print(f"ROOM {idx} id={room_id} base={base:#x}")
        print(" name:", read_cstr(h, p0))
        print(" title:", read_cstr(h, p1))
        print(" desc:", read_cstr(h, p2))
        print(" objective:", read_cstr(h, p3))
        print(f" rows: begin={begin:#x} end={end:#x} cap={cap:#x} count={(end - begin) // 0x20}")
        for row_ptr in range(begin, end, 0x20):
            print("  " + read_string_obj(h, row_ptr))
        print()


if __name__ == "__main__":
    main()
