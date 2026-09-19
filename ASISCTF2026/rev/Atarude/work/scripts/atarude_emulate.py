#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
import struct

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_PROT_ALL, UcError
from unicorn.x86_const import (
    UC_X86_REG_RAX,
    UC_X86_REG_RBX,
    UC_X86_REG_RCX,
    UC_X86_REG_RDI,
    UC_X86_REG_RDX,
    UC_X86_REG_RIP,
    UC_X86_REG_RSI,
    UC_X86_REG_RSP,
    UC_X86_REG_R8,
    UC_X86_REG_R12,
    UC_X86_REG_R14,
    UC_X86_REG_R15,
)


ROOT = Path(__file__).resolve().parents[2]
ELF = ROOT / "work" / "evidence" / "archive_contents" / "Atarude" / "Atarude"
FLAG_ENC = ROOT / "work" / "evidence" / "archive_contents" / "Atarude" / "flag.enc"

C24570 = 0xC24570
C267C0 = 0xC267C0
C28E80 = 0xC28E80
C29BF0 = 0xC29BF0
C2A98C = 0xC2A98C
C255C0 = 0xC255C0
RET = 0x4FFF000

STUB_MEMCPY = 0x5000000
STUB_FREE = 0x5000100
STUB_MALLOC = 0x5000200
STUB_MEMSET = 0x5000300

STACK = 0x7000000
STACK_SIZE = 0x400000
HEAP = 0x8000000
HEAP_SIZE = 0x800000
SCRATCH = 0x9000000
SCRATCH_SIZE = 0x200000

GOT_MEMCPY = 0xC7B9E8
GOT_FREE = 0xC7B9F0
GOT_MALLOC = 0xC7B9F8
GOT_MEMSET = 0xC7BA00

TARGET_GATE = bytes.fromhex("10fe0df1471d48b5226d8b3b9e3559f3")


def align_up(x: int, a: int = 0x1000) -> int:
    return (x + a - 1) & ~(a - 1)


class Core:
    def __init__(self) -> None:
        self.data = ELF.read_bytes()
        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        self._load_elf()
        self.uc.mem_map(RET & ~0xFFF, 0x1000, UC_PROT_ALL)
        self.uc.mem_map(STUB_MEMCPY, 0x4000, UC_PROT_ALL)
        self.uc.mem_map(STACK, STACK_SIZE, UC_PROT_ALL)
        self.uc.mem_map(HEAP, HEAP_SIZE, UC_PROT_ALL)
        self.uc.mem_map(SCRATCH, SCRATCH_SIZE, UC_PROT_ALL)
        self.uc.mem_write(GOT_MEMCPY, STUB_MEMCPY.to_bytes(8, "little"))
        self.uc.mem_write(GOT_FREE, STUB_FREE.to_bytes(8, "little"))
        self.uc.mem_write(GOT_MALLOC, STUB_MALLOC.to_bytes(8, "little"))
        self.uc.mem_write(GOT_MEMSET, STUB_MEMSET.to_bytes(8, "little"))
        self.heap_next = HEAP
        self.uc.hook_add(UC_HOOK_CODE, self._hook_code, begin=STUB_MEMCPY, end=STUB_MEMSET + 0x100)

    def _load_elf(self) -> None:
        if self.data[:4] != b"\x7fELF" or self.data[4] != 2 or self.data[5] != 1:
            raise ValueError("expected a little-endian ELF64")

        e_phoff = struct.unpack_from("<Q", self.data, 0x20)[0]
        e_shoff = struct.unpack_from("<Q", self.data, 0x28)[0]
        e_phentsize = struct.unpack_from("<H", self.data, 0x36)[0]
        e_phnum = struct.unpack_from("<H", self.data, 0x38)[0]
        e_shentsize = struct.unpack_from("<H", self.data, 0x3A)[0]
        e_shnum = struct.unpack_from("<H", self.data, 0x3C)[0]
        e_shstrndx = struct.unpack_from("<H", self.data, 0x3E)[0]

        loads = []
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            p_type, _p_flags, p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, _p_align = struct.unpack_from(
                "<IIQQQQQQ", self.data, off
            )
            if p_type == 1:
                loads.append((p_offset, p_vaddr, p_filesz, p_memsz))
        max_vaddr = max(vaddr + memsz for _off, vaddr, _filesz, memsz in loads)
        self.uc.mem_map(0, align_up(max_vaddr + 0x1000), UC_PROT_ALL)
        for p_offset, p_vaddr, p_filesz, p_memsz in loads:
            if p_filesz:
                self.uc.mem_write(p_vaddr, self.data[p_offset : p_offset + p_filesz])
            if p_memsz > p_filesz:
                self.uc.mem_write(p_vaddr + p_filesz, b"\x00" * (p_memsz - p_filesz))

        if e_shoff and e_shnum and e_shstrndx != 0xFFFF:
            shstr_off = e_shoff + e_shstrndx * e_shentsize
            shstr = struct.unpack_from("<IIQQQQIIQQ", self.data, shstr_off)
            shstr_data = self.data[shstr[4] : shstr[4] + shstr[5]]
            for i in range(e_shnum):
                off = e_shoff + i * e_shentsize
                sh_name, sh_type, _sh_flags, _sh_addr, sh_offset, sh_size, _sh_link, _sh_info, _sh_addralign, sh_entsize = struct.unpack_from(
                    "<IIQQQQIIQQ", self.data, off
                )
                end = shstr_data.find(b"\x00", sh_name)
                name = shstr_data[sh_name:end].decode("ascii", "replace") if end != -1 else ""
                if name != ".rela.dyn" or sh_type != 4:
                    continue
                entsize = sh_entsize or 24
                for rel_off in range(sh_offset, sh_offset + sh_size, entsize):
                    r_offset, r_info, r_addend = struct.unpack_from("<QQq", self.data, rel_off)
                    r_type = r_info & 0xFFFFFFFF
                    if r_type == 8:  # R_X86_64_RELATIVE with load base 0
                        self.uc.mem_write(r_offset, struct.pack("<Q", r_addend & 0xFFFFFFFFFFFFFFFF))

    def _ret(self) -> None:
        rsp = self.uc.reg_read(UC_X86_REG_RSP)
        ret = int.from_bytes(self.uc.mem_read(rsp, 8), "little")
        self.uc.reg_write(UC_X86_REG_RSP, rsp + 8)
        self.uc.reg_write(UC_X86_REG_RIP, ret)

    def _hook_code(self, uc: Uc, address: int, size: int, user_data: object) -> None:
        if address == STUB_MALLOC:
            n = uc.reg_read(UC_X86_REG_RDI)
            ptr = align_up(self.heap_next, 0x10)
            self.heap_next = ptr + align_up(max(n, 1), 0x10)
            if self.heap_next >= HEAP + HEAP_SIZE:
                raise RuntimeError("emulated heap exhausted")
            uc.mem_write(ptr, b"\x00" * n)
            uc.reg_write(UC_X86_REG_RAX, ptr)
            self._ret()
        elif address == STUB_FREE:
            self._ret()
        elif address == STUB_MEMCPY:
            dst = uc.reg_read(UC_X86_REG_RDI)
            src = uc.reg_read(UC_X86_REG_RSI)
            n = uc.reg_read(UC_X86_REG_RDX)
            uc.mem_write(dst, bytes(uc.mem_read(src, n)))
            uc.reg_write(UC_X86_REG_RAX, dst)
            self._ret()
        elif address == STUB_MEMSET:
            dst = uc.reg_read(UC_X86_REG_RDI)
            val = uc.reg_read(UC_X86_REG_RSI) & 0xFF
            n = uc.reg_read(UC_X86_REG_RDX)
            uc.mem_write(dst, bytes([val]) * n)
            uc.reg_write(UC_X86_REG_RAX, dst)
            self._ret()

    def _setup_stack(self) -> int:
        sp = STACK + STACK_SIZE - 0x10000
        sp &= ~0xF
        self.uc.mem_write(STACK, b"\x00" * STACK_SIZE)
        self.uc.reg_write(UC_X86_REG_RSP, sp)
        self.uc.mem_write(sp, RET.to_bytes(8, "little"))
        return sp

    def run(self, start: int, end: int = RET, timeout: int = 0, count: int = 0) -> None:
        try:
            self.uc.emu_start(start, end, timeout=timeout, count=count)
        except UcError as exc:
            rip = self.uc.reg_read(UC_X86_REG_RIP)
            rsp = self.uc.reg_read(UC_X86_REG_RSP)
            regs = {
                "rax": self.uc.reg_read(UC_X86_REG_RAX),
                "rbx": self.uc.reg_read(UC_X86_REG_RBX),
                "rcx": self.uc.reg_read(UC_X86_REG_RCX),
                "rdx": self.uc.reg_read(UC_X86_REG_RDX),
                "rsi": self.uc.reg_read(UC_X86_REG_RSI),
                "rdi": self.uc.reg_read(UC_X86_REG_RDI),
                "r8": self.uc.reg_read(UC_X86_REG_R8),
                "r12": self.uc.reg_read(UC_X86_REG_R12),
                "r14": self.uc.reg_read(UC_X86_REG_R14),
            }
            reg_text = " ".join(f"{k}={v:#x}" for k, v in regs.items())
            raise RuntimeError(
                f"unicorn stopped at rip={rip:#x} rsp={rsp:#x}: {exc}\n"
                f"regs: {reg_text}"
            ) from exc

    def c24570(self, seed: int, blocks: bytes) -> bytes:
        assert len(blocks) % 16 == 0
        sp = self._setup_stack()
        inp = SCRATCH
        out = SCRATCH + 0x10000
        self.uc.mem_write(inp, blocks)
        self.uc.mem_write(out, b"\x00" * 16)
        self.uc.reg_write(UC_X86_REG_RDI, out)
        self.uc.reg_write(UC_X86_REG_RSI, seed)
        self.uc.reg_write(UC_X86_REG_RDX, inp)
        self.uc.reg_write(UC_X86_REG_RCX, len(blocks) // 16)
        self.run(C24570)
        return bytes(self.uc.mem_read(out, 16))

    def c267c0(self, record: bytes, index: int) -> bytes:
        assert len(record) == 0xB0
        sp = self._setup_stack()
        rec = SCRATCH
        out = SCRATCH + 0x10000
        self.uc.mem_write(rec, record)
        self.uc.mem_write(out, b"\x00" * 0xB0)
        self.uc.reg_write(UC_X86_REG_RDI, out)
        self.uc.reg_write(UC_X86_REG_RSI, rec)
        self.uc.reg_write(UC_X86_REG_RDX, index)
        self.run(C267C0)
        return bytes(self.uc.mem_read(out, 0xB0))

    def expected_e_input(self, index: int, oracle_count: int = 0) -> bytes:
        sp = self._setup_stack()
        main_sp = sp
        dummy = SCRATCH + 0x20000
        self.uc.mem_write(dummy, b"\x00" * 0xA0)
        self.uc.mem_write(main_sp + 0x40, index.to_bytes(8, "little"))
        self.uc.mem_write(main_sp + 0xD8, dummy.to_bytes(8, "little"))
        self.uc.mem_write(main_sp + 0xE0, (0xA0).to_bytes(8, "little"))
        self.uc.reg_write(UC_X86_REG_R12, index * 3)
        self.uc.reg_write(UC_X86_REG_R14, oracle_count)
        self.uc.reg_write(UC_X86_REG_RCX, 0)
        self.run(C28E80, C29BF0)
        return bytes(self.uc.mem_read(main_sp + 0xD0, 0xA0))

    def e_record(self, index: int, oracle_count: int = 0) -> bytes:
        expected = self.expected_e_input(index, oracle_count)
        return self.record_for_plaintext(index, expected)

    def record_for_plaintext(self, index: int, plaintext: bytes) -> bytes:
        assert len(plaintext) == 0xA0
        sp = self._setup_stack()
        main_sp = sp
        inp = SCRATCH + 0x30000
        self.uc.mem_write(inp, plaintext)
        self.uc.mem_write(main_sp + 0xD0, plaintext)
        self.uc.mem_write(main_sp + 0x40, index.to_bytes(8, "little"))
        self.uc.mem_write(main_sp + 0x58, inp.to_bytes(8, "little"))
        self.uc.reg_write(UC_X86_REG_R15, main_sp + 0xD0)
        self.run(C29BF0, C2A98C)
        rec = self.uc.reg_read(UC_X86_REG_R12)
        return bytes(self.uc.mem_read(rec, 0xB0))

    def c255c0(self, blocks: bytes, flag_enc: bytes) -> tuple[int, bytes, int, int]:
        assert len(blocks) % 16 == 0
        sp = self._setup_stack()
        inp = SCRATCH
        flag = SCRATCH + 0x20000
        out = SCRATCH + 0x30000
        self.uc.mem_write(inp, blocks)
        self.uc.mem_write(flag, flag_enc)
        self.uc.mem_write(out, b"\x00" * 0x40)
        self.uc.reg_write(UC_X86_REG_RDI, out)
        self.uc.reg_write(UC_X86_REG_RSI, inp)
        self.uc.reg_write(UC_X86_REG_RDX, len(blocks) // 16)
        self.uc.reg_write(UC_X86_REG_RCX, flag)
        self.uc.reg_write(UC_X86_REG_R8, len(flag_enc))
        self.run(C255C0)
        q0 = int.from_bytes(self.uc.mem_read(out, 8), "little")
        q1 = int.from_bytes(self.uc.mem_read(out + 8, 8), "little")
        q2 = int.from_bytes(self.uc.mem_read(out + 16, 8), "little")
        if q0 == 0x8000000000000000:
            return q0, b"", q1, q2
        # Most Rust Vec layouts in this binary are cap, ptr, len.
        ptr = q1
        n = q2
        if ptr == 0 or n > 0x10000:
            return q0, b"", q1, q2
        return q0, bytes(self.uc.mem_read(ptr, n)), q1, q2


def xor_block(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def make_s_from_e(core: Core, rec: bytes, index: int) -> tuple[bytes, bytes]:
    out = core.c267c0(rec, index)
    forged = bytearray(rec)
    forged[:16] = xor_block(forged[:16], out[:16])
    check = core.c267c0(bytes(forged), index)
    assert check[:16] == b"\x00" * 16
    return bytes(forged), out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dump", action="store_true")
    args = ap.parse_args()

    expected = []
    e_records = []
    s_records = []
    for i in range(6):
        exp = Core().expected_e_input(i, 0)
        rec = Core().e_record(i, 0)
        forged, out = make_s_from_e(Core(), rec, i)
        expected.append(exp)
        e_records.append(rec)
        s_records.append(forged)
        print(f"idx={i} e_input={exp.hex()}")
        print(f"idx={i} e_record={rec.hex()}")
        print(f"idx={i} c267c0(e)[0]={out[:16].hex()}")
        print(f"idx={i} s_record={forged.hex()}")

    final_blocks = b"".join(s_records)
    gate = Core().c24570(0x5F, final_blocks)
    print(f"gate={gate.hex()}")
    print(f"target={TARGET_GATE.hex()}")
    print(f"gate_ok={gate == TARGET_GATE}")

    q0, plain, q1, q2 = Core().c255c0(final_blocks, FLAG_ENC.read_bytes())
    print(f"c255c0_q0={q0:016x} q1={q1:016x} q2={q2:016x}")
    if plain:
        print(f"plaintext={plain!r}")
        try:
            print(plain.decode())
        except UnicodeDecodeError:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
