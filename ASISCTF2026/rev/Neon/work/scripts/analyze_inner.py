import argparse
import bisect
import struct
from pathlib import Path

from capstone import CS_ARCH_AARCH64, CS_MODE_LITTLE_ENDIAN, CS_OP_IMM, CS_OP_MEM, Cs
from capstone.aarch64_const import AARCH64_OP_IMM, AARCH64_OP_MEM
from elftools.elf.elffile import ELFFile


def load_elf(path: Path):
    f = path.open("rb")
    elf = ELFFile(f)
    sections = {sec.name: sec for sec in elf.iter_sections()}
    return f, elf, sections


def parse_plt(elf, sections):
    rel = sections[".rela.plt"]
    dynsym = elf.get_section(rel["sh_link"])
    plt = sections[".plt"]
    out = {}
    for idx, reloc in enumerate(rel.iter_relocations()):
        sym = dynsym.get_symbol(reloc["r_info_sym"])
        out[plt["sh_addr"] + 0x20 + idx * 0x10] = sym.name
    return out


def parse_eh_frame_hdr(sections):
    hdr = sections[".eh_frame_hdr"]
    data = hdr.data()
    base = hdr["sh_addr"]
    if data[:4] != bytes([1, 0x1B, 0x03, 0x3B]):
        return []
    count = struct.unpack_from("<I", data, 8)[0]
    starts = []
    pos = 12
    for _ in range(count):
        loc_rel, _fde_rel = struct.unpack_from("<ii", data, pos)
        starts.append(base + loc_rel)
        pos += 8
    return sorted(set(starts))


def read_cstrings(data, sec):
    start = sec["sh_addr"]
    raw = sec.data()
    strings = []
    i = 0
    while i < len(raw):
        if 32 <= raw[i] < 127:
            j = i
            while j < len(raw) and 32 <= raw[j] < 127:
                j += 1
            if j - i >= 4:
                strings.append((start + i, raw[i:j].decode("ascii", "replace")))
            i = j
        i += 1
    return strings


def string_at(strings, addr):
    addrs = [x[0] for x in strings]
    idx = bisect.bisect_right(addrs, addr) - 1
    if idx < 0:
        return None
    saddr, text = strings[idx]
    if saddr <= addr < saddr + len(text):
        return saddr, text[addr - saddr :]
    return None


def disasm_text(sections):
    text = sections[".text"]
    md = Cs(CS_ARCH_AARCH64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    return list(md.disasm(text.data(), text["sh_addr"]))


def op_imm(op):
    return op.imm if op.type in (CS_OP_IMM, AARCH64_OP_IMM) else None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("inner", type=Path)
    parser.add_argument("--around", type=lambda x: int(x, 0))
    parser.add_argument("--bytes", type=lambda x: int(x, 0), default=0x180)
    args = parser.parse_args()

    f, elf, sections = load_elf(args.inner)
    try:
        plt = parse_plt(elf, sections)
        starts = parse_eh_frame_hdr(sections)
        rostrings = read_cstrings(f.read(), sections[".rodata"])
        insns = disasm_text(sections)
        by_addr = {i.address: i for i in insns}

        if args.around is not None:
            lo = args.around
            hi = args.around + args.bytes
            for insn in insns:
                if lo <= insn.address < hi:
                    note = ""
                    if insn.mnemonic == "bl" and insn.operands:
                        imm = op_imm(insn.operands[0])
                        if imm in plt:
                            note = f" ; {plt[imm]}"
                        elif imm is not None:
                            note = f" ; call {imm:#x}"
                    print(f"{insn.address:08x}: {insn.mnemonic:<8} {insn.op_str}{note}")
            return

        print("functions_from_eh_frame", len(starts))
        for s in starts:
            print(f"FUNC {s:#x}")
        print("\nimport calls")
        for insn in insns:
            if insn.mnemonic == "bl" and insn.operands:
                imm = op_imm(insn.operands[0])
                if imm in plt:
                    print(f"{insn.address:#x} {plt[imm]}")

        print("\nlikely rodata xrefs")
        regs = {}
        for insn in insns:
            if insn.mnemonic == "adrp" and len(insn.operands) >= 2:
                regs[insn.operands[0].reg] = op_imm(insn.operands[1])
                continue
            if insn.mnemonic == "add" and len(insn.operands) >= 3:
                dst, src, immop = insn.operands[:3]
                if src.reg in regs and immop.type in (CS_OP_IMM, AARCH64_OP_IMM):
                    addr = regs[src.reg] + immop.imm
                    hit = string_at(rostrings, addr)
                    if hit:
                        saddr, text = hit
                        print(f"{insn.address:#x} -> {saddr:#x} {text[:100]!r}")
                continue
            if insn.mnemonic.startswith("ldr") and len(insn.operands) >= 2:
                mem = insn.operands[1]
                if mem.type in (CS_OP_MEM, AARCH64_OP_MEM) and mem.mem.base in regs:
                    addr = regs[mem.mem.base] + mem.mem.disp
                    hit = string_at(rostrings, addr)
                    if hit:
                        saddr, text = hit
                        print(f"{insn.address:#x} -> {saddr:#x} {text[:100]!r}")
    finally:
        f.close()


if __name__ == "__main__":
    main()
