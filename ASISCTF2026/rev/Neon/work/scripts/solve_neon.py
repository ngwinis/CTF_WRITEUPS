import hashlib
import io
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from unicorn import UC_ARCH_ARM64, UC_HOOK_CODE, UC_MODE_ARM, UC_PROT_ALL, Uc, UcError
from unicorn.arm64_const import *


ROOT = Path(__file__).resolve().parents[1]
INNER = ROOT / "outputs" / "unpacked" / "app" / "last-cartridge.inner"
STAGE2_OUT = ROOT / "outputs" / "stage2.bin"
REPLAY_OUT = ROOT / "outputs" / "solution.tlrp"

PAGE = 0x1000
STACK = 0x7000000000
STACK_SIZE = 0x400000
HEAP = 0x6000000000
HEAP_SIZE = 0x4000000
DATA = 0x5000000000
DATA_SIZE = 0x200000
RET = 0x4FFF0000
CANARY = DATA + 0x180000

FIRST16 = [4, 8, 5, 1, 2, 9, 7, 4, 4, 2, 10, 4, 5, 2, 6, 4]
ACTION_NAMES = {
    1: "W",
    2: "S",
    3: "A",
    4: "D",
    5: "X",
    6: "SPACE",
    7: "R",
    8: "1",
    9: "2",
    10: "3",
    11: "E",
}


def obs_for(action: int) -> int:
    return action - 7 if 8 <= action <= 10 else 0


def make_replay(actions: list[int]) -> bytes:
    if len(actions) != 32:
        raise ValueError("expected exactly 32 actions")
    body = (
        b"TLRP"
        + bytes([1, 0])
        + struct.pack("<HHH", len(actions), 1, 0)
        + b"".join(bytes([a, obs_for(a)]) for a in actions)
        + struct.pack("<HHHH", 1, 6, 4, 1)
    )
    return body + struct.pack("<I", zlib.crc32(body) & 0xFFFFFFFF)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


@dataclass
class Snapshot:
    context: object
    stack_addr: int
    stack: bytes
    heap: bytes
    heap_cur: int
    trace_base: int


class NeonHarness:
    def __init__(self):
        self.file_bytes = INNER.read_bytes()
        self.elf = ELFFile(io.BytesIO(self.file_bytes))
        self.loads = []
        for seg in self.elf.iter_segments():
            if seg["p_type"] == "PT_LOAD":
                self.loads.append(
                    (seg["p_vaddr"], seg["p_memsz"], seg["p_offset"], seg["p_filesz"])
                )

        self.relative_relocs = []
        self.stack_guard_relocs = []
        dynsym = self.elf.get_section_by_name(".dynsym")
        for sec in self.elf.iter_sections():
            if not isinstance(sec, RelocationSection):
                continue
            for rel in sec.iter_relocations():
                typ = rel["r_info_type"]
                off = rel["r_offset"]
                add = rel["r_addend"] if rel.is_RELA() else 0
                if typ == 0x403:  # R_AARCH64_RELATIVE
                    self.relative_relocs.append((off, add))
                elif typ == 0x401 and dynsym:
                    name = dynsym.get_symbol(rel["r_info_sym"]).name
                    if name == "__stack_chk_guard":
                        self.stack_guard_relocs.append(off)

        relplt = self.elf.get_section_by_name(".rela.plt")
        plt = self.elf.get_section_by_name(".plt")
        dynsym = self.elf.get_section(relplt["sh_link"])
        self.plt = {
            plt["sh_addr"] + 0x20 + idx * 0x10: dynsym.get_symbol(rel["r_info_sym"]).name
            for idx, rel in enumerate(relplt.iter_relocations())
        }

        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.heap_cur = HEAP
        self.stop_reason = None
        self.target_row_start = None
        self.target_row_success = None
        self.row_starts = []
        self.max_row_success = -1
        self.hkdfs = {}
        self.next_hkdf_ctx = DATA + 0x1000
        self.aes = {}
        self.next_aes_ctx = DATA + 0x4000
        self.last_stage2 = b""
        self.aes_ok = False
        self.success_out = b""

        self._map_image()
        self._install_code_hooks()

    def _install_code_hooks(self):
        hook_points = set(self.plt)
        hook_points.update(
            {
                0x10F54,
                0x114B0,
                0x11854,
                0x11858,
                0x11C5C,
                0x1211C,
                0x12140,
                0x12218,
                0x12220,
                0x18A6C,
                0x18AB0,
                0x192A4,
                0x193F0,
                0x1B040,
            }
        )
        for address in sorted(hook_points):
            self.uc.hook_add(UC_HOOK_CODE, self._hook_code, None, address, address + 4)

    def _map_image(self):
        for va, memsz, off, filesz in self.loads:
            start = va & ~(PAGE - 1)
            end = (va + memsz + PAGE - 1) & ~(PAGE - 1)
            self.uc.mem_map(start, end - start, UC_PROT_ALL)
            self.uc.mem_write(va, self.file_bytes[off : off + filesz])
        self.uc.mem_map(STACK, STACK_SIZE, UC_PROT_ALL)
        self.uc.mem_map(HEAP, HEAP_SIZE, UC_PROT_ALL)
        self.uc.mem_map(DATA, DATA_SIZE, UC_PROT_ALL)
        self.uc.mem_map(RET & ~(PAGE - 1), PAGE, UC_PROT_ALL)
        for off, add in self.relative_relocs:
            self.uc.mem_write(off, struct.pack("<Q", add))
        for off in self.stack_guard_relocs:
            self.uc.mem_write(off, struct.pack("<Q", CANARY))
        self.uc.mem_write(CANARY, struct.pack("<Q", 0x1122334455667788))

    def _alloc(self, size: int) -> int:
        size = (int(size) + 15) & ~15
        ptr = self.heap_cur
        self.heap_cur += max(size, 16)
        if self.heap_cur >= HEAP + HEAP_SIZE:
            raise RuntimeError("heap exhausted")
        self.uc.mem_write(ptr, b"\0" * max(size, 16))
        return ptr

    def _stop(self, reason: str):
        self.stop_reason = reason
        self.uc.emu_stop()

    def _hook_code(self, uc, address, _size, _user):
        if address == 0x11C5C:
            row = uc.reg_read(UC_ARM64_REG_X20)
            self.row_starts.append(row)
            if self.target_row_start is not None and row >= self.target_row_start:
                trace_base = uc.reg_read(UC_ARM64_REG_X8)
                self._stop(f"row_start_{row}")
                self.trace_base = trace_base
                return

        if address == 0x12140:
            row = uc.reg_read(UC_ARM64_REG_X20)
            self.max_row_success = max(self.max_row_success, row)
            if self.target_row_success is not None and row >= self.target_row_success:
                self._stop(f"row_success_{row}")
                return

        if address == 0x1211C:
            row = uc.reg_read(UC_ARM64_REG_X20)
            self._stop(f"row_fail_{row}")
            return

        if address in (0x11854, 0x11858, 0x12220, 0x12218, 0x10F54):
            self._stop(f"fail_{address:x}")
            return

        if address == 0x114B0:
            self._stop("final_check")
            return

        if address == 0x18A6C:
            # The constructor initializes Vulkan resources. The CPU transform at
            # 0x18ae8 is deterministic and does not need the Vulkan object.
            uc.mem_write(uc.reg_read(UC_ARM64_REG_X0), struct.pack("<Q", 0))
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
            return

        if address in (0x18AB0, 0x192A4, 0x193F0, 0x1B040):
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
            return

        if address in self.plt:
            name = self.plt[address]
            self._handle_plt(name)
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))

    def _handle_plt(self, name: str):
        uc = self.uc
        x = lambda reg: uc.reg_read(reg)
        if name == "_Znwm":
            uc.reg_write(UC_ARM64_REG_X0, self._alloc(x(UC_ARM64_REG_X0)))
        elif name == "_ZdlPvm":
            return
        elif name in ("memcpy", "memmove"):
            dst, src, size = x(UC_ARM64_REG_X0), x(UC_ARM64_REG_X1), x(UC_ARM64_REG_X2)
            if size:
                uc.mem_write(dst, bytes(uc.mem_read(src, size)))
            uc.reg_write(UC_ARM64_REG_X0, dst)
        elif name == "memset":
            dst, val, size = x(UC_ARM64_REG_X0), x(UC_ARM64_REG_X1) & 0xFF, x(UC_ARM64_REG_X2)
            if size:
                uc.mem_write(dst, bytes([val]) * size)
            uc.reg_write(UC_ARM64_REG_X0, dst)
        elif name in ("bcmp", "CRYPTO_memcmp"):
            left, right, size = x(UC_ARM64_REG_X0), x(UC_ARM64_REG_X1), x(UC_ARM64_REG_X2)
            result = bytes(uc.mem_read(left, size)) != bytes(uc.mem_read(right, size))
            uc.reg_write(UC_ARM64_REG_W0, 1 if result else 0)
        elif name == "strlen":
            ptr = x(UC_ARM64_REG_X0)
            size = 0
            while uc.mem_read(ptr + size, 1)[0] != 0:
                size += 1
            uc.reg_write(UC_ARM64_REG_X0, size)
        elif name == "OPENSSL_cleanse":
            ptr, size = x(UC_ARM64_REG_X0), x(UC_ARM64_REG_X1)
            if size:
                uc.mem_write(ptr, b"\0" * size)
        elif name == "EVP_sha256":
            uc.reg_write(UC_ARM64_REG_X0, DATA + 0x2000)
        elif name == "EVP_Digest":
            ptr, size = x(UC_ARM64_REG_X0), x(UC_ARM64_REG_X1)
            out, outlen = x(UC_ARM64_REG_X2), x(UC_ARM64_REG_X3)
            digest = hashlib.sha256(bytes(uc.mem_read(ptr, size))).digest()
            uc.mem_write(out, digest)
            uc.mem_write(outlen, struct.pack("<I", len(digest)))
            uc.reg_write(UC_ARM64_REG_W0, 1)
        elif name == "EVP_PKEY_CTX_new_id":
            ctx = self.next_hkdf_ctx
            self.next_hkdf_ctx += 0x100
            self.hkdfs[ctx] = {}
            uc.reg_write(UC_ARM64_REG_X0, ctx)
        elif name in (
            "EVP_PKEY_derive_init",
            "EVP_PKEY_CTX_set_hkdf_mode",
            "EVP_PKEY_CTX_set_hkdf_md",
        ):
            uc.reg_write(UC_ARM64_REG_W0, 1)
        elif name == "EVP_PKEY_CTX_set1_hkdf_salt":
            ctx, ptr, size = x(UC_ARM64_REG_X0), x(UC_ARM64_REG_X1), x(UC_ARM64_REG_X2)
            self.hkdfs[ctx]["salt"] = bytes(uc.mem_read(ptr, size))
            uc.reg_write(UC_ARM64_REG_W0, 1)
        elif name == "EVP_PKEY_CTX_set1_hkdf_key":
            ctx, ptr, size = x(UC_ARM64_REG_X0), x(UC_ARM64_REG_X1), x(UC_ARM64_REG_X2)
            self.hkdfs[ctx]["key"] = bytes(uc.mem_read(ptr, size))
            uc.reg_write(UC_ARM64_REG_W0, 1)
        elif name == "EVP_PKEY_CTX_add1_hkdf_info":
            ctx, ptr, size = x(UC_ARM64_REG_X0), x(UC_ARM64_REG_X1), x(UC_ARM64_REG_X2)
            self.hkdfs[ctx]["info"] = bytes(uc.mem_read(ptr, size))
            uc.reg_write(UC_ARM64_REG_W0, 1)
        elif name == "EVP_PKEY_derive":
            ctx, out, len_ptr = x(UC_ARM64_REG_X0), x(UC_ARM64_REG_X1), x(UC_ARM64_REG_X2)
            size = struct.unpack("<Q", bytes(uc.mem_read(len_ptr, 8)))[0]
            state = self.hkdfs[ctx]
            key = HKDF(
                algorithm=hashes.SHA256(),
                length=size,
                salt=state.get("salt", b""),
                info=state.get("info", b""),
            ).derive(state.get("key", b""))
            uc.mem_write(out, key)
            uc.mem_write(len_ptr, struct.pack("<Q", size))
            uc.reg_write(UC_ARM64_REG_W0, 1)
        elif name == "EVP_PKEY_CTX_free":
            return
        elif name == "mmap":
            uc.reg_write(UC_ARM64_REG_X0, self._alloc(x(UC_ARM64_REG_X1)))
        elif name in ("mprotect", "munmap"):
            uc.reg_write(UC_ARM64_REG_W0, 0)
        elif name == "EVP_CIPHER_CTX_new":
            ctx = self.next_aes_ctx
            self.next_aes_ctx += 0x100
            self.aes[ctx] = {"aad": b"", "ct": b"", "out": 0, "ivlen": 12, "tag": b""}
            uc.reg_write(UC_ARM64_REG_X0, ctx)
        elif name == "EVP_CIPHER_CTX_free":
            return
        elif name == "EVP_aes_256_gcm":
            uc.reg_write(UC_ARM64_REG_X0, DATA + 0x3000)
        elif name == "EVP_DecryptInit_ex":
            ctx = x(UC_ARM64_REG_X0)
            key_ptr = x(UC_ARM64_REG_X3)
            iv_ptr = x(UC_ARM64_REG_X4)
            state = self.aes.setdefault(ctx, {"aad": b"", "ct": b"", "out": 0, "ivlen": 12})
            if key_ptr:
                state["key"] = bytes(uc.mem_read(key_ptr, 32))
            if iv_ptr:
                state["iv"] = bytes(uc.mem_read(iv_ptr, state.get("ivlen", 12)))
            uc.reg_write(UC_ARM64_REG_W0, 1)
        elif name == "EVP_CIPHER_CTX_ctrl":
            ctx = x(UC_ARM64_REG_X0)
            typ = x(UC_ARM64_REG_X1)
            arg = x(UC_ARM64_REG_X2)
            ptr = x(UC_ARM64_REG_X3)
            state = self.aes.setdefault(ctx, {"aad": b"", "ct": b"", "out": 0, "ivlen": 12})
            if typ == 9:
                state["ivlen"] = arg
            elif typ == 0x11:
                state["tag"] = bytes(uc.mem_read(ptr, arg))
            uc.reg_write(UC_ARM64_REG_W0, 1)
        elif name == "EVP_DecryptUpdate":
            ctx = x(UC_ARM64_REG_X0)
            out = x(UC_ARM64_REG_X1)
            outlen = x(UC_ARM64_REG_X2)
            inp = x(UC_ARM64_REG_X3)
            size = x(UC_ARM64_REG_X4)
            state = self.aes[ctx]
            chunk = bytes(uc.mem_read(inp, size)) if size else b""
            if out:
                state["ct"] += chunk
                state["out"] = out
                written = size
            else:
                state["aad"] += chunk
                written = 0
            if outlen:
                uc.mem_write(outlen, struct.pack("<I", written))
            uc.reg_write(UC_ARM64_REG_W0, 1)
        elif name == "EVP_DecryptFinal_ex":
            ctx = x(UC_ARM64_REG_X0)
            outlen = x(UC_ARM64_REG_X2)
            state = self.aes[ctx]
            try:
                plain = AESGCM(state["key"]).decrypt(
                    state["iv"], state["ct"] + state["tag"], state.get("aad", b"")
                )
                uc.mem_write(state["out"], plain)
                self.last_stage2 = plain
                self.aes_ok = True
                if outlen:
                    uc.mem_write(outlen, struct.pack("<I", 0))
                uc.reg_write(UC_ARM64_REG_W0, 1)
            except Exception:
                self.aes_ok = False
                if outlen:
                    uc.mem_write(outlen, struct.pack("<I", 0))
                uc.reg_write(UC_ARM64_REG_W0, 0)
        elif name.startswith("vk") or name.startswith("SDL"):
            self._stop(f"unexpected_ui_{name}")
        elif name == "__cxa_atexit":
            uc.reg_write(UC_ARM64_REG_W0, 0)
        elif name.startswith("_ZSt") or name.startswith("__cxa") or name in (
            "abort",
            "_Unwind_Resume",
            "__stack_chk_fail",
        ):
            self._stop(f"exception_{name}")
        else:
            self._stop(f"unimplemented_{name}")

    def restore(self, snap: Snapshot):
        self.uc.context_restore(snap.context)
        self.uc.mem_write(snap.stack_addr, snap.stack)
        if snap.heap:
            self.uc.mem_write(HEAP, snap.heap)
        self.heap_cur = snap.heap_cur
        self.trace_base = snap.trace_base
        self.stop_reason = None
        self.row_starts = []
        self.max_row_success = -1

    def snapshot(self) -> Snapshot:
        trace_base = getattr(self, "trace_base", self.uc.reg_read(UC_ARM64_REG_X8))
        sp = self.uc.reg_read(UC_ARM64_REG_SP)
        stack_addr = max(STACK, (sp - 0x4000) & ~(PAGE - 1))
        stack_end = min(STACK + STACK_SIZE, stack_addr + 0x7000)
        return Snapshot(
            self.uc.context_save(),
            stack_addr,
            bytes(self.uc.mem_read(stack_addr, stack_end - stack_addr)),
            bytes(self.uc.mem_read(HEAP, self.heap_cur - HEAP)),
            self.heap_cur,
            trace_base,
        )

    def patch_trace_action(self, index: int, action: int):
        row = struct.pack("<IIHBB", index, index, 0, action, obs_for(action))
        self.uc.mem_write(self.trace_base + index * 12, row)

    def patch_replay_state(self, replay: bytes):
        self.uc.mem_write(DATA + 0x10000, replay)
        sp = self.uc.reg_read(UC_ARM64_REG_SP)
        packed = [0] * (0x90 // 4)
        for index, value in enumerate(replay):
            packed[(index & ~3) // 4] |= value << ((index * 8) & 0x18)
        self.uc.mem_write(sp + 0x1C0, struct.pack("<" + "I" * len(packed), *packed))

    def decoded_extra(self) -> bytes:
        return xor_bytes(self.file_bytes[0x211FC:0x21214], self.file_bytes[0x21214:0x2122C])

    def setup_input(self, actions: list[int]):
        replay = make_replay(actions)
        raw = DATA + 0x10000
        obj = DATA + 0x30000
        out = DATA + 0x50000
        self.uc.mem_write(raw, replay)
        self.uc.mem_write(
            obj,
            struct.pack("<QQ", raw, len(replay))
            + self.decoded_extra()
            + b"\0" * (0x100 - 16 - len(self.decoded_extra())),
        )
        self.uc.mem_write(out, b"\0" * 0x200)
        self.uc.reg_write(UC_ARM64_REG_SP, STACK + STACK_SIZE // 2)
        self.uc.reg_write(UC_ARM64_REG_LR, RET)
        self.uc.reg_write(UC_ARM64_REG_X0, obj)
        self.uc.reg_write(UC_ARM64_REG_X8, out)
        return replay, out

    def run_to_row_start(self, actions: list[int], row: int) -> Snapshot:
        self.setup_input(actions)
        self.target_row_start = row
        self.target_row_success = None
        try:
            self.uc.emu_start(0x10A5C, RET, count=12_000_000)
        except UcError as err:
            raise RuntimeError(f"unicorn stopped at {self.uc.reg_read(UC_ARM64_REG_PC):#x}: {err}")
        if self.stop_reason != f"row_start_{row}":
            raise RuntimeError(f"did not reach row {row}: {self.stop_reason}")
        snap = self.snapshot()
        self.target_row_start = None
        return snap

    def run_from_snapshot_to_row(self, snap: Snapshot, index: int, action: int) -> Snapshot | None:
        self.restore(snap)
        self.patch_trace_action(index, action)
        self.target_row_start = index + 1
        self.target_row_success = None
        try:
            self.uc.emu_start(self.uc.reg_read(UC_ARM64_REG_PC), RET, count=1_500_000)
        except UcError:
            self.target_row_start = None
            return None
        self.target_row_start = None
        if self.stop_reason == f"row_start_{index + 1}":
            return self.snapshot()
        return None

    def run_full(self, actions: list[int]):
        self.setup_input(actions)
        self.target_row_start = None
        self.target_row_success = None
        self.stop_reason = None
        self.row_starts = []
        self.max_row_success = -1
        self.aes_ok = False
        self.last_stage2 = b""
        try:
            self.uc.emu_start(0x10A5C, RET, count=80_000_000)
        except UcError as err:
            self.stop_reason = f"ucerr_{err}_{self.uc.reg_read(UC_ARM64_REG_PC):x}"
        out = DATA + 0x50000
        self.success_out = bytes(self.uc.mem_read(out, 0x90))
        return self.stop_reason, self.aes_ok, self.max_row_success, self.success_out

    def run_suffix_from_snapshot(self, snap: Snapshot, suffix: list[int]):
        if len(suffix) != 15:
            raise ValueError("suffix must cover action indexes 16..30")
        self.restore(snap)
        replay = make_replay(FIRST16 + suffix + [11])
        self.patch_replay_state(replay)
        for index, action in enumerate(suffix, start=16):
            self.patch_trace_action(index, action)
        self.target_row_start = None
        self.target_row_success = None
        self.stop_reason = None
        self.aes_ok = False
        self.last_stage2 = b""
        try:
            self.uc.emu_start(self.uc.reg_read(UC_ARM64_REG_PC), RET, count=80_000_000)
        except UcError as err:
            self.stop_reason = f"ucerr_{err}_{self.uc.reg_read(UC_ARM64_REG_PC):x}"
        out = DATA + 0x50000
        self.success_out = bytes(self.uc.mem_read(out, 0x90))
        return self.stop_reason, self.aes_ok, self.max_row_success, self.success_out

    def finish_from_snapshot(self, snap: Snapshot):
        self.restore(snap)
        self.target_row_start = None
        self.target_row_success = None
        self.stop_reason = None
        self.aes_ok = False
        self.last_stage2 = b""
        try:
            self.uc.emu_start(self.uc.reg_read(UC_ARM64_REG_PC), RET, count=80_000_000)
        except UcError as err:
            self.stop_reason = f"ucerr_{err}_{self.uc.reg_read(UC_ARM64_REG_PC):x}"
        out = DATA + 0x50000
        self.success_out = bytes(self.uc.mem_read(out, 0x90))
        return self.stop_reason, self.aes_ok, self.max_row_success, self.success_out


def search_prefixes(limit: int = 5000) -> list[list[int]]:
    base_actions = FIRST16 + [5] * 15 + [11]
    harness = NeonHarness()
    base = harness.run_to_row_start(base_actions, 16)
    frontier: list[tuple[list[int], Snapshot]] = [([], base)]
    for index in range(16, 31):
        next_frontier: list[tuple[list[int], Snapshot]] = []
        for prefix, snap in frontier:
            for action in range(1, 11):
                child = harness.run_from_snapshot_to_row(snap, index, action)
                if child is not None:
                    next_frontier.append((prefix + [action], child))
        print(f"row {index}: {len(frontier)} -> {len(next_frontier)}")
        if not next_frontier:
            return []
        if len(next_frontier) > limit:
            print("frontier too large; keeping prefixes only")
            return [prefix for prefix, _ in next_frontier]
        frontier = next_frontier
    return [prefix for prefix, _ in frontier]


def feistel_check() -> int:
    mask = 0xFFFFFFFF
    a = [
        0x243F6A88,
        0x85A308D3,
        0x13198A2E,
        0x03707344,
        0xA4093822,
        0x299F31D0,
        0x082EFA98,
        0xEC4E6C89,
        0x452821E6,
        0x38D01377,
        0xBE5466CF,
        0x34E90C6C,
    ]
    b = [0x9E3779B1, 0x85EBCA77, 0xC2B2AE3D, 0x27D4EB2F]
    c = [5, 11, 17, 23, 7, 13, 19, 29, 3, 9, 15, 21]

    def ror(x: int, n: int) -> int:
        n &= 31
        x &= mask
        return ((x >> n) | ((x << (32 - n)) & mask)) & mask

    def div31ish(v: int) -> int:
        q = ((v & mask) * 0x08421085) >> 32
        q = (q + (((v - q) & mask) >> 1)) & mask
        return (v + (q >> 4)) & mask

    def fparts(right: int, i: int, key: int):
        f1 = ror(((a[i] ^ right) * b[i & 3] + key) & mask, (-c[i]) & mask)
        idx = i + 5 if i < 7 else i - 7
        f2 = ror((a[idx] + right) & mask, (~div31ish(c[i] + 0xB)) & mask)
        return f1, f2

    left = 0x6BEC7F69 ^ 0xC6EF3720
    right = 0xCF4FB92C ^ 0x54FF53A5
    keys = []
    key = 0xA511E9B3
    for _ in range(12):
        keys.append(key)
        key = (key + 0xA511E9B3) & mask
    for i in range(11, -1, -1):
        old_right = left
        f1, f2 = fparts(old_right, i, keys[i])
        old_left = right ^ f2 ^ f1
        left, right = old_left & mask, old_right & mask
    packed = ((left ^ 0xA5C3F17B) & mask) | (((right ^ 0x9E6D42C1) & mask) << 32)
    return packed


def main():
    packed = feistel_check()
    derived = [(packed >> (4 * i)) & 0xF for i in range(16)]
    print("first16:", derived)
    print("first16_keys:", " ".join(ACTION_NAMES[a] for a in derived))
    prefixes = search_prefixes()
    print("prefix_count:", len(prefixes))
    for prefix in prefixes[:20]:
        print("prefix:", prefix, "keys:", " ".join(ACTION_NAMES[a] for a in prefix))
    if len(prefixes) <= 2000:
        for prefix in prefixes:
            actions = FIRST16 + prefix + [11]
            harness = NeonHarness()
            reason, aes_ok, rows, out = harness.run_full(actions)
            if aes_ok or out[0] == 1:
                print("candidate:", actions)
                print("keys:", " ".join(ACTION_NAMES[a] for a in actions))
                print("reason:", reason, "aes_ok:", aes_ok, "rows:", rows)
                print("out:", out.hex())
                if harness.last_stage2:
                    STAGE2_OUT.write_bytes(harness.last_stage2)
                    print("stage2_sha256:", hashlib.sha256(harness.last_stage2).hexdigest())
                replay = make_replay(actions)
                REPLAY_OUT.write_bytes(replay)
                print("replay:", REPLAY_OUT)
                return


if __name__ == "__main__":
    main()
