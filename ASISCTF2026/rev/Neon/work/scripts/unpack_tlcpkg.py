import argparse
import os
import struct
import zlib
from pathlib import Path


MAGIC = b"TLCPKG14"
ENTRY = struct.Struct("<HHIQQQQ")


def safe_join(root: Path, name: str) -> Path:
    target = (root / name).resolve()
    root = root.resolve()
    if os.path.commonpath([str(root), str(target)]) != str(root):
        raise ValueError(f"unsafe archive path: {name!r}")
    return target


def unpack(package: Path, out_dir: Path) -> None:
    data = package.read_bytes()
    magic_at = data.rfind(MAGIC)
    if magic_at < 0:
        raise ValueError("TLCPKG14 footer not found")

    toc_off, toc_size, count = struct.unpack_from("<QQI", data, magic_at + len(MAGIC))
    if toc_off + toc_size != magic_at:
        raise ValueError("TOC bounds do not end at footer magic")

    pos = toc_off
    for index in range(count):
        name_len, flags, mode, off, comp_size, raw_size, crc = ENTRY.unpack_from(data, pos)
        pos += ENTRY.size
        name = data[pos : pos + name_len].decode("utf-8")
        pos += name_len

        comp = data[off : off + comp_size]
        raw = zlib.decompress(comp)
        if len(raw) != raw_size:
            raise ValueError(f"{name}: expected {raw_size} bytes, got {len(raw)}")
        got_crc = zlib.crc32(raw) & 0xFFFFFFFF
        if got_crc != (crc & 0xFFFFFFFF):
            raise ValueError(f"{name}: CRC mismatch {got_crc:08x} != {crc:08x}")

        target = safe_join(out_dir, name)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        if mode:
            try:
                target.chmod(mode)
            except OSError:
                pass
        print(
            f"{index:02d} {name} off=0x{off:x} comp=0x{comp_size:x} "
            f"raw=0x{raw_size:x} crc={got_crc:08x} flags={flags}"
        )

    if pos != magic_at:
        raise ValueError("TOC parse did not consume exactly to footer")


def main() -> None:
    parser = argparse.ArgumentParser(description="Unpack last-cartridge TLCPKG14 bundles")
    parser.add_argument("package", type=Path)
    parser.add_argument("out_dir", type=Path)
    args = parser.parse_args()
    unpack(args.package, args.out_dir)


if __name__ == "__main__":
    main()
