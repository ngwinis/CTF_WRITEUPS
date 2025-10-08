# Paste this into IDA's Python console or save as dump_mz.py and run it.
import ida_bytes
import ida_segment
import ida_search
import idaapi
import os
import struct
import sys

# Output directory - change if you want
if os.name == "nt":
    out_dir = r"C:\\temp"
else:
    out_dir = "/tmp"

os.makedirs(out_dir, exist_ok=True)

def read_dword(ea):
    b = ida_bytes.get_bytes(ea, 4)
    if not b:
        return None
    return struct.unpack("<I", b)[0]

def try_dump_at(mz_ea, idx=0):
    # read e_lfanew at offset 0x3C
    e_lfanew = read_dword(mz_ea + 0x3C)
    if e_lfanew is None:
        print("  [!] cannot read e_lfanew at 0x{:X}".format(mz_ea))
        return False

    nt_header = mz_ea + e_lfanew
    # check 'PE\0\0' signature
    sig = ida_bytes.get_bytes(nt_header, 4)
    if sig != b'PE\x00\x00':
        print("  [!] no PE signature at expected NT headers (ea 0x{:X})".format(nt_header))
        # still continue with fallback
    # SizeOfImage is at: mz + e_lfanew + 0x50 (4 bytes) for both PE32/PE32+
    size_of_image_addr = mz_ea + e_lfanew + 0x50
    size_of_image = read_dword(size_of_image_addr)
    if not size_of_image or size_of_image == 0:
        print("  [!] invalid SizeOfImage read (0x{:X}), fallback to segment end".format(size_of_image_addr))
        # fallback: dump until segment end
        seg = ida_segment.getseg(mz_ea)
        if not seg:
            print("  [!] no segment for ea 0x{:X}".format(mz_ea))
            return False
        start = mz_ea
        end = seg.end_ea
        size = end - start
    else:
        start = mz_ea
        size = size_of_image

    # Make sure bytes are present in IDA for the whole range (may span segments)
    data = ida_bytes.get_bytes(start, size)
    if not data:
        # Try progressively smaller sizes (in case SizeOfImage too large)
        print("  [!] could not read {} bytes at 0x{:X}, trying smaller read...".format(size, start))
        # try until next segment boundary
        seg = ida_segment.getseg(start)
        if seg:
            size = seg.end_ea - start
            data = ida_bytes.get_bytes(start, size)
            if not data:
                print("  [!] failed to read even until seg end; aborting this candidate.")
                return False
        else:
            return False

    fname = os.path.join(out_dir, "myapp_dump_{:02d}.exe".format(idx))
    with open(fname, "wb") as f:
        f.write(data)
    print("  [+] dumped 0x{:X} bytes from 0x{:X} to {}".format(len(data), start, fname))
    return True

# find all 'MZ' occurrences in executable segments
found = list(ida_search.find_binary(ida_segment.get_segm_by_name(".text").start_ea if ida_segment.get_segm_by_name(".text") else 0,
                                   ida_segment.get_segm_by_name(".text").end_ea if ida_segment.get_segm_by_name(".text") else idaapi.BADADDR,
                                   "4D 5A", 16, ida_search.SEARCH_DOWN)) if False else None

# Better: scan all segments
idx = 0
for seg in ida_segment.get_segm_qty() and [ida_segment.getnseg(i) for i in range(ida_segment.get_segm_qty())] or []:
    if not seg:
        continue
    # only scan readable segments
    start = seg.start_ea
    end = seg.end_ea
    # search for bytes 0x4D 0x5A
    ea = ida_search.find_binary(start, end, "4D 5A", 16, ida_search.SEARCH_DOWN)
    while ea and ea != idaapi.BADADDR and ea < end:
        print("[*] candidate MZ at 0x{:X} (segment {})".format(ea, seg.name))
        ok = try_dump_at(ea, idx)
        idx += 1
        # find next MZ in this segment
        ea = ida_search.find_binary(ea+2, end, "4D 5A", 16, ida_search.SEARCH_DOWN)

# If nothing found via segments (older IDA builds), fallback to whole file search
if idx == 0:
    print("[*] no MZ found in segment scan, trying full memory search")
    ea = ida_search.find_binary(idaapi.BADADDR, idaapi.BADADDR, "4D 5A", 16, ida_search.SEARCH_DOWN)
    while ea and ea != idaapi.BADADDR:
        print("[*] candidate MZ at 0x{:X}".format(ea))
        try_dump_at(ea, idx)
        idx += 1
        ea = ida_search.find_binary(ea+2, idaapi.BADADDR, "4D 5A", 16, ida_search.SEARCH_DOWN)

print("[*] done. {} dump(s) attempted.".format(idx))
