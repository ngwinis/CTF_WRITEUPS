#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
solve.py — loader đa chữ ký cho decrypt_flag_file trong libnative.{so|dll}

Chiến lược:
1) Tải libnative (ưu tiên libnative.so, fallback libnative.dll).
2) Thử lần lượt các prototype phổ biến của decrypt_flag_file:
   A) int f(const char* in_path, void** out_ptr, int* out_len)
   B) int f(const char* in_path, void* out_buf, int max_len)
   C) void* f(const char* in_path, int* out_len)
   D) int f(const char* in_path)  -> chương trình có thể tự ghi ra file (flag.txt/flag.dec/flag.out)

3) Nếu có hàm free_mem, tự động giải phóng.
4) Ghi plaintext ra flag.dec và in ra màn hình (nếu là ASCII/UTF-8).

Ghi chú:
- Script KHÔNG phụ thuộc môi trường OpenSSL của bạn, chỉ dùng ctypes.
- Nếu lib có anti-debug/check_integrity, chỉ cần nó không chặn call giải mã
  thì script vẫn trích được flag. Nếu cần tham số cho check_integrity, thêm ở phần call_optional_checks().

"""

import sys
import os
import argparse
import ctypes
from ctypes import (
    CDLL, c_char_p, c_int, c_void_p, POINTER,
    create_string_buffer
)
from pathlib import Path

def locate_lib(base_dir: Path):
    # Ưu tiên .so, sau đó .dll (dành cho Windows)
    cand = [base_dir / "main_extracted/libnative.so", base_dir / "libnative.dll"]
    for p in cand:
        if p.exists():
            return p
    raise FileNotFoundError("Không tìm thấy libnative.so hoặc libnative.dll trong thư mục làm việc.")

def call_optional_checks(lib):
    """
    Một số binary yêu cầu qua check_integrity trước khi cho decrypt.
    Nếu thấy symbol 'check_integrity', ta gọi thử với tham số rỗng/placeholder.
    Nếu không có, bỏ qua.
    """
    for name in ("check_integrity", "CheckIntegrity", "integrity_check"):
        fn = getattr(lib, name, None)
        if fn is None:
            continue
        try:
            fn.argtypes = [c_char_p]
            fn.restype  = c_int
            rc = fn(b"")  # tuỳ binary, có thể cần chuỗi khác. Thường rỗng/placeholder là đủ.
            # Không ép buộc rc==0/1… chỉ cần gọi để lib "khởi động" trạng thái nếu nó cần.
        except Exception:
            pass

def try_decrypt_through_variants(lib, enc_path: Path):
    """
    Thử 4 biến thể chữ ký thường thấy cho decrypt_flag_file.
    Trả về (data: bytes, how: str).
    """
    names = [
        "decrypt_flag_file", "decrypt_flag", "decrypt_file",
        "DecryptFlagFile", "DecryptFlag", "dec_flag_file"
    ]

    # Tìm free_mem (nếu có)
    free_fn = None
    for cand in ("free_mem", "FreeMem", "release_mem", "destroy_buf", "free"):
        free_fn = getattr(lib, cand, None)
        if free_fn:
            try:
                free_fn.argtypes = [c_void_p]
                free_fn.restype = None
                break
            except Exception:
                free_fn = None

    in_path_b = str(enc_path).encode()

    for nm in names:
        fn = getattr(lib, nm, None)
        if fn is None:
            continue

        # Variant A: int f(const char* in_path, void** out_ptr, int* out_len)
        try:
            fn.argtypes = [c_char_p, POINTER(c_void_p), POINTER(c_int)]
            fn.restype  = c_int
            out_ptr = c_void_p()
            out_len = c_int(0)
            rc = fn(in_path_b, ctypes.byref(out_ptr), ctypes.byref(out_len))
            if rc == 0 and out_ptr.value and out_len.value > 0:
                data = ctypes.string_at(out_ptr.value, out_len.value)
                if free_fn:
                    try:
                        free_fn(out_ptr)
                    except Exception:
                        pass
                return data, f"{nm}:A"
        except Exception:
            pass

        # Variant B: int f(const char* in_path, void* out_buf, int max_len)
        try:
            MAX = 1 << 20  # 1MB buffer tạm
            buf = create_string_buffer(MAX)
            fn.argtypes = [c_char_p, c_void_p, c_int]
            fn.restype  = c_int
            rc = fn(in_path_b, buf, MAX)
            if rc > 0:
                data = bytes(buf[:rc])
                return data, f"{nm}:B"
        except Exception:
            pass

        # Variant C: void* f(const char* in_path, int* out_len)
        try:
            fn.argtypes = [c_char_p, POINTER(c_int)]
            fn.restype  = c_void_p
            out_len = c_int(0)
            ptr = fn(in_path_b, ctypes.byref(out_len))
            if ptr and out_len.value > 0:
                data = ctypes.string_at(ptr, out_len.value)
                if free_fn:
                    try:
                        free_fn(ptr)
                    except Exception:
                        pass
                return data, f"{nm}:C"
        except Exception:
            pass

        # Variant D: int f(const char* in_path) -> chương trình có thể tự ghi file
        try:
            fn.argtypes = [c_char_p]
            fn.restype  = c_int
            rc = fn(in_path_b)
            # Thử đọc một số tên file thường dùng
            for cand in ("flag.txt", "flag.dec", "flag.out"):
                outp = enc_path.parent / cand
                if outp.exists() and outp.stat().st_size > 0:
                    return outp.read_bytes(), f"{nm}:D->{cand}"
        except Exception:
            pass

    return None, None

def main():
    ap = argparse.ArgumentParser(description="Trích xuất flag từ libnative và flag.enc bằng ctypes")
    ap.add_argument("-l", "--lib", type=Path, help="Đường dẫn libnative.so/dll (mặc định: ./libnative.so|.dll)")
    ap.add_argument("-i", "--input", type=Path, default=Path("flag.enc"), help="Đường dẫn flag.enc (mặc định: ./flag.enc)")
    ap.add_argument("-o", "--output", type=Path, default=Path("flag.dec"), help="File xuất plaintext (mặc định: ./flag.dec)")
    args = ap.parse_args()

    enc_path = args.input.resolve()
    if not enc_path.exists():
        sys.exit(f"[!] Không thấy input: {enc_path}")

    lib_path = args.lib.resolve() if args.lib else locate_lib(Path.cwd())
    try:
        lib = CDLL(str(lib_path))
    except OSError as e:
        # Trường hợp lỗi GLIBC version mismatch trên môi trường container,
        # hãy chạy script này trực tiếp trên máy bạn – nơi lib được build.
        sys.exit(f"[!] Lỗi khi nạp thư viện: {e}\n"
                 f"    → Hãy chạy script trên cùng hệ với binary (khớp GLIBC/CRT).")

    # Gọi optional check nếu có
    call_optional_checks(lib)

    data, how = try_decrypt_through_variants(lib, enc_path)
    if not data:
        sys.exit("[!] Không gọi được decrypt_flag_file với các chữ ký phổ biến. "
                 "Hãy mở libnative trong IDA/Ghidra để xác nhận prototype chính xác.")

    # Lưu output
    args.output.write_bytes(data)
    print(f"[+] Đã lưu plaintext → {args.output} (len={len(data)})")
    # In preview nếu có thể
    try:
        text = data.decode()
        print("[+] Preview (UTF-8):", text)
    except UnicodeDecodeError:
        # Không phải text thuần – vẫn có thể là flag dạng nhị phân hoặc cần parse thêm
        print("[i] Plaintext không phải UTF-8 thuần. Mở file để xem nội dung.")

    print(f"[i] Cách trích: {how}")

if __name__ == "__main__":
    main()
