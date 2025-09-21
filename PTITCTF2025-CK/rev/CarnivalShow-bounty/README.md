# Carnival Show

## [1] TỔNG QUAN
- Đề bài:

    ![alt text](../../images/carnivalshow01.png)

## [2] PHÂN TÍCH
### [2.1] Logic chính của chương trình:
- Mình mở bảng strings trong IDA và tìm thì thấy có 1 string khá quen thuộc `"Correct!"` và `"Nope."` nên mình focus vào đó thì mình thấy luôn logic chính của chương trình nằm tại hàm `sub_1300()`
- Đây chính là chỗ nhập input:
    
    ![alt text](../../images/carnivalshow02.png)

- Ngay phía dưới chính là logic check flag và in ra màn hình thông báo correct hoặc nope.

    ![alt text](../../images/carnivalshow03.png)

- Từ đó có thể suy ra logic mã hoá sẽ nằm ở ngay giữa 2 phần này:

    ![alt text](../../images/carnivalshow04.png)

- Ta có công thức `4 * ((L + 2)/3)` là độ dài Base64 của chuỗi đầu vào.
    
    ⇒ Điều kiện buộc độ dài `base64(input)` == 60.

    Giải ra: `4 * ((L+2)/3) = 60` ⇒ `(L+2)/3 = 15` ⇒ `L = 43`.

    Từ đó suy ra flag plaintext dài đúng 43 byte. Nếu không phải 43, chương trình bỏ qua toàn bộ kiểm tra chính và sẽ fail.

- Nếu điều kiện độ dài pass (L=43), hàm đi vào check
- Phần đầu tiên là Base64 tự custom
    - Lặp qua `s` theo cụm 3 byte → xuất 4 ký tự.

        ![alt text](../../images/carnivalshow05.png)

    - Bảng chữ cái được sử dụng là `QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm0123456789-_`
    - Padding ở cuối thường dùng là dấu `=`, tuy nhiên bảng custom này lại dùng dấu `.`

        ![alt text](../../images/carnivalshow06.png)

- Phần thứ 2 là hoán vị theo khối 4 byte:

    ![alt text](../../images/carnivalshow07.png)

    - Chuỗi `v31 = 1, 4, 7, …, 43` (15 giá trị) ⇒ tức có 15 khối 4 byte.
    - Mỗi khối ứng với một phép xoay theo byte với s = `v31 & 3`:<br>
    Với dãy trên, `v31 & 3` chạy theo chu kỳ `1,0,3,2,1,0,3,2,...`
    - Kết quả khối đã xoay được chép sang một vùng khác (vẫn mượn field của `rlimits`).

- Phần thứ 3 là PRNG mask 60 byte

    ![alt text](../../images/carnivalshow08.png)

    - `v33` là 1 mã hash FNV-1a 32-bit của `"empty_string"`, rồi XOR với 0x9E377985.
    - PRNG `v36` cập nhật theo kiểu xorshift + feedback.
    - `v39` là mask byte: `v36` + `"n0_dbg^_^"[j % 9]`.
    - `byte_2220[j]` là mảng 60 byte trong .rodata:

        ```python
        byte_2220 = [
        0x87, 0xA4, 0x55, 0x21, 0xAC, 0x4B, 0x57, 0xAE, 0x13, 0xAB, 
        0x5D, 0x97, 0x5C, 0xFD, 0xF0, 0xB5, 0xCA, 0x5D, 0x22, 0xCF, 
        0xE7, 0xE0, 0x3F, 0x98, 0x49, 0x58, 0x06, 0xAF, 0x87, 0x90, 
        0x50, 0xBC, 0xE3, 0xA9, 0x30, 0xFC, 0xE0, 0xB3, 0x8F, 0xAE, 
        0x4C, 0x04, 0x56, 0x39, 0x76, 0xC0, 0x39, 0x93, 0xDC, 0x08, 
        0x21, 0xF7, 0xC2, 0xE2, 0x56, 0xFC, 0xFE, 0x16, 0xDE, 0x43]
        ```
    - `rlimits[0].sa_handler` là 60 byte đã qua (base64 custom) + (xoay khối 4B).
    - Gán cho biến `v37` bằng phép OR bit của `(byte_2220[j] ^ permenc[j]) ^ mask[j]`.

- Có thể hiểu phương trình cốt lõi cho mỗi vị trí j là:

    ```
    C[j]  ^  permute4( custom_b64(s) )[j]  ==  PRNG(j)
    ```
    hay tương đương:
    ```
    permute4( custom_b64(s) )[j]  ==  C[j] ^ PRNG(j)
    ```

### [2.2] Anti-debug:
- Dưới đây là bảng các kỹ thuật anti-debug được sử dụng trong chương trình này (đa phần nằm ở hàm xử lý logic `sub_1300()`):

| #  | Kỹ thuật                                             | Mục đích / Dấu hiệu                            | Vị trí gọi (trong `sub_1300`)                                          | Ghi chú nhanh                                                                                |
| -- | ---------------------------------------------------- | ---------------------------------------------- | ---------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| 1  | `ptrace(PTRACE_TRACEME)` (syscall 101)               | Bị attach/trace → trả `-1`                     | Ngay đầu hàm `sub_1300` (≈ `sub_1300+0x00`)                            | Nếu fail: log `"Debugger detected (ptrace).\n"` rồi `exit(1337)`                             |
| 2  | Đọc `/proc/self/status` tìm `TracerPid` (`sub_1040`) | Có tracer cha → `TracerPid != 0`               | `call sub_1040` (đầu hàm, ngay sau #1)                                 | Nếu có: `"Debugger detected (TracerPid).\n"` → `exit(1338)`                                  |
| 3  | Kiểm tra **cha đáng ngờ** (`sub_10F0`)               | Parent là tracer/launcher lạ                   | `call sub_10F0` (sau #2)                                               | Nếu có: `"Debugger parent detected.\n"` → `exit(1339)`                                       |
| 4  | Kiểm tra **preload env**                             | Hook qua `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES` | 2× `getenv` và so sánh (sau #3)                                        | Nếu var tồn tại & non-empty: `"Suspicious preload env.\n"` → `exit(1340)`                    |
| 5  | **TSC timing anti single-step**                      | Single-step làm thời gian vòng lặp lớn         | Khối `v43=__rdtsc(); for(...) v44+=i; v45=__rdtsc(); if (v45-v43>4e7)` | Nếu vượt ngưỡng: `"Suspicious single-step timing.\n"` → `exit(1341)`                         |
| 6  | **Quét INT3 (0xCC)** quanh checker                   | Phát hiện breakpoint cứng                      | Vòng `for` duyệt từ `sub_1300` đến `sub_1300+64`                       | Nếu thấy `0xCC`: `"Breakpoint detected near checker.\n"` → `exit(1342)`                      |
| 7  | `cpuid` kiểm tra **hypervisor bit**                  | Phát hiện chạy trong VM (ECX\[31])             | Cặp `cpuid` sau vòng quét 0xCC                                         | Chỉ **cảnh báo**: `"[warn] Running under hypervisor.\n"` (không thoát)                       |
| 8  | **Tắt core dump**                                    | Giảm thông tin rò rỉ khi crash                 | `setrlimit(RLIMIT_CORE, ...)` (sau `cpuid`)                            | Chuẩn hardening anti-RE                                                                      |
| 9  | `prctl(PR_SET_DUMPABLE, 0)`                          | Cấm sinh core dump / gdb attach khó hơn        | `prctl(4, 0)` ngay sau #8                                              | 4 = `PR_SET_DUMPABLE`                                                                        |
| 10 | `prctl(PR_SET_NAME, "[kworker/u:0]")`                | Ngụy trang tên tiến trình                      | `prctl(15, "[kworker/u:0]")`                                           | 15 = `PR_SET_NAME`                                                                           |
| 11 | Cài **signal handlers**                              | Bẫy `SIGTRAP` & `SIGALRM`                      | `sigaction(5, ...)` và `sigaction(14, ...)`                            | Handler là `sub_1A40`                                                                        |
| 12 | `alarm(3)`                                           | Cắt phiên khi debug/treo                       | `alarm(3u)`                                                            | Timeout 3 giây                                                                               |
| 13 | `prctl(PR_SET_PDEATHSIG, 1)`                         | Chết theo parent / né trick reparent           | `prctl(22, 1)` ngay trước bước xử lý base64                            | 22 = `PR_SET_PDEATHSIG` — không “chống debug” trực diện, nhưng phá nhiều flow attach/suspend |
| 14 | **Scrub bộ nhớ tạm**                                 | Xoá vùng `rlimits` trước khi thoát             | Vòng set 0 từ `rlimits` tới `v49`                                      | Giảm artifact khi dump                                                                       |


## [3] SOLVE
```python
from __future__ import annotations
from dataclasses import dataclass
from typing import Iterable, List
import argparse

# ---- Constants lifted from the binary ----

ALPH = b"QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm0123456789-_"
A_N0_DBG = b"n0_dbg^_^"

C = [
    0x87, 0xA4, 0x55, 0x21, 0xAC, 0x4B, 0x57, 0xAE, 0x13, 0xAB,
    0x5D, 0x97, 0x5C, 0xFD, 0xF0, 0xB5, 0xCA, 0x5D, 0x22, 0xCF,
    0xE7, 0xE0, 0x3F, 0x98, 0x49, 0x58, 0x06, 0xAF, 0x87, 0x90,
    0x50, 0xBC, 0xE3, 0xA9, 0x30, 0xFC, 0xE0, 0xB3, 0x8F, 0xAE,
    0x4C, 0x04, 0x56, 0x39, 0x76, 0xC0, 0x39, 0x93, 0xDC, 0x08,
    0x21, 0xF7, 0xC2, 0xE2, 0x56, 0xFC, 0xFE, 0x16, 0xDE, 0x43,
]
C_BYTES = bytes(C)  # 60 bytes


# ---- Bit helpers ----

def ror8(x: int, r: int) -> int:
    """Rotate-right 8-bit value by r (0..7)."""
    r &= 7
    return ((x >> r) | ((x << (8 - r)) & 0xFF)) & 0xFF


def ror_block4(block: bytes, s: int) -> bytes:
    """
    Right-rotate a 4-byte block by s positions at byte granularity.
    s in {0,1,2,3}. Inverse of a left-rotate-by-s done in the binary.
    """
    s &= 3
    if s == 0:
        return block
    return block[-s:] + block[:-s]


# ---- Hash & PRNG (as reconstructed) ----

def fnv1a32(data: bytes) -> int:
    """FNV-1a 32-bit hash."""
    h = 0x811C9DC5
    for b in data:
        h = ((h ^ b) * 0x01000193) & 0xFFFFFFFF
    return h


def prng60(seed_tag: bytes = A_N0_DBG) -> List[int]:
    v = (fnv1a32(seed_tag) ^ 0x9E377985) & 0xFFFFFFFF
    out: List[int] = []

    for j in range(60):
        # xorshift-like update with extra (32*u) feedback:
        a = ((v ^ ((v << 13) & 0xFFFFFFFF)) >> 17) & 0xFFFFFFFF
        b = (v << 13) & 0xFFFFFFFF
        u = (a ^ v ^ b) & 0xFFFFFFFF
        v = (v ^ a ^ b ^ ((32 * u) & 0xFFFFFFFF)) & 0xFFFFFFFF

        idx = j % 9  # same as the binary's weird arithmetic
        out.append((v + seed_tag[idx]) & 0xFF)

    return out
    
@dataclass(frozen=True)
class CustomB64:
    alphabet: bytes
    pad_byte: int = ord('.')

    def decode(self, data: bytes) -> bytes:
        inv = {self.alphabet[i]: i for i in range(64)}
        out = bytearray()

        if len(data) % 4 != 0:
            raise ValueError("Input length must be a multiple of 4.")

        for i in range(0, len(data), 4):
            chunk = data[i:i + 4]
            pad = chunk.count(self.pad_byte)
            vals = [(0 if b == self.pad_byte else inv[b]) for b in chunk]
            v = (vals[0] << 18) | (vals[1] << 12) | (vals[2] << 6) | vals[3]

            b1, b2, b3 = (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF
            if pad == 0:
                out += bytes([b1, b2, b3])
            elif pad == 1:
                out += bytes([b1, b2])
            elif pad == 2:
                out += bytes([b1])
            else:
                raise ValueError("Invalid padding in custom base64.")
        return bytes(out)

def undo_xor(cipher: bytes, mask: Iterable[int]) -> bytes:
    """XOR each cipher byte with corresponding mask byte."""
    return bytes(c ^ m for c, m in zip(cipher, mask))


def undo_block_rotations(data: bytes) -> bytes:
    """
    Data length must be multiple of 4.
    Each 4-byte block is right-rotated by s = v31 & 3,
    where v31 starts at 1 and increases by +3 per block.
    """
    if len(data) % 4 != 0:
        raise ValueError("Length must be a multiple of 4.")
    out = bytearray()
    v31 = 1
    for i in range(0, len(data), 4):
        s = v31 & 3
        out += ror_block4(data[i:i + 4], s)
        v31 += 3
    return bytes(out)


def rebuild_flag(verbose: bool = False) -> str:
    # 1) PRNG mask
    mask = prng60(A_N0_DBG)
    if verbose:
        print(f"[+] PRNG bytes (len={len(mask)}): {bytes(mask).hex()}")

    # 2) Undo XOR
    eperm = undo_xor(C_BYTES, mask)
    if verbose:
        print(f"[+] After XOR/undo (eperm, len={len(eperm)}): {eperm.hex()}")

    # 3) Undo per-4-byte rotation
    enc = undo_block_rotations(eperm)
    if verbose:
        print(f"[+] After undo rotations (enc, len={len(enc)}): {enc.hex()}")

    # 4) Custom base64 decode to get the flag bytes
    b64 = CustomB64(ALPH)
    flag_bytes = b64.decode(enc)
    flag = flag_bytes.decode(errors="strict")

    if verbose:
        print(f"[+] Flag bytes: {flag_bytes!r}")
    return flag

def main():
    parser = argparse.ArgumentParser(description="Rebuild flag from CarnivalShow constants.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print intermediate stages")
    args = parser.parse_args()

    flag = rebuild_flag(verbose=args.verbose)
    print(flag)


if __name__ == "__main__":
    main()
```
> **Flag:** `PTITCTF{Y0u_c4n_bypass_4ll_types_0f_4nt1!!!}`
