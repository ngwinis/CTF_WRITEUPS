def generate_keystream(seed, length):
    """
    Tái tạo lại hàm `keystream__nimrod_20` trong Python.
    Hàm này sử dụng thuật toán LCG (Linear Congruential Generator).
    """
    keystream = bytearray()
    state = seed

    # Các hằng số được sử dụng trong LCG của chương trình
    multiplier = 1664525
    increment = 1013904223

    for _ in range(length):
        # Công thức LCG: state = (a * state + c).
        # Sử dụng `& 0xFFFFFFFF` để mô phỏng số nguyên 32-bit không dấu,
        # vì đây là hành vi phổ biến trong C.
        state = (multiplier * state + increment) & 0xFFFFFFFF

        # Chương trình C lấy byte thứ 3 (BYTE2) của state.
        # 0xAABBCCDD -> Dịch phải 16 bit -> 0x0000AABB -> & 0xFF -> 0xBB
        key_byte = (state >> 16) & 0xFF
        keystream.append(key_byte)
    
    return keystream

def solve():
    """
    Hàm chính để giải challenge.
    """
    # Khóa (seed) được sử dụng trong hàm xorEncrypt__nimrod_46
    SEED = 0x13371337

    # --- BẠN CẦN CUNG CẤP GIÁ TRỊ NÀY ---
    # Sử dụng debugger để tìm giá trị của `encryptedFlag__nimrod_10`.
    # Nó sẽ là một mảng các byte. Hãy điền chúng vào đây.
    # Ví dụ: encrypted_flag_bytes = [115, 33, 43, 111, 11, 83, 10, 23, 93, 22]
    encrypted_flag_bytes = [
        0x28, 0xF8, 0x3E, 0xE6, 0x3E, 0x2F, 0x43, 0x0C, 0xB9, 0x96, 
  0xD1, 0x5C, 0xD6, 0xBF, 0x36, 0xD8, 0x20, 0x79, 0x0E, 0x8E, 
  0x52, 0x21, 0xB2, 0x50, 0xE3, 0x98, 0xB5, 0xC9, 0xB8, 0xA0, 
  0x88, 0x30, 0xD9, 0x0A
    ]

    if not encrypted_flag_bytes:
        print("[-] Lỗi: Vui lòng chỉnh sửa script và điền giá trị cho biến 'encrypted_flag_bytes'.")
        print("[-] Bạn có thể lấy giá trị này bằng cách dùng debugger (GDB, IDA Pro, x64dbg) để xem nội dung của biến `encryptedFlag__nimrod_10`.")
        return

    # Độ dài của flag bằng với độ dài của chuỗi đã mã hóa
    flag_length = len(encrypted_flag_bytes)
    print(f"[+] Độ dài của flag đã mã hóa: {flag_length}")

    # 1. Tái tạo lại keystream
    print(f"[+] Đang tạo keystream với seed = {hex(SEED)}...")
    keystream = generate_keystream(SEED, flag_length)
    print(f"[+] Keystream (dạng hex): {keystream.hex()}")

    # 2. Giải mã bằng cách XOR ciphertext với keystream
    print("[+] Đang giải mã...")
    decrypted_flag = bytearray()
    for i in range(flag_length):
        decrypted_byte = encrypted_flag_bytes[i] ^ keystream[i]
        decrypted_flag.append(decrypted_byte)

    # 3. In kết quả
    print("\n" + "="*30)
    try:
        print(f"[+] SUCCESS! Flag đã giải mã là: {decrypted_flag.decode('utf-8')}")
    except UnicodeDecodeError:
        print(f"[+] Hoàn thành! Flag đã giải mã (dạng byte): {decrypted_flag}")
        print(f"[+] Flag đã giải mã (dạng hex): {decrypted_flag.hex()}")
    print("="*30)


if __name__ == "__main__":
    solve()

# Flag: ictf{a_mighty_hunter_bfc16cce9dc8}