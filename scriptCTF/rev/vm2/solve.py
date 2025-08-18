from pwn import *

# Thay đổi thông tin kết nối
HOST = "play.scriptsorcerers.xyz"
PORT = 10461

# Header 5-byte: một lệnh jmp hợp lệ nhảy đến đầu chương trình logic
jmp_padding = b"\x90\x05\x00\x00\x00"  # jmp 0x05

# Core logic 66-byte với các địa chỉ nhảy đã được tính toán lại cho offset +5
logic_bytecode_66_bytes = (
    # --- Khởi tạo (18 bytes) ---
    b"\x60\x04\x04\x20\x04\x00"    # r4 = r0 (original_N)
    b"\x10\x02\x0a\x00\x00\x00"    # r2 = 10
    b"\x60\x03\x03"                # r3 = 0 (reversed_N)
    b"\x60\x05\x05"                # r5 = 0 (để so sánh với N)
    
    # --- Vòng lặp (loop_start @ 0x17) (8 bytes) ---
    b"\xa0\x00\x05"                # cmp r0, r5 (N == 0?)
    b"\xb0\x2d\x00\x00\x00"        # je 0x2d (loop_end)
    
    # --- Thân vòng lặp (14 bytes) ---
    b"\x50\x00\x02"                # div r0, r2. r0=quotient, r1=remainder
    b"\x40\x03\x02"                # r3 = reversed * 10
    b"\x20\x03\x01"                # r3 = reversed + remainder
    b"\x90\x17\x00\x00\x00"        # jmp 0x17 (loop_start)
    
    # --- Kết thúc (loop_end @ 0x2D) (26 bytes) ---
    b"\xa0\x04\x03"                # cmp original_N, reversed_N
    b"\xe0\x40\x00\x00\x00"        # jne 0x40 (not_palindrome)

    # is_palindrome
    b"\x10\x00\x01\x00\x00\x00"    # r0 = 1
    b"\x90\x46\x00\x00\x00"        # jmp 0x46 (end_program)

    # not_palindrome @ 0x40
    b"\x10\x00\x00\x00\x00\x00"    # r0 = 0

    # end_program @ 0x46
    b"\xf0"                        # halt
)

# Ghép lại thành payload 71-byte cuối cùng
final_payload = jmp_padding + logic_bytecode_66_bytes

# Kiểm tra lại độ dài
assert len(final_payload) == 71, f"Lỗi: Bytecode có độ dài {len(final_payload)}, không phải 71!"

conn = remote(HOST, PORT)
log.info(f"Đang gửi chính xác {len(final_payload)} bytes với jmp header...")
conn.send(final_payload)
response = conn.recvall()
log.success("Phản hồi từ server:")
try:
    print(response.decode())
except UnicodeDecodeError:
    print(response)