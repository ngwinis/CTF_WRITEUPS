import sys

# Dán token MỚI NHẤT bạn vừa tạo ở bước 1 vào đây
hex_token = "9a5a84b72652c6b22edd4faee20722df98f6ddfc051c07c073c77ae933fa5d43571577fcddecff67a7ee635b4431a791d81010779f6728f339ca1d08d3f99ef6e0a08846c162eca2db02ea8a6af3ef997b12afc4b2176fc367726691ee04d54cd7f30ce9a7d18687fe5f6c067c3622d3"

# Chuyển từ hex sang bytes
ciphertext = bytearray.fromhex(hex_token)

# ĐÂY LÀ INDEX ĐÃ ĐƯỢC HIỆU CHỈNH
target_index = 78

# Giá trị XOR để đổi '0' thành '1'
xor_value = ord('0') ^ ord('1')

# Lật bit tại vị trí mục tiêu cuối cùng
original_byte = ciphertext[target_index]
modified_byte = original_byte ^ xor_value
ciphertext[target_index] = modified_byte

# Chuyển lại sang dạng hex để submit
modified_hex_token = ciphertext.hex()

print("Modified Token:", modified_hex_token)