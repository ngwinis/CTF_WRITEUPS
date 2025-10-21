encrypted = [122, 86, 27, 22, 53, 35, 80, 77, 24, 98, 122, 7, 72, 21, 98, 114]
key = [66, 51, 122, 33, 86]

decrypted_part1 = ""
for i in range(len(encrypted)):
  decrypted_byte = encrypted[i] ^ key[i % len(key)]
  decrypted_part1 += chr(decrypted_byte)

print(decrypted_part1)
# Output: 8ea7cac794842440