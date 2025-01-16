def decrypt(cipher):
    return ''.join([chr(ord(cipher[i]) >> 8) + chr(int(bin(ord(cipher[i]))[-8:], 2)) for i in range(0, len(cipher))])

s = open('enc-transf', 'r', encoding='utf-8').read()
s = decrypt(s)
print(f'flag: {s}')

# flag: grodno{instead_of_8_bits_make_16_bits}