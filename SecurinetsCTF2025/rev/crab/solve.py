from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from binascii import unhexlify

# điền key hex ở đây (16 byte cho AES-128 hoặc 32 byte cho AES-256)
KEY_HEX = "ffffffffffffffffffffffffffffffff"  # ví dụ 16B
# KEY_HEX = "..."  # nếu là 32B, AES-256

with open("/mnt/data/flag.txt.crs", "rb") as f:
    blob = f.read()

iv = blob[:16]
ct = blob[16:]
key = unhexlify(KEY_HEX)

def try_cbc(key):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(ct), 16)

pt = try_cbc(key)
print(pt.decode("utf-8", "replace"))
