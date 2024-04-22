from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from hashlib import md5
import os

# with open("flag.txt", "r") as f:
#     flag = f.read()
flag = 'grey{hello}'
BLOCK_SIZE = 16
iv = os.urandom(BLOCK_SIZE)

xor = lambda x, y: bytes(a^b for a,b in zip(x,y))

key = os.urandom(16)

def encrypt(pt):
    cipher = AES.new(key=key, mode=AES.MODE_ECB)
    blocks = [pt[i:i+BLOCK_SIZE] for i in range(0, len(pt), BLOCK_SIZE)]
    tmp = iv
    ret = b""
    
    for block in blocks:
        res = cipher.encrypt(xor(block, tmp))
        ret += res
        tmp = xor(block, res)
        
    return ret

    
def decrypt(ct):
    cipher = AES.new(key=key, mode=AES.MODE_ECB)
    blocks = [ct[i:i+BLOCK_SIZE] for i in range(0, len(ct), BLOCK_SIZE)]

    
    tmp = iv
    ret = b""
    idx = 0
    for block in blocks:
        res = xor(cipher.decrypt(block), tmp)
        if (res not in secret):
            ret += res
        print("res in secret:", res in secret,"tmp", idx, "=", tmp.hex())
        tmp = xor(block, res)
        idx += 1
        
    return ret

def decrypt1(ct):
    cipher = AES.new(key=key, mode=AES.MODE_ECB)
    blocks = [ct[i:i+BLOCK_SIZE] for i in range(0, len(ct), BLOCK_SIZE)]

    
    tmp = iv
    ret = b""
    for block in blocks:
        res = xor(cipher.decrypt(block), tmp)
        ret += res
        tmp = xor(block, res)
        
    return ret
    
secret = os.urandom(80)
secret_enc = encrypt(secret)

print(f"Encrypted secret: {secret_enc.hex()}")

secret_key = md5(secret).digest()
secret_iv = os.urandom(BLOCK_SIZE)
cipher = AES.new(key = secret_key, iv = secret_iv, mode = AES.MODE_CBC)
flag_enc = cipher.encrypt(pad(flag.encode(), BLOCK_SIZE))

print(f"iv: {secret_iv.hex()}")

print(f"ct: {flag_enc.hex()}")

print("Enter messages to decrypt (in hex): ")

while True:
    res = input("> ")

    try:
        enc = bytes.fromhex(res)
        dec = decrypt(enc)
        dec1 = decrypt1(secret_enc)
        print(dec.hex())
        print(secret.hex())
        secret_key = md5(dec1).digest()
        cipher = AES.new(key = secret_key, iv = secret_iv, mode = AES.MODE_CBC)
        flag_real = cipher.decrypt(flag_enc)
        print(flag_real)
        
    except Exception as e:
        print(e)
        continue

    


