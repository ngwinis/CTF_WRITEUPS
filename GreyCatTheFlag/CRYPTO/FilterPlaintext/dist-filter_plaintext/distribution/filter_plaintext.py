from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from hashlib import md5
import os

flag = 'flag{crypto_is_so_hard_isnt_it?}'

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
    
    for block in blocks:
        res = xor(cipher.decrypt(block), tmp)
        if (res not in secret):
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



secret_enc1 = secret_enc.hex()
last = os.urandom(16)
secret_enc1 += last.hex()
ret1 = b""
for i in range(len(secret_enc1)//32-1):
    message = secret_enc1[0:(i+1)*32] + secret_enc1[(i+1)*32:(i+2)*32]*2 + secret_enc1[(i+2)*32:len(secret_enc1)]
    print(">", f'{message}')




    res = message

    try:
        enc = bytes.fromhex(res)
        dec = decrypt(enc)
        print(dec.hex())
        
    except Exception as e:
        print(e)
        continue


    response = dec
    # print(response)
    res1 = b""
    if i == len(secret_enc1)//32-2:
        iv = xor(response[16:32], last)
        res1 = xor(iv, bytes.fromhex(secret_enc1[i*32:(i+1)*32]))
    else:
        iv = xor(response[0:16], bytes.fromhex(secret_enc1[(i+1)*32:(i+2)*32]))
        res1 = xor(iv, bytes.fromhex(secret_enc1[i*32:(i+1)*32]))
    ret1 += res1

secret1 = ret1 + last

secret_key1 = md5(secret1).digest()
cipher = AES.new(key = secret_key1, iv = secret_iv, mode = AES.MODE_CBC)
flag = cipher.decrypt(flag_enc)
print("flag:", f'{flag}')
