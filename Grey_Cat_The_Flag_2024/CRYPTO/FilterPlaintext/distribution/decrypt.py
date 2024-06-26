from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from hashlib import md5
import socket
import os

xor = lambda x, y: bytes(a^b for a, b in zip(x, y))


host = 'challs.nusgreyhats.org'
port = 32223

# Create a socket object
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to server
s.connect((host, port))

data = s.recv(1024).decode()
secret_enc = data[18:178]
secret_iv = bytes.fromhex(data[(data.find('iv:')+4):(data.find('iv:')+36)])
flag_enc = bytes.fromhex(data[(data.find('ct:')+4):(data.find('ct:')+100)])

print(data, end='') # Enter messages to decrypt (in hex):
last = os.urandom(16)
secret_enc += last.hex()
ret = b""
iv = b""
i = 0
for i in range(len(secret_enc)//32-1):
    message = secret_enc[0:(i+1)*32] + secret_enc[(i+1)*32:(i+2)*32]*2 + secret_enc[(i+2)*32:len(secret_enc)]
    print(message)
    s.send(message.encode())
    s.send('\n'.encode())

    response = bytes.fromhex(s.recv(1024).decode()[0:64])
    print(response.hex(), end='\n> ')
    if i == len(secret_enc)//32-2:
        iv = xor(response[16:32], bytes.fromhex(secret_enc[(i+1)*32:(i+2)*32]))
    else:
        iv = xor(response[0:16], bytes.fromhex(secret_enc[(i+1)*32:(i+2)*32]))
    res1 = xor(iv, bytes.fromhex(secret_enc[i*32:(i+1)*32]))
    ret += res1

s.close()
secret = ret

secret_key = md5(secret).digest()
cipher = AES.new(key = secret_key, iv = secret_iv, mode = AES.MODE_CBC)
flag = cipher.decrypt(flag_enc)
print("flag:", f'{flag}')

# flag: grey{pcbc_d3crypt10n_0r4cl3_3p1c_f41l}
