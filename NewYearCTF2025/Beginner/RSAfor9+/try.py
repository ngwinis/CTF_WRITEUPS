from Crypto.Util.number import *
from base64 import b64encode, b64decode
from pwn import *

s = remote('ctf.mf.grsu.by', 9019)
x = s.recvuntil(b'Plaintext is (b64):').strip().decode()
print(x)

e = x[x.find('e:')+3:x.find('d:')-1]
d = x[x.find('d:')+3:x.find('n:')-1]
n = x[x.find('n:')+3:x.find('secret ciphertext (b64):')-1]
c = x[x.find('secret ciphertext (b64): ')+len('secret ciphertext (b64): '):x.find('Plaintext is (b64):')-1]

e = int(e, 16)
d = int(d, 16)
n = int(n, 16)
c = bytes_to_long(b64decode(c))

message = b64encode(long_to_bytes(pow(c, d, n)))
s.sendline(message)
print(message)
x = s.recv().strip().decode()
print(x)