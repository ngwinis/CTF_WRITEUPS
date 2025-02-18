from Crypto.Util.number import *
from base64 import b64decode, b64encode
from pwn import *

s = remote('ctf.mf.grsu.by', 9019)
x = s.recvuntil(b'Plaintext is (b64):').strip().decode()
print(x)

i = x[x.find('Раунд ')+len('Раунд ')]
i = int(i)
cnt = x[x.find('Раунд ')+len('Раунд ')+2:x.find('Раунд ')+len('Раунд ')+4]
cnt = int(cnt)
while i <= cnt:
    e = x[x.find('e:')+5:x.find('d:')-1]
    d = x[x.find('d:')+5:x.find('n:')-1]
    n = x[x.find('n:')+5:x.find('secret ciphertext (b64):')-1]
    c = x[x.find('secret ciphertext (b64): ')+len('secret ciphertext (b64): '):x.find('Plaintext is (b64):')-1]

    e = 0x10001
    d = int(d, 16)
    n = int(n, 16)
    c = bytes_to_long(b64decode(c.encode())[::-1])

    message = b64encode(long_to_bytes(pow(c, d, n))[::-1])
    s.sendline(message)
    print(message)
    i += 1
    try:
        x = s.recvuntil(b'Plaintext is (b64):').strip().decode()
        print(x)
    except EOFError as e:
        x = s.recv().strip().decode()
        print(x)

s.close()

# flag: grodno{9cced0Take_y0urself_the_b1ggest_candy3fcc4e}
