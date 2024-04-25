from pwn import *
import time
import random

# connect to server
s = remote("challs.nusgreyhats.org", 31111)

# print text from server
x = s.recv().strip().decode()
print(x, end='')

# send random number to server
random.seed(int(time.time()))
n = random.randint(1000000000000000, 10000000000000000-1)
message = str(n) + '\n'
s.sendline(message.encode())
print(message[:-1])

# get the flag
response = s.recvline().strip().decode()
print(response)
s.close()

# flag: grey{t1m3_i5_a_s0c1al_coNstRucT}
