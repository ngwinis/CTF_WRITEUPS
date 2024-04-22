import socket

host = 'challs.nusgreyhats.org'  # Change this to the server's IP address
port = 32222        # Change this to the server's port number
# trigger_message = "> "

# Create a socket object
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to server
s.connect((host, port))

# Read from server
data = s.recv(1024).decode()
print(data, end='')
x = data[18:178]
blocks = [x[i:i+32] for i in range(0, len(x), 32)]
message = ""
for block in blocks:
    message += block*2
message += '\n'
print(message, end='')
s.sendall(message.encode())

response = s.recv(1024)
print("Response from server:", response.decode())

# flag: grey{00ps_n3v3r_m0d1fy_wh1l3_1t3r4t1ng}