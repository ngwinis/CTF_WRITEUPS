import socket
import time
import random

def send_string_to_server(host, port, trigger_message, message):
    # Create a socket object
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # Connect to the server
        s.connect((host, port))

        # Continuously receive data from the server until trigger message is received
        data = b""
        while not data.endswith(trigger_message.encode()):
            data += s.recv(1024)

        # Once trigger message is received, send the message
        print("Received trigger message from server:", data.decode())
        print("Sending message to server:", message)
        s.sendall(message.encode())
        response = s.recv(1024)
        print("flag:", response.decode())

    except Exception as e:
        print("An error occurred:", str(e))

    finally:
        # Close the connection
        s.close()

# Example usage
host = 'challs.nusgreyhats.org'  # Change this to the server's IP address
port = 31111        # Change this to the server's port number
trigger_message = "Your guess:"
random.seed(int(time.time()))
n = random.randint(1000000000000000, 10000000000000000-1)
message = str(n) + '\n'
send_string_to_server(host, port, trigger_message, message)

# flag: grey{t1m3_i5_a_s0c1al_coNstRucT}