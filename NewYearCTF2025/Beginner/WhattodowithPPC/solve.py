from time import sleep
import socket

sock = socket.socket()
sock.connect(("ip-adress", port))

while True:
     sleep(1)
    # get data from server
     data = sock.recv(1024).decode('utf-8')
    # check if there is already a flag there?
     if 'grodno{' in data:
         print(data)
         break
     task = f1(data) # extract task condition from data
     result = f2(task) # calculate the answer
    # send reply
     sock.send((str(result) + '\r\n').encode())

sock.close()