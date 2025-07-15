import socket
import time

# TODO: src/dst IP addresses and ports should be configurable
CLIENT_IP = "172.16.2.1"
SERVER_IP = "172.16.1.1"
SERVER_PORT = 5000
NUM_PACKETS = 1000

s = socket.socket()
s.bind((CLIENT_IP, 0))
s.connect((SERVER_IP, SERVER_PORT))

for i in range(NUM_PACKETS):
    msg = f"Packet id: {i}.".encode()
    s.sendall(msg)
    data = s.recv(1024)
    time.sleep(0.001)  # Slight delay (1 ms) to avoid flooding

print(f"Sent {NUM_PACKETS} packets")
s.close()
