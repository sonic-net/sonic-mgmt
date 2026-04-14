import socket
import time

s = socket.socket()
s.connect(("172.16.1.1", 5000))

for i in range(1000):
    msg = f"Packet {i}".encode()
    s.sendall(msg)
    data = s.recv(1024)
    time.sleep(0.001)  # Slight delay (1 ms) to avoid flooding

print("Sent 1000 packets")
s.close()
