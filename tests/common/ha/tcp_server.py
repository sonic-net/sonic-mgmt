import socket

s = socket.socket()
s.bind(("172.16.1.1", 5000))
s.listen(1)
conn, addr = s.accept()
print("Connected by", addr)

received_count = 0

while received_count < 1000:
    data = conn.recv(1024)
    if not data:
        break
    received_count += 1
    conn.sendall(b"ACK")

print(f"Received {received_count} packets")
conn.close()
