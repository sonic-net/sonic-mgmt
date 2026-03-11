import http.server
import socket
import socketserver

PORT = 8080


Handler = http.server.SimpleHTTPRequestHandler

class IPv6TCPServer(socketserver.TCPServer):
    address_family = socket.AF_INET6

httpd = IPv6TCPServer(("::", PORT, 0, 0), Handler)

print("serving at port", PORT)
httpd.serve_forever()
