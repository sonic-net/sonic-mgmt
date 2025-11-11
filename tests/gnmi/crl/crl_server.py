import sys
import argparse
import socket
from http.server import HTTPServer, BaseHTTPRequestHandler


crl_content = bytes(0)


def log_to_file(filename, message):
    with open(filename, 'a') as file:
        file.write(message)


def load_cert():
    global crl_content
    with open('sonic.crl.pem', 'rb') as file:
        # Read the entire file content into a string
        crl_content = file.read()


class writer(object):
    def write(self, data):
        log_to_file("crl.log", data)

    def flush(self):
        # No-op for file logging, but required for stdout/stderr compatibility
        pass


class IPv6HTTPServer(HTTPServer):
    address_family = socket.AF_INET6


class TempHttpServer(BaseHTTPRequestHandler):

    def do_GET(self):
        try:
            global crl_content
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(crl_content)
        except Exception as e:
            log_to_file("crl.log", "Handle get request exception: " + str(e))


if __name__ == "__main__":
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='CRL HTTP Server')
    parser.add_argument('--bind', default='0.0.0.0', help='IP address to bind to')
    parser.add_argument('--port', type=int, default=1234, help='Port to bind to (default: 1234)')
    args = parser.parse_args()

    # nohup will break stderr and cause broken pipe error
    sys.stdout = writer()
    sys.stderr = writer()

    # Create HTTP server with specified bind address
    # Automatically detect if we need IPv6 or IPv4 based on the bind address
    try:
        # Try to parse the address to determine if it's IPv6
        socket.inet_pton(socket.AF_INET6, args.bind)
        # If successful, it's an IPv6 address
        httpd = IPv6HTTPServer((args.bind, args.port), TempHttpServer)
        log_to_file("crl.log", f"IPv6 HTTPServer started on [{args.bind}]:{args.port}\n")
    except socket.error:
        # Not a valid IPv6 address, fallback to IPv4
        httpd = HTTPServer((args.bind, args.port), TempHttpServer)
        log_to_file("crl.log", f"IPv4 HTTPServer started on {args.bind}:{args.port}\n")

    # load cert
    load_cert()

    # handle download CRL request
    while True:
        try:
            log_to_file("crl.log", "Ready handle request\n")
            httpd.serve_forever()  # For GET request from client
        except Exception as e:
            log_to_file("crl.log", "Handle request exception: " + str(e))
