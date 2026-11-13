import sys
import json
import os
import signal
import socket

from http.server import HTTPServer, BaseHTTPRequestHandler

MAGIC_STRING = "MAGIC_STRING_FOR_TESTING"


class TempHttpServer(BaseHTTPRequestHandler):

    def do_GET(self):
        # Python 3 requires an explicit encoding for text sent over a socket.
        response = MAGIC_STRING.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)


if __name__ == "__main__":
    if sys.argv[1] == "--stop":
        # Only terminate our own server, never an unrelated reused PID.
        with open(sys.argv[2]) as stream:
            pid = int(json.load(stream)['pid'])
        try:
            with open('/proc/{}/cmdline'.format(pid), 'rb') as stream:
                arguments = stream.read().split(b'\0')
            if os.fsencode(os.path.abspath(__file__)) not in arguments:
                raise RuntimeError('HTTP server PID belongs to another process')
            os.kill(pid, signal.SIGTERM)
        except FileNotFoundError:
            pass  # The bounded server may already have finished naturally.
        sys.exit(0)
    port = int(sys.argv[1])
    bind_address = sys.argv[3] if len(sys.argv) > 3 else '0.0.0.0'
    server_class = HTTPServer
    if ':' in bind_address:
        class IPv6HTTPServer(HTTPServer):
            address_family = socket.AF_INET6
        server_class = IPv6HTTPServer
    httpd = server_class((bind_address, port), TempHttpServer)
    httpd.timeout = 30
    if len(sys.argv) > 2:
        # Port zero asks the kernel for an unused port; publish it after bind.
        # Atomic rename prevents the test from seeing partially written JSON.
        with open(sys.argv[2] + '.tmp', 'w') as stream:
            json.dump({'port': httpd.server_port, 'pid': os.getpid()}, stream)
        os.replace(sys.argv[2] + '.tmp', sys.argv[2])

    # Handle three requests and exit.
    # Each handle_request() will block for httpd.timeout seconds if no request is received.
    # Close the socket even if a client disconnects or the test fails.
    try:
        httpd.handle_request()  # For testing http port open
        httpd.handle_request()  # For GET request from client
        httpd.handle_request()  # For GET through ip vrf exec mgmt
    finally:
        httpd.server_close()
