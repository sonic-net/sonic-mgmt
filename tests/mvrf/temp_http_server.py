import sys

from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler

MAGIC_STRING = "MAGIC_STRING_FOR_TESTING"


class TempHttpServer(BaseHTTPRequestHandler):

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()

        self.wfile.write(bytes(MAGIC_STRING))


if __name__ == "__main__":
    port = int(sys.argv[1])
    httpd = HTTPServer(('0.0.0.0', port), TempHttpServer)
    httpd.timeout = 30

    # Handle two requests and exit.
    # Each handle_request() will block for httpd.timeout seconds if no request is received.
    # This script will exit after 2 * httpd.timeout seconds in worst case that no request is received at all.
    httpd.handle_request()  # For testing http port open
    httpd.handle_request()  # For GET request from client
    httpd.handle_request()  # For second GET request from client issued by cmd ip vrf exec mgmt curl
