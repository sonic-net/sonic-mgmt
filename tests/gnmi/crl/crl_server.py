import sys

from http.server import HTTPServer, BaseHTTPRequestHandler

class TempHttpServer(BaseHTTPRequestHandler):

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()

        with open('sonic.crl.pem', 'rb') as file:
            # Read the entire file content into a string
            crl_content = file.read()
            print("Read sonic.crl.pem success\n")
            self.wfile.write(crl_content)


if __name__ == "__main__":
    httpd = HTTPServer(('0.0.0.0', 1234), TempHttpServer)
    httpd.timeout = 30

    # handle download CRL request
    while True:
        print("Ready handle request\n")
        httpd.handle_request()  # For GET request from client
