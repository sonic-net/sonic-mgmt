import sys
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
    # nohup will break stderr and cause broken pipe error
    sys.stdout = writer()
    sys.stderr = writer()

    httpd = HTTPServer(('', 1234), TempHttpServer)
    log_to_file("crl.log", "HTTPServer stated\n")

    # load cert
    load_cert()

    # handle download CRL request
    while True:
        try:
            log_to_file("crl.log", "Ready handle request\n")
            httpd.serve_forever()  # For GET request from client
        except Exception as e:
            log_to_file("crl.log", "Handle request exception: " + str(e))
