#!/usr/bin/env python3
"""Mock KBS for the BNB nightly test.

Serves the two endpoints BNB calls:
  GET /kubesonicbootstrapservice/v1/bootstrap?arch=<arch>  -> join metadata in headers
  GET /kubesonicbootstrapservice/v1/image                  -> the KNB image tarball

HTTPS only. BNB pins the server cert's SPKI (sha256 of SubjectPublicKeyInfo), so
the cert passed in here MUST be the one whose SPKI hash is encoded into CONFIG_DB's
`.cahash.` field (see the test for the derivation).
"""
import argparse
import os
import socket
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BOOTSTRAP_PATH = "/kubesonicbootstrapservice/v1/bootstrap"
IMAGE_PATH = "/kubesonicbootstrapservice/v1/image"


def make_handler(args):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):  # keep the DUT console quiet
            pass

        def do_GET(self):
            path = self.path.split("?", 1)[0]
            if path == BOOTSTRAP_PATH:
                self.send_response(200)
                self.send_header("X-Join-Token", args.join_token)
                self.send_header("X-Apiserver", args.apiserver)
                self.send_header("X-Ca-Hash", args.ca_hash)
                self.send_header("X-Image-Digest", args.image_digest)
                self.send_header("X-Node-Registered-Ready", args.node_registered_ready)
                self.send_header("X-Device-Hostname", args.device_hostname)
                self.send_header("X-KNB-Env", args.knb_env)
                self.send_header("Content-Length", "0")
                self.end_headers()
            elif path == IMAGE_PATH:
                # Stream from disk: the tarball can be hundreds of MB (the
                # mock KNB is based on a local SONiC image), so neither
                # preload it at startup nor hold it in memory per request.
                size = os.path.getsize(args.tarball)
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(size))
                self.end_headers()
                with open(args.tarball, "rb") as f:
                    while True:
                        chunk = f.read(1 << 20)
                        if not chunk:
                            break
                        self.wfile.write(chunk)
            else:
                self.send_response(404)
                self.end_headers()

    return Handler


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--tarball", required=True)
    ap.add_argument("--image-digest", required=True, help='e.g. "sha256:<hex>"')
    ap.add_argument("--apiserver", default="10.0.0.1:6443")
    ap.add_argument("--join-token", default="abcdef.0123456789abcdef")
    ap.add_argument("--ca-hash", default="sha256:deadbeef")
    ap.add_argument("--node-registered-ready", default="false")
    ap.add_argument("--device-hostname", default="mock-node-1")
    ap.add_argument("--knb-env", default="ACR_HOST=mock-acr.invalid")
    # IPv6 loopback: BNB dials tcp6 only (the fleet is v6-only), and
    # loopback keeps the mock off every DUT interface.
    ap.add_argument("--bind", default="::1")
    args = ap.parse_args()

    if not os.path.isfile(args.tarball):
        raise SystemExit("tarball not found: %s" % args.tarball)

    if ":" in args.bind:
        ThreadingHTTPServer.address_family = socket.AF_INET6
    httpd = ThreadingHTTPServer((args.bind, args.port), make_handler(args))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(args.cert, args.key)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    print("mock-kbs listening on :{} (image-digest={})".format(args.port, args.image_digest), flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
