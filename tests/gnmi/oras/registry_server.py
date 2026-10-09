"""
Minimal pull-only OCI registry for the gNOI ORAS tests.

Runs on the PTF host (which has no Docker daemon, so a real registry:2
container is not an option there). Serves pre-generated artifact files
from a data directory over HTTPS with Basic auth -- just the read-side
subset of the OCI distribution API that the DUT's oras-go client needs:

    GET/HEAD /v2/                          -> 200 (API version probe)
    GET/HEAD /v2/<repo>/manifests/<tag>    -> manifest JSON
    GET/HEAD /v2/<repo>/blobs/<digest>     -> blob bytes

Every request must carry the expected Basic auth header; anything else
gets 401 with a "Basic realm" challenge. Unknown tags/digests get 404.

Expected data directory layout (created by the test fixture):
    server.crt, server.key   TLS certificate for this host's IP
    manifests/<tag>          manifest JSON files
    blobs/<sha256:...>       blob files named by their digest
"""

import argparse
import base64
import hashlib
import os
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"


class OrasRegistryHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        self._handle(send_body=True)

    def do_HEAD(self):
        self._handle(send_body=False)

    def _handle(self, send_body):
        # Reject anything without the exact expected Basic auth header
        if self.headers.get("Authorization") != self.server.auth_header:
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="Registry"')
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        # Route by path; the repository name segment is intentionally ignored
        path = self.path.split("?", 1)[0]
        if path in ("/v2", "/v2/"):
            body, content_type = b"{}", "application/json"
        elif "/manifests/" in path:
            body = self._read_file("manifests", path.rsplit("/manifests/", 1)[1])
            content_type = MANIFEST_MEDIA_TYPE
        elif "/blobs/" in path:
            body = self._read_file("blobs", path.rsplit("/blobs/", 1)[1])
            content_type = "application/octet-stream"
        else:
            body = None

        if body is None:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        # Clients use this header to verify what they got is what they asked for
        self.send_header(
            "Docker-Content-Digest",
            "sha256:" + hashlib.sha256(body).hexdigest())
        self.end_headers()
        if send_body:
            self.wfile.write(body)

    def _read_file(self, subdir, name):
        return self.server.files.get(subdir, {}).get(name)


def _load_registry_files(data_dir):
    files = {}
    for subdir in ("manifests", "blobs"):
        files[subdir] = {}
        directory = os.path.join(data_dir, subdir)
        with os.scandir(directory) as entries:
            for entry in entries:
                if not entry.is_file(follow_symlinks=False):
                    continue
                with open(entry.path, "rb") as f:
                    files[subdir][entry.name] = f.read()
    return files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--dir", required=True, help="data directory")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    args = parser.parse_args()

    server = ThreadingHTTPServer(("", args.port), OrasRegistryHandler)
    # Load the fixed test artifact before accepting requests. Request path
    # components are then dictionary keys, never filesystem path expressions.
    server.files = _load_registry_files(args.dir)
    # Precompute the one header value that counts as authenticated
    creds = "{}:{}".format(args.username, args.password).encode()
    server.auth_header = "Basic " + base64.b64encode(creds).decode()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # Disallow the deprecated TLSv1 / TLSv1.1 protocol versions
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(
        os.path.join(args.dir, "server.crt"),
        os.path.join(args.dir, "server.key"))
    server.socket = context.wrap_socket(server.socket, server_side=True)

    server.serve_forever()


if __name__ == "__main__":
    main()
