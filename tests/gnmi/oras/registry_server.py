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
import re
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"

# Tags are plain identifiers (e.g. "latest", "v1.2.3"); digests look like
# "sha256:<hex>". Reject anything outside this allowlist before it is ever
# used to build a filesystem path, rather than relying solely on
# basename()/realpath() containment checks after the fact.
SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.:-]*$")


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
        # Reject anything that isn't a plain tag/digest identifier before it
        # ever touches a filesystem path -- no "/", "..", or other
        # traversal-relevant characters are permitted.
        if not SAFE_NAME_RE.match(name):
            return None
        base_dir = os.path.realpath(os.path.join(self.server.data_dir, subdir))
        # Resolve the request against the set of files actually present in
        # base_dir (a fixed, trusted location) rather than trusting the
        # client-supplied name to build a path directly. Only a name that is
        # an exact match for an existing entry is ever opened.
        try:
            existing_names = set(os.listdir(base_dir))
        except OSError:
            return None
        if name not in existing_names:
            return None
        fpath = os.path.join(base_dir, name)
        if not os.path.isfile(fpath):
            return None
        with open(fpath, "rb") as f:
            return f.read()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--dir", required=True, help="data directory")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    args = parser.parse_args()

    server = ThreadingHTTPServer(("", args.port), OrasRegistryHandler)
    server.data_dir = args.dir
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
