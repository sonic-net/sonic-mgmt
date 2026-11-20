#!/usr/bin/env python3
"""gNMI dial-out collector for sonic-mgmt tests.

Implements the server side of SONiC's gnmi.sonic.gNMIDialOut service
(sonic-gnmi/proto/dial_out.proto): a bidirectional-streaming Publish RPC
whose request messages are standard gNMI SubscribeResponse. The service is
registered as a generic gRPC handler over raw bytes, so the collector needs
no proto codegen at all — its only dependency is grpcio. Received messages
are appended as base64 JSON lines with receive metadata to a data file;
decoding happens test-side in conftest.py via pygnmi's bundled gnmi_pb2
(docker-sonic-mgmt ships pygnmi; docker-ptf does not).

The SONiC dialout client always dials with TLS (server verification
disabled via -insecure), so the collector serves TLS with the throwaway
cert pair deployed by the test (see conftest.py copy_collector).

Runs on the PTF host, started with nohup (see conftest.py); stdout/stderr
are redirected to a log file because nohup breaks stderr for long-running
python processes (same pattern as tests/gnmi/crl/crl_server.py).
"""
import argparse
import base64
import json
import sys
import threading
import time
from concurrent import futures

import grpc

PUBLISH_METHOD = "/gnmi.sonic.gNMIDialOut/Publish"


class Recorder(object):
    def __init__(self, data_file):
        self.data_file = data_file
        self.lock = threading.Lock()

    def record(self, raw, peer):
        entry = {
            "size": len(raw),
            "raw_b64": base64.b64encode(raw).decode("ascii"),
            "ts": time.time(),
            "peer": peer,
        }
        with self.lock:
            with open(self.data_file, "a") as f:
                f.write(json.dumps(entry) + "\n")
                f.flush()


class DialOutHandler(grpc.GenericRpcHandler):
    """Serves gnmi.sonic.gNMIDialOut/Publish over raw bytes."""

    def __init__(self, recorder):
        self.recorder = recorder

    def service(self, handler_call_details):
        if handler_call_details.method != PUBLISH_METHOD:
            return None
        recorder = self.recorder

        def publish(request_iterator, context):
            peer = context.peer()
            print("Publish stream opened from %s" % peer)
            sys.stdout.flush()
            for raw in request_iterator:
                recorder.record(raw, peer)
            print("Publish stream closed from %s" % peer)
            sys.stdout.flush()
            return
            yield  # pragma: no cover - makes publish a generator

        return grpc.stream_stream_rpc_method_handler(
            publish, request_deserializer=None, response_serializer=None)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--data", required=True, help="JSONL output file")
    parser.add_argument("--cert", required=True, help="TLS server certificate (PEM)")
    parser.add_argument("--key", required=True, help="TLS server private key (PEM)")
    args = parser.parse_args()

    with open(args.key, "rb") as f:
        key_bytes = f.read()
    with open(args.cert, "rb") as f:
        crt_bytes = f.read()

    # SO_REUSEPORT (grpc's default on Linux) would let a second collector —
    # e.g. from another sonic-mgmt session sharing this PTF — bind the same
    # port and silently steal a share of the publish streams. Disable it so
    # a port collision fails loudly here instead.
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4),
                         options=(("grpc.so_reuseport", 0),))
    server.add_generic_rpc_handlers((DialOutHandler(Recorder(args.data)),))
    creds = grpc.ssl_server_credentials([(key_bytes, crt_bytes)])
    bound = server.add_secure_port("[::]:%d" % args.port, creds)
    if bound != args.port:
        print("FATAL: could not bind port %d (got %d) — already in use?"
              % (args.port, bound))
        sys.stdout.flush()
        sys.exit(1)
    server.start()
    print("Ready to serve on %d" % args.port)
    sys.stdout.flush()
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
