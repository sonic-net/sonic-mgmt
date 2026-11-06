"""Shared native gNMI connection and JSON request construction."""
import json
from contextlib import contextmanager

import grpc
from pygnmi.spec.v080 import gnmi_pb2, gnmi_pb2_grpc


@contextmanager
def gnmi_connection(fixture):
    """Open one shared TLS connection and close it even if stub creation fails."""
    certs = fixture.pygnmi_client
    with open(certs.ca_cert, "rb") as stream:
        ca = stream.read()
    with open(certs.client_key, "rb") as stream:
        key = stream.read()
    with open(certs.client_cert, "rb") as stream:
        certificate = stream.read()
    credentials = grpc.ssl_channel_credentials(root_certificates=ca, private_key=key, certificate_chain=certificate)
    host = fixture.host
    if ":" in host and not host.startswith("["):
        host = "[{}]".format(host)
    with grpc.secure_channel("{}:{}".format(host, fixture.port), credentials,
                             options=(("grpc.enable_retries", 0),)) as channel:
        yield channel, gnmi_pb2_grpc.gNMIStub(channel)


def build_native_set_request(parts, value):
    request = gnmi_pb2.SetRequest()
    update = request.update.add()
    update.path.origin = "sonic-db"
    for name in parts:
        update.path.elem.add(name=name)
    update.val.json_ietf_val = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return request
