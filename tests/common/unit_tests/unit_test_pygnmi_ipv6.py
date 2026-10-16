"""Real local gRPC transport checks for the pinned PyPI pygnmi client."""
import datetime
import ipaddress
from concurrent.futures import ThreadPoolExecutor

import grpc
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from pygnmi.spec.v080 import gnmi_pb2 as pb
from pygnmi.spec.v080 import gnmi_pb2_grpc as rpc

from tests.common import pygnmi_client as module


class GnmiService(rpc.gNMIServicer):
    def Capabilities(self, request, context):
        return pb.CapabilityResponse(supported_encodings=[pb.JSON_IETF], gNMI_version="0.8.0")

    def Get(self, request, context):
        return pb.GetResponse(notification=[pb.Notification(update=[
            pb.Update(path=pb.Path(elem=[pb.PathElem(name="value")]),
                      val=pb.TypedValue(json_ietf_val=b'"received"'))])])

    def Subscribe(self, request_iterator, context):
        next(request_iterator)
        yield pb.SubscribeResponse(update=pb.Notification(timestamp=1, update=[
            pb.Update(path=pb.Path(elem=[pb.PathElem(name="value")]),
                      val=pb.TypedValue(json_ietf_val=b'"received"'))]))
        yield pb.SubscribeResponse(sync_response=True)


@pytest.fixture
def pki(tmp_path):
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "unit-test-ca")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - datetime.timedelta(minutes=5))
          .not_valid_after(now + datetime.timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .sign(ca_key, hashes.SHA256()))

    def leaf(name, usage, server=False):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        builder = (x509.CertificateBuilder()
                   .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
                   .issuer_name(ca_name).public_key(key.public_key())
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(now - datetime.timedelta(minutes=5))
                   .not_valid_after(now + datetime.timedelta(days=1))
                   .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                   .add_extension(x509.ExtendedKeyUsage([usage]), critical=False))
        if server:
            builder = builder.add_extension(x509.SubjectAlternativeName([
                x509.IPAddress(ipaddress.ip_address("::1")),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")), x509.DNSName("localhost")]), critical=False)
        return (key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()),
                builder.sign(ca_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM))

    server_key, server_cert = leaf("localhost", ExtendedKeyUsageOID.SERVER_AUTH, True)
    client_key, client_cert = leaf("test-client", ExtendedKeyUsageOID.CLIENT_AUTH)
    ca_pem = ca.public_bytes(serialization.Encoding.PEM)
    paths = {}
    for name, content in [("ca_cert", ca_pem), ("client_cert", client_cert), ("client_key", client_key)]:
        path = tmp_path / name
        path.write_bytes(content)
        path.chmod(0o600)
        paths[name] = str(path)
    return grpc.ssl_server_credentials([(server_key, server_cert)], root_certificates=ca_pem,
                                       require_client_auth=True), paths


@pytest.mark.parametrize("host,tls", [("::1", False), ("::1", True), ("[::1]", True),
                                      ("127.0.0.1", False), ("127.0.0.1", True),
                                      ("localhost", True), ("unix", False)])
def test_get_and_once_subscription_over_real_transport(host, tls, pki, tmp_path):
    server = grpc.server(ThreadPoolExecutor(max_workers=2))
    rpc.add_gNMIServicer_to_server(GnmiService(), server)
    address = "unix:" + str(tmp_path / "gnmi.sock") if host == "unix" else "[::1]:0" if ":" in host else "127.0.0.1:0"
    port = server.add_secure_port(address, pki[0]) if tls else server.add_insecure_port(address)
    assert port
    server.start()
    client = None
    try:
        client = module.PygnmiClient(
            address if host == "unix" else host, port,
            plaintext=not tls, timeout=3, **(pki[1] if tls else {}))
        result = client.get("value")
        assert result["notification"][0]["update"][0]["val"] == "received"
        updates = list(client.subscribe("value", mode=module.SubscribeMode.ONCE))
        assert any("received" in str(update) for update in updates)
    finally:
        if client:
            client.close()
        server.stop(0).wait()


@pytest.mark.parametrize("host,expected", [
    ("2001:db8::1", "[2001:db8::1]"),
    ("fe80::1%eth0", "[fe80::1%eth0]"),
    ("[::1]", "[::1]"), ("example.com", "example.com"),
    ("192.0.2.1", "192.0.2.1"),
    ("unix:/tmp/gnmi.sock", "unix:/tmp/gnmi.sock"),
])
def test_public_target_argument_is_normalized_without_changing_host(monkeypatch, host, expected):
    calls = []
    monkeypatch.setattr(module, "gNMIclient", lambda **kwargs: calls.append(kwargs))
    client = module.PygnmiClient(host, 50052, plaintext=True, connect=False)
    client._build_client()
    assert calls[0]["target"] == (expected, 50052)
    assert client.host == host
