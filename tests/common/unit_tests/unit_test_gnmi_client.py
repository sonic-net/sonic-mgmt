"""Real loopback RPC contract tests; no DUT, Ansible or pygnmi required."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager
from datetime import datetime, timedelta, timezone
import ipaddress
from pathlib import Path
import sys
import threading
import time

import grpc
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from google.protobuf import descriptor_pb2, descriptor_pool

# Avoid tests/common/__init__.py's unrelated Ansible imports in an offline run.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from gnmi import GnmiClient, GnmiClientError, GnmiClientTimeoutError  # noqa: E402
from gnmi.proto import gnmi_pb2 as pb, gnmi_pb2_grpc as rpc  # noqa: E402


class Server(rpc.gNMIServicer):
    def __init__(self):
        self.requests = []
        self.subscription = None
        self.get_response = pb.GetResponse(notification=[pb.Notification(
            timestamp=1, update=[pb.Update(path=pb.Path(elem=[pb.PathElem(name="vni")]),
                                           val=pb.TypedValue(json_ietf_val=b'"1000"'))],
        )])
        self.status = None
        self.delay = 0
        self.finished = threading.Event()
        self.polls = 0

    def Capabilities(self, request, context):
        pytest.fail("Client must not issue an implicit Capabilities RPC")

    def Get(self, request, context):
        self.requests.append(request)
        if self.status:
            context.abort(self.status, "test refusal")
        if self.delay:
            time.sleep(self.delay)
        return self.get_response

    def Set(self, request, context):
        self.requests.append(request)
        return pb.SetResponse(timestamp=12, response=[pb.UpdateResult(
            path=request.update[0].path if request.update else pb.Path(), op=pb.UpdateResult.UPDATE,
        )])

    def Subscribe(self, requests, context):
        self.requests.append(next(requests))
        try:
            yield from self.subscription(requests, context)
        finally:
            self.finished.set()


def update(value=1):
    return pb.SubscribeResponse(update=pb.Notification(timestamp=1, update=[
        pb.Update(path=pb.Path(elem=[pb.PathElem(name="counter")]), val=pb.TypedValue(int_val=value)),
    ]))


def sync():
    return pb.SubscribeResponse(sync_response=True)


@contextmanager
def serve(service, address="127.0.0.1", credentials=None):
    with ThreadPoolExecutor(max_workers=4) as executor:
        server = grpc.server(executor)
        rpc.add_gNMIServicer_to_server(service, server)
        endpoint = f"[{address}]:0" if ":" in address else f"{address}:0"
        port = (server.add_secure_port(endpoint, credentials) if credentials else server.add_insecure_port(endpoint))
        assert port
        server.start()
        try:
            yield port
        finally:
            server.stop(0).wait(5)


@pytest.fixture
def connection():
    service = Server()
    with serve(service) as port:
        yield service, GnmiClient("127.0.0.1", port, plaintext=True, timeout=0.3)


def test_get_set_wire_and_json_compatibility(connection):
    service, client = connection
    result = client.get("/openconfig-interfaces:interfaces/interface[name=Ethernet0]/config/mtu")
    assert result["notification"][0]["update"][0]["val"] == "1000"
    path = service.requests[-1].path[0]
    assert path.origin == "openconfig-interfaces"
    assert path.elem[1].key == {"name": "Ethernet0"}
    assert service.requests[-1].encoding == pb.JSON_IETF
    client.get(r"ROUTE_TABLE/0.0.0.0\/0", target="APPL_DB/asic0")
    assert [element.name for element in service.requests[-1].path[0].elem] == ["ROUTE_TABLE", "0.0.0.0/0"]
    assert service.requests[-1].prefix.target == "APPL_DB/asic0"
    result = client.set(update=[("PORT/Ethernet0/description", '"Public"')],
                        replace=[("TABLE", {"vni": "1000"})], delete=["OLD"], prefix="sonic-db:CONFIG_DB/localhost")
    request = service.requests[-1]
    assert request.update[0].val.json_ietf_val == b'"Public"'
    assert request.replace[0].val.json_ietf_val == b'{"vni": "1000"}'
    assert request.delete[0].elem[0].name == "OLD"
    assert request.prefix.origin == "sonic-db"
    assert result["timestamp"] == 12 and result["response"][0]["op"] == "UPDATE"
    client.set(update=[("DASH_VNET_TABLE/Vnet1", b"\x00\xff")], encoding="proto")
    assert service.requests[-1].update[0].val.proto_bytes == b"\x00\xff"


@pytest.mark.parametrize("typed,expected", [
    (pb.TypedValue(double_val=0.0), 0.0), (pb.TypedValue(double_val=1.25), 1.25),
    (pb.TypedValue(bool_val=False), False), (pb.TypedValue(uint_val=2**63), 2**63),
    (pb.TypedValue(bytes_val=b"\x00\xff"), b"\x00\xff"),
    (pb.TypedValue(json_val=b'""'), ""),
    (pb.TypedValue(leaflist_val=pb.ScalarArray(element=[pb.TypedValue(int_val=0)])), [0]),
])
def test_typed_values_preserve_zero_and_bytes(connection, typed, expected):
    service, client = connection
    service.get_response.notification[0].update[0].val.CopyFrom(typed)
    result = client.get("value")["notification"][0]["update"][0]["val"]
    assert result == expected and type(result) is type(expected)


@pytest.mark.parametrize("status", [grpc.StatusCode.PERMISSION_DENIED, grpc.StatusCode.UNAUTHENTICATED])
def test_rpc_errors_keep_status(connection, status):
    service, client = connection
    service.status = status
    with pytest.raises(GnmiClientError) as caught:
        client.get("value")
    assert caught.value.__cause__.code() == status


def test_unary_deadline(connection):
    service, client = connection
    service.delay = 0.5
    with pytest.raises(GnmiClientTimeoutError) as caught:
        client.get("value")
    assert caught.value.__cause__.code() == grpc.StatusCode.DEADLINE_EXCEEDED


def test_once_stops_at_sync_without_waiting_for_server_eof(connection):
    service, client = connection

    def subscription(requests, context):
        yield update()
        yield sync()
        while context.is_active():
            time.sleep(0.01)

    service.subscription = subscription
    assert list(client.subscribe("openconfig://interfaces", mode="once")) == [
        {"update": {"timestamp": 1, "prefix": None, "origin": None, "target": None, "atomic": False,
                    "update": [{"path": "counter", "val": 1}]}}, {"sync_response": True},
    ]
    assert service.finished.wait(2)


def test_poll_initial_snapshot_then_explicit_polls_and_deletes(connection):
    service, client = connection

    def subscription(requests, context):
        yield sync()  # A valid empty initial snapshot.
        for request in requests:
            assert request.WhichOneof("request") == "poll"
            service.polls += 1
            if service.polls == 1:
                yield update(2)
                yield update(3)
            else:
                yield pb.SubscribeResponse(update=pb.Notification(delete=[pb.Path(elem=[pb.PathElem(name="gone")])]))
            yield sync()

    service.subscription = subscription
    results = list(client.subscribe("table", mode="poll", poll_count=3, poll_interval=0))
    assert results[0] == {"update": {}, "sync_response": True}
    assert [item["val"] for item in results[1]["update"]["update"]] == [2, 3]
    assert results[2]["update"]["delete"] == [{"path": "gone"}]
    assert service.polls == 2
    assert service.finished.wait(2)


@pytest.mark.parametrize("mode", ["once", "poll"])
def test_missing_sync_is_timeout(connection, mode):
    service, client = connection

    def subscription(requests, context):
        yield update()
        while context.is_active():
            time.sleep(0.01)

    service.subscription = subscription
    with pytest.raises(GnmiClientTimeoutError):
        list(client.subscribe("table", mode=mode))
    assert service.finished.wait(2)


@pytest.mark.parametrize("target", ["COUNTERS_DB", "EVENTS"])
def test_stream_count_and_early_close(connection, target):
    service, client = connection

    def subscription(requests, context):
        yield update()
        if target != "EVENTS":
            yield sync()
        while context.is_active():
            yield update(2)
            time.sleep(0.01)

    service.subscription = subscription
    results = list(client.subscribe("counter", target=target, count=2))
    assert len(results) == 2
    assert ("sync_response" in results[0]) == (target != "EVENTS")
    assert service.finished.wait(2)
    service.finished.clear()
    with closing(client.subscribe("counter", target=target)) as subscription:
        next(subscription)
    assert service.finished.wait(2)
    assert not any(t.name == "gnmi-subscribe-reader" for t in threading.enumerate())


def test_stream_window_and_server_error_are_distinct(connection):
    service, client = connection

    def subscription(requests, context):
        yield sync()
        while context.is_active():
            time.sleep(0.01)

    service.subscription = subscription
    assert len(list(client.subscribe("counter", collect_seconds=0.1))) == 1
    assert service.finished.wait(2)

    def refused(requests, context):
        yield sync()
        context.abort(grpc.StatusCode.PERMISSION_DENIED, "role revoked")

    service.subscription = refused
    with pytest.raises(GnmiClientError) as caught:
        list(client.subscribe("counter", collect_seconds=1))
    assert caught.value.__cause__.code() == grpc.StatusCode.PERMISSION_DENIED


def test_subscription_wire_options(connection):
    service, client = connection
    service.subscription = lambda requests, context: iter([sync()])
    list(client.subscribe([{"path": "all[heartbeat=2]", "mode": "on_change", "heartbeat_interval": 2,
                            "suppress_redundant": True}], count=1, prefix="sonic-db://", sample_interval=0.25,
                          updates_only=True, qos={"marking": 32}))
    request = service.requests[-1].subscribe
    assert request.prefix.origin == "sonic-db" and request.updates_only and request.qos.marking == 32
    item = request.subscription[0]
    assert item.path.elem[0].key == {"heartbeat": "2"}
    assert item.mode == pb.ON_CHANGE and item.sample_interval == 250000000
    assert item.heartbeat_interval == 2000000000 and item.suppress_redundant


def certificate_files(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "loopback-test")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
            .sign(key, hashes.SHA256()))
    certificate = cert.public_bytes(serialization.Encoding.PEM)
    private_key = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption())
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(certificate)
    key_path.write_bytes(private_key)
    return certificate, private_key, str(cert_path), str(key_path)


def test_mtls_and_reject_untrusted_server(tmp_path):
    certificate, key, cert_path, key_path = certificate_files(tmp_path)
    service = Server()
    credentials = grpc.ssl_server_credentials([(key, certificate)], root_certificates=certificate,
                                              require_client_auth=True)
    with serve(service, credentials=credentials) as port:
        client = GnmiClient("127.0.0.1", port, ca_cert=cert_path, client_cert=cert_path, client_key=key_path, timeout=1)
        assert client.get("vni")["notification"][0]["update"][0]["val"] == "1000"
        other = tmp_path / "other"
        other.mkdir()
        _, _, wrong_ca, _ = certificate_files(other)
        client.ca_cert = wrong_ca
        with pytest.raises(GnmiClientError):
            client.get("vni")


def test_ipv6_loopback():
    service = Server()
    with serve(service, address="::1") as port:
        assert GnmiClient("::1", port, plaintext=True).get("vni")["notification"]


def test_descriptors_do_not_use_the_process_global_pool():
    # Simulate another library owning an incompatible file with the same name.
    descriptor_pool.Default().AddSerializedFile(descriptor_pb2.FileDescriptorProto(
        name="gnmi.proto", package="another_client", syntax="proto3",
    ).SerializeToString())
    assert pb.GetRequest(path=[pb.Path(origin="sonic-db")]).path[0].origin == "sonic-db"


@pytest.mark.parametrize("mode", ["once", "poll", "stream"])
@pytest.mark.parametrize("failure", ["refused", "eof", "in_band", "bad_json"])
def test_subscription_failures_are_not_success(connection, mode, failure):
    service, client = connection

    def subscription(requests, context):
        if failure == "refused":
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "unmapped identity")
        elif failure == "in_band":
            yield pb.SubscribeResponse(error=pb.Error(code=7, message="denied"))
        elif failure == "bad_json":
            yield pb.SubscribeResponse(update=pb.Notification(update=[
                pb.Update(val=pb.TypedValue(json_ietf_val=b"not-json")),
            ]))

    service.subscription = subscription
    with pytest.raises(GnmiClientError):
        list(client.subscribe("table", mode=mode, collect_seconds=1))
    assert service.finished.wait(2)


def test_poll_failure_after_initial_snapshot(connection):
    service, client = connection

    def subscription(requests, context):
        yield sync()
        assert next(requests).HasField("poll")
        context.abort(grpc.StatusCode.PERMISSION_DENIED, "permission changed")

    service.subscription = subscription
    with closing(client.subscribe("table", mode="poll", poll_count=2, poll_interval=0)) as responses:
        assert next(responses)["sync_response"]
        with pytest.raises(GnmiClientError) as caught:
            next(responses)
    assert caught.value.__cause__.code() == grpc.StatusCode.PERMISSION_DENIED
    assert service.finished.wait(2)


@pytest.mark.parametrize("mode", ["poll", "stream"])
@pytest.mark.parametrize("difference", ["prefix", "origin", "target", "timestamp", "atomic"])
def test_coalescing_rejects_incompatible_notification_metadata(connection, mode, difference):
    service, client = connection

    def subscription(requests, context):
        first, second = update(1), update(2)
        first.update.prefix.elem.add(name="a")
        second.update.prefix.elem.add(name="a")
        if difference == "prefix":
            second.update.prefix.elem[0].name = "b"
        elif difference in ("origin", "target"):
            setattr(second.update.prefix, difference, "other")
        elif difference == "timestamp":
            second.update.timestamp = 2
        else:
            second.update.atomic = True
        yield first
        yield second
        yield sync()

    service.subscription = subscription
    with pytest.raises(GnmiClientError, match="Cannot coalesce"):
        list(client.subscribe("table", mode=mode, count=1))
    assert service.finished.wait(2)


@pytest.mark.parametrize("action", [
    lambda client: client.get([]), lambda client: client.set(),
    lambda client: client.get("a[bad]"), lambda client: client.get("a[key=x"),
    lambda client: client.subscribe("a", poll_count=0),
    lambda client: client.subscribe("a", count=-1),
    lambda client: client.subscribe("a", sample_interval=-1),
    lambda client: client.subscribe("a", mode="invalid"),
])
def test_invalid_requests_fail_before_connect(action):
    with pytest.raises(GnmiClientError):
        action(GnmiClient("invalid", 1, plaintext=True))
