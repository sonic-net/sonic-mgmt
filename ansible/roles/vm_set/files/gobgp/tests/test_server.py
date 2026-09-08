"""HTTP front end wire behaviour.

Covers the framing the shim relies on rather than the command semantics the
parser and translator tests already own: the body cap under both framings
`requests` can emit, ``/adj-in`` routing, the plain-text error contract, and
fail-fast binding.
"""
import json
import socket
import threading

import pytest

pytest.importorskip("gobgp.shim._gbapi",
                    reason="gobgp gRPC stubs are generated into the PTF image")
pytest.importorskip("flask", reason="flask ships in the PTF image")

from werkzeug.serving import make_server  # noqa: E402

from gobgp.shim import server as shim_server  # noqa: E402
from gobgp.shim.server import make_app, MAX_BODY_BYTES, _RequestHandler  # noqa: E402
from gobgp.shim.translator import NeighborClient  # noqa: E402
from gobgp.tests.fakes import FakeStub  # noqa: E402

ANNOUNCE = b"command=announce route 100.0.0.0/24 next-hop 10.0.0.57"


@pytest.fixture
def serve():
    """Factory starting a shim server on an ephemeral port; returns the port."""
    servers = []

    def _start(stub):
        client = NeighborClient("127.0.0.1:50052", "v4", "ARISTA01T1", stub=stub)
        srv = make_server("127.0.0.1", 0, make_app(client), threaded=True,
                          request_handler=_RequestHandler)
        servers.append(srv)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv.server_address[1]

    yield _start
    for srv in servers:
        srv.shutdown()
        srv.server_close()


def _send(port, raw):
    """Send a raw request; return the response, read to end of connection."""
    sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    try:
        sock.sendall(raw)
        chunks = []
        while True:
            buf = sock.recv(65536)
            if not buf:
                break
            chunks.append(buf)
        return b"".join(chunks).decode("utf-8", errors="replace")
    finally:
        sock.close()


def _post_sized(port, body, content_length):
    """POST ``body`` under a chosen ``Content-Length``."""
    head = ("POST / HTTP/1.1\r\n"
            "Host: 127.0.0.1\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Connection: close\r\n"
            "Content-Length: %d\r\n\r\n" % content_length)
    return _send(port, head.encode() + body)


def _post_chunked(port, body):
    """POST ``body`` as a single chunk, with no ``Content-Length``."""
    head = ("POST / HTTP/1.1\r\n"
            "Host: 127.0.0.1\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Connection: close\r\n"
            "Transfer-Encoding: chunked\r\n\r\n")
    frame = b"%x\r\n%s\r\n0\r\n\r\n" % (len(body), body)
    return _send(port, head.encode() + frame)


def test_oversized_content_length_rejected(serve):
    stub = FakeStub()
    resp = _post_sized(serve(stub), b"", MAX_BODY_BYTES + 1)
    assert "413" in resp.splitlines()[0]
    assert stub.call_count == 0


def test_oversized_chunked_body_rejected(serve, monkeypatch):
    """An over-cap chunked body must be refused, not truncated and applied.

    werkzeug caps the stream at ``MAX_CONTENT_LENGTH`` without raising, so
    without the shim's own check this returns 200 for a body cut mid-command.
    """
    monkeypatch.setattr(shim_server, "MAX_BODY_BYTES", 1000)
    stub = FakeStub()
    resp = _post_chunked(serve(stub), ANNOUNCE + b"\n" + b"x" * 2000)
    assert "413" in resp.splitlines()[0]
    assert stub.call_count == 0


def test_body_within_cap_applies(serve):
    stub = FakeStub()
    resp = _post_sized(serve(stub), ANNOUNCE, len(ANNOUNCE))
    assert "200" in resp.splitlines()[0]
    assert stub.total_paths == 1


def test_chunked_body_applies(serve):
    """A body framed by ``Transfer-Encoding`` must apply, not silently no-op."""
    stub = FakeStub()
    resp = _post_chunked(serve(stub), ANNOUNCE)
    assert "200" in resp.splitlines()[0]
    assert resp.rstrip().endswith("done")
    assert stub.total_paths == 1


@pytest.mark.parametrize("target", ["/adj-in", "/adj-in/", "/adj-in?debug=1"])
def test_adj_in_returns_received_prefixes(serve, target):
    """A trailing slash or query string must not fall through to liveness."""
    stub = FakeStub(peers=["10.0.0.57"], adj_in={"10.0.0.57": ["100.0.0.0/24"]})
    resp = _send(serve(stub), ("GET %s HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                               "Connection: close\r\n\r\n" % target).encode())
    assert "200" in resp.splitlines()[0]
    body = json.loads(resp.split("\r\n\r\n", 1)[1])
    assert body == {"prefixes": ["100.0.0.0/24"]}


@pytest.mark.parametrize("target", ["/", "/anything", "/static/x"])
def test_other_gets_return_liveness(serve, target):
    """Every non-``/adj-in`` GET is liveness, including flask's static path."""
    resp = _send(serve(FakeStub()), ("GET %s HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                                     "Connection: close\r\n\r\n" % target).encode())
    assert "200" in resp.splitlines()[0]
    assert resp.split("\r\n\r\n", 1)[1] == "OK\n"


def test_unexpected_error_stays_plain_text(serve, monkeypatch):
    """An unhandled error must keep the text contract, not render an HTML page.

    The handler owns the log record, so werkzeug never logs the untrusted
    request path, and the reply names only the failure type.
    """
    def _boom(_body):
        raise RuntimeError("boom")

    monkeypatch.setattr(shim_server.parser, "commands_from_body", _boom)
    resp = _post_sized(serve(FakeStub()), ANNOUNCE, len(ANNOUNCE))
    assert "500" in resp.splitlines()[0]
    assert "<!doctype" not in resp.lower()
    body = resp.split("\r\n\r\n", 1)[1]
    assert body == "error: RuntimeError\n"
    assert "boom" not in body


def test_bind_clash_fails_the_shard(tmp_path):
    """An unbindable port must fail the shard, not leave a dead serve thread."""
    from gobgp.shim.__main__ import main

    held = socket.socket()
    # loopback is enough to collide with the shim's 0.0.0.0 bind
    held.bind(("127.0.0.1", 0))
    held.listen(1)
    port = held.getsockname()[1]
    portmap = tmp_path / "portmap.json"
    portmap.write_text(json.dumps(
        {str(port): {"grpc": "127.0.0.1:50052", "family": "v4", "name": "N1"}}))

    result = []
    # main() serves forever once bound, so a regression would hang the suite.
    runner = threading.Thread(
        target=lambda: result.append(main(["--portmap", str(portmap)])),
        daemon=True)
    try:
        runner.start()
        runner.join(timeout=30)
        assert not runner.is_alive(), "shard kept running despite a bound port"
        assert result == [1]
    finally:
        held.close()
