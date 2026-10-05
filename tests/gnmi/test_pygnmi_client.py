"""Integration tests for the PygnmiClient gNMI client via the gnmi_tls fixture."""
import logging
import threading

import grpc
import pytest

from tests.common.fixtures.grpc_fixtures import gnmi_tls  # noqa: F401
from tests.common.pygnmi_client import (
    PygnmiClient,
    PygnmiClientCallError,
    StreamMode,
    SubscribeMode,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
]


def test_pygnmi_capabilities(gnmi_tls):  # noqa: F811
    """Test capabilities() returns expected encodings and models."""
    result = gnmi_tls.pygnmi_client.capabilities()
    logger.info("Capabilities response: %s", result)

    assert "gnmi_version" in result, \
        f"Missing gnmi_version in response: {list(result.keys())}"
    assert result.get("supported_models"), \
        f"supported_models should not be empty: {list(result.keys())}"

    encodings = result.get("supported_encodings", [])
    assert "json_ietf" in encodings, \
        f"json_ietf not in supported_encodings: {encodings}"

    logger.info("gnmi_version: %s", result["gnmi_version"])
    logger.info("supported_encodings: %s", encodings)
    logger.info("supported_models count: %d", len(result["supported_models"]))


def _iter_get_updates(result):
    """Yield (prefix, path, val) for every update in a pygnmi get() response."""
    assert isinstance(result, dict), f"Expected dict response, got: {type(result)}"
    notifications = result.get("notification", [])
    assert notifications, f"Expected at least one notification: {result}"
    for notif in notifications:
        prefix = notif.get("prefix")
        for upd in notif.get("update", []):
            yield prefix, upd.get("path"), upd.get("val")


def _iter_subscribe_updates(result):
    """Yield (prefix, path, val) for every update across subscribe() notifications.

    pygnmi wraps each notification as {"update": {"update": [...], ...}}; a bare
    {"sync_response": True} marker carries no payload and is skipped.
    """
    assert isinstance(result, list), f"Expected list response, got: {type(result)}"
    for notif in result:
        container = notif.get("update")
        if not isinstance(container, dict):
            continue
        prefix = container.get("prefix")
        for upd in container.get("update", []):
            yield prefix, upd.get("path"), upd.get("val")


def _all_keys(obj):
    """Recursively collect every dict key found within a nested val payload."""
    keys = set()
    if isinstance(obj, dict):
        for key, value in obj.items():
            keys.add(key)
            keys |= _all_keys(value)
    elif isinstance(obj, list):
        for value in obj:
            keys |= _all_keys(value)
    return keys


def _as_int(value):
    """Return value as an int if it is an int or an integer-valued string, else None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None


def _find_leaf(obj, suffix):
    """Return the first scalar leaf value whose key ends with `suffix`, else None."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            if isinstance(value, (dict, list)):
                found = _find_leaf(value, suffix)
                if found is not None:
                    return found
            elif key.endswith(suffix):
                return value
    elif isinstance(obj, list):
        for item in obj:
            found = _find_leaf(item, suffix)
            if found is not None:
                return found
    return None


def test_pygnmi_get_interface_mtu(gnmi_tls):  # noqa: F811
    """Test get() returns the exact configured MTU leaf for Ethernet0."""
    path = "/openconfig-interfaces:interfaces/interface[name=Ethernet0]/config/mtu"

    # Read the compared value from the same DUT the fixture targets, so
    # multi-DUT runs cannot cross-compare against a different device.
    expected_mtu = int(
        gnmi_tls.duthost.shell(
            "sonic-db-cli CONFIG_DB hget 'PORT|Ethernet0' mtu")["stdout"].strip()
    )

    result = gnmi_tls.pygnmi_client.get(path)
    logger.info("GET mtu response: %s (expected mtu=%d)", result, expected_mtu)

    updates = list(_iter_get_updates(result))
    assert updates, f"No updates in get() response: {result}"
    assert any(
        (_as_int(val) == expected_mtu
         or _as_int(_find_leaf(val, "mtu")) == expected_mtu)
        and "mtu" in (str(prefix or "") + str(path_str or ""))
        for prefix, path_str, val in updates
    ), f"No 'mtu' update equal to CONFIG_DB mtu {expected_mtu} in: {result}"


def test_pygnmi_get_interface_counters(gnmi_tls):  # noqa: F811
    """Test get() returns numeric interface counters for Ethernet0."""
    path = "/openconfig-interfaces:interfaces/interface[name=Ethernet0]/state/counters"

    result = gnmi_tls.pygnmi_client.get(path)
    logger.info("GET counters response: %s", result)

    payloads = [val for _, _, val in _iter_get_updates(result)]
    assert payloads, f"No update payloads in get() response: {result}"

    for leaf in ["in-pkts", "out-pkts", "in-octets", "out-octets",
                 "in-errors", "out-errors"]:
        val = next((_find_leaf(payload, leaf) for payload in payloads
                    if _find_leaf(payload, leaf) is not None), None)
        assert val is not None, f"Missing counter {leaf} in response: {result}"
        assert _as_int(val) is not None, \
            f"Counter {leaf} value is not numeric: {val!r}"


def test_pygnmi_get_empty_paths_raises(gnmi_tls):  # noqa: F811
    """Test get() raises PygnmiClientCallError when no paths are provided."""
    with pytest.raises(PygnmiClientCallError, match="at least one path"):
        gnmi_tls.pygnmi_client.get([])


def test_pygnmi_subscribe_sample_queue_counters(gnmi_tls):  # noqa: F811
    """Test subscribe() STREAM+SAMPLE collects COUNTERS_DB queue stats."""
    result = list(gnmi_tls.pygnmi_client.subscribe(
        "COUNTERS/Ethernet0/Queues",
        target="COUNTERS_DB",
        sample_interval=1,
        collect_seconds=6,
    ))
    logger.info("SUBSCRIBE queue counters response: %s", result)

    keys = set()
    for _, path_str, val in _iter_subscribe_updates(result):
        keys |= _all_keys(val)
        if path_str:
            keys.add(path_str)
    assert keys, f"No update payloads collected: {result}"

    assert any("Ethernet0:0" in key for key in keys), \
        f"Missing queue Ethernet0:0 in keys: {sorted(keys)}"
    assert any("SAI_QUEUE_STAT_PACKETS" in key for key in keys), \
        f"Missing SAI_QUEUE_STAT_PACKETS in keys: {sorted(keys)}"


def test_pygnmi_subscribe_stream_count(gnmi_tls):  # noqa: F811
    """Test subscribe() STREAM stops after `count` notifications."""
    count = 3
    result = list(gnmi_tls.pygnmi_client.subscribe(
        "COUNTERS/Ethernet0",
        target="COUNTERS_DB",
        sample_interval=1,
        count=count,
        collect_seconds=30,
    ))
    logger.info("SUBSCRIBE stream count collected %d notifications", len(result))
    assert len(result) == count, \
        f"Expected exactly {count} notifications, got {len(result)}: {result}"


def test_pygnmi_subscribe_early_break(gnmi_tls):  # noqa: F811
    """Test subscribe() yields incrementally and stops cleanly on early break."""
    want = 2
    collected = []
    for notif in gnmi_tls.pygnmi_client.subscribe(
        "COUNTERS/Ethernet0",
        target="COUNTERS_DB",
        sample_interval=1,
        collect_seconds=30,
    ):
        collected.append(notif)
        if len(collected) >= want:
            break
    logger.info("SUBSCRIBE yielded %d notifications before break", len(collected))
    assert len(collected) == want, \
        f"Expected to break after {want} notifications, got {len(collected)}"


def test_pygnmi_subscribe_poll(gnmi_tls):  # noqa: F811
    """Test subscribe() POLL returns one coalesced update per poll."""
    poll_count = 2
    result = list(gnmi_tls.pygnmi_client.subscribe(
        "COUNTERS/Ethernet0",
        target="COUNTERS_DB",
        mode=SubscribeMode.POLL,
        poll_count=poll_count,
        poll_interval=0.5,
    ))
    logger.info("SUBSCRIBE poll response: %s", result)
    assert len(result) == poll_count, \
        f"Expected {poll_count} poll responses, got {len(result)}"
    for notif in result:
        assert "update" in notif, f"Poll response missing update payload: {notif}"


def test_pygnmi_subscribe_once(gnmi_tls):  # noqa: F811
    """Test subscribe() ONCE drains a snapshot up to sync_response.

    Uses an OpenConfig path: sonic-gnmi's DbClient has a no-op OnceRun, so
    ONCE only works via TranslClient, whose Subscribe routing requires path
    origin to be exactly "openconfig" (pygnmi's "origin://" syntax; a
    "/module:element" path would emit origin="openconfig-interfaces" and be
    rejected as an unsupported origin).
    """
    result = list(gnmi_tls.pygnmi_client.subscribe(
        "openconfig://interfaces/interface[name=Ethernet0]/state/counters",
        mode=SubscribeMode.ONCE,
    ))
    logger.info("SUBSCRIBE once collected %d notifications", len(result))
    assert result, "ONCE subscription returned no notifications"
    updates = list(_iter_subscribe_updates(result))
    assert updates, f"ONCE subscription returned no update payloads: {result}"


# --- offline unit tests (no DUT required) -----------------------------------


def _offline_client():
    """A client used only for request-building/validation paths (never connects)."""
    return PygnmiClient("", 0, plaintext=True, connect=False)


def test_build_subscribe_request_passthrough():
    """Test _build_subscribe_request forwards extra options verbatim."""
    client = _offline_client()
    request = client._build_subscribe_request(
        ["proc/uptime"],
        SubscribeMode.STREAM,
        StreamMode.SAMPLE,
        1,
        30,
        "json_ietf",
        extra={"prefix": "/", "updates_only": True, "qos": {"marking": 32}},
    )
    assert request["mode"] == "stream"
    assert request["encoding"] == "json_ietf"
    assert request["prefix"] == "/"
    assert request["updates_only"] is True
    assert request["qos"] == {"marking": 32}

    sub = request["subscription"][0]
    assert sub["path"] == "proc/uptime"
    assert sub["mode"] == "sample"
    assert sub["sample_interval"] == 1_000_000_000
    assert sub["heartbeat_interval"] == 30_000_000_000


def test_build_subscribe_request_per_path_dict():
    """Test _build_subscribe_request honors per-path dict overrides."""
    client = _offline_client()
    request = client._build_subscribe_request(
        [
            {"path": "a", "mode": "on_change"},
            {"path": "b", "sample_interval": 2},
        ],
        SubscribeMode.STREAM,
        StreamMode.SAMPLE,
        1,
        None,
        "json_ietf",
    )
    first, second = request["subscription"]
    assert first["path"] == "a"
    assert first["mode"] == "on_change"
    assert second["path"] == "b"
    assert second["mode"] == "sample"
    assert second["sample_interval"] == 2_000_000_000


def test_build_subscribe_request_poll_drops_stream_keys():
    """Test _build_subscribe_request strips stream-only keys for POLL/ONCE."""
    client = _offline_client()
    request = client._build_subscribe_request(
        [{"path": "a", "mode": "sample", "sample_interval": 1}],
        SubscribeMode.POLL,
        StreamMode.SAMPLE,
        None,
        None,
        "json_ietf",
    )
    assert request["mode"] == "poll"
    sub = request["subscription"][0]
    assert "mode" not in sub
    assert "sample_interval" not in sub
    assert "heartbeat_interval" not in sub


def test_subscribe_requires_paths():
    """Test subscribe() rejects an empty path list before connecting."""
    with pytest.raises(PygnmiClientCallError, match="at least one path"):
        _offline_client().subscribe([])


def test_subscribe_poll_rejects_negative_interval():
    """Test POLL rejects a negative trigger interval before connecting."""
    with pytest.raises(PygnmiClientCallError, match="poll_interval must be >= 0"):
        _offline_client().subscribe("path", mode=SubscribeMode.POLL,
                                    poll_interval=-1)


def test_subscribe_poll_rejects_non_positive_count():
    """Test POLL rejects a non-positive trigger count before connecting."""
    with pytest.raises(PygnmiClientCallError, match="poll_count must be > 0"):
        _offline_client().subscribe("path", mode=SubscribeMode.POLL,
                                    poll_count=0)


def test_get_requires_paths():
    """Test get() rejects an empty path list before connecting."""
    with pytest.raises(PygnmiClientCallError, match="at least one path"):
        _offline_client().get([])


@pytest.mark.parametrize(
    "status, details",
    [
        (grpc.StatusCode.CANCELLED, "Channel closed!"),
        (grpc.StatusCode.INVALID_ARGUMENT, "queue: disposed"),
    ],
)
def test_subscribe_closes_receiver_without_unhandled_exception(monkeypatch, status, details):
    """Test wrapper-owned shutdown absorbs pygnmi's terminal RPC errors."""
    channel_closed = threading.Event()
    unhandled = []

    class ExpectedShutdownError(grpc.RpcError):
        def code(self):
            return status

        def details(self):
            return details

    class FakeSubscriber:
        def __init__(self):
            self._subscribe_thread = threading.Thread(target=self._receive)
            self._subscribe_thread.start()

        def _receive(self):
            channel_closed.wait(timeout=1)
            raise ExpectedShutdownError()

        def get_update(self, timeout):
            return {"update": {}}

        def close(self):
            self._subscribe_thread.join(0.01)

    class FakeGnmiClient:
        def connect(self):
            pass

        def subscribe2(self, **kwargs):
            self.subscriber = FakeSubscriber()
            return self.subscriber

        def close(self):
            channel_closed.set()

    fake_client = FakeGnmiClient()
    monkeypatch.setattr("tests.common.pygnmi_client.gNMIclient", lambda **kwargs: fake_client)
    monkeypatch.setattr(threading, "excepthook", lambda args: unhandled.append(args.exc_value))

    subscription = _offline_client().subscribe("path", collect_seconds=30)
    result = next(subscription)
    subscription.close()

    assert result == {"update": {}}
    assert not fake_client.subscriber._subscribe_thread.is_alive()
    assert unhandled == []


@pytest.mark.parametrize(
    "error",
    [
        RuntimeError("unexpected receiver failure"),
        type(
            "UnexpectedCancellation",
            (grpc.RpcError,),
            {
                "code": lambda self: grpc.StatusCode.CANCELLED,
                "details": lambda self: "server cancelled request",
            },
        )(),
    ],
)
def test_subscribe_reports_unexpected_receiver_exception(monkeypatch, error):
    """Test wrapper-owned shutdown does not hide unrelated receiver errors."""
    channel_closed = threading.Event()
    unhandled = []

    class FakeSubscriber:
        def __init__(self):
            self._subscribe_thread = threading.Thread(target=self._receive)
            self._subscribe_thread.start()

        def _receive(self):
            channel_closed.wait(timeout=1)
            raise error

        def get_update(self, timeout):
            return {"update": {}}

        def close(self):
            self._subscribe_thread.join(0.01)

    class FakeGnmiClient:
        def connect(self):
            pass

        def subscribe2(self, **kwargs):
            self.subscriber = FakeSubscriber()
            return self.subscriber

        def close(self):
            channel_closed.set()

    fake_client = FakeGnmiClient()
    monkeypatch.setattr("tests.common.pygnmi_client.gNMIclient", lambda **kwargs: fake_client)
    monkeypatch.setattr(threading, "excepthook", lambda args: unhandled.append(args.exc_value))

    list(_offline_client().subscribe("path", count=1, collect_seconds=1))

    assert len(unhandled) == 1
    assert unhandled[0] is error
