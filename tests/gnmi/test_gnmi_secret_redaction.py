"""Verify read-response redaction using only isolated synthetic credentials."""

import shlex
import threading
import uuid

import pytest
from pygnmi.spec.v080 import gnmi_pb2

from tests.common.fixtures.grpc_fixtures import gnmi_tls  # noqa: F401
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.gnmi_connection import gnmi_connection

pytestmark = [
    pytest.mark.topology("any"),
    pytest.mark.disable_loganalyzer,
    pytest.mark.usefixtures("setup_gnmi_ntp_client_server", "check_dut_timestamp"),
]

CREATE_ENTRY = (
    "if redis.call('exists', KEYS[1]) ~= 0 then return 0 end " "redis.call('hset', KEYS[1], unpack(ARGV)); return 1"
)
DELETE_ENTRY = (
    "if redis.call('hlen', KEYS[1]) ~= #ARGV / 2 then return 0 end "
    "for i = 1, #ARGV, 2 do "
    "if redis.call('hget', KEYS[1], ARGV[i]) ~= ARGV[i + 1] then return 0 end end "
    "return redis.call('del', KEYS[1])"
)


@pytest.fixture(params=["TACPLUS_SERVER", "MACSEC_PROFILE", "SNMP_COMMUNITY"])
def synthetic_entry(request, duthosts, rand_one_dut_hostname, gnmi_tls):  # noqa: F811
    """Create one owned entry atomically; never back up existing credentials."""
    duthost = duthosts[rand_one_dut_hostname]
    token = uuid.uuid4().hex
    secret = "gnmi_test_{}".format(token[:20])
    table = request.param
    key = "gnmi_redaction_{}".format(token)
    if table == "TACPLUS_SERVER":
        key = "192.0.2.{}".format(1 + int(token[:2], 16) % 254)
        fields = {"passkey": secret, "tcp_port": "49"}
        secret_field, public_field, public_value = "passkey", "tcp_port", "49"
    elif table == "MACSEC_PROFILE":
        secret = "00112233445566778899aabbccddeeff" + token
        fields = {"primary_cak": secret, "fallback_cak": secret, "cipher_suite": "GCM-AES-128"}
        secret_field, public_field, public_value = "primary_cak", "cipher_suite", "GCM-AES-128"
    else:
        key = secret
        fields = {"TYPE": "RO"}
        secret_field, public_field, public_value = None, "TYPE", "RO"
    redis_key = "{}|{}".format(table, key)
    arguments = [item for pair in fields.items() for item in pair]

    def run_script(script):
        command = shlex.join(["sonic-db-cli", "CONFIG_DB", "EVAL", script, "1", redis_key] + arguments)
        result = duthost.shell(command, module_ignore_errors=True)
        pytest_assert(result.get("rc") == 0, "Synthetic entry operation failed")
        return result["stdout"].strip()

    if run_script(CREATE_ENTRY) != "1":
        pytest.skip("Synthetic entry key already exists; existing configuration was not read or changed")
    try:
        yield {
            "table": table,
            "key": key,
            "secret": secret,
            "secret_field": secret_field,
            "public_field": public_field,
            "public_value": public_value,
        }
    finally:
        pytest_assert(run_script(DELETE_ENTRY) == "1", "Synthetic entry changed; refusing to delete foreign data")


def _read_path(entry, route, field=None):
    """Construct an exact-entry/leaf read, never a live table or database dump."""
    prefix = gnmi_pb2.Path()
    parts = [entry["table"], entry["key"]]
    if route == "native":
        prefix.origin = "sonic-db"
        parts = ["CONFIG_DB", "localhost"] + parts
    else:
        prefix.target = "CONFIG_DB"
    if field:
        parts.append(field)
    path = gnmi_pb2.Path()
    for part in parts:
        path.elem.add(name=part)
    return prefix, path


def _assert_redacted(response, entry, public=False):
    """Inspect protobuf bytes without including response contents in failures."""
    wire = response.SerializeToString()
    pytest_assert(entry["secret"].encode() not in wire, "Synthetic credential leaked in gNMI response")
    if public:
        notifications = response.notification if isinstance(response, gnmi_pb2.GetResponse) else [response.update]
        pytest_assert(
            any(
                entry["public_value"].encode() in update.val.SerializeToString()
                for notification in notifications
                for update in notification.update
            ),
            "Non-secret field was removed",
        )


@pytest.mark.parametrize("route", ["native", "legacy"])
def test_gnmi_get_secret_redaction(gnmi_tls, synthetic_entry, route):  # noqa: F811
    """Check exact-entry, secret-leaf and public-leaf Get serialization on both DB routes."""
    entry = synthetic_entry
    fields = [None, entry["public_field"]]
    if entry["secret_field"]:
        fields.append(entry["secret_field"])
    with gnmi_connection(gnmi_tls) as (_, client):
        for field in fields:
            prefix, path = _read_path(entry, route, field)
            response = client.Get(
                gnmi_pb2.GetRequest(prefix=prefix, path=[path], encoding=gnmi_pb2.JSON_IETF),
                timeout=30,
            )
            pytest_assert(any(n.update for n in response.notification), "Get returned no synthetic entry")
            _assert_redacted(response, entry, public=field != entry["secret_field"] or field is None)


@pytest.mark.parametrize("route", ["native", "legacy"])
@pytest.mark.parametrize(
    "mode",
    [gnmi_pb2.SubscriptionList.ONCE, gnmi_pb2.SubscriptionList.POLL, gnmi_pb2.SubscriptionList.STREAM],
    ids=["once", "poll", "stream"],
)
def test_gnmi_subscribe_secret_redaction(gnmi_tls, synthetic_entry, route, mode):  # noqa: F811
    """Check initial ONCE/POLL/STREAM notifications for synthetic values and SNMP path keys."""
    entry = synthetic_entry
    prefix, path = _read_path(entry, route)
    request = gnmi_pb2.SubscribeRequest(
        subscribe=gnmi_pb2.SubscriptionList(
            prefix=prefix,
            mode=mode,
            encoding=gnmi_pb2.JSON_IETF,
            subscription=[gnmi_pb2.Subscription(path=path, mode=gnmi_pb2.SAMPLE, sample_interval=1000000000)],
        )
    )
    finished = threading.Event()

    def requests():
        yield request
        # Half-closing POLL/ONCE can stop the server before its first update.
        finished.wait(35)

    with gnmi_connection(gnmi_tls) as (_, client):
        responses = client.Subscribe(requests(), timeout=30)
        try:
            found = False
            for response in responses:
                _assert_redacted(response, entry)
                if response.HasField("update") and response.update.update:
                    _assert_redacted(response, entry, public=True)
                    found = True
                    break
            pytest_assert(found, "Subscribe returned no synthetic entry")
        finally:
            finished.set()
            responses.cancel()
