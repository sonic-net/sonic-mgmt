"""gNMI revocation boundaries: credentials and authorization are distinct.

These cases revoke roles/CN mappings on an active Subscribe RPC; deleting a
CN mapping is not CRL certificate revocation. The managed CRL case is currently
maintained in sonic-mgmt #27429 and requires its separate tls_crl fixture.

Requires sonic-gnmi #789 (periodic reauthentication) and #807 (PermissionDenied
status for role denial). Observation budgets are test limits, not revocation
SLAs: a timeout also requires checking backend health and blocked I/O.
"""

import logging
import multiprocessing
import shlex
import threading
import time
from contextlib import contextmanager
from types import SimpleNamespace

import grpc
import pytest
from pygnmi.spec.v080 import gnmi_pb2

from tests.common.fixtures.grpc_fixtures import gnmi_tls  # noqa: F401
from tests.common.helpers.gnmi_connection import gnmi_connection

pytestmark = [pytest.mark.topology("any"), pytest.mark.disable_loganalyzer]
logger = logging.getLogger(__name__)

CERT_KEY = "GNMI_CLIENT_CERT|test.client.gnmi.sonic"
READWRITE = "gnmi_config_db_readwrite"
READONLY = "gnmi_config_db_readonly"
NOACCESS = "gnmi_config_db_noaccess"
REAUTH_BUDGET = 90
ALLOW_OBSERVATION = 130  # Cross two of the server's 60-second checks.
METADATA_PATH = gnmi_pb2.Path(
    origin="sonic-db",
    elem=[gnmi_pb2.PathElem(name=name) for name in ("CONFIG_DB", "localhost", "DEVICE_METADATA", "localhost")],
)
SERVER_PID_COMMAND = "sudo -n docker exec gnmi supervisorctl pid gnmi-native"


def _db(duthost, *args):
    return duthost.shell(shlex.join(["sonic-db-cli", "CONFIG_DB"] + list(args)))["stdout"].strip()


def _set_role(duthost, role):
    """Change the fixture identity's role (None removes its CN mapping), then read back."""
    if role is None:
        assert _db(duthost, "DEL", CERT_KEY) == "1", "Certificate mapping was not removed"
        assert _db(duthost, "EXISTS", CERT_KEY) == "0", "Certificate mapping still exists"
    else:
        _db(duthost, "HSET", CERT_KEY, "role@", role)
        assert _db(duthost, "HGET", CERT_KEY, "role@") == role, "Role update did not persist"


@pytest.fixture
def subscription_control(gnmi_tls):  # noqa: F811
    """Own the mapping restore; gnmi_tls owns the outer configuration rollback.

    The subscription process exits before restoring the mapping and checking a
    fresh read. All configuration commands use the existing duthost environment.
    """
    duthost = gnmi_tls.duthost
    assert _db(duthost, "HLEN", CERT_KEY) == "1", "Expected fixture-owned role-only certificate mapping"
    original_role = _db(duthost, "HGET", CERT_KEY, "role@")
    assert original_role, "Fixture certificate role is missing"
    assert _db(duthost, "HGET", "GNMI|gnmi", "user_auth") == "cert", "Test requires cert-only authentication"
    pid = duthost.shell(SERVER_PID_COMMAND)["stdout"].strip()
    assert pid.isdigit() and int(pid) > 0, "gnmi-native is not running"
    try:
        _set_role(duthost, READWRITE)
        yield duthost
    finally:
        _set_role(duthost, original_role)
        with gnmi_connection(gnmi_tls) as (_, client):
            response = client.Get(gnmi_pb2.GetRequest(path=[METADATA_PATH], encoding=gnmi_pb2.JSON_IETF), timeout=15)
            assert any(n.update for n in response.notification), "Restored identity returned no data"
        assert duthost.shell(SERVER_PID_COMMAND)["stdout"].strip() == pid, "gnmi-native restarted during the test"


def _subscribe_worker(fixture, mode, result, stop, last_update):
    """Receive one RPC: report readiness/errors and the latest data arrival time."""
    outcome = ("failure", "Subscribe ended without terminal authentication status")
    finished = threading.Event()
    requests_started = threading.Event()
    requests_done = threading.Event()
    request = gnmi_pb2.SubscribeRequest(
        subscribe=gnmi_pb2.SubscriptionList(
            mode=mode,
            encoding=gnmi_pb2.JSON_IETF,
            subscription=[gnmi_pb2.Subscription(path=METADATA_PATH, mode=gnmi_pb2.SAMPLE, sample_interval=1000000000)],
        )
    )

    def requests():
        requests_started.set()
        try:
            yield request
            # Keep POLL open after the initial snapshot, without issuing a Poll.
            finished.wait(200)
        finally:
            requests_done.set()

    try:
        with gnmi_connection(fixture) as (_, client):
            responses = client.Subscribe(requests(), timeout=200)

            def cancel_on_stop():
                stop.wait()
                responses.cancel()

            canceller = threading.Thread(target=cancel_on_stop)
            canceller.start()
            try:
                saw_update = False
                ready = False
                for response in responses:
                    assert not response.HasField("error"), "Subscribe returned an in-band error"
                    has_update = response.HasField("update") and bool(response.update.update)
                    saw_update |= has_update
                    if has_update:
                        last_update.value = time.monotonic()
                    if response.sync_response and not ready:
                        assert saw_update, "Initial Subscribe contained no data"
                        ready = True
                        result.send(("ready", None))
            finally:
                finished.set()
                stop.set()
                responses.cancel()
                canceller.join(10)
                assert not canceller.is_alive(), "Subscribe cancellation did not finish"
                if requests_started.is_set():
                    assert requests_done.wait(10), "Subscribe request iterator failed to stop"
    except grpc.RpcError as error:
        outcome = ("error", error.code().name)
    except Exception as error:
        outcome = ("failure", str(error))
    finally:
        result.send(outcome)
        result.close()


@contextmanager
def _active_subscription(fixture, mode):
    """Spawn only serializable connection details, never the DUT/Ansible fixture."""
    context = multiprocessing.get_context("spawn")
    parent, child = context.Pipe(duplex=False)
    stop, last_update = context.Event(), context.Value("d", 0)
    certs = fixture.pygnmi_client
    connection = SimpleNamespace(
        host=fixture.host,
        port=fixture.port,
        pygnmi_client=SimpleNamespace(
            ca_cert=certs.ca_cert, client_cert=certs.client_cert, client_key=certs.client_key
        ),
    )
    process = context.Process(target=_subscribe_worker, args=(connection, mode, child, stop, last_update))
    started = False
    try:
        process.start()
        started = True
        child.close()
        assert parent.poll(40), "Subscribe did not become ready"
        ready = parent.recv()
        assert ready == ("ready", None), "Subscribe failed before data + sync: {}".format(ready)
        yield parent, last_update
    finally:
        try:
            if started:
                stop.set()
                process.join(15)
                forced = process.is_alive()
                if forced:
                    process.terminate()
                    process.join(5)
                if process.is_alive():
                    process.kill()
                    process.join(5)
                assert not forced and process.exitcode == 0, "Subscription worker did not exit cleanly"
                # Negative cases consumed their terminal result; positive cases
                # must still check cleanup, even if the worker exited with zero.
                if parent.poll():
                    try:
                        outcome = parent.recv()
                    except EOFError:
                        pass  # Terminal result was already consumed.
                    else:
                        assert outcome == ("error", "CANCELLED"), "Subscription cleanup failed: {}".format(outcome)
        finally:
            parent.close()
            child.close()
            process.close()


@pytest.mark.parametrize(
    "mode", [gnmi_pb2.SubscriptionList.STREAM, gnmi_pb2.SubscriptionList.POLL], ids=["stream", "poll"]
)
@pytest.mark.parametrize(
    "role,expected_code",
    [(NOACCESS, grpc.StatusCode.PERMISSION_DENIED), (None, grpc.StatusCode.UNAUTHENTICATED)],
    ids=["noaccess", "unmapped"],
)
def test_subscribe_reauthorization(gnmi_tls, subscription_control, mode, role, expected_code):  # noqa: F811
    """An active STREAM or idle POLL terminates with the original auth status."""
    with _active_subscription(gnmi_tls, mode) as (result, _):
        _set_role(subscription_control, role)
        changed_at = time.monotonic()
        assert result.poll(REAUTH_BUDGET), "Reauthorization timed out; inspect RPC/backend health"
        outcome = result.recv()
        assert outcome == ("error", expected_code.name), "Unexpected Subscribe terminal outcome: {}".format(outcome)
        logger.info("Same Subscribe RPC revoked with %s after %.1fs", expected_code, time.monotonic() - changed_at)


def test_subscribe_readonly_remains_authorized(gnmi_tls, subscription_control):  # noqa: F811
    """Observe fresh SAMPLE data across two reauth intervals after RW-to-RO.

    Freshness is sampled once a second, not an exhaustive inter-update gap check.
    """
    with _active_subscription(gnmi_tls, gnmi_pb2.SubscriptionList.STREAM) as (result, last_update):
        _set_role(subscription_control, READONLY)
        until = time.monotonic() + ALLOW_OBSERVATION
        while last_update.value < until:
            if result.poll(1):
                pytest.fail("Readonly subscription failed after role change: {}".format(result.recv()))
            assert time.monotonic() - last_update.value <= 15, "Readonly SAMPLE stream stopped delivering data"
