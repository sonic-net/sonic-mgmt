"""gNMI revocation boundaries: credentials and authorization are distinct.

These cases revoke roles/CN mappings on an active Subscribe RPC; deleting a
CN mapping is not CRL certificate revocation. The managed CRL case is currently
maintained in sonic-mgmt #27429 and requires its separate tls_crl fixture.

Requires sonic-gnmi #789 (periodic reauthentication) and #807 (PermissionDenied
status for role denial). Observation budgets are test limits, not revocation
SLAs: a timeout also requires checking backend health and blocked I/O.
"""

import logging
import shlex
import threading
import time
from contextlib import contextmanager

import grpc
import pytest
from pygnmi.spec.v080 import gnmi_pb2

from tests.common.fixtures.grpc_fixtures import gnmi_tls  # noqa: F401
from tests.common.helpers.gnmi_connection import gnmi_connection
from tests.common.utilities import paramiko_ssh

pytestmark = [pytest.mark.topology("any"), pytest.mark.disable_loganalyzer]
logger = logging.getLogger(__name__)

CERT_KEY = "GNMI_CLIENT_CERT|test.client.gnmi.sonic"
READWRITE = "gnmi_config_db_readwrite"
READONLY = "gnmi_config_db_readonly"
NOACCESS = "gnmi_config_db_noaccess"
REAUTH_BUDGET = 90
ALLOW_OBSERVATION = 130  # Cross two of the server's 60-second checks.


def _ssh_command(ssh, command):
    """Use the already-open control connection; never fork Ansible mid-RPC."""
    stdin, stdout, stderr = ssh.exec_command(command, timeout=15)
    try:
        stdin.close()
        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()
        assert stdout.channel.recv_exit_status() == 0, "SSH control command failed: {}".format(error)
        return output
    finally:
        stdout.channel.close()


def _db(ssh, *args):
    return _ssh_command(ssh, shlex.join(["sonic-db-cli", "CONFIG_DB"] + list(args)))


def _server_pid(ssh):
    pid = _ssh_command(ssh, "sudo -n docker exec gnmi supervisorctl pid gnmi-native")
    assert pid.isdigit() and int(pid) > 0, "gnmi-native is not running"
    return pid


def _set_role(ssh, role):
    if role is None:
        assert _db(ssh, "DEL", CERT_KEY) == "1", "Certificate mapping was not removed"
        assert _db(ssh, "EXISTS", CERT_KEY) == "0", "Certificate mapping still exists"
    else:
        _db(ssh, "HSET", CERT_KEY, "role@", role)
        assert _db(ssh, "HGET", CERT_KEY, "role@") == role, "Role update did not persist"


def _path():
    path = gnmi_pb2.Path(origin="sonic-db")
    for name in ("CONFIG_DB", "localhost", "DEVICE_METADATA", "localhost"):
        path.elem.add(name=name)
    return path


def _assert_fresh_read(fixture):
    with gnmi_connection(fixture) as (_, client):
        response = client.Get(gnmi_pb2.GetRequest(path=[_path()], encoding=gnmi_pb2.JSON_IETF), timeout=15)
        assert any(n.update for n in response.notification), "Restored identity returned no data"


@pytest.fixture
def subscription_control(gnmi_tls, creds):  # noqa: F811
    """Own the mapping restore; gnmi_tls owns the outer configuration rollback.

    Tests cancel their RPC before this fixture restores the original mapping
    and verifies a fresh read. Only then may gnmi_tls perform Ansible teardown.
    """
    ssh = paramiko_ssh(
        gnmi_tls.host,
        creds["sonicadmin_user"],
        [creds["sonicadmin_password"]] + creds.get("ansible_altpasswords", []),
    )
    try:
        # gnmi_tls creates this mapping. Do not delete unowned extra fields.
        assert _db(ssh, "HLEN", CERT_KEY) == "1", "Expected fixture-owned role-only certificate mapping"
        original_role = _db(ssh, "HGET", CERT_KEY, "role@")
        assert original_role, "Fixture certificate role is missing"
        assert _db(ssh, "HGET", "GNMI|gnmi", "user_auth") == "cert", "Test requires cert-only authentication"
        pid = _server_pid(ssh)
        try:
            _set_role(ssh, READWRITE)
            yield ssh
        finally:
            _set_role(ssh, original_role)
            _assert_fresh_read(gnmi_tls)
            assert _server_pid(ssh) == pid, "gnmi-native restarted during the test"
    finally:
        ssh.close()


@contextmanager
def _subscription(fixture, mode):
    """Reuse the native response iterator; gRPC owns receiving and status errors."""
    finished = threading.Event()
    requests_started = threading.Event()
    requests_done = threading.Event()
    request = gnmi_pb2.SubscribeRequest(
        subscribe=gnmi_pb2.SubscriptionList(
            mode=mode,
            encoding=gnmi_pb2.JSON_IETF,
            subscription=[gnmi_pb2.Subscription(path=_path(), mode=gnmi_pb2.SAMPLE, sample_interval=1000000000)],
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

    with gnmi_connection(fixture) as (_, client):
        responses = client.Subscribe(requests(), timeout=30 + max(REAUTH_BUDGET, ALLOW_OBSERVATION) + 15)
        try:
            yield responses
        finally:
            finished.set()
            responses.cancel()
            if requests_started.is_set():
                assert requests_done.wait(10), "Subscribe request iterator failed to stop"


@contextmanager
def _rpc_budget(responses, seconds):
    """Cancel a silent RPC at a phase boundary; cancellation is never auth PASS."""
    timer = threading.Timer(seconds, responses.cancel)
    timer.start()
    try:
        yield
    finally:
        timer.cancel()
        timer.join()


def _wait_initial_sync(responses):
    saw_update = False
    with _rpc_budget(responses, 30):
        for response in responses:
            assert not response.HasField("error"), "Initial Subscribe returned an in-band error"
            saw_update |= response.HasField("update") and bool(response.update.update)
            if response.sync_response:
                assert saw_update, "Initial Subscribe contained no data"
                return
    pytest.fail("Subscribe ended before initial sync")


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
    with _subscription(gnmi_tls, mode) as responses:
        _wait_initial_sync(responses)
        _set_role(subscription_control, role)
        changed_at = time.monotonic()
        with _rpc_budget(responses, REAUTH_BUDGET):
            with pytest.raises(grpc.RpcError) as error:
                for response in responses:
                    # Data already sent before the periodic check is allowed.
                    assert not response.HasField("error"), "Expected terminal auth status, not an in-band error"
        assert error.value.code() == expected_code, (
            "Unexpected Subscribe status {}; cancellation/deadline requires checking RPC/backend health"
        ).format(error.value.code())
        logger.info("Same Subscribe RPC revoked with %s after %.1fs", expected_code, time.monotonic() - changed_at)


def test_subscribe_readonly_remains_authorized(gnmi_tls, subscription_control):  # noqa: F811
    """RW-to-RO preserves the same SAMPLE stream across two reauth intervals."""
    with _subscription(gnmi_tls, gnmi_pb2.SubscriptionList.STREAM) as responses:
        _wait_initial_sync(responses)
        _set_role(subscription_control, READONLY)
        changed_at = time.monotonic()
        last_update = changed_at
        with _rpc_budget(responses, ALLOW_OBSERVATION + 15):
            for response in responses:
                assert not response.HasField("error"), "Readonly Subscribe returned an in-band error"
                if response.HasField("update") and response.update.update:
                    now = time.monotonic()
                    assert now - last_update <= 15, "Readonly SAMPLE stream stopped delivering data"
                    last_update = now
                    if now >= changed_at + ALLOW_OBSERVATION:
                        break
            else:
                pytest.fail("Readonly Subscribe ended before the observation completed")
