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
import time

import grpc
import pytest
from pygnmi.spec.v080 import gnmi_pb2

from tests.common.fixtures.grpc_fixtures import gnmi_tls  # noqa: F401
from tests.common.helpers.gnmi_connection import gnmi_connection
from tests.gnmi.subscribe_client import subscribe

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
def active_subscription(gnmi_tls, request):  # noqa: F811
    """Own one subscriber process, then restore the role and check fresh access."""
    duthost = gnmi_tls.duthost
    assert _db(duthost, "HLEN", CERT_KEY) == "1", "Expected fixture-owned role-only certificate mapping"
    original_role = _db(duthost, "HGET", CERT_KEY, "role@")
    assert original_role, "Fixture certificate role is missing"
    assert _db(duthost, "HGET", "GNMI|gnmi", "user_auth") == "cert", "Test requires cert-only authentication"
    pid = duthost.shell(SERVER_PID_COMMAND)["stdout"].strip()
    assert pid.isdigit() and int(pid) > 0, "gnmi-native is not running"
    context = multiprocessing.get_context("spawn")
    parent, child = context.Pipe()
    certs = gnmi_tls.pygnmi_client
    process = context.Process(
        target=subscribe,
        args=(
            (gnmi_tls.host, gnmi_tls.port),
            (certs.ca_cert, certs.client_cert, certs.client_key),
            getattr(request, "param", "stream"),
            child,
        ),
    )
    started = False
    try:
        _set_role(duthost, READWRITE)
        process.start()
        started = True
        child.close()
        assert parent.poll(40), "Subscribe did not become ready"
        assert parent.recv() == ("ready", None), "Subscribe failed before data + sync"
        yield parent
    finally:
        try:
            if started:
                try:
                    parent.send(("stop", None))
                except (BrokenPipeError, OSError):
                    pass  # An already terminated subscriber may have closed IPC.
                process.join(20)
                forced = process.is_alive()
                if forced:
                    process.terminate()
                    process.join(5)
                if process.is_alive():
                    process.kill()
                    process.join(5)
                assert not forced and process.exitcode == 0, "Subscriber did not exit cleanly"
        finally:
            parent.close()
            child.close()
            process.close()
            _set_role(duthost, original_role)
            with gnmi_connection(gnmi_tls) as (_, client):
                response = client.Get(
                    gnmi_pb2.GetRequest(path=[METADATA_PATH], encoding=gnmi_pb2.JSON_IETF), timeout=15
                )
                assert any(n.update for n in response.notification), "Restored identity returned no data"
            assert duthost.shell(SERVER_PID_COMMAND)["stdout"].strip() == pid, "gnmi-native restarted during the test"


@pytest.mark.parametrize("active_subscription", ["stream", "poll"], indirect=True)
@pytest.mark.parametrize(
    "role,expected_code",
    [(NOACCESS, grpc.StatusCode.PERMISSION_DENIED), (None, grpc.StatusCode.UNAUTHENTICATED)],
    ids=["noaccess", "unmapped"],
)
def test_subscribe_reauthorization(gnmi_tls, active_subscription, role, expected_code, request):  # noqa: F811
    """An active STREAM or POLL terminates with the original auth status."""
    _set_role(gnmi_tls.duthost, role)
    changed_at = time.monotonic()
    assert active_subscription.poll(REAUTH_BUDGET), "Reauthorization timed out"
    assert active_subscription.recv() == ("error", expected_code.name), "Unexpected Subscribe terminal status"
    logger.info(
        "AUTHZ_VERIFIED node=%s role=%s scope=test-body status=%s elapsed=%.1fs",
        request.node.nodeid,
        role,
        expected_code.name,
        time.monotonic() - changed_at,
    )


def test_subscribe_readonly_remains_authorized(gnmi_tls, active_subscription, request):  # noqa: F811
    """Require data after the observation window and after draining the client queue."""
    _set_role(gnmi_tls.duthost, READONLY)
    active_subscription.send(("observe", ALLOW_OBSERVATION))
    assert active_subscription.poll(ALLOW_OBSERVATION + 40), "Readonly observation timed out"
    assert active_subscription.recv() == ("observed", None), "Readonly subscription failed"
    logger.info("AUTHZ_VERIFIED node=%s role=%s scope=test-body", request.node.nodeid, READONLY)
