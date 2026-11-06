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
import time

import grpc
import pytest
from pygnmi.spec.v080 import gnmi_pb2

from tests.common.fixtures.grpc_fixtures import gnmi_tls  # noqa: F401
from tests.common.helpers.gnmi_connection import gnmi_connection
from tests.common.utilities import wait_until

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
    try:
        _set_role(duthost, READWRITE)
        with gnmi_tls.pygnmi_client.isolated_subscription(
            {
                "mode": getattr(request, "param", "stream"),
                "encoding": "json_ietf",
                "subscription": [
                    {
                        "path": "sonic-db:CONFIG_DB/localhost/DEVICE_METADATA/localhost",
                        "mode": "sample",
                        "sample_interval": 1000000000,
                    }
                ],
            }
        ) as subscription:
            initial = subscription.get_update(timeout=30)
            assert initial.get("sync_response"), "No initial sync"
            assert initial.get("update", {}).get("update"), "No initial data"
            assert subscription.terminal_status is None, "Subscribe failed before revocation"
            yield subscription
    finally:
        _set_role(duthost, original_role)
        with gnmi_connection(gnmi_tls) as (_, client):
            response = client.Get(gnmi_pb2.GetRequest(path=[METADATA_PATH], encoding=gnmi_pb2.JSON_IETF), timeout=15)
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
    assert wait_until(
        REAUTH_BUDGET, 1, 0, lambda: active_subscription.terminal_status is not None
    ), "Reauthorization timed out"
    assert active_subscription.terminal_status == expected_code, "Unexpected Subscribe terminal status"
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
    until = time.monotonic() + ALLOW_OBSERVATION
    while time.monotonic() < until:
        assert active_subscription.terminal_status is None, "Readonly subscription failed"
        update = active_subscription.get_update(timeout=15)
        assert update.get("update", {}).get("update"), "Readonly subscription returned no data"
    deadline = time.monotonic() + 15
    # A new application enqueue does not prove DUT generation time or exclude network backlog.
    while active_subscription.peek():
        assert time.monotonic() < deadline, "Unable to drain queued updates"
        active_subscription.get_update(timeout=1)
    update = active_subscription.get_update(timeout=15)
    assert update.get("update", {}).get("update"), "No data after observation"
    assert active_subscription.terminal_status is None, "Readonly subscription failed"
    logger.info("AUTHZ_VERIFIED node=%s role=%s scope=test-body", request.node.nodeid, READONLY)
