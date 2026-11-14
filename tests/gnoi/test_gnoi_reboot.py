"""
Native gNOI reboot test.

This is the VS-verifiable exerciser of the native suite's reboot-survival
design. A ``System.Reboot`` tears down the DUT control plane; on the way back up
the gNMI/gNOI server has lost the test-provisioned TLS configuration (the suite
persists nothing across a reboot), and
:func:`tests.gnoi.gnoi_tls_setup.ensure_gnoi_ready` idempotently re-provisions it
so the same native client - reusing the same client credentials - can talk to
the DUT again.

The native upgrade test reuses the exact same re-provision path across an image
boundary, so proving this test on a virtual switch also proves that machinery.
"""
import logging
import time

import pytest

from sonic_grpc.gnoi import system_pb2

from tests.common.helpers.assertions import pytest_assert
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.reboot import (
    REBOOT_TYPE_COLD,
    check_reboot_cause,
    wait_for_shutdown,
    wait_for_startup,
)
from tests.common.utilities import wait_until
from tests.gnoi import gnoi_tls_setup

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("any"),
    # gnoi_tls_bundle mutates GNMI CONFIG_DB and the DUT is rebooted here; skip
    # the teardown config-drift check that would otherwise force a reload.
    pytest.mark.skip_check_dut_health,
    # A cold reboot floods the DUT syslog with expected boot-time errors (for
    # example "Failed to start system-health.service"); disable LogAnalyzer so
    # that boot noise does not fail the teardown.
    pytest.mark.disable_loganalyzer,
]


@pytest.mark.device_type("vs")
def test_gnoi_cold_reboot_and_reprovision(
    duthosts, rand_one_dut_hostname, localhost, gnoi_tls_bundle
):
    """Cold-reboot the DUT via gNOI, then re-establish the mTLS session.

    Steps: confirm reachable -> System.Reboot(COLD) -> wait down/up ->
    ensure_gnoi_ready -> confirm the same client works again.
    """
    duthost = duthosts[rand_one_dut_hostname]
    bundle = gnoi_tls_bundle

    pytest_assert(
        gnoi_tls_setup.is_ready(bundle, timeout=10),
        "gNOI server not reachable before reboot",
    )

    # System.Reboot is a trigger RPC: the control plane usually drops mid-call,
    # so a transport error here does not mean the reboot failed to start.
    client = bundle.open_client()
    try:
        client.system.Reboot(
            system_pb2.RebootRequest(
                method=system_pb2.RebootMethod.COLD,
                message="native gNOI reboot test",
            ),
            timeout=30,
        )
    except Exception as exc:  # noqa: BLE001
        logger.info("System.Reboot trigger returned/raised (expected on drop): %s", exc)
    finally:
        client.close()

    reboot_start = time.time()
    wait_for_shutdown(duthost, localhost, delay=10, timeout=300)
    wait_for_startup(duthost, localhost, delay=10, timeout=300)
    wait_critical_processes(duthost)
    logger.info("DUT back up %.0fs after gNOI reboot trigger", time.time() - reboot_start)

    # Best-effort confirmation that this was a cold reboot; the load-bearing
    # assertion is that gNOI is usable again after re-provision.
    if not wait_until(120, 10, 0, check_reboot_cause, duthost, REBOOT_TYPE_COLD):
        logger.warning("Reboot cause did not settle to '%s'", REBOOT_TYPE_COLD)

    # The server lost its TLS config across the reboot; re-provision idempotently.
    gnoi_tls_setup.ensure_gnoi_ready(duthost, bundle, timeout=180)

    # Same client credentials, fresh server session: native RPCs work again.
    client = bundle.open_client()
    try:
        response = client.system.Time(system_pb2.TimeRequest(), timeout=10)
        pytest_assert(
            response.time > 0,
            "System.Time returned a non-positive timestamp after re-provision",
        )
    finally:
        client.close()
