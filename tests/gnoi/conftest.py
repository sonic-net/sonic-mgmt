"""
Fixtures for the PTF-free native gNOI test suite.

The DUT is driven the "API way": an in-process Python gRPC client
(``sonic_grpc.gnoi.GnoiClient``) running in the sonic-mgmt container talks
mTLS gRPC directly to the DUT's gNOI server on the management IP. There is no
PTF hop and no in-repo stub generation.

The ``sonic_grpc`` package is provided by a standalone wheel (built from
sonic-buildimage ``src/sonic-grpc``) and must be present in the sonic-mgmt
image. It is imported directly (not guarded), so a missing wheel is a hard
collection error for this suite rather than a silent skip.

Two fixtures are exposed:

  * ``gnoi_client`` - function scoped, for the plain (non-rebooting) tests. It
    checkpoints CONFIG_DB, provisions mTLS, yields a connected client, and rolls
    back on teardown.
  * ``gnoi_tls_bundle`` - module scoped, for the reboot and upgrade suites. It
    provisions once and yields a reusable bundle whose client credentials
    survive DUT reboots; the tests re-establish the server side across a reboot
    with :func:`tests.gnoi.gnoi_tls_setup.ensure_gnoi_ready`.
"""
import logging
import os
import shutil

import pytest

from sonic_grpc.gnoi import system_pb2

from tests.common.gu_utils import create_checkpoint, rollback
from tests.common.platform.processes_utils import wait_critical_processes
from tests.gnoi import gnoi_tls_setup

logger = logging.getLogger(__name__)

CHECKPOINT_NAME = "gnoi_native_setup"


@pytest.fixture(scope="function")
def gnoi_client(duthosts, rand_one_dut_hostname):
    """Yield a native ``GnoiClient`` connected to the DUT gNOI server over mTLS.

    Flow: checkpoint CONFIG_DB -> provision certs + configure TLS + restart
    gnmi-native -> verify readiness with a native gNOI call -> yield the client
    -> rollback + wait for critical processes + clean up certs.
    """
    duthost = duthosts[rand_one_dut_hostname]

    create_checkpoint(duthost, CHECKPOINT_NAME)

    client = None
    try:
        bundle = gnoi_tls_setup.provision(duthost)

        # Native readiness check: retry System.Time until the TLS listener is up.
        # (supervisor reporting RUNNING does not guarantee the port is bound.)
        if not gnoi_tls_setup.wait_ready(bundle, timeout=60):
            pytest.fail("gNOI server did not become reachable over mTLS")

        client = bundle.open_client()
        # A final direct call surfaces a clear error if something regressed
        # between the readiness poll and first use.
        client.system.Time(system_pb2.TimeRequest(), timeout=10)

        yield client

    finally:
        if client is not None:
            client.close()
        rollback(duthost, CHECKPOINT_NAME)
        duthost.shell("config save -y", module_ignore_errors=True)
        try:
            wait_critical_processes(duthost)
        except Exception as exc:  # noqa: BLE001
            logger.warning("wait_critical_processes after rollback failed: %s", exc)
        if os.path.exists(gnoi_tls_setup.CERT_DIR):
            shutil.rmtree(gnoi_tls_setup.CERT_DIR, ignore_errors=True)


@pytest.fixture(scope="module")
def gnoi_tls_bundle(duthosts, rand_one_dut_hostname):
    """Provision gNOI mTLS once and yield a reusable bundle for reboot/upgrade tests.

    The client credentials in the returned bundle are stable across DUT reboots;
    only the DUT-side state is re-applied (idempotently) by
    :func:`tests.gnoi.gnoi_tls_setup.ensure_gnoi_ready` after each reboot.

    Teardown is best-effort: a rebooted (or upgraded) DUT may no longer hold the
    pre-test CONFIG_DB checkpoint, so the test rows and pushed certs are removed
    explicitly.
    """
    duthost = duthosts[rand_one_dut_hostname]

    bundle = gnoi_tls_setup.provision(duthost)
    if not gnoi_tls_setup.wait_ready(bundle, timeout=60):
        pytest.fail("gNOI server did not become reachable over mTLS")

    try:
        yield bundle
    finally:
        gnoi_tls_setup.cleanup(duthost, bundle)
        try:
            wait_critical_processes(duthost)
        except Exception as exc:  # noqa: BLE001
            logger.warning("wait_critical_processes after cleanup failed: %s", exc)
