"""
Fixtures for the PTF-free native gNOI test suite.

The DUT is driven the "API way": an in-process Python gRPC client
(``sonic_grpc.gnoi.GnoiClient``) running in the sonic-mgmt container talks
mTLS gRPC directly to the DUT's gNOI server on the management IP. There is no
PTF hop and no in-repo stub generation.

The ``sonic_grpc`` package is provided by a standalone wheel (built from
sonic-buildimage ``src/sonic-grpc``). Tests are skipped at the symbol level
when it is not installed, so the suite merges dark and lights up once the wheel
ships in docker-sonic-mgmt.
"""
import logging
import os
import shutil

import pytest

from tests.common.cert_utils import create_gnmi_cert_generator
from tests.common.grpc_config import grpc_config
from tests.common.gu_utils import create_checkpoint, rollback
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.utilities import wait_until
# Reuse the tested server-side setup (CONFIG_DB TLS mode + gnmi-native restart).
# These touch only the DUT (no PTF).
from tests.common.fixtures.grpc_fixtures import (
    _configure_gnoi_tls_server,
    _restart_gnoi_server,
)

logger = logging.getLogger(__name__)

CHECKPOINT_NAME = "gnoi_native_setup"
CERT_DIR = "/tmp/gnoi_native_certs"


def _grpc_target(host, port):
    """Build a gRPC target, bracketing IPv6 literals."""
    if ":" in host:
        return "[{}]:{}".format(host, port)
    return "{}:{}".format(host, port)


def _provision_certs(duthost, cert_dir):
    """Generate a CA/server/client chain locally and push server certs to the DUT.

    PTF-free: the client cert/key/CA stay in the sonic-mgmt container (the
    native client reads them locally); only the server cert/key + CA go to the
    DUT, matching what ``_configure_gnoi_tls_server`` points CONFIG_DB at.
    The server cert SAN includes the DUT management IP, so the native client can
    dial the management IP and verify the server certificate against the CA.
    """
    generator = create_gnmi_cert_generator(server_ip=duthost.mgmt_ip)
    generator.write_all(cert_dir)

    dut_dir = grpc_config.DUT_CERT_DIR
    for name in (grpc_config.CA_CERT, grpc_config.SERVER_CERT, grpc_config.SERVER_KEY):
        duthost.copy(src=os.path.join(cert_dir, name), dest="{}/{}".format(dut_dir, name))


@pytest.fixture(scope="function")
def gnoi_client(duthosts, rand_one_dut_hostname):
    """Yield a native ``GnoiClient`` connected to the DUT gNOI server over mTLS.

    Flow: checkpoint CONFIG_DB -> provision certs -> configure TLS mode +
    register the client CN in GNMI_CLIENT_CERT -> restart gnmi-native -> verify
    readiness with a native gNOI call -> yield the client -> rollback + wait for
    critical processes + clean up certs.
    """
    duthost = duthosts[rand_one_dut_hostname]

    # Symbol-level skip guard: the client + its file stubs come from the
    # standalone sonic-grpc wheel, which may not be installed in the image yet.
    grpc = pytest.importorskip("grpc")
    pytest.importorskip("sonic_grpc.gnoi.file_pb2_grpc")
    from sonic_grpc.gnoi import GnoiClient, system_pb2

    create_checkpoint(duthost, CHECKPOINT_NAME)

    client = None
    try:
        _provision_certs(duthost, CERT_DIR)
        _configure_gnoi_tls_server(duthost)
        _restart_gnoi_server(duthost)

        creds = grpc.ssl_channel_credentials(
            root_certificates=open(os.path.join(CERT_DIR, grpc_config.CA_CERT), "rb").read(),
            private_key=open(os.path.join(CERT_DIR, grpc_config.CLIENT_KEY), "rb").read(),
            certificate_chain=open(os.path.join(CERT_DIR, grpc_config.CLIENT_CERT), "rb").read(),
        )
        target = _grpc_target(duthost.mgmt_ip, grpc_config.DEFAULT_TLS_PORT)

        client = GnoiClient(target, credentials=creds)
        client.__enter__()

        # Native readiness check: retry System.Time until the TLS listener is up.
        # (supervisor reporting RUNNING does not guarantee the port is bound.)
        def _ready():
            try:
                client.system.Time(system_pb2.TimeRequest(), timeout=5)
                return True
            except grpc.RpcError as exc:
                logger.debug("gNOI not ready yet: %s", exc.code())
                return False

        if not wait_until(60, 2, 0, _ready):
            pytest.fail("gNOI server did not become reachable over mTLS")

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
        if os.path.exists(CERT_DIR):
            shutil.rmtree(CERT_DIR, ignore_errors=True)
