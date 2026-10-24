"""
Reusable server-side TLS setup and idempotent readiness for the native gNOI
suite.

The suite drives the DUT gNOI server over mTLS from the sonic-mgmt container
(no PTF). This module centralizes three things so the plain, reboot, and upgrade
suites share one implementation:

  * one-time PKI provisioning - the CA and client cert/key are generated once
    and stay in the sonic-mgmt container; only the server cert/key and CA are
    pushed to the DUT,
  * pointing CONFIG_DB at the server certs and restarting the gNMI/gNOI server,
  * an idempotent :func:`ensure_gnoi_ready` that re-establishes the mTLS session
    after a DUT reboot.

Why re-provision instead of persisting the config across a reboot
-----------------------------------------------------------------
It is tempting to ``config save`` the TLS setup so it survives a reboot. On
SONiC that is unsafe for anything that crosses an image boundary:

  * ``GNMI_CLIENT_CERT`` is version-gated in YANG - the table is absent on older
    versions and its ``role`` leaf is a mandatory scalar on some versions but a
    leaf-list on others - so a saved test config carried through config
    migration can be YANG-invalid and strand the DUT.
  * ``GNMI|certs`` points at ``/etc/sonic/telemetry``, which lives in the
    per-image writable overlay and is wiped on upgrade, so even a YANG-valid
    migrated config would leave the gNMI container crash-looping on missing
    certificate files.

Persistence is also not something a test controls: several shared code paths
(the advanced-reboot teardown, ``config_reload``, sanity checks) issue
``config save`` on their own, and a warm/fast upgrade crosses the boundary via
the running CONFIG_DB rather than ``config_db.json``. The safe design is
therefore zero persistence plus a single idempotent re-apply after every reboot,
which :func:`ensure_gnoi_ready` provides for same-image reboot and cross-image
upgrade alike.
"""
import logging
import os
import shutil

import grpc

from sonic_grpc.gnoi import GnoiClient, system_pb2

from tests.common.cert_utils import create_gnmi_cert_generator
from tests.common.grpc_config import grpc_config
# Reuse the already-tested DUT-side setup (CONFIG_DB TLS mode + gnmi-native
# restart). These touch only the DUT (no PTF).
from tests.common.fixtures.grpc_fixtures import (
    _configure_gnoi_tls_server,
    _restart_gnoi_server,
)
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

CERT_DIR = "/tmp/gnoi_native_certs"
# Client CN baked into the generated client cert (create_gnmi_cert_generator
# default) and into the GNMI_CLIENT_CERT row registered by
# _configure_gnoi_tls_server. Kept in sync here for cleanup.
CLIENT_CN = "test.client.gnmi.sonic"


def _grpc_target(host, port):
    """Build a gRPC target, bracketing IPv6 literals."""
    if ":" in host:
        return "[{}]:{}".format(host, port)
    return "{}:{}".format(host, port)


def _read(cert_dir, name):
    with open(os.path.join(cert_dir, name), "rb") as handle:
        return handle.read()


class GnoiTlsBundle:
    """Container-side PKI plus a ready-to-dial mTLS target for the DUT.

    The CA and client cert/key are generated once and never leave the sonic-mgmt
    container, so the same client credentials keep working across DUT reboots -
    only the server-side state is re-applied by :func:`ensure_gnoi_ready`.
    """

    def __init__(self, duthost, cert_dir=CERT_DIR):
        self.duthost = duthost
        self.cert_dir = cert_dir
        self.target = _grpc_target(duthost.mgmt_ip, grpc_config.DEFAULT_TLS_PORT)
        self._credentials = None

    @property
    def credentials(self):
        """mTLS channel credentials built from the cached client materials."""
        if self._credentials is None:
            self._credentials = grpc.ssl_channel_credentials(
                root_certificates=_read(self.cert_dir, grpc_config.CA_CERT),
                private_key=_read(self.cert_dir, grpc_config.CLIENT_KEY),
                certificate_chain=_read(self.cert_dir, grpc_config.CLIENT_CERT),
            )
        return self._credentials

    def open_client(self):
        """Return an entered :class:`GnoiClient` (caller must ``close()`` it)."""
        client = GnoiClient(self.target, credentials=self.credentials)
        client.__enter__()
        return client


def generate_pki(duthost, cert_dir=CERT_DIR):
    """Generate the CA/server/client chain once, in the container.

    The server certificate SAN includes the DUT management IP, so the native
    client can dial the management IP and verify the server certificate.
    """
    generator = create_gnmi_cert_generator(server_ip=duthost.mgmt_ip)
    generator.write_all(cert_dir)


def push_server_certs(duthost, cert_dir=CERT_DIR):
    """Copy the CA and server cert/key to the DUT (client materials stay local)."""
    dut_dir = grpc_config.DUT_CERT_DIR
    duthost.shell("mkdir -p {}".format(dut_dir))
    for name in (grpc_config.CA_CERT, grpc_config.SERVER_CERT, grpc_config.SERVER_KEY):
        duthost.copy(src=os.path.join(cert_dir, name), dest="{}/{}".format(dut_dir, name))


def provision(duthost, cert_dir=CERT_DIR):
    """Full one-time setup: generate PKI, push server certs, configure and restart.

    Returns a :class:`GnoiTlsBundle` whose client credentials are reused across
    reboots.
    """
    generate_pki(duthost, cert_dir)
    push_server_certs(duthost, cert_dir)
    _configure_gnoi_tls_server(duthost)
    _restart_gnoi_server(duthost)
    return GnoiTlsBundle(duthost, cert_dir)


def is_ready(bundle, timeout=5):
    """Return True if the DUT gNOI server answers System.Time over mTLS."""
    client = bundle.open_client()
    try:
        client.system.Time(system_pb2.TimeRequest(), timeout=timeout)
        return True
    except grpc.RpcError as exc:
        logger.debug("gNOI probe not ready: %s", exc.code())
        return False
    finally:
        client.close()


def wait_ready(bundle, timeout=60, interval=2):
    """Poll :func:`is_ready` until the server is reachable or ``timeout`` elapses."""
    return wait_until(timeout, interval, 0, is_ready, bundle)


def ensure_gnoi_ready(duthost, bundle, timeout=120):
    """Idempotently bring the DUT gNOI server back to mTLS-ready after a reboot.

    One uniform path for same-image reboot and cross-image upgrade: probe first
    (a no-op if the server is already reachable), otherwise re-push the cached
    server certs, re-apply the CONFIG_DB TLS config, restart gnmi-native, and
    wait for readiness.

    Nothing test-owned is ever written to disk - the re-apply is always fresh via
    ``sonic-db-cli`` on the running image - so no test config crosses a config
    migration boundary. See the module docstring for why that matters.
    """
    if is_ready(bundle, timeout=5):
        logger.info("gNOI already reachable; no re-provision needed")
        return
    logger.info("gNOI not reachable after reboot; re-provisioning TLS")
    push_server_certs(duthost, bundle.cert_dir)
    _configure_gnoi_tls_server(duthost)
    _restart_gnoi_server(duthost)
    if not wait_ready(bundle, timeout=timeout):
        raise RuntimeError("gNOI server did not become reachable after re-provision")


def cleanup(duthost, bundle):
    """Best-effort removal of test-provisioned state from the DUT and container.

    Deletes the registered client-cert row and the pushed server certs, then
    saves the cleaned config. Used by suites that reboot the DUT, where a
    pre-reboot CONFIG_DB checkpoint may no longer exist (for example after an
    upgrade into a new image).
    """
    duthost.shell(
        'sonic-db-cli CONFIG_DB del "GNMI_CLIENT_CERT|{}"'.format(CLIENT_CN),
        module_ignore_errors=True,
    )
    dut_dir = grpc_config.DUT_CERT_DIR
    for name in (grpc_config.CA_CERT, grpc_config.SERVER_CERT, grpc_config.SERVER_KEY):
        duthost.shell("rm -f {}/{}".format(dut_dir, name), module_ignore_errors=True)
    duthost.shell("config save -y", module_ignore_errors=True)
    if os.path.exists(bundle.cert_dir):
        shutil.rmtree(bundle.cert_dir, ignore_errors=True)
