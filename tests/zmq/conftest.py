import pytest
import logging

from tests.common.helpers.gnmi_utils import ensure_gnmi_insecure_mode, cleanup_gnmi_insecure_mode, GNMIEnvironment

logger = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def setup_gnmi_insecure(duthosts, rand_one_dut_hostname, backup_and_restore_config_db_module):
    """
    Configure GNMI|certs with empty cert fields so telemetry starts with --insecure
    (TLS with self-signed cert) instead of --noTLS (cleartext).

    This mirrors the pattern of setup_gnoi_tls_server but uses the lightweight
    --insecure mode rather than full certificate management.

    Back up the startup config before adding empty cert fields: enable_zmq saves
    and reloads them during setup and teardown. Running DB cleanup alone leaves
    invalid cert paths in config_db.json for subsequent tests to reload.
    """
    duthost = duthosts[rand_one_dut_hostname]
    ensure_gnmi_insecure_mode(duthost, mode=GNMIEnvironment.GNMI_MODE)
    yield
    cleanup_gnmi_insecure_mode(duthost, mode=GNMIEnvironment.GNMI_MODE)
