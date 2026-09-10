import pytest
import logging

from tests.common.helpers.gnmi_utils import ensure_gnmi_insecure_mode, cleanup_gnmi_insecure_mode

logger = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def setup_gnmi_insecure(duthosts, rand_one_dut_hostname):
    """
    Configure GNMI|certs with empty cert fields so gnmi starts with --insecure
    (TLS with self-signed cert) instead of --noTLS (cleartext).

    This mirrors the pattern of setup_gnoi_tls_server but uses the lightweight
    --insecure mode rather than full certificate management.
    """
    duthost = duthosts[rand_one_dut_hostname]
    ensure_gnmi_insecure_mode(duthost)
    yield
    cleanup_gnmi_insecure_mode(duthost)
