import pytest
import logging

from tests.common.helpers.gnmi_utils import ensure_gnmi_insecure_mode, cleanup_gnmi_insecure_mode, GNMIEnvironment
from tests.common.helpers.sonic_db import CONFIG_DB, redis_hdel, redis_hgetall, redis_hset

logger = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def setup_gnmi_insecure(duthosts, rand_one_dut_hostname):
    """
    Configure GNMI|certs with empty cert fields so telemetry starts with --insecure
    (TLS with self-signed cert) instead of --noTLS (cleartext).

    This mirrors the pattern of setup_gnoi_tls_server but uses the lightweight
    --insecure mode rather than full certificate management.
    """
    duthost = duthosts[rand_one_dut_hostname]
    gnmi_table = "GNMI|gnmi"
    original_gnmi_config = redis_hgetall(duthost, CONFIG_DB, gnmi_table)
    redis_hset(duthost, CONFIG_DB, gnmi_table, port="8080", client_auth="false")
    ensure_gnmi_insecure_mode(duthost, mode=GNMIEnvironment.GNMI_MODE)

    try:
        yield
    finally:
        cleanup_gnmi_insecure_mode(duthost, mode=GNMIEnvironment.GNMI_MODE)
        original_fields = {
            field: original_gnmi_config[field]
            for field in ("port", "client_auth")
            if field in original_gnmi_config
        }
        absent_fields = [
            field for field in ("port", "client_auth")
            if field not in original_gnmi_config
        ]
        redis_hset(duthost, CONFIG_DB, gnmi_table, **original_fields)
        redis_hdel(duthost, CONFIG_DB, gnmi_table, *absent_fields)
