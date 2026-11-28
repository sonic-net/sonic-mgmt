import pytest
import logging

from tests.common.helpers.gnmi_utils import gnmi_container
from tests.common.helpers.sonic_db import CONFIG_DB, redis_hdel, redis_hgetall, redis_hset

logger = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def setup_gnmi_tls(duthosts, rand_one_dut_hostname, backup_and_restore_config_db_module):
    """
    Provision explicit TLS credentials without relying on --insecure fallback.

    Keep credentials under the container-mounted telemetry directory across
    enable_zmq's config reloads. The backup fixture restores the startup config.
    The test client supplies neither a client certificate nor user credentials;
    restore both authentication settings along with the TLS profile on exit.
    """
    duthost = duthosts[rand_one_dut_hostname]
    service = gnmi_container(duthost)
    original = {
        table: redis_hgetall(duthost, CONFIG_DB, table)
        for table in ("GNMI|gnmi", "GNMI|certs")
    }
    tls_dir = duthost.tempfile(
        state="directory", path="/etc/sonic/telemetry", prefix="zmq-gnmi-",
    )["path"]
    settings = {
        "GNMI|gnmi": {"port": "8080", "client_auth": "false", "user_auth": "none"},
        "GNMI|certs": {
            "server_crt": tls_dir + "/server.crt",
            "server_key": tls_dir + "/server.key",
            "ca_crt": "",
        },
    }
    try:
        duthost.command(argv=[
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-days", "1", "-subj", "/CN=example.com",
            "-keyout", settings["GNMI|certs"]["server_key"],
            "-out", settings["GNMI|certs"]["server_crt"],
        ])
        for table, fields in settings.items():
            redis_hset(duthost, CONFIG_DB, table, **fields)
        duthost.service(name=service, state="restarted")
        duthost.wait_for(port=8080, state="started", timeout=60)
        yield
    finally:
        try:
            for table, fields in settings.items():
                original_fields = {
                    field: original[table][field]
                    for field in fields if field in original[table]
                }
                absent_fields = [
                    field for field in fields if field not in original[table]
                ]
                redis_hset(duthost, CONFIG_DB, table, **original_fields)
                redis_hdel(duthost, CONFIG_DB, table, *absent_fields)
            duthost.service(name=service, state="restarted")
        finally:
            duthost.file(path=tls_dir, state="absent")
