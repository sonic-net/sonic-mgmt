import logging
from contextlib import contextmanager
from tests.common.helpers.gnmi_utils import GNMIEnvironment
from tests.common.helpers.assertions import pytest_assert as py_assert
from tests.common.helpers.sonic_db import CONFIG_DB, redis_hdel, redis_hset
from tests.common.utilities import wait_until, get_mgmt_ipv6, wait_tcp_connection

logger = logging.getLogger(__name__)


@contextmanager
def setup_gnmi_streaming_context(is_ipv6, duthost, localhost, ptfhost, gnxi_path):
    """
    Run credential-free gNMI clients over TLS using the testbed's telemetry certs.

    A port alone is not a complete TLS/authentication profile. Apply the whole
    temporary profile before restarting, then restore each field's original
    value or absence before the cleanup restart, including when setup fails.
    """
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    config = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    original = config.get(env.gnmi_config_table, {})
    settings = {
        "gnmi": {
            "port": original.get("gnmi", {}).get("port", "50052"),
            "client_auth": "false",
            "user_auth": "none",
        },
        "certs": {
            "ca_crt": "/etc/sonic/telemetry/dsmsroot.cer",
            "server_crt": "/etc/sonic/telemetry/streamingtelemetryserver.cer",
            "server_key": "/etc/sonic/telemetry/streamingtelemetryserver.key",
        },
    }
    dut_ip = get_mgmt_ipv6(duthost) if is_ipv6 else duthost.mgmt_ip
    port = int(settings["gnmi"]["port"])
    try:
        for table, fields in settings.items():
            key = "{}|{}".format(env.gnmi_config_table, table)
            result = redis_hset(duthost, CONFIG_DB, key, **fields)
            py_assert(result["rc"] == 0, "Failed to configure {}".format(key))
        duthost.shell("systemctl reset-failed %s" % (env.gnmi_container))
        duthost.service(name=env.gnmi_container, state="restarted")
        py_assert(wait_until(100, 10, 0, duthost.is_service_fully_started, env.gnmi_container),
                  "%s not started." % (env.gnmi_container))

        py_assert(wait_tcp_connection(localhost, dut_ip, port, timeout_s=60),
                  "Failed to establish TCP connection to {}:{}".format(dut_ip, port))

        # pyclient should be available on ptfhost. If it was not available, then fail pytest.
        if is_ipv6:
            cmd = "docker cp %s:/usr/sbin/gnmi_get ~/" % (env.gnmi_container)
            ret = duthost.shell(cmd)['rc']
            py_assert(ret == 0)
        else:
            file_exists = ptfhost.stat(path=gnxi_path + "gnmi_cli_py/py_gnmicli.py")
            py_assert(file_exists["stat"]["exists"] is True)

        yield
    finally:
        logger.info("Restoring the original gNMI TLS and authentication configuration")
        for table, fields in settings.items():
            key = "{}|{}".format(env.gnmi_config_table, table)
            original_fields = {
                field: original[table][field]
                for field in fields if field in original.get(table, {})
            }
            absent_fields = [field for field in fields if field not in original.get(table, {})]
            if original_fields:
                result = redis_hset(duthost, CONFIG_DB, key, **original_fields)
                py_assert(result["rc"] == 0, "Failed to restore {}".format(key))
            if absent_fields:
                result = redis_hdel(duthost, CONFIG_DB, key, *absent_fields)
                py_assert(result["rc"] == 0, "Failed to remove temporary fields from {}".format(key))
        duthost.shell("systemctl reset-failed %s" % (env.gnmi_container))
        duthost.service(name=env.gnmi_container, state="restarted")
        py_assert(wait_until(100, 10, 0, duthost.is_service_fully_started, env.gnmi_container),
                  "%s not started after restoring configuration." % (env.gnmi_container))
