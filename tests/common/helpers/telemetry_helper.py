import logging
import shlex
from contextlib import contextmanager
from tests.common.helpers.gnmi_utils import GNMIEnvironment
from tests.common.helpers.assertions import pytest_assert as py_assert
from tests.common.utilities import wait_until, get_mgmt_ipv6, wait_tcp_connection

logger = logging.getLogger(__name__)


def check_gnmi_config(duthost):
    cmd = 'sonic-db-cli CONFIG_DB HGET "GNMI|gnmi" port'
    port = duthost.shell(cmd, module_ignore_errors=False)['stdout']
    return port != ""


def create_gnmi_config(duthost):
    cmd = "sonic-db-cli CONFIG_DB hset 'GNMI|gnmi' port 50052"
    duthost.shell(cmd, module_ignore_errors=False)
    cmd = "sonic-db-cli CONFIG_DB hset 'GNMI|gnmi' client_auth true"
    duthost.shell(cmd, module_ignore_errors=False)
    cmd = "sonic-db-cli CONFIG_DB hset 'GNMI|certs' "\
          "ca_crt /etc/sonic/telemetry/dsmsroot.cer"
    duthost.shell(cmd, module_ignore_errors=False)
    cmd = "sonic-db-cli CONFIG_DB hset 'GNMI|certs' "\
          "server_crt /etc/sonic/telemetry/streamingtelemetryserver.cer"
    duthost.shell(cmd, module_ignore_errors=False)
    cmd = "sonic-db-cli CONFIG_DB hset 'GNMI|certs' "\
          "server_key /etc/sonic/telemetry/streamingtelemetryserver.key"
    duthost.shell(cmd, module_ignore_errors=False)


def delete_gnmi_config(duthost):
    cmd = "sonic-db-cli CONFIG_DB hdel 'GNMI|gnmi' port"
    duthost.shell(cmd, module_ignore_errors=False)
    cmd = "sonic-db-cli CONFIG_DB hdel 'GNMI|gnmi' client_auth"
    duthost.shell(cmd, module_ignore_errors=False)
    cmd = "sonic-db-cli CONFIG_DB hdel 'GNMI|certs' ca_crt"
    duthost.shell(cmd, module_ignore_errors=False)
    cmd = "sonic-db-cli CONFIG_DB hdel 'GNMI|certs' server_crt"
    duthost.shell(cmd, module_ignore_errors=False)
    cmd = "sonic-db-cli CONFIG_DB hdel 'GNMI|certs' server_key"
    duthost.shell(cmd, module_ignore_errors=False)


def setup_telemetry_forpyclient(duthost):
    """ Set client_auth=false. This is needed for pyclient to successfully set up channel with gnmi server.
        Restart telemetry process
    """
    env = GNMIEnvironment(duthost, GNMIEnvironment.TELEMETRY_MODE)
    client_auth = duthost.shell(
        'sonic-db-cli CONFIG_DB HGET "%s|gnmi" "client_auth"' % (env.gnmi_config_table),
        module_ignore_errors=False)['stdout']

    if client_auth == "true":
        duthost.shell('sonic-db-cli CONFIG_DB HSET "%s|gnmi" "client_auth" "false"' % (env.gnmi_config_table),
                      module_ignore_errors=False)
        duthost.shell("systemctl reset-failed %s" % (env.gnmi_container))
        duthost.service(name=env.gnmi_container, state="restarted")
        # Wait until telemetry was restarted
        py_assert(wait_until(100, 10, 0, duthost.is_service_fully_started, env.gnmi_container),
                  "%s not started." % (env.gnmi_container))
        logger.info("telemetry process restarted")
    else:
        logger.info('client auth is false. No need to restart telemetry')

    return client_auth


def restore_telemetry_forpyclient(duthost, default_client_auth, env=None):
    if env is None:
        env = GNMIEnvironment(duthost, GNMIEnvironment.TELEMETRY_MODE)
    client_auth = duthost.shell(
        'sonic-db-cli CONFIG_DB HGET "%s|gnmi" "client_auth"' % (env.gnmi_config_table),
        module_ignore_errors=False)['stdout']
    if client_auth != default_client_auth:
        if default_client_auth:
            duthost.shell('sonic-db-cli CONFIG_DB HSET "%s|gnmi" "client_auth" %s'
                          % (env.gnmi_config_table, shlex.quote(default_client_auth)),
                          module_ignore_errors=False)
        else:
            duthost.shell('sonic-db-cli CONFIG_DB HDEL "%s|gnmi" "client_auth"' % (env.gnmi_config_table),
                          module_ignore_errors=False)
        duthost.shell("systemctl reset-failed %s" % (env.gnmi_container))
        duthost.service(name=env.gnmi_container, state="restarted")


@contextmanager
def setup_streaming_telemetry_context(is_ipv6, duthost, localhost, ptfhost, gnxi_path):
    """
    @summary: Post setting up the streaming telemetry before running the test.
    """
    has_gnmi_config = check_gnmi_config(duthost)
    default_client_auth = None
    dut_ip = get_mgmt_ipv6(duthost) if is_ipv6 else duthost.mgmt_ip
    try:
        if not has_gnmi_config:
            create_gnmi_config(duthost)
        env = GNMIEnvironment(duthost, GNMIEnvironment.TELEMETRY_MODE)
        # Snapshot before setup, which can fail after changing authentication.
        default_client_auth = duthost.shell(
            'sonic-db-cli CONFIG_DB HGET "%s|gnmi" "client_auth"' % (env.gnmi_config_table),
            module_ignore_errors=False)['stdout']
        setup_telemetry_forpyclient(duthost)

        # Wait until the TCP port was opened
        py_assert(wait_tcp_connection(localhost, dut_ip, env.gnmi_port, timeout_s=60),
                  "Failed to establish TCP connection to %s:%s" % (dut_ip, env.gnmi_port))

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
        try:
            if default_client_auth is not None:
                # A failed restart must not redirect cleanup to another config table.
                restore_telemetry_forpyclient(duthost, default_client_auth, env=env)
                py_assert(wait_tcp_connection(localhost, dut_ip, env.gnmi_port, timeout_s=60),
                          "Failed to establish TCP connection to %s:%s after restoring client authentication."
                          % (dut_ip, env.gnmi_port))
        finally:
            if not has_gnmi_config:
                delete_gnmi_config(duthost)
