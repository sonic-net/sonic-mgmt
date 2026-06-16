import logging
from contextlib import contextmanager
from tests.common.errors import RunAnsibleModuleFail
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
    duthost.shell(cmd, module_ignore_errors=True)
    cmd = "sonic-db-cli CONFIG_DB hset 'GNMI|gnmi' client_auth true"
    duthost.shell(cmd, module_ignore_errors=True)
    cmd = "sonic-db-cli CONFIG_DB hset 'GNMI|certs' "\
          "ca_crt /etc/sonic/telemetry/dsmsroot.cer"
    duthost.shell(cmd, module_ignore_errors=True)
    cmd = "sonic-db-cli CONFIG_DB hset 'GNMI|certs' "\
          "server_crt /etc/sonic/telemetry/streamingtelemetryserver.cer"
    duthost.shell(cmd, module_ignore_errors=True)
    cmd = "sonic-db-cli CONFIG_DB hset 'GNMI|certs' "\
          "server_key /etc/sonic/telemetry/streamingtelemetryserver.key"
    duthost.shell(cmd, module_ignore_errors=True)


def delete_gnmi_config(duthost):
    cmd = "sonic-db-cli CONFIG_DB hdel 'GNMI|gnmi' port"
    duthost.shell(cmd, module_ignore_errors=True)
    cmd = "sonic-db-cli CONFIG_DB hdel 'GNMI|gnmi' client_auth"
    duthost.shell(cmd, module_ignore_errors=True)
    cmd = "sonic-db-cli CONFIG_DB hdel 'GNMI|certs' ca_crt"
    duthost.shell(cmd, module_ignore_errors=True)
    cmd = "sonic-db-cli CONFIG_DB hdel 'GNMI|certs' server_crt"
    duthost.shell(cmd, module_ignore_errors=True)
    cmd = "sonic-db-cli CONFIG_DB hdel 'GNMI|certs' server_key"
    duthost.shell(cmd, module_ignore_errors=True)


def setup_telemetry_forpyclient(duthost):
    """ Set client_auth=false. This is needed for pyclient to successfully set up channel with gnmi server.
        Restart telemetry process
    """
    env = GNMIEnvironment(duthost, GNMIEnvironment.TELEMETRY_MODE)
    client_auth_out = duthost.shell('sonic-db-cli CONFIG_DB HGET "%s|gnmi" "client_auth"' % (env.gnmi_config_table),
                                    module_ignore_errors=False)['stdout_lines']
    client_auth = str(client_auth_out[0])

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


def restore_telemetry_forpyclient(duthost, default_client_auth):
    env = GNMIEnvironment(duthost, GNMIEnvironment.TELEMETRY_MODE)
    client_auth_out = duthost.shell('sonic-db-cli CONFIG_DB HGET "%s|gnmi" "client_auth"' % (env.gnmi_config_table),
                                    module_ignore_errors=False)['stdout_lines']
    client_auth = str(client_auth_out[0])
    if client_auth != default_client_auth:
        duthost.shell('sonic-db-cli CONFIG_DB HSET "%s|gnmi" "client_auth" %s'
                      % (env.gnmi_config_table, default_client_auth),
                      module_ignore_errors=False)
        duthost.shell("systemctl reset-failed %s" % (env.gnmi_container))
        duthost.service(name=env.gnmi_container, state="restarted")


@contextmanager
def setup_streaming_telemetry_context(is_ipv6, duthost, localhost, ptfhost, gnxi_path):
    """
    @summary: Post setting up the streaming telemetry before running the test.
    """
    original_idle_conn_duration = None
    try:
        has_gnmi_config = check_gnmi_config(duthost)
        if not has_gnmi_config:
            create_gnmi_config(duthost)
        env = GNMIEnvironment(duthost, GNMIEnvironment.TELEMETRY_MODE)

        # Nokia IXR7220 telemetry server defaults to a 5-minute idle connection timeout
        # (--idle_conn_duration 5).  EVENTS streaming tests can take more than 5 minutes,
        # causing DEADLINE_EXCEEDED failures.  Set idle_conn_duration to 30 minutes before
        # starting the telemetry container so the gRPC stream stays alive for the full test.
        if 'Nokia' in duthost.facts.get('hwsku', ''):
            orig = duthost.shell(
                'sonic-db-cli CONFIG_DB HGET "%s|gnmi" idle_conn_duration' % env.gnmi_config_table,
                module_ignore_errors=True)['stdout'].strip()
            if orig != '30':
                original_idle_conn_duration = orig  # '' means key was absent
                duthost.shell(
                    'sonic-db-cli CONFIG_DB HSET "%s|gnmi" idle_conn_duration 30' % env.gnmi_config_table)

        default_client_auth = setup_telemetry_forpyclient(duthost)

        # If idle_conn_duration was changed but setup_telemetry_forpyclient did not restart
        # the container (client_auth was already false), force a restart now.
        if original_idle_conn_duration is not None and default_client_auth != "true":
            duthost.shell("systemctl reset-failed %s" % env.gnmi_container)
            duthost.service(name=env.gnmi_container, state="restarted")
            py_assert(wait_until(100, 10, 0, duthost.is_service_fully_started, env.gnmi_container),
                      "%s not started after idle_conn_duration change." % env.gnmi_container)

        # Wait until the TCP port was opened
        dut_ip = duthost.mgmt_ip
        if is_ipv6:
            dut_ip = get_mgmt_ipv6(duthost)
        wait_tcp_connection(localhost, dut_ip, env.gnmi_port, timeout_s=60)

        # pyclient should be available on ptfhost. If it was not available, then fail pytest.
        if is_ipv6:
            cmd = "docker cp %s:/usr/sbin/gnmi_get ~/" % (env.gnmi_container)
            ret = duthost.shell(cmd)['rc']
            py_assert(ret == 0)
        else:
            file_exists = ptfhost.stat(path=gnxi_path + "gnmi_cli_py/py_gnmicli.py")
            py_assert(file_exists["stat"]["exists"] is True)
    except RunAnsibleModuleFail as e:
        logger.info("Error happens in the setup period of setup_streaming_telemetry, recover the telemetry.")
        restore_telemetry_forpyclient(duthost, default_client_auth)
        raise e

    yield
    restore_telemetry_forpyclient(duthost, default_client_auth)
    # Restore Nokia idle_conn_duration if it was changed
    if original_idle_conn_duration is not None:
        env = GNMIEnvironment(duthost, GNMIEnvironment.TELEMETRY_MODE)
        if original_idle_conn_duration:
            duthost.shell(
                'sonic-db-cli CONFIG_DB HSET "%s|gnmi" idle_conn_duration %s'
                % (env.gnmi_config_table, original_idle_conn_duration))
        else:
            duthost.shell(
                'sonic-db-cli CONFIG_DB HDEL "%s|gnmi" idle_conn_duration' % env.gnmi_config_table)
    if not has_gnmi_config:
        delete_gnmi_config(duthost)
