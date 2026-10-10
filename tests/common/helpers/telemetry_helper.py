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


def _diag_capture(duthost, tag):
    # DIAGNOSTIC ONLY. Dump the state that decides whether gnmi-native survives the
    # CONFIG_DB cleanup, so every forced cycle leaves process/config/syslog evidence.
    cmds = [
        "date -u +%Y-%m-%dT%H:%M:%S.%NZ",
        "sonic-db-cli CONFIG_DB hgetall 'GNMI|gnmi'",
        "sonic-db-cli CONFIG_DB hgetall 'GNMI|certs'",
        "docker exec gnmi supervisorctl status",
        "docker exec gnmi ps -ef",
        "grep -a 'supervisor-proc-exit-listener\\|gnmi-native\\|Incorrect port value' /var/log/syslog | tail -n 25",
    ]
    for cmd in cmds:
        res = duthost.shell(cmd, module_ignore_errors=True)
        logger.warning("GNMI-RACE-DIAG [%s] $ %s\n%s", tag, cmd, res.get('stdout', ''))


def delete_gnmi_config(duthost):
    # !!! DIAGNOSTIC-ONLY BRANCH - FORCED REPRODUCTION - NEVER MERGE !!!
    # Identical to 202605 except for the instrumentation and the sleep below.
    # The sleep widens the "GNMI|gnmi exists without port" window from the ~3 s measured
    # on an idle KVM testbed to ~20 s, past the measured 5-6 s gnmi container re-render
    # delay, which turns the intermittent race into a deterministic kill.
    _diag_capture(duthost, "before delete_gnmi_config")
    cmd = "sonic-db-cli CONFIG_DB hdel 'GNMI|gnmi' port"
    duthost.shell(cmd, module_ignore_errors=True)
    logger.warning("GNMI-RACE-DIAG forced window OPEN - sleeping 20s with 'GNMI|gnmi' present and portless")
    duthost.shell("sleep 20", module_ignore_errors=True)
    _diag_capture(duthost, "inside forced window")
    cmd = "sonic-db-cli CONFIG_DB hdel 'GNMI|gnmi' client_auth"
    duthost.shell(cmd, module_ignore_errors=True)
    cmd = "sonic-db-cli CONFIG_DB hdel 'GNMI|certs' ca_crt"
    duthost.shell(cmd, module_ignore_errors=True)
    cmd = "sonic-db-cli CONFIG_DB hdel 'GNMI|certs' server_crt"
    duthost.shell(cmd, module_ignore_errors=True)
    cmd = "sonic-db-cli CONFIG_DB hdel 'GNMI|certs' server_key"
    duthost.shell(cmd, module_ignore_errors=True)
    _diag_capture(duthost, "after delete_gnmi_config")


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
    try:
        has_gnmi_config = check_gnmi_config(duthost)
        if not has_gnmi_config:
            create_gnmi_config(duthost)
        env = GNMIEnvironment(duthost, GNMIEnvironment.TELEMETRY_MODE)
        default_client_auth = setup_telemetry_forpyclient(duthost)

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
    if not has_gnmi_config:
        delete_gnmi_config(duthost)
