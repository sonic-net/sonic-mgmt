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
    # Delete the whole CONFIG_DB entries rather than one field at a time. gnmi-native.sh
    # re-reads CONFIG_DB every time supervisord starts the gnmi program, and it exits with
    # "Incorrect port value null, expecting positive integers" whenever 'GNMI|gnmi' still
    # exists but 'port' has already been removed. Removing the entries whole keeps the
    # config either complete or absent for any restart that overlaps with the cleanup.
    cmd = "sonic-db-cli CONFIG_DB del 'GNMI|certs'"
    duthost.shell(cmd, module_ignore_errors=True)
    cmd = "sonic-db-cli CONFIG_DB del 'GNMI|gnmi'"
    duthost.shell(cmd, module_ignore_errors=True)


def wait_gnmi_ready(duthost, env):
    py_assert(wait_until(100, 10, 0, duthost.is_service_fully_started, env.gnmi_container),
              "%s not started." % (env.gnmi_container))

    def _program_running():
        cmd = "docker exec %s supervisorctl status %s" % (env.gnmi_container, env.gnmi_program)
        return "RUNNING" in duthost.shell(cmd, module_ignore_errors=True)['stdout']

    py_assert(wait_until(60, 5, 0, _program_running),
              "%s is not running in container %s." % (env.gnmi_program, env.gnmi_container))


def restart_gnmi(duthost, env):
    duthost.shell("systemctl reset-failed %s" % (env.gnmi_container))
    duthost.service(name=env.gnmi_container, state="restarted")
    wait_gnmi_ready(duthost, env)


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
        restart_gnmi(duthost, env)


def restore_gnmi_state(duthost, env, has_gnmi_config, default_client_auth):
    """ Undo everything setup_streaming_telemetry_context changed.

        The order matters. When this helper created the GNMI config, putting client_auth back
        would recreate 'GNMI|gnmi' without 'port', which is the state gnmi-native.sh rejects.
        The config is therefore removed first and the container is restarted once afterwards,
        so no restart ever observes a partially deleted GNMI config.
    """
    if not has_gnmi_config:
        delete_gnmi_config(duthost)
        if env is not None:
            restart_gnmi(duthost, env)
    elif default_client_auth is not None:
        restore_telemetry_forpyclient(duthost, default_client_auth)


@contextmanager
def setup_streaming_telemetry_context(is_ipv6, duthost, localhost, ptfhost, gnxi_path):
    """
    @summary: Post setting up the streaming telemetry before running the test.
    """
    env = None
    has_gnmi_config = True
    default_client_auth = None
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
        restore_gnmi_state(duthost, env, has_gnmi_config, default_client_auth)
        raise e

    yield
    restore_gnmi_state(duthost, env, has_gnmi_config, default_client_auth)
