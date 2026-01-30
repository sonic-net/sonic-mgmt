import pytest
import logging

from tests.gnmi.conftest import setup_gnmi_rotated_server
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.helpers.gnmi_utils import GNMIEnvironment, gnmi_capabilities
from tests.common.utilities import get_image_type


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]


def check_gnmi_status(duthost):
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    dut_command = "docker exec %s supervisorctl status %s" % (env.gnmi_container, env.gnmi_program)
    output = duthost.shell(dut_command, module_ignore_errors=True)
    return "RUNNING" in output['stdout']


def check_telemetry_status(duthost):
    env = GNMIEnvironment(duthost, GNMIEnvironment.TELEMETRY_MODE)
    dut_command = "docker exec %s supervisorctl status %s" % (env.gnmi_container, env.gnmi_program)
    output = duthost.shell(dut_command, module_ignore_errors=True)
    return "RUNNING" in output['stdout']


def test_mimic_hwproxy_cert_rotation(duthosts, rand_one_dut_hostname, localhost, ptfhost):
    duthost = duthosts[rand_one_dut_hostname]

    # Use bash -c to run the pipeline properly
    cmd_feature = (
        'bash -c "show feature status | awk \'$1==\\"gnmi\\" || $1==\\"telemetry\\" {print $1, $2}\'"'
    )
    logging.debug("show feature status command is: {}".format(cmd_feature))

    result = duthost.command(cmd_feature, module_ignore_errors=True)
    output = result["stdout"]

    gnmi_enabled = False
    telemetry_enabled = False

    for line in output.splitlines():
        parts = line.split()
        if len(parts) == 2:
            feature, state = parts
            if feature == "gnmi" and state == "enabled":
                gnmi_enabled = True
            elif feature == "telemetry" and state == "enabled":
                telemetry_enabled = True

    if get_image_type(duthost) != "public":
        pytest_assert(
            gnmi_enabled or telemetry_enabled,
            "Internal image has neither gnmi nor telemetry feature enabled"
        )

    if gnmi_enabled:
        cmd_feature = "docker images | grep 'docker-sonic-gnmi'"
        result = duthost.command(cmd_feature, module_ignore_errors=True)
        if result["stdout"].strip():
            # disable feature
            disable_feature = 'sudo config feature state gnmi disabled'
            duthost.command(disable_feature, module_ignore_errors=True)
            # rotate gnmi cert
            setup_gnmi_rotated_server(duthosts, rand_one_dut_hostname, localhost, ptfhost)
            # set gnmi table
            env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
            port = env.gnmi_port
            set_table = (
                f'sonic-db-cli CONFIG_DB hset "GNMI|gnmi" '
                f'client_auth "true" '
                f'log_level "2" '
                f'port "{port}"'
            )
            duthost.command(set_table, module_ignore_errors=True)
            set_table_cert = 'sonic-db-cli CONFIG_DB hset "GNMI|certs"   \
                    ca_crt "/etc/sonic/telemetry/gnmiCA.pem"   \
                    server_crt "/etc/sonic/telemetry/gnmiserver.crt"   \
                    server_key "/etc/sonic/telemetry/gnmiserver.key"'
            duthost.command(set_table_cert, module_ignore_errors=True)
            # enable feature
            enable_feature = 'sudo config feature state gnmi enabled'
            duthost.command(enable_feature, module_ignore_errors=True)
            assert wait_until(60, 3, 0, check_gnmi_status, duthost), "GNMI service failed to start"
            ret, msg = gnmi_capabilities(duthost, localhost)
            assert ret == 0, msg
            assert "sonic-db" in msg, msg
            assert "JSON_IETF" in msg, msg

    if telemetry_enabled:
        cmd_feature = "docker images | grep 'docker-sonic-telemetry'"
        result = duthost.command(cmd_feature, module_ignore_errors=True)
        if result["stdout"].strip():
            # disable feature
            disable_feature = 'sudo config feature state telemetry disabled'
            duthost.command(disable_feature, module_ignore_errors=True)
            # rotate telemetry cert
            setup_gnmi_rotated_server(duthosts, rand_one_dut_hostname, localhost, ptfhost)
            # set telemetry table
            env = GNMIEnvironment(duthost, GNMIEnvironment.TELEMETRY_MODE)
            port = env.gnmi_port
            set_table = (
                f'sonic-db-cli CONFIG_DB hset "TELEMETRY|gnmi" '
                f'client_auth "true" '
                f'log_level "2" '
                f'port "{port}"'
            )
            duthost.command(set_table, module_ignore_errors=True)
            set_table_cert = 'sonic-db-cli CONFIG_DB hset "TELEMETRY|certs"   \
                    ca_crt "/etc/sonic/telemetry/gnmiCA.pem"   \
                    server_crt "/etc/sonic/telemetry/gnmiserver.crt"   \
                    server_key "/etc/sonic/telemetry/gnmiserver.key"'
            duthost.command(set_table_cert, module_ignore_errors=True)
            # enable feature
            enable_feature = 'sudo config feature state telemetry enabled'
            duthost.command(enable_feature, module_ignore_errors=True)
            assert wait_until(60, 3, 0, check_telemetry_status, duthost), "TELEMETRY service failed to start"
