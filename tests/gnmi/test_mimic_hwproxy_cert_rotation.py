import pytest
import logging

from tests.gnmi.conftest import setup_gnmi_rotated_server
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.helpers.gnmi_utils import GNMIEnvironment
from .helper import gnmi_capabilities


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]


def check_gnmi_status(duthost):
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    dut_command = "docker exec %s supervisorctl status %s" % (env.gnmi_container, env.gnmi_program)
    output = duthost.shell(dut_command, module_ignore_errors=True)
    return "RUNNING" in output['stdout']


def test_mimic_hwproxy_cert_rotation(duthosts, rand_one_dut_hostname, localhost, ptfhost):
    duthost = duthosts[rand_one_dut_hostname]

    # Use bash -c to run the pipeline properly
    cmd_feature = (
        'bash -c \'show feature status | awk "$1==\\"gnmi\\" || $1==\\"telemetry\\" {print $1, $2}"\''
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

    if "internal" in duthost.os_version:
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
            # enable feature
            enable_feature = 'sudo config feature state telemetry enabled'
            duthost.command(enable_feature, module_ignore_errors=True)
            assert wait_until(60, 3, 0, check_gnmi_status, duthost), "GNMI service failed to start"
            ret, msg = gnmi_capabilities(duthost, localhost)
            assert ret == 0, msg
            assert "sonic-db" in msg, msg
            assert "JSON_IETF" in msg, msg
