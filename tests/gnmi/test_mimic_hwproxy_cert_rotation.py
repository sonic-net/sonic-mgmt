import pytest
import logging

from tests.gnmi.conftest import setup_gnmi_rotated_server
from tests.gnmi.test_gnmi_countersdb import test_gnmi_queue_buffer_cnt
from tests.common.helpers.assertions import pytest_assert


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]


def test_mimic_hwproxy_cert_rotation(duthosts, rand_one_dut_hostname, localhost, ptfhost):
    duthost = duthosts[rand_one_dut_hostname]
    cmd_feature = 'show feature status | awk \'$1=="gnmi" || $1=="telemetry" {print $1, $2}\''
    logging.debug("show feature status command is: {}".format(cmd_feature))
    output = duthost.command(cmd_feature, module_ignore_errors=True)

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
        pytest_assert(gnmi_enabled or telemetry_enabled,
                      "Internal image has neither gnmi nor telemetry feature enabled")

    if gnmi_enabled:
        cmd_feature = "docker images| grep 'docker-sonic-gnmi'"
        result = duthost.command(cmd_feature, module_ignore_errors=True)
        if result.stdout.strip():
            # disable feature
            disable_feature = 'sudo config feature state gnmi disabled'
            duthost.command(disable_feature, module_ignore_errors=True)
            # rotate gnmi cert
            setup_gnmi_rotated_server(duthosts, rand_one_dut_hostname, localhost, ptfhost)
            # enable feature
            enable_feature = 'sudo config feature state gnmi enabled'
            duthost.command(enable_feature, module_ignore_errors=True)
            test_gnmi_queue_buffer_cnt(duthosts, rand_one_dut_hostname, ptfhost)

    if telemetry_enabled:
        cmd_feature = "docker images| grep 'docker-sonic-telemetry'"
        result = duthost.command(cmd_feature, module_ignore_errors=True)
        if result.stdout.strip():
            # disable feature
            disable_feature = 'sudo config feature state telemetry disabled'
            duthost.command(disable_feature, module_ignore_errors=True)
            # rotate telemetry cert
            setup_gnmi_rotated_server(duthosts, rand_one_dut_hostname, localhost, ptfhost)
            # enable feature
            enable_feature = 'sudo config feature state telemetry enabled'
            duthost.command(enable_feature, module_ignore_errors=True)
            test_gnmi_queue_buffer_cnt(duthosts, rand_one_dut_hostname, ptfhost)
