import pytest
import logging
import json

from tests.gnmi.conftest import setup_gnmi_rotated_server, create_revoked_cert_and_crl
from tests.gnmi.test_gnmi_countersdb import test_gnmi_queue_buffer_cnt
from sonic_py_common import device_info

import re

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]

def test_mimic_hwproxy_cert_rotation(duthosts, rand_one_dut_hostname, localhost, ptfhost):
    duthost = duthosts[rand_one_dut_hostname]
    cmd_feature = "show feature status | awk '$1=="gnmi" || $1=="telemetry" {print $1, $2}'"
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

    image_version = device_info.get_sonic_version_info()
    build_version = image_version['build_version']
    if re.match(r'^internal-(\d{8})', build_version):
        pytest_assert(gnmi_enabled or telemetry_enabled, "Internal image has neither gnmi nor telemetry feature enabled")

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


