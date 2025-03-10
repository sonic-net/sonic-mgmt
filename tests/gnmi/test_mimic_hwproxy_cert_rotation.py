import pytest
import logging
import json

from .helper import gnoi_request
from tests.common.helpers.assertions import pytest_assert
import re

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]



def test_mimic_hwproxy_cert_rotation(duthosts, rand_one_dut_hostname, localhost):
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

    if gnmi_enabled:
        cmd_feature = "docker images| grep 'docker-sonic-gnmi'"
        result = duthost.command(cmd_feature, module_ignore_errors=True)
        if result.stdout.strip():
            disable_feature = 'sudo config feature state gnmi disabled'
            duthost.command(disable_feature, module_ignore_errors=True)
            # rotate gnmi cert

    if telemetry_enabled:
        cmd_feature = "docker images| grep 'docker-sonic-telemetry'"
        result = duthost.command(cmd_feature, module_ignore_errors=True)
        if result.stdout.strip():
            disable_feature = 'sudo config feature state telemetry disabled'
            duthost.command(disable_feature, module_ignore_errors=True)
            # rotate telemetry cert