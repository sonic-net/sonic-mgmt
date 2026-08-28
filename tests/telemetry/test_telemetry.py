import time
import logging
import pytest
from telemetry_utils import skip_201911_and_older
from telemetry_utils import generate_client_cli

pytestmark = [
    pytest.mark.topology('any', 't1-multi-asic')
]

logger = logging.getLogger(__name__)

METHOD_SUBSCRIBE = "subscribe"


@pytest.mark.parametrize('setup_streaming_telemetry', [False], indirect=True)
def test_sysuptime(duthosts, enum_rand_one_per_hwsku_hostname, ptfhost, gnxi_path, setup_streaming_telemetry):
    """
    @summary: Run pyclient from ptfdocker and test the dataset 'system uptime' to check
              whether the value of 'system uptime' was float number and whether the value was
              updated correctly.
    """
    logger.info("start test the dataset 'system uptime'")
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    skip_201911_and_older(duthost)
    cmd = generate_client_cli(duthost, gnxi_path, method="get", xpath="proc/uptime", target="OTHERS")
    system_uptime_info = ptfhost.shell(cmd)["stdout_lines"]
    system_uptime_1st = 0
    found_system_uptime_field = False
    for line_info in system_uptime_info:
        if "total" in line_info:
            try:
                system_uptime_1st = float(line_info.split(":")[1].strip().rstrip(','))
                found_system_uptime_field = True
            except ValueError as err:
                pytest.fail(
                    "The value of system uptime was not a float. Error message was '{}'".format(err))

    if not found_system_uptime_field:
        pytest.fail("The field of system uptime was not found.")

    # Wait 10 seconds such that the value of system uptime was added 10 seconds.
    time.sleep(10)
    system_uptime_info = ptfhost.shell(cmd)["stdout_lines"]
    system_uptime_2nd = 0
    found_system_uptime_field = False
    for line_info in system_uptime_info:
        if "total" in line_info:
            try:
                system_uptime_2nd = float(line_info.split(":")[1].strip().rstrip(','))
                found_system_uptime_field = True
            except ValueError as err:
                pytest.fail(
                    "The value of system uptime was not a float. Error message was '{}'".format(err))

    if not found_system_uptime_field:
        pytest.fail("The field of system uptime was not found.")

    if system_uptime_2nd - system_uptime_1st < 10:
        pytest.fail("The value of system uptime was not updated correctly.")


def invoke_py_cli_from_ptf(ptfhost, cmd, callback):
    ret = ptfhost.shell(cmd)
    assert ret["rc"] == 0, "PTF docker did not get a response"
    if callback is not None:
        callback(ret["stdout"])
