import time
import logging
import re
import pytest
from tests.common.helpers.assertions import pytest_assert
from telemetry_utils import assert_equal, skip_201911_and_older
from telemetry_utils import generate_client_cli

pytestmark = [
    pytest.mark.topology('any', 't1-multi-asic')
]

logger = logging.getLogger(__name__)

METHOD_SUBSCRIBE = "subscribe"
METHOD_GET = "get"


@pytest.mark.parametrize('setup_streaming_telemetry', [False], indirect=True)
def test_telemetry_ouput(duthosts, enum_rand_one_per_hwsku_hostname, ptfhost,
                         setup_streaming_telemetry, gnxi_path):
    """Run pyclient from ptfdocker and show gnmi server outputself.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    if duthost.is_supervisor_node():
        pytest.skip(
            "Skipping test as no Ethernet0 frontpanel port on supervisor")
    logger.info('start telemetry output testing')
    cmd = generate_client_cli(duthost, gnxi_path, method="get", xpath="COUNTERS/Ethernet0", target="COUNTERS_DB")
    show_gnmi_out = ptfhost.shell(cmd)['stdout']
    logger.info("GNMI Server output")
    logger.info(show_gnmi_out)
    result = str(show_gnmi_out)
    inerrors_match = re.search("SAI_PORT_STAT_IF_IN_ERRORS", result)
    pytest_assert(inerrors_match is not None,
                  "SAI_PORT_STAT_IF_IN_ERRORS not found in gnmi_output")


@pytest.mark.parametrize('setup_streaming_telemetry', [False], indirect=True)
def test_osbuild_version(duthosts, enum_rand_one_per_hwsku_hostname, ptfhost,
                         setup_streaming_telemetry, gnxi_path):
    """ Test osbuild/version query.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    skip_201911_and_older(duthost)
    cmd = generate_client_cli(duthost=duthost, gnxi_path=gnxi_path,
                              method=METHOD_GET, target="OTHERS", xpath="osversion/build")
    show_gnmi_out = ptfhost.shell(cmd)['stdout']
    result = str(show_gnmi_out)

    assert_equal(len(re.findall(r'"build_version": "SONiC\.', result)),
                 1, "build_version value at {0}".format(result))
    assert_equal(len(re.findall(r'SONiC\.NA', result, flags=re.IGNORECASE)),
                 0, "invalid build_version value at {0}".format(result))


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


@pytest.mark.parametrize('setup_streaming_telemetry', [False], indirect=True)
def test_virtualdb_table_streaming(duthosts, enum_rand_one_per_hwsku_hostname, ptfhost, gnxi_path,
                                   setup_streaming_telemetry):
    """Run pyclient from ptfdocker to stream a virtual-db query multiple times.
    """
    logger.info('start virtual db sample streaming testing')

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    if duthost.is_supervisor_node():
        pytest.skip(
            "Skipping test as no Ethernet0 frontpanel port on supervisor")
    skip_201911_and_older(duthost)
    cmd = generate_client_cli(
        duthost=duthost, gnxi_path=gnxi_path, method=METHOD_SUBSCRIBE, update_count=3)
    show_gnmi_out = ptfhost.shell(cmd)['stdout']
    result = str(show_gnmi_out)

    assert_equal(len(re.findall('Max update count reached 3', result)),
                 1, "Streaming update count in:\n{0}".format(result))
    assert_equal(len(re.findall('name: "Ethernet0"\n', result)), 4,
                 "Streaming updates for Ethernet0 in:\n{0}".format(result))  # 1 for request, 3 for response
    assert_equal(len(re.findall(r'timestamp: \d+', result)), 3,
                 "Timestamp markers for each update message in:\n{0}".format(result))
