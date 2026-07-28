import pytest
import logging

from tests.common.helpers.gnmi_utils import gnmi_capabilities, add_gnmi_client_common_name
from .helper import gnmi_subscribe_streaming_sample
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure


logger = logging.getLogger(__name__)
allure.logger = logger

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer,
    pytest.mark.usefixtures("setup_gnmi_ntp_client_server", "setup_gnmi_server",
                            "setup_gnmi_rotated_server", "check_dut_timestamp")
]


def test_gnmi_capabilities(duthosts, rand_one_dut_hostname, localhost):
    '''
    Verify GNMI capabilities
    '''
    duthost = duthosts[rand_one_dut_hostname]
    ret, msg = gnmi_capabilities(duthost, localhost)
    assert ret == 0, (
        "GNMI capabilities command failed (non-zero return code).\n"
        "- Error message: {}"
    ).format(msg)

    assert "sonic-db" in msg, (
        "'sonic-db' not found in GNMI capabilities response message.\n"
        "- Actual message: {}"
    ).format(msg)

    assert "JSON_IETF" in msg, (
        "'JSON_IETF' not found in GNMI capabilities response message.\n"
        "- Actual message: {}"
    ).format(msg)


def test_gnmi_capabilities_authenticate(duthosts, rand_one_dut_hostname, localhost):
    '''
    Verify GNMI capabilities with different roles
    '''
    duthost = duthosts[rand_one_dut_hostname]

    with allure.step("Verify GNMI capabilities with noaccess role"):
        role = "gnmi_noaccess"
        add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic", role)
        ret, msg = gnmi_capabilities(duthost, localhost)
        assert ret != 0, (
            "GNMI capabilities authenticate with noaccess role command unexpectedly succeeded "
            "(zero return code) for a client with noaccess role.\n"
            "- Error message: {}"
        ).format(msg)

        assert role in msg, (
            "Expected role '{}' in GNMI capabilities authenticate with noaccess role response, but got: {}"
        ).format(role, msg)

    with allure.step("Verify GNMI capabilities with readonly role"):
        role = "gnmi_readonly"
        add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic", role)
        ret, msg = gnmi_capabilities(duthost, localhost)
        assert ret == 0, (
            "GNMI capabilities authenticate readonly command failed (non-zero return code).\n"
            "- Error message: {}"
        ).format(msg)

        assert "sonic-db" in msg, (
            "Expected 'sonic-db' in GNMI capabilities authenticate with readonly role response, but got: {}"
        ).format(msg)

        assert "JSON_IETF" in msg, (
            "Expected 'JSON_IETF' in GNMI capabilities authenticate with readonly role  response, but got: {}"
        ).format(msg)

    with allure.step("Verify GNMI capabilities with readwrite role"):
        role = "gnmi_readwrite"
        add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic", role)
        ret, msg = gnmi_capabilities(duthost, localhost)
        assert ret == 0, (
            "GNMI capabilities authenticate readwrite role command failed (non-zero return code).\n"
            "- Error message: {}"
        ).format(msg)

        assert "sonic-db" in msg, (
            "Expected 'sonic-db' in GNMI capabilities with readwrite role response, but got: {}"
        ).format(msg)

        assert "JSON_IETF" in msg, (
            "Expected 'JSON_IETF' in GNMI capabilities  with readwrite role response, but got: {}"
        ).format(msg)

    with allure.step("Verify GNMI capabilities with empty role"):
        role = ""
        add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic", role)
        ret, msg = gnmi_capabilities(duthost, localhost)
        assert ret == 0, (
            "GNMI capabilities authenticate with empty role command failed (non-zero return code).\n"
            "- Error message: {}"
        ).format(msg)

        assert "sonic-db" in msg, (
            "Expected 'sonic-db' in GNMI capabilities with empty role response, but got: {}"
        ).format(msg)

        assert "JSON_IETF" in msg, (
            "Expected 'JSON_IETF' in GNMI capabilities with empty role response, but got: {}"
        ).format(msg)

    # Restore default role
    add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic")




def test_gnmi_subscribe_sample(duthosts, rand_one_dut_hostname, ptfhost):
    '''
    Verify GNMI subscribe sample request
    '''
    duthost = duthosts[rand_one_dut_hostname]

    # Skip test for supervisor nodes as they don't have Ethernet0 frontpanel port
    if duthost.is_supervisor_node():
        pytest.skip("Skipping test as no Ethernet0 frontpanel port on supervisor")

    interval_ms = 5000  # 5 second interval
    count = 5

    def validates_subscribe_sample(output: str):
        respCnt = output.count("response received")

        # expected <count> responses + 1 sync response
        assert respCnt == count + 1, f"expected {count + 1} responses, got {respCnt}"

        timestamps = [ts for ts in output.split("\n") if "timestamp" in ts]
        for i in range(len(timestamps) - 1):
            if i == 0:
                break
            # format "timestamp: <timestamp in nanoseconds>"
            currTs = int(timestamps[i].split(': ')[1])
            nextTs = int(timestamps[i + 1].split(': ')[1])
            # round to the nearest second
            assert round(nextTs - currTs, -8) == 5000000000, (
                "expected 5 second timestamp diff," f"currTs: {currTs}, nextTs: {nextTs}"
            )

        logger.info(f"Successfully received exactly {count} gNMI subscribe sample responses")

    with allure.step("Perform gNMI subscribe sample request to state DB"):
        stdout_msg, _ = gnmi_subscribe_streaming_sample(
            duthost, ptfhost,  ["/PSU_INFO"], interval_ms, count, target="STATE_DB"
        )
        logger.debug("gNMI subscribe response: %s", stdout_msg)
        validates_subscribe_sample(stdout_msg)

    with allure.step("Perform gNMI subscribe sample request to sonic DB"):
        stdout_msg, _ = gnmi_subscribe_streaming_sample(
            duthost, ptfhost, ["/COUNTERS_DB/localhost/COUNTERS"], interval_ms, count, origin="sonic-db"
        )
        logger.debug("gNMI subscribe response: %s", stdout_msg)
        validates_subscribe_sample(stdout_msg)
