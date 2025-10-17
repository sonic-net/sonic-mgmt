import pytest
import logging
import re

from .helper import gnoi_request
from tests.common.helpers.assertions import pytest_assert

pytestmark = [pytest.mark.topology("any")]

"""
This module contains tests for the gNOI Healthz API
"""

# Below were the current supported containers which supports Healthz RPC's.
containers = ["gnmi", "orch"]


@pytest.mark.disable_loganalyzer
def test_gnoi_healthz_get_alert_info(duthosts, rand_one_dut_hostname, localhost):
    """
    Verify the gNOI Healthz is retrieving the latest health status for a gNMI alert-info path
    """

    duthost = duthosts[rand_one_dut_hostname]

    for container in containers:

        request_json1 = f'{{\"path\":\"/components/component[name={container}]/healthz/alert-info\"}}'
        ret, msg = gnoi_request(duthost, localhost, "Healthz", "Get", request_json1)
        pytest_assert(ret == 0, f"Healthz.Get-alert-info RPC failed: rc = {ret}, msg = {msg}")

        logging.info("Healthz.Get-alert-info API returned msg: {}".format(msg))
        # Assert that the response contains Status: STATUS_HEALTHY
        pytest_assert("STATUS_HEALTHY" in msg, "Healthz.Get-alert_info did not return correct HEALTH status")

        # Now invoking Aritifact RPC
        file_pattern_match = re.search(r"File Name:\s*(.*)", msg)
        file_name = file_pattern_match.group(1).strip()
        id = f' -id "{file_name}"'

        ret1, msg1 = gnoi_request(duthost, localhost, "Healthz", "Artifact", "", id)
        pytest_assert(ret1 == 0, f"Healthz.Get-alert-info RPC failed: rc = {ret1}, msg = {msg1}")

        logging.info("Healthz.Get-alert-info API returned msg: {}".format(msg1))
        # Assert that the response contains Status: Response Success
        pytest_assert(
            "Artifact Response success" in msg1,
            "Healthz.Get-alert_info did not return correct Artificat status"
        )

        # Now invoking Acknowledge RPC
        request_json2 = (
            f'{{\"path\": \"/components/component[name={container}]/healthz/alert-info\", \"id\": \"{file_name}\"}}'
        )
        ret2, msg2 = gnoi_request(duthost, localhost, "Healthz", "Acknowledge", request_json2)
        pytest_assert(ret2 == 0, f"Healthz.Get-alert-info RPC failed: rc = {ret2}, msg = {msg2}")

        logging.info("Healthz.Get-alert-info API returned msg: {}".format(msg2))
        # Assert that the response contains Status: Acknowledge resonse nil
        pytest_assert(
            "Acknowledge response: <nil>" in msg2,
            "Healthz.Get-alert_info did not return correct Acknowledge status"
        )


@pytest.mark.disable_loganalyzer
def test_gnoi_healthz_get_all_info(duthosts, rand_one_dut_hostname, localhost):
    """
    Verify the gNOI Healthz is retrieving the latest health status for a gNMI all-info path
    """

    duthost = duthosts[rand_one_dut_hostname]

    for container in containers:

        request_json = f'{{\"path\":\"/components/component[name={container}]/healthz/all-info\"}}'
        ret, msg = gnoi_request(duthost, localhost, "Healthz", "Get", request_json)
        pytest_assert(ret == 0, f"Healthz.Get-all-info RPC failed: rc = {ret}, msg = {msg}")

        logging.info("Healthz.Get-all-info API returned msg: {}".format(msg))
        # Assert that the response contains Status: STATUS_HEALTHY
        pytest_assert("STATUS_HEALTHY" in msg, "Healthz.Get-all_info did not return correct HEALTH status")

        # Now invoking Aritifact RPC
        file_pattern_match = re.search(r"File Name:\s*(.*)", msg)
        file_name = file_pattern_match.group(1).strip()
        id = f' -id "{file_name}"'

        ret1, msg1 = gnoi_request(duthost, localhost, "Healthz", "Artifact", "", id)
        pytest_assert(ret1 == 0, f"Healthz.Get-all-info RPC failed: rc = {ret1}, msg = {msg1}")

        logging.info("Healthz.Get-all-info API returned msg: {}".format(msg1))
        # Assert that the response contains Status: Response Success
        pytest_assert(
            "Artifact Response success" in msg1,
            "Healthz.Get-all_info did not return correct Artificat status"
        )

        # Now invoking Acknowledge RPC
        request_json2 = (
            f'{{\"path\": \"/components/component[name={container}]/healthz/all-info\", \"id\": \"{file_name}\"}}'
        )
        ret2, msg2 = gnoi_request(duthost, localhost, "Healthz", "Acknowledge", request_json2)
        pytest_assert(ret2 == 0, f"Healthz.Get-all-info RPC failed: rc = {ret2}, msg = {msg2}")

        logging.info("Healthz.Get-all-info API returned msg: {}".format(msg2))
        # Assert that the response contains Status: Acknowledge resonse nil
        pytest_assert(
            "Acknowledge response: <nil>" in msg2,
            "Healthz.Get-all_info did not return correct Acknowledge status"
        )


@pytest.mark.disable_loganalyzer
def test_gnoi_healthz_get_critical_info(duthosts, rand_one_dut_hostname, localhost):
    """
    Verify the gNOI Healthz is retrieving the latest health status for a gNMI critical-info path
    """

    duthost = duthosts[rand_one_dut_hostname]

    for container in containers:

        request_json = f'{{\"path\":\"/components/component[name={container}]/healthz/critical-info\"}}'
        ret, msg = gnoi_request(duthost, localhost, "Healthz", "Get", request_json)
        pytest_assert(ret == 0, f"Healthz.Get-critical-info RPC failed: rc = {ret}, msg = {msg}")

        logging.info("Healthz.Get-critical-info API returned msg: {}".format(msg))
        # Assert that the response contains Status: STATUS_HEALTHY
        pytest_assert("STATUS_HEALTHY" in msg, "Healthz.Get-critical_info did not return correct HEALTH status")

        # Now invoking Aritifact RPC
        file_pattern_match = re.search(r"File Name:\s*(.*)", msg)
        file_name = file_pattern_match.group(1).strip()
        id = f' -id "{file_name}"'

        ret1, msg1 = gnoi_request(duthost, localhost, "Healthz", "Artifact", "", id)
        pytest_assert(ret1 == 0, f"Healthz.Get-critical-info RPC failed: rc = {ret1}, msg = {msg1}")

        logging.info("Healthz.Get-critical-info API returned msg: {}".format(msg1))
        # Assert that the response contains Status: Response Success
        pytest_assert(
            "Artifact Response success" in msg1,
            "Healthz.Get-critical_info did not return correct Artificat status"
        )

        # Now invoking Acknowledge RPC
        request_json2 = (
            f'{{\"path\": \"/components/component[name={container}]/healthz/critical-info\", \"id\": \"{file_name}\"}}'
        )
        ret2, msg2 = gnoi_request(duthost, localhost, "Healthz", "Acknowledge", request_json2)
        pytest_assert(ret2 == 0, f"Healthz.Get-critical-info RPC failed: rc = {ret2}, msg = {msg2}")

        logging.info("Healthz.Get-critical-info API returned msg: {}".format(msg2))
        # Assert that the response contains Status: Acknowledge resonse nil
        pytest_assert(
            "Acknowledge response: <nil>" in msg2,
            "Healthz.Get-critical_info did not return correct Acknowledge status"
        )


@pytest.mark.disable_loganalyzer
def test_gnoi_healthz_list(duthosts, rand_one_dut_hostname, localhost):
    """
    Verify the gNOI Healthz List RPC is returning Method Unimplimented Error
    """

    duthost = duthosts[rand_one_dut_hostname]

    request_json = '{\"path\":\"/components/component[name=healthz]\", \"include_acknowledged\": true}'
    ret, msg = gnoi_request(duthost, localhost, "Healthz", "List", request_json)
    pytest_assert(ret == 0, f"Healthz.List RPC failed: rc = {ret}, msg = {msg}")

    logging.info("Healtlz.List API returned msg: {}".format(msg))
    # Assert that the response contains "not implimented Error"
    pytest_assert("not implemented" in msg, "Expected method unimplemented error")


@pytest.mark.disable_loganalyzer
def test_gnoi_healthz_check(duthosts, rand_one_dut_hostname, localhost):
    """
    Verify the gNOI Healthz Check RPC is returning Method Unimplimented Error
    """

    duthost = duthosts[rand_one_dut_hostname]

    request_json = '{\"path\":\"/components/component[name=healthz]\", \"event_id\": \"event-abc123\"}'
    ret, msg = gnoi_request(duthost, localhost, "Healthz", "Check", request_json)
    pytest_assert(ret == 0, f"Healthz.Check RPC failed: rc = {ret}, msg = {msg}")

    logging.info("Healtlz.Check API returned msg: {}".format(msg))
    # Assert that the response contains "not implimented Error"
    pytest_assert("not implemented" in msg, "Expected method unimplemented error")
