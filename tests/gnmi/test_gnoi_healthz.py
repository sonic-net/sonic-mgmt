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
healthz_paths = ["alert-info", "all-info", "critical-info"]


@pytest.mark.parametrize("container", containers)
@pytest.mark.parametrize("path_type", healthz_paths)
@pytest.mark.disable_loganalyzer
def test_gnoi_healthz_get_operations(duthosts, rand_one_dut_hostname, localhost, container, path_type):
    """
    Verify the gNOI Healthz is retrieving the latest health status for various gNMI paths
    and testing the Artifact and Acknowledge RPCs.
    """
    duthost = duthosts[rand_one_dut_hostname]
    # 1. Test Healthz.Get RPC
    path = f"/components/component[name={container}]/healthz/{path_type}"
    request_json_get = f'{{"path":"{path}"}}'
    ret_get, msg_get = gnoi_request(duthost, localhost, "Healthz", "Get", request_json_get)
    pytest_assert(ret_get == 0, f"Healthz.Get ({container}/{path_type}) RPC failed: rc = {ret_get}, msg = {msg_get}")

    logging.info(f"Healthz.Get ({container}/{path_type}) API returned msg: {msg_get}")
    # Assert that the response contains Status: STATUS_HEALTHY
    pytest_assert("STATUS_HEALTHY" in msg_get, f"Healthz.Get ({path_type}) did not return correct HEALTH status")

    # Extract File Name for subsequent RPCs
    file_pattern_match = re.search(r"File Name:\s*(.*)", msg_get)
    pytest_assert(file_pattern_match is not None, f"Could not find 'File Name:' in Healthz.Get response for {path}")
    file_name = file_pattern_match.group(1).strip()
    logging.info(f"Extracted File Name for Artifact/Acknowledge: {file_name}")

    # 2. Test Healthz.Artifact RPC
    artifact_id = f' -id "{file_name}"'

    ret_artifact, msg_artifact = gnoi_request(duthost, localhost, "Healthz", "Artifact", "", artifact_id)
    pytest_assert(
        ret_artifact == 0,
        f"Healthz.Artifact ({container}/{path_type}) RPC failed: rc = {ret_artifact}, msg = {msg_artifact}"
    )

    logging.info(f"Healthz.Artifact API returned msg: {msg_artifact}")
    # Assert that the response contains Status: Response Success
    pytest_assert(
        "Artifact Response success" in msg_artifact,
        f"Healthz.Artifact ({path_type}) did not return correct Artificat status"
    )

    # 3. Test Healthz.Acknowledge RPC
    request_json_ack = (
        f'{{"path": "{path}", "id": "{file_name}"}}'
    )
    ret_ack, msg_ack = gnoi_request(duthost, localhost, "Healthz", "Acknowledge", request_json_ack)
    pytest_assert(
        ret_ack == 0,
        f"Healthz.Acknowledge ({container}/{path_type}) RPC failed: rc = {ret_ack}, msg = {msg_ack}"
    )

    logging.info(f"Healthz.Acknowledge API returned msg: {msg_ack}")
    # Assert that the response contains Status: Acknowledge resonse nil
    pytest_assert(
        "Acknowledge response: <nil>" in msg_ack,
        f"Healthz.Acknowledge ({path_type}) did not return correct Acknowledge status"
    )


@pytest.mark.disable_loganalyzer
def test_gnoi_healthz_list(duthosts, rand_one_dut_hostname, localhost):
    """
    Verify the gNOI Healthz List RPC is returning Method Unimplemented Error
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
    Verify the gNOI Healthz Check RPC is returning Method Unimplemented Error
    """

    duthost = duthosts[rand_one_dut_hostname]

    request_json = '{\"path\":\"/components/component[name=healthz]\", \"event_id\": \"event-abc123\"}'
    ret, msg = gnoi_request(duthost, localhost, "Healthz", "Check", request_json)
    pytest_assert(ret == 0, f"Healthz.Check RPC failed: rc = {ret}, msg = {msg}")

    logging.info("Healtlz.Check API returned msg: {}".format(msg))
    # Assert that the response contains "not implimented Error"
    pytest_assert("not implemented" in msg, "Expected method unimplemented error")
