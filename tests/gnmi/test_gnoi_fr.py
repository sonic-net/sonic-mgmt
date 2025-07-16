import pytest
import logging
import json

from .helper import gnoi_request
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology('any')
]

"""
This module contains tests for the gNOI FactoryReset API.
"""


@pytest.mark.disable_loganalyzer
def test_gnoi_factory_reset(duthosts, rand_one_dut_hostname, localhost):
    """
    Expects 'Method FactoryReset.Start is unimplemented.' error.
    """
    duthost = duthosts[rand_one_dut_hostname]
    request_json = '{"factoryOs": true}'
    ret, msg = gnoi_request(duthost, localhost, "FactoryReset", "Start", request_json)
    pytest_assert(ret == 0, f"FactoryReset.Start RPC failed: rc = {ret}, msg = {msg}")

    msg_json = json.loads(msg)
    logging.info(f"FactoryReset.Start Response: {msg_json}")
    pytest_assert("Response" in msg_json, "Missing 'Response' in output")
    pytest_assert("ResetError" in msg_json["Response"], "Expected ResetError in response")
    pytest_assert("unimplemented" in msg_json["Response"]["ResetError"]["detail"].lower(),
                  "Expected method unimplemented error")


@pytest.mark.disable_loganalyzer
def test_gnoi_factory_reset_zero_fill(duthosts, rand_one_dut_hostname, localhost):
    """
    Expects zero_fill_unsupported error in the response.
    """
    duthost = duthosts[rand_one_dut_hostname]
    request_json = '{"factory_os": true, "zero_fill": true}'
    ret, msg = gnoi_request(duthost, localhost, "FactoryReset", "Start", request_json)
    pytest_assert(ret == 0, f"FactoryReset.Start RPC failed: rc = {ret}, msg = {msg}")

    msg_json = json.loads(msg)
    logging.info(f"FactoryReset.Start Response: {msg_json}")
    pytest_assert("Response" in msg_json, "Missing 'Response' in output")
    pytest_assert("ResetError" in msg_json["Response"], "Expected ResetError in response")
    pytest_assert("zero_fill" in msg_json["Response"]["ResetError"]["detail"].lower(),
                  "Expected unsupported error detail mentioning zero_fill")


@pytest.mark.disable_loganalyzer
def test_gnoi_factory_reset_retain_certs(duthosts, rand_one_dut_hostname, localhost):
    """
    Expects method unimplemented error.
    """
    duthost = duthosts[rand_one_dut_hostname]
    request_json = '{"factoryOs": true, "retainCerts": true}'
    ret, msg = gnoi_request(duthost, localhost, "FactoryReset", "Start", request_json)
    pytest_assert(ret == 0, f"FactoryReset.Start RPC failed: rc = {ret}, msg = {msg}")

    msg_json = json.loads(msg)
    logging.info(f"FactoryReset.Start Response: {msg_json}")
    pytest_assert("Response" in msg_json, "Missing 'Response' in output")
    pytest_assert("ResetError" in msg_json["Response"], "Expected ResetError in response")
    pytest_assert("unimplemented" in msg_json["Response"]["ResetError"]["detail"].lower(),
                  "Expected method unimplemented error")
