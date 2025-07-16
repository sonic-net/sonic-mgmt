import pytest
import logging

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

    logging.info(f"FactoryReset.Start Response: {msg}")
    pytest_assert("ResetError" in msg, "Expected ResetError in response")
    pytest_assert("FactoryReset.Start" in msg, "Expected method FactoryReset.Start error")
    pytest_assert("unsupported" in msg, "Expected method unsupported error")


@pytest.mark.disable_loganalyzer
def test_gnoi_factory_reset_zero_fill(duthosts, rand_one_dut_hostname, localhost):
    """
    Expects zero_fill_unsupported error in the response.
    """
    duthost = duthosts[rand_one_dut_hostname]

    request_json = '{"factory_os": true, "zero_fill": true}'
    ret, msg = gnoi_request(duthost, localhost, "FactoryReset", "Start", request_json)
    pytest_assert(ret == 0, f"FactoryReset.Start RPC failed: rc = {ret}, msg = {msg}")

    logging.info(f"FactoryReset.Start Response: {msg}")
    pytest_assert("ResetError" in msg, "Expected ResetError in response")
    pytest_assert("zero_fill" in msg, "Expected unsupported error detail mentioning zero_fill")


@pytest.mark.disable_loganalyzer
def test_gnoi_factory_reset_retain_certs(duthosts, rand_one_dut_hostname, localhost):
    """
    Expects method unimplemented error.
    """
    duthost = duthosts[rand_one_dut_hostname]

    request_json = '{"factoryOs": true, "retainCerts": true}'
    ret, msg = gnoi_request(duthost, localhost, "FactoryReset", "Start", request_json)
    pytest_assert(ret == 0, f"FactoryReset.Start RPC failed: rc = {ret}, msg = {msg}")

    logging.info(f"FactoryReset.Start Response: {msg}")
    pytest_assert("ResetError" in msg, "Expected ResetError in response")
    pytest_assert("FactoryReset.Start" in msg, "Expected method FactoryReset.Start error")
    pytest_assert("unsupported" in msg, "Expected method unimplemented error")
