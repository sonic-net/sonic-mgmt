import pytest
import logging
import random
import json
import os

pytestmark = [
    pytest.mark.disable_loganalyzer,
]

def send_and_verify_command(duthost, cmd: str, expect: str = None):
    """Send command via duthost and verify result"""
    result = duthost.shell(cmd, module_ignore_errors=True)
    if expect:
        assert expect in result['stdout'], f"Expected '{expect}' in response, got: {result['stdout']}"
    return result['stdout']

def inval_test(duthost, error_port, errorinfo="Error"):
    """Test invalid port pair configuration
    Args:
        duthost: DUT host object
        error_port: Invalid port pair string to test
        errorinfo: Expected error message in response
    """
    invalid_pair = error_port
    send_and_verify_command(duthost, f'config ocs cross-connect add {invalid_pair} update', expect=errorinfo)

def test_configure_ocs_cross_invalid(duthost):
    """Verify OCS cross-connect configuration rejects invalid port pairs
    Valid format: [1-64]a-[1-64]b (e.g. 1a-1b)
    All other formats should be rejected
    """
    # Test case 1: Invalid port pair formats
    logging.info('Step 1: Invalid port-pair format')
    inval_test(duthost, "1b-1a", errorinfo="Invalid")  # Wrong suffix order
    inval_test(duthost, "1-1", errorinfo="Invalid")    # Missing suffix
    inval_test(duthost, "1-10001", errorinfo="Invalid")  # Port out of range
    inval_test(duthost, "1-b1", errorinfo="Invalid")   # Wrong suffix position
    inval_test(duthost, "1-1001", errorinfo="Invalid")  # Port out of range
    inval_test(duthost, "a1-1b", errorinfo="Invalid")  # Wrong prefix position

    # Test case 2: Port number out of valid range (1-64)
    logging.info('Step 2: Port number out of range (1-64)')
    inval_test(duthost, "0a-1b")    # Port 0 is invalid
    inval_test(duthost, "1a-0b")    # Port 0 is invalid
    inval_test(duthost, "1a-65b")   # Port 65 is invalid
    inval_test(duthost, "65a-1b")   # Port 65 is invalid

    # Test case 3: Invalid characters in port pair
    logging.info('Step 3: Invalid characters in port pair')
    inval_test(duthost, "1a+1b", errorinfo="Invalid")  # Invalid separator
    inval_test(duthost, "1c-1b", errorinfo="Invalid")  # Invalid suffix (only a/b allowed)
    inval_test(duthost, "1a 1b")    # Space instead of hyphen