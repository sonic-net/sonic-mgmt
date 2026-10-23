"""
Helper functions for PDDF platform tests.

This module provides common utilities for testing PDDF (Platform Driver Development Framework)
functionality across different test cases.
"""

import json
import logging
import pytest

logger = logging.getLogger(__name__)

PDDF_DEVICE_JSON_PATH = "/usr/share/sonic/platform/pddf/pddf-device.json"


def check_pddf_device_json_exists(duthost, skip_if_missing=True):
    """
    Check if pddf-device.json file exists on the DUT.

    Args:
        duthost: DUT host object
        skip_if_missing: If True, skip the test when file doesn't exist.
                        If False, return False when file doesn't exist.

    Returns:
        bool: True if file exists, False otherwise (only when skip_if_missing=False)

    Raises:
        pytest.skip: When file doesn't exist and skip_if_missing=True
    """
    logger.info("Checking if {} exists on DUT".format(PDDF_DEVICE_JSON_PATH))
    try:
        file_check = duthost.command("[ -f {} ]".format(PDDF_DEVICE_JSON_PATH), module_ignore_errors=True)
        if file_check['rc'] != 0:
            if skip_if_missing:
                pytest.skip("PDDF device JSON file {} does not exist, skipping test".format(PDDF_DEVICE_JSON_PATH))
            return False
    except Exception as e:
        if skip_if_missing:
            pytest.skip("PDDF device JSON file {} does not exist, skipping test: {}".format(
                PDDF_DEVICE_JSON_PATH, str(e)))
        return False

    return True


def read_pddf_device_json(duthost):
    """
    Read and parse the pddf-device.json file from the DUT.

    Args:
        duthost: DUT host object

    Returns:
        dict: Parsed JSON data from pddf-device.json

    Raises:
        pytest.fail: When file cannot be read or parsed
    """
    logger.info("Reading {} from DUT".format(PDDF_DEVICE_JSON_PATH))
    try:
        cat_output = duthost.command("cat {}".format(PDDF_DEVICE_JSON_PATH))
        pddf_device_data = json.loads(cat_output['stdout'])
        return pddf_device_data
    except Exception as e:
        pytest.fail("Failed to read or parse {}: {}".format(PDDF_DEVICE_JSON_PATH, str(e)))
