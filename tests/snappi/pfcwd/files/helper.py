from tests.common.helpers.assertions import pytest_require
from tests.common.broadcom_data import is_broadcom_device

def skip_pfcwd_test(duthost, trigger_pfcwd):
    """
    Skip PFC watchdog tests that may cause fake alerts

    PFC watchdog on Broadcom devices use some approximation techniques to detect
    PFC storms, which may cause some fake alerts. Therefore, we skip test cases
    whose trigger_pfcwd is False for Broadcom devices.

    Args:
        duthost (obj): device to test
        trigger_pfcwd (bool): if PFC watchdog is supposed to trigger

    Returns:
        N/A
    """
    pytest_require(trigger_pfcwd is True or is_broadcom_device(duthost) is False,
                   'Skip trigger_pfcwd=False test cases for Broadcom devices')
