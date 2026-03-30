import json
import os
import pytest
import logging
import time

from tests.common.helpers.assertions import pytest_assert
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]


def is_hardware_mode_enabled(duthost):
    """
    Check if hardware-based PFC watchdog is enabled on the DUT

    Args:
        duthost (AnsibleHost): instance

    Returns:
        bool: True if hardware mode is enabled, False otherwise
    """
    cmd = "redis-cli -n 6 HGET 'PFC_WD_STATE_TABLE|PFC_WD' 'RECOVERY_MECHANISM'"
    result = duthost.shell(cmd, module_ignore_errors=True)
    
    if result['rc'] != 0:
        return False
    
    recovery_mechanism = result['stdout'].strip().strip('"')
    return recovery_mechanism.upper() == 'HARDWARE'


def get_hardware_timer_limits(duthost):
    """
    Get hardware watchdog timer limits from STATE_DB

    Args:
        duthost (AnsibleHost): instance

    Returns:
        dict: Dictionary with detection and restoration time limits, or None if not available
    """
    cmd = "redis-cli -n 6 HGETALL 'PFC_WD_STATE_TABLE|PFC_WD'"
    result = duthost.shell(cmd, module_ignore_errors=True)
    
    if result['rc'] != 0:
        return None
    
    lines = result['stdout'].strip().split('\n')
    state_data = {}
    for i in range(0, len(lines), 2):
        if i + 1 < len(lines):
            key = lines[i].strip().strip('"')
            value = lines[i + 1].strip().strip('"')
            state_data[key] = value
    
    if state_data.get('RECOVERY_MECHANISM', '').upper() != 'HARDWARE':
        return None
    
    try:
        return {
            'detection_min': int(state_data.get('DETECTION_TIME_MIN', 0)),
            'detection_max': int(state_data.get('DETECTION_TIME_MAX', 0)),
            'restoration_min': int(state_data.get('RESTORATION_TIME_MIN', 0)),
            'restoration_max': int(state_data.get('RESTORATION_TIME_MAX', 0)),
        }
    except (ValueError, KeyError):
        return None


@pytest.fixture(scope='function', autouse=True)
def stop_pfcwd(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """
    Fixture that stops PFC Watchdog before each test run

    Args:
        duthost: instance of AnsibleHost class

    Returns:
        None
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    logger.info("--- Stop Pfcwd --")
    duthost.command("pfcwd stop")

    yield

    logger.info("--- Start Pfcwd--")
    duthost.command("pfcwd start_default")


class TestPfcHardwareConfig(object):
    """
    Test case definition for hardware-based PFC watchdog configuration
    """
    
    def test_hardware_mode_detection(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """
        Tests if hardware mode is properly detected and configured in STATE_DB

        Args:
            duthost(AnsibleHost): instance

        Returns:
            None
        """
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        
        if not is_hardware_mode_enabled(duthost):
            pytest.skip("Hardware mode is not enabled on this platform")
        
        logger.info("Hardware mode is enabled, verifying STATE_DB entries")
        
        # Verify RECOVERY_MECHANISM is set to HARDWARE
        cmd = "redis-cli -n 6 HGET 'PFC_WD_STATE_TABLE|PFC_WD' 'RECOVERY_MECHANISM'"
        result = duthost.shell(cmd)
        recovery_mechanism = result['stdout'].strip().strip('"')
        pytest_assert(recovery_mechanism.upper() == 'HARDWARE',
                     "RECOVERY_MECHANISM should be HARDWARE, got: {}".format(recovery_mechanism))
        
        logger.info("Hardware mode properly configured in STATE_DB")
    
    def test_hardware_timer_limits(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """
        Tests if hardware timer limits are properly set in STATE_DB

        Args:
            duthost(AnsibleHost): instance

        Returns:
            None
        """
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        
        if not is_hardware_mode_enabled(duthost):
            pytest.skip("Hardware mode is not enabled on this platform")
        
        limits = get_hardware_timer_limits(duthost)
        pytest_assert(limits is not None, "Failed to retrieve hardware timer limits from STATE_DB")
        
        logger.info("Hardware timer limits: {}".format(limits))

