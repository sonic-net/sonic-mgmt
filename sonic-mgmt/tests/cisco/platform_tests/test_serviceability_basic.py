"""
Tests for the `show platform npu...` commands in SONiC
"""
import time
import logging
import pytest
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]

def get_asic_str(duthost):
    if duthost.is_multi_asic:
        return " -n asic0"
    else:
        return ""

def test_disable_dshell_client(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `sudo config platform cisco sdk-debug disable"`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    result = duthost.shell("ps -efl", module_ignore_errors=True)['stdout']
    if "/usr/bin/dshell_client.py" not in result:
        # dshell_client is not running. enable it
        result = duthost.shell("sudo config platform cisco sdk-debug enable", module_ignore_errors=True)['stdout']
        logging.info(result)
        time.sleep(360)
        assert "dshell_client: started" in result, "dshell_client not started"
        result = duthost.shell("ps -efl", module_ignore_errors=True)['stdout']
        assert "/usr/bin/dshell_client.py" in result, "dshell_client is not running"
   
    result = duthost.shell("sudo config platform cisco sdk-debug disable", module_ignore_errors=True)['stdout']
    logging.info(result)
    assert "sdk-debug has been disabled" in result, "dshell_client is not stopped"
    time.sleep(10)
    result = duthost.shell("ps -efl", module_ignore_errors=True)['stdout']
    assert "/usr/bin/dshell_client.py" not in result, "dshell_client is still running"

def test_enable_dshell_client(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `sudo config platform cisco sdk-debug enable"`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    result = duthost.shell("sudo config platform cisco sdk-debug enable", module_ignore_errors=True)['stdout']
    logging.info(result)
    time.sleep(360)
    assert "dshell_client: started" in result, "dshell_client not started"

def test_check_dshell_client_after_enable(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `"ps -efl "`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    result = duthost.shell("ps -efl", module_ignore_errors=True)['stdout']
    logging.info(result)
    assert "/usr/bin/dshell_client.py" in result, "dshell_client is not running"


def test_show_platform_npu_lpts(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `show platform npu lpts`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    result = duthost.shell(f"sudo show platform npu lpts {get_asic_str(duthost)}", module_ignore_errors=True)['stdout']
    logging.info(result)
    traceback_found = "Traceback" in result
    assert not traceback_found, "Traceback found in show platform npu lpts output"
    assert result, "No ouput for this CLI"

def test_show_platform_npu_counters(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `show platform npu counters`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    result = duthost.shell(f"sudo show platform npu counters {get_asic_str(duthost)}", module_ignore_errors=True)['stdout']
    logging.info(result)
    traceback_found = "Traceback" in result
    assert not traceback_found, "Traceback found in show platform npu counters output"
    assert result, "No ouput for this CLI"

def test_show_platform_npu_ecmp(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `show platform npu ecmp`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    result = duthost.shell(f"sudo show platform npu ecmp {get_asic_str(duthost)}", module_ignore_errors=True)['stdout']
    logging.info(result)
    traceback_found = "Traceback" in result
    assert not traceback_found, "Traceback found in show platform npu ecmp output"
    assert result, "No ouput for this CLI"

def test_show_platform_npu_event_trap(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `show platform npu event-trap`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    result = duthost.shell(f"sudo show platform npu event-trap {get_asic_str(duthost)}", module_ignore_errors=True)['stdout']
    logging.info(result)
    traceback_found = "Traceback" in result
    assert not traceback_found, "Traceback found in show platform npu event-trap"
    assert result, "No ouput for this CLI"

def test_show_platform_npu_trap(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `show platform npu trap`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    result = duthost.shell(f"sudo show platform npu trap {get_asic_str(duthost)}", module_ignore_errors=True)['stdout']
    logging.info(result)
    traceback_found = "Traceback" in result
    assert not traceback_found, "Traceback found in show platform npu trap"
    assert result, "No ouput for this CLI"
