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


def test_disable_dshell_client(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `sudo config platform cisco sdk-debug disable"`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    result = duthost.command("sudo config platform cisco sdk-debug disable")
    logging.info(result)
    assert "dshell_client: stopped" in result["stdout"], "dshell_client is not stopped"

def test_enable_dshell_client(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `sudo config platform cisco sdk-debug enable"`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    result = duthost.command("sudo config platform cisco sdk-debug enable")
    logging.info(result)
    time.sleep(360)
    assert "dshell_client: started" in result["stdout"], "dshell_client not started"

def test_check_dshell_client_after_enable(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `docker exec -it syncd ps -efl "`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    result = duthost.command("docker exec -it syncd ps -efl")
    logging.info(result)
    assert "/usr/bin/dshell_client.py" in result["stdout"], "dshell_client is not running"


def test_show_platform_npu_lpts(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `show platform npu lpts`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    result = duthost.command("sudo show platform npu lpts")
    logging.info(result)
    traceback_found = "Traceback" in result["stdout"]
    assert not traceback_found, "Traceback found in show platform npu lpts output"
    assert result["stdout"], "No ouput for this CLI"

def test_show_platform_npu_counters(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `show platform npu counters`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    result = duthost.command("sudo show platform npu counters")
    logging.info(result)
    traceback_found = "Traceback" in result["stdout"]
    assert not traceback_found, "Traceback found in show platform npu counters output"
    assert result["stdout"], "No ouput for this CLI"

def test_show_platform_npu_ecmp(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `show platform npu ecmp`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    result = duthost.command("sudo show platform npu ecmp")
    logging.info(result)
    traceback_found = "Traceback" in result["stdout"]
    assert not traceback_found, "Traceback found in show platform npu ecmp output"
    assert result["stdout"], "No ouput for this CLI"

def test_show_platform_npu_event_trap(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `show platform npu event-trap`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    result = duthost.command("sudo show platform npu event-trap")
    logging.info(result)
    traceback_found = "Traceback" in result["stdout"]
    assert not traceback_found, "Traceback found in show platform npu event-trap"
    assert result["stdout"], "No ouput for this CLI"

def test_show_platform_npu_trap(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `show platform npu trap`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    result = duthost.command("sudo show platform npu trap")
    logging.info(result)
    traceback_found = "Traceback" in result["stdout"]
    assert not traceback_found, "Traceback found in show platform npu trap"
    assert result["stdout"], "No ouput for this CLI"
