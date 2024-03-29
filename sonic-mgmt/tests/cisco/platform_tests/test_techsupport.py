"""
Tests for the `show techsupport ...` commands in SONiC
"""
import time
import logging
import re
import pytest
from tests.common.helpers.assertions import pytest_assert


pytestmark = [
    pytest.mark.topology('any')
]


def test_show_platform_npu_techsupport(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `show platform npu techsupport`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    platform_npu_help = duthost.command("sudo show platform npu -h")
    if "techsupport" not in platform_npu_help["stdout"]:
        pytest.skip("Not supported in this image")
    result = duthost.command("sudo show platform npu techsupport")
    logging.info(result)
    traceback_found = "Traceback" in result["stdout"]
    assert not traceback_found, "Traceback found in show platform npu techsupport"
    assert result["stdout"], "No ouput for this CLI"
    pattern = "/var/dump/sonic_npu_dump_[a-zA-Z0-9_-]+_(?P<date_time>\d+_\d+)\.tar\.gz"
    m = re.search(pattern, result["stdout"])
    assert m, f"No npu techsupport dump archive matching {pattern} created"
    if m:
        date_time = m.groupdict()['date_time']
        assert f"_{date_time}/generate_npu_dump" in result["stdout"]
        assert f"_{date_time}/dump/platform.npu." in result["stdout"]
        assert "Cleaning up working directory" in result["stdout"]


def test_show_techsupport_npu(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `show techsupport npu`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    platform_npu_help = duthost.command("sudo show techsupport -h")
    if "npu" not in platform_npu_help["stdout"]:
        pytest.skip("Not supported in this image")
    result = duthost.command("sudo show techsupport npu")
    logging.info(result)
    traceback_found = "Traceback" in result["stdout"]
    assert not traceback_found, "Traceback found in show techsupport npu"
    assert result["stdout"], "No ouput for this CLI"
    pattern = "/var/dump/sonic_npu_dump_[a-zA-Z0-9_-]+_(?P<date_time>\d+_\d+)\.tar\.gz"
    m = re.search(pattern, result["stdout"])
    assert m, f"No npu techsupport dump archive matching {pattern} created"
    if m:
        date_time = m.groupdict()['date_time']
        assert f"_{date_time}/generate_npu_dump" in result["stdout"]
        assert f"_{date_time}/dump/platform.npu." in result["stdout"]
        assert "Cleaning up working directory" in result["stdout"]
