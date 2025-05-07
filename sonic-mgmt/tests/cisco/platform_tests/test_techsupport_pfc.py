"""
Tests for the `show platform npu techsupport --pfc` command in SONiC
"""
import time
import logging
import re
import pytest
from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]


def test_show_platform_npu_techsupport_pfc(duthosts):
    """
    @summary: Verify output of `show platform npu techsupport --pfc`
    """
    for duthost in duthosts:
        platform_npu_help = duthost.command("sudo show platform npu techsupport -h")
        if "pfc" not in (platform_npu_help["stdout"] + platform_npu_help["stderr"]):
            pytest.skip("Not supported in this image")
        logger.info(f"techsupport --pfc for {duthost}")
        result = duthost.command("sudo show platform npu techsupport --pfc")
        output = result["stdout"] + result["stderr"]
        if "Traceback" in output:
            pytest.fail("Unexpected traceback in command output")
        pattern = "/var/dump/sonic_npu_dump_[a-zA-Z0-9_-]+_(?P<date_time>\d+_\d+)\.tar\.gz"
        m = re.search(pattern, output)
        if not m:
            pytest.fail("Missing pfc dump in /var/dump") 
