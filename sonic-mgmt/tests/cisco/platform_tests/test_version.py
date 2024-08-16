"""
Tests for the `show platform version` command in SONiC
"""

import logging
import pytest
from tests.common.helpers.assertions import pytest_assert


pytestmark = [
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]

def test_show_platform_version(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `show platform version`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    result = duthost.command(f"dpkg -l")["stdout_lines"]
    for line in result:
        if 'Cisco Silicon One' in line and 'SDK' in line:
            dpkg_sdk_version = line.split()[2]
        if 'Cisco Silicon One validation' in line:
            dpkg_validation_version = line.split()[2]

    result = duthost.command(f"show platform version")["stdout_lines"]
    for line in result:
        if 'Silicon One SDK Version' in line:
            show_sdk_version = line.split()[6]
        if 'Silicon One SDK Validation Version' in line:
            show_validation_version = line.split()[7]

    assert show_sdk_version == dpkg_sdk_version
    if not duthost.is_supervisor_node():
        # Chassis Supervisor does not have validation pkg installed
        assert show_validation_version == dpkg_validation_version
