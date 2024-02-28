import logging
import pytest

from tests.common.utilities import wait_until, check_skip_release
from tests.common.helpers.assertions import pytest_assert


pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('physical'),
]

SUPPORTED_HWSKUS = [
        "Nokia-7215",
        "Force10-S6100",
        "Mellanox-SN2700-D40C8S8",
        "Mellanox-SN2700-A1-D40C8S8",
        "Arista-7060CX-32S-D48C8",
        "Arista-7260CX3-D108C8",
        "Arista-7050QX32S-Q32",
        "Arista-7050-QX-32S",
        "Arista-7050CX3-32S-C32"
        ]


def test_var_log_tmpfs(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Check DUT /var/log partition and verify that it is mounted as tmpfs
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    var_log = "/var/log"
    tmpfs = "tmpfs"


    # Skip this test for 201811, 201911 images for all platforms:
    (skip, reason) = check_skip_release(duthost, ["201811", "201911", "master"])

    # Skip this test if OS version is < 202012 for all platforms OR Image version >= 202012 and HWSKU of DUT isn't one of the supported HWSKUs
    if skip is True or (skip is False and duthost.facts['hwsku'] not in SUPPORTED_HWSKUS):
        if reason: pytest.skip(reason)
        else: pytest.skip("Skip test 'is /var/log on tmpfs' for {} running image {}".format(duthost.facts['hwsku'], duthost.os_version))

    # Get '/var/log' mountpoint information from the DUT
    partition = duthost.get_mountpoint(mountpoint=var_log)['mountpoint_results']


    assert partition['mountpoint'] == var_log, "Expected mountpoint: {}, received mountpoint: {}".format(var_log, partition['mountpoint'])
    assert partition['fstype'] == tmpfs, "Expected fstype: {}, received fstype: {}".format(tmpfs, partition['fstype'])

