import logging
import pytest

from tests.common.utilities import wait_until, check_skip_release
from tests.common.helpers.assertions import pytest_assert
from tests.common.platform.device_utils import LOGS_ON_TMPFS_PLATFORMS

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('physical'),
]

def is_logs_tmpfs_platform(duthost):
    platform = duthost.facts["platform"]
    if platform not in LOGS_ON_TMPFS_PLATFORMS:
        pytest.skip('skipped on this platform: {} - logs are not intended to be on tmpfs.'.format(platform))

def test_var_log_tmpfs(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Check /var/log partition and verify that it is mounted as tmpfs on supported platforms
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    var_log = "/var/log"
    tmpfs = "tmpfs"

    # Skip this test for master, 201811 and 201911 images for all platforms:
    (skip, reason) = check_skip_release(duthost, ["201811", "201911", "master"])
    if skip is True:
        pytest.skip("Skip test 'is /var/log on tmpfs' for {} running image {} due to reason: {}".format(duthost.facts['platform'], duthost.os_version, reason))

    # Skip this test for platforms where logs are not tmpfs
    is_logs_tmpfs_platform(duthost)

    # Get '/var/log' mountpoint information from the DUT
    partition = duthost.get_mountpoint(mountpoint=var_log)['mountpoint_results']

    assert partition['mountpoint'] == var_log, "Expected mountpoint: {}, received mountpoint: {}".format(var_log, partition['mountpoint'])
    assert partition['fstype'] == tmpfs, "Expected fstype: {}, received fstype: {}".format(tmpfs, partition['fstype'])

