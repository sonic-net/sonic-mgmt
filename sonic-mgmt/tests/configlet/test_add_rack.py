#! /usr/bin/env python

import pytest
import sys
from tests.common.utilities import skip_release

sys.path.append("./configlet/util")

from base_test import do_test_add_rack, backup_minigraph, restore_orig_minigraph
from helpers import log_info

pytestmark = [
        pytest.mark.topology("t1")
        ]


@pytest.fixture(scope="module", autouse=True)
def check_image_version(duthost):
    """Skips this test if the SONiC image installed on DUT is older than 202111

    Args:
        duthost: DUT host object.

    Returns:
        None.
    """
    skip_release(duthost, ["201811", "201911", "202012", "202106", "202111"])


@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exceptions(duthost, loganalyzer):
    """
       Ignore expected errors in logs during test execution

       Args:
           loganalyzer: Loganalyzer utility fixture
           duthost: DUT host object
    """
    if loganalyzer:
         loganalyzer_ignore_regex = [
             ".*ERR sonic_yang: Data Loading Failed:Must condition not satisfied.*",
             ".*ERR sonic_yang: Failed to validate data tree#012.*",
             ".*ERR config: Change Applier:.*",
         ]
         loganalyzer[duthost.hostname].ignore_regex.extend(loganalyzer_ignore_regex)

    yield


@pytest.fixture(scope="module")
def configure_dut(duthosts, rand_one_dut_hostname):
    try:
        log_info("configure_dut fixture on setup for {}".format(rand_one_dut_hostname))
        if not restore_orig_minigraph(duthosts[rand_one_dut_hostname]):
            backup_minigraph(duthosts[rand_one_dut_hostname])
        log_info("configure_dut fixture DONE for {}".format(rand_one_dut_hostname))
        yield
    finally:
        log_info("configure_dut fixture on cleanup for {}".format(rand_one_dut_hostname))
        restore_orig_minigraph(duthosts[rand_one_dut_hostname])
        log_info("configure_dut fixture DONE for {}".format(rand_one_dut_hostname))



def test_add_rack(configure_dut, tbinfo, duthosts, rand_one_dut_hostname):
    global data_dir, orig_db_dir, clet_db_dir, files_dir

    duthost = duthosts[rand_one_dut_hostname]

    log_info("sys.version={}".format(sys.version))
    do_test_add_rack(duthost, is_storage_backend = 'backend' in tbinfo['topo']['name'])

