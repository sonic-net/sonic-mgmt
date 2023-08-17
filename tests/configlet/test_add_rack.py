#! /usr/bin/env python

import pytest
import sys

from tests.configlet.util.base_test import restore_orig_minigraph, backup_minigraph, do_test_add_rack
from tests.configlet.util.helpers import log_info

sys.path.append("./configlet/util")

pytestmark = [
        pytest.mark.topology("t1")
        ]

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


@pytest.mark.disable_loganalyzer
def test_add_rack(configure_dut, tbinfo, duthosts, rand_one_dut_hostname):
    global data_dir, orig_db_dir, clet_db_dir, files_dir

    duthost = duthosts[rand_one_dut_hostname]

    log_info("sys.version={}".format(sys.version))
    do_test_add_rack(duthost, is_storage_backend = 'backend' in tbinfo['topo']['name'],
            hack_apply=True)

