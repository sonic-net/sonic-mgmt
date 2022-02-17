#! /usr/bin/env python

import pytest
import sys

sys.path.append("./configlet/util")

from base_test import do_test_add_rack, backup_minigraph, restore_orig_minigraph
from helpers import log_info

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



def test_add_rack(configure_dut, tbinfo, duthosts, rand_one_dut_hostname):
    global data_dir, orig_db_dir, clet_db_dir, files_dir

    duthost = duthosts[rand_one_dut_hostname]

    log_info("sys.version={}".format(sys.version))
    do_test_add_rack(duthost, is_storage_backend = 'backend' in tbinfo['topo']['name'],
            hack_apply=True)

