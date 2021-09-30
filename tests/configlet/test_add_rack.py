#! /usr/bin/env python

import argparse
import json
import os
import sys
import time
import yaml

import pytest
from tests.common.config_reload import config_reload
from tests.common.utilities import wait_until

sys.path.append("./configlet/util")

from helpers import *
import files_create
from common import *

# Test Description:
# configlet is a generic tool that can patch any entry in CONFIG-DB.
# AddRack is one of the scenarios that uses configlet
#
# AddRack:
#   This is part of building of a new cluster with a T0. 
#   Using AddRack-configlet, this new T0 could be added to a T1
#   This includes the following
#
#   Use CLI to ensure that this port is marked as down
#
#   a) Adds a new Device Neighbor
#   b) Adds a new Portchannel for this port
#   c) Appends to ACL_TABLE for Everflow
#   d) Adds other port related entries 
#       CABLE_LENGTH, QUEUE, BUGGER_PG, BUFFER_QUEUE, BUFFER_PG,
#       BUFFER_PORT_INGRESS_PROFILE_LIST & BUFFER_PORT_EGRESS_PROFILE_LIST, if 
#       Mellanox, PORT_QOS_MAP, PFC_WD
#   e) Add a new BGP Neighbor
#   
#   Use CLI to set this port up
# 
# How this test works ?
#   a) Load the current/original minigraph for this device, which has all T0s
#      per its topology
#   b) Take a dump of CONFIG-DB, APP-DB & ASIC-DB
#   c) Generate a new minigraph, by removing a T0 from the original minigraph
#   d) Load the new minigraph
#   e) Generate the configlet for this removed T0
#   f) Apply this configlet
#   g) Get dump of CONFIG-DB, APP-DB & ASIC-DB
#   h) Verify the following
#       a) BGP is up for this new neighbor
#       b) Compare the DB dumps with the dumps taken with original minigraph
#

pytestmark = [
        pytest.mark.topology("t1")
        ]

ORIG_DB_SUB_DIR = "orig"
CLET_DB_SUB_DIR = "clet"
FILES_SUB_DIR = "files"

base_dir    = "logs/configlet"
data_dir    = "{}/AddRack".format(base_dir)
orig_db_dir = "{}/{}".format(data_dir, ORIG_DB_SUB_DIR)
clet_db_dir = "{}/{}".format(data_dir, CLET_DB_SUB_DIR)
files_dir   = "{}/{}".format(data_dir, FILES_SUB_DIR)

def MINS_TO_SECS(n):
    return n * 60


def do_pause(secs, msg):
    log_info("do_pause: seconds:{} {}".format(secs, msg))
    time.sleep(secs)
    log_info("do_pause: DONE")


def init(duthost, duthost_name):
    global init_data

    if not os.path.exists(base_dir):
        os.mkdir(base_dir)

    for i in [ data_dir, orig_db_dir, clet_db_dir, files_dir ]:
        os.mkdir(i)

    init_data["files_dir"] = files_dir 
    init_data["data_dir"] = data_dir
    init_data["switch_name"] = duthost_name

    init_data["version"] = duthost.os_version
    log_debug("Created data_dir={} version={}".format(data_dir, init_data["version"]))


def backup_minigraph(duthost):
    ret = duthost.stat(path="/etc/sonic/orig/minigraph.xml.addRack.orig")
    if not ret["stat"]["exists"]:
        log_info("Backing up minigraph.xml")
        duthost.shell("mkdir -p /etc/sonic/orig")
        duthost.shell("cp /etc/sonic/minigraph.xml /etc/sonic/orig/minigraph.xml.addRack.orig")
        duthost.shell("chmod a-w /etc/sonic/orig/minigraph.xml.addRack.orig")
        return True
    else:
        log_info("Already backed up")
        return False


def restore_orig_minigraph(duthost):
    ret = duthost.stat(path="/etc/sonic/orig/minigraph.xml.addRack.orig")
    if ret["stat"]["exists"]:
        duthost.shell("cp /etc/sonic/orig/minigraph.xml.addRack.orig /etc/sonic/minigraph.xml")
        duthost.shell("chmod u+w /etc/sonic/minigraph.xml")
        # Reload original minigraph
        load_minigraph(duthost, duthost.hostname)
        log_info("restored minigraph")
        return True
    else:
        log_info("No minigraph file to restore from")
        return False


@pytest.fixture(scope="module")
def configure_dut(duthosts, rand_one_dut_hostname):
    try:
        log_info("configure_dut fixture on setup for {}".format(rand_one_dut_hostname))
        if not restore_orig_minigraph(duthosts[rand_one_dut_hostname]):
            backup_minigraph(duthosts[rand_one_dut_hostname])
        log_info("configure_dut fixture DONE for {}".format(rand_one_dut_hostname))
        yield 0
    finally:
        log_info("configure_dut fixture on cleanup for {}".format(rand_one_dut_hostname))
        restore_orig_minigraph(duthosts[rand_one_dut_hostname])
        log_info("configure_dut fixture DONE for {}".format(rand_one_dut_hostname))



def load_minigraph(duthost, duthost_name):
    config_reload(duthost, config_source="minigraph", wait=180, start_bgp=True) 
    assert wait_until(300, 20, duthost.critical_services_fully_started), \
            "All critical services should fully started!{}".format(duthost.critical_services)


def apply_clet(duthost, duthost_name):
    mini_wo_to = managed_files["minigraph_wo_to"]
    clet_file = managed_files["configlet"]
    sonic_clet_file = "/etc/sonic/add_Rack.json"

    del_clet_file = os.path.join(os.path.dirname(
        os.path.abspath(__file__)), "everlow_delete.json")
    del_sonic_clet_file = "/etc/sonic/everlow_delete.json"

    if not mini_wo_to or not clet_file:
        report_error("Failed to get files wo_to={} clet={}".format(
            mini_wo_to, clet_file))

    if not os.path.exists(mini_wo_to):
        report_error("minigraph {} file absent".format(mini_wo_to))

    if not os.path.exists(clet_file):
        report_error("configlet {} file absent".format(clet_file))

    duthost.copy(src=mini_wo_to, dest="/etc/sonic/minigraph.xml")
    duthost.copy(src=clet_file, dest=sonic_clet_file)
    duthost.copy(src=del_clet_file, dest=del_sonic_clet_file)

    load_minigraph(duthost, duthost_name)

    # Apply delete 
    duthost.shell("sudo configlet -d -j {}".format(del_sonic_clet_file))

    tor_ifname = tor_data["links"][0]["local"]["sonic_name"]
    duthost.shell("sudo config interface shutdown {}".format(tor_ifname))
    do_pause(MINS_TO_SECS(1), "pause upon i/f {} shutdown".format(tor_ifname))

    duthost.shell("sudo configlet -u -j {}".format(sonic_clet_file))
    do_pause(MINS_TO_SECS(3), "Pause after applying configlet")

    duthost.shell("sudo config interface startup {}".format(tor_ifname))
    do_pause(MINS_TO_SECS(1), "pause upon i/f {} startup".format(tor_ifname))


def download_sonic_files(duthost, dir):
    for f in [ "minigraph.xml", "config_db.json" ]:
        duthost.fetch(src="/etc/sonic/{}".format(f), dest=data_dir)

def chk_bgp_session(duthost, ip, msg):
    info = duthost.get_bgp_neighbor_info(ip.decode('utf-8'))
    bgp_state = info.get("bgpState", "")
    assert bgp_state == "Established", \
            "{}: BGP session for {} = {}; expect established".format(msg, ip, bgp_state)


def test_add_rack(configure_dut, tbinfo, duthosts, rand_one_dut_hostname):
    global data_dir, orig_db_dir, clet_db_dir, files_dir

    duthost = duthosts[rand_one_dut_hostname]
    duthost_name = rand_one_dut_hostname

    init(duthost, duthost_name)

    # Loads original minigraph with all T0s & get dumps
    load_minigraph(duthost, rand_one_dut_hostname)
    log_info("config reloaded; Taking dumps ...")
    take_DB_dumps(duthost, duthost_name, orig_db_dir, data_dir)

    # Download sonic files required to generate minigraph w/o a T0
    # and configlet. 
    download_sonic_files(duthost, files_dir)

    # Create minigraph w/o a T0 & configlet, apply & take dump
    files_create.do_run(is_mlnx = duthost.facts["asic_type"] == "mellanox",
            is_storage_backend = 'backend' in tbinfo['topo']['name'])

    # Ensure BGP session is up before we apply stripped minigraph
    chk_bgp_session(duthost, tor_data["ip"]["remote"], "pre-clet test")
    chk_bgp_session(duthost, tor_data["ipv6"]["remote"].lower(), "pre-clet test")

    apply_clet(duthost, rand_one_dut_hostname)
    take_DB_dumps(duthost, duthost_name, clet_db_dir, data_dir)

    ret, msg = compare_dumps(orig_db_dir, clet_db_dir)
    assert not ret, "Failed to compare: " + msg

    # Ensure BGP session is up
    chk_bgp_session(duthost, tor_data["ip"]["remote"], "post-clet test")
    chk_bgp_session(duthost, tor_data["ipv6"]["remote"].lower(), "post-clet test")

    log_info("Test run is good!")

