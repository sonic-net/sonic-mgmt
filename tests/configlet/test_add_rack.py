#! /usr/bin/env python

import argparse
import json
import os
import sys
import time

import pytest
from tests.common.config_reload import config_reload
from tests.common.utilities import wait_until

sys.path.append("./configlet/util")

from helpers import *
import files_create
from common import *

pytestmark = [
        pytest.mark.topology("t1")
        ]

ORIG_DB_SUB_DIR = "orig"
CLET_DB_SUB_DIR = "clet"
FILES_SUB_DIR = "files"

data_dir    = "logs/AddRack"
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

    for i in [ data_dir, orig_db_dir, clet_db_dir, files_dir ]:
        os.mkdir(i)

    init_data["files_dir"] = files_dir 
    init_data["data_dir"] = os.path.join(data_dir, duthost_name)
    init_data["switch_name"] = duthost_name

    duthost.fetch(src="/etc/sonic/sonic_version.yml", dest=data_dir)
    local_file = "{}/{}/etc/sonic/sonic_version.yml".format(
            data_dir, duthost_name)
    with open(local_file, "r") as s:
        d = yaml.safe_load(s)
        init_data["version"] = d["build_version"]

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



def load_minigraph(duthost):
    config_reload(duthost, config_source="minigraph", wait=180, start_bgp=True) 
    assert wait_until(300, 20, duthost.critical_services_fully_started), \
            "All critical services should fully started!{}".format(duthost.critical_services)


def apply_clet(duthost):
    mini_wo_to = managed_files["minigraph_wo_to"]
    clet_file = managed_files["configlet"]
    sonic_clet_file = "/etc/sonic/add_Rack.json"

    if not mini_wo_to or not clet_file:
        report_error("Failed to get files wo_to={} clet={}".format(
            mini_wo_to, clet_file))

    if not os.path.exists(mini_wo_to):
        report_error("minigraph {} file absent".format(mini_wo_to))

    if not os.path.exists(clet_file):
        report_error("configlet {} file absent".format(clet_file))

    duthost.copy(src=mini_wo_to, dest="/etc/sonic/minigraph.xml")
    duthost.copy(src=clet_file, dest=sonic_clet_file)

    load_minigraph(duthost)

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

def chk_bgp_session(duthost, ip):
    info = duthost.get_bgp_neighbor_info(ip.decode('utf-8'))
    bgp_state = info.get("bgpState", "")
    assert bgp_state == "Established", \
            "BGP session for {} = {} not established".format(bgp_state, ip)


def test_add_rack(configure_dut, duthosts, rand_one_dut_hostname):
    global data_dir, orig_db_dir, clet_db_dir, files_dir

    duthost = duthosts[rand_one_dut_hostname]
    duthost_name = rand_one_dut_hostname

    init(duthost, duthost_name)

    # Loads original minigraph with all T0s & get dumps
    load_minigraph(duthost)
    log_info("config reloaded; Taking dumps ...")
    take_DB_dumps(duthost, duthost_name, orig_db_dir, data_dir)


    # Download sonic files required to generate minigraph w/o a T0
    # and configlet. 
    download_sonic_files(duthost, files_dir)

    # Create minigraph w/o a T0 & configlet, apply & take dump
    files_create.do_run()
    apply_clet(duthost)
    take_DB_dumps(duthost, duthost_name, clet_db_dir, data_dir)

    ret = compare_dumps(orig_db_dir, clet_db_dir)
    assert not ret, "Failed to compare dumps"

    # Ensure BGP session is up
    chk_bgp_session(duthost, tor_data["ip"]["remote"])
    chk_bgp_session(duthost, tor_data["ipv6"]["remote"])

    log_info("Test run is good!")



def __test_db_dump(duthosts, rand_one_dut_hostname):
    global duthost

    log_info("Dump in {}".format(rand_one_dut_hostname))
    duthost = duthosts[rand_one_dut_hostname]

    dbs = [[0, "appdb"], [1, "asicdb"], [2, "counterdb"], [4, "configdb"]]
    for db in dbs:
        duthost.shell("redis-dump -d {} --pretty -o /tmp/{}.json".format(db[0], db[1]))
        duthost.fetch(src="/tmp/{}.json".format(db[1]), dest="logs/{}.json".format(db[1]))
        log_info("Dumped DB {} {}".format(db[0], db[1]))

    log_info("Succeeded")


def __test_copy_files(duthosts, rand_one_dut_hostname):
    log_info("copy files {}".format(rand_one_dut_hostname))
    
    duthost = duthosts[rand_one_dut_hostname]
    log_info("type(duthost)={}".format(type(duthost)))

    # duthost.fetch(src="/etc/sonic/minigraph.xml", dest="logs/test_xml")
    d = ""
    with open("logs/test_xml/{}/etc/sonic/minigraph.xml".format(rand_one_dut_hostname), "r") as s:
        d = s.read()

    d = "# hello\n" + d
    with open("logs/test_upd.xml", "w") as s:
        s.write(d)

    duthost.copy(src="logs/test_upd.xml", dest="/etc/sonic/minigraph.xml")

    log_info("Succeeded")


def __test_chk_copy(duthosts, rand_one_dut_hostname):
    log_info("test_chk_copy")

    duthost = duthosts[rand_one_dut_hostname]

    res = duthost.shell("ls -l /etc/sonic/orig/minigraph.xml.addRack.orig", module_ignore_errors=True)["stdout"]

    log_info("res={}".format(res))
    
    if not res:
        duthost.shell("mkdir -p /etc/sonic/orig")
        log_info("created orig dir")
    else:
        log_info("None created")


def __test_code(duthosts, rand_one_dut_hostname):
    log_info("test in {}".format(rand_one_dut_hostname))


