#! /usr/bin/env python

import argparse
import json
import jsonpatch
import os
import sys
import time
import yaml

from helpers import *
from common import *
import strip
import configlet

if os.path.exists("/etc/sonic/sonic-environment"):
    from mock_for_switch import config_reload, wait_until
else:
    from tests.common.config_reload import config_reload
    from tests.common.utilities import wait_until


# Test Description:
# configlet is a generic tool that can patch any entry in CONFIG-DB.
# AddRack is one of the scenarios that uses configlet
#
# AddRack:
#   This is part of building of a new cluster with a T0. 
#   Using AddRack-configlet, this new T0 could be added to a T1
#   This includes the following
#
#   1) Use CLI (config ...) to ensure that this port is marked as down
#
#   Creates a configlet per strict template that is published in OneNote.
#   (a) Adds a new Device Neighbor
#   (b) Adds a new Portchannel for this port
#   (c) Appends to ACL_TABLE for Everflow
#   (d) Adds other port related entries 
#       CABLE_LENGTH, QUEUE, BUGGER_PG, BUFFER_QUEUE, BUFFER_PG,
#       BUFFER_PORT_INGRESS_PROFILE_LIST & BUFFER_PORT_EGRESS_PROFILE_LIST, if 
#       Mellanox, PORT_QOS_MAP, PFC_WD
#   (e) Add a new BGP Neighbor
#   
#   2) Apply the above template using "configlet" tool
#   3) Use CLI to set this port up
# 
# How this test works ?
#   (a) Load the current/original minigraph for this device, which has all T0s
#      per its topology
#   (b) Take a dump of CONFIG-DB, APP-DB & ASIC-DB
#   (c) Generate a new minigraph, by removing a T0 from the original minigraph
#   (d) Load the new minigraph
#   (e) Generate the configlet for this removed T0
#   (f) Apply this configlet
#   (g) Get dump of CONFIG-DB, APP-DB & ASIC-DB
#   (h) Verify the following
#       (a) BGP is up for this new neighbor
#       (b) Compare the DB dumps with the dumps taken with original minigraph
#
# Upon successful testing via configlet using strict template, retry the 
# same using generic updater.
# During above test, it takes a copy of config_db.json w/o T0 
# Takes a diff between config_db.json original & w/o T0.
# Apply this patch using CLI (config apply-patch ...) which uses generic
# updater. 
#   1) Load config_db.json w/o T0
#   2) Create patch from config_db.json w/o To to original
#   3) Apply the patch
#   4) Take DB dumps & compare with original
#   5) Check BGP session
#
# Upon successful testing of patch application using generic updater,
# test removal of same T0
#
#   1) Create patch from config_db.json original to w/o T0
#   2) Apply patch (confilg apply-patch ...) 
#   3) Take DB dumps and compare with those taken upon loading minigraph w/o T0
#

ORIG_DB_SUB_DIR = "orig"
NO_T0_DB_SUB_DIR = "no_T0"
CLET_DB_SUB_DIR = "clet"
PATCH_ADD_T0_SUB_DIR = "patch_add"
PATCH_RM_T0_SUB_DIR = "patch_rm"
FILES_SUB_DIR = "files"

# Ansible test run creates all files under logs/<test dir name, which in our
# case is "configlet">
# Create a AddRack under that and put all files under that.
# NOTE: Any duthost.fetch will download the file under 
# <given dir>/<dut hostname>/<entire path of the src file>
# if you download /etc/sonic/minigraph.xml under data_dir,
# it will be created as <data_dir>/<duthost name>/etc/sonic/minigraph.xml
# Say, return value of duthost.fetch is ret, then ret["dest"]
# is easier way to get the destination path.
#
base_dir    = "logs/configlet"
data_dir    = "{}/AddRack".format(base_dir)
orig_db_dir = "{}/{}".format(data_dir, ORIG_DB_SUB_DIR)
no_t0_db_dir = "{}/{}".format(data_dir, NO_T0_DB_SUB_DIR)
clet_db_dir = "{}/{}".format(data_dir, CLET_DB_SUB_DIR)
patch_add_t0_dir = "{}/{}".format(data_dir, PATCH_ADD_T0_SUB_DIR)
patch_rm_t0_dir = "{}/{}".format(data_dir, PATCH_RM_T0_SUB_DIR)
files_dir   = "{}/{}".format(data_dir, FILES_SUB_DIR)

def MINS_TO_SECS(n):
    return n * 60

RELOAD_WAIT_TIME = MINS_TO_SECS(3)      # TODO: Change to 3

PAUSE_INTF_DOWN = MINS_TO_SECS(1)
PAUSE_INTF_UP = MINS_TO_SECS(3)         # TODO: change to 3
PAUSE_CLET_APPLY = MINS_TO_SECS(1)

DB_COMP_WAIT_TIME = MINS_TO_SECS(3)     # TODO: change to 5


def do_pause(secs, msg):
    log_info("do_pause: seconds:{} {}".format(secs, msg))
    time.sleep(secs)
    log_info("do_pause: DONE")


def init(duthost):
    global init_data

    if not os.path.exists(base_dir):
        os.system("mkdir -p {}".format(base_dir))

    for i in [ data_dir, orig_db_dir, no_t0_db_dir, clet_db_dir,
            patch_add_t0_dir, patch_rm_t0_dir, files_dir ]:
        os.mkdir(i)

    init_data["files_dir"] = files_dir 
    init_data["data_dir"] = data_dir
    init_data["orig_db_dir"] = orig_db_dir
    init_data["switch_name"] = duthost.duthost_name

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


def restore_orig_minigraph(duthost, skip_load=False):
    ret = duthost.stat(path="/etc/sonic/orig/minigraph.xml.addRack.orig")
    if ret["stat"]["exists"]:
        duthost.shell("cp /etc/sonic/orig/minigraph.xml.addRack.orig /etc/sonic/minigraph.xml")
        duthost.shell("chmod u+w /etc/sonic/minigraph.xml")
        # Reload original minigraph
        if not skip_load:
            load_minigraph(duthost)
        log_info("restored minigraph")
        return True
    else:
        log_info("No minigraph file to restore from")
        return False


def load_minigraph(duthost):
    log_info("Loading minigraph")
    config_reload(duthost, config_source="minigraph", wait=RELOAD_WAIT_TIME, start_bgp=True) 
    assert wait_until(300, 20, 0, duthost.critical_services_fully_started), \
            "All critical services should fully started!"
    assert wait_until(300, 20, 0, chk_for_pfc_wd, duthost), \
            "PFC_WD is missing in CONFIG-DB"


def apply_clet(duthost):
    global no_t0_db_dir

    pfx_lvl = get_prefix_lvl()

    try:
        mini_wo_to = managed_files["minigraph_wo_to"]
        clet_file = managed_files["configlet"]
        sonic_clet_file = "/etc/sonic/add_Rack.json"

        del_clet_file = os.path.join(os.path.dirname(
            os.path.abspath(__file__)), "everflow_delete.json")
        del_sonic_clet_file = "/etc/sonic/everflow_delete.json"

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

        append_log_prefix_msg("load_mini_wo_t0", pfx_lvl)
        load_minigraph(duthost)

        append_log_prefix_msg("load_mini_wo_t0", pfx_lvl)
        take_DB_dumps(duthost, no_t0_db_dir, data_dir)

        append_log_prefix_msg("applying", pfx_lvl)
        # Apply delete 
        duthost.shell("sudo configlet -d -j {}".format(del_sonic_clet_file))

        tor_ifname = tor_data["links"][0]["local"]["sonic_name"]
        duthost.shell("sudo config interface shutdown {}".format(tor_ifname))
        do_pause(PAUSE_INTF_DOWN, "pause upon i/f {} shutdown".format(tor_ifname))

        duthost.shell("sudo configlet -u -j {}".format(sonic_clet_file))
        do_pause(PAUSE_CLET_APPLY, "Pause after applying configlet")

        duthost.shell("sudo config interface startup {}".format(tor_ifname))
        do_pause(PAUSE_INTF_UP, "pause upon i/f {} startup".format(tor_ifname))

        append_log_prefix_msg("checking_dump", pfx_lvl)
        assert wait_until(DB_COMP_WAIT_TIME, 20, 0, db_comp, duthost, clet_db_dir,
                orig_db_dir, "apply_clet"), \
                "DB compare failed after apply-clet"

        # Ensure BGP session is up
        chk_bgp_session(duthost, tor_data["ip"]["remote"], "post-clet test")
        chk_bgp_session(duthost, tor_data["ipv6"]["remote"].lower(), "post-clet test")

        log_info("AddRack by template succeeded")
    finally:
        set_prefix_lvl(pfx_lvl)


def download_sonic_files(duthost):
    for f in [ "minigraph.xml", "config_db.json" ]:
        duthost.fetch(src="/etc/sonic/{}".format(f), dest=data_dir)

def files_create(is_mlnx, is_storage_backend):
    init_global_data()

    strip.main(init_data["files_dir"])
    configlet.main(init_data["files_dir"], is_mlnx, is_storage_backend)

    log_info("Managed files: {}".format(json.dumps(managed_files, indent=4)))
                                
                                        
def chk_bgp_session(duthost, ip, msg):
    # info = duthost.get_bgp_neighbor_info(ip.decode('utf-8'))
    info = duthost.get_bgp_neighbor_info(ip)
    bgp_state = info.get("bgpState", "")
    assert bgp_state == "Established", \
            "{}: BGP session for {} = {}; expect established".format(msg, ip, bgp_state)


def _create_patch(src_dir, dst_dir, patch_file):
    with open(os.path.join(src_dir, "config_db.json"), "r") as s:
        src_json = json.load(s)

    with open(os.path.join(dst_dir, "config_db.json"), "r") as s:
        dst_json = json.load(s)

    jpatch = list(jsonpatch.JsonPatch.from_diff(src_json, dst_json))

    with open(patch_file, "w") as s:
        s.write(json.dumps(jpatch, indent=4))


def db_comp(duthost, test_db_dir, ref_db_dir, ctx):
    global data_dir

    take_DB_dumps(duthost, test_db_dir, data_dir)

    ret, msg = compare_dumps(ref_db_dir, test_db_dir)
    if ret:
        log_info("{}: Failed to compare:{}; retry if withing limits".format(
            ctx, msg))
        return False
    return True


def generic_patch_add_t0(duthost):
    # Create patch from no_t0 to original that had T0.
    #
    # Load config w/o T0
    #
    duthost.copy(src=os.path.join(no_t0_db_dir, "config_db.json"),
            dest="/etc/sonic/config_db.json")
    config_reload(duthost, wait=RELOAD_WAIT_TIME, start_bgp=True)

    patch_file = os.path.join(patch_add_t0_dir, "patch.json")
    _create_patch(no_t0_db_dir, orig_db_dir, patch_file)

    # Apply patch
    res = duthost.shell("config apply-patch  -f CONFIGDB -v {}".format(
        patch_file))
    assert res["rc"] == 0, "Failed to apply patch"


    assert wait_until(DB_COMP_WAIT_TIME, 20, 0, db_comp, duthost, patch_add_t0_dir,
            orig_db_dir, "generic_patch_add_t0"), \
            "DB compare failed after adding T0 via generic patch updater"

    # Ensure BGP session is up
    chk_bgp_session(duthost, tor_data["ip"]["remote"], "post-patch-add test")
    chk_bgp_session(duthost, tor_data["ipv6"]["remote"].lower(), "post-patch-add test")


def generic_patch_rm_t0(duthost):
    # Create patch from original to no_t0
    #
    # As this test follows generic_patch_add_t0, the current
    # config has all T0s
    #
    patch_file = os.path.join(patch_rm_t0_dir, "patch.json")
    _create_patch(orig_db_dir, no_t0_db_dir, patch_file)

    # Apply patch
    res = duthost.shell("config apply-patch  -f CONFIGDB -v {}".format(
        patch_file))
    assert res["rc"] == 0, "Failed to apply patch"


    assert wait_until(DB_COMP_WAIT_TIME, 20, 0, db_comp, duthost, patch_rm_t0_dir,
            no_t0_db_dir, "generic_patch_rm_t0"), \
            "DB compare failed after adding T0 via generic patch updater"


def do_test_add_rack(duthost, is_storage_backend = False, skip_test=False,
        skip_generic=False, skip_load=False):
    global data_dir, orig_db_dir, clet_db_dir, files_dir

    init(duthost)

    fpath = "/usr/local/lib/python3.9/dist-packages/generic_config_updater/services_validator.py"
    ret = duthost.stat(path=fpath)
    if not ret["stat"]["exists"]:
        log_info("Skipping test as file does not exist: {}".format(fpath))
        return

    set_log_prefix_msg("init")
    if not skip_load:
        # start of the test ensures that original minigraph is available in
        # /etc/sonic/
        #
        log_debug("Loading original minigraph")
        # Loads original minigraph with all T0s & get dumps

        load_minigraph(duthost)
        log_info("config reloaded; Taking dumps ...")

    set_log_prefix_msg("orig_DB_dumps")
    take_DB_dumps(duthost, orig_db_dir, data_dir)

    set_log_prefix_msg("create files")
    # Download sonic files required to generate minigraph w/o a T0
    # and configlet. 
    download_sonic_files(duthost)

    # Create minigraph w/o a T0 & configlet, apply & take dump
    files_create(is_mlnx = duthost.facts["asic_type"] == "mellanox",
            is_storage_backend = is_storage_backend)

    # Ensure BGP session is up before we apply stripped minigraph
    chk_bgp_session(duthost, tor_data["ip"]["remote"], "pre-clet test")
    chk_bgp_session(duthost, tor_data["ipv6"]["remote"].lower(), "pre-clet test")

    if skip_test:
        # Pause after all create files
        return
    
    set_log_prefix_msg("apply clet")
    apply_clet(duthost)

    if skip_generic:
        return False

    # Note: apply_clet is required to run the update test
    # via generic-updater as that helps create no_t0 files
    # that are required to create patch for generic updater.
    #
    set_log_prefix_msg("patch_add")
    generic_patch_add_t0(duthost)

    set_log_prefix_msg("patch_rm")
    generic_patch_rm_t0(duthost)
    log_info("Test run is good!")


