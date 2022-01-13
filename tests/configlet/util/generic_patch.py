#! /usr/bin/env python

import argparse
import json
import jsonpatch
import os
import re
import sys
import time
import yaml

from helpers import *
from common import *

if os.path.exists("/etc/sonic/sonic-environment"):
    from mock_for_switch import config_reload, wait_until
else:
    from tests.common.config_reload import config_reload
    from tests.common.utilities import wait_until

# HACKS summary:
# 1) While adding i/f (add_t0), interfaces must be added at the start, before
#    adding/updating any other object
#    Reverse is true for removing interface (rm_t0).
#    Remove the interface objects, last
# 
# 2) Do not split a single object into multiple updates.
#    This is found to break when adding BGP_NEIGHBOR object as multiple updates
#     Sample:
#     Patch Applier:   * [{"op": "add", "path": "/BGP_NEIGHBOR/10.0.0.33", "value": {"admin_status": "up"}}]
#     Patch Applier:   * [{"op": "add", "path": "/BGP_NEIGHBOR/10.0.0.33/asn", "value": "64001"}]
#     Patch Applier:   * [{"op": "add", "path": "/BGP_NEIGHBOR/10.0.0.33/holdtime", "value": "10"}]
#     Patch Applier:   * [{"op": "add", "path": "/BGP_NEIGHBOR/10.0.0.33/keepalive", "value": "3"}]
# 
# Work around/hack:
# 1) Interface changes are collected into a separate file and applied at the start/end
# 2) Use "-i ''" so as to avoid object split


def _create_patch(src_dir, dst_dir, patch_dir):
    add_intf = False

    with open(os.path.join(src_dir, "config_db.json"), "r") as s:
        src_json = json.load(s)

    with open(os.path.join(dst_dir, "config_db.json"), "r") as s:
        dst_json = json.load(s)

    jpatch = list(jsonpatch.JsonPatch.from_diff(src_json, dst_json))

    # This gets auto added.
    #
    interface_patch = []
    other_patch = []

    # Golden config will never add this. So required for test only
    rm_pattern = "^/BUFFER_PG/Ethernet[0-9][0-9]*\|3-4"

    # TODO: Hack; Have this until generic patch updater will order 
    # Interfaces add/remove correctly
    #
    intf_pattern = ("^/INTERFACE/Ethernet[0-9][0-9]*$"
            "|"
            "^/INTERFACE/Ethernet[0-9][0-9]*\\|[0-9a-fA-F][0-9a-fA-F\\.:]*[0-9a-fA-F]~1[0-9][0-9]*$")

    for e in jpatch:
        if re.search(intf_pattern, e["path"]):
            interface_patch.append(e)
            add_intf = e["op"] == "add"

        elif not re.search(rm_pattern, e["path"]):
            other_patch.append(e)

    patch_intf_file = os.path.join(patch_dir, "patch_intf.json")
    patch_other_file = os.path.join(patch_dir, "patch_other.json")

    with open(patch_intf_file, "w") as s:
        s.write(json.dumps(interface_patch, indent=4))

    with open(patch_other_file, "w") as s:
        s.write(json.dumps(other_patch, indent=4))

    # TODO: Hack until generic patch updater does this.
    if add_intf:
        return [ patch_intf_file, patch_other_file ]
    else:
        return [ patch_other_file, patch_intf_file ]



def generic_patch_add_t0(duthost, do_load):
    # Load config w/o T0
    #
    if do_load:
        duthost.copy(src=os.path.join(no_t0_db_dir, "config_db.json"),
                dest="/etc/sonic/config_db.json")
        config_reload(duthost, wait=RELOAD_WAIT_TIME, start_bgp=True)

    # Create patch from no_t0 to original that had T0.
    #
    patch_files = _create_patch(no_t0_db_dir, orig_db_dir, patch_add_t0_dir)

    # Hack: TODO: Before adding port, patch updater need to ensure
    # the port is down. Until then bring it down explicitly.
    #
    tor_ifname = tor_data["links"][0]["local"]["sonic_name"]
    duthost.shell("config interface shutdown {}".format(tor_ifname))
    do_pause(PAUSE_INTF_DOWN, "pause upon i/f {} shutdown before add patch".format(tor_ifname))

    # Apply patch
    # HACK: TODO: by default fields of an object is split into multiple
    # add. This breaks, especialy when BGP_NEIGHBOR object is split into multiple
    # Hence force as one for now.
    # Patch Applier:   * [{"op": "add", "path": "/BGP_NEIGHBOR/10.0.0.33", "value": {"admin_status": "up"}}]
    # Patch Applier:   * [{"op": "add", "path": "/BGP_NEIGHBOR/10.0.0.33/asn", "value": "64001"}]
    # Patch Applier:   * [{"op": "add", "path": "/BGP_NEIGHBOR/10.0.0.33/holdtime", "value": "10"}]
    # Patch Applier:   * [{"op": "add", "path": "/BGP_NEIGHBOR/10.0.0.33/keepalive", "value": "3"}]
    # Patch Applier:   * [{"op": "add", "path": "/BGP_NEIGHBOR/10.0.0.33/local_addr", "value": "10.0.0.32"}]
    # Patch Applier:   * [{"op": "add", "path": "/BGP_NEIGHBOR/10.0.0.33/name", "value": "ARISTA01T0"}]
    # Patch Applier:   * [{"op": "add", "path": "/BGP_NEIGHBOR/10.0.0.33/nhopself", "value": "0"}]
    # Patch Applier:   * [{"op": "add", "path": "/BGP_NEIGHBOR/10.0.0.33/rrclient", "value": "0"}]
    #
    CMD = "config apply-patch -n -i '' -v {}"
    for fl in patch_files:
        res = duthost.shell(CMD.format(fl))

    # HACK: TODO: There are scenarios, where it applies patchand still consider as failed
    # "...Error: After applying patch to config, there are still some parts not updated\n"
    #
    # assert res["rc"] == 0, "Failed to apply patch"
    do_pause(PAUSE_CLET_APPLY, "Pause after applying add patch")

    duthost.shell("config interface startup {}".format(tor_ifname))
    do_pause(PAUSE_INTF_UP, "pause upon i/f {} startup after add patch".format(tor_ifname))

    assert wait_until(DB_COMP_WAIT_TIME, 20, 0, db_comp, duthost, patch_add_t0_dir,
            orig_db_dir, "generic_patch_add_t0"), \
            "DB compare failed after adding T0 via generic patch updater"

    # Ensure BGP session is up
    chk_bgp_session(duthost, tor_data["ip"]["remote"], "post-patch-add test")
    chk_bgp_session(duthost, tor_data["ipv6"]["remote"].lower(), "post-patch-add test")


def generic_patch_rm_t0(duthost, do_load):
    # Load config with T0
    #
    if do_load:
        duthost.copy(src=os.path.join(orig_db_dir, "config_db.json"),
                dest="/etc/sonic/config_db.json")
        config_reload(duthost, wait=RELOAD_WAIT_TIME, start_bgp=True)

    # Create patch from original to no_t0
    #
    # As this test follows generic_patch_add_t0, the current
    # config has all T0s
    #
    patch_files = _create_patch(orig_db_dir, no_t0_db_dir, patch_rm_t0_dir)

    # Hack: TODO: Before removing port, patch updater need to ensure
    # the port is down. Until then bring it down explicitly.
    #
    tor_ifname = tor_data["links"][0]["local"]["sonic_name"]
    duthost.shell("config interface shutdown {}".format(tor_ifname))
    do_pause(PAUSE_INTF_DOWN, "pause upon i/f {} shutdown before add patch".format(tor_ifname))

    # Apply patch
    # HACK: TODO: by default fields of an object is split into multiple
    # add. This breaks, especialy when BGP_NEIGHBOR object is split into multiple
    # Hence force as one for now.
    # Patch Applier:   * [{"op": "add", "path": "/BGP_NEIGHBOR/10.0.0.33", "value": {"admin_status": "up"}}]
    # Patch Applier:   * [{"op": "add", "path": "/BGP_NEIGHBOR/10.0.0.33/asn", "value": "64001"}]
    # Patch Applier:   * [{"op": "add", "path": "/BGP_NEIGHBOR/10.0.0.33/holdtime", "value": "10"}]
    # Patch Applier:   * [{"op": "add", "path": "/BGP_NEIGHBOR/10.0.0.33/keepalive", "value": "3"}]
    # Patch Applier:   * [{"op": "add", "path": "/BGP_NEIGHBOR/10.0.0.33/local_addr", "value": "10.0.0.32"}]
    # Patch Applier:   * [{"op": "add", "path": "/BGP_NEIGHBOR/10.0.0.33/name", "value": "ARISTA01T0"}]
    # Patch Applier:   * [{"op": "add", "path": "/BGP_NEIGHBOR/10.0.0.33/nhopself", "value": "0"}]
    # Patch Applier:   * [{"op": "add", "path": "/BGP_NEIGHBOR/10.0.0.33/rrclient", "value": "0"}]
    #
    CMD = "config apply-patch -n -i '' -v {}"
    for fl in patch_files:
        res = duthost.shell(CMD.format(fl))

    # HACK: TODO: There are scenarios, where it applies patchand still consider as failed
    # "...Error: After applying patch to config, there are still some parts not updated\n"
    #
    # assert res["rc"] == 0, "Failed to apply patch"
    do_pause(PAUSE_CLET_APPLY, "Pause after applying add patch")

    assert wait_until(DB_COMP_WAIT_TIME, 20, 0, db_comp, duthost, patch_rm_t0_dir,
            no_t0_db_dir, "generic_patch_rm_t0"), \
            "DB compare failed after adding T0 via generic patch updater"


