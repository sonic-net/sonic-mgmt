#! /usr/bin/env python

import json
import jsonpatch
import fnmatch
import os
import re

from helpers import *
from common import *

if os.path.exists("/etc/sonic/sonic-environment"):
    from mock_for_switch import config_reload, wait_until
else:
    from tests.common.config_reload import config_reload
    from tests.common.utilities import wait_until

CMD_APPLY_HACK = "config apply-patch -n -i '' -v {}"
CMD_APPLY = "config apply-patch -n -v {}"

# HACKS summary:
#
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
# 3) Mark interface down at the start before any config update for that port
#    Mark interface up, if this patch requires port up at the end.
#
# Work around/hack:
# 1) Port is explicitly marked down at the start. In case of "add", it is
#    explicitly marked up at the end
# 2) Interface changes are collected into a separate file and applied at the start/end
# 3) Use "-i ''" so as to avoid object split
#

def create_patch(src_dir, dst_dir, patch_dir, hack_apply=False):
    # Some keys could get updated by some control plane components
    # Use this filter to mimic patch from NDM generated golden config.
    #
    filter = {
            "ACL_TABLE",
            "BGP_NEIGHBOR",
            "BUFFER_PG",
            "BUFFER_PORT_EGRESS_PROFILE_LIST",
            "BUFFER_PORT_INGRESS_PROFILE_LIST",
            "BUFFER_QUEUE",
            "CABLE_LENGTH",
            "DEVICE_NEIGHBOR",
            "DEVICE_NEIGHBOR_METADATA",
            "INTERFACE",
            "PFC_WD",
            "PORT",
            "PORTCHANNEL",
            "PORTCHANNEL_INTERFACE",
            "PORTCHANNEL_MEMBER",
            "PORT_QOS_MAP",
            "QUEUE",
            "VLAN_SUB_INTERFACE"
    }
    with open(os.path.join(src_dir, "config_db.json"), "r") as s:
        src_json = json.load(s)

    with open(os.path.join(dst_dir, "config_db.json"), "r") as s:
        dst_json = json.load(s)

    diff_patch = list(jsonpatch.JsonPatch.from_diff(src_json, dst_json))

    jpatch = []

    # Golden config will never add this. So required for test only
    rm_pattern = "^/BUFFER_PG/Ethernet[0-9][0-9]*\|3-4"
    for e in diff_patch:
        if ((e["path"].split("/")[1] in filter) and
                (not re.search(rm_pattern, e["path"]))):
            jpatch.append(e)

    if not hack_apply:
        patch_file = os.path.join(patch_dir, "patch_0_all.json")
        with open(patch_file, "w") as s:
            s.write(json.dumps(jpatch, indent=4))
    else:
        # Hack:
        # Split Interface off of tghe patch into seperate file
        # Have this until generic patch updater will order 
        # Interfaces add/remove correctly. Also remove port-admin-up
        # as that should come at the end.
        #
        add_intf = False
        interface_patch = []
        other_patch = []

        intf_pattern = ("^/INTERFACE/Ethernet[0-9][0-9]*$"
                "|"
                "^/INTERFACE/Ethernet[0-9][0-9]*\\|[0-9a-fA-F][0-9a-fA-F\\.:]*[0-9a-fA-F]~1[0-9][0-9]*$")

        admin_up_pattern = "^/PORT/Ethernet[0-9][0-9]*/admin_status"

        for e in jpatch:
            if re.search(intf_pattern, e["path"]):
                interface_patch.append(e)
                add_intf = e["op"] == "add"
            elif not re.search(admin_up_pattern, e["path"]):
                other_patch.append(e)

        patch_intf_file = os.path.join(patch_dir,
                "patch_{}_intf.json".format(0 if add_intf else 1))
        patch_other_file = os.path.join(patch_dir,
                "patch_{}_other.json".format(1 if add_intf else 0))

        with open(patch_intf_file, "w") as s:
            s.write(json.dumps(interface_patch, indent=4))

        with open(patch_other_file, "w") as s:
            s.write(json.dumps(other_patch, indent=4))


def _list_patch_files(patch_dir):
    return sorted(fnmatch.filter(os.listdir(patch_dir), "patch_[0-9]_*.json"))


def generic_patch_add_t0(duthost, skip_load=False, hack_apply=False):
    # Load config w/o T0
    #
    if not skip_load:
        duthost.copy(src=os.path.join(no_t0_db_dir, "config_db.json"),
                dest="/etc/sonic/config_db.json")
        config_reload(duthost, wait=RELOAD_WAIT_TIME, start_bgp=True)

    if hack_apply:
        # Hack: TODO: Before adding port, patch updater need to ensure
        # the port is down. Until then bring it down explicitly.
        #
        tor_ifname = tor_data["links"][0]["local"]["sonic_name"]
        duthost.shell("config interface shutdown {}".format(tor_ifname))
        do_pause(PAUSE_INTF_DOWN,
                "pause upon i/f {} shutdown before add patch".format(tor_ifname))

    patch_files = _list_patch_files(patch_add_t0_dir)

    CMD = CMD_APPLY_HACK if hack_apply else CMD_APPLY

    for fl in patch_files:
        sonic_fl = os.path.join("/etc/sonic", fl)
        duthost.copy(src=os.path.join(patch_add_t0_dir, fl), dest=sonic_fl)
        duthost.shell(CMD.format(sonic_fl), module_ignore_errors=True)

        # HACK: TODO: There are scenarios, where it applies patch and still consider as failed
        # "...Error: After applying patch to config, there are still some parts not updated\n"
        # The above error is possible, if some control plane component is making an update.
        # We can ignore rc, as DB comp is the final check. So skip it.
        # assert res["rc"] == 0, "Failed to apply patch"

    do_pause(PAUSE_CLET_APPLY, "Pause after applying add patch")

    if hack_apply:
        duthost.shell("config interface startup {}".format(tor_ifname))
        do_pause(PAUSE_INTF_UP, "pause upon i/f {} startup after add patch".format(tor_ifname))

    assert wait_until(DB_COMP_WAIT_TIME, 20, 0, db_comp, duthost, patch_add_t0_dir,
            orig_db_dir, "generic_patch_add_t0"), \
            "DB compare failed after adding T0 via generic patch updater"

    # Ensure BGP session is up
    chk_bgp_session(duthost, tor_data["ip"]["remote"], "post-patch-add test")
    chk_bgp_session(duthost, tor_data["ipv6"]["remote"].lower(), "post-patch-add test")


def generic_patch_rm_t0(duthost, skip_load=False, hack_apply=False):
    # Load config with T0
    #
    if not skip_load:
        duthost.copy(src=os.path.join(orig_db_dir, "config_db.json"),
                dest="/etc/sonic/config_db.json")
        config_reload(duthost, wait=RELOAD_WAIT_TIME, start_bgp=True)

    if hack_apply:
        # Hack: TODO: Before removing port, patch updater need to ensure
        # the port is down. Until then bring it down explicitly.
        #
        tor_ifname = tor_data["links"][0]["local"]["sonic_name"]
        duthost.shell("config interface shutdown {}".format(tor_ifname))
        do_pause(PAUSE_INTF_DOWN, "pause upon i/f {} shutdown before add patch".format(tor_ifname))

    patch_files = _list_patch_files(patch_rm_t0_dir)

    CMD = CMD_APPLY_HACK if hack_apply else CMD_APPLY

    for fl in patch_files:
        sonic_fl = os.path.join("/etc/sonic", fl)
        duthost.copy(src=os.path.join(patch_rm_t0_dir, fl), dest=sonic_fl)
        duthost.shell(CMD.format(sonic_fl), module_ignore_errors=True)

        # HACK: TODO: There are scenarios, where it applies patch and still consider as failed
        # "...Error: After applying patch to config, there are still some parts not updated\n"
        # The above error is possible, if some control plane component is making an update.
        # We can ignore rc, as DB comp is the final check. So skip it.
        # assert res["rc"] == 0, "Failed to apply patch"

    assert wait_until(DB_COMP_WAIT_TIME, 20, 0, db_comp, duthost, patch_rm_t0_dir,
            no_t0_db_dir, "generic_patch_rm_t0"), \
            "DB compare failed after adding T0 via generic patch updater"


