#! /usr/bin/env python

import inspect
import json
import os
import re
import sys
import time

if sys.version_info.major > 2:
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent))

from helpers import log_error, log_info, log_debug, set_print

CONFIG_DB_FILE = "etc/sonic/config_db.json"
MINIGRAPH_FILE = "etc/sonic/minigraph.xml"

tor_data = {}
managed_files = {}
config_db_data_orig = {}

init_data = {
        "version": "",
        "switch_name": "",
        "files_dir": "",
        "data_dir": "",
        "orig_db_dir": ""
        }


MAX_MISMATCH_CNT = 10

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
base_dir = "logs/configlet"
data_dir = "{}/AddRack".format(base_dir)
orig_db_dir = "{}/{}".format(data_dir, ORIG_DB_SUB_DIR)
no_t0_db_dir = "{}/{}".format(data_dir, NO_T0_DB_SUB_DIR)
clet_db_dir = "{}/{}".format(data_dir, CLET_DB_SUB_DIR)
patch_add_t0_dir = "{}/{}".format(data_dir, PATCH_ADD_T0_SUB_DIR)
patch_rm_t0_dir = "{}/{}".format(data_dir, PATCH_RM_T0_SUB_DIR)
files_dir = "{}/{}".format(data_dir, FILES_SUB_DIR)


def MINS_TO_SECS(n):
    return n * 60


RELOAD_WAIT_TIME = MINS_TO_SECS(3)

PAUSE_INTF_DOWN = MINS_TO_SECS(1)
PAUSE_INTF_UP = MINS_TO_SECS(3)
PAUSE_CLET_APPLY = MINS_TO_SECS(1)

DB_COMP_WAIT_TIME = MINS_TO_SECS(5)


def do_pause(secs, msg):
    log_info("do_pause: seconds:{} {}".format(secs, msg))
    time.sleep(secs)
    log_info("do_pause: DONE")


#
# App-DB/"LLDP_ENTRY_TABLE" is very dynamic -- not a candidate for comparison
# link-local IPv6 addresses starts with "fe80:" are skipped from comparison
#
scan_dbs = {
        "config-db": {
            "db_no": 4,
            "keys_to_compare": set(),
            "keys_to_skip_comp": {
                "BUFFER_PROFILE|pg_lossless_40000_5m_profile",
                "FLEX_COUNTER_TABLE"
                },
            "keys_skip_val_comp": set()
        },
        "app-db": {
            "db_no": 0,
            "keys_to_compare": set(),
            "keys_to_skip_comp": {
                "LLDP_ENTRY_TABLE",
                "NEIGH_TABLE:eth0",
                "NEIGH_TABLE_DEL_SET",
                "ROUTE_TABLE:fe80:",
                "ROUTE_TABLE:192.168.0.128/25",
                "ROUTE_TABLE:20c0:a800::/64",
                "ROUTE_TABLE:2064:100::11",
                "ROUTE_TABLE:192.168.0.0/25",
                "ROUTE_TABLE:100.1.0.17",
                "ROUTE_TABLE:20c0:a800:0:80::/64",
                "ROUTE_TABLE:FE80:",
                "TUNNEL_DECAP_TABLE",
                # BUFFER_PG.*3-4 is an auto created entry by buffermgr
                # configlet skips it. So skip verification too.
                "BUFFER_PG_TABLE:Ethernet[0-9][0-9]*:3-4",
                # Diff in TUNNEL_DECAP_TERM_TABLE is expected because router port
                # is set admin down in the test, which leads to tunnel term change
                "TUNNEL_DECAP_TERM_TABLE:IPINIP_TUNNEL",
                "TUNNEL_DECAP_TERM_TABLE:IPINIP_V6_TUNNEL",
                "NEIGH_RESOLVE_TABLE*"
                },
            "keys_skip_val_comp": {
                "last_up_time",
                "flap_count"
            }
        },
        "state-db": {
            "db_no": 6,
            "keys_to_compare": {
                "NEIGH_STATE_TABLE",
                "TRANSCEIVER_INFO",
                "TRANSCEIVER_STATUS",
                "VLAN_MEMBER_TABLE",
                "VLAN_TABLE"
            },
            "keys_to_skip_comp": {
                "PORT_TABLE"
            },
            "keys_skip_val_comp": set()
        }
    }


def init_global_data():
    global tor_data, managed_files, config_db_data_orig

    for k in init_data:
        if not init_data[k]:
            assert False, "missing init_data for {}".format(k)

    tor_data.update({
            "name": {"local": init_data["switch_name"], "remote": ""},
            "mgmt_ip": {"local": "", "remote": ""},
            "ip": {"local": "", "remote": ""},
            "ipv6": {"local": "", "remote": ""},
            "links": [{"local": {"alias": "", "sonic_name": ""}, "remote": ""}],
            "hwsku": {"local": "", "remote": ""},
            "portChannel": "",
            "os_version": init_data["version"],
            "bgp_info": {
                "asn": "",
                "holdtime": "",
                "keepalive": ""
            }
        })

    data_dir = init_data["data_dir"]
    duthost_name = init_data["switch_name"]
    managed_files.update({
            "minigraph_file": os.path.join(data_dir, duthost_name, MINIGRAPH_FILE),
            "config_db_file": os.path.join(data_dir, duthost_name, CONFIG_DB_FILE),
            "minigraph_wo_to": "",
            "configlet": ""
            })

    log_info("managed_files.update={}".format(json.dumps(managed_files, indent=4)))

    with open(managed_files["config_db_file"], "r") as s:
        config_db_data_orig.update(json.load(s))


def report_error(m):
    log_error("failure: {}:{}: {}".format(inspect.stack()[1][1], inspect.stack()[1][2], m))
    assert False, m


def match_key(key, kset):
    for k in kset:
        if key.startswith(k):
            return True
        elif re.match(k, key):
            return True
    return False


def chk_for_pfc_wd(duthost):
    ret = False
    res = duthost.shell('redis-dump -d 4 --pretty -k \"DEVICE_METADATA|localhost\"')
    meta_data = json.loads(res["stdout"])
    pfc_status = meta_data["DEVICE_METADATA|localhost"]["value"].get("default_pfcwd_status", "")
    log_debug("pfc_status={}".format(pfc_status))

    if pfc_status == "enable":
        for namespace in duthost.get_frontend_asic_namespace_list():
            cmd_prefix = ''
            if duthost.is_multi_asic:
                cmd_prefix = 'sudo ip netns exec {} '.format(namespace)
            res = duthost.shell(cmd_prefix + 'redis-dump -d 4 --pretty -k \"PFC_WD*\"')
            pfc_wd_data = json.loads(res["stdout"])
            if len(pfc_wd_data):
                ret = True
    else:
        # pfc is not enabled; return True, as there will not be any pfc to check
        ret = True
    return ret


def dut_dump(redis_cmd, duthost, data_dir, fname):
    db_read = {}

    dump_file = "/tmp/{}.json".format(fname)
    ret = duthost.shell("{} -o {}".format(redis_cmd, dump_file))
    assert ret["rc"] == 0, "Failed to run cmd:{}".format(redis_cmd)

    ret = duthost.fetch(src=dump_file, dest=data_dir)
    dest_file = ret.get("dest", None)

    assert dest_file is not None, "Failed to fetch src={} dest:{}".format(dump_file, data_dir)
    assert os.path.exists(dest_file), "Fetched file not exist: {}".format(dest_file)

    with open(dest_file, "r") as s:
        db_read = json.load(s)
    return db_read


def get_dump(duthost, db_name, db_info, dir_name, data_dir):
    db_no = db_info["db_no"]
    lst_keys = db_info["keys_to_compare"]

    db_read = {}
    if not lst_keys:
        db_read = dut_dump("redis-dump -d {} --pretty".format(db_no),
                           duthost, data_dir, db_name)
    else:
        for k in lst_keys:
            fname = "{}_{}.json".format(k, db_name)
            cmd = 'redis-dump -d {} --pretty -k \"{}*\"'.format(db_no, k)
            db_read.update(dut_dump(cmd, duthost, data_dir, fname))

    keys_skip_cmp = db_info["keys_to_skip_comp"]
    keys_skip_val = db_info["keys_skip_val_comp"]

    db_write = {}
    for k in db_read:
        # Transient keys start with "_"; Hence skipped
        if (not k.startswith("_")) and (not match_key(k, keys_skip_cmp)):
            value = db_read[k].get("value", {})  # Get the value or empty dictionary if

            for skip_val in keys_skip_val:
                if match_key(skip_val, value):
                    value.pop(skip_val)
            db_write[k] = db_read[k]

    dst_file = os.path.join(dir_name, "{}.json".format(db_name))
    with open(dst_file, "w") as s:
        s.write(json.dumps(db_write, indent=4, default=str))

    log_info("Written dst_file: {}".format(dst_file))


def take_DB_dumps(duthost, dir_name, data_dir):
    log_info("Taking DB dumps dir= {}".format(dir_name))
    for db_name, db_info in scan_dbs.items():
        get_dump(duthost, db_name, db_info, dir_name, data_dir)

    duthost.shell("config save -y")

    for i in ["config_db.json", "minigraph.xml"]:
        ret = duthost.fetch(src=os.path.join("/etc/sonic/", i), dest=data_dir)
        os.system("cp {} {}".format(ret["dest"], dir_name))

    log_info("dumps created in dir = {}".format(dir_name))


def cmp_str(orig_s, clet_s):
    orig_v = sorted(orig_s.split(","))
    clet_v = sorted(clet_s.split(","))
    if orig_v != clet_v:
        log_info("compare str failed: {} != {}".format(orig_v, clet_v))
    return orig_v == clet_v


def cmp_value(orig_val, clet_val):
    if orig_val == clet_val:
        return True

    if type(orig_val) == str:
        return cmp_str(orig_val, clet_val)

    if type(orig_val) == dict:
        for fld, val in orig_val.items():
            if fld not in clet_val:
                return False
            if not cmp_value(orig_val[fld], clet_val[fld]):
                return False
    return True


def cmp_dump(db_name, orig_db_dir, clet_db_dir):
    mismatch_cnt = 0
    orig_data = {}
    clet_data = {}
    msg = ""

    log_info("comparing dump {} {} {}".format(
        db_name, orig_db_dir, clet_db_dir))
    fname = "{}.json".format(db_name)
    with open(os.path.join(orig_db_dir, fname), "r") as s:
        orig_data = json.load(s)

    with open(os.path.join(clet_db_dir, fname), "r") as s:
        clet_data = json.load(s)

    if clet_data == orig_data:
        log_info("{} compared good orig={} clet={}".format(db_name, orig_db_dir, clet_db_dir))
        return 0, ""

    orig_keys = set(sorted(orig_data.keys()))
    clet_keys = set(sorted(clet_data.keys()))

    diff = orig_keys - clet_keys
    for k in diff:
        log_error("{}: Missing key: {}".format(fname, k))
        mismatch_cnt += 1
        if not msg:
            msg = "Missing key: {}".format(k)
        if mismatch_cnt >= MAX_MISMATCH_CNT:
            log_error("Too many errors; bailing out")
            break

    diff = clet_keys - orig_keys
    for k in diff:
        log_info("{}: New key:  {}".format(fname, k))

    for k in orig_keys.intersection(clet_keys):
        if mismatch_cnt >= MAX_MISMATCH_CNT:
            log_error("Too many errors; bailing out")
            break

        if orig_data[k] != clet_data[k]:
            if orig_data[k]["type"] != clet_data[k]["type"]:
                log_error("{}: mismatch key:{} type:{} != {}".format(
                    fname, k, orig_data[k]["type"], clet_data[k]["type"]))
                mismatch_cnt += 1
                if not msg:
                    msg = "mismatch key:{} type:{} != {}".format(
                            k, orig_data[k]["type"], clet_data[k]["type"])

            if not cmp_value(orig_data[k]["value"], clet_data[k]["value"]):
                log_error("{}: mismatch key:{} {} != {}"
                          .format(fname, k, orig_data[k]["value"], clet_data[k]["value"]))
                mismatch_cnt += 1
                if not msg:
                    msg = "mismatch key:{} value:{} != {}".format(
                            k, orig_data[k]["value"], clet_data[k]["value"])

    if not mismatch_cnt:
        log_info("{} compared good orig={} clet={}".format(db_name, orig_db_dir, clet_db_dir))
    else:
        log_info("{} compare failed orig={} clet={} mismatch_cnt={}".format(
            db_name, orig_db_dir, clet_db_dir, mismatch_cnt))
    if msg:
        msg = "{}: {}".format(db_name, msg)
    log_info("compared dump {} mismatch_cnt={} msg={}".format(
        db_name, mismatch_cnt, msg))
    return mismatch_cnt, msg


def compare_dumps(orig_db_dir, clet_db_dir):
    mismatch_cnt = 0
    ret_msg = ""
    for db_name in scan_dbs:
        cnt, msg = cmp_dump(db_name, orig_db_dir, clet_db_dir)
        mismatch_cnt += cnt
        if not ret_msg:
            ret_msg = msg
    return mismatch_cnt, ret_msg


def db_comp(duthost, test_db_dir, ref_db_dir, ctx):
    global data_dir

    take_DB_dumps(duthost, test_db_dir, data_dir)

    ret, msg = compare_dumps(ref_db_dir, test_db_dir)
    if ret:
        log_info("{}: Failed to compare:{}; retry if withing limits".format(
            ctx, msg))
        return False
    log_info("{}: Succeeded to compare".format(ctx))
    return True


def chk_bgp_session(duthost, ip, msg):
    if sys.version_info[0] > 2:
        info = duthost.get_bgp_neighbor_info(ip)
    else:
        info = duthost.get_bgp_neighbor_info(ip.decode('utf-8'))
    bgp_state = info.get("bgpState", "")
    assert bgp_state == "Established", \
        "{}: BGP session for {} = {}; expect established".format(msg, ip, bgp_state)


def main():
    set_print()
    print("Calling compare dumps")
    ret, msg = compare_dumps("logs/AddRack/orig", "logs/AddRack/clet")
    print(("ret = {} msg={}".format(ret, msg)))


if __name__ == "__main__":
    main()
