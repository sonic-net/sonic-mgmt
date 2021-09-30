#! /usr/bin/env python

import json
import os

from helpers import *

CONFIG_DB_FILE = "etc/sonic/config_db.json"
MINIGRAPH_FILE = "etc/sonic/minigraph.xml"

tor_data = {}
managed_files = {}
config_db_data_orig = {}

init_data = {
        "version": "",
        "switch_name": "",
        "files_dir": "",
        "data_dir": ""
        }

running_in_switch = False

#
# App-DB/"LLDP_ENTRY_TABLE" is very dynamic -- not a candidate for comparison
# link-local IPv6 addresses starts with "fe80:" are skipped from comparison
#
scan_dbs = {
        "config-db": {
            "db_no": 4,
            "keys_to_compare": set(),
            "keys_to_skip_comp": {"BUFFER_PROFILE|pg_lossless_40000_5m_profile"},
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
                "ROUTE_TABLE:FE80:"},
            "keys_skip_val_comp": set()
            },
        "state-db": {
            "db_no": 6,
            "keys_to_compare": {
                "NEIGH_STATE_TABLE",
                "PORT_TABLE",
                "TRANSCEIVER_DOM_SENSOR",
                "TRANSCEIVER_INFO",
                "TRANSCEIVER_STATUS",
                "VLAN_MEMBER_TABLE",
                "VLAN_TABLE"
            },
            "keys_to_skip_comp": set(),
            "keys_skip_val_comp": set()
        }
    }


def init_global_data():
    global tor_data, managed_files, config_db_data_orig

    for k in init_data:
        if not init_data[k]:
            assert False, "missing init_data for {}".format(k)


    tor_data.update({
            "name": { "local": init_data["switch_name"], "remote": "" },
            "mgmt_ip": { "local": "", "remote": "" },
            "ip": { "local": "", "remote": "" },
            "ipv6": { "local": "", "remote": "" },
            "links": [{ "local": { "alias": "", "sonic_name": ""}, "remote": "" }],
            "hwsku": { "local": "", "remote": "" },
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
    log_error("failure: {}".format(m))
    assert False, m


def match_key(key, kset):
    for k in kset:
        if key.startswith(k):
            return True
    return False


def chk_for_pfc_wd(duthost, duthost_name, data_dir):
    ret = False
    res = duthost.shell('redis-dump -d 4 --pretty -k \"DEVICE_METADATA|localhost\"')
    meta_data = json.loads(res["stdout"])
    pfc_status = meta_data["DEVICE_METADATA|localhost"]["value"].get("default_pfcwd_status", "")
    log_debug("pfc_status={}".format(pfc_status))

    if pfc_status == "enable":
        res = duthost.shell('redis-dump -d 4 --pretty -k \"PFC_WD*\"')
        pfc_wd_data = json.loads(res["stdout"])
        if len(pfc_wd_data):
            ret = True
    else:
        # pfc is not enabled; return True, as there will not be any pfc to check
        ret = True
    return ret

def set_running_in_switch():
    global running_in_switch

    running_in_switch = True


def dut_dump(redis_cmd, duthost, duthost_name, data_dir, fname):
    db_read = {}
    if not running_in_switch:
        duthost.shell("{} -o /tmp/{}.json".format(redis_cmd, fname))
        duthost.fetch(src="/tmp/{}.json".format(fname), dest=data_dir)
        with open("{}/{}/tmp/{}.json".format(data_dir, duthost_name, fname), "r") as s:
            db_read = json.load(s)
    else:
        os.system("{} -o {}/tmp/{}.json".format(redis_cmd, data_dir, fname))
        with open("{}/tmp/{}.json".format(data_dir, fname), "r") as s:
            db_read = json.load(s)
    return db_read


def get_dump(duthost, duthost_name, db_name, db_info, dir_name, data_dir):
    db_no = db_info["db_no"]
    lst_keys = db_info["keys_to_compare"]

    db_read = {}
    if not lst_keys:
        db_read = dut_dump("redis-dump -d {} --pretty".format(db_no),
                duthost, duthost_name, data_dir, db_name)
    else:
        for k in lst_keys:
            fname = "{}_{}.json".format(k, db_name)
            cmd = 'redis-dump -d {} --pretty -k \"{}*\"'.format(db_no, k)
            db_read.update(dut_dump(cmd, duthost, duthost_name, data_dir, fname))

    keys_skip_cmp = db_info["keys_to_skip_comp"]
    keys_skip_val = db_info["keys_skip_val_comp"]

    db_write = {}
    for k in db_read:
        # Transient keys start with "_"; Hence skipped
        if ((not k.startswith("_")) and (not match_key(k, keys_skip_cmp))):
            db_write[k] = {} if match_key(k, keys_skip_val) else db_read[k]

    dst_file = os.path.join(dir_name, "{}.json".format(db_name))
    with open(dst_file, "w") as s:
        s.write(json.dumps(db_write, indent=4, default=str))
    
    log_info("Written dst_file: {}".format(dst_file))

    
def take_DB_dumps(duthost, duthost_name, dir_name, data_dir):
    for db_name, db_info in scan_dbs.items():
        get_dump(duthost, duthost_name, db_name, db_info, dir_name, data_dir)

    log_info("created in dir = {}".format(dir_name))


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

    fname = "{}.json".format(db_name)
    with open(os.path.join(orig_db_dir, fname), "r") as s:
        orig_data = json.load(s)

    with open(os.path.join(clet_db_dir, fname), "r") as s:
        clet_data = json.load(s)

    if clet_data == orig_data:
        log_info("{} compared good orig={} clet={}".format(db_name, orig_db_dir, clet_db_dir))
        return 0

    orig_keys = set(sorted(orig_data.keys()))
    clet_keys = set(sorted(clet_data.keys()))

    diff = orig_keys - clet_keys
    for k in diff:
        log_error("{}: Missing key: {}".format(fname, k))
        mismatch_cnt += 1
        if not msg:
            msg = "Missing key: {}".format(k)

    diff = clet_keys - orig_keys
    for k in diff:
        log_info("{}: New key:  {}".format(fname, k))

    for k in orig_keys.intersection(clet_keys):
        if orig_data[k] != clet_data[k]:
            if orig_data[k]["type"] != clet_data[k]["type"]:
                log_error("{}: mismatch key:{} type:{} != {}".format(
                    fname, k, orig_data[k]["type"], clet_data[k]["type"]))
                mismatch_cnt += 1
                if not msg:
                    msg = "mismatch key:{} type:{} != {}".format(
                            k, orig_data[k]["type"], clet_data[k]["type"])


            if not cmp_value(orig_data[k]["value"], clet_data[k]["value"]):
                log_error("{}: mismatch key:{} {} != {}".format(
                    fname, k, orig_data[k]["value"], clet_data[k]["value"]))
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
    

def main():
    set_print()
    print("Calling compare dumps")
    ret, msg = compare_dumps("logs/AddRack/orig", "logs/AddRack/clet")
    print("ret = {} msg={}".format(ret, msg))

if __name__ == "__main__":
    main()

