#! /usr/bin/env python

import argparse
import os
import socket
import time
import yaml

from helpers import *
from common import *
import files_create

def _pause(m, t):
    log_debug("{}; Sleeping for {} seconds".format(m, t))
    time.sleep(t)


def _load_minigraph():
    os.system("sudo config load_minigraph -y")
    _pause("load minigraph", 180)


def main():
    # Used only when running in switch
    #
    global managed_files, init_data, do_print

    set_print()

    if not os.path.exists("/etc/sonic/sonic_version.yml"):
        print("run in SONiC switch only")
        return -1
    
    ct_dir = os.path.dirname(os.path.realpath(__file__))
    base_dir = "{}/test".format(ct_dir)

    parser=argparse.ArgumentParser(description="configlet create params")
    parser.add_argument("-d", "--dir", help="dir to use for created files",
            default=base_dir)
    args = parser.parse_args()

    base_dir = args.dir
    data_dir    = "{}/AddRack".format(base_dir)
    files_dir   = "{}/files".format(data_dir)
    orig_db_dir = "{}/orig".format(data_dir)
    clet_db_dir = "{}/clet".format(data_dir)
    tmp_db_dir = "{}/tmp".format(data_dir)

    os.system("rm -rf {}".format(base_dir))
    for i in [ base_dir, data_dir, orig_db_dir, clet_db_dir, files_dir, tmp_db_dir ]:
        log_debug("create dir {}".format(i))
        os.mkdir(i)

    sonic_dir = "{}/{}/etc/sonic".format(data_dir, socket.gethostname().lower())
    os.system("mkdir -p {}".format(sonic_dir))

    for i in [ "minigraph.xml", "config_db.json" ]:
        os.system("cp /etc/sonic/{} {}".format(i, sonic_dir))


    init_data["files_dir"] = files_dir
    init_data["data_dir"] = data_dir
    init_data["switch_name"] = socket.gethostname().lower()
    d = {}
    with open("/etc/sonic/sonic_version.yml", "r") as s:
        d = yaml.safe_load(s)
    init_data["version"] = d["build_version"]
    is_mlnx = (d["asic_type"].lower() == "mellanox")

    _load_minigraph()

    take_DB_dumps(None, init_data["switch_name"], orig_db_dir, data_dir)

    # Create required files
    #
    files_create.do_run(is_mlnx)

    # Copy new files to /etc/sonic
    #
    os.system("sudo cp {} /etc/sonic/minigraph.xml".format(
        managed_files["minigraph_wo_to"]))

    os.system("sudo cp {} /etc/sonic/add_Rack.json".format(
        managed_files["configlet"]))

    os.system("sudo cp {}/everlow_delete.json /etc/sonic/".format(ct_dir))

    _load_minigraph()

    os.system("sudo configlet -d -j /etc/sonic/everlow_delete.json")

    tor_ifname = tor_data["links"][0]["local"]["sonic_name"]
    os.system("sudo config interface shutdown {}".format(tor_ifname))
    _pause("interface shutdown", 60)

    os.system("sudo configlet -u -j /etc/sonic/add_Rack.json")
    _pause("apply configlet", 180)

    tor_ifname = tor_data["links"][0]["local"]["sonic_name"]
    os.system("sudo config interface startup {}".format(tor_ifname))
    _pause("interface startup", 60)

    take_DB_dumps(None, init_data["switch_name"], clet_db_dir, data_dir)
    ret = compare_dumps(orig_db_dir, clet_db_dir)
    assert not ret, "Failed to compare dumps"

    log_info("test ran successfully")


def restore_mini():
    backup = "/etc/sonic/orig/minigraph.xml.addRack.orig"
    exist = "/etc/sonic/minigraph.xml"

    if os.path.exists(backup):
        os.system("sudo cp {} {}".format(backup, exist))
        log_debug("restored minigraph")
        return True
    else:
        os.system("sudo mkdir -p /etc/sonic/orig")
        os.system("sudo cp {} {}".format(exist, backup))
        log_debug("created minigraph backup")
        return False


if __name__ == "__main__":
    set_running_in_switch()
    try:
        # restore original
        restore_mini()
        main()
    finally:
        log_info("restoring minigraph")
        restore_mini()


