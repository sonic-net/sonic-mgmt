#! /usr/bin/env python

import argparse
import json
import yaml

from helpers import *
from common import *
import strip
import configlet


def do_run(is_mlnx, is_storage_backend):
    init_global_data()

    strip.main(init_data["files_dir"])
    configlet.main(init_data["files_dir"], is_mlnx, is_storage_backend)

    log_info("Managed files: {}".format(json.dumps(managed_files, indent=4)))


def main():
    # Test code to help run in switch to look at generated files.
    # Used only when running in switch
    # This helps create all files, minigraph.xml w/o T0 and configlet
    #
    import socket

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

    os.system("rm -rf {}".format(base_dir))
    for i in [ base_dir, data_dir, orig_db_dir, clet_db_dir, files_dir ]:
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

    do_run(is_mlnx, False)


if __name__ == "__main__":
    main()

