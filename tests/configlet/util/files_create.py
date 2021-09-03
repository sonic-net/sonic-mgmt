#! /usr/bin/env python

import argparse
import json
import yaml

from helpers import *
from common import *
import strip
import configlet


def do_run():
    init_global_data()

    strip.main(init_data["files_dir"])
    configlet.main(init_data["files_dir"])

    log_info("Managed files: {}".format(json.dumps(managed_files, indent=4)))


def main():
    global managed_files, init_data

    parser=argparse.ArgumentParser(description="configlet create params")
    parser.add_argument("-s", "--switch", help="Name of the switch",
            default=init_data["switch_name"])
    parser.add_argument("-d", "--filesdir", default=init_data["files_dir"],
            help="Dir with minigraph & config_db.json")
    parser.add_argument("-v", "--version", default=init_data["version"],
            help="OSVersion. sample: 20191130.76")

    args = parser.parse_args()

    init_data["version"] = args.version
    init_data["files_dir"] = args.filesdir
    init_data["data_dir"] = "/"
    init_data["switch_name"] = args.switch

    if not init_data["version"]:
        if os.path.exists("/etc/sonic/sonic_version.yml"):
            with open("/etc/sonic/sonic_version.yml", "r") as s:
                d = yaml.safe_load(s)
                init_data["version"] = d["build_version"]
    if not init_data["version"]:
        report_error("Unable to get OS version")

    do_run()


if __name__ == "__main__":
    main()

