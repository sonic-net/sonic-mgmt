#!/usr/bin/env python3
import argparse
import json
import logging
import os
import re
import sys

import yaml

logging.basicConfig(
    stream=sys.stdout,
    level=logging.DEBUG,
    format="%(asctime)s %(filename)s#%(lineno)d %(levelname)s - %(message)s"
)

logger = logging.getLogger(__name__)

_self_dir = os.path.dirname(os.path.abspath(__file__))
# base_path = os.path.realpath(os.path.join(_self_dir, "../.."))
# if base_path not in sys.path:
#     sys.path.append(base_path)
ANSIBLE_PATH = os.path.realpath(os.path.join(_self_dir, "../../ansible"))

if ANSIBLE_PATH not in sys.path:
    sys.path.append(ANSIBLE_PATH)

GRAPH_PATH = os.path.join(ANSIBLE_PATH, "files")

from devutil.devices.factory import init_hosts  # noqa E402

TESTBED_FILE = "./testbed.yaml"
VEOS_FILE = "./veos"


def remove_dangling_images(host_name_list, inv_file):
    logger.info("====================================starts====================================")

    logger.info(host_name_list)

    if len(host_name_list) > 0:
        server_hosts = init_hosts(inv_file, host_name_list)

        # This command specifically targets and removes "dangling" images, which are images that have no tag associated
        # with them. These are typically leftover or unused images that can consume disk space.
        rst = server_hosts.shell('docker images -q --filter "dangling=true" | xargs docker rmi',
                                 module_ignore_errors=True)

        logger.info(json.dumps(rst, indent=4))
    else:
        logger.info("Hosts list is empty, skip.")

    logger.info("====================================ends====================================")


def main(args):
    inventory = args.inventory
    try:
        # Get all testbeds servers
        with open(TESTBED_FILE, "r") as file:
            testbeds = yaml.safe_load(file)

        servers_set = set()

        for testbed in testbeds:
            server = testbed.get("server", None)
            if testbed.get("inv_name") == inventory:
                servers_set.add(server)

        # Get all testbeds servers hostnames
        with open(VEOS_FILE, "r") as file:
            inv_yaml = yaml.safe_load(file)

        # Regular expression pattern to match the desired part
        pattern = r'host_vars/([A-Z0-9-]+)\.yml'
        server_host_name_list = []

        for key in inv_yaml:
            if key in servers_set:
                file_name = inv_yaml[key]["vars"]["host_var_file"]
                server_name = re.search(pattern, file_name, re.IGNORECASE).group(1)
                server_host_name_list.append(server_name)

        # Clean old images on testbeds servers
        remove_dangling_images(server_host_name_list, VEOS_FILE)

    except Exception as e:
        logger.error("Exception raised: {}".format(repr(e)))
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description="Tool for cleaning unused old images on servers.")

    parser.add_argument(
        "-i", "--inventory",
        dest="inventory",
        help="Ansible inventory file")

    args = parser.parse_args()

    main(args)
