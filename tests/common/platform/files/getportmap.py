#!/usr/bin/env python
# This script runs on the DUT and is intended to retrieve the portmapping from logical interfaces to physical ones
# The way the port mapping retrieved is exactly the same as what xcvrd does

import os
import json
import argparse

import sonic_platform_base.sonic_sfp.sfputilhelper
from sonic_py_common import device_info
from sonic_py_common import multi_asic

asic_id = None
PORT_CONFIG_FILE = "port_config.ini"

parser = argparse.ArgumentParser(description='Get the interface list for an asic',
                                     formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('-asicid', '--asic_index', type=str, help='the asic instance', default=None)

args = parser.parse_args()
if args.asic_index:
    asic_id = args.asic_index

platform_sfputil = sonic_platform_base.sonic_sfp.sfputilhelper.SfpUtilHelper()
if multi_asic.is_multi_asic():
    # load and parse the port configuration file on DUT
    (platform_path, hwsku_path) = device_info.get_paths_to_platform_and_hwsku_dirs()

    # handle case where asic_id input is "all" or a valid asic index.
    if asic_id == "all":
        platform_sfputil.read_all_porttab_mappings(hwsku_path, multi_asic.get_num_asics())
    else:
        port_config_path = os.path.join(hwsku_path, asic_id, PORT_CONFIG_FILE)
        platform_sfputil.read_porttab_mappings(port_config_path)
else:
    port_config_path = device_info.get_path_to_port_config_file()
    platform_sfputil.read_porttab_mappings(port_config_path)

# print the mapping to stdout in json format
print json.dumps(platform_sfputil.logical_to_physical)

# json will be loaded by sonic-mgmt
