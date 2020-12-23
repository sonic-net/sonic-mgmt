#!/usr/bin/env python
# This script runs on the DUT and is intended to retrieve the portmapping from logical interfaces to physical ones
# The way the port mapping retrieved is exactly the same as what xcvrd does

import json

import sonic_platform_base.sonic_sfp.sfputilhelper
from sonic_py_common import device_info

# load and parse the port configuration file on DUT
port_config_path = device_info.get_path_to_port_config_file()
platform_sfputil = sonic_platform_base.sonic_sfp.sfputilhelper.SfpUtilHelper()
platform_sfputil.read_porttab_mappings(port_config_path)

# print the mapping to stdout in json format
print json.dumps(platform_sfputil.logical_to_physical)

# json will be loaded by sonic-mgmt
