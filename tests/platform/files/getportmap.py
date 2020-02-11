#!/usr/bin/env python
# This script runs on the DUT and is intended to retrieve the portmapping from logical interfaces to physical ones
# The way the port mapping retrieved is exactly the same as what xcvrd does

import sfputil
import json
import subprocess

PLATFORM_ROOT_PATH = '/usr/share/sonic/device'
SONIC_CFGGEN_PATH = '/usr/local/bin/sonic-cfggen'
HWSKU_KEY = 'DEVICE_METADATA.localhost.hwsku'
PLATFORM_KEY = 'DEVICE_METADATA.localhost.platform'
PLATFORM_ROOT_DOCKER = "/usr/share/sonic/platform"

platform_sfputil = sfputil.SfpUtil()

# Returns platform and HW SKU
def get_hwsku():
    proc = subprocess.Popen([SONIC_CFGGEN_PATH, '-d', '-v', HWSKU_KEY],
                            stdout=subprocess.PIPE,
                            shell=False,
                            stderr=subprocess.STDOUT)
    stdout = proc.communicate()[0]
    proc.wait()
    hwsku = stdout.rstrip('\n')

    return hwsku


# Returns path to port config file
def get_path_to_port_config_file():
    # Get platform and hwsku
    hwsku = get_hwsku()

    # Load platform module from source
    platform_path = PLATFORM_ROOT_DOCKER
    hwsku_path = "/".join([platform_path, hwsku])

    port_config_file_path = "/".join([hwsku_path, "port_config.ini"])

    return port_config_file_path


port_config_path = get_path_to_port_config_file()
platform_sfputil.read_porttab_mappings(port_config_path)

# print the mapping to stdout in json format
print json.dumps(platform_sfputil.logical_to_physical)

# json will be loaded by sonic-mgmt
