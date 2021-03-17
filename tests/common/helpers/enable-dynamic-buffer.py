#!/usr/bin/env python3

import os
import argparse
import json
import sys
import traceback
import subprocess
import re

from sonic_py_common import device_info, logger
from swsscommon.swsscommon import SonicV2Connector, ConfigDBConnector, SonicDBConfig

lossless_profile_name_pattern = 'pg_lossless_([1-9][0-9]*000)_([1-9][0-9]*m)_profile'

# Connect to the CONFIG_DB
db_kwargs = {}
config_db = ConfigDBConnector(**db_kwargs)
config_db.db_connect('CONFIG_DB')

# Don't enable dynamic buffer calculation if it is a MSFT SKU
metadata = config_db.get_entry('DEVICE_METADATA', 'localhost')
if 'ACS-MSN' not in metadata['hwsku']:
    print("Don't enable dynamic buffer calculation for MSFT SKUs")
    exit(0)

# Remove lossless PGs from BUFFER_PG table
pgs = config_db.get_table('BUFFER_PG')
lossless_pgs = {};
for key, pg in pgs.items():
    if re.search(lossless_profile_name_pattern, pg['profile']):
        config_db.set_entry('BUFFER_PG', key, None)
        lossless_pgs[key] = pg

# Remove dynamic generated profiles
profiles = config_db.get_table('BUFFER_PROFILE')
for key, profile in profiles.items():
    if re.search(lossless_profile_name_pattern, key):
        config_db.set_entry('BUFFER_PROFILE', key, None)

# Stop the buffermgrd
# We don't stop the buffermgrd at the beginning
# because we need it to remove tables from APPL_DB while their counter part are removed from CONFIG_DB
command = 'docker exec swss supervisorctl stop buffermgrd'
proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
_, err = proc.communicate()
if err:
    print("Failed to stop buffermgrd {}".format(err))

# Remove size for dynamic size buffer pools
dynamic_size_pools = ['ingress_lossless_pool', 'ingress_lossy_pool', 'egress_lossy_pool']
pools = config_db.get_table('BUFFER_POOL')
for key, pool in pools.items():
    if key in dynamic_size_pools:
        config_db.set_entry('BUFFER_POOL', key, None)
        if 'size' in pool.keys():
            pool.pop('size')
        config_db.set_entry('BUFFER_POOL', key, pool)

# Add buffer PGs who uses dynamic generated profiles
for key, pg in lossless_pgs.items():
    pg['profile'] = 'NULL'
    config_db.set_entry('BUFFER_PG', key, pg)

# Add necessary tables to run dynamic model
default_lossless_param = {'default_dynamic_th': '0'}
config_db.set_entry('DEFAULT_LOSSLESS_BUFFER_PARAMETER', 'AZURE', default_lossless_param)

lossless_traffic_pattern = {'mtu': '1024', 'small_packet_percentage': '100'}
config_db.set_entry('LOSSLESS_TRAFFIC_PATTERN', 'AZURE', lossless_traffic_pattern)

# Prepare the DEVICE_METADATA
metadata['buffer_model'] = 'dynamic'
config_db.set_entry('DEVICE_METADATA', 'localhost', metadata)

# Start the buffermgrd
command = 'docker exec swss supervisorctl start buffermgrd'
proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
_, err = proc.communicate()
if err:
    print("Failed to start buffermgrd {}".format(err))
