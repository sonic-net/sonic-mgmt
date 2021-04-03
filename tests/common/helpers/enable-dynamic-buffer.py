#!/usr/bin/env python3

import subprocess
import re

from sonic_py_common.logger import Logger
from swsscommon.swsscommon import ConfigDBConnector

lossless_profile_name_pattern = 'pg_lossless_([1-9][0-9]*000)_([1-9][0-9]*m)_profile'
logger = Logger()

def stop_traditional_buffer_model(config_db):
    """
    Stop the traditional buffer model

    Args:
        config_db: object representing the CONFIG_DB connection

    Returns:
        lossless_pgs: a dict containing the lossless PGs fetched from CONFIG_DB

    Description:
        1. Remove lossless PGs from BUFFER_PG table.
        2. Remove dynamically generated profiles from BUFFER_PROFILE table.
        3. Stop the buffermgrd
    """
    # Remove lossless PGs from BUFFER_PG table
    # A PG whose profile matches pg_lossless_<speed>_<cable-length>_profile is treated as a lossless PG
    pgs = config_db.get_table('BUFFER_PG')
    lossless_pgs = {};
    for key, pg in pgs.items():
        if re.search(lossless_profile_name_pattern, pg['profile']):
            config_db.set_entry('BUFFER_PG', key, None)
            pg['profile'] = 'NULL'
            lossless_pgs[key] = pg

    logger.log_notice("Lossless PGs have been removed from BUFFER_PG: {}".format(lossless_pgs.keys()))

    # Remove dynamically generated profiles
    profiles = config_db.get_table('BUFFER_PROFILE')
    dynamic_profile = []
    for key, profile in profiles.items():
        if re.search(lossless_profile_name_pattern, key):
            config_db.set_entry('BUFFER_PROFILE', key, None)
            dynamic_profile.append(key)

    logger.log_notice("Dynamically generated profiles have been removed from BUFFER_PROFILE: {}".format(dynamic_profile))

    # Stop the buffermgrd
    # We don't stop the buffermgrd at the beginning
    # because we need it to remove tables from APPL_DB while their counter part are removed from CONFIG_DB
    command = 'docker exec swss supervisorctl stop buffermgrd'
    proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
    _, err = proc.communicate()
    if err:
        print("Failed to stop buffermgrd {}".format(err))
        exit(1)

    logger.log_notice("Daemon buffermgrd has been stopped")

    return lossless_pgs


def start_dynamic_buffer_model(config_db, lossless_pgs, metadata):
    """
    Start the dynamic buffer model

    Args:
        config_db: object representing the CONFIG_DB connection
        lossless_pgs: a dict containing the lossless PGs fetched from CONFIG_DB
        metadata: a dict containing the DEVICE_METADATA|localhost fetched from CONFIG_DB

    Description:
        1. Remove the size for dynamic size buffer pools
        2. Create lossless PGs according to lossless_pgs
           If lossless_pgs is empty, create lossless PGs for each port
           This can happen when the system is just starting and buffermgrd hasn't created lossless PGs yet
        3. Add necessary tables to run dynamic model:
           - DEFAULT_LOSSLESS_BUFFER_PARAMETER
           - LOSSLESS_TRAFFIC_PATTERN
        4. Update DEVICE_METADATA
        5. Start the buffermgrd
    """
    # Remove size for dynamic size buffer pools
    # By default, all pools except egress_lossless_pool are dynamic size pools
    dynamic_size_pools = ['ingress_lossless_pool', 'ingress_lossy_pool', 'egress_lossy_pool']
    pools = config_db.get_table('BUFFER_POOL')
    for key, pool in pools.items():
        if key in dynamic_size_pools:
            config_db.set_entry('BUFFER_POOL', key, None)
            if 'size' in pool.keys():
                pool.pop('size')
            config_db.set_entry('BUFFER_POOL', key, pool)

    logger.log_notice("Sizes have been removed from {}".format(dynamic_size_pools))

    # Create lossless PGs
    if lossless_pgs:
        for key, pg in lossless_pgs.items():
            pg['profile'] = 'NULL'
            config_db.set_entry('BUFFER_PG', key, pg)
        logger.log_notice("Lossless PGs have been created for {}".format(lossless_pgs.keys()))
    else:
        ports = config_db.get_keys('PORT')
        for port in ports:
            config_db.set_entry('BUFFER_PG', '{}|3-4'.format(port), {'profile': 'NULL'})
        logger.log_notice("No lossless PG in CONFIG_DB, lossless PGs have been created for all ports {}".format(ports)) 

    # Add necessary tables to run dynamic model
    default_lossless_param = {'default_dynamic_th': '0'}
    config_db.set_entry('DEFAULT_LOSSLESS_BUFFER_PARAMETER', 'AZURE', default_lossless_param)

    logger.log_notice("DEFAULT_LOSSLESS_BUFFER_PARAMETER|AZURE has been created")

    lossless_traffic_pattern = {'mtu': '1024', 'small_packet_percentage': '100'}
    config_db.set_entry('LOSSLESS_TRAFFIC_PATTERN', 'AZURE', lossless_traffic_pattern)

    logger.log_notice("LOSSLESS_TRAFFIC_PATTERN|AZURE has been created")

    # Prepare the DEVICE_METADATA
    metadata['buffer_model'] = 'dynamic'
    config_db.set_entry('DEVICE_METADATA', 'localhost', metadata)

    logger.log_notice("buffer_model has been updated to dynamic")

    # Start the buffermgrd
    command = 'docker exec swss supervisorctl start buffermgrd'
    proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
    _, err = proc.communicate()
    if err:
        print("Failed to start buffermgrd {}".format(err))
        exit(1)

    logger.log_notice("Daemon buffermgrd has been started")


# Connect to the CONFIG_DB
db_kwargs = {}
config_db = ConfigDBConnector(**db_kwargs)
config_db.db_connect('CONFIG_DB')

# Don't enable dynamic buffer calculation if it is not a default SKU
metadata = config_db.get_entry('DEVICE_METADATA', 'localhost')
if 'ACS-MSN' not in metadata['hwsku']:
    print("Don't enable dynamic buffer calculation for non-default SKUs")
    exit(0)

lossless_pgs = stop_traditional_buffer_model(config_db)

start_dynamic_buffer_model(config_db, lossless_pgs, metadata)
