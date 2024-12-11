#!/usr/bin/env python3

import subprocess
import re
import time

from sonic_py_common.logger import Logger
from swsscommon.swsscommon import ConfigDBConnector

lossless_profile_name_pattern = 'pg_lossless_([1-9][0-9]*000)_([1-9][0-9]*m)_profile'
zero_profile_name_pattern = '.*zero_profile'
zero_pool_name_pattern = '.*zero_pool'
zero_profiles_to_normal_profiles = {
    '[BUFFER_PROFILE|ingress_lossy_pg_zero_profile]': '[BUFFER_PROFILE|ingress_lossy_profile]',
    '[BUFFER_PROFILE|ingress_lossless_zero_profile]': '[BUFFER_PROFILE|ingress_lossless_profile]',
    '[BUFFER_PROFILE|ingress_lossy_zero_profile]': '[BUFFER_PROFILE|ingress_lossy_profile]',
    '[BUFFER_PROFILE|egress_lossless_zero_profile]': '[BUFFER_PROFILE|egress_lossless_profile]',
    '[BUFFER_PROFILE|egress_lossy_zero_profile]': '[BUFFER_PROFILE|egress_lossy_profile]',
    'ingress_lossy_pg_zero_profile': 'ingress_lossy_profile',
    'ingress_lossless_zero_profile': 'ingress_lossless_profile',
    'ingress_lossy_zero_profile': 'ingress_lossy_profile',
    'egress_lossless_zero_profile': 'egress_lossless_profile',
    'egress_lossy_zero_profile': 'egress_lossy_profile'
    }
logger = Logger()


def _replace_buffer_profile_lists(config_db, table):
    ingress_profile_lists = config_db.get_table(table)
    for key, profile_list in list(ingress_profile_lists.items()):
        if re.search(zero_profile_name_pattern, profile_list['profile_list']):
            zero_profiles = profile_list['profile_list'].split(',')
            normal_profiles = ''
            for profile in zero_profiles:
                normal_profile = zero_profiles_to_normal_profiles.get(profile)
                if normal_profile:
                    normal_profiles += normal_profile + ','
            profile_list['profile_list'] = normal_profiles[:-1]
            config_db.set_entry(table, key, profile_list)


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
    lossless_pgs = {}
    zero_pgs = []
    for key, pg in list(pgs.items()):
        if re.search(lossless_profile_name_pattern, pg['profile']):
            config_db.set_entry('BUFFER_PG', key, None)
            pg['profile'] = 'NULL'
            lossless_pgs[key] = pg
            # We can not apply profile as NULL for now. The traditional buffer manager can not handle them

        if re.search(zero_profile_name_pattern, pg['profile']):
            normal_profile = zero_profiles_to_normal_profiles.get(pg['profile'])
            if normal_profile:
                pg['profile'] = normal_profile
                config_db.set_entry('BUFFER_PG', key, pg)
                zero_pgs.append(key)

    logger.log_notice("Lossless PGs have been removed from BUFFER_PG and \
                      will be applied after dynamic buffer manager starts {}".format(lossless_pgs))
    logger.log_notice("Zero PGs have been replaced by normal profile {}".format(zero_pgs))

    queues = config_db.get_table('BUFFER_QUEUE')
    zero_queues = []
    for key, queue in list(queues.items()):
        if re.search(zero_profile_name_pattern, queue['profile']):
            normal_profile = zero_profiles_to_normal_profiles.get(queue['profile'])
            if normal_profile:
                queue['profile'] = normal_profile
                config_db.set_entry('BUFFER_QUEUE', key, queue)
                zero_queues.append(key)

    logger.log_notice("Queues referencing zero profiles have been removed from BUFFER_QUEUE and \
                      will be replaced by normal profile: {}".format(zero_queues))

    _replace_buffer_profile_lists(config_db, 'BUFFER_PORT_INGRESS_PROFILE_LIST')
    _replace_buffer_profile_lists(config_db, 'BUFFER_PORT_EGRESS_PROFILE_LIST')

    # Remove dynamically generated profiles
    profiles = config_db.get_table('BUFFER_PROFILE')
    dynamic_profile = []
    zero_profile = []
    for key, profile in list(profiles.items()):
        if re.search(lossless_profile_name_pattern, key):
            config_db.set_entry('BUFFER_PROFILE', key, None)
            dynamic_profile.append(key)
        elif re.search(zero_profile_name_pattern, key):
            config_db.set_entry('BUFFER_PROFILE', key, None)
            zero_profile.append(key)

    logger.log_notice("Dynamically generated profiles and zero profiles have been removed from BUFFER_PROFILE: {} {}"
                      .format(dynamic_profile, zero_profile))

    pools = config_db.get_table('BUFFER_POOL')
    zero_pool = []
    for key, pool in list(pools.items()):
        if re.search(zero_pool_name_pattern, key):
            config_db.set_entry('BUFFER_POOL', key, None)
            zero_pool.append(key)

    logger.log_notice("Zero pools have been removed from BUFFER_TABLE: {}".format(zero_pool))

    # Stop the buffermgrd
    # We don't stop the buffermgrd at the beginning
    # because we need it to remove tables from APPL_DB while their counter part are removed from CONFIG_DB

    # Before stopping buffermgrd, need to make sure buffermgrd is running,
    # otherwise it might cause some side-effect timing issue
    check_buffermgrd_is_running()
    command = 'docker exec swss supervisorctl stop buffermgrd'
    proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
    _, err = proc.communicate()
    if err:
        print(("Failed to stop buffermgrd {}".format(err)))
        exit(1)

    logger.log_notice("Daemon buffermgrd has been stopped")

    return lossless_pgs


def check_buffermgrd_is_running():
    cmd_get_buffermgrd_status = "docker exec swss supervisorctl status buffermgrd"
    max_try_times = 10
    try_times = 0
    while try_times < max_try_times:
        try_times += 1
        proc = subprocess.Popen(cmd_get_buffermgrd_status, shell=True, stdout=subprocess.PIPE)
        output, err = proc.communicate()
        if err:
            logger.log_notice("try_times:{}. Failed to check buffermgrd status: {}".format(try_times, err))
        else:
            if "RUNNING" in output.decode('utf-8'):
                logger.log_notice("Daemon buffermgrd is running")
                return True
            else:
                logger.log_notice("try_times:{}. Daemon buffermgrd is not running".format(try_times))
        time.sleep(2)

    logger.log_notice("Daemon buffermgrd is not running, after checking {} times".format(max_try_times))
    exit(1)


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
    shared_headroom_pool = False
    for key, pool in list(pools.items()):
        if key in dynamic_size_pools:
            config_db.set_entry('BUFFER_POOL', key, None)
            if 'size' in list(pool.keys()):
                pool.pop('size')
            if 'xoff' in list(pool.keys()):
                pool.pop('xoff')
                shared_headroom_pool = True
            config_db.set_entry('BUFFER_POOL', key, pool)

    logger.log_notice("Sizes have been removed from {}".format(dynamic_size_pools))

    # Create lossless PGs
    if lossless_pgs:
        for key, pg in list(lossless_pgs.items()):
            config_db.set_entry('BUFFER_PG', key, pg)
        logger.log_notice("Lossless PGs have been created for {}".format(list(lossless_pgs.keys())))
    else:
        # The lossless_pgs can be None if this script is called immediately after reloading minigraph
        # because the lossless PGs hasn't been inserted into CONFIG_DB by traditional buffer manager
        ports = config_db.get_keys('PORT')
        for port in ports:
            config_db.set_entry('BUFFER_PG', '{}|3-4'.format(port), {'profile': 'NULL'})
        logger.log_notice("No lossless PG in CONFIG_DB, lossless PGs have been created for all ports {}".format(ports))

    # Add necessary tables to run dynamic model
    default_lossless_param = {'default_dynamic_th': '0'}
    if shared_headroom_pool:
        default_lossless_param['over_subscribe_ratio'] = '2'
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
        print(("Failed to start buffermgrd {}".format(err)))
        exit(1)

    logger.log_notice("Daemon buffermgrd has been started")


# Connect to the CONFIG_DB
db_kwargs = {}
config_db = ConfigDBConnector(**db_kwargs)
config_db.db_connect('CONFIG_DB')

# Don't enable dynamic buffer calculation if it is not a default SKU
metadata = config_db.get_entry('DEVICE_METADATA', 'localhost')
if 'ACS-MSN' not in metadata['hwsku'] and 'ACS-SN' not in metadata['hwsku']:
    print("Don't enable dynamic buffer calculation for non-default SKUs")
    exit(0)

if 'dynamic' == metadata.get('buffer_model'):
    print("The current model is already dynamic model")
    exit(0)

lossless_pgs = stop_traditional_buffer_model(config_db)

start_dynamic_buffer_model(config_db, lossless_pgs, metadata)
