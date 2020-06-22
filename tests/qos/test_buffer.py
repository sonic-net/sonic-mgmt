import logging
import os
import sys
import time
import re

import pytest

from tests.common import config_reload

profile_format = 'pg_lossless_{}_{}_profile'

default_cable_length_list = ['5m', '40m', '300m']
default_mtu = '9100'

def check_pool_size(duthost, expected_pool_size):
    pool_size = duthost.shell('redis-cli hget "BUFFER_POOL_TABLE:ingress_lossless_pool" size')['stdout']
    assert int(pool_size) == expected_pool_size, "Pool size isn't correct: expected {} but got {}".format(expected_pool_size, pool_size)


def check_profile(duthost, pg, expected_profile):
    profile = duthost.shell('redis-cli hget {} profile'.format(pg))['stdout'][1:-1]
    assert profile == 'BUFFER_PROFILE_TABLE:' + expected_profile, 'Expected profile {} not found'.format(expected_profile)


def check_pfc_enable(duthost, port, expected_pfc_enable_map):
    pfc_enable = duthost.shell('redis-cli -n 4 hget "PORT_QOS_MAP|{}" pfc_enable'.format(port))['stdout']
    assert expected_pfc_enable_map == pfc_enable, \
        "Expected pfc enable map {} doesn't match {}".format(expected_pfc_enable_map, pfc_enable)


def detect_ingress_pool_number(duthost):
    pools = duthost.shell('redis-cli -n 4 keys "BUFFER_POOL|ingress*"')['stdout']
    return len(pools.split())


def check_lossless_profile_removed(duthost, profile):
    time.sleep(10)
    profile_info = duthost.shell('redis-cli -n 6 hgetall "BUFFER_PROFILE_TABLE|{}"'.format(profile))['stdout']
    assert not profile_info, "Profile {} isn't removed from STATE_DB".format(profile)
    profile_info = duthost.shell('redis-cli hgetall "BUFFER_PROFILE_TABLE:{}"'.format(profile))['stdout']
    assert not profile_info, "Profile {} isn't removed from APPL_DB".format(profile)
    logging.info('Profile {} has been removed from STATE_DB and APPL_DB'.format(profile))


def check_dynamic_th_in_appldb(duthost, profile, expected_dynamic_th, must_exist = False):
    time.sleep(10)
    dynamic_th = duthost.shell('redis-cli hget "BUFFER_PROFILE_TABLE:{}" dynamic_th'.format(profile))['stdout']
    assert not must_exist and not dynamic_th or dynamic_th == expected_dynamic_th, "dynamic_th of profile {} in APPL_DB isn't correct".format(profile)


@pytest.fixture(params=['50000', '10000'])
def speed_to_test(request):
    '''
    @summary: used to parametrized test cases 
    @param request: pytest request object
    @return: speed_to_test
    '''
    return request.param


@pytest.fixture(params=['15m', '40m'])
def cable_len_to_test(request):
    '''
    @summary: used to parametrized test cases
    @param request: pytest request object
    @return: cable_len_to_test
    '''
    return request.param


@pytest.fixture(params=['1500', '9100'])
def mtu_to_test(request):
    '''
    @summary: used to parametrized test cases
    @param request: pytest request object
    @return: cable_len_to_test
    '''
    return request.param


lag_member_checked = False
lag_interface_port_belongs_to = None
port_under_test = None

@pytest.fixture(params=['Ethernet8'])
def port_to_test(request, duthost):
    '''
    @summary: used to parametrized test cases
    @param request: pytest request object
    @return: port_under_test
    '''
    global lag_member_checked 
    global lag_interface_port_belongs_to
    global port_under_test

    port_under_test = request.param
    if not lag_member_checked:
        portchannel_member_key = duthost.shell('redis-cli -n 4 keys "PORTCHANNEL_MEMBER|*|{}"'.format(port_under_test))['stdout']
        if portchannel_member_key:
            portchannel = portchannel_member_key.split('|')[1]
            duthost.shell('config portchannel member del {} {}'.format(portchannel, port_under_test))
            logging.info("Preparing: remove port {} from port channel {}".format(port_under_test, portchannel))
            lag_interface_port_belongs_to = portchannel

    return port_under_test


@pytest.fixture(params=['3-4', '6'])
def pg_to_test(request):
    return request.param


@pytest.fixture(scope="module", autouse=True)
def teardown_module(duthost):
    yield

    if lag_interface_port_belongs_to:
        logging.info("Tearing down: restore the port channel configuration")
        duthost.shell('config portchannel member add {} {}'.format(lag_interface_port_belongs_to, port_under_test))


def test_change_speed_cable(duthost, conn_graph_facts, port_to_test, speed_to_test, mtu_to_test, cable_len_to_test):
    '''
    @summary: change speed in different ways and observe whether the DUT behaves correctly
              if all of the speed_to_test, mtu_to_test and cable_len_to_test match the current value, the test will be skipped
    @port_to_test: on which port will the test be performed
    @speed_to_test: to what speed will the port's be changed
    @mtu_to_test: to what mtu will the port's be changed
    @cable_len_to_test: to what cable length will the port's be changed
    '''
    original_speed = duthost.shell('redis-cli -n 4 hget "PORT|{}" speed'.format(port_to_test))['stdout']
    original_cable_len = duthost.shell('redis-cli -n 4 hget "CABLE_LENGTH|AZURE" {}'.format(port_to_test))['stdout']
    profile = duthost.shell('redis-cli hget "BUFFER_PG_TABLE:{}:3-4" profile'.format(port_to_test))['stdout'][1:-1]
    original_headroom_size = duthost.shell('redis-cli hget "{}" size'.format(profile))['stdout']
    original_pool_size = duthost.shell('redis-cli hget BUFFER_POOL_TABLE:ingress_lossless_pool size')['stdout']
    number_of_pools = detect_ingress_pool_number(duthost)

    if speed_to_test == original_speed and cable_len_to_test == original_cable_len and mtu_to_test == default_mtu:
        pytest.skip('Speed, MTU and cable length matches the default value, nothing to test, skip')

    try:
        if not speed_to_test == original_speed:
            logging.info("Changing port's speed to {}".format(speed_to_test))
            duthost.shell('config interface speed {} {}'.format(port_to_test, speed_to_test))
        if not mtu_to_test == default_mtu:
            logging.info("Changing port's mtu to {}".format(mtu_to_test))
            duthost.shell('config interface mtu {} {}'.format(port_to_test, mtu_to_test))
        if not cable_len_to_test == original_cable_len:
            logging.info("Changing port's cable length to {}".format(cable_len_to_test))
            duthost.shell('config interface cable-length {} {}'.format(port_to_test, cable_len_to_test))

        check_profile_removed = cable_len_to_test not in default_cable_length_list

        time.sleep(10)
        # check whether profile is correct in PG table
        if mtu_to_test != default_mtu:
            expected_profile = 'pg_lossless_{}_{}_mtu{}_profile'.format(speed_to_test, cable_len_to_test, mtu_to_test)
            check_profile_removed = True
        else:
            expected_profile = 'pg_lossless_{}_{}_profile'.format(speed_to_test, cable_len_to_test)
        logging.info('[speed and/or cable-len and/or MTU updated] Checking whether new profile {} has been created and pfc_enable has been updated'.format(expected_profile))
        check_profile(duthost, 'BUFFER_PG_TABLE:{}:3-4'.format(port_to_test), expected_profile)
        check_pfc_enable(duthost, port_to_test, '3,4')

        # check whether profile exist
        headroom_size = duthost.shell('redis-cli hget "BUFFER_PROFILE_TABLE:{}" size'.format(expected_profile))['stdout']
        check_pool_size(duthost, (int(original_pool_size) * number_of_pools + (int(original_headroom_size) - int(headroom_size)) * 2) / number_of_pools)

        # Remove all the lossless profile on the port
        logging.info('[remove all lossless PGs] Checking pool size and pfc_enable')
        duthost.shell('config interface buffer priority-group lossless remove {} 3-4'.format(port_to_test))
        time.sleep(10)
        check_pool_size(duthost, (int(original_pool_size) * number_of_pools + int(original_headroom_size) * 2) / number_of_pools)
        check_pfc_enable(duthost, port_to_test, '')
        if check_profile_removed:
            logging.info('[remove dynamic profile on PG removed] Checking whether the profile {} is removed on receiving all lossless PG removed'.format(expected_profile))
            check_lossless_profile_removed(duthost, expected_profile)

            # Re-add another lossless profile
            logging.info('Re-add a lossless_pg and check pool size and pfc_enable')
            duthost.shell('config interface buffer priority-group lossless add {} 6'.format(port_to_test))
            time.sleep(10)
            check_pool_size(duthost, (int(original_pool_size) * number_of_pools + int(original_headroom_size) * 2 - int(headroom_size)) / number_of_pools)
            check_pfc_enable(duthost, port_to_test, '6')

            if cable_len_to_test != original_cable_len:
                duthost.shell('config interface cable-length {} {}'.format(port_to_test, original_cable_len))
            if mtu_to_test != default_mtu:
                duthost.shell('config interface mtu {} {}'.format(port_to_test, default_mtu))
            # remove old profile on cable length change
            logging.info('[remove dynamic profile on cable length and/or MTU updated] Checking whether the old profile is removed')
            check_lossless_profile_removed(duthost, expected_profile)
            expected_profile = 'pg_lossless_{}_{}_profile'.format(speed_to_test, original_cable_len)
            check_profile(duthost, 'BUFFER_PG_TABLE:{}:6'.format(port_to_test), expected_profile)
            headroom_size = duthost.shell('redis-cli hget "BUFFER_PROFILE_TABLE:{}" size'.format(expected_profile))['stdout']
            check_pool_size(duthost, (int(original_pool_size) * number_of_pools + int(original_headroom_size) * 2 - int(headroom_size)) / number_of_pools)

            duthost.shell('config interface buffer priority-group lossless remove {} 6'.format(port_to_test))
            time.sleep(10)
            check_pool_size(duthost, (int(original_pool_size) * number_of_pools + int(original_headroom_size) * 2) / number_of_pools)
            check_pfc_enable(duthost, port_to_test, '')
        else:
            if cable_len_to_test != original_cable_len:
                logging.info('[update cable length without any lossless pg configured]')
                duthost.shell('config interface cable-length {} {}'.format(port_to_test, original_cable_len))
            if mtu_to_test != default_mtu:
                logging.info('[update mtu without any lossless pg configured]')
                duthost.shell('config interface mtu {} {}'.format(port_to_test, default_mtu))

        if speed_to_test != original_speed:
            logging.info('[update speed without any lossless pg configured]')
            duthost.shell('config interface speed {} {}'.format(port_to_test, original_speed))

        logging.info('[add lossless pg with speed and cable length ready]')
        duthost.shell('config interface buffer priority-group lossless add {} 3-4'.format(port_to_test))
        time.sleep(10)
        expected_profile = 'pg_lossless_{}_{}_profile'.format(original_speed, original_cable_len)
        check_profile(duthost, 'BUFFER_PG_TABLE:{}:3-4'.format(port_to_test), expected_profile)
        check_pfc_enable(duthost, port_to_test, '3,4')

        headroom_size = duthost.shell('redis-cli hget "BUFFER_PROFILE_TABLE:{}" size'.format(expected_profile))['stdout']
        check_pool_size(duthost, int(original_pool_size))

        logging.info('[extra lossless PG]')
        duthost.shell('config interface buffer priority-group lossless add {} 6'.format(port_to_test))
        time.sleep(10)
        check_profile(duthost, 'BUFFER_PG_TABLE:{}:6'.format(port_to_test), expected_profile)
        check_pfc_enable(duthost, port_to_test, '3,4,6')
        check_pool_size(duthost, (int(original_pool_size) * number_of_pools - int(original_headroom_size)) / number_of_pools)

        logging.info('[restore config]')
        duthost.shell('config interface buffer priority-group lossless remove {} 6'.format(port_to_test))
        time.sleep(10)
        check_pfc_enable(duthost, port_to_test, '3,4')
        check_pool_size(duthost, int(original_pool_size))
    finally:
        duthost.shell('config interface buffer priority-group lossless remove {}'.format(port_to_test), module_ignore_errors = True)
        duthost.shell('config interface speed {} {}'.format(port_to_test, original_speed), module_ignore_errors = True)
        duthost.shell('config interface mtu {} {}'.format(port_to_test, default_mtu), module_ignore_errors = True)
        duthost.shell('config interface cable-length {} {}'.format(port_to_test, original_cable_len), module_ignore_errors = True)
        duthost.shell('config interface buffer priority-group lossless add {} 3-4'.format(port_to_test), module_ignore_errors = True)


def test_headroom_override(duthost, conn_graph_facts, port_to_test):
    '''
    @summary: headroom override test
    @port_to_test: on which port will the test be performed
    '''
    original_speed = duthost.shell('redis-cli -n 4 hget "PORT|{}" speed'.format(port_to_test))['stdout']
    original_cable_len = duthost.shell('redis-cli -n 4 hget "CABLE_LENGTH|AZURE" {}'.format(port_to_test))['stdout']
    original_profile = duthost.shell('redis-cli hget "BUFFER_PG_TABLE:{}:3-4" profile'.format(port_to_test))['stdout'][1:-1]
    original_headroom_size = duthost.shell('redis-cli hget "{}" size'.format(original_profile))['stdout']
    original_pool_size = duthost.shell('redis-cli hget BUFFER_POOL_TABLE:ingress_lossless_pool size')['stdout']
    number_of_pools = detect_ingress_pool_number(duthost)

    try:
        # Configure a static profile
        logging.info("[prepare configuration]")
        duthost.shell('config buffer profile add headroom-override --xon 18432 --xoff 18432 --dynamic_th 1')
        time.sleep(10)

        logging.info("[test: headroom override on lossless PG 3-4] apply the profile on the PG and check pool size")
        duthost.shell('config interface buffer priority-group lossless set {} 3-4 headroom-override'.format(port_to_test))
        time.sleep(10)
        check_profile(duthost, 'BUFFER_PG_TABLE:{}:3-4'.format(port_to_test), 'headroom-override')
        check_pfc_enable(duthost, port_to_test, '3,4')
        check_pool_size(duthost, (int(original_pool_size) * number_of_pools + 2 * int(original_headroom_size) - 73728) / number_of_pools)

        # Add another headroom override
        logging.info("[test: headroom override on more lossless PGs 6] apply the profile on the PG and check pool size")
        duthost.shell('config interface buffer priority-group lossless add {} 6 headroom-override'.format(port_to_test))
        time.sleep(10)
        check_profile(duthost, 'BUFFER_PG_TABLE:{}:6'.format(port_to_test), 'headroom-override')
        check_pfc_enable(duthost, port_to_test, '3,4,6')
        check_pool_size(duthost, (int(original_pool_size) * number_of_pools + 2 * int(original_headroom_size) - 110592) / number_of_pools)

        logging.info("[test: update headroom-override profile] update the profile and check pool size")
        duthost.shell('config buffer profile set headroom-override --xon 18432 --xoff 36864')
        time.sleep(10)
        check_pool_size(duthost, (int(original_pool_size) * number_of_pools + 2 * int(original_headroom_size) - 165888) / number_of_pools)

        # Recover configuration
        logging.info("[test: static headroom being referenced can not be removed]")
        duthost.shell('config buffer profile remove headroom-override', module_ignore_errors = True)
        time.sleep(20)
        profile = duthost.shell('redis-cli hgetall "BUFFER_PROFILE_TABLE:headroom-override"')['stdout']
        assert profile, 'Headroom override profile has been removed when being referenced'
        logging.info("[recover configuration]")
        duthost.shell('config interface buffer priority-group lossless remove {}'.format(port_to_test))
        duthost.shell('config interface buffer priority-group lossless add {} 3-4'.format(port_to_test))
        time.sleep(10)
        check_profile(duthost, 'BUFFER_PG_TABLE:{}:3-4'.format(port_to_test), original_profile.split(':')[1])
        check_pfc_enable(duthost, port_to_test, '3,4')
        check_pool_size(duthost, int(original_pool_size))
    finally:
        duthost.shell('config interface buffer priority-group lossless remove {}'.format(port_to_test), module_ignore_errors = True)
        duthost.shell('config interface buffer priority-group lossless add {} 3-4'.format(port_to_test), module_ignore_errors = True)
        duthost.shell('config buffer profile remove headroom-override', module_ignore_errors = True)


def test_lossless_pg(duthost, conn_graph_facts, port_to_test, pg_to_test):
    '''
    @summary: non default dynamic th test
    @port_to_test: on which port will the test be performed
    @speed_to_test: to what speed will the port's be changed
    '''
    original_speed = duthost.shell('redis-cli -n 4 hget "PORT|{}" speed'.format(port_to_test))['stdout']
    original_cable_len = duthost.shell('redis-cli -n 4 hget "CABLE_LENGTH|AZURE" {}'.format(port_to_test))['stdout']

    # create profiles
    logging.info('[preparing]: create static buffer profile for headroom override and non default dynamic_th')
    duthost.shell('config buffer profile add headroom-override --xon 18432 --xoff 32768')
    duthost.shell('config buffer profile add non-default-dynamic_th --dynamic_th 2')

    # update cable length to 15m
    logging.info('[preparing]: update cable length')
    duthost.shell('config interface cable-length {} 15m'.format(port_to_test))
    expected_profile = 'pg_lossless_{}_15m_profile'.format(original_speed, original_cable_len)
    check_profile(duthost, 'BUFFER_PG_TABLE:{}:3-4'.format(port_to_test), expected_profile)

    set_command = 'config interface buffer priority-group lossless set {} {} '.format(port_to_test, pg_to_test)
    add_command = 'config interface buffer priority-group lossless add {} {} '.format(port_to_test, pg_to_test)
    if pg_to_test == '3-4':
        first_command = set_command
    else:
        first_command = add_command

    buffer_pg = 'BUFFER_PG_TABLE:{}:{}'.format(port_to_test, pg_to_test)

    try:
        # 1. original it should be a dynamic PG, update it to override
        logging.info('[testcase: dynamic headroom => headroom override]')
        duthost.shell(first_command + 'headroom-override')
        # check whether lossless dynamic profile is removed
        check_profile(duthost, buffer_pg, 'headroom-override')
        if pg_to_test == '3-4':
            check_lossless_profile_removed(duthost, expected_profile)

        # update it to non-default dynamic_th
        logging.info('[testcase: headroom override => dynamically calculated headroom with non-default dynamic_th]')
        duthost.shell(set_command + 'non-default-dynamic_th')
        expected_nondef_profile = 'pg_lossless_{}_15m_th2_profile'.format(original_speed)
        check_profile(duthost, buffer_pg, expected_nondef_profile)

        # update it to dynamic PG
        logging.info('[testcase: dynamically calculated headroom with non-default dynamic_th => dynamic headroom]')
        duthost.shell(set_command)
        check_profile(duthost, buffer_pg, expected_profile)
        check_lossless_profile_removed(duthost, expected_nondef_profile)

        # update it to non-default dynamic_th
        logging.info('[testcase: dynamic headroom => [dynamically calculated headroom with non-default dynamic_th]')
        duthost.shell(set_command + 'non-default-dynamic_th')
        check_profile(duthost, buffer_pg, expected_nondef_profile)
        if pg_to_test == '3-4':
            check_lossless_profile_removed(duthost, expected_profile)

        # update it to headroom override
        logging.info('[testcase: dynamically calculated headroom with non-default dynamic_th => headroom override]')
        duthost.shell(set_command + 'headroom-override')
        check_profile(duthost, buffer_pg, 'headroom-override')
        check_lossless_profile_removed(duthost, expected_nondef_profile)

        # update it to dynamic PG, recover
        logging.info('[testcase: headroom override => dynamic headroom]')
        duthost.shell(set_command)
        check_profile(duthost, buffer_pg, expected_profile)

        # remove all static profiles
        logging.info('[restoring configuration]')
        duthost.shell('config buffer profile remove headroom-override')
        duthost.shell('config buffer profile remove non-default-dynamic_th')
        check_lossless_profile_removed(duthost, 'headroom-override')
        check_lossless_profile_removed(duthost, 'non-default-dynamic_th')
    finally:
        if pg_to_test == '3-4':
            duthost.shell(set_command, module_ignore_errors = True)
        else:
            duthost.shell('config interface buffer priority-group lossless remove {} {} '.format(port_to_test, pg_to_test), module_ignore_errors = True)
        duthost.shell('config interface cable-length {} {}'.format(port_to_test, original_cable_len), module_ignore_errors = True)
        duthost.shell('config buffer profile remove headroom-override', module_ignore_errors = True)
        duthost.shell('config buffer profile remove non-default-dynamic_th', module_ignore_errors = True)


def test_exceeding_headroom(duthost, conn_graph_facts, port_to_test):
    '''
    @summary: 
    '''
    max_headroom_size = duthost.shell('redis-cli -n 6 hget "BUFFER_MAX_PARAM_TABLE|{}" max_headroom_size'.format(port_to_test))['stdout']
    if not max_headroom_size:
        pytest.skip('No max headroom found on port {}, skip'.format(port_to_test))

    original_cable_len = duthost.shell('redis-cli -n 4 hget "CABLE_LENGTH|AZURE" {}'.format(port_to_test))['stdout']
    original_speed = duthost.shell('redis-cli -n 4 hget "PORT|{}" speed'.format(port_to_test))['stdout']
    original_profile = 'pg_lossless_{}_{}_profile'.format(original_speed, original_cable_len)

    try:
        # set to super long cable length
        logging.info('[config a super long cable length]')
        duthost.shell('config interface cable-length {} 10000m'.format(port_to_test))
        time.sleep(20)
        logging.info('verify the profile isn\'t changed')
        check_profile(duthost, 'BUFFER_PG_TABLE:{}:3-4'.format(port_to_test), original_profile)
        duthost.shell('config interface cable-length {} {}'.format(port_to_test, original_cable_len))

        # add additional PG
        logging.info('[config the cable length on the port]')
        duthost.shell('config interface cable-length {} 300m'.format(port_to_test))
        time.sleep(20)
        logging.info('verify the profile has been changed')
        expected_profile = 'pg_lossless_{}_{}_profile'.format(original_speed, '300m')
        check_profile(duthost, 'BUFFER_PG_TABLE:{}:3-4'.format(port_to_test), expected_profile)
        logging.info('add another PG and make sure the system isn\'t broken')
        duthost.shell('config interface buffer priority-group lossless add {} {}'.format(port_to_test, '5-7'))
        time.sleep(20)
        # we can't say whether this will accumulative headroom exceed the limit, but the system should not crash
        # leverage sanity check to verify that
        duthost.shell('config interface buffer priority-group lossless remove {} {}'.format(port_to_test, '5-7'))
        duthost.shell('config interface cable-length {} {}'.format(port_to_test, original_cable_len))

        # static profile
        logging.info('[config headroom override to PG 3-4]')
        duthost.shell('config buffer profile add test-headroom --xon 18432 --xoff 50000 -headroom 68432')
        duthost.shell('config interface buffer priority-group lossless set {} {} {}'.format(port_to_test, '3-4', 'test-headroom'))
        time.sleep(20)
        logging.info('verify the profile is applied')
        check_profile(duthost, 'BUFFER_PG_TABLE:{}:3-4'.format(port_to_test), 'test-headroom')
        duthost.shell('config interface buffer priority-group lossless add {} {} {}'.format(port_to_test, '5-7', 'test-headroom'))
        time.sleep(20)
        # again, we can't say for sure whether the accumulative headroom exceeding.
        # just make sure the system doesn't crash
        duthost.shell('config interface buffer priority-group lossless remove {} {}'.format(port_to_test, '5-7'))

        logging.info('[update headroom override to a lager size]')
        duthost.shell('config buffer profile set test-headroom --xon 18432 --xoff 860160 -headroom 878592')
        time.sleep(20)
        # this should make it exceed the limit, so the profile should not applied to the APPL_DB
        size_in_appldb = duthost.shell('redis-cli hget "BUFFER_PROFILE_TABLE:test-headroom" size')['stdout']
        assert size_in_appldb == '68432', 'The profile with a large size was applied to APPL_DB, which can make headroom exceeding'
        duthost.shell('config interface buffer priority-group lossless set {} {}'.format(port_to_test, '3-4'))
        duthost.shell('config buffer profile remove test-headroom')
        logging.info('[clean up]')
    finally:
        duthost.shell('config interface cable-length {} {}'.format(port_to_test, original_cable_len), module_ignore_errors = True)
        duthost.shell('config interface buffer priority-group lossless remove {} 5-7'.format(port_to_test), module_ignore_errors = True)
        duthost.shell('config interface buffer priority-group lossless set {} 3-4'.format(port_to_test), module_ignore_errors = True)
        duthost.shell('config buffer profile remove test-headroom', module_ignore_errors = True)


def _recovery_to_dynamic_buffer_model(duthost):
    duthost.shell('kill $(pgrep buffermgrd)')
    duthost.shell('config qos reload')
    duthost.shell('config save -y')
    config_reload(duthost, config_source='config_db')


def test_buffer_model_test(duthost, conn_graph_facts):
    '''
    @summary: verify whether the buffer model is expected after configuration operations:
              - whether the buffer model is traditional after executing config load_minigraph
              - whether the buffer model is dynamic after recovering the buffer model to dynamic
    '''
    try:
        logging.info('[config load_minigraph]')
        config_reload(duthost, config_source='minigraph')
        buffer_model = duthost.shell('redis-cli -n 4 hget "DEVICE_METADATA|localhost" buffer_model')['stdout']
        assert buffer_model == 'traditional', 'Got buffer model {} after executing config load_minigraph, traditional expected'

        logging.info('[Recover the DUT to default buffer model]')
        _recovery_to_dynamic_buffer_model(duthost)
        buffer_model = duthost.shell('redis-cli -n 4 hget "DEVICE_METADATA|localhost" buffer_model')['stdout']
        assert buffer_model == 'dynamic', 'Got buffer model {} after executing recovering the buffer model to dynamic'
    finally:
        _recovery_to_dynamic_buffer_model(duthost)
