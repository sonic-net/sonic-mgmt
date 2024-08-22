# -*- coding:UTF-8 -*-
import time
import os
import sys
import re

from tests.common.reboot import logger
from tests.common.ixia.ixia_helpers import (
    logger_msg,
    load_config,
    modify_vlan,
    reserve_port,
    send_ping,
    start_protocols,
    get_connection_info
)
from tests.common.helpers.assertions import pytest_assert

"""
IP4/IP6
Configure an ipv6 address on the Layer 3 interface in the down state, and then admin up
"""


def test_ipv6_from_up_status(ixiahost, testbed, duthost):
    ###############################################################
    #                   STEP1: Prepare preconditions
    ###############################################################
    #           1.1 Set the global result, the default is True,
    # if the intermediate detection point fails, update the value to False
    result = True

    # 1.2 Set the test IxNetwork configuration file name
    configFile = os.path.join(os.path.dirname(__file__), sys._getframe().f_code.co_name + '.ixncfg')
    logger.info(configFile)

    # 1.3 Get topology connection information, intf is used to configure DUT,
    #       and vlanid is used to update test configuration file
    logger_msg(u'Get topology connection information.')
    intf, vlanid = get_connection_info(testbed)

    # 1.4 Create an Ixia session, return the session and the port information
    #                   to be used in the test environment
    logger_msg(u'Create Ixia Session IPs.')
    session, portList = ixiahost

    ###############################################################
    #                   STEP2: DUT configuration
    ###############################################################
    logger_msg(u'Dut: Interface startup')
    duthost.shell("sudo config interface startup {}".format(intf['dut1port1']))

    ###############################################################
    #        STEP3: Operations related to test instruments
    ###############################################################

    # 3.1: Load instrument configuration file
    logger_msg(u'Load the configuration file.')
    load_config(session, configFile)

    # 3.2: Load the vlan corresponding to the port
    logger_msg(u'Update vlan.')
    modify_vlan(session, 'Ethernet - 001', vlanid['dut1port1'])

    # 3.4: Reserve port
    logger_msg(u'Connect to the Chassis and reserve ports: %s' % portList)
    reserve_port(session, portList)

    ###############################################################
    #      STEP4: Interface startup, and configure ipv4 address
    ###############################################################

    logger_msg(u'配置DUT 三层接口')
    duthost.shell("sudo config interface ip add {} 2000:0:0:1::2/64".format(intf['dut1port1']))
    time.sleep(5)

    logger_msg(u'protocol start')
    start_protocols(session)
    time.sleep(10)

    ###############################################################
    #                STEP5: Check the DUT ip interface
    ###############################################################

    ret = str(duthost.shell('show ipv6 int'))
    logger_msg(ret)

    if re.search('2000:0:0:1::2/64', ret):
        logger_msg('CHECK1:Device ip Success.')

    else:
        logger_msg('CHECK1:Device ip Fail.', 'ErrOR')
        result = False

    ###############################################################
    #                STEP6: DUT ping interface
    ###############################################################

    logger_msg(u'DUT Ping')
    ret = str(duthost.shell('ping -c 3 2000:0:0:1::1'))
    logger_msg(ret)

    if re.search('2000:0:0:1::1', ret) and re.search('time', ret):
        logger_msg('CHECK2:DUT ping Success.')

    else:
        logger_msg('CHECK2:DUT ping Fail.', 'ErrOR')
        result = False

    ###############################################################
    #                STEP7: Api server ping DUT
    ###############################################################

    logger_msg(u'Ixia api server ping DUT interface address 2000:0:0:1::2')
    res = send_ping(session, '2000:0:0:1::1', '2000:0:0:1::2')
    logger_msg(res)

    if res['arg2'] is True:
        logger_msg('Check3: Ixia ping DUT Success')

    else:

        logger_msg('Check3: Ixia ping DUT Fail', 'ErrOR')
        logger_msg(res['arg3'])
        result = False

    ##############################################################
    #               STEP8: Clear configuration
    ##############################################################

    logger_msg(u'Clear configuration')
    duthost.shell("sudo config interface ip remove {} 2000:0:0:1::2/64".format(intf['dut1port1']))

    ##############################################################
    # STEP9: Determine whether the test case passes
    ##############################################################
    pytest_assert(result is True, 'Test case test_ipv6_from_down_status failed')
