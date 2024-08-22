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
IP4/IP6 basics
Configure ipv6 addresses with 10-bit, 48-bit, 53-bit, 58-bit, 64-bit, 92-bit, and 127-bit prefixes on the Layer 3 port
"""


def test_ipv6_with_multiple_address_prefix(ixiahost, testbed, duthost):
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
    #                   STEP2: Send DUT configuration
    ###############################################################
    logger_msg(u'DUT configuration.')

    duthost.shell("sudo config interface startup {}".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip add {} 1000:0:0:1::2/10".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip add {} 2001:0:0:1::2/48".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip add {} 2002:0:0:1::2/53".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip add {} 2003:0:0:1::2/58".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip add {} 2004:0:0:1::2/64".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip add {} 2005:0:0:1::2/92".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip add {} 2006:0:0:1::10/127".format(intf['dut1port1']))
    time.sleep(5)

    ###############################################################
    #        STEP3: Operations related to test instruments
    ###############################################################

    # 3.1: Load instrument configuration file
    logger_msg(u'Load the configuration file.')
    load_config(session, configFile)

    # 3.2: Load the vlan corresponding to the port
    logger_msg(u'Update vlan.')
    modify_vlan(session, 'Ethernet - 001', vlanid['dut1port1'], index='0')
    modify_vlan(session, 'Ethernet - 001', vlanid['dut1port1'], index='1')
    modify_vlan(session, 'Ethernet - 001', vlanid['dut1port1'], index='2')
    modify_vlan(session, 'Ethernet - 001', vlanid['dut1port1'], index='3')
    modify_vlan(session, 'Ethernet - 001', vlanid['dut1port1'], index='4')
    modify_vlan(session, 'Ethernet - 001', vlanid['dut1port1'], index='5')
    modify_vlan(session, 'Ethernet - 001', vlanid['dut1port1'], index='6')

    # 3.3: Reserve port
    logger_msg(u'Connect to the Chassis and reserve ports: %s' % portList)
    reserve_port(session, portList)

    # 3.4: Protocol start
    logger_msg(u'protocol start')
    start_protocols(session)
    time.sleep(5)

    ###############################################################
    #                STEP4: Check the DUT ip interface
    ###############################################################

    logger_msg(u'View DUT interface ip')

    ret = str(duthost.shell('show ipv6 int'))
    logger_msg(ret)

    if re.search('1000:0:0:1::2/10', ret) and re.search('2001:0:0:1::2/48', ret) and \
            re.search('2002:0:0:1::2/53', ret) and re.search('2003:0:0:1::2/58', ret) and \
            re.search('2004:0:0:1::2/64', ret) and re.search('2005:0:0:1::2/92', ret) and \
            re.search('2006:0:0:1::10/127', ret):
        logger_msg('CHECK1:Device ip Success.')

    else:
        logger_msg('CHECK1:Device ip Fail.', 'ErrOR')
        result = False
    ###############################################################
    #                STEP5: DUT ping interface
    ###############################################################

    logger_msg(u'DUT Ping 1000:0:0:1::1')
    ret1 = str(duthost.shell('ping -c 3 1000:0:0:1::1'))
    logger_msg(ret1)
    logger_msg(u'DUT Ping 2001:0:0:1::1')
    ret2 = str(duthost.shell('ping -c 3 2001:0:0:1::1'))
    logger_msg(ret2)
    logger_msg(u'DUT Ping 2002:0:0:1::1')
    ret3 = str(duthost.shell('ping -c 3 2002:0:0:1::1'))
    logger_msg(ret3)
    logger_msg(u'DUT Ping 2003:0:0:1::1')
    ret4 = str(duthost.shell('ping -c 3 2003:0:0:1::1'))
    logger_msg(ret4)
    logger_msg(u'DUT Ping 2004:0:0:1::1')
    ret5 = str(duthost.shell('ping -c 3 2004:0:0:1::1'))
    logger_msg(ret5)
    logger_msg(u'DUT Ping 2005:0:0:1::1')
    ret6 = str(duthost.shell('ping -c 3 2005:0:0:1::1'))
    logger_msg(ret6)
    logger_msg(u'DUT Ping 2006:0:0:1::1')
    ret7 = str(duthost.shell('ping -c 3 2006:0:0:1::11'))
    logger_msg(ret7)

    if re.search('1000:0:0:1::1', ret1) and re.search('time', ret1) and \
       re.search('2001:0:0:1::1', ret2) and re.search('time', ret2) and \
       re.search('2002:0:0:1::1', ret3) and re.search('time', ret3) and \
       re.search('2003:0:0:1::1', ret4) and re.search('time', ret4) and \
       re.search('2004:0:0:1::1', ret5) and re.search('time', ret5) and \
       re.search('2005:0:0:1::1', ret6) and re.search('time', ret6) and \
       re.search('2006:0:0:1::11', ret7) and re.search('time', ret7):
        logger_msg('CHECK2:DUT ping ipv6 Success.')

    else:
        logger_msg('CHECK2:DUT ping ipv6 Fail.', 'ErrOR')
        result = False

    ###############################################################
    #                STEP6: Api server ping DUT
    ###############################################################

    logger_msg(u'Ixia api server ping DUT interface address 1000:0:0:1::2')
    res_10 = send_ping(session, '1000:0:0:1::1', '1000:0:0:1::2')
    logger_msg(res_10)
    logger_msg(u'Ixia api server ping DUT interface address 2001:0:0:1::2')
    res_48 = send_ping(session, '2001:0:0:1::1', '2001:0:0:1::2')
    logger_msg(res_48)
    logger_msg(u'Ixia api server ping DUT interface address 2002:0:0:1::2')
    res_53 = send_ping(session, '2002:0:0:1::1', '2002:0:0:1::2')
    logger_msg(res_53)
    logger_msg(u'Ixia api server ping DUT interface address 2003:0:0:1::2')
    res_58 = send_ping(session, '2003:0:0:1::1', '2003:0:0:1::2')
    logger_msg(res_58)
    logger_msg(u'Ixia api server ping DUT interface address 2004:0:0:1::2')
    res_64 = send_ping(session, '2004:0:0:1::1', '2004:0:0:1::2')
    logger_msg(res_64)
    logger_msg(u'Ixia api server ping DUT interface address 2005:0:0:1::2')
    res_92 = send_ping(session, '2005:0:0:1::1', '2005:0:0:1::2')
    logger_msg(res_92)
    logger_msg(u'Ixia api server ping DUT interface address 2006:0:0:1::10')
    res_127 = send_ping(session, '2006:0:0:1::11', '2006:0:0:1::10')
    logger_msg(res_127)

    if res_10['arg2'] is True & res_48['arg2'] is True & res_53['arg2'] is True & res_58['arg2'] is True \
            & res_64['arg2'] is True & res_92['arg2'] is True & res_127['arg2'] is True:
        logger_msg('Check3: Ixia ping DUT Success')
    else:
        logger_msg('Check3: Ixia ping DUT Fail', 'ERROR')
        if res_10['arg2'] is not True:
            logger_msg(res_10['arg3'])
        if res_48['arg2'] is not True:
            logger_msg(res_48['arg3'])
        if res_53['arg2'] is not True:
            logger_msg(res_53['arg3'])
        if res_58['arg2'] is not True:
            logger_msg(res_58['arg3'])
        if res_64['arg2'] is not True:
            logger_msg(res_64['arg3'])
        if res_92['arg2'] is not True:
            logger_msg(res_92['arg3'])
        if res_127['arg2'] is not True:
            logger_msg(res_127['arg3'])
        result = False

    ##############################################################
    #               STEP7: Clear configuration
    ##############################################################
    logger_msg(u'Clear configuration')

    duthost.shell("sudo config interface ip remove {} 1000:0:0:1::2/10".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip remove {} 2001:0:0:1::2/48".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip remove {} 2002:0:0:1::2/53".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip remove {} 2003:0:0:1::2/58".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip remove {} 2004:0:0:1::2/64".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip remove {} 2005:0:0:1::2/92".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip remove {} 2006:0:0:1::10/127".format(intf['dut1port1']))

    ##############################################################
    # STEP8: Determine whether the test case passes
    ##############################################################
    pytest_assert(result is True, 'Test case test_ipv6_with_multiple_address_prefix failed')
