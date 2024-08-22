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
Configure 8-bit, 16-bit, 24-bit, 26-bit, and 31-bit ipv4 addresses on the Layer 3 interface in up state
"""


def test_ipv4_with_multiple_address_mask(ixiahost, testbed, duthost):
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

    logger_msg(u'配置DUT接口IP地址并UP接口。')

    duthost.shell("sudo config interface startup {}".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip add {} 11.1.1.2/8".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip add {} 12.1.1.2/16".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip add {} 13.1.1.2/24".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip add {} 14.1.1.2/26".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip add {} 15.1.1.10/31".format(intf['dut1port1']))
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

    # 3.3: Reserve port
    logger_msg(u'Connect to the Chassis and reserve ports: %s' % portList)
    reserve_port(session, portList)

    # 3.4: Protocol start
    logger_msg(u'protocol start')
    start_protocols(session)
    time.sleep(5)

    ###############################################################
    #                STEP5: Check the DUT ip interface
    ###############################################################

    logger_msg(u'View DUT interface ip')

    ret = str(duthost.shell("show ip int"))
    logger_msg(ret)
    if ('11.1.1.2/8' in ret) and ('12.1.1.2/16' in ret) and ('13.1.1.2/24' in ret) and  \
       ('14.1.1.2/26' in ret) and ('15.1.1.10/31' in ret):
        logger_msg('CHECK1:Device ip Success.')
    else:
        logger_msg('CHECK1:Device ip Fail.', 'ErrOR')
        result = False

    ###############################################################
    #                STEP6: DUT ping interface
    ###############################################################

    logger_msg(u'DUT Ping 11.1.1.1')
    ret1 = str(duthost.shell("ping -c 3 11.1.1.1"))
    logger_msg(ret1)
    ret2 = str(duthost.shell("ping -c 3 12.1.1.1"))
    logger_msg(ret2)
    logger_msg(u'DUT Ping 13.1.1.1')
    ret3 = str(duthost.shell("ping -c 3 13.1.1.1"))
    logger_msg(ret3)
    logger_msg(u'DUT Ping 14.1.1.1')
    ret4 = str(duthost.shell("ping -c 3 14.1.1.1"))
    logger_msg(ret4)
    logger_msg(u'DUT Ping 15.1.1.11')
    ret5 = str(duthost.shell("ping -c 3 15.1.1.11"))
    logger_msg(ret5)

    if re.search('11.1.1.1', ret1) and re.search('time', ret1) and \
       re.search('12.1.1.1', ret2) and re.search('time', ret2) and \
       re.search('13.1.1.1', ret3) and re.search('time', ret3) and \
       re.search('14.1.1.1', ret4) and re.search('time', ret4) and \
       re.search('15.1.1.11', ret5) and re.search('time', ret5):
        logger_msg('CHECK2:DUT ping ipv4 Success.')

    else:
        logger_msg('CHECK2:DUT ping ipv4 Fail.', 'ErrOR')
        result = False

    ###############################################################
    #                STEP7: Api server ping DUT
    ###############################################################

    logger_msg(u'Ixia api server ping DUT interface address 11.1.1.2')
    res_8 = send_ping(session, '11.1.1.1', '11.1.1.2')
    logger_msg(res_8)
    logger_msg(u'Ixia api server ping DUT interface address 12.1.1.2')
    res_16 = send_ping(session, '12.1.1.1', '12.1.1.2')
    logger_msg(res_16)
    logger_msg(u'Ixia api server ping DUT interface address 13.1.1.2')
    res_24 = send_ping(session, '13.1.1.1', '13.1.1.2')
    logger_msg(res_24)
    logger_msg(u'Ixia api server ping DUT interface address 14.1.1.2')
    res_26 = send_ping(session, '14.1.1.1', '14.1.1.2')
    logger_msg(res_26)
    logger_msg(u'Ixia api server ping DUT interface address 15.1.1.10')
    res_31 = send_ping(session, '15.1.1.11', '15.1.1.10')
    logger_msg(res_31)

    if res_8['arg2'] is True & res_16['arg2'] is True & res_24['arg2'] is True \
            & res_26['arg2'] is True & res_31['arg2'] is True:
        logger_msg('Check3: Ixia ping DUT Success')
    else:
        logger_msg('Check3: Ixia ping DUT Fail', 'ErrOR')
        if res_8['arg2'] is not True:
            logger_msg(res_8['arg3'])
        if res_16['arg2'] is not True:
            logger_msg(res_16['arg3'])
        if res_24['arg2'] is not True:
            logger_msg(res_24['arg3'])
        if res_26['arg2'] is not True:
            logger_msg(res_26['arg3'])
        if res_31['arg2'] is not True:
            logger_msg(res_31['arg3'])
        result = False

    ##############################################################
    #               STEP24: Clear configuration
    ##############################################################
    logger_msg(u'Clear configuration')

    duthost.shell("sudo config interface startup {}".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip remove {} 11.1.1.2/8".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip remove {} 12.1.1.2/16".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip remove {} 13.1.1.2/24".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip remove {} 14.1.1.2/26".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip remove {} 15.1.1.10/31".format(intf['dut1port1']))

    ##############################################################
    # STEP9: Determine whether the test case passes
    ##############################################################
    pytest_assert(result is True, 'Test case test_ipv4_with_multiple_address_mask failed')
