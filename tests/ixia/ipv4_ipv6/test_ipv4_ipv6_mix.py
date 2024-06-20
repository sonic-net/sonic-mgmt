# -*- coding:UTF-8 -*-
import time
import os
import sys

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
Configure both ipv4 and ipv6 addresses on the layer 3 interface
"""


def test_ipv4_ipv6_mix(ixiahost, testbed, duthost):
    ###############################################################
    #                   STEP1: Prepare preconditions
    ###############################################################
    #          1.1 Set the global result, the default is True,
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
    logger_msg(u'Configure the IP address of the DUT interface.')
    duthost.shell("sudo config interface ip add {} 11.1.1.2/24".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip add {} 2000:0:0:1::2/64".format(intf['dut1port1']))
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

    # 3.3: Reserve ports
    logger_msg(u'Connect to the Chassis and reserve ports: %s' % portList)
    reserve_port(session, portList)

    # 3.5: Protocol start
    logger_msg(u'Protocol start')
    start_protocols(session)
    time.sleep(5)

    ###############################################################
    #                STEP4: Check the DUT ip interface
    ###############################################################

    logger_msg(u'View DUT interface ip')
    ret_ipv6 = str(duthost.shell("show ipv6 int"))
    ret_ipv4 = str(duthost.shell("show ip int"))
    logger_msg(ret_ipv6)
    logger_msg(ret_ipv4)

    if ('2000:0:0:1::2/64' in ret_ipv6) and ('11.1.1.2/24' in ret_ipv4):
        logger_msg('CHECK1:Device ip Success.')

    else:
        logger_msg('CHECK1:Device ip Fail.', 'ERROR')
        result = False

    ###############################################################
    #                STEP5: DUT ping interface
    ###############################################################

    logger_msg(u'DUT Ping ipv4')
    ret = str(duthost.shell("ping -c 3 11.1.1.1"))
    logger_msg(ret)

    if ('11.1.1.1' in ret) and ('time' in ret):
        logger_msg('CHECK2:DUT ping ipv4 Success.')

    else:
        logger_msg('CHECK2:DUT ping ipv4 Fail.', 'ERROR')
        result = False

    logger_msg(u'DUT Ping ipv6')
    ret = str(duthost.shell("ping -c 3 2000:0:0:1::1"))
    logger_msg(ret)
    if ('2000:0:0:1::1' in ret) and ('time' in ret):
        logger_msg('CHECK2:DUT ping ipv6 Success.')

    else:
        logger_msg('CHECK2:DUT ping ipv6 Fail.', 'ERROR')
        result = False

    ###############################################################
    #                STEP6: Api server ping DUT
    ###############################################################

    logger_msg(u'Ixia ping DUT interface 11.1.1.2')
    res_ipv4 = send_ping(session, '11.1.1.1', '11.1.1.2')
    logger_msg(res_ipv4)
    logger_msg(u'Ixia ping DUT interface 2000:0:0:1::2')
    res_ipv6 = send_ping(session, '2000:0:0:1::1', '2000:0:0:1::2')
    logger_msg(res_ipv6)
    if res_ipv4['arg2'] is True & res_ipv6['arg2'] is True:
        logger_msg('Check3: Ixia ping DUT Success')
    else:
        logger_msg('CHECK2:DUT ping Fail.', 'ERROR')
        logger_msg(res_ipv4['arg3'])
        logger_msg(res_ipv6['arg3'])
        result = False

    ##############################################################
    #               STEP7: Clear configuration
    ##############################################################
    logger_msg(u'Clear configuration')
    duthost.shell("sudo config interface ip remove {} 11.1.1.2/24".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip remove {} 2000:0:0:1::2/64".format(intf['dut1port1']))

    ##############################################################
    # STEP8: Determine whether the test case passes
    ##############################################################
    pytest_assert(result is True, 'Test case test_ipv4_ipv6_mix failed')
