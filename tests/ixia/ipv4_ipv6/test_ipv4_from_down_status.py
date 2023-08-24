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
IP4 basics
Configure an ipv4 address on the Layer 3 interface in the down state, and then up
"""


def test_ipv4_from_down_status(ixiahost, testbed, duthost):
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
    logger_msg(u'The initial DUT is in the shutdown state.')
    duthost.shell("sudo config interface shutdown {}".format(intf['dut1port1']))
    time.sleep(2)

    ###############################################################
    #        STEP3: Operations related to test instruments
    ###############################################################

    # 3.1: Load configuration file
    logger_msg(u'Load the configuration file.')
    load_config(session, configFile)

    # 3.2: Load the vlan corresponding to the port
    logger_msg(u'Update vlan.')
    modify_vlan(session, 'Ethernet - 001', vlanid['dut1port1'])

    # 3.3: Reserve ports
    logger_msg(u'Connect to the Chassis and reserve ports: %s' % portList)
    reserve_port(session, portList)

    ###############################################################
    # STEP4: Log in to DUT, admin up interface, and configure ipv4 address
    ###############################################################
    logger_msg(u'Configure the DUT layer 3 interface and startup port')
    duthost.shell("sudo config interface startup {}".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip add {} 100.1.1.2/24".format(intf['dut1port1']))
    time.sleep(5)

    logger_msg(u'Protocol start')
    start_protocols(session)
    time.sleep(10)

    ###############################################################
    #       STEP5: Check the DUT ip interface
    ###############################################################

    logger_msg(u'View DUT interface ip')
    ret = str(duthost.shell("sudo show ip int"))
    logger_msg(ret)

    if '100.1.1.2/24' in ret:
        logger_msg('CHECK1:Device ip Success.')
    else:
        logger_msg('CHECK1:Device ip Fail.', 'ERROR')
        result = False

    ###############################################################
    #                STEP6: DUT ping interface
    ###############################################################

    logger_msg(u'DUT Ping')
    ret = str(duthost.shell("ping -c 3 100.1.1.1"))

    if ('100.1.1.1' in ret) and ('time' in ret):
        logger_msg('CHECK2:DUT ping Success.')

    else:
        logger_msg('CHECK2:DUT ping Fail.', 'ERROR')
        result = False

    ###############################################################
    #                STEP7: Api server ping DUT
    ###############################################################

    logger_msg(u'Ixia ping DUT interface 100.1.1.2')
    res = send_ping(session, '100.1.1.1', '100.1.1.2')
    logger_msg(res)
    if res['arg2'] is True:
        logger_msg('Check3: Ixia ping DUT Success')
    else:
        logger_msg('Check3: Ixia ping DUT Fail', 'ERROR')
        logger_msg(res['arg3'])
        result = False

    ##############################################################
    #               STEP8: Clear configuration
    ##############################################################

    logger_msg(u'Clear configuration')
    duthost.shell("sudo config interface ip remove {} 100.1.1.2/24".format(intf['dut1port1']))

    ##############################################################
    #       STEP9: Determine whether the test case passes
    ##############################################################
    pytest_assert(result is True, 'Test case test_ipv4_from_down_status failed')
