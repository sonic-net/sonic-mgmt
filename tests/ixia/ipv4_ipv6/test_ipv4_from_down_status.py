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
IP4/IP6 basics, 1. Layer 3 interface, 1. Configuration interface address test
Configure an ipv4 address on the Layer 3 interface in the down state, and then admin up
author：forrestfu 202102
"""


def test_ipv4_from_down_status(ixiahost, testbed, duthost):
    ###############################################################
    #                   STEP1: Prepare preconditions
    ###############################################################
    # 1.1 设置全局结果，默认为True, 如果中间检测点不通过，将该值更新为False
    # if the intermediate detection point fails, update the value to False
    result = True

    # 1.2 设置测试仪表IxNetwork配置文件名称，建议和测试例函数同名
    configFile = os.path.join(os.path.dirname(__file__), sys._getframe().f_code.co_name + '.ixncfg')
    logger.info(configFile)

    # 1.3 获取拓扑连接信息，获得intf, vlanid, 其中intf用于配置DUT, vlanid用于更新测试仪表配置文件
    logger_msg(u'获取拓扑连接信息。')
    intf, vlanid = get_connection_info(testbed)

    # 1.4 创建Ixia session, 返回session句柄和测试环境中要使用的端口信息
    logger_msg(u'配置DUT接口IP地址并UP接口。')
    session, portList = ixiahost

    ###############################################################
    #                   STEP2: 测试仪表相关操作
    ###############################################################
    logger_msg(u'初始DUT为shutdown状态。')
    duthost.shell("sudo config interface shutdown {}".format(intf['dut1port1']))
    time.sleep(2)

    ###############################################################
    #        STEP3: 测试仪表相关操作
    ###############################################################

    # 3.1: Load instrument configuration file
    logger_msg(u'加载配置文件。')
    load_config(session, configFile)

    # 3.2: 加载仪表端口对应的vlan, 需要更新仪表配置文件中的端口名字
    logger_msg(u'更新vlan, 虚拟机框更新vlan, 物理机框disable vlan。')
    modify_vlan(session, 'Ethernet - 001', vlanid['dut1port1'])

    # 3.3: 占用端口
    logger_msg(u'连接机框，开始抢占端口%s' % portList)
    reserve_port(session, portList)

    ###############################################################
    #                STEP4: 登录到DUT,admin up接口，并配置ipv4地址
    ###############################################################
    logger_msg(u'配置DUT 三层接口，并no shutdown端口')
    duthost.shell("sudo config interface startup {}".format(intf['dut1port1']))
    duthost.shell("sudo config interface ip add {} 100.1.1.2/24".format(intf['dut1port1']))
    # logger_msg(ret)
    time.sleep(5)

    logger_msg(u'protocol start')
    start_protocols(session)
    time.sleep(10)

    ###############################################################
    #                STEP5: 登录到DUT,验证DUT可以查到对应的ip
    ###############################################################

    # Step5: 登录到DUT,检测arp表项
    logger_msg(u'查看DUT arp表项')
    ret = str(duthost.shell("sudo show ip int"))
    logger_msg(ret)

    if '100.1.1.2/24' in ret:
        logger_msg('CHECK1:Device ip 学习成功.')
    else:
        logger_msg('CHECK1:Device ip 学习失败.', 'ERROR')
        result = False

    ###############################################################
    #                STEP6: DUT ping 仪表
    ###############################################################
    # 6. DUT ping 仪表端口
    logger_msg(u'DUT Ping')
    ret = str(duthost.shell("ping -c 3 100.1.1.1"))

    if ('100.1.1.1' in ret) and ('time' in ret):
        logger_msg('CHECK2:DUT ping 仪表地址成功.')

    else:
        logger_msg('CHECK2:DUT ping 仪表地址失败.', 'ERROR')
        result = False

    ###############################################################
    #                STEP7: 仪表 ping DUT
    ###############################################################
    # 7: 测试仪表发送ping

    logger_msg(u'Ixia测试ping DUT 接口地址100.1.1.2')
    res = send_ping(session, '100.1.1.1', '100.1.1.2')
    logger_msg(res)
    if res['arg2'] is True:
        logger_msg('Check3: 仪表ping DUT 正常')
    else:
        logger_msg('Check3: 仪表ping DUT 不正常，请检查', 'ERROR')
        logger_msg(res['arg3'])
        result = False

    ##############################################################
    #               STEP8: 清除配置
    ##############################################################

    logger_msg(u'清除配置')
    duthost.shell("sudo config interface ip remove {} 100.1.1.2/24".format(intf['dut1port1']))

    ##############################################################
    # STEP9: 设置最终结果，判断测试例是否通过
    ##############################################################
    pytest_assert(result is True, 'Test case test_ipv4_from_down_status failed')
