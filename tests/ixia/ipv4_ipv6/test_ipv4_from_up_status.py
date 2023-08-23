# -*- coding:UTF-8 -*-
import time
import os
import sys

from common.reboot import logger
from common.ixia.ixia_helpers import (
    logger_msg,
    load_config,
    modify_vlan,
    reserve_port,
    send_ping,
    start_protocols,
    get_connection_info
)
from common.helpers.assertions import pytest_assert

"""
IP4/IP6基础，1.三层口，1.配置接口地址测试
在状态up的3层口上配置ipv4地址
author：forrestfu 202102
"""


def test_ipv4_from_up_status(ixiahost, testbed, duthost):
    ###############################################################
    #                   STEP1: 准备预置条件
    ###############################################################
    # 1.1 设置全局结果，默认为True, 如果中间检测点不通过，将该值更新为False
    result = True

    # 1.2 设置测试仪表IxNetwork配置文件名称，建议和测试例函数同名
    configFile = os.path.join(os.path.dirname(__file__), sys._getframe().f_code.co_name + '.ixncfg')
    logger.info(configFile)

    # 1.3 获取拓扑连接信息，获得intf, vlanid, 其中intf用于配置DUT, vlanid用于更新测试仪表配置文件
    logger_msg(u'获取拓扑连接信息。')
    intf, vlanid = get_connection_info(testbed)

    # 1.4 创建Ixia session, 返回session句柄和测试环境中要使用的端口信息
    logger_msg(u'创建 Ixia Session IP。')
    session, portList = ixiahost

    ###############################################################
    #                   STEP2: 测试仪表相关操作
    ###############################################################
    logger_msg(u'初始DUT为up状态。')
    duthost.shell("sudo config interface startup {}".format(intf['dut1port1']))

    ###############################################################
    #        STEP3: Operations related to test instruments
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
    #                STEP4: 登录到DUT，并配置ipv4地址
    ###############################################################
    logger_msg(u'配置DUT 三层接口')
    duthost.shell("sudo config interface ip add {} 100.1.1.2/24".format(intf['dut1port1']))
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

    if '100.1.1.2/24' in str(ret):
        logger_msg('CHECK1:Device ip 学习成功.')

    else:
        logger_msg('CHECK1:Device ip 学习失败.', 'ERROR')
        result = False

    ###############################################################
    #                STEP6: DUT ping 仪表
    ###############################################################
    # 6. DUT ping 仪表端口
    ret = str(duthost.shell("ping -c 3 100.1.1.1"))
    logger_msg(ret)

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
    pytest_assert(result is True, 'Test case test_ipv4_from_up_status failed')
