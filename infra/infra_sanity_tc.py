#!/usr/bin/env python3
import argparse
import grpc
import os
import sys
import json
import re
from time import sleep
from topology.topo_mgr.topo_mgr import Topology
from framework.pytest.cafy import Cafy
import pytest
from logger.cafylog import CafyLog
from topology.zap.zap import Zap
from utils.helper import Helper
from utils.cafyexception import CafyException
from datetime import datetime
import six
import google.protobuf.json_format
log = CafyLog("INFRA AP")

TP_DIR = "./../../godiva-test/lib"
tp_dirs = os.listdir(TP_DIR)
for tp_dir in tp_dirs:
    sys.path.append(os.path.join(TP_DIR,tp_dir))

sys.path.append('../gnmi/')
import gnmi_test_lib as gnmiTestLib
sys.path.append('./../../godiva-test/lib/')
import common_lib as commonLib
sys.path.append('../p4/')
from p4_error_utils import printGrpcError
from p4_error_utils import parseGrpcError
from infra_base_ap import ApData, InfraApBase


def _test_Memory_Usage():
    #Currently sample added for getting Memory info from DUT in docker. Will update for TH3
    cmd = "cat /proc/meminfo\n"
    reply = commonLib.node_get(ApData.svr_addr, ApData.uname, ApData.pwd, cmd)
    log.info(reply.decode())


def _test_Optics_Presence_All():
    cmd = "sudo /usr/cisco/godiva/optics/opticsd -presence all\n"
    reply = commonLib.node_get(ApData.svr_addr, ApData.uname, ApData.pwd, cmd)
    log.info(reply.decode())
    op = reply.decode()
    op = op.splitlines()
    data = [i for i in op if "cisco@godiva" not in i and cmd not in i]

    #with open ("data-files/mock-rslt.txt", "r") as myfile:
    #    data=myfile.readlines()
    up_ports = {}
    for item in data[4:]:
        if item.split()[1] == "Yes":
            up_ports[item.split()[0]] = item.split()[1]
    log.info("Opt_Presence1:The below Ports have Optics Inserted")
    print(up_ports)


def _test_Optics_Laser_Status_All():
    cmd = "sudo /usr/cisco/godiva/optics/opticsd -laser_status all\n"
    reply = commonLib.node_get(ApData.svr_addr, ApData.uname, ApData.pwd, cmd)
    op = reply.decode()
    op = op.splitlines()
    data = [i for i in op if "cisco@godiva" not in i and cmd not in i]
    #print(data)
    #data = reply.decode()
    lsr_up = {}
    no_lsr = "No optics present"
    for item in data[4:]:
        print(item)
        if (no_lsr not in item) and (item.split()[1] == "On"):
            lsr_up[item.split()[0]] = item.split()[1]
    log.info("Opt_Laser1:The below Ports have Laser Status ON")
    print(lsr_up)

def _test_Optics_Laser_Status():

    input_conf = json.loads(six.moves.builtins.open(ApData.zap.get_testcase_configuration("test_Optics_Laser_Status/input_conf_file"), 'r').read())

    if 'IND_OPTICS_LASER_STATUS' in input_conf:
        slot_list = input_conf['IND_OPTICS_LASER_STATUS']['SLOT_LIST']
        for slot_num in slot_list:
            cmd = "sudo /usr/cisco/godiva/optics/opticsd -laser_status {}\n".format(slot_num)
            reply = commonLib.node_get(ApData.svr_addr, ApData.uname, ApData.pwd, cmd)
            op = reply.decode()
            op = op.splitlines()
            print(op)
            data = [i for i in op if "cisco@godiva" not in i and cmd not in i]
            for item in data:
                log.info(item)
    #print(data)
    #data = reply.decode()
    """
    lsr_up = {}
    no_lsr = "No optics present"
    for item in data[4:]:
        print(item)
        if (no_lsr not in item) and (item.split()[1] == "On"):
            lsr_up[item.split()[0]] = item.split()[1]
    log.info("Opt_Laser1:The below Ports have Laser Status ON")
    print(lsr_up)
    """
