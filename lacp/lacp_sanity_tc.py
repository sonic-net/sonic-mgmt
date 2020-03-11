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
log = CafyLog("LACP AP")

TP_DIR = "./../../godiva-test/lib"
tp_dirs = os.listdir(TP_DIR)
for tp_dir in tp_dirs:
    sys.path.append(os.path.join(TP_DIR,tp_dir))

sys.path.append('../gnmi/')
import gnmi_test_lib as gnmiTestLib
from gnmi_test_lib import GnmiConnection
sys.path.append('./../../godiva-test/lib/')
import common_lib as commonLib
sys.path.append('../p4/')
from p4_error_utils import printGrpcError
from p4_error_utils import parseGrpcError
from lacp_base_ap import ApData, LacpApBase

def _test_Optics_Laser_Status():
    user = None
    password = None
    err_msg = list()

    input_conf = json.loads(six.moves.builtins.open(ApData.zap.get_testcase_configuration("test_Optics_Laser_Status/input_conf_file"), 'r').read())
    gnmi_input_conf = json.loads(six.moves.builtins.open(ApData.zap.get_testcase_configuration("test_Optics_Laser_Status/gnmi_input_conf_file"), 'r').read())
    gnmi_conn = GnmiConnection(target=ApData.svr_addr, port=ApData.gnmi_port_addr)
    stub = gnmi_conn.stub

    log.info('Performing SET-UPDATE Request to target \n')
    try:
        if 'PORT_INTF' in gnmi_input_conf:
            set_info = gnmi_input_conf['PORT_INTF']['config']
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            reply = gnmiTestLib._set(stub, paths, 'update', user, password, set_info)
            log.info(str(reply))
            if ('response' in str(reply) and 'op: UPDATE' in str(reply)):
                log.info("test_Get_with_prefix:Passed - was able to do SET-UPDATE with input json")
            else:
                log.info("test_Get_with_prefix:Failed - was unable to do SET-UPDATE with input json")
            
            #xpath = "/if:interfaces/if:interface"
            for verify_sec in gnmi_input_conf['PORT_INTF']['verfiy']:
                prefix = verify_sec['prefix']
                #prefix = gnmiTestLib._parse_path(gnmiTestLib._path_names(prefix))
                path = verify_sec['path']
                path = gnmiTestLib._parse_path(gnmiTestLib._path_names(path))
                response = gnmiTestLib._get(stub, path, user, password,prefix,type='CONFIG')
                #log.info(response)   

                msg_dict = google.protobuf.json_format.MessageToDict(response)
                log.info(json.dumps(msg_dict,sort_keys=True, indent=4))
                resp_dict = gnmiTestLib.get_response_dict(msg_dict)
                for cfg in verify_sec['config']:
                    result = gnmiTestLib.verify_get_response(resp_dict,set_info,cfg)
                    err_msg = result['err_msg'] + err_msg
    
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        err_msg.append("test_Get_with_prefix failed due to Grpc Error {err}".format(err=e.details()))

    index = None
    if 'IND_OPTICS_LASER_STATUS' in input_conf:
        slot_list = input_conf['IND_OPTICS_LASER_STATUS']['SLOT_LIST']
        verify_status_list = input_conf['IND_OPTICS_LASER_STATUS']['VERIFY']['Status']
        for slot_num,status in zip(slot_list, verify_status_list):
            cmd = "sudo /usr/cisco/godiva/optics/opticsd -laser_status {}\n".format(slot_num)
            reply = commonLib.node_get(ApData.svr_addr, ApData.uname, ApData.pwd, cmd)
            op = reply.decode()
            op = op.splitlines()            
            data = [i for i in op if "cisco@godiva" not in i and cmd.strip('\n') not in i]            
            for item in data:
                if 'Port' in item:
                    index = data.index(item)
            if index is not None:
                data[0:index+1] = []
                for item in data:
                    if item.split()[0] == str(slot_num) and item.split()[1].lower() == status.lower():
                        log.info("Laser Status is up for slot_num {}".format(slot_num))
                    else:
                        log.error("Laser Status is {} for slot_num {}".format(item.split()[1],slot_num))
            else:
                log.error("Port Status not present in the output : {}".format(reply.decode()))
    
    if len(err_msg) != 0:
        log.error("test_Optics_Laser_Status failed due to : {}".format(*err_msg))
        pytest.fail("test_Optics_Laser_Status failed due to : {}".format(*err_msg))
    else:
        log.info("test_Optics_Laser_Status Passed")
