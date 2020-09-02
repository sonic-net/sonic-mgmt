#!/usr/bin/env python3
from __future__ import absolute_import
from __future__ import print_function
import argparse
import json
import logging
import os
import re
import sys
import six
import paramiko
from time import sleep
import threading
from queue import Queue
from logger.cafylog import CafyLog
from topology.zap.zap import Zap
from utils.helper import Helper
from utils.cafyexception import CafyException
import grpc

from infra_base_ap import ApData, InfraApBase
TP_DIR = "./../../godiva-test/lib"
tp_dirs = os.listdir(TP_DIR)
for tp_dir in tp_dirs:
    sys.path.append(os.path.join(TP_DIR,tp_dir))

sys.path.append('../gnmi/')
import gnmi_test_lib as gnmiTestLib
from gnmi_test_lib import GnmiConnection
sys.path.append('./../../godiva-test/lib/')
log = CafyLog("INFRA Test Lib")
sys.path.append('../p4/')
from p4_error_utils import printGrpcError
from p4_error_utils import parseGrpcError


def create_intf():
    #This proc helps Create 3 Interfaces, Ports and associated Component Configs which can be used by various Infra TCs
    user = None
    password = None
    success = False
    
    gnmi_input_conf = json.loads(six.moves.builtins.open(ApData.zap.get_testcase_configuration("test_Optics_Laser_Status/gnmi_input_conf_file"), 'r').read())
    gnmi_conn = GnmiConnection(target=ApData.svr_addr, port=ApData.gnmi_port_addr)
    stub = gnmi_conn.stub

    log.info('Performing SET-REPLACE Request to Create Interfaces on target \n')
    try:
        if 'PORT_INTF' in gnmi_input_conf:
            set_info = gnmi_input_conf['PORT_INTF']['config']
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            reply = gnmiTestLib._set(stub, paths, 'replace', user, password, set_info)
            log.info(str(reply))
            if ('response' in str(reply) and 'op: REPLACE' in str(reply)):
                log.info("InfrLib_CreateIntf:Passed - was able to do SET-REPLACE to Create Interfaces")
                success = True
            else:
                log.info("InfrLib_CreateIntf:Failed - was unable to do SET-REPLACE to Create Interfaces")

    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        err_msg.append("InfrLib_CreateIntf failed due to Grpc Error {err}".format(err=e.details()))

    return success


def intf_oper(int_name, oper, value):
    #This proc executes various Interface triggers and returns Status or Output
    user = None
    password = None
    success = False
    
    gnmi_input_conf = json.loads(six.moves.builtins.open(ApData.zap.get_testcase_configuration("test_Optics_Laser_Status/gnmi_input_conf_file"), 'r').read())
    gnmi_conn = GnmiConnection(target=ApData.svr_addr, port=ApData.gnmi_port_addr)
    stub = gnmi_conn.stub

    #Getting Interface List Config to use in various Opers below
    #This can be modified later to make more generic or get from TH3 Complete Port Config list
    if 'FLAP_INTF_DOWN' in gnmi_input_conf:
        int_info = gnmi_input_conf['FLAP_INTF_DOWN']['config']['openconfig-interfaces:interfaces']['interface']
    else:
        log.error("Cannot proceed with Test as there is no Interfaces List available")

    if oper.upper() == 'ENABLED':
        log.info('Performing SET-UPDATE Request to to bring Interface DOWN \n')
        try:
            set_info = [x for x in int_info if x['name'] == int_name]
            print(set_info)
            set_info[0]['config']['enabled'] = value
            if set_info:
                xpath = "/openconfig-interfaces:interfaces/interface"
                paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
                reply = gnmiTestLib._set(stub, paths, 'update', user, password, set_info)
                log.info(str(reply))
                if ('response' in str(reply) and 'op: UPDATE' in str(reply)):
                    log.info("InfrLib_CreateIntf:Passed - was able to do SET-REPLACE to Create Interfaces")
                    success = True
                else:
                    log.info("InfrLib_CreateIntf:Failed - was unable to do SET-REPLACE to Create Interfaces")

        except KeyboardInterrupt:
            log.info("Shutting down.")
        except grpc.RpcError as e:
            log.error("### GRPC ERROR RECEIVED:: ###")
            log.error(e)
            printGrpcError(e)
            err_msg.append("InfrLib_CreateIntf failed due to Grpc Error {err}".format(err=e.details()))

    return success
