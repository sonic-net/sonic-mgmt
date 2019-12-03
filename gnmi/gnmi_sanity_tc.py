#!/usr/bin/env python3
import argparse
import grpc
import os
import sys
import re
import json
from time import sleep
from topology.topo_mgr.topo_mgr import Topology
from framework.pytest.cafy import Cafy
import pytest
from logger.cafylog import CafyLog
from topology.zap.zap import Zap
from utils.helper import Helper
from utils.cafyexception import CafyException
from gnmi_base_ap import ApData, GnmiApBase
import marshal
from datetime import datetime
import six
log = CafyLog("GNMI AP")

# Import the required Proto files from lib dir
# Probably there's a better way of doing this.
# sys.path.append(
#    os.path.join(os.path.dirname(os.path.abspath(__file__)),
#                 '../../lib/'))

# Add 3rd party python packages' paths (instead of setting PYTHONPATH)
TP_DIR = "./../../godiva-test/lib"
tp_dirs = os.listdir(TP_DIR)
for tp_dir in tp_dirs:
    sys.path.append(os.path.join(TP_DIR,tp_dir))

import gnmi_test_lib as gnmiTestLib
sys.path.append('../p4/')
from p4_error_utils import printGrpcError
from p4_error_utils import parseGrpcError

def _test_gnmi_Capability(stub):
    user = None
    password = None
    log.info('Performing CapabilitiesRequest to target \n')
    response = gnmiTestLib._cap(stub, user, password)
    log.info(response)


def _test_gnmi_GetTimestamp(stub):
    user = None
    password = None
    log.info('Performing Get Timestamp format from target \n')
    try:
        xpath = "/oc-if:interfaces"
        paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
        reply = gnmiTestLib._get(stub, paths, user, password)
        log.info(str(reply))
        opt = re.search(r'timestamp: (.+)', str(reply), re.MULTILINE)
        rtime = datetime.fromtimestamp(int(opt.group(1)) // 1000000000)
        log.info("TIMESTAMP rcvd in Epoch: %d", int(opt.group(1)))
        print("Converted TIMESTAMP rcvd: ", rtime.strftime('%Y-%m-%d %H:%M:%S'))
        ctime = datetime.now()
        if((rtime.year == ctime.year) and (rtime.month == ctime.month) and (rtime.day == ctime.day)):
            log.info("gnmi_GetTimestamp: PASSED - Timestamp rcvd as Epoch timestamp")
        else:
            log.info("gnmi_GetTimestamp: FAILED - Timestamp not rcvd as Epoch timestamp")
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        raise CafyException.VerificationError("Test gnmi_GetTimestamp failed due to Grpc Error {err}".format(err=e.details()))    


def _test_GetSet_Sanity1(stub):
    user = None
    password = None
    #with open(ApData.input_conf_file, 'r') as ip_conf_file:
    #    input_conf = gnmiTestLib.json_load_byteified(ip_conf_file)

    input_conf = json.loads(six.moves.builtins.open(ApData.input_conf_file, 'r').read())
    print(input_conf)

    log.info('Performing SET-REPLACE Request to target \n')
    try:
        if 'GETSET_Sanity1_1' in input_conf:
            set_info1 = input_conf['GETSET_Sanity1_1']
            print(type(set_info1))
            print(set_info1)
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            reply = gnmiTestLib._set(stub, paths, 'replace', user, password, set_info1)
            log.info(str(reply))
            if ('response' in str(reply) and 'op: REPLACE' in str(reply)):
                log.info("GETSET_Sanity1_1:Passed - was able to do SET-REPLACE with input json")
            else:
                log.info("GETSET_Sanity1_1:Failed - was unable to do SET-REPLACE with input json")
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        raise CafyException.VerificationError("Test GETSET_Sanity1_1 failed due to Grpc Error {err}".format(err=e.details()))


    log.info('Performing SET-UPDATE Request to target \n')
    try:
        if 'GETSET_Sanity1_2' in input_conf:
            set_info2 = input_conf['GETSET_Sanity1_2']
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            reply = gnmiTestLib._set(stub, paths, 'update', user, password, set_info2)
            log.info(str(reply))
            if ('response' in str(reply) and 'op: UPDATE' in str(reply)):
                log.info("GETSET_Sanity1_2:Passed - was able to do SET-UPDATE with input json")
            else:
                log.info("GETSET_Sanity1_2:Failed - was unable to do SET-UPDATE with input json")
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        raise CafyException.VerificationError("Test GETSET_Sanity1_2 failed due to Grpc Error {err}".format(err=e.details()))


    log.info('Performing SET-REPLACE after UPDATE on target \n')
    try:
        reply = gnmiTestLib._set(stub, paths, 'replace', user, password, set_info1)
        log.info(str(reply))
        if ('response' in str(reply) and 'op: REPLACE' in str(reply)):
            log.info("GETSET_Sanity1_3:Passed - was able to do SET-REPLACE after UPDATE on target")
        else:
            log.info("GETSET_Sanity1_3:Failed - was unable to do SET-REPLACE after UPDATE on target")
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        raise CafyException.VerificationError("Test GETSET_Sanity1_3 failed due to Grpc Error {err}".format(err=e.details()))



    log.info('Performing SET-DELETE Request on target \n')
    sleep(2)
    try:
        xpath = "/if:interfaces"
        paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
        reply = gnmiTestLib._set(stub, paths, 'delete', user, password, set_info1)
        log.info(str(reply))
        if ('response' in str(reply) and 'op: DELETE' in str(reply)):
            log.info("GETSET_Sanity1_4:Passed - was able to do SET-DELETE on target")
        else:
            log.info("GETSET_Sanity1_4:Failed - was unable to do SET-DELETE on target")
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        raise CafyException.VerificationError("Test GETSET_Sanity1_4 failed due to Grpc Error {err}".format(err=e.details()))



'''
def _test_GetSet_Sanity2(stub):
    user = None
    password = None
    log.info('Performing SET Request to target \n')
    xpath = "/"
    paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
    set_info = '@' + ApData.input_conf_file
    print("HDHDHDHD")
    print(set_info)
    response = gnmiTestLib._set(stub, paths, 'replace', user, password, set_info)
    log.info(response)
'''




