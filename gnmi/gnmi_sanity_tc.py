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
import google.protobuf.json_format
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

def _test_gnmi_get(stub):
    user = None
    password = None
    log.info('Performing CapabilitiesRequest to target \n')
    xpath = "/oc-if:interfaces/oc-if:interface[name=\"eth0\"]/oc-if:config"
    paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
    response = gnmiTestLib._get(stub, paths, user, password)
    #log.info(response)
    msg_dict = google.protobuf.json_format.MessageToDict(response)
    log.info(msg_dict)
    msg_json = google.protobuf.json_format.MessageToJson(response)
    log.info(msg_json)
    xpath = "/oc-if:interfaces/oc-if:interface[name=\"eth0\"]/oc-if:state"
    paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
    response = gnmiTestLib._get(stub, paths, user, password)
    #log.info(response)
    msg_dict = google.protobuf.json_format.MessageToDict(response)
    log.info(msg_dict)
    msg_json = google.protobuf.json_format.MessageToJson(response)
    log.info(msg_json)

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
    err_msg = list()
    resp_key_list = list()
    #with open(ApData.input_conf_file, 'r') as ip_conf_file:
    #    input_conf = gnmiTestLib.json_load_byteified(ip_conf_file)

    input_conf = json.loads(six.moves.builtins.open(ApData.zap.get_testcase_configuration("test_GetSet_Sanity1/input_conf_file"), 'r').read())

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
            
            #xpath = "/if:interfaces/if:interface"
            xpath = input_conf['VERIFY_GETSET_Sanity1_1']['filter']
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            response = gnmiTestLib._get(stub, paths, user, password)
            #log.info(response)
            msg_dict = google.protobuf.json_format.MessageToDict(response)
            log.info(msg_dict)
            resp_dict = gnmiTestLib.get_oc_response_dict(msg_dict)
            resp_key_list.append(set_info1['ietf-interfaces:interfaces']['interface'][0]['name'])
            for resp_key in resp_key_list:
                if resp_key + ',interfaces,interface,name' in resp_dict.keys():
                    if set_info1['ietf-interfaces:interfaces']['interface'][0]['name'] != resp_dict[resp_key + ',interfaces,interface,name']:
                        err_msg.append("{} does not match the name in input json file: {}".format(resp_dict[resp_key + ',interfaces,interface,name'], set_info1['ietf-interfaces:interfaces']['interface'][0]['name']))
                    if set_info1['ietf-interfaces:interfaces']['interface'][0]['description'] != resp_dict[resp_key + ',interfaces,interface,description']:
                        err_msg.append("{} does not match the description in input json file: {}".format(resp_dict[resp_key + ',interfaces,interface,description'], set_info1['ietf-interfaces:interfaces']['interface'][0]['description']))
                    if resp_dict[resp_key + ',interfaces,interface,type'] not in set_info1['ietf-interfaces:interfaces']['interface'][0]['type']:
                        err_msg.append("{} does not match the type in input json file: {}".format(resp_dict[resp_key + ',interfaces,interface,type'], set_info1['ietf-interfaces:interfaces']['interface'][0]['type']))
                    if not resp_dict[resp_key + ',interfaces,interface,enabled']:
                        err_msg.append("The interface {} is not enabled. Current status is {}".format(resp_dict[resp_key + ',interfaces,interface,name'], resp_dict[resp_key + ',interfaces,interface,enabled']))
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        raise CafyException.VerificationError("Test GETSET_Sanity1_1 failed due to Grpc Error {err}".format(err=e.details()))

    if len(err_msg) != 0:
        log.error("Test GETSET_Sanity1_1 failed due to : {}".format(*err_msg))
    else:
        log.info("Test GETSET_Sanity1_1 - Set and Get Passed")

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
                log.error("GETSET_Sanity1_2:Failed - was unable to do SET-UPDATE with input json")
                err_msg.append("GETSET_Sanity1_2:Failed - was unable to do SET-UPDATE with input json")
            
            xpath = input_conf['VERIFY_GETSET_Sanity1_2']['filter']
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            response = gnmiTestLib._get(stub, paths, user, password)
            #log.info(response)
            msg_dict = google.protobuf.json_format.MessageToDict(response)
            resp_dict = gnmiTestLib.get_oc_response_dict(msg_dict)
            log.info(resp_dict)
            for cfg in input_conf['VERIFY_GETSET_Sanity1_2']['config']:
                cfg_section = cfg['section']
                set_info = input_conf[cfg_section]
                resp_key = cfg['name']
                if resp_key + ',interfaces,interface,name' in resp_dict.keys():
                    if set_info['ietf-interfaces:interfaces']['interface'][0]['name'] != resp_dict[resp_key + ',interfaces,interface,name']:
                        err_msg.append("{} does not match the name in input json file: {}".format(resp_dict[resp_key + ',interfaces,interface,name'], set_info['ietf-interfaces:interfaces']['interface'][0]['name']))
                    if set_info['ietf-interfaces:interfaces']['interface'][0]['description'] != resp_dict[resp_key + ',interfaces,interface,description']:
                        err_msg.append("{} does not match the description in input json file: {}".format(resp_dict[resp_key + ',interfaces,interface,description'], set_info['ietf-interfaces:interfaces']['interface'][0]['description']))
                    if resp_dict[resp_key + ',interfaces,interface,type'] not in set_info['ietf-interfaces:interfaces']['interface'][0]['type']:
                        err_msg.append("{} does not match the type in input json file: {}".format(resp_dict[resp_key + ',interfaces,interface,type'], set_info['ietf-interfaces:interfaces']['interface'][0]['type']))
                    if not resp_dict[resp_key + ',interfaces,interface,enabled']:
                        err_msg.append("The interface {} is not enabled. Current status is {}".format(resp_dict[resp_key + ',interfaces,interface,name'], resp_dict[resp_key + ',interfaces,interface,enabled']))
                else:
                    err_msg.append("Interface {} missing from the GET response".format(resp_key))

        if len(err_msg) != 0:
            log.error("Test GETSET_Sanity1_2 failed due to : {}".format(*err_msg))
        else:
            log.info("Test GETSET_Sanity1_2 - Set and Get Passed")


    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        raise CafyException.VerificationError("Test GETSET_Sanity1_2 failed due to Grpc Error {err}".format(err=e.details()))

    log.info('Performing SET-REPLACE after UPDATE on target \n')
    try:
        xpath = "/"
        paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
        reply = gnmiTestLib._set(stub, paths, 'replace', user, password, set_info1)
        log.info(str(reply))
        if ('response' in str(reply) and 'op: REPLACE' in str(reply)):
            log.info("GETSET_Sanity1_3:Passed - was able to do SET-REPLACE after UPDATE on target")
        else:
            log.error("GETSET_Sanity1_3:Failed - was unable to do SET-REPLACE after UPDATE on target")
            err_msg.append("GETSET_Sanity1_3:Failed - was unable to do SET-REPLACE after UPDATE on target")
        
        xpath = input_conf['VERIFY_GETSET_Sanity1_3']['filter']
        paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
        response = gnmiTestLib._get(stub, paths, user, password)
        #log.info(response)
        msg_dict = google.protobuf.json_format.MessageToDict(response)
        resp_dict = gnmiTestLib.get_oc_response_dict(msg_dict)
        log.info(resp_dict)

        for cfg in input_conf['VERIFY_GETSET_Sanity1_3']['config']:
                cfg_section = cfg['section']
                set_info = input_conf[cfg_section]
                resp_key = cfg['name']
                if resp_key + ',interfaces,interface,name' in resp_dict.keys():
                    if set_info['ietf-interfaces:interfaces']['interface'][0]['name'] != resp_dict[resp_key + ',interfaces,interface,name']:
                        err_msg.append("{} does not match the name in input json file: {}".format(resp_dict[resp_key + ',interfaces,interface,name'], set_info['ietf-interfaces:interfaces']['interface'][0]['name']))
                    if set_info['ietf-interfaces:interfaces']['interface'][0]['description'] != resp_dict[resp_key + ',interfaces,interface,description']:
                        err_msg.append("{} does not match the description in input json file: {}".format(resp_dict[resp_key + ',interfaces,interface,description'], set_info['ietf-interfaces:interfaces']['interface'][0]['description']))
                    if resp_dict[resp_key + ',interfaces,interface,type'] not in set_info['ietf-interfaces:interfaces']['interface'][0]['type']:
                        err_msg.append("{} does not match the type in input json file: {}".format(resp_dict[resp_key + ',interfaces,interface,type'], set_info['ietf-interfaces:interfaces']['interface'][0]['type']))
                    if not resp_dict[resp_key + ',interfaces,interface,enabled']:
                        err_msg.append("The interface {} is not enabled. Current status is {}".format(resp_dict[resp_key + ',interfaces,interface,name'], resp_dict[resp_key + ',interfaces,interface,enabled']))
                else:
                    err_msg.append("Interface {} missing from the GET response".format(resp_key))

        if len(err_msg) != 0:
            log.error("Test GETSET_Sanity1_3 failed due to : {}".format(*err_msg))
        else:
            log.info("Test GETSET_Sanity1_3 - Set and Get Passed")

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
            log.error("GETSET_Sanity1_4:Failed - was unable to do SET-DELETE on target")
            err_msg.append("GETSET_Sanity1_4:Failed - was unable to do SET-DELETE on target")
        
        xpath = input_conf['VERIFY_GETSET_Sanity1_4']['filter']
        paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
        response = gnmiTestLib._get(stub, paths, user, password)
        #log.info(response)
        msg_dict = google.protobuf.json_format.MessageToDict(response)
        log.info(msg_dict)
        resp_dict = gnmiTestLib.get_oc_response_dict(msg_dict)
        if resp_dict != None:
            err_msg.append(resp_dict)

        if len(err_msg) != 0:
            log.error("Test GETSET_Sanity1_4 failed due to : {}".format(*err_msg))
        else:
            log.info("Test GETSET_Sanity1_4 - Set and Get Passed")
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        raise CafyException.VerificationError("Test GETSET_Sanity1_4 failed due to Grpc Error {err}".format(err=e.details()))

    if len(err_msg) != 0:
        log.error("Test_GetSet_Sanity1 failed due to : {}".format(*err_msg))
        pytest.fail("Test_GetSet_Sanity1 failed due to : {}".format(*err_msg))
    else:
        log.info("Test_GetSet_Sanity1 - All sections passed")

def _test_Get_with_prefix(stub):
    user = None
    password = None
    err_msg = list()
    resp_key_list = list()
    ctr = 0
    
    input_conf = json.loads(six.moves.builtins.open(ApData.zap.get_testcase_configuration("test_Get_with_prefix/input_conf_file"), 'r').read())
    
    log.info('Performing SET-REPLACE Request to target \n')
    try:
        if 'GET_WITH_PFX' in input_conf:
            set_info = input_conf['GET_WITH_PFX']
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            reply = gnmiTestLib._set(stub, paths, 'replace', user, password, set_info)
            log.info(str(reply))
            if ('response' in str(reply) and 'op: REPLACE' in str(reply)):
                log.info("test_Get_with_prefix:Passed - was able to do SET-REPLACE with input json")
            else:
                log.info("test_Get_with_prefix:Failed - was unable to do SET-REPLACE with input json")
            
            #xpath = "/if:interfaces/if:interface"
            prefix = input_conf['VERIFY_GET_WITH_PFX']['prefix']
            #prefix = gnmiTestLib._parse_path(gnmiTestLib._path_names(prefix))
            path = input_conf['VERIFY_GET_WITH_PFX']['path']
            path = gnmiTestLib._parse_path(gnmiTestLib._path_names(path))
            response = gnmiTestLib._get(stub, path, user, password,prefix,type='CONFIG')
            #log.info(response)
            msg_dict = google.protobuf.json_format.MessageToDict(response)
            log.info(msg_dict)
            resp_dict = gnmiTestLib.get_oc_response_dict(msg_dict)
            resp_key_list.append(set_info['openconfig-interfaces:interfaces']['interface'][0]['name'])
            resp_key_list.append(set_info['openconfig-interfaces:interfaces']['interface'][1]['name'])
            for resp_key in resp_key_list:
                if resp_key + ',interfaces,interface,name' in resp_dict.keys():
                    if set_info['openconfig-interfaces:interfaces']['interface'][ctr]['name'] != resp_dict[resp_key + ',interfaces,interface,name']:
                        err_msg.append("{} does not match the name in input json file: {}".format(resp_dict[resp_key + ',interfaces,interface,name'], set_info['openconfig-interfaces:interfaces']['interface'][ctr]['name']))
                    if set_info['openconfig-interfaces:interfaces']['interface'][ctr]['config']['description'] != resp_dict[resp_key + ',interfaces,interface,config,description']:
                        err_msg.append("{} does not match the description in input json file: {}".format(resp_dict[resp_key + ',interfaces,interface,config,description'], set_info['openconfig-interfaces:interfaces']['interface'][ctr]['config']['description']))
                    if resp_dict[resp_key + ',interfaces,interface,config,type'] not in set_info['openconfig-interfaces:interfaces']['interface'][ctr]['config']['type']:
                        err_msg.append("{} does not match the type in input json file: {}".format(resp_dict[resp_key + ',interfaces,interface,config,type'], set_info['openconfig-interfaces:interfaces']['interface'][ctr]['config']['type']))
                    if not resp_dict[resp_key + ',interfaces,interface,config,enabled']:
                        err_msg.append("The interface {} is not enabled. Current status is {}".format(resp_dict[resp_key + ',interfaces,interface,name'], resp_dict[resp_key + ',interfaces,interface,config,enabled']))
                else:
                    err_msg.append("Interface {} missing from the GET response".format(resp_key))
                ctr += 1    
    
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        err_msg.append("test_Get_with_prefix failed due to Grpc Error {err}".format(err=e.details()))

    if len(err_msg) != 0:
        log.error("test_Get_with_prefix failed due to : {}".format(*err_msg))
        pytest.fail("test_Get_with_prefix failed due to : {}".format(*err_msg))
    else:
        log.info("test_Get_with_prefix Passed")
    
    try:
        xpath = "/oc-if:interfaces"
        paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
        reply = gnmiTestLib._set(stub, paths, 'delete', user, password, set_info)
        log.info(str(reply))
        if ('response' in str(reply) and 'op: DELETE' in str(reply)):
            log.info("test_Get_with_prefix:Passed - was able to do SET-DELETE on target")
        else:
            log.error("test_Get_with_prefix:Failed - was unable to do SET-DELETE on target")
            err_msg.append("test_Get_with_prefix:Failed - was unable to do SET-DELETE on target")
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        pytest.fail("test_Get_with_prefix - Delete Config during cleanup failed due to Grpc Error {err}".format(err=e.details()))

def _test_GetSet_OC_Components(stub):
    user = None
    password = None
    err_msg = list()
    #with open(ApData.input_conf_file, 'r') as ip_conf_file:
    #    input_conf = gnmiTestLib.json_load_byteified(ip_conf_file)

    input_conf = json.loads(six.moves.builtins.open(ApData.zap.get_testcase_configuration("test_Get_with_prefix/input_conf_file"), 'r').read())

    log.info('Performing SET-REPLACE Request to target \n')
    try:
        if 'GET_WITH_OC_COMP' in input_conf:
            set_info1 = input_conf['GET_WITH_OC_COMP']
            print(type(set_info1))
            print(set_info1)
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            reply = gnmiTestLib._set(stub, paths, 'replace', user, password, set_info1)
            log.info(str(reply))
            if ('response' in str(reply) and 'op: REPLACE' in str(reply)):
                log.info("GET_WITH_OC_COMP:Passed - was able to do SET-REPLACE with input json")
            else:
                log.info("GET_WITH_OC_COMP:Failed - was unable to do SET-REPLACE with input json")
            
            #xpath = "/if:interfaces/if:interface"
            prefix = input_conf['VERIFY_GET_WITH_OC_COMP']['prefix']
            path = input_conf['VERIFY_GET_WITH_OC_COMP']['path']
            path = gnmiTestLib._parse_path(gnmiTestLib._path_names(path))
            log.info("Verify Get for OC Components ")
            response = gnmiTestLib._get(stub, path, user, password,prefix,type='ALL')
            log.info(response)
            
            msg_dict = google.protobuf.json_format.MessageToDict(response)
            log.info(msg_dict)
            #resp_dict = gnmiTestLib.get_oc_response_dict(msg_dict)
            #log.info(resp_dict)
            
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        pytest.fail("Test test_GetSet_OC_Components failed due to Grpc Error {err}".format(err=e.details()))

    if len(err_msg) != 0:
        log.error("Test test_GetSet_OC_Components failed due to : {}".format(*err_msg))
    else:
        log.info("Test test_GetSet_OC_Components - Set and Get Passed")

def _test_Get_OC_Components(stub):
    user = None
    password = None
    err_msg = list()
    #with open(ApData.input_conf_file, 'r') as ip_conf_file:
    #    input_conf = gnmiTestLib.json_load_byteified(ip_conf_file)

    input_conf = json.loads(six.moves.builtins.open(ApData.zap.get_testcase_configuration("test_Get_with_prefix/input_conf_file"), 'r').read())

    log.info('Performing SET-REPLACE Request to target \n')
    try:
        if 'GET_WITH_OC_COMP' in input_conf:
            prefix = input_conf['VERIFY_GET_WITH_OC_COMP']['prefix']
            #prefix = gnmiTestLib._parse_path(gnmiTestLib._path_names(prefix))
            path = input_conf['VERIFY_GET_WITH_OC_COMP']['path']
            path = gnmiTestLib._parse_path(gnmiTestLib._path_names(path))
            log.info("Verify Get for OC Components ")
            response = gnmiTestLib._get(stub, path, user, password,prefix,type='CONFIG')
            msg_json = google.protobuf.json_format.MessageToJson(response)
            log.info(msg_json)
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        pytest.fail("Test GETSET_Sanity1_1 failed due to Grpc Error {err}".format(err=e.details()))

    if len(err_msg) != 0:
        log.error("Test GET_WITH_OC_COMP failed due to : {}".format(*err_msg))
    else:
        log.info("Test GET_WITH_OC_COMP - Set and Get Passed")

def _test_Get_with_type(stub):
    user = None
    password = None
    err_msg = list()
    
    input_conf = json.loads(six.moves.builtins.open(ApData.zap.get_testcase_configuration("test_Get_with_prefix/input_conf_file"), 'r').read())
    
    log.info('Performing SET-REPLACE Request to target \n')
    try:
        if 'GET_WITH_TYPE' in input_conf:
            set_info = input_conf['GET_WITH_TYPE']
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            reply = gnmiTestLib._set(stub, paths, 'replace', user, password, set_info)
            log.info(str(reply))
            if ('response' in str(reply) and 'op: REPLACE' in str(reply)):
                log.info("test_Get_with_type:Passed - was able to do SET-REPLACE with input json")
            else:
                log.info("test_Get_with_type:Failed - was unable to do SET-REPLACE with input json")
            
            #xpath = "/if:interfaces/if:interface"
            prefix = input_conf['VERIFY_GET_WITH_TYPE']['prefix']
            #prefix = gnmiTestLib._parse_path(gnmiTestLib._path_names(prefix))
            path = input_conf['VERIFY_GET_WITH_TYPE']['path']
            path = gnmiTestLib._parse_path(gnmiTestLib._path_names(path))
            log.info("Verify Get with Type='ALL' ")
            response = gnmiTestLib._get(stub, path, user, password,prefix,type='ALL')
            #log.info(response)
            msg_dict = google.protobuf.json_format.MessageToDict(response)
            log.info(msg_dict)
            resp_dict = gnmiTestLib.get_oc_response_dict(msg_dict)
            resp_dict_keys = list(resp_dict.keys())
            state_status = False
            config_status = False
            for keys in resp_dict_keys:
                if 'config' in keys and not config_status:
                    config_status = True
                if 'state' in keys and not state_status:
                    state_status = True
                if config_status and state_status:
                    log.info("Both Config and state are present in Get response with Type=ALL")
                    break
            if not config_status or not state_status:
                log.error("Either Config or state not present in Get response with Type=ALL")
                err_msg.append("Either Config or state not present in Get response with Type=ALL")    

    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        err_msg.append("test_Get_with_type failed due to Grpc Error {err}".format(err=e.details()))

    try:
        log.info("Verify Get with Type='CONFIG' ")
        response = gnmiTestLib._get(stub, path, user, password,prefix,type='CONFIG')
        #log.info(response)
        msg_dict = google.protobuf.json_format.MessageToDict(response)
        log.info(msg_dict)
        resp_dict = gnmiTestLib.get_oc_response_dict(msg_dict)
        resp_dict_keys = list(resp_dict.keys())
        state_status = False
        config_status = False
        for keys in resp_dict_keys:
            if 'config' in keys and not config_status:
                config_status = True
            if 'state' in keys and not state_status:
                state_status = True
            if config_status and not state_status:
                log.info("Only Config is present in Get response with Type=Config")
                break
        if state_status:
            log.error("State is present in Get response with Type=Config")
            err_msg.append("State is present in Get response with Type=Config")    
    
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        err_msg.append("test_Get_with_type failed due to Grpc Error {err}".format(err=e.details()))

    try:
        log.info("Verify Get with Type='STATE' ")
        response = gnmiTestLib._get(stub, path, user, password,prefix,type='STATE')
        #log.info(response)
        msg_dict = google.protobuf.json_format.MessageToDict(response)
        log.info(msg_dict)
        resp_dict = gnmiTestLib.get_oc_response_dict(msg_dict)
        resp_dict_keys = list(resp_dict.keys())
        state_status = False
        config_status = False
        for keys in resp_dict_keys:
            if 'config' in keys and not config_status:
                config_status = True
            if 'state' in keys and not state_status:
                state_status = True
            if not config_status and state_status:
                log.info("Only State is present in Get response with Type=State")
                break
        if config_status:
            log.error("Config is present in Get response with Type=State")
            err_msg.append("Config is present in Get response with Type=State")    
    
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        err_msg.append("test_Get_with_type failed due to Grpc Error {err}".format(err=e.details()))

    if len(err_msg) != 0:
        log.error("test_Get_with_type failed due to : {}".format(*err_msg))
        pytest.fail("test_Get_with_type failed due to : {}".format(*err_msg))
    else:
        log.info("test_Get_with_type Passed")
    
    try:
        xpath = "/oc-if:interfaces"
        paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
        reply = gnmiTestLib._set(stub, paths, 'delete', user, password, set_info)
        log.info(str(reply))
        if ('response' in str(reply) and 'op: DELETE' in str(reply)):
            log.info("test_Get_with_type:Passed - was able to do SET-DELETE on target")
        else:
            log.error("test_Get_with_type:Failed - was unable to do SET-DELETE on target")
            err_msg.append("test_Get_with_type:Failed - was unable to do SET-DELETE on target")
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        pytest.fail("test_Get_with_type - Delete Config during cleanup failed due to Grpc Error {err}".format(err=e.details()))  

def _test_Get_with_wrong_path(stub):
    user = None
    password = None
    err_msg = list()
    
    input_conf = json.loads(six.moves.builtins.open(ApData.zap.get_testcase_configuration("test_Get_with_prefix/input_conf_file"), 'r').read())
    
    log.info('Performing SET-REPLACE Request to target \n')
    try:
        if 'GET_WITH_PFX' in input_conf:
            set_info = input_conf['GET_WITH_PFX']
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            reply = gnmiTestLib._set(stub, paths, 'replace', user, password, set_info)
            log.info(str(reply))
            if ('response' in str(reply) and 'op: REPLACE' in str(reply)):
                log.info("_test_Get_with_wrong_path: was able to do SET-REPLACE with input json")
            else:
                log.info("_test_Get_with_wrong_path:Failed - was unable to do SET-REPLACE with input json")
            
            #xpath = "/if:interfaces/if:interface"
            prefix = input_conf['VERIFY_GET_WITH_WRONG_PATH']['prefix']
            #prefix = gnmiTestLib._parse_path(gnmiTestLib._path_names(prefix))
            path = input_conf['VERIFY_GET_WITH_WRONG_PATH']['path']
            path = gnmiTestLib._parse_path(gnmiTestLib._path_names(path))
            response = gnmiTestLib._get(stub, path, user, password,prefix,type='ALL')
            log.info(response)
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        if ('StatusCode.INVALID_ARGUMENT' in str(e) and 'item does not exist: badpath' in str(e)):
            log.info("Test test_Get_with_wrong_path:Passed - received correct error message on sending wrong path in GET RPC")
        else:
            log.error("Test test_Get_with_wrong_path:Failed - received incorrect error message on sending wrong path in GET RPC")
            err_msg.append("test_Get_with_prefix failed due to Grpc Error {err}".format(err=e.details()))

    if len(err_msg) != 0:
        log.error("test_Get_with_wrong_path failed due to : {}".format(*err_msg))
        pytest.fail("test_Get_with_wrong_path failed due to : {}".format(*err_msg))
    else:
        log.info("test_Get_with_wrong_path Passed")
    
    try:
        xpath = "/oc-if:interfaces"
        paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
        reply = gnmiTestLib._set(stub, paths, 'delete', user, password, set_info)
        log.info(str(reply))
        if ('response' in str(reply) and 'op: DELETE' in str(reply)):
            log.info("test_Get_with_wrong_path:Passed - was able to do SET-DELETE on target")
        else:
            log.error("test_Get_with_wrong_path:Failed - was unable to do SET-DELETE on target")
            err_msg.append("test_Get_with_wrong_path:Failed - was unable to do SET-DELETE on target")
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        pytest.fail("test_Get_with_wrong_path - Delete Config during cleanup failed due to Grpc Error {err}".format(err=e.details())) 

def _test_Get_with_wrong_encoding(stub):
    user = None
    password = None
    err_msg = list()
    
    input_conf = json.loads(six.moves.builtins.open(ApData.zap.get_testcase_configuration("test_Get_with_prefix/input_conf_file"), 'r').read())
    
    log.info('Performing SET-REPLACE Request to target \n')
    try:
        if 'GET_WITH_PFX' in input_conf:
            set_info = input_conf['GET_WITH_PFX']
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            reply = gnmiTestLib._set(stub, paths, 'replace', user, password, set_info)
            log.info(str(reply))
            if ('response' in str(reply) and 'op: REPLACE' in str(reply)):
                log.info("_test_Get_with_wrong_path: was able to do SET-REPLACE with input json")
            else:
                log.info("_test_Get_with_wrong_path:Failed - was unable to do SET-REPLACE with input json")
            
            #xpath = "/if:interfaces/if:interface"
            prefix = input_conf['VERIFY_GET_WITH_PFX']['prefix']
            #prefix = gnmiTestLib._parse_path(gnmiTestLib._path_names(prefix))
            path = input_conf['VERIFY_GET_WITH_PFX']['path']
            path = gnmiTestLib._parse_path(gnmiTestLib._path_names(path))
            
            response = gnmiTestLib._get_wo_encoding(stub, path, user, password,prefix,type='ALL')
            log.info(response)
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        if ('StatusCode.INVALID_ARGUMENT' in str(e) and 'gNMI: Specified encoding 0 is not supported' in str(e)):
            log.info("Test test_Get_with_wrong_encoding.1 - No Encoding :Passed - received correct error message on sending no encoding in GET RPC")
        else:
            log.error("Test test_Get_with_wrong_encoding.1 - No Encoding :Failed - received incorrect error message on sending no encoding in GET RPC")
            err_msg.append("test_Get_with_wrong_encoding.1 - No Encoding :Failed due to Grpc Error {err}".format(err=e.details()))

    try:
        response = gnmiTestLib._get(stub, path, user, password,prefix,type='ALL',encoding='JSON')
        log.info(response)
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        if ('StatusCode.UNIMPLEMENTED' in str(e) and 'gNMI: Specified encoding 0 is not supported' in str(e)):
            log.info("Test test_Get_with_wrong_encoding.2 - Unsupported Encoding :Passed - received correct error message on sending unsupported encoding in GET RPC")
        else:
            log.error("Test test_Get_with_wrong_encoding.2 - Unsupported :Failed - received incorrect error message on sending unsupported encoding in GET RPC")
            err_msg.append("test_Get_with_wrong_encoding.2 - Unsupported :Failed - received incorrect error message on sending \
            unsupported encoding in GET RPC {err}".format(err=e.details()))

    if len(err_msg) != 0:
        log.error("test_Get_with_wrong_encoding failed due to : {}".format(*err_msg))
        pytest.fail("test_Get_with_wrong_encoding failed due to : {}".format(*err_msg))
    else:
        log.info("test_Get_with_wrong_encoding Passed")
    
    try:
        xpath = "/oc-if:interfaces"
        paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
        reply = gnmiTestLib._set(stub, paths, 'delete', user, password, set_info)
        log.info(str(reply))
        if ('response' in str(reply) and 'op: DELETE' in str(reply)):
            log.info("test_Get_with_wrong_encoding:Passed - was able to do SET-DELETE on target")
        else:
            log.error("test_Get_with_wrong_encoding:Failed - was unable to do SET-DELETE on target")
            err_msg.append("test_Get_with_wrong_encoding:Failed - was unable to do SET-DELETE on target")
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        pytest.fail("test_Get_with_wrong_encoding - Delete Config during cleanup failed due to Grpc Error {err}".format(err=e.details())) 

def _test_set_unsup_payload(stub):
    user = None
    password = None
    err_msg = list()
    #with open(ApData.input_conf_file, 'r') as ip_conf_file:
    #    input_conf = gnmiTestLib.json_load_byteified(ip_conf_file)

    input_conf = json.loads(six.moves.builtins.open(ApData.zap.get_testcase_configuration("test_Get_with_prefix/input_conf_file"), 'r').read())

    log.info('Performing SET-REPLACE Request to target \n')
    try:
        if 'GET_WITH_OC_COMP' in input_conf:
            set_info1 = input_conf['GET_WITH_OC_COMP']
            print(type(set_info1))
            print(set_info1)
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            reply = gnmiTestLib._set(stub, paths, 'replace', user, password, set_info1,neg_payload=True)
            log.info(str(reply))
            if ('response' in str(reply) and 'op: REPLACE' in str(reply)):
                log.error("test_set_unsup_payload-replace:Failed - Didn't hit any grpc error")
                err_msg.append("test_set_unsup_payload-replace:Failed - Didn't hit any grpc error")
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        if ('StatusCode.INVALID_ARGUMENT' in str(e) and 'Only JSON_IFTF encoding is supported' in str(e)):
            log.info("test_set_unsup_payload-replace:Passed - Got the right error message")
        else:
            log.error("test_set_unsup_payload-replace:Failed - Error message not matching expected message")
            err_msg.append("test_set_unsup_payload-replace:Failed - Error message not matching expected message")

    try:
        if 'GET_WITH_OC_COMP' in input_conf:
            set_info1 = input_conf['GET_WITH_OC_COMP']
            print(type(set_info1))
            print(set_info1)
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            reply = gnmiTestLib._set(stub, paths, 'update', user, password, set_info1,neg_payload=True)
            log.info(str(reply))
            if ('response' in str(reply) and 'op: UPDATE' in str(reply)):
                log.error("test_set_unsup_payload-update:Failed - Didn't hit any grpc error")
                err_msg.append("test_set_unsup_payload-update:Failed - Didn't hit any grpc error")
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        if ('StatusCode.INVALID_ARGUMENT' in str(e) and 'Only JSON_IFTF encoding is supported' in str(e)):
            log.info("test_set_unsup_payload-update:Passed - Got the right error message")
        else:
            log.error("test_set_unsup_payload-update:Failed - Error message not matching expected message")
            err_msg.append("test_set_unsup_payload-update:Failed - Error message not matching expected message")

    if len(err_msg) != 0:
        log.error("Test test_set_unsup_payload failed due to : {}".format(*err_msg))
        pytest.fail("Test test_set_unsup_payload failed due to : {}".format(*err_msg))
    else:
        log.info("Test test_set_unsup_payload - Passed")

def _test_set_unsup_payload_schema(stub):
    user = None
    password = None
    err_msg = list()
    #with open(ApData.input_conf_file, 'r') as ip_conf_file:
    #    input_conf = gnmiTestLib.json_load_byteified(ip_conf_file)

    input_conf = json.loads(six.moves.builtins.open(ApData.zap.get_testcase_configuration("test_Get_with_prefix/input_conf_file"), 'r').read())

    log.info('Performing SET-REPLACE Request to target \n')
    try:
        if 'GET_WITH_PFX' in input_conf:
            set_info = input_conf['GET_WITH_PFX']
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            reply = gnmiTestLib._set(stub, paths, 'replace', user, password, set_info)
            log.info(str(reply))
            if ('response' in str(reply) and 'op: REPLACE' in str(reply)):
                log.info("test_set_unsup_payload_schema: was able to do SET-REPLACE with input json")
            else:
                log.info("test_set_unsup_payload_schema:Failed - was unable to do SET-REPLACE with input json")

        if 'Neg_Set_Payload_Schema_1' in input_conf:
            set_info1 = input_conf['Neg_Set_Payload_Schema_1']
            print(type(set_info1))
            print(set_info1)
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            reply = gnmiTestLib._set(stub, paths, 'replace', user, password, set_info1)
            log.info(str(reply))
            if ('response' in str(reply) and 'op: REPLACE' in str(reply)):
                log.error("test_set_unsup_payload_schema-replace:Failed - Didn't hit any grpc error")
                err_msg.append("test_set_unsup_payload_schema-replace:Failed - Didn't hit any grpc error")
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        if ('StatusCode.INVALID_ARGUMENT' in str(e) and 'invalid value' in str(e)):
            log.info("test_set_unsup_payload_schema-replace:Passed - Got the right error message")
        else:
            log.error("test_set_unsup_payload_schema-replace:Failed - Error message not matching expected message")
            err_msg.append("test_set_unsup_payload_schema-replace:Failed - Error message not matching expected message")

    try:
        if 'Neg_Set_Payload_Schema_1' in input_conf:
            set_info1 = input_conf['Neg_Set_Payload_Schema_1']
            print(type(set_info1))
            print(set_info1)
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            reply = gnmiTestLib._set(stub, paths, 'update', user, password, set_info1)
            log.info(str(reply))
            if ('response' in str(reply) and 'op: UPDATE' in str(reply)):
                log.error("test_set_unsup_payload_schema-update:Failed - Didn't hit any grpc error")
                err_msg.append("test_set_unsup_payload_schema-update:Failed - Didn't hit any grpc error")
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        if ('StatusCode.INVALID_ARGUMENT' in str(e) and 'invalid value' in str(e)):
            log.info("test_set_unsup_payload_schema-update:Passed - Got the right error message")
        else:
            log.error("test_set_unsup_payload_schema-update:Failed - Error message not matching expected message")
            err_msg.append("test_set_unsup_payload_schema-update:Failed - Error message not matching expected message")

    try:
        xpath = "/oc-if:interfaces"
        paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
        reply = gnmiTestLib._set(stub, paths, 'delete', user, password, set_info)
        log.info(str(reply))
        if ('response' in str(reply) and 'op: DELETE' in str(reply)):
            log.info("test_set_unsup_payload_schema:Passed - was able to do SET-DELETE on target")
        else:
            log.error("test_set_unsup_payload_schema:Failed - was unable to do SET-DELETE on target")
            err_msg.append("test_set_unsup_payload_schema:Failed - was unable to do SET-DELETE on target")
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        pytest.fail("test_set_unsup_payload_schema - Delete Config during cleanup failed due to Grpc Error {err}".format(err=e.details()))

    if len(err_msg) != 0:
        log.error("Test test_set_unsup_payload_schema failed due to : {}".format(*err_msg))
        pytest.fail("Test test_set_unsup_payload_schema failed due to : {}".format(*err_msg))
    else:
        log.info("Test test_set_unsup_payload_schema - Passed")



def _test_gnmi_SetPfxPath(stub):
    user = None
    password = None
    err_msg = list()

    tData = ApData.zap.get_testcase_configuration("test_gnmi_SetPfxPath")
    input_conf = json.loads(six.moves.builtins.open(tData["input_conf_file"], 'r').read())
    print(input_conf)

    log.info('Performing SET-REPLACE Request w/Prefix-Path to target \n')
    try:
        if 'SETPfxPath1_1' in input_conf:
            set_info1 = input_conf['SETPfxPath1_1']
            print(set_info1['prefix-path'])
            print(set_info1['Updates'])
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            pfx_path = gnmiTestLib._parse_path(gnmiTestLib._path_names(set_info1['prefix-path']))
            reply = gnmiTestLib._set(stub, paths, 'replace', user, password, set_info1['Updates'], pfx_path)
            resp = str(reply)
            log.info(resp)
            sresp = "".join(resp.split('\n'))
            log.info (sresp)
            mt1 = 'prefix {  elem {    name: "ietf-interfaces:interfaces"  }'
            mt2 = 'response {  path {  }'
            if (mt1 in sresp and mt2 in sresp):
                log.info("SETPfxPath1_1:Passed - was able to do SET-REPLACE Request w/Prefix-Path")
            else:
                log.info("SETPfxPath1_1:Failed - was unable to do SET-REPLACE Request w/Prefix-Path")
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        raise CafyException.VerificationError("Test SETPfxPath1_1 failed due to Grpc Error {err}".format(err=e.details()))


def _test_SetPfxPath_2node(stub):
    user = None
    password = None
    err_msg = list()

    tData = ApData.zap.get_testcase_configuration("test_gnmi_SetPfxPath")
    input_conf = json.loads(six.moves.builtins.open(tData["input_conf_file"], 'r').read())
    print(input_conf)

    log.info('Performing SET-REPLACE Request w/Prefix-Path for Multiple nodes - TC_2.4.1 \n')
    try:
        if 'SETPfxPath2_1' in input_conf:
            set_info1 = input_conf['SETPfxPath2_1']
            print(set_info1['prefix-path'])
            print(set_info1['Updates'])
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            pfx_path = gnmiTestLib._parse_path(gnmiTestLib._path_names(set_info1['prefix-path']))
            reply = gnmiTestLib._set(stub, paths, 'replace', user, password, set_info1['Updates'], pfx_path)
            resp = str(reply)
            log.info(resp)
            sresp = "".join(resp.split('\n'))
            log.info (sresp)
            mt1 = 'prefix {  elem {    name: "ietf-interfaces:interfaces"  }'
            mt2 = 'response {  path {  }'
            if (mt1 in sresp and mt2 in sresp):
                log.info("SETPfxPath_2node_1:Passed - was able to do SET-REPLACE Request w/Prefix-Path for Multiple Nodes")
            else:
                log.info("SETPfxPath_2node_1:Failed - was unable to do SET-REPLACE Request w/Prefix-Path for Multiple Nodes")
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        raise CafyException.VerificationError("Test SETPfx_2node_1 failed due to Grpc Error {err}".format(err=e.details()))


def _test_MultiSet_Sanity1(stub):
    user = None
    password = None
    err_msg = list()

    input_conf = json.loads(six.moves.builtins.open(ApData.input_conf_file, 'r').read())
    print(input_conf)

    log.info('Performing SET Request w/Multiple Ops(REPLACE+UPDATE) \n')
    try:
        if 'MULTISET_Sanity1_1' in input_conf:
            set_info1 = input_conf['MULTISET_Sanity1_1']
            print(set_info1)
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            if set_info1['set-type'] == 'multiple':
                reply = gnmiTestLib._set(stub, paths, 'multiple', user, password, set_info1)
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        raise CafyException.VerificationError("Test SETReq_Del1_2 failed due to Grpc Error {err}".format(err=e.details()))            


def _test_PfxPath_MSet1(stub):
    user = None
    password = None
    err_msg = list()

    tData = ApData.zap.get_testcase_configuration("test_gnmi_SetPfxPath")
    input_conf = json.loads(six.moves.builtins.open(tData["input_conf_file"], 'r').read())
    print(input_conf)

    log.info('Performing SET w/Multiple Ops(REPLACE+UPDATE) & Prefix-Path \n')
    try:
        if 'PFXPath_MSet_1' in input_conf:
            set_info1 = input_conf['PFXPath_MSet_1']
            print(set_info1['prefix-path'])
            print(set_info1['Updates'])
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            pfx_path = gnmiTestLib._parse_path(gnmiTestLib._path_names(set_info1['prefix-path']))
            reply = gnmiTestLib._set(stub, paths, 'multiple', user, password, set_info1['Updates'], pfx_path)
            resp = str(reply)
            log.info(resp)
            sresp = "".join(resp.split('\n'))
            log.info (sresp)
            mt1 = 'prefix {  elem {    name: "ietf-interfaces:interfaces"  }'
            mt2 = 'response {  path {  }'
            if (mt1 in sresp and mt2 in sresp):
                log.info("PFXPath_MSet_1:Passed - was able to do SET w/Multiple Ops(REPLACE+UPDATE) & Prefix-Path ")
            else:
                log.info("PFXPath_MSet_1:Failed - was unable to do SET w/Multiple Ops(REPLACE+UPDATE) & Prefix-Path ")
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        raise CafyException.VerificationError("Test PFXPath_MSet_1 failed due to Grpc Error {err}".format(err=e.details()))


def _test_SetReq_Del1(stub):
    user = None
    password = None
    err_msg = list()

    input_conf = json.loads(six.moves.builtins.open(ApData.input_conf_file, 'r').read())
    print(input_conf)

    log.info('Performing Test Set-Delete of Node with Children on target \n')
    try:
        if 'GETSET_Sanity1_1' in input_conf:
            set_info1 = input_conf['GETSET_Sanity1_1']
            print(type(set_info1))
            print(set_info1)
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            reply = gnmiTestLib._set(stub, paths, 'replace', user, password, set_info1)
        if 'GETSET_Sanity1_2' in input_conf:
            set_info2 = input_conf['GETSET_Sanity1_2']
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            reply = gnmiTestLib._set(stub, paths, 'update', user, password, set_info2)
        log.info('Send SET-DELETE Request to Element w/Child nodes \n')
        xpath = "/if:interfaces"
        paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
        reply = gnmiTestLib._set(stub, paths, 'delete', user, password, set_info1)
        log.info(str(reply))
        if ('response' in str(reply) and 'op: DELETE' in str(reply)):
            log.info("SETReq_Del1_1:Passed - was able to do SET-DELETE on target")
        else:
            log.error("SETReq_Del1_1:Failed - was unable to do SET-DELETE on target")
            err_msg.append("SETReq_Del1_1:Failed - was unable to do SET-DELETE on target")
        
        xpath = input_conf['VERIFY_GETSET_Sanity1_4']['filter']
        paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
        response = gnmiTestLib._get(stub, paths, user, password)
        #log.info(response)
        msg_dict = google.protobuf.json_format.MessageToDict(response)
        log.info(msg_dict)
        resp_dict = gnmiTestLib.get_oc_response_dict(msg_dict)
        if resp_dict != None:
            err_msg.append(resp_dict)

        if len(err_msg) != 0:
            log.error("Test SETReq_Del1_2 failed due to : {}".format(*err_msg))
        else:
            log.info("Test SETReq_Del1_2 - Set and Get Passed")
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        err_msg.append("Test SETReq_Del1_2 failed due to Grpc Error {err}".format(err=e.details()))

    log.info('Performing Test Set-Delete of Non-Existant Path on target \n')
    try:
        xpath = "/if:interfaces/interface[name='Loopback123']"
        paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
        reply = gnmiTestLib._set(stub, paths, 'delete', user, password, set_info1)
        log.info(str(reply))
        if ('response' in str(reply) and 'op: DELETE' in str(reply)):
            log.error("SETReq_Del1_2:Failed - Target should silently ignore the Delete Request")
            err_msg.append("SETReq_Del1_2:Failed - Target should silently ignore the Delete Request")
        else:
            log.info("SETReq_Del1_2:Passed - Target silently ignored Deletion of Non-existant Path")
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        err_msg.append("Test SETReq_Del1_2:Failed failed due to Grpc Error {err}".format(err=e.details()))

    if len(err_msg) != 0:
        log.error("Test_SETReq_Del1 failed due to : {}".format(*err_msg))
        pytest.fail("Test_SETReq_Del1 failed due to : {}".format(*err_msg))
    else:
        log.info("Test_SETReq_Del1 - All sections passed")

def _test_Neg_set_with_vld_del_inv_upd(stub):
    user = None
    password = None
    err_msg = list()
    resp_key_list = list()
    ctr = 0
    
    input_conf = json.loads(six.moves.builtins.open(ApData.zap.get_testcase_configuration("test_Get_with_prefix/input_conf_file"), 'r').read())
    
    log.info('Performing SET-REPLACE Request to target \n')
    try:
        if 'GET_WITH_PFX' in input_conf:
            set_info = input_conf['GET_WITH_PFX']
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            reply = gnmiTestLib._set(stub, paths, 'replace', user, password, set_info)
            log.info(str(reply))
            if ('response' in str(reply) and 'op: REPLACE' in str(reply)):
                log.info("test_Neg_set_with_vld_del_inv_upd:Passed - was able to do SET-REPLACE with input json")
            else:
                log.info("test_Neg_set_with_vld_del_inv_upd:Failed - was unable to do SET-REPLACE with input json")
            
            #xpath = "/if:interfaces/if:interface"
            prefix = input_conf['VERIFY_GET_WITH_PFX']['prefix']
            #prefix = gnmiTestLib._parse_path(gnmiTestLib._path_names(prefix))
            path = input_conf['VERIFY_GET_WITH_PFX']['path']
            path = gnmiTestLib._parse_path(gnmiTestLib._path_names(path))
            response = gnmiTestLib._get(stub, path, user, password,prefix,type='CONFIG')
            #log.info(response)
            msg_dict = google.protobuf.json_format.MessageToDict(response)
            log.info(msg_dict)
            resp_dict = gnmiTestLib.get_oc_response_dict(msg_dict)
            resp_key_list.append(set_info['openconfig-interfaces:interfaces']['interface'][0]['name'])
            resp_key_list.append(set_info['openconfig-interfaces:interfaces']['interface'][1]['name'])
            log.info("********************")
            log.info(resp_dict.keys())
            log.info("********************")

            for resp_key in resp_key_list:
                if resp_key + ',interfaces,interface,name' in resp_dict.keys():
                    if set_info['openconfig-interfaces:interfaces']['interface'][ctr]['name'] != resp_dict[resp_key + ',interfaces,interface,name']:
                        err_msg.append("{} does not match the name in input json file: {}".format(resp_dict[resp_key + ',interfaces,interface,name'], set_info['openconfig-interfaces:interfaces']['interface'][ctr]['name']))
                    if set_info['openconfig-interfaces:interfaces']['interface'][ctr]['config']['description'] != resp_dict[resp_key + ',interfaces,interface,config,description']:
                        err_msg.append("{} does not match the description in input json file: {}".format(resp_dict[resp_key + ',interfaces,interface,config,description'], set_info['openconfig-interfaces:interfaces']['interface'][ctr]['config']['description']))
                    if resp_dict[resp_key + ',interfaces,interface,config,type'] not in set_info['openconfig-interfaces:interfaces']['interface'][ctr]['config']['type']:
                        err_msg.append("{} does not match the type in input json file: {}".format(resp_dict[resp_key + ',interfaces,interface,config,type'], set_info['openconfig-interfaces:interfaces']['interface'][ctr]['config']['type']))
                    if not resp_dict[resp_key + ',interfaces,interface,config,enabled']:
                        err_msg.append("The interface {} is not enabled. Current status is {}".format(resp_dict[resp_key + ',interfaces,interface,name'], resp_dict[resp_key + ',interfaces,interface,config,enabled']))
                else:
                    err_msg.append("Interface {} missing from the GET response".format(resp_key))
                ctr += 1    
    
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        err_msg.append("_test_Neg_set_with_vld_del_inv_upd failed due to Grpc Error {err}".format(err=e.details()))

    if len(err_msg) != 0:
        log.error("_test_Neg_set_with_vld_del_inv_upd Step1: failed due to : {}".format(*err_msg))
        err_msg.append("test_Neg_set_with_vld_del_inv_upd Step1: failed due to : {}".format(*err_msg))
    else:
        log.info("test_Neg_set_with_vld_del_inv_upd - Step1: Passed")

    if len(err_msg) == 0:
        log.info('Performing SET w/Multiple Ops(REPLACE+UPDATE) & Prefix-Path \n')
        try:
            if 'Inv_Upd_Neg_1' in input_conf:
                set_info1 = input_conf['Inv_Upd_Neg_1']
                #print(set_info1['prefix-path'])
                print(set_info1['Updates'])
                xpath = "/"
                paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
                #pfx_path = gnmiTestLib._parse_path(gnmiTestLib._path_names(set_info1['prefix-path']))
                reply = gnmiTestLib._set(stub, paths, 'multiple', user, password, set_info1['Updates'])
                resp = str(reply)
                log.info(resp)
                sresp = "".join(resp.split('\n'))
                log.info (sresp)
                mt1 = 'path {    elem {      name: "oc-if:interfaces"    }'
                mt2 = 'response {  path {  }'
                if (mt1 in sresp and mt2 in sresp):
                    log.info("test_Neg_set_with_vld_del_inv_upd:Failed - was able to do SET w/Multiple Ops(REPLACE+UPDATE) & Prefix-Path ")
                    err_msg.append("test_Neg_set_with_vld_del_inv_upd:Failed - was able to do SET w/Multiple Ops(REPLACE+UPDATE) & Prefix-Path ")
        except KeyboardInterrupt:
            log.info("Shutting down.")
        except grpc.RpcError as e:
            log.error("### GRPC ERROR RECEIVED:: ###")
            log.error(e)
            printGrpcError(e)
            if ('StatusCode.ABORTED' in str(e) and 'unknown element: descriptions' in str(e)):
                log.info("test_Neg_set_with_vld_del_inv_upd:Passed - Got the right error message")
            else:
                log.error("test_Neg_set_with_vld_del_inv_upd:Failed - Error message not matching expected message")
                err_msg.append("test_Neg_set_with_vld_del_inv_upd:Failed - Error message not matching expected message")
        
        if len(err_msg) != 0:
            log.error("_test_Neg_set_with_vld_del_inv_upd Step2: failed due to : {}".format(*err_msg))
            err_msg.append("test_Neg_set_with_vld_del_inv_upd Step2: failed due to : {}".format(*err_msg))
        else:
            log.info("test_Neg_set_with_vld_del_inv_upd - Step2: Passed")

    if len(err_msg) == 0:
        log.info("Now lets verify that the changes didn't go through")
        resp_key_list = None
        resp_key_list = list()
        ctr = 0
        try:
            set_info = input_conf['GET_WITH_PFX']
            prefix = input_conf['VERIFY_GET_WITH_PFX']['prefix']
            #prefix = gnmiTestLib._parse_path(gnmiTestLib._path_names(prefix))
            path = input_conf['VERIFY_GET_WITH_PFX']['path']
            path = gnmiTestLib._parse_path(gnmiTestLib._path_names(path))
            response = gnmiTestLib._get(stub, path, user, password,prefix,type='CONFIG')
            #log.info(response)
            msg_dict = google.protobuf.json_format.MessageToDict(response)
            log.info(msg_dict)
            resp_dict = gnmiTestLib.get_oc_response_dict(msg_dict)
            resp_key_list.append(set_info['openconfig-interfaces:interfaces']['interface'][0]['name'])
            resp_key_list.append(set_info['openconfig-interfaces:interfaces']['interface'][1]['name'])

            for resp_key in resp_key_list:
                if resp_key + ',interfaces,interface,name' in resp_dict.keys():
                    
                    if set_info['openconfig-interfaces:interfaces']['interface'][ctr]['name'] != resp_dict[resp_key + ',interfaces,interface,name']:
                        err_msg.append("{} does not match the name in input json file: {}".format(resp_dict[resp_key + ',interfaces,interface,name'], set_info['openconfig-interfaces:interfaces']['interface'][ctr]['name']))
                    if set_info['openconfig-interfaces:interfaces']['interface'][ctr]['config']['description'] != resp_dict[resp_key + ',interfaces,interface,config,description']:
                        err_msg.append("{} does not match the description in input json file: {}".format(resp_dict[resp_key + ',interfaces,interface,config,description'], set_info['openconfig-interfaces:interfaces']['interface'][ctr]['config']['description']))
                    if resp_dict[resp_key + ',interfaces,interface,config,type'] not in set_info['openconfig-interfaces:interfaces']['interface'][ctr]['config']['type']:
                        err_msg.append("{} does not match the type in input json file: {}".format(resp_dict[resp_key + ',interfaces,interface,config,type'], set_info['openconfig-interfaces:interfaces']['interface'][ctr]['config']['type']))
                    if not resp_dict[resp_key + ',interfaces,interface,config,enabled']:
                        err_msg.append("The interface {} is not enabled. Current status is {}".format(resp_dict[resp_key + ',interfaces,interface,name'], resp_dict[resp_key + ',interfaces,interface,config,enabled']))
                else:
                    err_msg.append("Interface {} missing from the GET response".format(resp_key))
                ctr += 1    
        except KeyboardInterrupt:
            log.info("Shutting down.")
        except grpc.RpcError as e:
            log.error("### GRPC ERROR RECEIVED:: ###")
            log.error(e)
            printGrpcError(e)
            err_msg.append("_test_Neg_set_with_vld_del_inv_upd failed due to Grpc Error {err}".format(err=e.details()))

        if len(err_msg) != 0:
            log.error("_test_Neg_set_with_vld_del_inv_upd Step3: failed due to : {}".format(*err_msg))
            err_msg.append("test_Neg_set_with_vld_del_inv_upd Step3: failed due to : {}".format(*err_msg))
        else:
            log.info("test_Neg_set_with_vld_del_inv_upd - Step3: Passed")

    try:
        xpath = "/oc-if:interfaces"
        paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
        reply = gnmiTestLib._set(stub, paths, 'delete', user, password, set_info)
        log.info(str(reply))
        if ('response' in str(reply) and 'op: DELETE' in str(reply)):
            log.info("test_Neg_set_with_vld_del_inv_upd:Passed - was able to do SET-DELETE on target")
        else:
            log.error("test_Neg_set_with_vld_del_inv_upd:Failed - was unable to do SET-DELETE on target")
            err_msg.append("test_Neg_set_with_vld_del_inv_upd:Failed - was unable to do SET-DELETE on target")
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        pytest.fail("test_Neg_set_with_vld_del_inv_upd - Delete Config during cleanup failed due to Grpc Error {err}".format(err=e.details()))

    if len(err_msg) != 0:
        log.error("Test test_Neg_set_with_vld_del_inv_upd failed due to : {}".format(*err_msg))
        pytest.fail("Test test_Neg_set_with_vld_del_inv_upd failed due to : {}".format(*err_msg))
    else:
        log.info("Test test_Neg_set_with_vld_del_inv_upd - Passed")


def _test_set_with_mul_attr_val(stub):
    user = None
    password = None
    err_msg = list()
    resp_key_list = list()
    ctr = 0
    
    input_conf = json.loads(six.moves.builtins.open(ApData.zap.get_testcase_configuration("test_Get_with_prefix/input_conf_file"), 'r').read())
    
    log.info('Performing SET-REPLACE Request to target \n')
    try:
        if 'GET_WITH_PFX' in input_conf:
            set_info = input_conf['GET_WITH_PFX']
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            reply = gnmiTestLib._set(stub, paths, 'replace', user, password, set_info)
            log.info(str(reply))
            if ('response' in str(reply) and 'op: REPLACE' in str(reply)):
                log.info("test_set_with_mul_attr_val:Passed - was able to do SET-REPLACE with input json")
            else:
                log.info("test_set_with_mul_attr_val:Failed - was unable to do SET-REPLACE with input json")
            
            #xpath = "/if:interfaces/if:interface"
            prefix = input_conf['VERIFY_GET_WITH_PFX']['prefix']
            #prefix = gnmiTestLib._parse_path(gnmiTestLib._path_names(prefix))
            path = input_conf['VERIFY_GET_WITH_PFX']['path']
            path = gnmiTestLib._parse_path(gnmiTestLib._path_names(path))
            response = gnmiTestLib._get(stub, path, user, password,prefix,type='CONFIG')
            #log.info(response)
            msg_dict = google.protobuf.json_format.MessageToDict(response)
            log.info(msg_dict)
            resp_dict = gnmiTestLib.get_oc_response_dict(msg_dict)
            resp_key_list.append(set_info['openconfig-interfaces:interfaces']['interface'][0]['name'])
            resp_key_list.append(set_info['openconfig-interfaces:interfaces']['interface'][1]['name'])
            
            for resp_key in resp_key_list:
                if resp_key + ',interfaces,interface,name' in resp_dict.keys():
                    if set_info['openconfig-interfaces:interfaces']['interface'][ctr]['name'] != resp_dict[resp_key + ',interfaces,interface,name']:
                        err_msg.append("{} does not match the name in input json file: {}".format(resp_dict[resp_key + ',interfaces,interface,name'], set_info['openconfig-interfaces:interfaces']['interface'][ctr]['name']))
                    if set_info['openconfig-interfaces:interfaces']['interface'][ctr]['config']['description'] != resp_dict[resp_key + ',interfaces,interface,config,description']:
                        err_msg.append("{} does not match the description in input json file: {}".format(resp_dict[resp_key + ',interfaces,interface,config,description'], set_info['openconfig-interfaces:interfaces']['interface'][ctr]['config']['description']))
                    if resp_dict[resp_key + ',interfaces,interface,config,type'] not in set_info['openconfig-interfaces:interfaces']['interface'][ctr]['config']['type']:
                        err_msg.append("{} does not match the type in input json file: {}".format(resp_dict[resp_key + ',interfaces,interface,config,type'], set_info['openconfig-interfaces:interfaces']['interface'][ctr]['config']['type']))
                    if not resp_dict[resp_key + ',interfaces,interface,config,enabled']:
                        err_msg.append("The interface {} is not enabled. Current status is {}".format(resp_dict[resp_key + ',interfaces,interface,name'], resp_dict[resp_key + ',interfaces,interface,config,enabled']))
                else:
                    err_msg.append("Interface {} missing from the GET response".format(resp_key))
                ctr += 1    
    
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        err_msg.append("test_set_with_mul_attr_val failed due to Grpc Error {err}".format(err=e.details()))

    if len(err_msg) != 0:
        log.error("test_set_with_mul_attr_val Step1: failed due to : {}".format(*err_msg))
        err_msg.append("test_set_with_mul_attr_val Step1: failed due to : {}".format(*err_msg))
    else:
        log.info("test_set_with_mul_attr_val - Step1: Passed")

    if len(err_msg) == 0:
        log.info('Performing SET w/Multiple Attributes (REPLACE) \n')
        ctr = 0
        resp_key_list = None
        resp_key_list = list()
        try:
            if 'Mult_Set_Rep_1' in input_conf:
                set_info = input_conf['Mult_Set_Rep_1']
                xpath = "/"
                paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
                reply = gnmiTestLib._set(stub, paths, 'replace', user, password, set_info)
                resp = str(reply)
                log.info(resp)
            if ('response' in str(reply) and 'op: REPLACE' in str(reply)):
                log.info("test_set_with_mul_attr_val:Passed - was able to do SET-REPLACE with input json")
            else:
                log.info("test_set_with_mul_attr_val:Failed - was unable to do SET-REPLACE with input json")
            
            
            prefix = input_conf['VERIFY_GET_WITH_PFX']['prefix']
            path = input_conf['VERIFY_GET_WITH_PFX']['path']
            path = gnmiTestLib._parse_path(gnmiTestLib._path_names(path))
            response = gnmiTestLib._get(stub, path, user, password,prefix,type='CONFIG')
            #log.info(response)
            msg_dict = google.protobuf.json_format.MessageToDict(response)
            log.info(msg_dict)
            resp_dict = gnmiTestLib.get_oc_response_dict(msg_dict)
            resp_key_list.append(set_info['openconfig-interfaces:interfaces']['interface'][0]['name'])
            resp_key_list.append(set_info['openconfig-interfaces:interfaces']['interface'][1]['name'])

            for resp_key in resp_key_list:
                if resp_key + ',interfaces,interface,name' in resp_dict.keys():
                    if set_info['openconfig-interfaces:interfaces']['interface'][ctr]['name'] != resp_dict[resp_key + ',interfaces,interface,name']:
                        err_msg.append("{} does not match the name in input json file: {}".format(resp_dict[resp_key + ',interfaces,interface,name'], set_info['openconfig-interfaces:interfaces']['interface'][ctr]['name']))
                    if set_info['openconfig-interfaces:interfaces']['interface'][ctr]['config']['description'] != resp_dict[resp_key + ',interfaces,interface,config,description']:
                        err_msg.append("{} does not match the description in input json file: {}".format(resp_dict[resp_key + ',interfaces,interface,config,description'], set_info['openconfig-interfaces:interfaces']['interface'][ctr]['config']['description']))
                    if resp_dict[resp_key + ',interfaces,interface,config,type'] not in set_info['openconfig-interfaces:interfaces']['interface'][ctr]['config']['type']:
                        err_msg.append("{} does not match the type in input json file: {}".format(resp_dict[resp_key + ',interfaces,interface,config,type'], set_info['openconfig-interfaces:interfaces']['interface'][ctr]['config']['type']))
                    if resp_dict[resp_key + ',interfaces,interface,config,mtu'] not in set_info['openconfig-interfaces:interfaces']['interface'][ctr]['config']['mtu']:
                        err_msg.append("{} does not match the type in input json file: {}".format(resp_dict[resp_key + ',interfaces,interface,config,mtu'], set_info['openconfig-interfaces:interfaces']['interface'][ctr]['config']['mtu']))
                    if not resp_dict[resp_key + ',interfaces,interface,config,enabled']:
                        err_msg.append("The interface {} is not enabled. Current status is {}".format(resp_dict[resp_key + ',interfaces,interface,name'], resp_dict[resp_key + ',interfaces,interface,config,enabled']))
                else:
                    err_msg.append("Interface {} missing from the GET response".format(resp_key))
                ctr += 1    

        except KeyboardInterrupt:
            log.info("Shutting down.")
        except grpc.RpcError as e:
            log.error("### GRPC ERROR RECEIVED:: ###")
            log.error(e)
            printGrpcError(e)
            err_msg.append("test_set_with_mul_attr_val-REPLACE:Failed - due to grpc error : {}".format(e))
        
        if len(err_msg) != 0:
            log.error("test_set_with_mul_attr_val-REPLACE: failed due to : {}".format(*err_msg))
            err_msg.append("test_set_with_mul_attr_val-REPLACE: failed due to : {}".format(*err_msg))
        else:
            log.info("test_set_with_mul_attr_val-REPLACE: Passed") 

    if len(err_msg) == 0:
        log.info('Performing SET w/Multiple Attributes (UPDATE) \n')
        ctr = 0
        resp_key_list = None
        resp_key_list = list()
        try:
            if 'GET_WITH_PFX' in input_conf:
                set_info = input_conf['GET_WITH_PFX']
                xpath = "/"
                paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
                reply = gnmiTestLib._set(stub, paths, 'update', user, password, set_info)
                resp = str(reply)
                log.info(resp)
            if ('response' in str(reply) and 'op: UPDATE' in str(reply)):
                log.info("test_set_with_mul_attr_val:Passed - was able to do SET-UPDATE with input json")
            else:
                log.info("test_set_with_mul_attr_val:Failed - was unable to do SET-UPDATE with input json")
            
            
            prefix = input_conf['VERIFY_GET_WITH_PFX']['prefix']
            path = input_conf['VERIFY_GET_WITH_PFX']['path']
            path = gnmiTestLib._parse_path(gnmiTestLib._path_names(path))
            response = gnmiTestLib._get(stub, path, user, password,prefix,type='CONFIG')
            #log.info(response)
            msg_dict = google.protobuf.json_format.MessageToDict(response)
            log.info(msg_dict)
            resp_dict = gnmiTestLib.get_oc_response_dict(msg_dict)
            resp_key_list.append(set_info['openconfig-interfaces:interfaces']['interface'][0]['name'])
            resp_key_list.append(set_info['openconfig-interfaces:interfaces']['interface'][1]['name'])

            for resp_key in resp_key_list:
                if resp_key + ',interfaces,interface,name' in resp_dict.keys():
                    if set_info['openconfig-interfaces:interfaces']['interface'][ctr]['name'] != resp_dict[resp_key + ',interfaces,interface,name']:
                        err_msg.append("{} does not match the name in input json file: {}".format(resp_dict[resp_key + ',interfaces,interface,name'], set_info['openconfig-interfaces:interfaces']['interface'][ctr]['name']))
                    if set_info['openconfig-interfaces:interfaces']['interface'][ctr]['config']['description'] != resp_dict[resp_key + ',interfaces,interface,config,description']:
                        err_msg.append("{} does not match the description in input json file: {}".format(resp_dict[resp_key + ',interfaces,interface,config,description'], set_info['openconfig-interfaces:interfaces']['interface'][ctr]['config']['description']))
                    if resp_dict[resp_key + ',interfaces,interface,config,type'] not in set_info['openconfig-interfaces:interfaces']['interface'][ctr]['config']['type']:
                        err_msg.append("{} does not match the type in input json file: {}".format(resp_dict[resp_key + ',interfaces,interface,config,type'], set_info['openconfig-interfaces:interfaces']['interface'][ctr]['config']['type']))
                    if resp_dict[resp_key + ',interfaces,interface,config,mtu'] not in set_info['openconfig-interfaces:interfaces']['interface'][ctr]['config']['mtu']:
                        err_msg.append("{} does not match the type in input json file: {}".format(resp_dict[resp_key + ',interfaces,interface,config,mtu'], set_info['openconfig-interfaces:interfaces']['interface'][ctr]['config']['mtu']))
                    if not resp_dict[resp_key + ',interfaces,interface,config,enabled']:
                        err_msg.append("The interface {} is not enabled. Current status is {}".format(resp_dict[resp_key + ',interfaces,interface,name'], resp_dict[resp_key + ',interfaces,interface,config,enabled']))
                else:
                    err_msg.append("Interface {} missing from the GET response".format(resp_key))
                ctr += 1    

        except KeyboardInterrupt:
            log.info("Shutting down.")
        except grpc.RpcError as e:
            log.error("### GRPC ERROR RECEIVED:: ###")
            log.error(e)
            printGrpcError(e)
            err_msg.append("test_set_with_mul_attr_val-REPLACE:Failed - due to grpc error : {}".format(e))

        if len(err_msg) != 0:
            log.error("test_set_with_mul_attr_val-UPDATE: failed due to : {}".format(*err_msg))
            err_msg.append("test_set_with_mul_attr_val-UPDATE: failed due to : {}".format(*err_msg))
        else:
            log.info("test_set_with_mul_attr_val-UPDATE: Passed") 
    
    try:
        xpath = "/oc-if:interfaces"
        paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
        reply = gnmiTestLib._set(stub, paths, 'delete', user, password, set_info)
        log.info(str(reply))
        if ('response' in str(reply) and 'op: DELETE' in str(reply)):
            log.info("test_set_with_mul_attr_val:Passed - was able to do SET-DELETE on target")
        else:
            log.error("test_set_with_mul_attr_val:Failed - was unable to do SET-DELETE on target")
            err_msg.append("test_set_with_mul_attr_val:Failed - was unable to do SET-DELETE on target")
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        pytest.fail("test_set_with_mul_attr_val - Delete Config during cleanup failed due to Grpc Error {err}".format(err=e.details()))

    if len(err_msg) != 0:
        log.error("Test test_set_with_mul_attr_val failed due to : {}".format(*err_msg))
        pytest.fail("Test test_set_with_mul_attr_val failed due to : {}".format(*err_msg))
    else:
        log.info("Test test_set_with_mul_attr_val - Passed")

def _test_Set_with_partial_val(stub):
    user = None
    password = None
    err_msg = list()
    resp_key_list = list()
    ctr = 0
    
    input_conf = json.loads(six.moves.builtins.open(ApData.zap.get_testcase_configuration("test_Get_with_prefix/input_conf_file"), 'r').read())
    
    log.info('Performing SET-REPLACE Request to target \n')
    try:
        if 'GET_WITH_PFX' in input_conf:
            set_info = input_conf['GET_WITH_PFX']
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            reply = gnmiTestLib._set(stub, paths, 'replace', user, password, set_info)
            log.info(str(reply))
            if ('response' in str(reply) and 'op: REPLACE' in str(reply)):
                log.info("test_Set_with_partial_val:Passed - was able to do SET-REPLACE with input json")
            else:
                log.info("test_Set_with_partial_val:Failed - was unable to do SET-REPLACE with input json")
            
            #xpath = "/if:interfaces/if:interface"
            prefix = input_conf['VERIFY_GET_WITH_PFX']['prefix']
            #prefix = gnmiTestLib._parse_path(gnmiTestLib._path_names(prefix))
            path = input_conf['VERIFY_GET_WITH_PFX']['path']
            path = gnmiTestLib._parse_path(gnmiTestLib._path_names(path))
            response = gnmiTestLib._get(stub, path, user, password,prefix,type='CONFIG')
            #log.info(response)
            msg_dict = google.protobuf.json_format.MessageToDict(response)
            log.info(msg_dict)
            resp_dict = gnmiTestLib.get_oc_response_dict(msg_dict)
            resp_key_list.append(set_info['openconfig-interfaces:interfaces']['interface'][0]['name'])
            resp_key_list.append(set_info['openconfig-interfaces:interfaces']['interface'][1]['name'])
            
            for resp_key in resp_key_list:
                if resp_key + ',interfaces,interface,name' in resp_dict.keys():
                    if set_info['openconfig-interfaces:interfaces']['interface'][ctr]['name'] != resp_dict[resp_key + ',interfaces,interface,name']:
                        err_msg.append("{} does not match the name in input json file: {}".format(resp_dict[resp_key + ',interfaces,interface,name'], set_info['openconfig-interfaces:interfaces']['interface'][ctr]['name']))
                    if set_info['openconfig-interfaces:interfaces']['interface'][ctr]['config']['description'] != resp_dict[resp_key + ',interfaces,interface,config,description']:
                        err_msg.append("{} does not match the description in input json file: {}".format(resp_dict[resp_key + ',interfaces,interface,config,description'], set_info['openconfig-interfaces:interfaces']['interface'][ctr]['config']['description']))
                    if resp_dict[resp_key + ',interfaces,interface,config,type'] not in set_info['openconfig-interfaces:interfaces']['interface'][ctr]['config']['type']:
                        err_msg.append("{} does not match the type in input json file: {}".format(resp_dict[resp_key + ',interfaces,interface,config,type'], set_info['openconfig-interfaces:interfaces']['interface'][ctr]['config']['type']))
                    if not resp_dict[resp_key + ',interfaces,interface,config,enabled']:
                        err_msg.append("The interface {} is not enabled. Current status is {}".format(resp_dict[resp_key + ',interfaces,interface,name'], resp_dict[resp_key + ',interfaces,interface,config,enabled']))
                else:
                    err_msg.append("Interface {} missing from the GET response".format(resp_key))
                ctr += 1    
    
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        err_msg.append("test_Set_with_partial_val failed due to Grpc Error {err}".format(err=e.details()))

    if len(err_msg) != 0:
        log.error("test_Set_with_partial_val Step1: failed due to : {}".format(*err_msg))
        err_msg.append("test_Set_with_partial_val Step1: failed due to : {}".format(*err_msg))
    else:
        log.info("test_Set_with_partial_val - Step1: Passed")

    if len(err_msg) == 0:
        log.info('Performing SET w/Some Attributes (REPLACE) \n')
        ctr = 0
        resp_key_list = None
        resp_key_list = list()
        try:
            if 'Neg_Set_Partial_1' in input_conf:
                set_info = input_conf['Neg_Set_Partial_1']
                xpath = "/"
                paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
                reply = gnmiTestLib._set(stub, paths, 'replace', user, password, set_info)
                resp = str(reply)
                log.info(resp)
            if ('response' in str(reply) and 'op: REPLACE' in str(reply)):
                log.info("test_Set_with_partial_val:Passed - was able to do SET-REPLACE with input json")
            else:
                log.info("test_Set_with_partial_val:Failed - was unable to do SET-REPLACE with input json")
            
            
            prefix = input_conf['VERIFY_GET_WITH_PFX']['prefix']
            path = input_conf['VERIFY_GET_WITH_PFX']['path']
            path = gnmiTestLib._parse_path(gnmiTestLib._path_names(path))
            response = gnmiTestLib._get(stub, path, user, password,prefix,type='CONFIG')
            #log.info(response)
            msg_dict = google.protobuf.json_format.MessageToDict(response)
            log.info(msg_dict)
            resp_dict = gnmiTestLib.get_oc_response_dict(msg_dict)
            resp_key_list.append(set_info['openconfig-interfaces:interfaces']['interface'][0]['name'])
            resp_key_list.append(set_info['openconfig-interfaces:interfaces']['interface'][1]['name'])

            for resp_key in resp_key_list:
                if resp_key + ',interfaces,interface,name' in resp_dict.keys():
                    if set_info['openconfig-interfaces:interfaces']['interface'][ctr]['name'] != resp_dict[resp_key + ',interfaces,interface,name']:
                        err_msg.append("{} does not match the name in input json file: {}".format(resp_dict[resp_key + ',interfaces,interface,name'], set_info['openconfig-interfaces:interfaces']['interface'][ctr]['name']))
                    if set_info['openconfig-interfaces:interfaces']['interface'][ctr]['config']['description'] != resp_dict[resp_key + ',interfaces,interface,config,description']:
                        err_msg.append("{} does not match the description in input json file: {}".format(resp_dict[resp_key + ',interfaces,interface,config,description'], set_info['openconfig-interfaces:interfaces']['interface'][ctr]['config']['description']))
                    if resp_dict[resp_key + ',interfaces,interface,config,type'] not in set_info['openconfig-interfaces:interfaces']['interface'][ctr]['config']['type']:
                        err_msg.append("{} does not match the type in input json file: {}".format(resp_dict[resp_key + ',interfaces,interface,config,type'], set_info['openconfig-interfaces:interfaces']['interface'][ctr]['config']['type']))
                    if resp_dict[resp_key + ',interfaces,interface,config,mtu'] not in set_info['openconfig-interfaces:interfaces']['interface'][ctr]['config']['mtu']:
                        err_msg.append("{} does not match the type in input json file: {}".format(resp_dict[resp_key + ',interfaces,interface,config,mtu'], set_info['openconfig-interfaces:interfaces']['interface'][ctr]['config']['mtu']))
                    if not resp_dict[resp_key + ',interfaces,interface,config,enabled']:
                        err_msg.append("The interface {} is not enabled. Current status is {}".format(resp_dict[resp_key + ',interfaces,interface,name'], resp_dict[resp_key + ',interfaces,interface,config,enabled']))
                else:
                    err_msg.append("Interface {} missing from the GET response".format(resp_key))
                ctr += 1    

        except KeyboardInterrupt:
            log.info("Shutting down.")
        except grpc.RpcError as e:
            log.error("### GRPC ERROR RECEIVED:: ###")
            log.error(e)
            printGrpcError(e)
            if ('StatusCode.ABORTED' in str(e) and 'type is not configured' in str(e)):
                log.info("test_Set_with_partial_val-REPLACE:Passed - Got the right error message")
            else:
                log.error("test_Set_with_partial_val-REPLACE:Failed - Error message not matching expected message")
                err_msg.append("test_Set_with_partial_val-REPLACE:Failed - Error message not matching expected message")
        
        if len(err_msg) != 0:
            log.error("test_Set_with_partial_val-REPLACE: failed due to : {}".format(*err_msg))
            err_msg.append("test_Set_with_partial_val-REPLACE: failed due to : {}".format(*err_msg))
        else:
            log.info("test_Set_with_partial_val-REPLACE: Passed") 

    if len(err_msg) == 0:
        log.info('Performing SET w/Some Attributes (UPDATE) \n')
        ctr = 0
        resp_key_list = None
        resp_key_list = list()
        try:
            if 'Neg_Set_Partial_1' in input_conf:
                # Bring the state back to initial state    
                set_info = input_conf['GET_WITH_PFX']
                xpath = "/"
                paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
                reply = gnmiTestLib._set(stub, paths, 'replace', user, password, set_info)
                log.info(str(reply))
                if ('response' in str(reply) and 'op: REPLACE' in str(reply)):
                    log.info("test_Set_with_partial_val:Passed - was able to do SET-REPLACE with input json")
                else:
                    log.info("test_Set_with_partial_val:Failed - was unable to do SET-REPLACE with input json")

                set_info = input_conf['Neg_Set_Partial_1']
                xpath = "/"
                paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
                reply = gnmiTestLib._set(stub, paths, 'update', user, password, set_info)
                resp = str(reply)
                log.info(resp)
                if ('response' in str(reply) and 'op: UPDATE' in str(reply)):
                    log.info("test_Set_with_partial_val:Passed - was able to do SET-UPDATE with input json")
                else:
                    log.info("test_Set_with_partial_val:Failed - was unable to do SET-UPDATE with input json")
                
                set_info1 = input_conf['GET_WITH_PFX']
                set_info = input_conf['Neg_Set_Partial_1']
                prefix = input_conf['VERIFY_GET_WITH_PFX']['prefix']
                path = input_conf['VERIFY_GET_WITH_PFX']['path']
                path = gnmiTestLib._parse_path(gnmiTestLib._path_names(path))
                response = gnmiTestLib._get(stub, path, user, password,prefix,type='CONFIG')
                #log.info(response)
                msg_dict = google.protobuf.json_format.MessageToDict(response)
                resp_dict = gnmiTestLib.get_oc_response_dict(msg_dict)
                resp_key_list.append(set_info['openconfig-interfaces:interfaces']['interface'][0]['name'])
                resp_key_list.append(set_info['openconfig-interfaces:interfaces']['interface'][1]['name'])

                for resp_key in resp_key_list:
                    if resp_key + ',interfaces,interface,name' in resp_dict.keys():
                        if set_info['openconfig-interfaces:interfaces']['interface'][ctr]['name'] != resp_dict[resp_key + ',interfaces,interface,name']:
                            err_msg.append("{} does not match the name in input json file: {}".format(resp_dict[resp_key + ',interfaces,interface,name'], set_info['openconfig-interfaces:interfaces']['interface'][ctr]['name']))
                        if set_info['openconfig-interfaces:interfaces']['interface'][ctr]['config']['description'] != resp_dict[resp_key + ',interfaces,interface,config,description']:
                            err_msg.append("{} does not match the description in input json file: {}".format(resp_dict[resp_key + ',interfaces,interface,config,description'], set_info['openconfig-interfaces:interfaces']['interface'][ctr]['config']['description']))
                        if resp_dict[resp_key + ',interfaces,interface,config,type'] not in set_info1['openconfig-interfaces:interfaces']['interface'][ctr]['config']['type']:
                            err_msg.append("{} does not match the type in input json file: {}".format(resp_dict[resp_key + ',interfaces,interface,config,type'], set_info['openconfig-interfaces:interfaces']['interface'][ctr]['config']['type']))
                        if resp_dict[resp_key + ',interfaces,interface,config,mtu'] not in set_info1['openconfig-interfaces:interfaces']['interface'][ctr]['config']['mtu']:
                            err_msg.append("{} does not match the type in input json file: {}".format(resp_dict[resp_key + ',interfaces,interface,config,mtu'], set_info['openconfig-interfaces:interfaces']['interface'][ctr]['config']['mtu']))
                        if not resp_dict[resp_key + ',interfaces,interface,config,enabled']:
                            err_msg.append("The interface {} is not enabled. Current status is {}".format(resp_dict[resp_key + ',interfaces,interface,name'], resp_dict[resp_key + ',interfaces,interface,config,enabled']))
                    else:
                        err_msg.append("Interface {} missing from the GET response".format(resp_key))
                    ctr += 1    

        except KeyboardInterrupt:
            log.info("Shutting down.")
        except grpc.RpcError as e:
            log.error("### GRPC ERROR RECEIVED:: ###")
            printGrpcError(e)
            err_msg.append("test_Set_with_partial_val-UPDATE:Failed - due to GRPC Error {}".format(printGrpcError(e)))
        
        if len(err_msg) != 0:
            log.error("test_Set_with_partial_val-UPDATE: failed due to : {}".format(*err_msg))
            err_msg.append("test_Set_with_partial_val-UPDATE: failed due to : {}".format(*err_msg))
        else:
            log.info("test_Set_with_partial_val-UPDATE: Passed") 

    try:
        xpath = "/oc-if:interfaces"
        paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
        reply = gnmiTestLib._set(stub, paths, 'delete', user, password, set_info)
        log.info(str(reply))
        if ('response' in str(reply) and 'op: DELETE' in str(reply)):
            log.info("test_Set_with_partial_val:Passed - was able to do SET-DELETE on target")
        else:
            log.error("test_Set_with_partial_val:Failed - was unable to do SET-DELETE on target")
            err_msg.append("test_Set_with_partial_val:Failed - was unable to do SET-DELETE on target")
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        pytest.fail("test_Set_with_partial_val - Delete Config during cleanup failed due to Grpc Error {err}".format(err=e.details()))

    if len(err_msg) != 0:
        log.error("Test test_Set_with_partial_val failed due to : {}".format(*err_msg))
        pytest.fail("Test test_Set_with_partial_val failed due to : {}".format(*err_msg))
    else:
        log.info("Test test_Set_with_partial_val - Passed")

def _test_Path_with_keys(stub):
    user = None
    password = None
    err_msg = list()
    ctr = 0
    
    input_conf = json.loads(six.moves.builtins.open(ApData.zap.get_testcase_configuration("test_Get_with_prefix/input_conf_file"), 'r').read())
    
    log.info('Performing SET-REPLACE Request to target \n')
    try:
        if 'GET_WITH_PFX' in input_conf:
            set_info = input_conf['GET_WITH_PFX']
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            reply = gnmiTestLib._set(stub, paths, 'replace', user, password, set_info)
            log.info(str(reply))
            if ('response' in str(reply) and 'op: REPLACE' in str(reply)):
                log.info("test_Path_with_keys:Passed - was able to do SET-REPLACE with input json")
            else:
                log.info("test_Path_with_keys:Failed - was unable to do SET-REPLACE with input json")
            
        if 'PATH_CHECK' in input_conf:
            set_info = input_conf['PATH_CHECK']
            xpath ="openconfig-interfaces:interfaces/interface[name=Loopback123]"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            reply = gnmiTestLib._set(stub, paths, 'update', user, password, set_info)
            log.info(str(reply))
            if ('response' in str(reply) and 'op: UPDATE' in str(reply)):
                log.info("test_Path_with_keys:Passed - was able to do SET-UPDATE with input json")
            else:
                log.info("test_Path_with_keys:Failed - was unable to do SET-UPDATE with input json")
                        
            #xpath = "/if:interfaces/if:interface"
            prefix = input_conf['VERIFY_GET_WITH_PATH_CHECK']['prefix']
            #prefix = gnmiTestLib._parse_path(gnmiTestLib._path_names(prefix))
            path = input_conf['VERIFY_GET_WITH_PATH_CHECK']['path']
            path = gnmiTestLib._parse_path(gnmiTestLib._path_names(path))
            response = gnmiTestLib._get(stub, path, user, password,prefix,type='CONFIG')
            #log.info(response)
            msg_dict = google.protobuf.json_format.MessageToDict(response)
            #log.info(msg_dict)
            set_info = input_conf['GET_WITH_PFX']
            resp_dict = gnmiTestLib.get_oc_response_dict(msg_dict)
            resp_key = "Loopback123"
            if resp_key + ',interfaces,interface,name' in resp_dict.keys():
                if set_info['openconfig-interfaces:interfaces']['interface'][ctr]['name'] != resp_dict[resp_key + ',interfaces,interface,name']:
                    err_msg.append("{} does not match the name in input json file: {}".format(resp_dict[resp_key + ',interfaces,interface,name'], set_info['openconfig-interfaces:interfaces']['interface'][ctr]['name']))
                if "For path check TC" != resp_dict[resp_key + ',interfaces,interface,config,description']:
                    err_msg.append("{} does not match the description in input json file: {}".format(resp_dict[resp_key + ',interfaces,interface,config,description'], set_info['openconfig-interfaces:interfaces']['interface'][ctr]['config']['description']))
                if resp_dict[resp_key + ',interfaces,interface,config,type'] not in set_info['openconfig-interfaces:interfaces']['interface'][ctr]['config']['type']:
                    err_msg.append("{} does not match the type in input json file: {}".format(resp_dict[resp_key + ',interfaces,interface,config,type'], set_info['openconfig-interfaces:interfaces']['interface'][ctr]['config']['type']))
                if not resp_dict[resp_key + ',interfaces,interface,config,enabled']:
                    err_msg.append("The interface {} is not enabled. Current status is {}".format(resp_dict[resp_key + ',interfaces,interface,name'], resp_dict[resp_key + ',interfaces,interface,config,enabled']))
            else:
                err_msg.append("Interface {} missing from the GET response".format(resp_key))
    
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        err_msg.append("test_Path_with_keys (SET-UPDATE) failed due to Grpc Error {err}".format(err=e.details()))

    try:
        if 'GET_WITH_PFX' in input_conf:
            set_info = input_conf['GET_WITH_PFX']
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            reply = gnmiTestLib._set(stub, paths, 'replace', user, password, set_info)
            log.info(str(reply))
            if ('response' in str(reply) and 'op: REPLACE' in str(reply)):
                log.info("test_Path_with_keys:Passed - was able to do SET-REPLACE with input json")
            else:
                log.info("test_Path_with_keys:Failed - was unable to do SET-REPLACE with input json")
            
        if 'PATH_CHECK' in input_conf:
            set_info = input_conf['PATH_CHECK']
            xpath ="openconfig-interfaces:interfaces/interface[name=Loopback123]"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            reply = gnmiTestLib._set(stub, paths, 'replace', user, password, set_info)
            log.info(str(reply))
            if ('response' in str(reply) and 'op: REPLACE' in str(reply)):
                log.info("test_Path_with_keys:Passed - was able to do SET-REPLACE with input json")
            else:
                log.info("test_Path_with_keys:Failed - was unable to do SET-REPLACE with input json")
                        
            #xpath = "/if:interfaces/if:interface"
            prefix = input_conf['VERIFY_GET_WITH_PATH_CHECK']['prefix']
            #prefix = gnmiTestLib._parse_path(gnmiTestLib._path_names(prefix))
            path = input_conf['VERIFY_GET_WITH_PATH_CHECK']['path']
            path = gnmiTestLib._parse_path(gnmiTestLib._path_names(path))
            response = gnmiTestLib._get(stub, path, user, password,prefix,type='CONFIG')
            #log.info(response)
            msg_dict = google.protobuf.json_format.MessageToDict(response)
            #log.info(msg_dict)
            set_info = input_conf['GET_WITH_PFX']
            resp_dict = gnmiTestLib.get_oc_response_dict(msg_dict)
            resp_key = "Loopback123"
            if resp_key + ',interfaces,interface,name' in resp_dict.keys():
                if set_info['openconfig-interfaces:interfaces']['interface'][ctr]['name'] != resp_dict[resp_key + ',interfaces,interface,name']:
                    err_msg.append("{} does not match the name in input json file: {}".format(resp_dict[resp_key + ',interfaces,interface,name'], set_info['openconfig-interfaces:interfaces']['interface'][ctr]['name']))
                if "For path check TC" != resp_dict[resp_key + ',interfaces,interface,config,description']:
                    err_msg.append("{} does not match the description in input json file: {}".format(resp_dict[resp_key + ',interfaces,interface,config,description'], set_info['openconfig-interfaces:interfaces']['interface'][ctr]['config']['description']))
                if resp_dict[resp_key + ',interfaces,interface,config,type'] not in set_info['openconfig-interfaces:interfaces']['interface'][ctr]['config']['type']:
                    err_msg.append("{} does not match the type in input json file: {}".format(resp_dict[resp_key + ',interfaces,interface,config,type'], set_info['openconfig-interfaces:interfaces']['interface'][ctr]['config']['type']))
                if not resp_dict[resp_key + ',interfaces,interface,config,enabled']:
                    err_msg.append("The interface {} is not enabled. Current status is {}".format(resp_dict[resp_key + ',interfaces,interface,name'], resp_dict[resp_key + ',interfaces,interface,config,enabled']))
            else:
                err_msg.append("Interface {} missing from the GET response".format(resp_key))
    
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        err_msg.append("test_Path_with_keys (SET-REPLACE) failed due to Grpc Error {err}".format(err=e.details()))
    
    try:
        xpath = "/oc-if:interfaces/oc-if:interface[name=Loopback123]"
        paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
        reply = gnmiTestLib._set(stub, paths, 'delete', user, password, set_info)
        log.info(str(reply))
        if ('response' in str(reply) and 'op: DELETE' in str(reply)):
            log.info("test_Path_with_keys:Passed - was able to do SET-DELETE with attributes on target")
        else:
            log.error("test_Path_with_keys:Failed - was unable to do SET-DELETE with attributes on target")
            err_msg.append("test_Path_with_keys:Failed - was unable to do SET-DELETE with attributes on target")
        
        xpath = "/oc-if:interfaces"
        paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
        reply = gnmiTestLib._set(stub, paths, 'delete', user, password, set_info)
        log.info(str(reply))
        if ('response' in str(reply) and 'op: DELETE' in str(reply)):
            log.info("test_Path_with_keys:Passed - was able to do SET-DELETE on target")
        else:
            log.error("test_Path_with_keys:Failed - was unable to do SET-DELETE on target")
            err_msg.append("test_Path_with_keys:Failed - was unable to do SET-DELETE on target")
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        err_msg.append("test_Path_with_keys - Delete Config during cleanup failed due to Grpc Error {err}".format(err=e.details()))

    if len(err_msg) != 0:
        log.error("Test test_Path_with_keys failed due to : {}".format(*err_msg))
        pytest.fail("Test test_Path_with_keys failed due to : {}".format(*err_msg))
    else:
        log.info("Test test_Path_with_keys - Passed")
    
def _test_Set_InvldPath1(stub):
    user = None
    password = None
    err_msg = list()
    rslt = True
    #with open(ApData.input_conf_file, 'r') as ip_conf_file:
    #    input_conf = gnmiTestLib.json_load_byteified(ip_conf_file)

    input_conf = json.loads(six.moves.builtins.open(ApData.zap.get_testcase_configuration("test_GetSet_Sanity1/input_conf_file"), 'r').read())

    log.info('Performing SET-REPLACE w/Invalid Path to target \n')
    try:
        if 'SET_InvldPath_1' in input_conf:
            set_info1 = input_conf['SET_InvldPath_1']
            print(set_info1)
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            reply = gnmiTestLib._set(stub, paths, 'replace', user, password, set_info1)
            log.info(str(reply))
            if ('response' in str(reply) and 'op: REPLACE' in str(reply)):
                log.error("SET_InvldPath1_1:FAILED - should not be able to do SET-REPLACE with Invalid Path")
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        if ('StatusCode.NOT_FOUND' in str(e) and 'unknown element' in str(e)):
            log.info("Test SET_InvldPath1_1::Passed - received correct error message on SET-REPLACE with Invalid Path")
        else:
            rslt = False
            log.error("Test SET_InvldPath1_1::Failed - rcvd incorrect error message on SET-REPLACE with Invalid Path")

    log.info('Performing SET-UPDATE w/Invalid Path to target \n')
    try:
        if 'SET_InvldPath_1' in input_conf:
            set_info1 = input_conf['SET_InvldPath_1']
            print(set_info1)
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            reply = gnmiTestLib._set(stub, paths, 'update', user, password, set_info1)
            log.info(str(reply))
            if ('response' in str(reply) and 'op: UPDATE' in str(reply)):
                log.error("SET_InvldPath1_2:FAILED - should not be able to do SET-UPDATE with Invalid Path")
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        if ('StatusCode.NOT_FOUND' in str(e) and 'unknown element' in str(e)):
            log.info("Test SET_InvldPath1_2::Passed - received correct error message on SET-UPDATE with Invalid Path")
        else:
            rslt = False
            log.error("Test SET_InvldPath1_2::Failed - rcvd incorrect error message on SET-UPDATE with Invalid Path")


    finally:
        if rslt:
            log.info("Test SET_InvldPath1:Passed - Error Scenarios for SET w/Invalid Path Passed")
        else:
            pytest.fail("Test SET_InvldPath1:Failed - One or More Error Scenarios for SET w/Invalid Path FAILED")


def _test_SetRpl_Omit1(stub):
    user = None
    password = None
    err_msg = list()
    rslt = True
    #with open(ApData.input_conf_file, 'r') as ip_conf_file:
    #    input_conf = gnmiTestLib.json_load_byteified(ip_conf_file)

    input_conf = json.loads(six.moves.builtins.open(ApData.zap.get_testcase_configuration("test_GetSet_Sanity1/input_conf_file"), 'r').read())

    log.info('Performing SET-REPLACE w/Omitting Options to target \n')
    try:
        if 'SET_RplOmit_1' in input_conf:
            set_info1 = input_conf['SET_RplOmit_1']
            print(set_info1['set-replace'])
            print("###############")
            print(set_info1['set-omit'])
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            reply = gnmiTestLib._set(stub, paths, 'replace', user, password, set_info1['set-replace'])
            log.info(str(reply))
            if ('response' in str(reply) and 'op: REPLACE' in str(reply)):
                log.info("SET_RplOmit1_1:Passed - was able to do SET-REPLACE with input json")
            else:
                log.info("SET_RplOmit1_1:Failed - was unable to do SET-REPLACE with input json")
                rslt = False
            
        if rslt:
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            reply = gnmiTestLib._set(stub, paths, 'replace', user, password, set_info1['set-omit'])
            log.info(str(reply))
            if ('response' in str(reply) and 'op: REPLACE' in str(reply)):
                log.info("SET_RplOmit1_2:Passed - was able to do SET-REPLACE Omitting data elements")
            else:
                log.info("SET_RplOmit1_2:Failed - was unable to do SET-REPLACE Omitting data elements")
                rslt = False

            #xpath = "/if:interfaces/if:interface"
            xpath = input_conf['VERIFY_GETSET_Sanity1_1']['filter']
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            response = gnmiTestLib._get(stub, paths, user, password)
            log.info(response)
            msg_dict = google.protobuf.json_format.MessageToDict(response)
            log.info(msg_dict)
            resp_dict = gnmiTestLib.get_oc_response_dict(msg_dict)
            print("################")
            print(resp_dict.keys())
            print(resp_dict.values())
            print(set_info1['set-omit'])
            print("################")
            resp_key = "SetRplOmt1"
            if resp_dict.get(resp_key + ',interfaces,interface,description') != None:
                err_msg.append("{} 'description' key should not be present in config as it was not sent in SET-REPLACE")
            if set_info1['set-omit']['ietf-interfaces:interfaces']['interface'][0]['name'] != resp_dict[resp_key + ',interfaces,interface,name']:
                err_msg.append("{} does not match the name in input json file: {}".format(resp_dict[resp_key + ',interfaces,interface,name'], set_info1['ietf-interfaces:interfaces']['interface'][0]['name']))
            #if set_info1['set-omit']['ietf-interfaces:interfaces']['interface'][0]['description'] != resp_dict[resp_key + ',description']:
            #    err_msg.append("{} does not match the description in input json file: {}".format(resp_dict[resp_key + ',description'], set_info1['ietf-interfaces:interfaces']['interface'][0]['description']))
            if resp_dict[resp_key + ',interfaces,interface,type'] not in set_info1['set-omit']['ietf-interfaces:interfaces']['interface'][0]['type']:
                err_msg.append("{} does not match the type in input json file: {}".format(resp_dict[resp_key + ',interfaces,interface,type'], set_info1['ietf-interfaces:interfaces']['interface'][0]['type']))
            if resp_dict.get(resp_key + ',interfaces,interface,enabled') !=None:
               log.info("SET_RplOmit1_3:Passed - Default values created even though they are not sent in SET-REPLACE")
               def_val = "SET_RplOmit1_3:Passed - Default value for Interface 'enabled' created = " + str(resp_dict.get(resp_key + ',interfaces,interface,enabled'))
               log.info(def_val)
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        raise CafyException.VerificationError("Test SET_RplOmit1_1 failed due to Grpc Error {err}".format(err=e.details()))

    if len(err_msg) != 0:
        log.error("Test SET_RplOmit1 failed due to : {}".format(*err_msg))
    else:
        log.info("Test SET_RplOmit1 - PASSED")