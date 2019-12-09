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
            resp_dict = gnmiTestLib.get_response_dict(msg_dict)
            for resp_key in resp_dict['key_list']:
                if set_info1['ietf-interfaces:interfaces']['interface'][0]['name'] != resp_dict[resp_key + ',name']:
                    err_msg.append("{} does not match the name in input json file: {}".format(resp_dict[resp_key + ',name'], set_info1['ietf-interfaces:interfaces']['interface'][0]['name']))
                if set_info1['ietf-interfaces:interfaces']['interface'][0]['description'] != resp_dict[resp_key + ',description']:
                    err_msg.append("{} does not match the description in input json file: {}".format(resp_dict[resp_key + ',description'], set_info1['ietf-interfaces:interfaces']['interface'][0]['description']))
                if resp_dict[resp_key + ',type'] not in set_info1['ietf-interfaces:interfaces']['interface'][0]['type']:
                    err_msg.append("{} does not match the type in input json file: {}".format(resp_dict[resp_key + ',type'], set_info1['ietf-interfaces:interfaces']['interface'][0]['type']))
                if not resp_dict[resp_key + ',enabled']:
                    err_msg.append("The interface {} is not enabled. Current status is {}".format(resp_dict[resp_key + ',name'], resp_dict[resp_key + ',enabled']))
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
            resp_dict = gnmiTestLib.get_response_dict(msg_dict)
            log.info(resp_dict)
            
            for cfg in input_conf['VERIFY_GETSET_Sanity1_2']['config']:
                cfg_section = cfg['section']
                set_info = input_conf[cfg_section]
                resp_key = cfg['name']
                if resp_key in resp_dict['key_list']:
                    if set_info['ietf-interfaces:interfaces']['interface'][0]['name'] != resp_dict[resp_key + ',name']:
                        err_msg.append("{} does not match the name in input json file: {}".format(resp_dict[resp_key + ',name'], set_info['ietf-interfaces:interfaces']['interface'][0]['name']))
                    if set_info['ietf-interfaces:interfaces']['interface'][0]['description'] != resp_dict[resp_key + ',description']:
                        err_msg.append("{} does not match the description in input json file: {}".format(resp_dict[resp_key + ',description'], set_info['ietf-interfaces:interfaces']['interface'][0]['description']))
                    if resp_dict[resp_key + ',type'] not in set_info['ietf-interfaces:interfaces']['interface'][0]['type']:
                        err_msg.append("{} does not match the type in input json file: {}".format(resp_dict[resp_key + ',type'], set_info['ietf-interfaces:interfaces']['interface'][0]['type']))
                    if not resp_dict[resp_key + ',enabled']:
                        err_msg.append("The interface {} is not enabled. Current status is {}".format(resp_dict[resp_key + ',name'], resp_dict[resp_key + ',enabled']))
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
        resp_dict = gnmiTestLib.get_response_dict(msg_dict)
        log.info(resp_dict)

        for cfg in input_conf['VERIFY_GETSET_Sanity1_3']['config']:
                cfg_section = cfg['section']
                set_info = input_conf[cfg_section]
                resp_key = cfg['name']
                if resp_key in resp_dict['key_list']:
                    if set_info['ietf-interfaces:interfaces']['interface'][0]['name'] != resp_dict[resp_key + ',name']:
                        err_msg.append("{} does not match the name in input json file: {}".format(resp_dict[resp_key + ',name'], set_info['ietf-interfaces:interfaces']['interface'][0]['name']))
                    if set_info['ietf-interfaces:interfaces']['interface'][0]['description'] != resp_dict[resp_key + ',description']:
                        err_msg.append("{} does not match the description in input json file: {}".format(resp_dict[resp_key + ',description'], set_info['ietf-interfaces:interfaces']['interface'][0]['description']))
                    if resp_dict[resp_key + ',type'] not in set_info['ietf-interfaces:interfaces']['interface'][0]['type']:
                        err_msg.append("{} does not match the type in input json file: {}".format(resp_dict[resp_key + ',type'], set_info['ietf-interfaces:interfaces']['interface'][0]['type']))
                    if not resp_dict[resp_key + ',enabled']:
                        err_msg.append("The interface {} is not enabled. Current status is {}".format(resp_dict[resp_key + ',name'], resp_dict[resp_key + ',enabled']))
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
        resp_dict = gnmiTestLib.get_response_dict(msg_dict)
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
                if resp_key in resp_dict['key_list']:
                    if set_info['openconfig-interfaces:interfaces']['interface'][ctr]['name'] != resp_dict[resp_key + ',interface,name']:
                        err_msg.append("{} does not match the name in input json file: {}".format(resp_dict[resp_key + ',interface,name'], set_info['openconfig-interfaces:interfaces']['interface'][ctr]['name']))
                    if set_info['openconfig-interfaces:interfaces']['interface'][ctr]['config']['description'] != resp_dict[resp_key + ',config,description']:
                        err_msg.append("{} does not match the description in input json file: {}".format(resp_dict[resp_key + ',config,description'], set_info['openconfig-interfaces:interfaces']['interface'][ctr]['config']['description']))
                    if resp_dict[resp_key + ',config,type'] not in set_info['openconfig-interfaces:interfaces']['interface'][ctr]['config']['type']:
                        err_msg.append("{} does not match the type in input json file: {}".format(resp_dict[resp_key + ',config,type'], set_info['openconfig-interfaces:interfaces']['interface'][ctr]['config']['type']))
                    if not resp_dict[resp_key + ',config,enabled']:
                        err_msg.append("The interface {} is not enabled. Current status is {}".format(resp_dict[resp_key + ',name'], resp_dict[resp_key + ',enabled']))
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

def _test_Get_with_type(stub):
    user = None
    password = None
    err_msg = list()
    resp_key_list = list()
    ctr = 0
    
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




