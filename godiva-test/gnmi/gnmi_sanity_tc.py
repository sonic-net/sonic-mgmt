#!/usr/bin/env python3
import argparse
import grpc
import os
import sys
import re
import json
from time import sleep
import multiprocessing
from multiprocessing import Pool, TimeoutError

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
from gnmi_test_lib import GnmiConnection
sys.path.append('./../../godiva-test/lib/')
import common_lib as commonLib
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
        pytest.fail("Test gnmi_GetTimestamp failed due to Grpc Error {err}".format(err=e.details()))    


def _test_Memory_Usage(stub):
    #Currently sample added for getting Memory info from DUT in docker. Will update for TH3
    rconn = commonLib.node_ssh('172.17.0.2', 'cisco', 'lab')
    rconn.send("\n")
    rconn.send("cat /proc/meminfo\n")
    sleep(2)
    reply = rconn.recv(5000)
    log.info(reply.decode())

    
def _test_GetSet_Sanity1(stub,encoding):
    user = None
    password = None
    err_msg = list()
    resp_key_list = list()
    status = True
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
            response = gnmiTestLib._get(stub, paths, user, password,encoding=encoding)
            #log.info(response)   
            
            #log.info("msg dict json dump: {}".format(json.dumps(msg_dict,sort_keys=True, indent=4)))
            if 'PROTO' in encoding:
                msg_dict = google.protobuf.json_format.MessageToDict(response)
                log.info(msg_dict)

                resp_dict = gnmiTestLib.get_response_dict(msg_dict)
                for cfg in input_conf['VERIFY_GETSET_Sanity1_1']['config']:
                    result = gnmiTestLib.verify_get_response(resp_dict,set_info1,cfg)
                    err_msg = result['err_msg'] + err_msg

            elif 'JSON_IETF' in encoding:
                json_ietf_val = json.loads(response.notification[0].update[0].val.json_ietf_val)
                print(json_ietf_val)
                json_ietf_val = json_ietf_val['data']['ietf-interfaces:interfaces']['interface']
                set_dict = set_info1['ietf-interfaces:interfaces']['interface']
                for set_d, get_d in zip(set_dict,json_ietf_val):
                    result = gnmiTestLib.verify_json_ietf_response(set_d,get_d)
                    err_msg = result['err_msg'] + err_msg

    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        pytest.fail("Test GETSET_Sanity1_1 failed due to Grpc Error {err}".format(err=e.details()))

    if len(err_msg) != 0:
        log.error("Test GETSET_Sanity1_1 failed due to : {}".format(*err_msg))
        status = False
        err_msg = list()
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
            response = gnmiTestLib._get(stub, paths, user, password,encoding=encoding)
            #log.info(response)   
            
            #log.info("msg dict json dump: {}".format(json.dumps(msg_dict,sort_keys=True, indent=4)))
            if 'PROTO' in encoding:
                msg_dict = google.protobuf.json_format.MessageToDict(response)
                resp_dict = gnmiTestLib.get_response_dict(msg_dict)
                for cfg in input_conf['VERIFY_GETSET_Sanity1_2']['config']:
                    section = cfg['section']
                    sifo = input_conf[section]
                    result = gnmiTestLib.verify_get_response(resp_dict,sifo,cfg)
                    err_msg = result['err_msg'] + err_msg
            
            elif 'JSON_IETF' in encoding:
                json_ietf_val = json.loads(response.notification[0].update[0].val.json_ietf_val)
                print(json_ietf_val)
                json_ietf_val = json_ietf_val['data']['ietf-interfaces:interfaces']['interface']
                set_dict = set_info1['ietf-interfaces:interfaces']['interface'] + set_info2['ietf-interfaces:interfaces']['interface']
                for set_d, get_d in zip(set_dict,json_ietf_val):
                    result = gnmiTestLib.verify_json_ietf_response(set_d,get_d)
                    err_msg = result['err_msg'] + err_msg


        if len(err_msg) != 0:
            log.error("Test GETSET_Sanity1_2 failed due to : {}".format(*err_msg))
            status = False
            err_msg = list()
        else:
            log.info("Test GETSET_Sanity1_2 - Set and Get Passed")

    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        pytest.fail("Test GETSET_Sanity1_2 failed due to Grpc Error {err}".format(err=e.details()))

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
        response = gnmiTestLib._get(stub, paths, user, password,encoding=encoding)
        #log.info(response)   
            
        #log.info("msg dict json dump: {}".format(json.dumps(msg_dict,sort_keys=True, indent=4)))
        if 'PROTO' in encoding:
            msg_dict = google.protobuf.json_format.MessageToDict(response)
            resp_dict = gnmiTestLib.get_response_dict(msg_dict)
            for cfg in input_conf['VERIFY_GETSET_Sanity1_3']['config']:
                result = gnmiTestLib.verify_get_response(resp_dict,set_info1,cfg)
                err_msg = result['err_msg'] + err_msg

        elif 'JSON_IETF' in encoding:
            json_ietf_val = json.loads(response.notification[0].update[0].val.json_ietf_val)
            print(json_ietf_val)
            json_ietf_val = json_ietf_val['data']['ietf-interfaces:interfaces']['interface']
            set_dict = set_info1['ietf-interfaces:interfaces']['interface']
            for set_d, get_d in zip(set_dict,json_ietf_val):
                result = gnmiTestLib.verify_json_ietf_response(set_d,get_d)
                err_msg = result['err_msg'] + err_msg


        if len(err_msg) != 0:
            log.error("Test GETSET_Sanity1_3 failed due to : {}".format(*err_msg))
            status = False
            err_msg = list()
        else:
            log.info("Test GETSET_Sanity1_3 - Set and Get Passed")

    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        pytest.fail("Test GETSET_Sanity1_3 failed due to Grpc Error {err}".format(err=e.details()))

    log.info('Performing SET-DELETE Request on target \n')
    #sleep(2)
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
        response = gnmiTestLib._get(stub, paths, user, password,encoding=encoding)
        #log.info(response)
        if 'PROTO' in encoding:
            msg_dict = google.protobuf.json_format.MessageToDict(response)
            log.info(msg_dict)
            resp_dict = gnmiTestLib.get_response_dict(msg_dict)
            if resp_dict != None:
                err_msg.append(resp_dict)
        
        elif 'JSON_IETF' in encoding:
            json_ietf_val = json.loads(response.notification[0].update[0].val.json_ietf_val)
            if bool(json_ietf_val['data']):
                err_msg.append("Configuration was not completely deleted. Config remaining %s" % json_ietf_val['data'])

        if len(err_msg) != 0:
            log.error("Test GETSET_Sanity1_4 failed due to : {}".format(*err_msg))
            status = False
            err_msg = list()

        else:
            log.info("Test GETSET_Sanity1_4 - Set and Get Passed")
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        pytest.fail("Test GETSET_Sanity1_4 failed due to Grpc Error {err}".format(err=e.details()))

    if not status:
        log.error("Test_GetSet_Sanity1 failed ")
        pytest.fail("Test_GetSet_Sanity1 failed ")
    else:
        log.info("Test_GetSet_Sanity1 - All sections passed")

def _test_Get_with_prefix(stub,encoding):
    user = None
    password = None
    err_msg = list()
    
    input_conf = json.loads(six.moves.builtins.open(ApData.zap.get_testcase_configuration("test_Get_with_prefix/input_conf_file"), 'r').read())
    
    log.info('Performing SET-REPLACE Request to target \n')
    try:
        if 'GET_WITH_PFX' in input_conf:
            set_info = input_conf['GET_WITH_PFX']['config']
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            reply = gnmiTestLib._set(stub, paths, 'replace', user, password, set_info)
            log.info(str(reply))
            if ('response' in str(reply) and 'op: REPLACE' in str(reply)):
                log.info("test_Get_with_prefix:Passed - was able to do SET-REPLACE with input json")
            else:
                log.info("test_Get_with_prefix:Failed - was unable to do SET-REPLACE with input json")
            
            prefix = input_conf['GET_WITH_PFX']['verify']['prefix']
            path = input_conf['GET_WITH_PFX']['verify']['path']
            path = gnmiTestLib._parse_path(gnmiTestLib._path_names(path))
            response = gnmiTestLib._get(stub, path, user, password,prefix,type='CONFIG',encoding=encoding)
            #log.info(response)   
            
            #log.info("msg dict json dump: {}".format(json.dumps(msg_dict,sort_keys=True, indent=4)))
            if 'PROTO' in encoding:
                msg_dict = google.protobuf.json_format.MessageToDict(response)
                resp_dict = gnmiTestLib.get_response_dict(msg_dict)
                #msg_dict = google.protobuf.json_format.MessageToDict(response)
                #log.info(json.dumps(msg_dict,sort_keys=True, indent=4))
                for cfg in input_conf['GET_WITH_PFX']['verify']['config']:
                    result = gnmiTestLib.verify_get_response(resp_dict,set_info,cfg)
                    err_msg = result['err_msg'] + err_msg
            
            elif 'JSON_IETF' in encoding:
                json_ietf_val = json.loads(response.notification[0].update[0].val.json_ietf_val)
                json_ietf_val = json_ietf_val['data']['openconfig-interfaces:interfaces']['interface']
                set_dict = set_info['openconfig-interfaces:interfaces']['interface']
                for set_d, get_d in zip(set_dict,json_ietf_val):
                    result = gnmiTestLib.verify_json_ietf_response(set_d['config'],get_d['config'])
                    err_msg = result['err_msg'] + err_msg

            
    
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
            set_info = input_conf['GET_WITH_OC_COMP']['config']
            print(set_info)
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            reply = gnmiTestLib._set(stub, paths, 'replace', user, password, set_info)
            log.info(str(reply))
            if ('response' in str(reply) and 'op: REPLACE' in str(reply)):
                log.info("GET_WITH_OC_COMP:Passed - was able to do SET-REPLACE with input json")
            else:
                log.info("GET_WITH_OC_COMP:Failed - was unable to do SET-REPLACE with input json")
            
            #xpath = "/if:interfaces/if:interface"
            prefix = input_conf['GET_WITH_OC_COMP']['verify']['prefix']
            path = input_conf['GET_WITH_OC_COMP']['verify']['path']
            path = gnmiTestLib._parse_path(gnmiTestLib._path_names(path))
            log.info("Verify Get for OC Components ")
            response = gnmiTestLib._get(stub, path, user, password,prefix,type='ALL')
            log.info(response)
            
            msg_dict = google.protobuf.json_format.MessageToDict(response)
            #log.info(json.dumps(msg_dict,sort_keys=True, indent=4))
            resp_dict = gnmiTestLib.get_response_dict(msg_dict)
            log.info(json.dumps(resp_dict,sort_keys=True, indent=4))
            for cfg in input_conf['GET_WITH_OC_COMP']['verify']['config']:
                result = gnmiTestLib.verify_get_response(resp_dict,set_info,cfg)
                err_msg = result['err_msg'] + err_msg
            
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

def _test_Get_with_type(stub,encoding):
    user = None
    password = None
    err_msg = list()
    
    input_conf = json.loads(six.moves.builtins.open(ApData.zap.get_testcase_configuration("test_Get_with_prefix/input_conf_file"), 'r').read())
    
    log.info('Performing SET-REPLACE Request to target \n')
    try:
        if 'GET_WITH_PFX' in input_conf:
            set_info = input_conf['GET_WITH_PFX']['config']
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            reply = gnmiTestLib._set(stub, paths, 'replace', user, password, set_info)
            log.info(str(reply))
            if ('response' in str(reply) and 'op: REPLACE' in str(reply)):
                log.info("test_Get_with_type:Passed - was able to do SET-REPLACE with input json")
            else:
                log.info("test_Get_with_type:Failed - was unable to do SET-REPLACE with input json")
            
            #xpath = "/if:interfaces/if:interface"
            prefix = input_conf['GET_WITH_PFX']['verify']['prefix']
            #prefix = gnmiTestLib._parse_path(gnmiTestLib._path_names(prefix))
            path = input_conf['GET_WITH_PFX']['verify']['path']
            path = gnmiTestLib._parse_path(gnmiTestLib._path_names(path))
            log.info("Verify Get with Type='ALL' ")
            response = gnmiTestLib._get(stub, path, user, password,prefix,type='ALL',encoding=encoding)
            #log.info(response)

            if 'PROTO' in encoding:
                msg_dict = google.protobuf.json_format.MessageToDict(response)
                
                #log.info(msg_dict)
                resp_dict = gnmiTestLib.get_response_dict(msg_dict)
                resp_dict_keys = list(resp_dict.keys())
                log.info(list(resp_dict.keys()))
                log.info(json.dumps(resp_dict,sort_keys=True, indent=4))
                state_status = False
                config_status = False
                for intf_key in resp_dict_keys:
                    for mkeys in resp_dict[intf_key]:
                        for keys in mkeys:
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

            elif 'JSON_IETF' in encoding:
                json_ietf_val = json.loads(response.notification[0].update[0].val.json_ietf_val)
                print(json_ietf_val)
                resp_dict_keys = list()
                resp_dict_list = json_ietf_val['data']['openconfig-interfaces:interfaces']['interface']
                for intfs in resp_dict_list:
                    resp_dict_keys.append(list(intfs.keys()))
                state_status = False
                config_status = False
                for intf_key in resp_dict_keys:
                    for keys in intf_key:
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
        prefix = input_conf['GET_WITH_PFX']['verify']['prefix']
        path = input_conf['GET_WITH_PFX']['verify']['path']
        path = gnmiTestLib._parse_path(gnmiTestLib._path_names(path))
        response = gnmiTestLib._get(stub, path, user, password,prefix,type='CONFIG',encoding=encoding)
        #log.info(response)

        if 'PROTO' in encoding:
            #log.info(response)
            msg_dict = google.protobuf.json_format.MessageToDict(response)
            log.info(msg_dict)
            resp_dict = gnmiTestLib.get_response_dict(msg_dict)
            resp_dict_keys = list(resp_dict.keys())
            state_status = False
            config_status = False
            for intf_key in resp_dict_keys:
                for mkeys in resp_dict[intf_key]:
                    for keys in mkeys:
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

        elif 'JSON_IETF' in encoding:
            json_ietf_val = json.loads(response.notification[0].update[0].val.json_ietf_val)
            resp_dict_keys = list()
            resp_dict_list = json_ietf_val['data']['openconfig-interfaces:interfaces']['interface']
            for intfs in resp_dict_list:
                resp_dict_keys.append(list(intfs.keys()))
            state_status = False
            config_status = False
            for intf_key in resp_dict_keys:
                for keys in intf_key:
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
        prefix = input_conf['GET_WITH_PFX']['verify']['prefix']
        path = input_conf['GET_WITH_PFX']['verify']['path']
        path = gnmiTestLib._parse_path(gnmiTestLib._path_names(path))
        response = gnmiTestLib._get(stub, path, user, password,prefix,type='STATE',encoding=encoding)
        #log.info(response)
        
        if 'PROTO' in encoding:
            msg_dict = google.protobuf.json_format.MessageToDict(response)
            #log.info(msg_dict)
            resp_dict = gnmiTestLib.get_response_dict(msg_dict)
            resp_dict_keys = list(resp_dict.keys())
            state_status = False
            config_status = False
            for intf_key in resp_dict_keys:
                for mkeys in resp_dict[intf_key]:
                    for keys in mkeys:
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

        elif 'JSON_IETF' in encoding:
            json_ietf_val = json.loads(response.notification[0].update[0].val.json_ietf_val)
            resp_dict_keys = list()
            resp_dict_list = json_ietf_val['data']['openconfig-interfaces:interfaces']['interface']
            for intfs in resp_dict_list:
                resp_dict_keys.append(list(intfs.keys()))
            state_status = False
            config_status = False
            for intf_key in resp_dict_keys:
                for keys in intf_key:
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
            set_info = input_conf['GET_WITH_PFX']['config']
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
            set_info = input_conf['GET_WITH_PFX']['config']
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            reply = gnmiTestLib._set(stub, paths, 'replace', user, password, set_info)
            log.info(str(reply))
            if ('response' in str(reply) and 'op: REPLACE' in str(reply)):
                log.info("_test_Get_with_wrong_encoding: was able to do SET-REPLACE with input json")
            else:
                log.info("_test_Get_with_wrong_encoding:Failed - was unable to do SET-REPLACE with input json")
            
            #xpath = "/if:interfaces/if:interface"
            prefix = input_conf['GET_WITH_PFX']['verify']['prefix']
            #prefix = gnmiTestLib._parse_path(gnmiTestLib._path_names(prefix))
            path = input_conf['GET_WITH_PFX']['verify']['path']
            path = gnmiTestLib._parse_path(gnmiTestLib._path_names(path))
            
            response = gnmiTestLib._get_wo_encoding(stub, path, user, password,prefix,type='ALL')
            log.info(response)
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        if ('StatusCode.UNIMPLEMENTED' in str(e) and 'gNMI: Specified encoding 0 is not supported' in str(e)):
            log.info("Test test_Get_with_wrong_encoding.1 - No Encoding :Passed - received correct error message on sending no encoding in GET RPC")
        else:
            log.error("Test test_Get_with_wrong_encoding.1 - No Encoding :Failed - received incorrect error message on sending no encoding in GET RPC")
            err_msg.append("test_Get_with_wrong_encoding.1 - No Encoding :Failed due to Grpc Error {err}".format(err=e.details()))

    try:
        response = gnmiTestLib._get(stub, path, user, password,prefix,type='ALL',encoding='JSON')
        log.info(response)
        log.error("Test test_Get_with_wrong_encoding.2 - Unsupported :Failed - Expected the testcase to fail, but got no GRPC Error")
        err_msg.append("test_Get_with_wrong_encoding.2 - Unsupported :Failed - Expected the testcase to fail, but got no GRPC Error")
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
            set_info1 = input_conf['GET_WITH_OC_COMP']['config']
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
            set_info1 = input_conf['GET_WITH_OC_COMP']['config']
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
            set_info = input_conf['GET_WITH_PFX']['config']
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
        pytest.fail("Test SETPfxPath1_1 failed due to Grpc Error {err}".format(err=e.details()))


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
        pytest.fail("Test SETPfx_2node_1 failed due to Grpc Error {err}".format(err=e.details()))


def _test_multiple_target_get(encoding):
     
    pool = Pool(processes=2)
    user = None
    password = None
    err_msg = list()
    gnmi_conn = GnmiConnection(target=ApData.svr_addr, port=ApData.port_addr)
    stub = gnmi_conn.stub

    try:

        tData = ApData.zap.get_testcase_configuration("test_gnmi_SetPfxPath")
        input_conf = json.loads(six.moves.builtins.open(tData["input_conf_file"], 'r').read())
        #print(input_conf)

        log.info('Performing SET-REPLACE w/Path Target(gnmi spec:2.2.2.1) for Multiple leaf nodes\n')
        log.info('For this test we will use Path Target = "SET_GNMI_TGT"')

        if 'SETPfxPath2_1' in input_conf:
            set_info1 = input_conf['SETPfxPath2_1']
            print(set_info1['prefix-path'])
            print(set_info1['Updates'])
            target = 'SET_GNMI_TGT'
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            pfx_path = gnmiTestLib._parse_path(gnmiTestLib._path_names(set_info1['prefix-path']),target)
            reply = gnmiTestLib._set(stub, paths, 'replace', user, password, set_info1['Updates'], pfx_path)
            resp = str(reply)
            log.info("### RCVD RESPONSE ###")
            log.info(resp)
            sresp = "".join(resp.split('\n'))
            log.info (sresp)
            mt1 = 'prefix {  elem {    name: "ietf-interfaces:interfaces"  }  target: "SET_GNMI_TGT"}'
            mt2 = 'response {  path {  }'
            if (mt1 in sresp and mt2 in sresp):
                log.info("Set_wTgt_1_1:Passed - was able to do SET-REPLACE Request w/Path Target for Multiple Leaf Nodes")
            else:
                log.info("Set_wTgt_1_1:Failed - was unable to do SET-REPLACE Request w/Path Target for Multiple Leaf Nodes")

            tget = 'target' + ":" + encoding
            no_tget = 'no_target' + ":" + encoding
            gnmi_conn.closeAllConnections()
            results = pool.map(gnmiTestLib.parallel_target_oper,[tget,no_tget])
            for result in results:
                oper = result['oper']
                status = result['status']
                if "target" in oper:
                    if status:
                        log.info("Test test_multiple_target_get Passed: GET received with the target information")
                    else:
                        msg=result['msg']
                        for error in msg:
                            err_msg.append("Test test_multiple_target_get: Failed failed due to : {}".format(error))

                if "no_target" in oper:
                    if status:
                        log.info("Test test_multiple_target_get Passed: GET received without the target information")
                    else:
                        msg=result['msg']
                        for error in msg:
                            err_msg.append("Test test_multiple_target_get :Failed - failed due to : {}".format(error))

    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
    
    try:
        gnmi_conn = gnmiTestLib.GnmiConnection(target=ApData.svr_addr,port=ApData.port_addr)
        #input_conf = json.loads(six.moves.builtins.open(ApData.zap.get_testcase_configuration("test_gnmi_parallel_oper/input_conf_file"), 'r').read())
        #set_info = input_conf["SCALE_INTF_{}".format(intf_num)]
        xpath = "/oc-if:interfaces"
        paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
        reply = gnmiTestLib._set(gnmi_conn.stub, paths, 'delete', user, password,None)
        log.info(str(reply))
        if ('response' in str(reply) and 'op: DELETE' in str(reply)):
            log.info("test_multiple_target_get:Passed - was able to do SET-DELETE on target")
        else:
            log.error("test_multiple_target_get:Failed - was unable to do SET-DELETE on target")
            err_msg.append("test_multiple_target_get:Failed - was unable to do SET-DELETE on target")
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        err_msg.append("test_parallel_set_get - Delete Config during cleanup failed due to Grpc Error {err}".format(err=e.details()))

    gnmi_conn.shutdown()
    if len(err_msg) != 0:
        log.error("Test test_multiple_target_get failed due to : {}".format(*err_msg))
        pytest.fail("Test test_multiple_target_get FAILED")
    else:
        log.info("Test test_multiple_target_get - PASSED")

def _test_Set_wTgt(stub,encoding):
    user = None
    password = None
    err_msg = list()

    tData = ApData.zap.get_testcase_configuration("test_gnmi_SetPfxPath")
    input_conf = json.loads(six.moves.builtins.open(tData["input_conf_file"], 'r').read())
    #print(input_conf)

    log.info('Performing SET-REPLACE w/Path Target(gnmi spec:2.2.2.1) for Multiple leaf nodes\n')
    log.info('For this test we will use Path Target = "SET_GNMI_TGT"')
    try:
        if 'SETPfxPath2_1' in input_conf:
            set_info1 = input_conf['SETPfxPath2_1']
            print(set_info1['prefix-path'])
            print(set_info1['Updates'])
            target = 'SET_GNMI_TGT'
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            pfx_path = gnmiTestLib._parse_path(gnmiTestLib._path_names(set_info1['prefix-path']),target)
            reply = gnmiTestLib._set(stub, paths, 'replace', user, password, set_info1['Updates'], pfx_path)
            resp = str(reply)
            log.info("### RCVD RESPONSE ###")
            log.info(resp)
            sresp = "".join(resp.split('\n'))
            log.info (sresp)
            mt1 = 'prefix {  elem {    name: "ietf-interfaces:interfaces"  }  target: "SET_GNMI_TGT"}'
            mt2 = 'response {  path {  }'
            if (mt1 in sresp and mt2 in sresp):
                log.info("Set_wTgt_1_1:Passed - was able to do SET-REPLACE Request w/Path Target for Multiple Leaf Nodes")
            else:
                log.info("Set_wTgt_1_1:Failed - was unable to do SET-REPLACE Request w/Path Target for Multiple Leaf Nodes")

            prefix = input_conf['VERIFY_SETPfxPath2_1']['prefix']
            path = input_conf['VERIFY_SETPfxPath2_1']['path']
            path = gnmiTestLib._parse_path(gnmiTestLib._path_names(path))
            response = gnmiTestLib._get(stub, path, user, password,prefix,type='CONFIG',target=target,encoding=encoding)
            #log.info(response) 
            if 'PROTO' in encoding:
                msg_dict = google.protobuf.json_format.MessageToDict(response)
                #log.info(json.dumps(msg_dict,sort_keys=True, indent=4))
                resp_dict = gnmiTestLib.get_response_dict(msg_dict)
                for cfg in input_conf['VERIFY_SETPfxPath2_1']['config']:
                    section = cfg['section']
                    set_info = input_conf[section]
                    result = gnmiTestLib.verify_get_response(resp_dict,set_info,cfg)
                    err_msg = result['err_msg'] + err_msg
        
            elif 'JSON_IETF' in encoding:
                resp_target = response.notification[0].prefix.target
                if resp_target is not "":
                    if resp_target == target:
                        log.info("Received matching target in GET response")
                    else:
                        log.error("Received target does not match the target set")
                        err_msg.append("Received target does not match the target set")
                else:
                    log.error("GET response does not have target set")
                    err_msg.append("GET response does not have target set")

                json_ietf_val = json.loads(response.notification[0].update[0].val.json_ietf_val)
                #print(json_ietf_val)
                json_ietf_val = json_ietf_val['data']['ietf-interfaces:interfaces']['interface']
                set_dict = set_info1['Updates']['interface']
                for set_d, get_d in zip(set_dict,json_ietf_val):
                    result = gnmiTestLib.verify_json_ietf_response(set_d,get_d)
                    err_msg = result['err_msg'] + err_msg
                
    
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        pytest.fail("Test Set_wTgt_1_1 failed due to Grpc Error {err}".format(err=e.details()))

    log.info('Performing SET-UPDATE w/Path Target MODIFY(gnmi spec:2.2.2.1) for leaf node\n')
    log.info('For this test we will MODIFY Path Target = "MDFY_GNMI_TGT"')
    try:
        if 'MdfyTGT1_1' in input_conf:
            set_info1 = input_conf['MdfyTGT1_1']
            print(set_info1['prefix-path'])
            print(set_info1['Updates'])
            target = 'MDFY_GNMI_TGT'
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            pfx_path = gnmiTestLib._parse_path(gnmiTestLib._path_names(set_info1['prefix-path']),target)
            reply = gnmiTestLib._set(stub, paths, 'update', user, password, set_info1['Updates'], pfx_path)
            resp = str(reply)
            log.info("### RCVD RESPONSE ###")
            log.info(resp)
            sresp = "".join(resp.split('\n'))
            log.info (sresp)
            mt1 = 'prefix {  elem {    name: "ietf-interfaces:interfaces"  }  target: "MDFY_GNMI_TGT"}'
            mt2 = 'response {  path {  }'
            if (mt1 in sresp and mt2 in sresp):
                log.info("Set_wTgt_1_2:Passed - was able to do SET-UPDATE Request w/Path Target MODIFY for Leaf Nodes")
            else:
                log.info("Set_wTgt_1_2:Failed - was unable to do SET-UPDATE Request w/Path Target MODIFY for Leaf Nodes")

            prefix = input_conf['VERIFY_MdfyTGT1_1']['prefix']
            path = input_conf['VERIFY_MdfyTGT1_1']['path']
            path = gnmiTestLib._parse_path(gnmiTestLib._path_names(path))
            response = gnmiTestLib._get(stub, path, user, password,prefix,type='CONFIG',target=target,encoding=encoding)
            #log.info(response) 
            if 'PROTO' in encoding:
                msg_dict = google.protobuf.json_format.MessageToDict(response)
                #log.info(json.dumps(msg_dict,sort_keys=True, indent=4))
                resp_dict = gnmiTestLib.get_response_dict(msg_dict)
                for cfg in input_conf['VERIFY_MdfyTGT1_1']['config']:
                    section = cfg['section']
                    set_info = input_conf[section]
                    result = gnmiTestLib.verify_get_response(resp_dict,set_info,cfg)
                    err_msg = result['err_msg'] + err_msg
            
            elif 'JSON_IETF' in encoding:
                resp_target = response.notification[0].prefix.target
                if resp_target is not "":
                    if resp_target == target:
                        log.info("Received matching target in GET response")
                    else:
                        log.error("Received target does not match the target set")
                        err_msg.append("Received target does not match the target set")
                else:
                    log.error("GET response does not have target set")
                    err_msg.append("GET response does not have target set")

                json_ietf_val = json.loads(response.notification[0].update[0].val.json_ietf_val)
                print(json_ietf_val)
                json_ietf_val = json_ietf_val['data']['ietf-interfaces:interfaces']['interface']
                set_dict = input_conf['SETPfxPath2_1']['Updates']['interface'] + set_info1['Updates']['interface']
                for set_d, get_d in zip(set_dict,json_ietf_val):
                    result = gnmiTestLib.verify_json_ietf_response(set_d,get_d)
                    err_msg = result['err_msg'] + err_msg

    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        pytest.fail("Test Set_wTgt_1_2 failed due to Grpc Error {err}".format(err=e.details()))

    log.info('Perform another SET-UPDATE but without Target for leaf node\n')
    log.info('For this test we will MODIFY without Path Target ')
    try:
        if 'MdfyTGT1_2' in input_conf:
            set_info1 = input_conf['MdfyTGT1_2']
            print(set_info1['prefix-path'])
            print(set_info1['Updates'])
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            pfx_path = gnmiTestLib._parse_path(gnmiTestLib._path_names(set_info1['prefix-path']))
            reply = gnmiTestLib._set(stub, paths, 'update', user, password, set_info1['Updates'], pfx_path)
            resp = str(reply)
            log.info("### RCVD RESPONSE ###")
            log.info(resp)
            sresp = "".join(resp.split('\n'))
            log.info (sresp)
            mt1 = 'prefix {  elem {    name: "ietf-interfaces:interfaces"  }}'
            mt2 = 'target'
            if (mt1 in sresp and mt2 not in sresp):
                log.info("Set_wTgt_1_3:Passed - was able to do SET-UPDATE Request Without Target and Verify its not sent back")
            else:
                log.info("Set_wTgt_1_3:Failed - was unable to do SET-UPDATE Request Without Target and Verify its not sent back")

            prefix = input_conf['VERIFY_MdfyTGT1_2']['prefix']
            path = input_conf['VERIFY_MdfyTGT1_2']['path']
            path = gnmiTestLib._parse_path(gnmiTestLib._path_names(path))
            response = gnmiTestLib._get(stub, path, user, password,prefix,type='CONFIG',encoding=encoding)
            log.info(response) 
            if 'PROTO' in encoding:
                msg_dict = google.protobuf.json_format.MessageToDict(response)
                #log.info(json.dumps(msg_dict,sort_keys=True, indent=4))
                resp_dict = gnmiTestLib.get_response_dict(msg_dict)
                for cfg in input_conf['VERIFY_MdfyTGT1_2']['config']:
                    section = cfg['section']
                    set_info = input_conf[section]
                    result = gnmiTestLib.verify_get_response(resp_dict,set_info,cfg)
                    err_msg = result['err_msg'] + err_msg
            
            elif 'JSON_IETF' in encoding:
                resp_target = response.notification[0].prefix.target
                if resp_target is not "":
                    log.error("GET response should not have a target set, current target set as : %s" % resp_target)
                    err_msg.append("GET response should not have a target set, current target set as : %s" % resp_target)
                else:
                    log.info("GET response does not have target set as expected")

                json_ietf_val = json.loads(response.notification[0].update[0].val.json_ietf_val)
                print(json_ietf_val)
                json_ietf_val = json_ietf_val['data']['ietf-interfaces:interfaces']['interface']
                set_dict = input_conf['SETPfxPath2_1']['Updates']['interface'] + input_conf['MdfyTGT1_1']['Updates']['interface'] + set_info1['Updates']['interface']
                for set_d, get_d in zip(set_dict,json_ietf_val):
                    result = gnmiTestLib.verify_json_ietf_response(set_d,get_d)
                    err_msg = result['err_msg'] + err_msg

    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        pytest.fail("Test Set_wTgt_1_3 failed due to Grpc Error {err}".format(err=e.details()))

    #sleep(555)

    log.info('Performing SET-DELETE w/Path Target MODIFY(gnmi spec:2.2.2.1) for leaf node\n')
    log.info('For this test we will MODIFY Path Target = "DEL_GNMI_TGT"')
    try:
        if 'MdfyTGT1_1' in input_conf:
            set_info1 = input_conf['MdfyTGT1_1']
            print(set_info1['prefix-path'])
            target = 'DEL_GNMI_TGT'
            tval = ""
            #xpath = "/if:interfaces"
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            set_info1['prefix-path'] = "/if:interfaces"
            pfx_path = gnmiTestLib._parse_path(gnmiTestLib._path_names(set_info1['prefix-path']),target)
            reply = gnmiTestLib._set(stub, paths, 'delete', user, password, tval, pfx_path)
            resp = str(reply)
            log.info("### RCVD RESPONSE ###")
            log.info(resp)
            sresp = "".join(resp.split('\n'))
            log.info (sresp)
            mt1 = 'prefix {  elem {    name: "ietf-interfaces:interfaces"  }  target: "DEL_GNMI_TGT"}'
            mt2 = 'response {  path {  }'
            if (mt1 in sresp and mt2 in sresp):
                log.info("Set_wTgt_1_4:Passed - was able to do SET-DELETE Request w/Path Target MODIFY for Leaf Nodes")
            else:
                log.info("Set_wTgt_1_4:Failed - was unable to do SET-DELETE Request w/Path Target MODIFY for Leaf Nodes")
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        pytest.fail("Test Set_wTgt_1_4 failed due to Grpc Error {err}".format(err=e.details()))

    if len(err_msg) != 0:
        log.error("Test_Set_wTgt failed due to : {}".format(*err_msg))
        pytest.fail("Test_Set_wTgt failed due to : {}".format(*err_msg))
    else:
        log.info("Test_Set_wTgt - All sections passed")


def _test_Path_with_slash(stub):
    user = None
    password = None
    err_msg = list()

    tData = ApData.zap.get_testcase_configuration("test_GetSet_Sanity1")
    input_conf = json.loads(six.moves.builtins.open(tData["input_conf_file"], 'r').read())
    #print(input_conf)

    log.info('Performing SET-REPLACE w/Path consisting of "/" in element \n')
    log.info('For this test we will use Path w/Element = "Loopback-1/1/0"')

    try:
        if 'SLASHSET_Sanity1_1' in input_conf:
            set_info1 = input_conf['SLASHSET_Sanity1_1']
            print(type(set_info1))
            print(set_info1)
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            reply = gnmiTestLib._set(stub, paths, 'replace', user, password, set_info1)
            log.info(str(reply))
            if ('response' in str(reply) and 'op: REPLACE' in str(reply)):
                log.info("SLASHSET_Sanity1_1:Passed - was able to do SET-REPLACE with '/' in Path element")
            else:
                log.info("SLASHSET_Sanity1_1:Failed - was unable to do SET-REPLACE with '/' in Path element")
            
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        pytest.fail("Test SLASHSET_Sanity1_1 failed due to Grpc Error {err}".format(err=e.details()))



    log.info('Performing SET-UPDATE w/Path consisting of "/" in element \n')
    log.info('For this test we will use Path w/Element = "Loopback-2/2/0"')
 
    try:
        if 'SLASHSET_Sanity1_2' in input_conf:
            set_info1 = input_conf['SLASHSET_Sanity1_2']
            print(set_info1)
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            reply = gnmiTestLib._set(stub, paths, 'update', user, password, set_info1)
            log.info(str(reply))
            if ('response' in str(reply) and 'op: UPDATE' in str(reply)):
                log.info("SLASHSET_Sanity1_2:Passed - was able to do SET-UPDATE with '/' in Path element")
            else:
                log.info("SLASHSET_Sanity1_2:Failed - was unable to do SET-UPDATE with '/' in Path element")
            
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        pytest.fail("Test SLASHSET_Sanity1_2 failed due to Grpc Error {err}".format(err=e.details()))



    log.info('Performing SET-DELETE Request on Path with "/" in element \n')

    try:
        xpath = "/if:interfaces/interface[name=Loopback-1/1/0]"
        paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
        reply = gnmiTestLib._set(stub, paths, 'delete', user, password, set_info1)
        log.info(str(reply))
        if ('response' in str(reply) and 'op: DELETE' in str(reply)):
            log.info("SLASHSET_Sanity1_3:Passed - was able to do SET-DELETE with '/' in Path element")
            #cleaning up the additional interface config also
            xpath = "/if:interfaces/interface[name=Loopback-2/2/0]"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            reply = gnmiTestLib._set(stub, paths, 'delete', user, password, set_info1)
        else:
            log.error("SLASHSET_Sanity1_3:Failed - was unable to do SET-DELETE with '/' in Path element")
            err_msg.append("SLASHSET_Sanity1_3:Failed - was unable to do SET-DELETE with '/' in Path element")

        
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        pytest.fail("Test SLASHSET_Sanity1_3 failed due to Grpc Error {err}".format(err=e.details()))

    if len(err_msg) != 0:
        log.error("Test_SLASHSET_Sanity failed due to : {}".format(*err_msg))
        pytest.fail("Test_SLASHSET_Sanity failed due to : {}".format(*err_msg))
    else:
        log.info("Test_SLASHSET_Sanity - All sections passed")



def _test_PfxPath_with_slash(stub):
    user = None
    password = None
    err_msg = list()

    tData = ApData.zap.get_testcase_configuration("test_gnmi_SetPfxPath")
    input_conf = json.loads(six.moves.builtins.open(tData["input_conf_file"], 'r').read())
    #print(input_conf)

    log.info('Performing SET-REPLACE Request w/Prefix-Path consisting of "/" to target \n')
    try:
        if 'SlshSET1_1' in input_conf:
            set_info1 = input_conf['SlshSET1_1']
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
            #mt2 = 'response {  path {  }'
            mt2 = 'response {  path {  }  op: REPLACE}'
            if (mt1 in sresp and mt2 in sresp):
                log.info("SlshInPfxPath1_1:Passed - was able to do SET-REPLACE with '/' in Prefix Path")
            else:
                log.info("SlshInPfxPath1_1:Failed - was unable to do SET-REPLACE with '/' in Prefix Path")
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        pytest.fail("Test SlshInPfxPath1_1 failed due to Grpc Error {err}".format(err=e.details()))


    log.info('Performing SET-UPDATE Request w/Prefix-Path consisting of "/" to target \n')
    try:
        if 'SlshSET1_2' in input_conf:
            set_info1 = input_conf['SlshSET1_2']
            print(set_info1['prefix-path'])
            print(set_info1['Updates'])
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            pfx_path = gnmiTestLib._parse_path(gnmiTestLib._path_names(set_info1['prefix-path']))
            reply = gnmiTestLib._set(stub, paths, 'update', user, password, set_info1['Updates'], pfx_path)
            resp = str(reply)
            log.info(resp)
            sresp = "".join(resp.split('\n'))
            log.info (sresp)
            mt1 = 'prefix {  elem {    name: "ietf-interfaces:interfaces"  }'
            #mt2 = 'response {  path {  }'
            mt2 = 'response {  path {  }  op: UPDATE}'
            if (mt1 in sresp and mt2 in sresp):
                log.info("SlshInPfxPath1_2:Passed - was able to do SET-UPDATE with '/' in Prefix Path")
            else:
                log.info("SlshInPfxPath1_2:Failed - was unable to do SET-UPDATE with '/' in Prefix Path")
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        pytest.fail("Test SlshInPfxPath1_2 failed due to Grpc Error {err}".format(err=e.details()))

def _test_MultiKey(stub,encoding):
    user = None
    password = None
    err_msg = list()
    status = True

    tData = ApData.zap.get_testcase_configuration("test_GetSet_Sanity1")
    input_conf = json.loads(six.moves.builtins.open(tData["input_conf_file"], 'r').read())
    #print(input_conf)

    log.info('Performing SET-REPLACE w/Path consisting of Multiple Keys \n')
    log.info('For this test we will use Path facility=KERNEL,severity=CRITICAL')

    try:
        if 'MKEYSET_Sanity1_1' in input_conf:
            set_info1 = input_conf['MKEYSET_Sanity1_1']
            print(type(set_info1))
            print(set_info1)
            xpath = "/openconfig-system:system/logging/console"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            reply = gnmiTestLib._set(stub, paths, 'replace', user, password, set_info1)
            resp = str(reply)
            log.info(resp)
            sresp = "".join(resp.split('\n'))
            log.info (sresp.replace(" ", ""))
            #mt1 = 'response {  path {    elem {      name: "openconfig-system:system"    }'
            mt1 = 'response{path{elem{name:"openconfig-system:system"}elem{name:"logging"}elem{name:"console"}}op:REPLACE}'
            if (mt1 in sresp.replace(" ", "")):
                log.info("MKEYSET_Sanity1_1:Passed - was able to do SET-REPLACE w/Path consisting of Multiple Keys")
            else:
                log.info("MKEYSET_Sanity1_1:Failed - was unable to do SET-REPLACE w/Path consisting of Multiple Keys")
            
            xpath = input_conf['VERIFY_MKEYSET_Sanity1_1']['filter']
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            response = gnmiTestLib._get(stub, paths, user, password,encoding=encoding)
            log.info(response)

            if 'PROTO' in encoding:
                msg_dict = google.protobuf.json_format.MessageToDict(response)
                #log.info(msg_dict)
                resp_dict = gnmiTestLib.get_response_dict(msg_dict)
                log.info(resp_dict)
                for cfg in input_conf['VERIFY_MKEYSET_Sanity1_1']['config']:
                    result = gnmiTestLib.verify_get_response(resp_dict,set_info1,cfg)
                    err_msg = result['err_msg'] + err_msg

            elif 'JSON_IETF' in encoding:
                json_ietf_val = json.loads(response.notification[0].update[0].val.json_ietf_val)
                json_ietf_val = json_ietf_val['data']['openconfig-system:system']['logging']['console']['selectors']['selector'][0]['config']
                set_dict = set_info1['selectors']['selector'][0]['config']
                result = gnmiTestLib.verify_json_ietf_response(set_dict,json_ietf_val)
                err_msg = result['err_msg'] + err_msg

    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        pytest.fail("Test MKEYSET_Sanity1_1 failed due to Grpc Error {err}".format(err=e.details())) 

    if len(err_msg) != 0:
        log.error("Test MKEYSET_Sanity1_1 failed due to : {}".format(*err_msg))
        status = False
    else:
        log.info("Test MKEYSET_Sanity1_1 - Set and Get Passed")

    err_msg = list()
    log.info('Performing SET-UPDATE w/Path consisting of Multiple Keys \n')
    log.info('For this test we will use Path facility=KERNEL,severity=ALERT')

    try:
        if 'MKEYSET_Sanity1_2' in input_conf:
            set_info1 = input_conf['MKEYSET_Sanity1_2']
            print(type(set_info1))
            print(set_info1)
            xpath = "/openconfig-system:system/logging/console"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            reply = gnmiTestLib._set(stub, paths, 'update', user, password, set_info1)
            resp = str(reply)
            log.info(resp)
            sresp = "".join(resp.split('\n'))
            log.info (sresp.replace(" ", ""))
            mt1 = 'response{path{elem{name:"openconfig-system:system"}elem{name:"logging"}elem{name:"console"}}op:UPDATE}'
            if (mt1 in sresp.replace(" ", "")):
                log.info("MKEYSET_Sanity1_2:Passed - was able to do SET-UPDATE w/Path consisting of Multiple Keys")
            else:
                log.info("MKEYSET_Sanity1_2:Failed - was unable to do SET-UPDATE w/Path consisting of Multiple Keys")

            xpath = input_conf['VERIFY_MKEYSET_Sanity1_2']['filter']
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            response = gnmiTestLib._get(stub, paths, user, password,encoding=encoding)
            log.info(response)
            if 'PROTO' in encoding:
                msg_dict = google.protobuf.json_format.MessageToDict(response)
                #log.info(msg_dict)
                resp_dict = gnmiTestLib.get_response_dict(msg_dict)
                log.info(resp_dict)                
                for cfg in input_conf['VERIFY_MKEYSET_Sanity1_2']['config']:
                    result = gnmiTestLib.verify_get_response(resp_dict,set_info1,cfg)
                    err_msg = result['err_msg'] + err_msg
            
            elif 'JSON_IETF' in encoding:
                json_ietf_val = json.loads(response.notification[0].update[0].val.json_ietf_val)
                json_ietf_val = json_ietf_val['data']['openconfig-system:system']['logging']['console']['selectors']['selector'][0]['config']
                set_dict = set_info1['selectors']['selector'][0]['config']
                result = gnmiTestLib.verify_json_ietf_response(set_dict,json_ietf_val)
                err_msg = result['err_msg'] + err_msg
            
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        pytest.fail("Test MKEYSET_Sanity1_2 failed due to Grpc Error {err}".format(err=e.details())) 

    if len(err_msg) != 0:
        log.error("Test MKEYSET_Sanity1_2 failed due to : {}".format(*err_msg))
        status = False
    else:
        log.info("Test MKEYSET_Sanity1_2 - Set and Get Passed")

    err_msg = list()
   
    log.info('Performing SET-DELETE w/Path consisting of Multiple Keys \n')
    try:
        xpath = "/system/logging/console/selectors/selector"
        paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
        reply = gnmiTestLib._set(stub, paths, 'delete', user, password, set_info1)
        resp = str(reply)
        log.info(resp)
        sresp = "".join(resp.split('\n'))
        log.info (sresp.replace(" ", ""))
        mt1 = 'response{path{elem{name:"openconfig-system:system"}elem{name:"logging"}elem{name:"console"}}op:DELETE}'
        if (mt1 in sresp.replace(" ", "")):
            log.info("MKEYSET_Sanity1_3:Passed - was able to do SET-DELETE w/Path consisting of Multiple Keys")
        else:
            log.info("MKEYSET_Sanity1_3:Failed - was unable to do SET-DELETE w/Path consisting of Multiple Keys")
            
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        pytest.fail("Test MKEYSET_Sanity1_3 failed due to Grpc Error {err}".format(err=e.details())) 
    
    if not status:
        pytest.fail("Test MKEYSET_Sanity failed ")
    else:
        log.info("Test MKEYSET_Sanity - Set and Get Passed")

def _test_PfxPath_with_MultiKey(stub,encoding):
    user = None
    password = None
    err_msg = list()
    status = True

    tData = ApData.zap.get_testcase_configuration("test_gnmi_SetPfxPath")
    input_conf = json.loads(six.moves.builtins.open(tData["input_conf_file"], 'r').read())
    #print(input_conf)

    log.info('Performing SET-REPLACE Request w/Prefix-Path consisting of Multikey to target \n')
    try:
        if 'MKEYPfx_SET1_1' in input_conf:
            set_info1 = input_conf['MKEYPfx_SET1_1']
            print(set_info1['prefix-path'])
            print(set_info1['Updates'])
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            pfx_path = gnmiTestLib._parse_path(gnmiTestLib._path_names(set_info1['prefix-path']))
            reply = gnmiTestLib._set(stub, paths, 'replace', user, password, set_info1['Updates'], pfx_path)
            resp = str(reply)
            log.info(resp)
            sresp = "".join(resp.split('\n'))
            log.info (sresp.replace(" ", ""))
            mt1 = 'prefix{elem{name:"openconfig-system:system"}elem{name:"logging"}elem{name:"console"}elem{name:"selectors"}'
            mt2 = 'elem{name:"selector"key{key:"facility"value:"openconfig-system-logging:KERNEL"}'
            mt3 = 'key{key:"severity"value:"CRITICAL"}}}response{path{}op:REPLACE}'
                   
            if (mt1+mt2+mt3 in sresp.replace(" ", "")):
                log.info("PfxPath_wMKEYSET1_1:Passed - was able to do SET-REPLACE w/PfxPath consisting of Multiple Keys")
            else:
                log.info("PfxPath_wMKEYSET1_1:Failed - was unable to do SET-REPLACE w/PfxPath consisting of Multiple Keys")

            prefix = input_conf['VERIFY_MKEYPfx_SET1_1']['prefix']
            path = input_conf['VERIFY_MKEYPfx_SET1_1']['path']
            path = gnmiTestLib._parse_path(gnmiTestLib._path_names(path))
            response = gnmiTestLib._get(stub, path, user, password,prefix,type='CONFIG',encoding=encoding)
            log.info("Response : {}".format(response)) 

            msg_dict = google.protobuf.json_format.MessageToDict(response)
            
            #log.info("msg dict json dump: {}".format(json.dumps(msg_dict,sort_keys=True, indent=4)))
            if 'PROTO' in encoding:
                resp_dict = gnmiTestLib.get_response_dict(msg_dict)
                for cfg in input_conf['VERIFY_MKEYPfx_SET1_1']['config']:
                    result = gnmiTestLib.verify_get_response(resp_dict,set_info1,cfg)
                    err_msg = result['err_msg'] + err_msg

            elif 'JSON_IETF' in encoding:
                json_ietf_val = json.loads(response.notification[0].update[0].val.json_ietf_val)
                pfx_path = set_info1['prefix-path']
                pfx_path = gnmiTestLib._path_names(pfx_path)
                json_ietf_val = json_ietf_val['data'][pfx_path[0]][pfx_path[1]][pfx_path[2]][pfx_path[3]]['selector'][0]['config']
                update = set_info1['Updates']['config']
                result = gnmiTestLib.verify_json_ietf_response(update,json_ietf_val)
                err_msg = result['err_msg'] + err_msg


    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        pytest.fail("Test PfxPath_wMKEYSET1_1 failed due to Grpc Error {err}".format(err=e.details()))

    if len(err_msg) != 0:
        log.error("Test MKEYPfx_SET1_1 failed due to : {}".format(*err_msg))
        status = False
    else:
        log.info("Test MKEYPfx_SET1_1 - Set and Get Passed")

    err_msg = list()
    log.info('Performing SET-UPDATE Request w/Prefix-Path consisting of Multikey to target \n')
    try:
        if 'MKEYPfx_SET1_2' in input_conf:
            set_info1 = input_conf['MKEYPfx_SET1_2']
            print(set_info1['prefix-path'])
            print(set_info1['Updates'])
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            pfx_path = gnmiTestLib._parse_path(gnmiTestLib._path_names(set_info1['prefix-path']))
            reply = gnmiTestLib._set(stub, paths, 'update', user, password, set_info1['Updates'], pfx_path)
            resp = str(reply)
            log.info(resp)
            sresp = "".join(resp.split('\n'))
            log.info (sresp.replace(" ", ""))
            mt1 = 'prefix{elem{name:"openconfig-system:system"}elem{name:"logging"}elem{name:"console"}elem{name:"selectors"}'
            mt2 = 'elem{name:"selector"key{key:"facility"value:"openconfig-system-logging:KERNEL"}'
            mt3 = 'key{key:"severity"value:"ALERT"}}}response{path{}op:UPDATE}'
                   
            if (mt1+mt2+mt3 in sresp.replace(" ", "")):
                log.info("PfxPath_wMKEYSET1_2:Passed - was able to do SET-UPDATE w/PfxPath consisting of Multiple Keys")
            else:
                log.info("PfxPath_wMKEYSET1_2:Failed - was unable to do SET-UPDATE w/PfxPath consisting of Multiple Keys")

            prefix = input_conf['VERIFY_MKEYPfx_SET1_2']['prefix']
            path = input_conf['VERIFY_MKEYPfx_SET1_2']['path']
            path = gnmiTestLib._parse_path(gnmiTestLib._path_names(path))
            response = gnmiTestLib._get(stub, path, user, password,prefix,type='CONFIG',encoding=encoding)
            #log.info(response) 

            if 'PROTO' in encoding:
                msg_dict = google.protobuf.json_format.MessageToDict(response)
                #log.info(json.dumps(msg_dict,sort_keys=True, indent=4))
                resp_dict = gnmiTestLib.get_response_dict(msg_dict)
                for cfg in input_conf['VERIFY_MKEYPfx_SET1_2']['config']:
                    result = gnmiTestLib.verify_get_response(resp_dict,set_info1,cfg)
                    err_msg = result['err_msg'] + err_msg

            elif 'JSON_IETF' in encoding:
                # Once 675 is fixed, we will be looking at only multikey value, then we need not loop through the list of json_ietf_value
                json_ietf_val = json.loads(response.notification[0].update[0].val.json_ietf_val)
                pfx_path = set_info1['prefix-path']
                pfx_path = gnmiTestLib._path_names(pfx_path)
                json_ietf_val = json_ietf_val['data'][pfx_path[0]][pfx_path[1]][pfx_path[2]][pfx_path[3]]['selector'][0]['config']
                update = set_info1['Updates']['config']
                log.info("json_ietf_val: %s" % json_ietf_val)
                result = gnmiTestLib.verify_json_ietf_response(update,json_ietf_val)
                err_msg = result['err_msg'] + err_msg

    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        pytest.fail("Test PfxPath_wMKEYSET1_2 failed due to Grpc Error {err}".format(err=e.details()))

    if len(err_msg) != 0:
        log.error("Test MKEYPfx_SET1_2 failed due to : {}".format(*err_msg))
        status = False
    else:
        log.info("Test MKEYPfx_SET1_2 - Set and Get Passed")

    err_msg = list()

    log.info('Performing SET-DELETE to CLEANUP above config of Multiple Keys \n')
    try:
        xpath = "/system/logging/console/selectors/selector"
        paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
        reply = gnmiTestLib._set(stub, paths, 'delete', user, password, set_info1)
        resp = str(reply)
        log.info(resp)
        sresp = "".join(resp.split('\n'))
        log.info (sresp.replace(" ", ""))
        mt1 = 'response{path{elem{name:"openconfig-system:system"}elem{name:"logging"}elem{name:"console"}}op:DELETE}'
        if (mt1 in sresp.replace(" ", "")):
            log.info("PfxPath_wMKEYSET1_3:Passed - was able to do SET-DELETE w/Path consisting of Multiple Keys")
        else:
            log.info("PfxPath_wMKEYSET1_3:Failed - was unable to do SET-DELETE w/Path consisting of Multiple Keys")
            
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        pytest.fail("Test PfxPath_wMKEYSET1_3 failed due to Grpc Error {err}".format(err=e.details())) 

    if not status:
        pytest.fail("Test MKEYPfx_SET failed ")
    else:
        log.info("Test MKEYPfx_SET - Set and Get Passed")


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
        pytest.fail("Test SETReq_Del1_2 failed due to Grpc Error {err}".format(err=e.details()))            


def _test_MultiSet_Mkey1(stub):
    user = None
    password = None
    err_msg = list()

    input_conf = json.loads(six.moves.builtins.open(ApData.input_conf_file, 'r').read())
    #print(input_conf)

    log.info('Performing SET Request w/Multiple Ops(REPLACE+UPDATE) on Paths consisting of Regular & Multikey \n')
    try:
        if 'MULTISET_Mkey1_1' in input_conf:
            set_info1 = input_conf['MULTISET_Mkey1_1']
            print(set_info1)
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            if set_info1['set-type'] == 'multiple':
                reply = gnmiTestLib._set(stub, paths, 'multiple', user, password, set_info1)
                resp = str(reply)
                log.info(resp)
                sresp = "".join(resp.split('\n'))
                log.info (sresp.replace(" ", ""))
                mt1 = 'response{path{}op:REPLACE}response{path{}op:UPDATE}'
                if (mt1 in sresp.replace(" ", "")):
                    log.info("MSET_Mkey1_1:Passed - was able to do Multi-Set w/Paths including Regular & Multiple Keys")
                else:
                    log.info("MSET_Mkey1_1:Failed - was unable to do SET-DELETE w/Path including Regular & Multiple Keys")
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        pytest.fail("Test MSET_Mkey1_1 failed due to Grpc Error {err}".format(err=e.details()))


    log.info('Performing SET Request w/Multiple Ops(REPLACE+UPDATE) on Paths consisting of only Multikeys \n')
    try:
        if 'MULTISET_Mkey1_2' in input_conf:
            set_info1 = input_conf['MULTISET_Mkey1_2']
            print(set_info1)
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            if set_info1['set-type'] == 'multiple':
                reply = gnmiTestLib._set(stub, paths, 'multiple', user, password, set_info1)
                resp = str(reply)
                log.info(resp)
                sresp = "".join(resp.split('\n'))
                log.info (sresp.replace(" ", ""))
                mt1 = 'response{path{}op:REPLACE}response{path{}op:UPDATE}'
                if (mt1 in sresp.replace(" ", "")):
                    log.info("MSET_Mkey1_2:Passed - was able to do Multi-Set w/Paths consisting of only Multikeys")
                else:
                    log.info("MSET_Mkey1_2:Failed - was unable to do SET-DELETE w/Paths consisting of only Multikeys")
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        pytest.fail("Test MSET_Mkey1_2 failed due to Grpc Error {err}".format(err=e.details()))

    log.info('Performing SET-DELETE to CLEANUP above config of MultiSet w/Multiple Keys \n')
    try:
        xpath = "/system/logging/console/selectors/selector"
        paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
        reply = gnmiTestLib._set(stub, paths, 'delete', user, password, set_info1)
        resp = str(reply)
        log.info(resp)
        sresp = "".join(resp.split('\n'))
        log.info (sresp.replace(" ", ""))
        mt1 = 'response{path{elem{name:"openconfig-system:system"}elem{name:"logging"}elem{name:"console"}}op:DELETE}'
        if (mt1 in sresp.replace(" ", "")):
            log.info("MSET_Mkey1_3:Passed - was able to do SET-DELETE w/Path consisting MultiSet of Multiple Keys")
        else:
            log.info("MSET_Mkey1_3:Failed - was unable to do SET-DELETE w/Path consisting MultiSet of Multiple Keys")
            
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        pytest.fail("Test MSET_Mkey1_3 failed due to Grpc Error {err}".format(err=e.details())) 


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
        pytest.fail("Test PFXPath_MSet_1 failed due to Grpc Error {err}".format(err=e.details()))


def _test_SetReq_Del1(stub):
    user = None
    password = None
    err_msg = list()

    input_conf = json.loads(six.moves.builtins.open(ApData.input_conf_file, 'r').read())
    #print(input_conf)

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
        resp_dict = gnmiTestLib.get_response_dict(msg_dict)
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
            set_info = input_conf['GET_WITH_PFX']['config']
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            reply = gnmiTestLib._set(stub, paths, 'replace', user, password, set_info)
            log.info(str(reply))
            if ('response' in str(reply) and 'op: REPLACE' in str(reply)):
                log.info("test_Neg_set_with_vld_del_inv_upd:Passed - was able to do SET-REPLACE with input json")
            else:
                log.info("test_Neg_set_with_vld_del_inv_upd:Failed - was unable to do SET-REPLACE with input json")
            
            prefix = input_conf['GET_WITH_PFX']['verify']['prefix']
            #prefix = gnmiTestLib._parse_path(gnmiTestLib._path_names(prefix))
            path = input_conf['GET_WITH_PFX']['verify']['path']
            path = gnmiTestLib._parse_path(gnmiTestLib._path_names(path))
            response = gnmiTestLib._get(stub, path, user, password,prefix,type='CONFIG')
            #log.info(response)   

            msg_dict = google.protobuf.json_format.MessageToDict(response)
            #log.info(json.dumps(msg_dict,sort_keys=True, indent=4))
            resp_dict = gnmiTestLib.get_response_dict(msg_dict)
            for cfg in input_conf['GET_WITH_PFX']['verify']['config']:
                result = gnmiTestLib.verify_get_response(resp_dict,set_info,cfg)
                err_msg = result['err_msg'] + err_msg
    
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
            set_info = input_conf['GET_WITH_PFX']['config']
            prefix = input_conf['GET_WITH_PFX']['verify']['prefix']
            #prefix = gnmiTestLib._parse_path(gnmiTestLib._path_names(prefix))
            path = input_conf['GET_WITH_PFX']['verify']['path']
            path = gnmiTestLib._parse_path(gnmiTestLib._path_names(path))
            response = gnmiTestLib._get(stub, path, user, password,prefix,type='CONFIG')
            #log.info(response)   

            msg_dict = google.protobuf.json_format.MessageToDict(response)
            #log.info(json.dumps(msg_dict,sort_keys=True, indent=4))
            resp_dict = gnmiTestLib.get_response_dict(msg_dict)
            for cfg in input_conf['GET_WITH_PFX']['verify']['config']:
                result = gnmiTestLib.verify_get_response(resp_dict,set_info,cfg)
                err_msg = result['err_msg'] + err_msg

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
            set_info = input_conf['GET_WITH_PFX']['config']
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            reply = gnmiTestLib._set(stub, paths, 'replace', user, password, set_info)
            log.info(str(reply))
            if ('response' in str(reply) and 'op: REPLACE' in str(reply)):
                log.info("test_set_with_mul_attr_val:Passed - was able to do SET-REPLACE with input json")
            else:
                log.info("test_set_with_mul_attr_val:Failed - was unable to do SET-REPLACE with input json")
            
            prefix = input_conf['GET_WITH_PFX']['verify']['prefix']
            path = input_conf['GET_WITH_PFX']['verify']['path']
            path = gnmiTestLib._parse_path(gnmiTestLib._path_names(path))
            response = gnmiTestLib._get(stub, path, user, password,prefix,type='CONFIG')
            #log.info(response)   

            msg_dict = google.protobuf.json_format.MessageToDict(response)
            #log.info(json.dumps(msg_dict,sort_keys=True, indent=4))
            resp_dict = gnmiTestLib.get_response_dict(msg_dict)
            for cfg in input_conf['GET_WITH_PFX']['verify']['config']:
                result = gnmiTestLib.verify_get_response(resp_dict,set_info,cfg)
                err_msg = result['err_msg'] + err_msg
    
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
                set_info = input_conf['Mult_Set_Rep_1']['config']
                xpath = "/"
                paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
                reply = gnmiTestLib._set(stub, paths, 'replace', user, password, set_info)
                resp = str(reply)
                log.info(resp)
            if ('response' in str(reply) and 'op: REPLACE' in str(reply)):
                log.info("test_set_with_mul_attr_val:Passed - was able to do SET-REPLACE with input json")
            else:
                log.info("test_set_with_mul_attr_val:Failed - was unable to do SET-REPLACE with input json")
            
            
            prefix = input_conf['GET_WITH_PFX']['verify']['prefix']
            path = input_conf['GET_WITH_PFX']['verify']['path']
            path = gnmiTestLib._parse_path(gnmiTestLib._path_names(path))
            response = gnmiTestLib._get(stub, path, user, password,prefix,type='CONFIG')
            #log.info(response)   

            msg_dict = google.protobuf.json_format.MessageToDict(response)
            #log.info(json.dumps(msg_dict,sort_keys=True, indent=4))
            resp_dict = gnmiTestLib.get_response_dict(msg_dict)
            for cfg in input_conf['Mult_Set_Rep_1']['verify']['config']:
                result = gnmiTestLib.verify_get_response(resp_dict,set_info,cfg)
                err_msg = result['err_msg'] + err_msg    

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
                set_info = input_conf['GET_WITH_PFX']['config']
                xpath = "/"
                paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
                reply = gnmiTestLib._set(stub, paths, 'update', user, password, set_info)
                resp = str(reply)
                log.info(resp)
            if ('response' in str(reply) and 'op: UPDATE' in str(reply)):
                log.info("test_set_with_mul_attr_val:Passed - was able to do SET-UPDATE with input json")
            else:
                log.info("test_set_with_mul_attr_val:Failed - was unable to do SET-UPDATE with input json")
            
            
            prefix = input_conf['GET_WITH_PFX']['verify']['prefix']
            path = input_conf['GET_WITH_PFX']['verify']['path']
            path = gnmiTestLib._parse_path(gnmiTestLib._path_names(path))
            response = gnmiTestLib._get(stub, path, user, password,prefix,type='CONFIG')
            #log.info(response)   

            msg_dict = google.protobuf.json_format.MessageToDict(response)
            #log.info(json.dumps(msg_dict,sort_keys=True, indent=4))
            resp_dict = gnmiTestLib.get_response_dict(msg_dict)
            for cfg in input_conf['GET_WITH_PFX']['verify']['config']:
                result = gnmiTestLib.verify_get_response(resp_dict,set_info,cfg)
                err_msg = result['err_msg'] + err_msg    

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
            set_info = input_conf['GET_WITH_PFX']['config']
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            reply = gnmiTestLib._set(stub, paths, 'replace', user, password, set_info)
            log.info(str(reply))
            if ('response' in str(reply) and 'op: REPLACE' in str(reply)):
                log.info("test_Set_with_partial_val:Passed - was able to do SET-REPLACE with input json")
            else:
                log.info("test_Set_with_partial_val:Failed - was unable to do SET-REPLACE with input json")
            
            prefix = input_conf['GET_WITH_PFX']['verify']['prefix']
            path = input_conf['GET_WITH_PFX']['verify']['path']
            path = gnmiTestLib._parse_path(gnmiTestLib._path_names(path))
            response = gnmiTestLib._get(stub, path, user, password,prefix,type='CONFIG')
            #log.info(response)   

            msg_dict = google.protobuf.json_format.MessageToDict(response)
            #log.info(json.dumps(msg_dict,sort_keys=True, indent=4))
            resp_dict = gnmiTestLib.get_response_dict(msg_dict)
            for cfg in input_conf['GET_WITH_PFX']['verify']['config']:
                result = gnmiTestLib.verify_get_response(resp_dict,set_info,cfg)
                err_msg = result['err_msg'] + err_msg    
    
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
                set_info = input_conf['Neg_Set_Partial_1']['config']
                xpath = "/"
                paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
                reply = gnmiTestLib._set(stub, paths, 'replace', user, password, set_info)
                resp = str(reply)
                log.info(resp)
            if ('response' in str(reply) and 'op: REPLACE' in str(reply)):
                log.info("test_Set_with_partial_val:Passed - was able to do SET-REPLACE with input json")
            else:
                log.info("test_Set_with_partial_val:Failed - was unable to do SET-REPLACE with input json")
            
            
                prefix = input_conf['Neg_Set_Partial_1']['verify']['prefix']
                path = input_conf['Neg_Set_Partial_1']['verify']['path']
                path = gnmiTestLib._parse_path(gnmiTestLib._path_names(path))
                response = gnmiTestLib._get(stub, path, user, password,prefix,type='CONFIG')
                #log.info(response)   

                msg_dict = google.protobuf.json_format.MessageToDict(response)
                #log.info(json.dumps(msg_dict,sort_keys=True, indent=4))
                resp_dict = gnmiTestLib.get_response_dict(msg_dict)
                for cfg in input_conf['Neg_Set_Partial_1']['verify']['config']:
                    result = gnmiTestLib.verify_get_response(resp_dict,set_info,cfg)
                    err_msg = result['err_msg'] + err_msg     

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
                set_info = input_conf['GET_WITH_PFX']["config"]
                xpath = "/"
                paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
                reply = gnmiTestLib._set(stub, paths, 'replace', user, password, set_info)
                log.info(str(reply))
                if ('response' in str(reply) and 'op: REPLACE' in str(reply)):
                    log.info("test_Set_with_partial_val:Passed - was able to do SET-REPLACE with input json")
                else:
                    log.info("test_Set_with_partial_val:Failed - was unable to do SET-REPLACE with input json")

                set_info = input_conf['Neg_Set_Partial_1']["config"]
                xpath = "/"
                paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
                reply = gnmiTestLib._set(stub, paths, 'update', user, password, set_info)
                resp = str(reply)
                log.info(resp)
                if ('response' in str(reply) and 'op: UPDATE' in str(reply)):
                    log.info("test_Set_with_partial_val:Passed - was able to do SET-UPDATE with input json")
                else:
                    log.info("test_Set_with_partial_val:Failed - was unable to do SET-UPDATE with input json")
                
                prefix = input_conf['Neg_Set_Partial_1']['verify']['prefix']
                path = input_conf['Neg_Set_Partial_1']['verify']['path']
                path = gnmiTestLib._parse_path(gnmiTestLib._path_names(path))
                response = gnmiTestLib._get(stub, path, user, password,prefix,type='CONFIG')
                #log.info(response)   

                msg_dict = google.protobuf.json_format.MessageToDict(response)
                #log.info(json.dumps(msg_dict,sort_keys=True, indent=4))
                resp_dict = gnmiTestLib.get_response_dict(msg_dict)
                for cfg in input_conf['Neg_Set_Partial_1']['verify']['config']:
                    section = cfg['section']
                    set_info = input_conf[section]['config']
                    result = gnmiTestLib.verify_get_response(resp_dict,set_info,cfg)
                    err_msg = result['err_msg'] + err_msg     

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
            set_info = input_conf['GET_WITH_PFX']['config']
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            reply = gnmiTestLib._set(stub, paths, 'replace', user, password, set_info)
            log.info(str(reply))
            if ('response' in str(reply) and 'op: REPLACE' in str(reply)):
                log.info("test_Path_with_keys:Passed - was able to do SET-REPLACE with input json")
            else:
                log.info("test_Path_with_keys:Failed - was unable to do SET-REPLACE with input json")
            
        if 'PATH_CHECK' in input_conf:
            set_info = input_conf['PATH_CHECK']['config']
            xpath ="openconfig-interfaces:interfaces/interface[name=eth-1/1/1]"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            reply = gnmiTestLib._set(stub, paths, 'update', user, password, set_info)
            log.info(str(reply))
            if ('response' in str(reply) and 'op: UPDATE' in str(reply)):
                log.info("test_Path_with_keys:Passed - was able to do SET-UPDATE with input json")
            else:
                log.info("test_Path_with_keys:Failed - was unable to do SET-UPDATE with input json")
                        
            prefix = input_conf['PATH_CHECK']['verify']['prefix']
            path = input_conf['PATH_CHECK']['verify']['path']
            path = gnmiTestLib._parse_path(gnmiTestLib._path_names(path))
            response = gnmiTestLib._get(stub, path, user, password,prefix,type='CONFIG')
            #log.info(response)   

            msg_dict = google.protobuf.json_format.MessageToDict(response)
            #log.info(json.dumps(msg_dict,sort_keys=True, indent=4))
            resp_dict = gnmiTestLib.get_response_dict(msg_dict)
            for cfg in input_conf['PATH_CHECK']['verify']['config']:
                section = cfg['section']
                set_info = input_conf[section]['config']
                result = gnmiTestLib.verify_get_response(resp_dict,set_info,cfg)
                err_msg = result['err_msg'] + err_msg

    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        err_msg.append("test_Path_with_keys (SET-UPDATE) failed due to Grpc Error {err}".format(err=e.details()))
    """
    try:
        if 'GET_WITH_PFX' in input_conf:
            set_info = input_conf['GET_WITH_PFX']['config']
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            reply = gnmiTestLib._set(stub, paths, 'replace', user, password, set_info)
            log.info(str(reply))
            if ('response' in str(reply) and 'op: REPLACE' in str(reply)):
                log.info("test_Path_with_keys:Passed - was able to do SET-REPLACE with input json")
            else:
                log.info("test_Path_with_keys:Failed - was unable to do SET-REPLACE with input json")
            
        if 'PATH_CHECK' in input_conf:
            set_info = input_conf['PATH_CHECK']['config']
            xpath ="openconfig-interfaces:interfaces/interface[name=eth-1/1/1]"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            reply = gnmiTestLib._set(stub, paths, 'replace', user, password, set_info)
            log.info(str(reply))
            if ('response' in str(reply) and 'op: REPLACE' in str(reply)):
                log.info("test_Path_with_keys:Passed - was able to do SET-REPLACE with input json")
            else:
                log.info("test_Path_with_keys:Failed - was unable to do SET-REPLACE with input json")
                        
            prefix = input_conf['PATH_CHECK']['verify']['prefix']
            path = input_conf['PATH_CHECK']['verify']['path']
            path = gnmiTestLib._parse_path(gnmiTestLib._path_names(path))
            response = gnmiTestLib._get(stub, path, user, password,prefix,type='CONFIG')
            #log.info(response)   

            msg_dict = google.protobuf.json_format.MessageToDict(response)
            #log.info(json.dumps(msg_dict,sort_keys=True, indent=4))
            resp_dict = gnmiTestLib.get_response_dict(msg_dict)
            for cfg in input_conf['PATH_CHECK']['verify']['config']:
                section = cfg['section']
                set_info = input_conf[section]['config']
                result = gnmiTestLib.verify_get_response(resp_dict,set_info,cfg)
                err_msg = result['err_msg'] + err_msg
    
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        err_msg.append("test_Path_with_keys (SET-REPLACE) failed due to Grpc Error {err}".format(err=e.details()))
    """
    try:
        xpath = "/oc-if:interfaces/oc-if:interface[name=eth-1/1/1]"
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


def _test_Tgt_in_NonPfx(stub):
    user = None
    password = None
    err_msg = list()

    tData = ApData.zap.get_testcase_configuration("test_gnmi_SetPfxPath")
    input_conf = json.loads(six.moves.builtins.open(tData["input_conf_file"], 'r').read())
    print(input_conf)

    log.info('Performing SET-REPLACE w/Path Target(gnmi spec:2.2.2.1) in Non Prefix Path\n')
    log.info('For this test we will use Path Target = "TGT_NON_PFX"')
    try:
        if 'SETPfxPath2_1' in input_conf:
            set_info1 = input_conf['SETPfxPath2_1']
            print(set_info1['prefix-path'])
            print(set_info1['Updates'])
            target = set_info1['target']
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath),target)
            pfx_path = gnmiTestLib._parse_path(gnmiTestLib._path_names(set_info1['prefix-path']))
            reply = gnmiTestLib._set(stub, paths, 'replace', user, password, set_info1['Updates'], pfx_path)
            resp = str(reply)
            log.info("### RCVD RESPONSE ###")
            log.info(resp)
            sresp = "".join(resp.split('\n'))
            log.info (sresp)
            mt1 = 'prefix {  elem {    name: "ietf-interfaces:interfaces"  }}'
            mt2 = 'target'
            if (mt1 in sresp and mt2 not in sresp):
                log.info("Tgt_NonPfx_1_1:Passed - SET w/Path Target in Non-Pfx Path works correctly")
            else:
                log.error("Tgt_NonPfx_1_1:Failed - Response of SET w/Path Target in Non-Pfx Path does not work correctly")
                err_msg.append("Tgt_NonPfx_1_1:Failed - Response of SET w/Path Target in Non-Pfx Path does not work correctly")
            
            prefix = "/"
            path = input_conf['VERIFY_TGT_NON_PFX']['prefix-path']
            path = gnmiTestLib._parse_path(gnmiTestLib._path_names(path),target=target)
            response = gnmiTestLib._get(stub, path, user, password,prefix,type='CONFIG')
            log.info(response) 

            msg_dict = google.protobuf.json_format.MessageToDict(response)
            #log.info(json.dumps(msg_dict,sort_keys=True, indent=4))
            resp_dict = gnmiTestLib.get_response_dict(msg_dict)
            for cfg in input_conf['VERIFY_TGT_NON_PFX']['config']:
                section = cfg['section']
                set_info = input_conf[section]
                result = gnmiTestLib.verify_get_response(resp_dict,set_info,cfg)
                err_msg = result['err_msg'] + err_msg

    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        pytest.fail("Test Tgt_NonPfx_1_1 failed due to Grpc Error {err}".format(err=e.details()))
    
    if len(err_msg) != 0:
        log.error("Test Tgt_NonPfx failed due to : {}".format(*err_msg))
        pytest.fail("Test Tgt_NonPfx - FAILED")
    else:
        log.info("Test Tgt_NonPfx - PASSED")


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
            resp_dict = gnmiTestLib.get_response_dict(msg_dict)

            cfg = input_conf['VERIFY_SET_RplOmit_1']['config'][0]
            result = gnmiTestLib.verify_get_response(resp_dict,set_info1['set-omit'],cfg)
            err_msg = result['err_msg'] + err_msg
            cfg = input_conf['VERIFY_SET_RplOmit_1']['config'][1]
            result = gnmiTestLib.verify_get_response(resp_dict,set_info1['set-omit'],cfg)
            if 'No matching check variable: description' not in result['err_msg'][0]:
                err_msg.append("{} 'description' key should not be present in config as it was not sent in SET-REPLACE")

            
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        pytest.fail("Test SET_RplOmit1_1 failed due to Grpc Error {err}".format(err=e.details()))

    if len(err_msg) != 0:
        log.error("Test SET_RplOmit1 failed due to : {}".format(*err_msg))
        pytest.fail("Test SET_RplOmit1 - FAILED")
    else:
        log.info("Test SET_RplOmit1 - PASSED")


def _test_gnmi_intf_scale(conn,del_cfg=True):
    stub = conn.stub
    user = None
    password = None
    err_msg = list()
    
    #with open(ApData.input_conf_file, 'r') as ip_conf_file:
    #    input_conf = gnmiTestLib.json_load_byteified(ip_conf_file)

    input_conf = json.loads(six.moves.builtins.open(ApData.zap.get_testcase_configuration("test_gnmi_intf_scale/input_conf_file"), 'r').read())

    log.info('Performing SET-UPDATE Request to target \n')
    try:
        for intf_num in range(1,4096):
            resp_key_list = list()
            set_info = input_conf["SCALE_INTF_{}".format(intf_num)]["config"]
            print(type(set_info))
            print(set_info)
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            reply = gnmiTestLib._set(stub, paths, 'update', user, password, set_info)
            log.info(str(reply))
            if ('response' in str(reply) and 'op: UPDATE' in str(reply)):
                log.info("test_gnmi_intf_scale:Passed - was able to do SET-UPDATE with input json")
            else:
                log.error("test_gnmi_intf_scale:Failed - was unable to do SET-UPDATE with input json")
                err_msg.append("test_gnmi_intf_scale:Failed - was unable to do SET-UPDATE with input json")
            
            prefix = input_conf["SCALE_INTF_{}".format(intf_num)]['verify']['prefix']
            #prefix = gnmiTestLib._parse_path(gnmiTestLib._path_names(prefix))
            path = input_conf["SCALE_INTF_{}".format(intf_num)]['verify']['path']
            path = gnmiTestLib._parse_path(gnmiTestLib._path_names(path))
            response = gnmiTestLib._get(stub, path, user, password,prefix,type='CONFIG')
            #log.info(response)
            msg_dict = google.protobuf.json_format.MessageToDict(response)
            resp_dict = gnmiTestLib.get_response_dict(msg_dict)
            for cfg in input_conf["SCALE_INTF_{}".format(intf_num)]['verify']['config']:
                section = cfg['section']
                set_info = input_conf[section]['config']
                result = gnmiTestLib.verify_get_response(resp_dict,set_info,cfg)
                err_msg = result['err_msg'] + err_msg
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        err_msg.append("Test test_gnmi_intf_scale failed due to Grpc Error {err}".format(err=e.details()))

    if del_cfg:
        try:
            xpath = "/oc-if:interfaces"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            reply = gnmiTestLib._set(stub, paths, 'delete', user, password, set_info)
            log.info(str(reply))
            if ('response' in str(reply) and 'op: DELETE' in str(reply)):
                log.info("test_gnmi_intf_scale:Passed - was able to do SET-DELETE on target")
            else:
                log.error("test_gnmi_intf_scale:Failed - was unable to do SET-DELETE on target")
                err_msg.append("test_gnmi_intf_scale:Failed - was unable to do SET-DELETE on target")
        except KeyboardInterrupt:
            log.info("Shutting down.")
        except grpc.RpcError as e:
            log.error("### GRPC ERROR RECEIVED:: ###")
            log.error(e)
            printGrpcError(e)
            err_msg.append("test_gnmi_intf_scale - Delete Config during cleanup failed due to Grpc Error {err}".format(err=e.details()))


    if len(err_msg) != 0:
        log.error("Test test_gnmi_intf_scale failed due to : {}".format(*err_msg))
        pytest.fail("Test test_gnmi_intf_scale - FAILED")
    else:
        log.info("Test test_gnmi_intf_scale - PASSED")

    conn.shutdown()

def _test_parallel_set_get(gnmi_conn):
    _test_gnmi_intf_scale(gnmi_conn,del_cfg=False)
    gnmi_conn.closeAllConnections() 
    pool = Pool(processes=2)
    user = None
    password = None
    err_msg = list()

    try:
        results = pool.map(gnmiTestLib.parallel_oper,['set','get'])
        for result in results:
            oper = result['oper']
            status = result['status']
            if "set" in oper:
                if status:
                    log.info("Test Passed: Process handling SET succeeded in updating the config")
                else:
                    msg=result['msg']
                    for error in msg:
                        err_msg.append("Test:Failed - Process handling SET failed due to : {}".format(error))

            if "get" in oper:
                if status:
                    log.info("Test Passed: Process handling GET succeeded in getting the config")
                else:
                    msg=result['msg']
                    for error in msg:
                        err_msg.append("Test:Failed - Process handling GET failed due to : {}".format(error))

    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
    
    try:
        gnmi_conn = gnmiTestLib.GnmiConnection(target=ApData.svr_addr,port=ApData.port_addr)
        #input_conf = json.loads(six.moves.builtins.open(ApData.zap.get_testcase_configuration("test_gnmi_parallel_oper/input_conf_file"), 'r').read())
        #set_info = input_conf["SCALE_INTF_{}".format(intf_num)]
        xpath = "/oc-if:interfaces"
        paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
        reply = gnmiTestLib._set(gnmi_conn.stub, paths, 'delete', user, password,None)
        log.info(str(reply))
        if ('response' in str(reply) and 'op: DELETE' in str(reply)):
            log.info("test_parallel_set_get:Passed - was able to do SET-DELETE on target")
        else:
            log.error("test_parallel_set_get:Failed - was unable to do SET-DELETE on target")
            err_msg.append("test_parallel_set_get:Failed - was unable to do SET-DELETE on target")
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        err_msg.append("test_parallel_set_get - Delete Config during cleanup failed due to Grpc Error {err}".format(err=e.details()))

    if len(err_msg) != 0:
        log.error("Test test_parallel_set_get failed due to : {}".format(*err_msg))
        pytest.fail("Test test_parallel_set_get FAILED")
    else:
        log.info("Test test_parallel_set_get - PASSED")

def _test_default_filter(stub,encoding):
    user = None
    password = None
    err_msg = list()
    
    input_conf = json.loads(six.moves.builtins.open(ApData.zap.get_testcase_configuration("test_Get_with_prefix/input_conf_file"), 'r').read())
    
    log.info('Performing SET-REPLACE Request to target \n')
    try:
        if 'GET_WITH_PFX' in input_conf:
            set_info = input_conf['GET_WITH_PFX']['config']
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            reply = gnmiTestLib._set(stub, paths, 'replace', user, password, set_info)
            log.info(str(reply))
            if ('response' in str(reply) and 'op: REPLACE' in str(reply)):
                log.info("test_Get_with_prefix:Passed - was able to do SET-REPLACE with input json")
            else:
                log.info("test_Get_with_prefix:Failed - was unable to do SET-REPLACE with input json")
            
            prefix = input_conf['GET_WITH_PFX']['verify']['prefix']
            path = input_conf['GET_WITH_PFX']['verify']['path']
            path = gnmiTestLib._parse_path(gnmiTestLib._path_names(path))
            response = gnmiTestLib._get(stub, path, user, password,prefix,type='CONFIG',encoding=encoding)
            #log.info(response)   
            
            #log.info("msg dict json dump: {}".format(json.dumps(msg_dict,sort_keys=True, indent=4)))
            if 'PROTO' in encoding:
                msg_dict = google.protobuf.json_format.MessageToDict(response)
                resp_dict = gnmiTestLib.get_response_dict(msg_dict)
                var = 'enabled'
                get_key = "interfaces,interface,config"
                for resp_key in resp_dict.keys():
                    for key_var in resp_dict[resp_key]:
                        if get_key in key_var.keys():
                            try:
                                get_var = key_var[get_key][var]
                                log.error("Default Filtering is disabled. Value for enabled is %s" % get_var)
                                err_msg.append("Default Filtering is disabled. Value for enabled is %s" % get_var)
                            except KeyError:
                                log.info("Default Filtering is enabled")
            
            elif 'JSON_IETF' in encoding:
                json_ietf_val = json.loads(response.notification[0].update[0].val.json_ietf_val)
                json_ietf_val = json_ietf_val['data']['openconfig-interfaces:interfaces']['interface']
                for set_d in json_ietf_val:
                    if 'enabled' in set_d['config'].keys():
                        get_var = set_d['config']['enabled']
                        log.error("Default Filtering is disabled. Value for enabled is %s" % get_var)
                        err_msg.append("Default Filtering is disabled. Value for enabled is %s" % get_var)
                    else:
                        log.info("Default Filtering is enabled")
    
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

def _test_get_at_root(stub,encoding):
    user = None
    password = None
    log.info('Performing CapabilitiesRequest to target \n')
    xpath = "/"
    paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
    response = gnmiTestLib._get(stub, paths, user, password,encoding=encoding)
    #log.info(response)
    if 'PROTO' in encoding:
        msg_dict = google.protobuf.json_format.MessageToDict(response)
        resp_dict = gnmiTestLib.get_response_dict(msg_dict)
        if resp_dict is not None or len(resp_dict) > 2:
            log.info("Keys in GNMI GET PROTO encoding: %s" % resp_dict.keys())
            log.info("Length of return dict: %s" % len(resp_dict))
        else:
            log.error("Test test_get_at_root failed, returned config is empty")
    elif 'JSON_IETF' in encoding:
        json_ietf_val = json.loads(response.notification[0].update[0].val.json_ietf_val)
        if not bool(json_ietf_val['data']) or len(json_ietf_val['data']) > 2:
            log.info("Keys in GNMI GET JSON_IETF encoding: %s" % json_ietf_val['data'].keys())
            log.info("Length of return dict: %s" % len(json_ietf_val['data']))
        else:
            log.error("Test test_get_at_root failed, returned config is empty")