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
from operator import itemgetter
import six
import google.protobuf.json_format
from infra_base_ap import ApData, InfraApBase
import infra_test_lib as infTestLib
log = CafyLog("INFRA AP")

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
    user = None
    password = None
    err_msg = list()

    input_conf = json.loads(six.moves.builtins.open(ApData.zap.get_testcase_configuration("test_Optics_Laser_Status/input_conf_file"), 'r').read())
    gnmi_input_conf = json.loads(six.moves.builtins.open(ApData.zap.get_testcase_configuration("test_Optics_Laser_Status/gnmi_input_conf_file"), 'r').read())
    gnmi_conn = GnmiConnection(target=ApData.svr_addr, port=ApData.gnmi_port_addr)
    stub = gnmi_conn.stub

    log.info('Performing SET-REPLACE Request to target \n')
    try:
        if 'PORT_INTF' in gnmi_input_conf:
            set_info = gnmi_input_conf['PORT_INTF']['config']
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            reply = gnmiTestLib._set(stub, paths, 'replace', user, password, set_info)
            log.info(str(reply))
            if ('response' in str(reply) and 'op: REPLACE' in str(reply)):
                log.info("test_Get_with_prefix:Passed - was able to do SET-REPLACE with input json")
            else:
                log.info("test_Get_with_prefix:Failed - was unable to do SET-REPLACE with input json")
            
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
                        log.info("Laser Status is {} for slot_num {}".format(item.split()[1],slot_num))
                    else:
                        log.error("Laser Status is {} for slot_num {}".format(item.split()[1],slot_num))
            else:
                log.error("Port Status not present in the output : {}".format(reply.decode()))
    
    if len(err_msg) != 0:
        log.error("test_Optics_Laser_Status failed due to : {}".format(*err_msg))
        pytest.fail("test_Optics_Laser_Status failed due to : {}".format(*err_msg))
    else:
        log.info("test_Optics_Laser_Status Passed")


def _test_Optics_Reset_All():
    #Initially Create Multiple Interfaces/Ports to be used in below test
    if infTestLib.create_intf():
        log.info("Opt_ResetAll_1_1:Passed - Needed Interfaces for this TC have been created ")
    else:
        log.error("Opt_ResetAll_1_1:Failed - Unable to Proceed Test as unable to create required Interfaces for this TC")
    cmd = "sudo /usr/cisco/godiva/optics/opticsd -reset all\n"
    reply1 = commonLib.node_get(ApData.svr_addr, ApData.uname, ApData.pwd, cmd)
    op = reply1.decode()
    op = op.splitlines()
    data = [i for i in op if "cisco@godiva" not in i and cmd not in i]
    lsr_up = {}
    no_lsr = "No optics present"
    #Currently RESET behavior/data output is unknown as outlined in #545
    #The below needs to be modified after #545 is fixed
    #Would need below Output to be verified against Expected Output/JSON
    for item in data[4:]:
        print(item)
    #    if (no_lsr not in item) and (item.split()[1] == "OK"):
    #        lsr_up[item.split()[0]] = item.split()[1]
    log.info("Opt_ResetAll_1_2_1:Below is Status after RESET ALL w/LASER ON all Intfs/Ports")
    #if ResetAll_OP in ExpctdOutput:
    #    log.info("Opt_ResetAll_1_2:Passed - Reset-ALL output matches Expected Output ")
    #else:
    #    log.error("Opt_ResetAll_1_2:Failed - Reset-ALL output does not match Expected Output")
    #print(lsr_up)
    # Now bring down couple of Interfaces and Reissue Reset-ALL and Verify
    if infTestLib.intf_oper('eth-1/1/0', 'enabled', False):
        log.info("Opt_ResetAll_1_2:Passed - Needed Interfaces for this TC have been brought DOWN ")
    else:
        log.error("Opt_ResetAll_1_2:Failed - Unable to Proceed Test as required Interfaces for this TC are not DOWN")    
    #Now execute and verify the output of Optics RESET ALL again
    reply2 = commonLib.node_get(ApData.svr_addr, ApData.uname, ApData.pwd, cmd)
    op = reply2.decode()
    op = op.splitlines()
    data = [i for i in op if "cisco@godiva" not in i and cmd not in i]
    lsr_up = {}
    no_lsr = "No optics present"
    #Currently RESET behavior/data output is unknown as outlined in #545
    #The below needs to be modified after #545 is fixed
    #Would need below Output to be verified against Expected Output/JSON
    for item in data[4:]:
        print(item)
    #    if (no_lsr not in item) and (item.split()[1] == "OK"):
    #        lsr_up[item.split()[0]] = item.split()[1]
    log.info("Opt_ResetAll_1_3_1:Below is Status after RESET ALL w/LASER ON all Intfs/Ports")
    #if ResetAll_OP in ExpctdOutput:
    #    log.info("Opt_ResetAll_1_3:Passed - Reset-ALL output matches Expected Output ")
    #else:
    #    log.error("Opt_ResetAll_1_3:Failed - Reset-ALL output does not match Expected Output")    



def _test_Optics_Reset_Port():
    #Initially Create Multiple Interfaces/Ports to be used in below test
    if infTestLib.create_intf():
        log.info("Opt_ResetPort_1_1:Passed - Needed Interfaces for this TC have been created ")
    else:
        log.error("Opt_ResetPort_1_1:Failed - Unable to Proceed Test as unable to create required Interfaces for this TC")
    prtnum = 2
    cmd = "sudo /usr/cisco/godiva/optics/opticsd -reset " + str(prtnum) + "\n"
    reply1 = commonLib.node_get(ApData.svr_addr, ApData.uname, ApData.pwd, cmd)
    op = reply1.decode()
    op = op.splitlines()
    data = [i for i in op if "cisco@godiva" not in i and cmd not in i]
    lsr_up = {}
    no_lsr = "No optics present"
    #Currently RESET behavior/data output is unknown as outlined in #545
    #The below needs to be modified after #545 is fixed
    #Would need below Output to be verified against Expected Output/JSON
    for item in data[4:]:
        print(item)
    #    if (no_lsr not in item) and (item.split()[1] == "OK"):
    #        lsr_up[item.split()[0]] = item.split()[1]
    log.info("Opt_ResetAll_1_2_1:Below is Status after RESET of Port 2 w/LASER ON")
    #if ResetAll_OP in ExpctdOutput:
    #    log.info("Opt_ResetPort_1_2:Passed - Reset-Port 2 output matches Expected Output ")
    #else:
    #    log.error("Opt_ResetPort_1_2:Failed - Reset-Port 2 output does not match Expected Output")
    #print(lsr_up)
    # Now bring down an Interfaces and Reissue Reset-Port and Verify
    if infTestLib.intf_oper('eth-1/1/0', 'enabled', False):
        log.info("Opt_ResetPort_1_2:Passed - Needed Interfaces for this TC have been brought DOWN ")
    else:
        log.error("Opt_ResetPort_1_2:Failed - Unable to Proceed Test as required Interfaces for this TC are not DOWN")    
    #Now execute and verify the output of Optics RESET PORT again
    #RESET will be issued for Port 1 (in DOWN state) and Port 2 (in UP state)
    reply2 = commonLib.node_get(ApData.svr_addr, ApData.uname, ApData.pwd, cmd)
    op = reply2.decode()
    print(cmd)
    prtnum = 1
    cmd = "sudo /usr/cisco/godiva/optics/opticsd -reset " + str(prtnum) + "\n"
    print(cmd)
    reply3 = commonLib.node_get(ApData.svr_addr, ApData.uname, ApData.pwd, cmd)
    op = reply3.decode()
    op = op.splitlines()
    data = [i for i in op if "cisco@godiva" not in i and cmd not in i]
    lsr_up = {}
    no_lsr = "No optics present"
    #Currently RESET behavior/data output is unknown as outlined in #545
    #The below needs to be modified after #545 is fixed
    #Would need below Output to be verified against Expected Output/JSON
    for item in data[4:]:
        print(item)
    #    if (no_lsr not in item) and (item.split()[1] == "OK"):
    #        lsr_up[item.split()[0]] = item.split()[1]
    log.info("Opt_ResetPort_1_3:Below is Status after RESET of Ports 1(LASER OFF) & 2(LASER ON) ")
    #if ResetAll_OP in ExpctdOutput:
    #    log.info("Opt_ResetAll_1_3:Passed - Reset-ALL output matches Expected Output ")
    #else:
    #    log.error("Opt_ResetAll_1_3:Failed - Reset-ALL output does not match Expected Output")


def _test_Optics_Monitor_Port():
    #Initially Create Multiple Interfaces/Ports to be used in below test
    if infTestLib.create_intf():
        log.info("Opt_MonitorPort_1_1:Passed - Needed Interfaces for this TC have been created ")
    else:
        log.error("Opt_MonitorPort_1_1:Failed - Unable to Proceed Test as unable to create required Interfaces for this TC")
    prtnum = 2
    cmd = "sudo /usr/cisco/godiva/optics/opticsd -monitor " + str(prtnum) + " >> MntrPrt2.log & \n"
    print(cmd)
    reply1 = commonLib.node_get(ApData.svr_addr, ApData.uname, ApData.pwd, cmd)
    op = reply1.decode()
    op = op.splitlines()
    data = [i for i in op if "cisco@godiva" not in i and cmd not in i]
    lsr_up = {}
    #Currently MONITOR behavior/data output is unknown as outlined in #547
    #The below needs to be modified after #547 is fixed
    #Would need to check if MntrPrt2.log is recording the output
    log.info("Opt_MonitorPort_1_1:Below is Status after Monitor of Port 2 w/LASER ON")
    #if ResetAll_OP in ExpctdOutput:
    #    log.info("Opt_MonitorPort_1_2:Passed - Monitor-Port 2 is logging data ")
    #else:
    #    log.error("Opt_MonitorPort_1_2:Failed - Monitor-Port 2 is not logging data")
    # Now bring down an Interfaces to trigger Monitor-Port events
    if infTestLib.intf_oper('eth-1/1/0', 'enabled', False):
        log.info("Opt_MonitorPort_1_3:Passed - Needed Interfaces for this TC have been brought DOWN ")
    else:
        log.error("Opt_MonitorPort_1_3:Failed - Unable to Proceed Test as required Interfaces for this TC are not DOWN")    
    #Now fetch the log with the output of Optics MONITOR PORT and kill the monitor process
    cmd = "ps -aef | grep 'sudo /usr/cisco/godiva/optics/opticsd' \n"
    cmd = "ps -aef | grep opticsd \n"
    #cmd = "gtpid = $!"
    reply1 = commonLib.node_get(ApData.svr_addr, ApData.uname, ApData.pwd, cmd)
    psid = [i for i in op if "grep" not in i and "sudo" in i]
    #cmd = "sudo kill -9 " + str(psid) + "\n"
    #Also fetch the Monitor Log - MntrPrt2.log


def _test_Optics_Eeprom_All():
    cmd = "sudo /usr/cisco/godiva/optics/opticsd -eeprom all\n"
    reply = commonLib.node_get(ApData.svr_addr, ApData.uname, ApData.pwd, cmd)
    log.info(reply.decode())
    op = reply.decode()
    op = op.splitlines()

    #The below 2 lines need to be commented out for TH3 runs
    #with open ("data-files/mock-eeprom.txt", "r") as myfile:
    #    op=myfile.readlines()

    data = []
    edict = {}
    newprt = False
    for line in op:
        if 'EEPROM INFO:' in line:                
            for line in op:
                if (line.startswith("Port")):
                    newprt = True
                    edict['name'] = line.split("\n")[0]
                    continue
                if newprt:
                    pinf = line.split(":")
                    edict[pinf[0]] = pinf[1].split("\n")[0]
                    if (pinf[0] == "Vendor Date"):
                        data.append(edict)
                        edict = {}
                        newprt = False

    log.info("Opt_Eeprom_1_1:Below is EEPROM ALL data from the target")
    print(data)

    input_conf = json.loads(six.moves.builtins.open(ApData.zap.get_testcase_configuration("test_Optics_Laser_Status/gnmi_input_conf_file"), 'r').read())
    try:
        if 'EEPROM_TH4' in input_conf:
            vrfy_info = input_conf['EEPROM_TH4']['PORTS']
            log.info("Input EEPROM Info to compare \n")
            print(vrfy_info)
            data,vrfy_info = [sorted(l, key=itemgetter('name')) for l in (data, vrfy_info)]
            cmb = zip(data, vrfy_info)
            if any(x != y for x, y in cmb):
                log.info("Opt_Eeprom_1_2:Passed - EEPROM Info from Target matches Input ")
            else:
                [(x, y) for x, y in cmb if x != y]
                log.error("Opt_Eeprom_1_2:Failed - EEPROM Info from Target does not match Input ")


    except KeyboardInterrupt:
        log.info("Shutting down.")
        err_msg.append("Opt_Eeprom_1_2:Failed - Unable to get EEPROM Values from Input json for comparison")




def _test_Optics_Eeprom_Port():
    prt_lst = []
    input_conf = json.loads(six.moves.builtins.open(ApData.zap.get_testcase_configuration("test_Optics_Laser_Status/gnmi_input_conf_file"), 'r').read())
    if 'EEPROM_TH4_PORT' in input_conf:
        vrfy_info = input_conf['EEPROM_TH4_PORT']['PORTS']
        log.info("Input EEPROM Info to compare \n")
        print(vrfy_info)
        for i in vrfy_info:
            prt_lst.append(i['name'].split(" ")[1])
        print(prt_lst)

    data = []
    for i in prt_lst:
        cmd = "sudo /usr/cisco/godiva/optics/opticsd -eeprom " + i + "\n"
        reply = commonLib.node_get(ApData.svr_addr, ApData.uname, ApData.pwd, cmd)
        log.info(reply.decode())
        op = reply.decode()
        op = op.splitlines()

        edict = {}
        for line in op:
            if 'EEPROM INFO:' in line:                
                for line in op:
                    if (line.startswith("Port")):
                        edict['name'] = line.split("\n")[0]
                        continue
                    pinf = line.split(":")
                    edict[pinf[0]] = pinf[1].split("\n")[0]
                    if (pinf[0] == "Vendor Date"):
                        data.append(edict)
                        break

    #Print EEPROM info obtained from Target for the various input Ports
    log.info(data)

    #Now Compare the outputs of EEPROM data of Ports with the info present in Input json
    data,vrfy_info = [sorted(l, key=itemgetter('name')) for l in (data, vrfy_info)]
    cmb = zip(data, vrfy_info)
    if any(x != y for x, y in cmb):
        log.info("Opt_Eeprom_Prt_1_1:Passed - EEPROM Info for Ports from Target matches Input ")
    else:
        [(x, y) for x, y in cmb if x != y]
        log.error("Opt_Eeprom_Prt_1_1:Failed - EEPROM Info for Ports from Target does not match Input ")




def _test_Flap_Intf_LS():
    user = None
    password = None
    err_msg = list()

    input_conf = json.loads(six.moves.builtins.open(ApData.zap.get_testcase_configuration("test_Optics_Laser_Status/input_conf_file"), 'r').read())
    gnmi_input_conf = json.loads(six.moves.builtins.open(ApData.zap.get_testcase_configuration("test_Optics_Laser_Status/gnmi_input_conf_file"), 'r').read())
    gnmi_conn = GnmiConnection(target=ApData.svr_addr, port=ApData.gnmi_port_addr)
    stub = gnmi_conn.stub

    log.info('Performing SET-REPLACE Request to target \n')
    try:
        if 'PORT_INTF' in gnmi_input_conf:
            set_info = gnmi_input_conf['PORT_INTF']['config']
            xpath = "/"
            paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
            reply = gnmiTestLib._set(stub, paths, 'replace', user, password, set_info)
            log.info(str(reply))
            if ('response' in str(reply) and 'op: REPLACE' in str(reply)):
                log.info("test_Get_with_prefix:Passed - was able to do SET-REPLACE with input json")
            else:
                log.info("test_Get_with_prefix:Failed - was unable to do SET-REPLACE with input json")
            
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
                        log.info("Laser Status is {} for slot_num {}".format(item.split()[1],slot_num))
                    else:
                        log.error("Laser Status is {} for slot_num {}".format(item.split()[1],slot_num))
            else:
                log.error("Port Status not present in the output : {}".format(reply.decode()))

    try:
        if 'FLAP_INTF_DOWN' in gnmi_input_conf:
            set_info = gnmi_input_conf['FLAP_INTF_DOWN']['config']
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
                #resp_dict = gnmiTestLib.get_response_dict(msg_dict)
                #for cfg in verify_sec['config']:
                #    result = gnmiTestLib.verify_get_response(resp_dict,set_info,cfg)
                #    err_msg = result['err_msg'] + err_msg
    
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        err_msg.append("test_Get_with_prefix failed due to Grpc Error {err}".format(err=e.details()))

    index = None
    if 'FLAP_INTF_DOWN' in input_conf:
        slot_list = input_conf['FLAP_INTF_DOWN']['SLOT_LIST']
        verify_status_list = input_conf['FLAP_INTF_DOWN']['VERIFY']['Status']
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
                        log.info("Laser Status is {} for slot_num {}".format(item.split()[1],slot_num))
                    else:
                        log.error("Laser Status is {} for slot_num {}".format(item.split()[1],slot_num))
            else:
                log.error("Port Status not present in the output : {}".format(reply.decode()))
    
    try:
        if 'FLAP_INTF_UP' in gnmi_input_conf:
            set_info = gnmi_input_conf['FLAP_INTF_UP']['config']
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
                #resp_dict = gnmiTestLib.get_response_dict(msg_dict)
                #for cfg in verify_sec['config']:
                #    result = gnmiTestLib.verify_get_response(resp_dict,set_info,cfg)
                #    err_msg = result['err_msg'] + err_msg
    
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        err_msg.append("test_Get_with_prefix failed due to Grpc Error {err}".format(err=e.details()))

    index = None
    if 'FLAP_INTF_UP' in input_conf:
        slot_list = input_conf['FLAP_INTF_UP']['SLOT_LIST']
        verify_status_list = input_conf['FLAP_INTF_UP']['VERIFY']['Status']
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
                        log.info("Laser Status is {} for slot_num {}".format(item.split()[1],slot_num))
                    else:
                        log.error("Laser Status is {} for slot_num {}".format(item.split()[1],slot_num))
            else:
                log.error("Port Status not present in the output : {}".format(reply.decode()))

    if len(err_msg) != 0:
        log.error("test_Optics_Laser_Status failed due to : {}".format(*err_msg))
        pytest.fail("test_Optics_Laser_Status failed due to : {}".format(*err_msg))
    else:
        log.info("test_Optics_Laser_Status Passed")