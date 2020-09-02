#!/usr/bin/env python3
import argparse
import grpc
import os
import sys
import json
import multiprocessing
from multiprocessing import Pool, TimeoutError
from time import sleep
from topology.topo_mgr.topo_mgr import Topology
from framework.pytest.cafy import Cafy, CafyTest
import pytest
from logger.cafylog import CafyLog
from topology.zap.zap import Zap
from utils.helper import Helper
from utils.cafyexception import CafyException
from p4_base_ap import ApData, P4ApBase
import marshal
import google.protobuf.json_format

log = CafyLog(name='APG & APM')

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
# sys.path.append(
#    os.path.join(os.path.dirname(os.path.abspath(__file__)),
#                 '../../utils/'))

# Add 3rd party python packages' paths (instead of setting PYTHONPATH)
TP_DIR = "./../../godiva-test/lib"
tp_dirs = os.listdir(TP_DIR)
for tp_dir in tp_dirs:
    sys.path.append(os.path.join(TP_DIR,tp_dir))

import p4_switch
from p4.v1 import p4runtime_pb2
from p4.v1 import p4runtime_pb2_grpc
from p4_error_utils import printGrpcError
from p4_error_utils import parseGrpcError
import p4_info_helper
import p4_test_lib as p4TestLib
import tc_helper_lib as TchLib

SWITCH_TO_HOST_PORT = 1
SWITCH_TO_SWITCH_PORT = 2

def _test_action_profile_groups(self,mode,sw_conn):
    log.info("Test: Action profile Groups")
    err_msg = list()
    tData = ApData.zap.get_testcase_configuration("test_action_profile_groups")
    p4info_helper = p4_info_helper.P4InfoHelper(ApData.p4info)
    with open(tData["input_conf_file"], 'r') as ip_conf_file:
        input_conf = p4TestLib.json_load_byteified(ip_conf_file)

    try:
        sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
        sw_conn.MasterArbitrationUpdate()
        # Create Members
        if 'INSERT' in mode:
            if 'member_entries' in input_conf:
                members = input_conf['member_entries']
                log.info("{mode} {num} members ...".format(num=len(members),mode=mode.upper()))
                for entry in members:
                    log.info("{mode} a member ".format(mode=mode.upper()))
                    p4TestLib.memberActions(sw_conn,entry,p4info_helper, mode)
                    member_id = entry["member_id"]
                    reply = sw_conn.ReadActionProfileMember(member_id=member_id)
                    for rep in reply:
                        log.info(p4TestLib.repr_pretty_p4runtime(rep))

        # Create Groups.
        if 'group_entries' in input_conf:
            group_entries = input_conf['group_entries']
            insrt_entrs = [x for x in group_entries if x['entry_oper'] == mode]
            log.info("{mode} {num} group entries...".format(num=len(insrt_entrs),mode=mode.upper()))
            for entry in insrt_entrs:
                log.info("{mode} a Group ".format(mode=mode.upper()))
                p4TestLib.groupActions(sw_conn,entry,p4info_helper, mode)
                group_id = entry["group_id"]
                if ('DELETE' not in mode):
                    reply = sw_conn.ReadActionProfileGroup(group_id=group_id)
                    for rep in reply:
                        log.info("Reply from DUT: %s" % rep)
                        log.info(p4TestLib.repr_pretty_p4runtime(rep))
        
        if 'DELETE' in mode:
            log.info("Delete members after group is deleted")            
            if 'member_entries' in input_conf:
                members = input_conf['member_entries']
                log.info("{mode} {num} members ...".format(num=len(members),mode=mode.upper()))
                for entry in members:
                    log.info("{mode} a member ".format(mode=mode.upper()))
                    p4TestLib.memberActions(sw_conn,entry,p4info_helper, mode)

    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error(e)
        printGrpcError(e)
        err_msg.append("Test failed due to Grpc Error {err}".format(err=e.details()))
    finally:
        sw_conn.shutdown()
        if not len(err_msg) == 0:
            pytest.fail("Test_action_profile_groups failed due to {}".format(err_msg))

def _test_batched_read_apg_apm(self,sw_conn):
    log.info("Test: batched read of Action profile Groups and Action profile group members")
    err_msg = list()
    tData = ApData.zap.get_testcase_configuration("test_action_profile_groups")
    p4info_helper = p4_info_helper.P4InfoHelper(ApData.p4info)
    with open(tData["input_conf_file"], 'r') as ip_conf_file:
        input_conf = p4TestLib.json_load_byteified(ip_conf_file)

    try:
        sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
        sw_conn.MasterArbitrationUpdate()
        mode = "INSERT"
        # Create Members
        if 'INSERT' in mode:
            if 'member_entries' in input_conf:
                members = input_conf['member_entries']
                log.info("{mode} {num} members ...".format(num=len(members),mode=mode.upper()))
                for entry in members:
                    log.info("{mode} a member ".format(mode=mode.upper()))
                    p4TestLib.memberActions(sw_conn,entry,p4info_helper, mode)
                    member_id = entry["member_id"]
                    reply = sw_conn.ReadActionProfileMember(member_id=member_id)
                    for rep in reply:
                        log.info(p4TestLib.repr_pretty_p4runtime(rep))

        # Create Groups.
        if 'group_entries' in input_conf:
            group_entries = input_conf['group_entries']
            insrt_entrs = [x for x in group_entries if x['entry_oper'] == mode]
            log.info("{mode} {num} group entries...".format(num=len(insrt_entrs),mode=mode.upper()))
            for entry in insrt_entrs:
                log.info("{mode} a Group ".format(mode=mode.upper()))
                p4TestLib.groupActions(sw_conn,entry,p4info_helper, mode)
                group_id = entry["group_id"]
                if ('DELETE' not in mode):
                    reply = sw_conn.ReadActionProfileGroup(group_id=group_id)
                    for rep in reply:
                        log.info("Reply from DUT: %s" % rep)
                        log.info(p4TestLib.repr_pretty_p4runtime(rep))
        
        reply = sw_conn.BatchedReadMemberGroup(member_id=member_id,group_id=group_id)
        for rep in reply:
            #log.info("Reply from DUT: %s" % rep)
            resp = p4TestLib.repr_pretty_p4runtime(rep)
            log.info(resp)
            if 'member_id: {}'.format(member_id) in resp and 'group_id: {}'.format(group_id) in resp:
                log.info("Batched read is successful")
            else:
                log.error("Either group or member is missing from Batched read")
                err_msg.append("Either group or member is missing from Batched read")

        #sleep(5)
        #reply = sw_conn.listen()
        #log.info(reply)

        # Incorrect member id 
        reply = sw_conn.BatchedReadMemberGroup(member_id=1001,group_id=group_id)
        for rep in reply:
            #log.info("Reply from DUT: %s" % rep)
            resp = p4TestLib.repr_pretty_p4runtime(rep)
            log.info(resp)
            if 'member_id: {}'.format(member_id) not in resp and 'group_id: {}'.format(group_id) in resp:
                log.info("Test test_batched_read_apg_apm - Neg TC 1: Batched read is successful")
            else:
                log.error("Test test_batched_read_apg_apm - Neg TC 1: group  is missing from Batched read")
                err_msg.append("Test test_batched_read_apg_apm - Neg TC 1: group  is missing from Batched read")

        # Incorrect group id
        reply = sw_conn.BatchedReadMemberGroup(member_id=member_id,group_id=1001)
        for rep in reply:
            #log.info("Reply from DUT: %s" % rep)
            resp = p4TestLib.repr_pretty_p4runtime(rep)
            log.info(resp)
            if 'member_id: {}'.format(member_id) in resp and 'group_id: {}'.format(group_id) not in resp:
                log.info("Test test_batched_read_apg_apm - Neg TC 2: Batched read is successful")
            else:
                log.error("Test test_batched_read_apg_apm - Neg TC 2: member is missing from Batched read")
                err_msg.append("Test test_batched_read_apg_apm - Neg TC 2: member is missing from Batched read")

        try:
            reply = sw_conn.InvlBatchedReadMemberGroup(member_id=member_id,group_id=1001)
            for rep in reply:
                #log.info("Reply from DUT: %s" % rep)
                resp = p4TestLib.repr_pretty_p4runtime(rep)
                log.info(resp)
        except grpc.RpcError as e_det:
            log.error("### GRPC ERROR RECEIVED:: ###")
            log.error(e_det)
            if ("StatusCode.UNKNOWN" in str(e_det)) and ("Incorrect entity type" in str(e_det)):
                log.info("Test test_batched_read_apg_apm - Neg TC 3 :Passed - received correct error message on trying to read with an invalid request")
            else:
                err_msg.append("Test test_batched_read_apg_apm - Neg TC 3 :Passed - received correct error message on trying to read with an invalid request")

        mode = 'DELETE'
        if 'DELETE' in mode:
            if 'group_entries' in input_conf:
                group_entries = input_conf['group_entries']
                insrt_entrs = [x for x in group_entries if x['entry_oper'] == mode]
                log.info("{mode} {num} group entries...".format(num=len(insrt_entrs),mode=mode.upper()))
                for entry in insrt_entrs:
                    log.info("{mode} a Group ".format(mode=mode.upper()))
                    p4TestLib.groupActions(sw_conn,entry,p4info_helper, mode)
                    group_id = entry["group_id"]
                        
            log.info("Delete members after group is deleted")            
            if 'member_entries' in input_conf:
                members = input_conf['member_entries']
                log.info("{mode} {num} members ...".format(num=len(members),mode=mode.upper()))
                for entry in members:
                    log.info("{mode} a member ".format(mode=mode.upper()))
                    p4TestLib.memberActions(sw_conn,entry,p4info_helper, mode)

    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error(e)
        printGrpcError(e)
        err_msg.append("Test failed due to Grpc Error {err}".format(err=e.details()))
    finally:
        sw_conn.shutdown()
        if not len(err_msg) == 0:
            pytest.fail("Test_action_profile_groups failed due to {}".format(err_msg))


def _test_negative_action_profile_groups_1(self,sw_conn):
    err_msg = list()
    log.info("Negative Test-1: Action profile Groups - Groups with Invalid Action Profile Id")
    tData = ApData.zap.get_testcase_configuration("test_action_profile_groups")
    p4info_helper = p4_info_helper.P4InfoHelper(ApData.p4info)
    with open(tData["input_conf_file"], 'r') as ip_conf_file:
        input_conf = p4TestLib.json_load_byteified(ip_conf_file)

    try:
        sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
        sw_conn.MasterArbitrationUpdate()
        # Create Members
        if 'NEG_APG_1' in input_conf:
            entries = input_conf['NEG_APG_1']
            insrt_entrs = [x for x in entries if x['entry_type'] == 'MEMBER']
            for entry in insrt_entrs:
                log.info("Insert a member ")
                p4TestLib.memberActions(sw_conn,entry,p4info_helper, 'INSERT')
                member_id = entry["member_id"]
                reply = sw_conn.ReadActionProfileMember(member_id=member_id)
                for rep in reply:
                    log.info(p4TestLib.repr_pretty_p4runtime(rep))

            # Create Groups.
            insrt_entrs = [x for x in entries if x['entry_type'] == 'GROUP']
            for entry in insrt_entrs:
                log.info("Insert a Group with invalid group id")
                p4TestLib.groupActions(sw_conn,entry,p4info_helper, 'INSERT')
                group_id = entry["group_id"]
                reply = sw_conn.ReadActionProfileGroup(group_id=group_id)
                for rep in reply:
                    log.info("Reply from DUT: %s" % rep)
                    log.info(p4TestLib.repr_pretty_p4runtime(rep))
                            
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        e_det = parseGrpcError(e)
        print("ERROR DETAILS::")
        print(e_det)
        for item in e_det:
            log.error(item)
            if (item['code'] == "INVALID_ARGUMENT") and (item['message'] == "Invalid P4 id"):
                log.info("Test test_negative_action_profile_groups_1:Passed - received correct error message on trying to Insert a group with Invalid Group Id")
                result = True
            else:
                err_msg.append("Test NEG_ActMem_3.2:Failed - received incorrect message on trying to o Insert a group with Invalid Group Id")
                
    finally:
        log.info("Delete members")            
        if 'NEG_APG_1' in input_conf:
            entries = input_conf['NEG_APG_1']
            insrt_entrs = [x for x in entries if x['entry_type'] == 'MEMBER']
            for entry in insrt_entrs:
                log.info("Delete a member ")
                p4TestLib.memberActions(sw_conn,entry,p4info_helper, 'DELETE')
        sw_conn.shutdown()
        if not len(err_msg) == 0:
            pytest.fail("test_negative_action_profile_groups_1 failed due to {}".format(err_msg))
        
def _test_negative_action_profile_groups_2(self,sw_conn):
    result = False
    err_msg = list()
    log.info("Negative Test-2: Action profile Groups - Groups with Group Id set to 0")
    tData = ApData.zap.get_testcase_configuration("test_action_profile_groups")
    p4info_helper = p4_info_helper.P4InfoHelper(ApData.p4info)
    with open(tData["input_conf_file"], 'r') as ip_conf_file:
        input_conf = p4TestLib.json_load_byteified(ip_conf_file)

    try:
        sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
        sw_conn.MasterArbitrationUpdate()
        # Create Members
        if 'NEG_APG_2' in input_conf:
            entries = input_conf['NEG_APG_2']
            insrt_entrs = [x for x in entries if x['entry_type'] == 'MEMBER']
            for entry in insrt_entrs:
                log.info("Insert a member ")
                p4TestLib.memberActions(sw_conn,entry,p4info_helper, 'INSERT')
                member_id = entry["member_id"]
                reply = sw_conn.ReadActionProfileMember(member_id=member_id)
                for rep in reply:
                    log.info(p4TestLib.repr_pretty_p4runtime(rep))

            # Create Groups.
            insrt_entrs = [x for x in entries if x['entry_type'] == 'GROUP']
            for entry in insrt_entrs:
                log.info("Insert a Group with invalid group id")
                p4TestLib.groupActions(sw_conn,entry,p4info_helper, 'INSERT')
                group_id = entry["group_id"]
                reply = sw_conn.ReadActionProfileGroup(group_id=group_id)
                for rep in reply:
                    log.info("Reply from DUT: %s" % rep)
                    log.info(p4TestLib.repr_pretty_p4runtime(rep))
                            
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        e_det = parseGrpcError(e)
        print("ERROR DETAILS::")
        if ('details = "Error when reading action profile entries from target"' in str(e)):
            print(str(e))
            log.error("Test:Failed - received error message while reading a group with group id = 0.")
            err_msg.append("Test:Failed - received error message while reading a group with group id = 0.")
        else:
            print(e_det)
            for item in e_det:
                log.error(item)
                if (item['code'] == "INVALID_ARGUMENT") and (item['message'] == "Invalid group id"):
                    log.info("Test test_negative_action_profile_groups_2:Passed - received correct error message on trying to Insert a group with Invalid Group Id")
                    result = True
                else:
                    err_msg.append("Test test_negative_action_profile_groups_2:Failed - received incorrect message on trying to o Insert a group with Invalid Group Id")
                    
    finally:
        if not result:
            insrt_entrs = [x for x in entries if x['entry_type'] == 'GROUP']
            for entry in insrt_entrs:
                p4TestLib.groupActions(sw_conn,entry,p4info_helper, 'DELETE')

        log.info("Delete members")            
        if 'NEG_APG_2' in input_conf:
            entries = input_conf['NEG_APG_1']
            insrt_entrs = [x for x in entries if x['entry_type'] == 'MEMBER']
            for entry in insrt_entrs:
                log.info("Delete a member ")
                p4TestLib.memberActions(sw_conn,entry,p4info_helper, 'DELETE')
        sw_conn.shutdown()
        if not len(err_msg) == 0:
            pytest.fail("test_negative_action_profile_groups_2 failed due to {}".format(err_msg))
        
def _test_negative_action_profile_groups_3(self,sw_conn):
    result = False
    err_msg = list()
    log.info("Negative Test-3: Action profile Groups - Groups with weight set to 0")
    tData = ApData.zap.get_testcase_configuration("test_action_profile_groups")
    p4info_helper = p4_info_helper.P4InfoHelper(ApData.p4info)
    with open(tData["input_conf_file"], 'r') as ip_conf_file:
        input_conf = p4TestLib.json_load_byteified(ip_conf_file)

    try:
        sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
        sw_conn.MasterArbitrationUpdate()
        # Create Members
        if 'NEG_APG_3' in input_conf:
            entries = input_conf['NEG_APG_3']
            insrt_entrs = [x for x in entries if x['entry_type'] == 'MEMBER']
            for entry in insrt_entrs:
                log.info("Insert a member ")
                p4TestLib.memberActions(sw_conn,entry,p4info_helper, 'INSERT')
                member_id = entry["member_id"]
                reply = sw_conn.ReadActionProfileMember(member_id=member_id)
                for rep in reply:
                    log.info(p4TestLib.repr_pretty_p4runtime(rep))

            # Create Groups.
            insrt_entrs = [x for x in entries if x['entry_type'] == 'GROUP']
            for entry in insrt_entrs:
                log.info("Insert a Group with invalid group id")
                p4TestLib.groupActions(sw_conn,entry,p4info_helper, 'INSERT')
                group_id = entry["group_id"]
                reply = sw_conn.ReadActionProfileGroup(group_id=group_id)
                for rep in reply:
                    log.info("Reply from DUT: %s" % rep)
                    log.info(p4TestLib.repr_pretty_p4runtime(rep))
                            
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        e_det = parseGrpcError(e)
        print("ERROR DETAILS::")
        print(e_det)
        for item in e_det:
            log.error(item)
            if (item['code'] == "INVALID_ARGUMENT") and (item['message'] == "Member weight must be a positive integer value"):
                log.info("Test test_negative_action_profile_groups_3:Passed - received correct error message on trying to insert a group with weight set to 0")
                result = True
            else:
                err_msg.append("Test test_negative_action_profile_groups_3:Failed - received incorrect message on trying to insert a group with weight set to 0")
                
    finally:
        if not result:
            insrt_entrs = [x for x in entries if x['entry_type'] == 'GROUP']
            for entry in insrt_entrs:
                p4TestLib.groupActions(sw_conn,entry,p4info_helper, 'DELETE')

        log.info("Delete members")            
        if 'NEG_APG_3' in input_conf:
            entries = input_conf['NEG_APG_3']
            insrt_entrs = [x for x in entries if x['entry_type'] == 'MEMBER']
            for entry in insrt_entrs:
                log.info("Delete a member ")
                p4TestLib.memberActions(sw_conn,entry,p4info_helper, 'DELETE')
        sw_conn.shutdown()
        if not len(err_msg) == 0:
            pytest.fail("test_negative_action_profile_groups_3 failed due to {}".format(err_msg))
        
def _test_negative_action_profile_groups_4(self,sw_conn):
    result = False
    err_msg = list()
    log.info("Negative Test-4: Action profile Groups - Groups with max_size related negative tests")
    tData = ApData.zap.get_testcase_configuration("test_action_profile_groups")
    p4info_helper = p4_info_helper.P4InfoHelper(ApData.p4info)
    with open(tData["input_conf_file"], 'r') as ip_conf_file:
        input_conf = p4TestLib.json_load_byteified(ip_conf_file)

    try:
        sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
        sw_conn.MasterArbitrationUpdate()
        # Create Members
        if 'NEG_APG_4' in input_conf:
            entries = input_conf['NEG_APG_4']
            insrt_entrs = [x for x in entries if x['entry_type'] == 'MEMBER']
            for entry in insrt_entrs:
                log.info("Insert a member ")
                p4TestLib.memberActions(sw_conn,entry,p4info_helper, 'INSERT')
                member_id = entry["member_id"]
                reply = sw_conn.ReadActionProfileMember(member_id=member_id)
                for rep in reply:
                    log.info(p4TestLib.repr_pretty_p4runtime(rep))

            # Create Groups.
            insrt_entrs = [x for x in entries if x['entry_type'] == 'GROUP']
            insrt_entrs = [x for x in insrt_entrs if x['entry_oper'] == 'INSERT']
            for entry in insrt_entrs:
                group_id = entry["group_id"]
                if group_id == 1:
                    p4TestLib.groupActions(sw_conn,entry,p4info_helper, 'INSERT')
                    reply = sw_conn.ReadActionProfileGroup(group_id=group_id)
                    for rep in reply:
                        log.info("Reply from DUT: %s" % rep)
                        log.info(p4TestLib.repr_pretty_p4runtime(rep))

            insrt_entrs = [x for x in entries if x['entry_type'] == 'GROUP']
            insrt_entrs = [x for x in insrt_entrs if x['entry_oper'] == 'MODIFY']
            for entry in insrt_entrs:
                group_id = entry["group_id"]
                if group_id == 1:
                    p4TestLib.groupActions(sw_conn,entry,p4info_helper, 'MODIFY')
                    reply = sw_conn.ReadActionProfileGroup(group_id=group_id)
                    for rep in reply:
                        log.info("Reply from DUT: %s" % rep)
                        log.info(p4TestLib.repr_pretty_p4runtime(rep))


    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        e_det = parseGrpcError(e)
        print("ERROR DETAILS::")
        print(e_det)
        for item in e_det:
            log.error(item)
            if (item['code'] == "INVALID_ARGUMENT") and (item['message'] == "Cannot change group max_size after group creation"):
                log.info("Test test_negative_action_profile_groups_4.1:Passed - received correct error message on trying to change max_size on group modify")
                result = True
            else:
                err_msg.append("Test test_negative_action_profile_groups_4.1:Failed - received incorrect message on trying to change max_size on group modify")

    result = False
    try:
        # Create Groups.
        insrt_entrs = [x for x in entries if x['entry_type'] == 'GROUP']
        insrt_entrs = [x for x in insrt_entrs if x['entry_oper'] == 'INSERT']
        for entry in insrt_entrs:
            group_id = entry["group_id"]
            if group_id == 2:
                p4TestLib.groupActions(sw_conn,entry,p4info_helper, 'INSERT')
                reply = sw_conn.ReadActionProfileGroup(group_id=group_id)
                for rep in reply:
                    log.info("Reply from DUT: %s" % rep)
                    log.info(p4TestLib.repr_pretty_p4runtime(rep))
            
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        e_det = parseGrpcError(e)
        print("ERROR DETAILS::")
        print(e_det)
        for item in e_det:
            log.error(item)
            err_msg.append(item)

    finally:
        if not result:
            insrt_entrs = [x for x in entries if x['entry_type'] == 'GROUP']
            insrt_entrs = [x for x in insrt_entrs if x['entry_oper'] == 'DELETE']
            for entry in insrt_entrs:
                p4TestLib.groupActions(sw_conn,entry,p4info_helper, 'DELETE')

        log.info("Delete members")            
        if 'NEG_APG_4' in input_conf:
            entries = input_conf['NEG_APG_3']
            insrt_entrs = [x for x in entries if x['entry_type'] == 'MEMBER']
            for entry in insrt_entrs:
                log.info("Delete a member ")
                p4TestLib.memberActions(sw_conn,entry,p4info_helper, 'DELETE')
        sw_conn.shutdown()
        if not len(err_msg) == 0:
            pytest.fail("test_negative_action_profile_groups_4 failed due to {}".format(err_msg))
        
def _test_negative_action_profile_groups_5(self,sw_conn):
    result = False
    err_msg = list()
    log.info("Negative Test-5: Action profile Groups - max_size greater than max_group_size")
    tData = ApData.zap.get_testcase_configuration("test_action_profile_groups")
    p4info_helper = p4_info_helper.P4InfoHelper(ApData.p4info)
    with open(tData["input_conf_file"], 'r') as ip_conf_file:
        input_conf = p4TestLib.json_load_byteified(ip_conf_file)

    try:
        sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
        sw_conn.MasterArbitrationUpdate()
        # Create Members
        if 'NEG_APG_5' in input_conf:
            entries = input_conf['NEG_APG_5']
            insrt_entrs = [x for x in entries if x['entry_type'] == 'MEMBER']
            for entry in insrt_entrs:
                log.info("Insert a member ")
                p4TestLib.memberActions(sw_conn,entry,p4info_helper, 'INSERT')
                member_id = entry["member_id"]
                reply = sw_conn.ReadActionProfileMember(member_id=member_id)
                for rep in reply:
                    log.info(p4TestLib.repr_pretty_p4runtime(rep))

            # Create Groups.
            insrt_entrs = [x for x in entries if x['entry_type'] == 'GROUP']
            for entry in insrt_entrs:
                log.info("Insert a Group where sum of member weights exceeds maximum group size")
                p4TestLib.groupActions(sw_conn,entry,p4info_helper, 'INSERT')
                group_id = entry["group_id"]
                reply = sw_conn.ReadActionProfileGroup(group_id=group_id)
                for rep in reply:
                    log.info("Reply from DUT: %s" % rep)
                    log.info(p4TestLib.repr_pretty_p4runtime(rep))
                            
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        e_det = parseGrpcError(e)
        print("ERROR DETAILS::")
        print(e_det)
        for item in e_det:
            log.error(item)
            if (item['code'] == "RESOURCE_EXHAUSTED") and (item['message'] == "Sum of member weights exceeds maximum group size"):
                log.info("Test test_negative_action_profile_groups_5:Passed - received correct error message on trying to set max_size greater than max_group_size")
                result = True
            else:
                err_msg.append("Test test_negative_action_profile_groups_5: Failed - received incorrect message on trying to set max_size greater than max_group_size")
                
    finally:
        if not result:
            insrt_entrs = [x for x in entries if x['entry_type'] == 'GROUP']
            for entry in insrt_entrs:
                p4TestLib.groupActions(sw_conn,entry,p4info_helper, 'DELETE')
            err_msg.append("Test test_negative_action_profile_groups_5: Failed - No GRPC Error was hit on trying to set max_size greater than max_group_size")
        log.info("Delete members")            
        if 'NEG_APG_5' in input_conf:
            entries = input_conf['NEG_APG_5']
            insrt_entrs = [x for x in entries if x['entry_type'] == 'MEMBER']
            for entry in insrt_entrs:
                log.info("Delete a member ")
                p4TestLib.memberActions(sw_conn,entry,p4info_helper, 'DELETE')
        sw_conn.shutdown()
        if not len(err_msg) == 0:
            pytest.fail("test_negative_action_profile_groups_5 failed due to {}".format(err_msg))
        

def _test_negative_action_profile_groups_6(self,sw_conn):
    result = False
    mem_result = True
    err_msg = list()
    log.info("Negative Test-6: Action profile Groups - INSERT - various failure condtions")
    tData = ApData.zap.get_testcase_configuration("test_action_profile_groups")
    p4info_helper = p4_info_helper.P4InfoHelper(ApData.p4info)
    with open(tData["input_conf_file"], 'r') as ip_conf_file:
        input_conf = p4TestLib.json_load_byteified(ip_conf_file)

    try:
        sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
        sw_conn.MasterArbitrationUpdate()
        # Create Members
        if 'NEG_APG_6' in input_conf:
            entries = input_conf['NEG_APG_6']
            insrt_entrs = [x for x in entries if x['entry_type'] == 'MEMBER']
            for entry in insrt_entrs:
                log.info("Insert a member ")
                p4TestLib.memberActions(sw_conn,entry,p4info_helper, 'INSERT')
                member_id = entry["member_id"]
                reply = sw_conn.ReadActionProfileMember(member_id=member_id)
                for rep in reply:
                    log.info(p4TestLib.repr_pretty_p4runtime(rep))

    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        mem_result = False
        e_det = parseGrpcError(e)
        for item in e_det:
            log.error(item)
            pytest.fail("Error while creating members: {}".format(item))
    
    if not mem_result:
        log.info("Delete members")            
        if 'NEG_APG_6' in input_conf:
            entries = input_conf['NEG_APG_3']
            insrt_entrs = [x for x in entries if x['entry_type'] == 'MEMBER']
            for entry in insrt_entrs:
                log.info("Delete a member ")
                p4TestLib.memberActions(sw_conn,entry,p4info_helper, 'DELETE')
        return

    try:    
        if 'NEG_APG_6' in input_conf:
            # Create Groups.
            insrt_entrs = [x for x in entries if x['entry_type'] == 'GROUP']
            for entry in insrt_entrs:
                log.info("Insert a Group")
                p4TestLib.groupActions(sw_conn,entry,p4info_helper, 'INSERT')
                group_id = entry["group_id"]
                reply = sw_conn.ReadActionProfileGroup(group_id=group_id)
                for rep in reply:
                    msg_dict = google.protobuf.json_format.MessageToDict(rep)
                    for item in msg_dict['entities']:
                        log.info(item['actionProfileGroup']['actionProfileId'])
                        log.info(item['actionProfileGroup']['groupId'])
                        log.info(item['actionProfileGroup']['maxSize'])
                    log.info("Reply from DUT: %s" % rep)
                    log.info(p4TestLib.repr_pretty_p4runtime(rep))
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        e_det = parseGrpcError(e)
        print("ERROR DETAILS::")
        print(e_det)
        for item in e_det:
            log.error(item)

    try:
        insrt_entrs = [x for x in entries if x['entry_type'] == 'GROUP']
        for entry in insrt_entrs:
            log.info("Insert same group again")
            p4TestLib.groupActions(sw_conn,entry,p4info_helper, 'INSERT')
    except grpc.RpcError as e:
        e_det = parseGrpcError(e)
        for item in e_det:
            log.error(item)
            result = True
            if (item['code'] == "ALREADY_EXISTS") and (item['message'] == "Duplicate group id: 1"):
                log.info("Test test_negative_action_profile_groups_6:Passed - ALREADY_EXISTS case verified")
            else:
                err_msg.append("Test test_negative_action_profile_groups_6: Failed - ALREADY_EXISTS case not verified")

    if not result:
        err_msg.append("Test test_negative_action_profile_groups_6: Failed - ALREADY_EXISTS case not verified - No GRPC Error hit")

    result = False
    try:
        insrt_entrs = [x for x in entries if x['entry_type'] == 'INSERT_NO_MEMBER']
        for entry in insrt_entrs:
            p4TestLib.groupActions(sw_conn,entry,p4info_helper, 'INSERT')
    except grpc.RpcError as e:
        e_det = parseGrpcError(e)
        for item in e_det:
            log.error(item)
            result = True
            if (item['code'] == "NOT_FOUND") and (item['message'] == "Member id does not exist: 2"):
                log.info("Test test_negative_action_profile_groups_6:Passed - NOT_FOUND case verified")
            else:
                err_msg.append("Test test_negative_action_profile_groups_6: Failed - NOT_FOUND case not verified")

    if not result:
        err_msg.append("Test test_negative_action_profile_groups_6: Failed - NOT_FOUND case not verified - No GRPC Error hit")

    result = False
    try:
        insrt_entrs = [x for x in entries if x['entry_type'] == 'INVALID_GROUP']
        for entry in insrt_entrs:
            log.info("Insert a Group with weight as 0")
            p4TestLib.groupActions(sw_conn,entry,p4info_helper, 'INSERT')
    except grpc.RpcError as e:
        e_det = parseGrpcError(e)
        for item in e_det:
            log.error(item)
            result = True
            if (item['code'] == "INVALID_ARGUMENT") and (item['message'] == "Member weight must be a positive integer value"):
                log.info("Test test_negative_action_profile_groups_6:Passed - received correct error message - INVALID_ARGUMENT case verified")
            else:
                err_msg.append("Test test_negative_action_profile_groups_6: Failed - received incorrect message - INVALID_ARGUMENT case not verified")

    if not result:
        err_msg.append("Test test_negative_action_profile_groups_6: Failed - INVALID_ARGUMENT case not verified - No GRPC Error hit")
                
    result = False
    insrt_entrs = [x for x in entries if x['entry_type'] == 'GROUP']
    for entry in insrt_entrs:
        p4TestLib.groupActions(sw_conn,entry,p4info_helper, 'DELETE')
    log.info("Delete members")            
    if 'NEG_APG_6' in input_conf:
        entries = input_conf['NEG_APG_6']
        insrt_entrs = [x for x in entries if x['entry_type'] == 'MEMBER']
        for entry in insrt_entrs:
            log.info("Delete a member ")
            p4TestLib.memberActions(sw_conn,entry,p4info_helper, 'DELETE')
    sw_conn.shutdown()
    if not len(err_msg) == 0:
        pytest.fail("test_negative_action_profile_groups_6 failed due to {}".format(err_msg))
    

def _test_negative_action_profile_groups_7(self,sw_conn):
    result = False
    err_msg = list()
    mem_result = True
    log.info("Negative Test-7: Action profile Groups - MODIFY - various failure condtions")
    tData = ApData.zap.get_testcase_configuration("test_action_profile_groups")
    p4info_helper = p4_info_helper.P4InfoHelper(ApData.p4info)
    with open(tData["input_conf_file"], 'r') as ip_conf_file:
        input_conf = p4TestLib.json_load_byteified(ip_conf_file)

    try:
        sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
        sw_conn.MasterArbitrationUpdate()
        # Create Members
        if 'NEG_APG_6' in input_conf:
            entries = input_conf['NEG_APG_6']
            insrt_entrs = [x for x in entries if x['entry_type'] == 'MEMBER']
            for entry in insrt_entrs:
                log.info("Insert a member ")
                p4TestLib.memberActions(sw_conn,entry,p4info_helper, 'INSERT')
                member_id = entry["member_id"]
                reply = sw_conn.ReadActionProfileMember(member_id=member_id)
                for rep in reply:
                    log.info(p4TestLib.repr_pretty_p4runtime(rep))

    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        mem_result = False
        e_det = parseGrpcError(e)
        for item in e_det:
            log.error(item)
            pytest.fail("Error while creating members: {}".format(item))
    
    if not mem_result:
        log.info("Delete members")            
        if 'NEG_APG_6' in input_conf:
            entries = input_conf['NEG_APG_3']
            insrt_entrs = [x for x in entries if x['entry_type'] == 'MEMBER']
            for entry in insrt_entrs:
                log.info("Delete a member ")
                p4TestLib.memberActions(sw_conn,entry,p4info_helper, 'DELETE')
        return

    try:    
        if 'NEG_APG_6' in input_conf:
            # Create Groups.
            insrt_entrs = [x for x in entries if x['entry_type'] == 'GROUP']
            for entry in insrt_entrs:
                log.info("Insert a Group")
                p4TestLib.groupActions(sw_conn,entry,p4info_helper, 'INSERT')
                group_id = entry["group_id"]
                reply = sw_conn.ReadActionProfileGroup(group_id=group_id)
                for rep in reply:
                    msg_dict = google.protobuf.json_format.MessageToDict(rep)
                    log.info(msg_dict)
                    log.info("Reply from DUT: %s" % rep)
                    log.info(p4TestLib.repr_pretty_p4runtime(rep))
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        e_det = parseGrpcError(e)
        print("ERROR DETAILS::")
        print(e_det)
        for item in e_det:
            log.error(item)

    try:
        insrt_entrs = [x for x in entries if x['entry_type'] == 'NO_MEMBER']
        for entry in insrt_entrs:
            p4TestLib.groupActions(sw_conn,entry,p4info_helper, 'MODIFY')
    except grpc.RpcError as e:
        e_det = parseGrpcError(e)
        for item in e_det:
            log.error(item)
            result = True
            if (item['code'] == "NOT_FOUND") and (item['message'] == "Member id does not exist: 2"):
                log.info("Test test_negative_action_profile_groups_7:Passed - NOT_FOUND case verified")
            else:
                err_msg.append("Test test_negative_action_profile_groups_7:Failed - NOT_FOUND case not verified")

    if not result:
        err_msg.append("Test test_negative_action_profile_groups_7:Failed - NOT_FOUND case not verified - No GRPC Error hit")

    result = False
    try:
        insrt_entrs = [x for x in entries if x['entry_type'] == 'INVALID_GROUP_MOD']
        for entry in insrt_entrs:
            log.info("Insert a Group with weight as 0")
            p4TestLib.groupActions(sw_conn,entry,p4info_helper, 'MODIFY')
    except grpc.RpcError as e:
        e_det = parseGrpcError(e)
        for item in e_det:
            log.error(item)
            result = True
            if (item['code'] == "INVALID_ARGUMENT") and (item['message'] == "Member weight must be a positive integer value"):
                log.info("Test test_negative_action_profile_groups_7:Passed - received correct error message - INVALID_ARGUMENT case verified")
            else:
                err_msg.append("Test test_negative_action_profile_groups_7: Failed - received incorrect message - INVALID_ARGUMENT case not verified")

    if not result:
        err_msg.append("Test test_negative_action_profile_groups_7: Failed - INVALID_ARGUMENT case not verified - No GRPC Error hit")
                
    result = False
    insrt_entrs = [x for x in entries if x['entry_type'] == 'GROUP']
    for entry in insrt_entrs:
        p4TestLib.groupActions(sw_conn,entry,p4info_helper, 'DELETE')
    log.info("Delete members")            
    if 'NEG_APG_6' in input_conf:
        entries = input_conf['NEG_APG_6']
        insrt_entrs = [x for x in entries if x['entry_type'] == 'MEMBER']
        for entry in insrt_entrs:
            log.info("Delete a member ")
            p4TestLib.memberActions(sw_conn,entry,p4info_helper, 'DELETE')
    sw_conn.shutdown()
    if not len(err_msg) == 0:
        pytest.fail("test_negative_action_profile_groups_7 failed due to {}".format(err_msg))

def _test_negative_action_profile_groups_8(self,sw_conn):
    result = False
    err_msg = list()
    mem_result = True
    log.info("Negative Test-8: Action profile Groups - DELETE - various failure condtions")
    tData = ApData.zap.get_testcase_configuration("test_action_profile_groups")
    p4info_helper = p4_info_helper.P4InfoHelper(ApData.p4info)
    with open(tData["input_conf_file"], 'r') as ip_conf_file:
        input_conf = p4TestLib.json_load_byteified(ip_conf_file)

    try:
        sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
        sw_conn.MasterArbitrationUpdate()
        # Create Members
        if 'NEG_APG_6' in input_conf:
            entries = input_conf['NEG_APG_6']
            insrt_entrs = [x for x in entries if x['entry_type'] == 'MEMBER']
            for entry in insrt_entrs:
                log.info("Insert a member ")
                p4TestLib.memberActions(sw_conn,entry,p4info_helper, 'INSERT')
                member_id = entry["member_id"]
                reply = sw_conn.ReadActionProfileMember(member_id=member_id)
                for rep in reply:
                    log.info(p4TestLib.repr_pretty_p4runtime(rep))

    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        mem_result = False
        e_det = parseGrpcError(e)
        for item in e_det:
            log.error(item)
            pytest.fail("Error while creating members: {}".format(item))
    
    if not mem_result:
        log.info("Delete members")            
        if 'NEG_APG_6' in input_conf:
            entries = input_conf['NEG_APG_3']
            insrt_entrs = [x for x in entries if x['entry_type'] == 'MEMBER']
            for entry in insrt_entrs:
                log.info("Delete a member ")
                p4TestLib.memberActions(sw_conn,entry,p4info_helper, 'DELETE')
        return

    try:    
        if 'NEG_APG_6' in input_conf:
            # Create Groups.
            insrt_entrs = [x for x in entries if x['entry_type'] == 'GROUP']
            for entry in insrt_entrs:
                log.info("Insert a Group")
                p4TestLib.groupActions(sw_conn,entry,p4info_helper, 'INSERT')
                group_id = entry["group_id"]
                reply = sw_conn.ReadActionProfileGroup(group_id=group_id)
                for rep in reply:
                    msg_dict = google.protobuf.json_format.MessageToDict(rep)
                    for item in msg_dict['entities']:
                        log.info(item['actionProfileGroup']['actionProfileId'])
                        log.info(item['actionProfileGroup']['groupId'])
                        log.info(item['actionProfileGroup']['maxSize'])
                    log.info("Reply from DUT: %s" % rep)
                    log.info(p4TestLib.repr_pretty_p4runtime(rep))
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        e_det = parseGrpcError(e)
        print("ERROR DETAILS::")
        print(e_det)
        for item in e_det:
            log.error(item)

    try:
        insrt_entrs = [x for x in entries if x['entry_type'] == 'NO_GROUP']
        for entry in insrt_entrs:
            p4TestLib.groupActions(sw_conn,entry,p4info_helper, 'DELETE')
    except grpc.RpcError as e:
        e_det = parseGrpcError(e)
        for item in e_det:
            log.info(item)
            result = True
            if (item['code'] == "NOT_FOUND") and (item['message'] == "Group id does not exist: 2"):
                log.info("Test test_negative_action_profile_groups_8:Passed - NOT_FOUND case verified")
            else:
                log.error("Test test_negative_action_profile_groups_8:Failed - NOT_FOUND case not verified")
                err_msg.append("Test test_negative_action_profile_groups_8:Failed - NOT_FOUND case not verified")

    if not result:
        err_msg.append("Test test_negative_action_profile_groups_8:Failed - NOT_FOUND case not verified - No GRPC Error hit")

    result = False
    try:
        insrt_entrs = [x for x in entries if x['entry_type'] == "TABLE"]
        for entry in insrt_entrs:
            log.info("Insert a table entry")
            p4TestLib.tableEntryActions(sw_conn, entry, p4info_helper, 'INSERT')
            sleep(1)
        
        insrt_entrs = [x for x in entries if x['entry_type'] == 'GROUP']
        for entry in insrt_entrs:
            p4TestLib.groupActions(sw_conn,entry,p4info_helper, 'DELETE')
    except grpc.RpcError as e:
        e_det = parseGrpcError(e)
        for item in e_det:
            log.info(item)
            result = True
            if (item['code'] == "FAILED_PRECONDITION") and (item['message'] == ""):
                log.info("Test test_negative_action_profile_groups_8:Passed - received correct error message - FAILED_PRECONDITION case verified")
            else:
                log.error("Test test_negative_action_profile_groups_8: Failed - received incorrect message - FAILED_PRECONDITION case not verified")
                err_msg.append("Test test_negative_action_profile_groups_8: Failed - received incorrect message - FAILED_PRECONDITION case not verified")

    if not result:
        err_msg.append("Test test_negative_action_profile_groups_8: Failed - FAILED_PRECONDITION case not verified - No GRPC Error hit")
    else:
        try:
            insrt_entrs = [x for x in entries if x['entry_type'] == 'GROUP']
            for entry in insrt_entrs:
                p4TestLib.groupActions(sw_conn,entry,p4info_helper, 'DELETE')
        except grpc.RpcError as e:
            e_det = parseGrpcError(e)
            for item in e_det:
                log.error(item)
                
    insrt_entrs = [x for x in entries if x['entry_type'] == "TABLE"]
    for entry in insrt_entrs:
        log.info("Delete table entry")
        p4TestLib.tableEntryActions(sw_conn, entry, p4info_helper, 'DELETE')
        sleep(1)
    
    log.info("Delete members")            
    if 'NEG_APG_6' in input_conf:
        entries = input_conf['NEG_APG_6']
        insrt_entrs = [x for x in entries if x['entry_type'] == 'MEMBER']
        for entry in insrt_entrs:
            log.info("Delete a member ")
            p4TestLib.memberActions(sw_conn,entry,p4info_helper, 'DELETE')
    
    sw_conn.shutdown()
    if not len(err_msg) == 0:
        pytest.fail("test_negative_action_profile_groups_7 failed due to {}".format(err_msg))

def _test_negative_action_profile_groups_9(self,sw_conn):
    err_msg = list()
    mem_result = True
    log.info("Negative Test-9: Action profile Groups - Groups with repeated members")
    tData = ApData.zap.get_testcase_configuration("test_action_profile_groups")
    p4info_helper = p4_info_helper.P4InfoHelper(ApData.p4info)
    with open(tData["input_conf_file"], 'r') as ip_conf_file:
        input_conf = p4TestLib.json_load_byteified(ip_conf_file)

    try:
        sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
        sw_conn.MasterArbitrationUpdate()
        # Create Members
        if 'NEG_APG_9' in input_conf:
            entries = input_conf['NEG_APG_9']
            insrt_entrs = [x for x in entries if x['entry_type'] == 'MEMBER']
            for entry in insrt_entrs:
                log.info("Insert a member ")
                p4TestLib.memberActions(sw_conn,entry,p4info_helper, 'INSERT')
                member_id = entry["member_id"]
                reply = sw_conn.ReadActionProfileMember(member_id=member_id)
                for rep in reply:
                    log.info(p4TestLib.repr_pretty_p4runtime(rep))

    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        mem_result = False
        e_det = parseGrpcError(e)
        for item in e_det:
            log.error(item)
            pytest.fail("Error while creating members: {}".format(item))
    
    if not mem_result:
        log.info("Delete members")            
        if 'NEG_APG_6' in input_conf:
            entries = input_conf['NEG_APG_3']
            insrt_entrs = [x for x in entries if x['entry_type'] == 'MEMBER']
            for entry in insrt_entrs:
                log.info("Delete a member ")
                p4TestLib.memberActions(sw_conn,entry,p4info_helper, 'DELETE')
        return
    
    try:
        if 'NEG_APG_9' in input_conf:
            # Create Groups.
            insrt_entrs = [x for x in entries if x['entry_type'] == 'GROUP-REPEAT-FAIL']
            for entry in insrt_entrs:
                log.info("Insert a Group with repeated members - same weight")
                p4TestLib.groupActions(sw_conn,entry,p4info_helper, 'INSERT')
                group_id = entry["group_id"]
                reply = sw_conn.ReadActionProfileGroup(group_id=group_id)
                for rep in reply:
                    log.info("Reply from DUT: %s" % rep)
                    log.info(p4TestLib.repr_pretty_p4runtime(rep))
                            
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        e_det = parseGrpcError(e)
        print("ERROR DETAILS::")
        print(e_det)
        for item in e_det:
            log.error(item)
            if (item['code'] == "INVALID_ARGUMENT") and (item['message'] == "Duplicate member id 1 for group 1, use weights instead"):
                log.info("Test test_negative_action_profile_groups_3:Passed - received correct error message on trying to insert a group with weight set to 0")
                result = True
            else:
                err_msg.append("Test test_negative_action_profile_groups_3:Failed - received incorrect message on trying to insert a group with weight set to 0")
                
    try:            
        insrt_entrs = [x for x in entries if x['entry_type'] == 'GROUP-REPEAT-FAIL']
        for entry in insrt_entrs:
            p4TestLib.groupActions(sw_conn,entry,p4info_helper, 'DELETE')
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        e_det = parseGrpcError(e)
        print("ERROR DETAILS::")
        print(e_det)
        for item in e_det:
            log.error(item)
            err_msg.append("Test test_negative_action_profile_groups_9:Failed - received error: {}".format(item))
    
    try:
        if 'NEG_APG_9' in input_conf:
            # Create Groups.
            insrt_entrs = [x for x in entries if x['entry_type'] == 'GROUP-REPEAT-PASS']
            for entry in insrt_entrs:
                log.info("Insert a Group with repeated members - different weight")
                p4TestLib.groupActions(sw_conn,entry,p4info_helper, 'INSERT')
                group_id = entry["group_id"]
                reply = sw_conn.ReadActionProfileGroup(group_id=group_id)
                for rep in reply:
                    log.info("Reply from DUT: %s" % rep)
                    log.info(p4TestLib.repr_pretty_p4runtime(rep))
                            
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        e_det = parseGrpcError(e)
        print("ERROR DETAILS::")
        print(e_det)
        for item in e_det:
            log.error(item)
            err_msg.append("Test test_negative_action_profile_groups_9:Failed - received error: {}".format(item))

    try:            
        insrt_entrs = [x for x in entries if x['entry_type'] == 'GROUP-REPEAT-PASS']
        for entry in insrt_entrs:
            p4TestLib.groupActions(sw_conn,entry,p4info_helper, 'DELETE')
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        e_det = parseGrpcError(e)
        print("ERROR DETAILS::")
        print(e_det)
        for item in e_det:
            log.error(item)
            err_msg.append("Test test_negative_action_profile_groups_9:Failed - received error: {}".format(item))


    log.info("Delete members")            
    if 'NEG_APG_9' in input_conf:
        entries = input_conf['NEG_APG_9']
        insrt_entrs = [x for x in entries if x['entry_type'] == 'MEMBER']
        for entry in insrt_entrs:
            log.info("Delete a member ")
            p4TestLib.memberActions(sw_conn,entry,p4info_helper, 'DELETE')
    sw_conn.shutdown()
    if not len(err_msg) == 0:
        pytest.fail("test_negative_action_profile_groups_9 failed due to {}".format(err_msg))
        
def _test_negative_action_profile_groups_10(self):
    p4_switch.ShutdownAllSwitchConnections()
    err_msg = list()
    log.info("Negative Test-10: Action profile Groups - Multiple controllers - Permission Denied Testcase")

    pool = Pool(processes=2)
    tData = ApData.zap.get_testcase_configuration("test_action_profile_groups")
    p4info_helper = p4_info_helper.P4InfoHelper(ApData.p4info)
    with open(tData["input_conf_file"], 'r') as ip_conf_file:
        input_conf = p4TestLib.json_load_byteified(ip_conf_file)

    try:
        sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
        sw_conn.MasterArbitrationUpdate()

        mode = "INSERT"
        if 'member_entries' in input_conf:
            members = input_conf['member_entries']
            log.info("{mode} {num} members ...".format(num=len(members),mode=mode.upper()))
            for entry in members:
                log.info("{mode} a member ".format(mode=mode.upper()))
                p4TestLib.memberActions(sw_conn,entry,p4info_helper, mode)
                member_id = entry["member_id"]
                reply = sw_conn.ReadActionProfileMember(member_id=member_id)
                for rep in reply:
                    log.info(p4TestLib.repr_pretty_p4runtime(rep))
        sw_conn.shutdown()

        results = pool.map(TchLib.blocking_apg_play,['sw1','sw2'])
        for result in results:
            name = result['sw_name']
            status = result['status']
            if "sw1" in name:
                if status:
                    log.info("Test subsection Passed: Expected Controller 1 to succeed in editing the table")
                else:
                    item = result['msg']
                    log.error(item)
                    err_msg.append("Test:Failed - Expected Controller 1 to succeed in editing the table but failed due to : \
                    {}".format(item))

            if "sw2" in name:
                status = result['status']
                if not status and 'status = StatusCode.PERMISSION_DENIED' in result['msg'] and 'details = "Not master"' in result['msg']:
                    log.info("Test test_negative_action_profile_groups_10 Passed: Expected Controller 2 to fail in adding a group due to : {msg}".format(msg=result['msg']))
                else:
                    err_msg.append("Test test_negative_action_profile_groups_10: Failed - received incorrect message - PERMISSION_DENIED case not verified")

    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
    
    if not len(err_msg) == 0:
        pytest.fail("test_negative_action_profile_groups_10 failed due to {}".format(err_msg))

def _test_action_profile_members(mode,sw_conn):
    err_msg = list()
    log.info("Test: Action profile Members")
    tData = ApData.zap.get_testcase_configuration("test_action_profile_groups")
    p4info_helper = p4_info_helper.P4InfoHelper(ApData.p4info)
    with open(tData["input_conf_file"], 'r') as ip_conf_file:
        input_conf = p4TestLib.json_load_byteified(ip_conf_file)

    p4info_helper = p4_info_helper.P4InfoHelper(ApData.p4info)
    try:       
        sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
        sw_conn.MasterArbitrationUpdate() 
        # Create Members
        if 'member_entries' in input_conf:
            members = input_conf['member_entries']
            log.info("{mode} {num} members ...".format(num=len(members),mode=mode.upper()))
            for entry in members:
                log.info("{mode} a member ".format(mode=mode.upper()))
                p4TestLib.memberActions(sw_conn,entry,p4info_helper, mode)
                member_id = entry["member_id"]
                if ('DELETE' not in mode):
                    reply = sw_conn.ReadActionProfileMember(member_id=member_id)
                    for rep in reply:
                        log.info(p4TestLib.repr_pretty_p4runtime(rep))

    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error(e)
        printGrpcError(e)
        sw_conn.shutdown()
        pytest.fail("Test failed due to Grpc Error {err}".format(err=e.details()))
    finally:
        sw_conn.shutdown()

def _test_actionMem_Neg1():
    log.info("Test: Negative Test:1 for Action profile Members with INSERT operation")
    tData = ApData.zap.get_testcase_configuration("test_actionMem_Neg1")
    p4info_helper = p4_info_helper.P4InfoHelper(ApData.p4info)
    with open(tData["input_conf_file"], 'r') as ip_conf_file:
        input_conf = p4TestLib.json_load_byteified(ip_conf_file)

    p4info_helper = p4_info_helper.P4InfoHelper(ApData.p4info)
    rslt = True 

    if 'NEG_ActMem_1' in input_conf:
        members = input_conf['NEG_ActMem_1']
        for entry in members:
            if entry["member_id"] == 32 and entry["entry_oper"] == "INSERT":
                entry_ins = entry
            elif entry["member_id"] == 32 and entry["entry_oper"] == "DUPE-INSERT":
                entry_dupe = entry
            elif entry["member_id"] == 31 and entry["entry_oper"] == "NO-ACTION":
                entry_noact = entry


    try:       
        sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
        sw_conn.MasterArbitrationUpdate() 
        # Create Members
        log.info ("NEG_ActMem_1.1: Verifying Error condition scenario of 'ALREADY_EXITS' ")
        mode = "INSERT"
        p4TestLib.memberActions(sw_conn,entry_ins,p4info_helper, mode)
        log.info ("Adding the Duplicate entry - %s", entry_dupe)
        sleep(3)
        p4TestLib.memberActions(sw_conn,entry_dupe,p4info_helper, mode)
        #log.info(str(reply))
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        e_det = parseGrpcError(e)
        print("ERROR DETAILS::")
        print(e_det)
        for item in e_det:
            if (item['code'] == "ALREADY_EXISTS") and (item['message'] == "Duplicate member id: 32"):
                log.info("Test NEG_ActMem_1.1:Passed - received correct error message on trying Duplicate Insert of Action Profile Member")
            else:
                log.error("Test NEG_ActMem_1.1:Failed - received incorrect message on Duplicate Insert")
                rslt = False
        sw_conn.shutdown()

    try:       
        sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
        sw_conn.MasterArbitrationUpdate() 
        # Create Members
        log.info ("NEG_ActMem_1.2: Verifying Error condition scenario of 'INVALID_ARGUMENT' ")
        sleep(2)
        mode = "INSERT"
        log.info ("Adding Member with No Action Specification - %s", entry_noact)
        p4TestLib.memberActions(sw_conn,entry_noact,p4info_helper, mode)
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e2:
        log.error("### GRPC ERROR RECEIVED:: ###")
        e_det = parseGrpcError(e2)
        print("ERROR DETAILS::")
        print(e_det)
        for item in e_det:
            if (item['code'] == "INVALID_ARGUMENT") and (item['message'] == ''):
                log.info("Test NEG_ActMem_1.2:Passed - received correct error message on inserting Member without Action spec")
            else:
                log.error("Test NEG_ActMem_1.2:Failed - received incorrect message on Member Insert without Action")
                rslt = False
    finally:
        mode = "DELETE"
        p4TestLib.memberActions(sw_conn,entry_ins,p4info_helper, mode)
        sw_conn.shutdown()        
        if rslt:
            log.info("Test NEG_ActMem_1:Passed - Error conditions for Action Profile Member with INSERT")
        else:
            pytest.fail("Test NEG_ActMem_1:Failed - One or More subtests Failed")


def _test_actionMem_Neg2():
    log.info("Test: Negative Test:2 for Action profile Members with MODIFY Operation")
    tData = ApData.zap.get_testcase_configuration("test_actionMem_Neg2")
    p4info_helper = p4_info_helper.P4InfoHelper(ApData.p4info)
    with open(tData["input_conf_file"], 'r') as ip_conf_file:
        input_conf = p4TestLib.json_load_byteified(ip_conf_file)

    p4info_helper = p4_info_helper.P4InfoHelper(ApData.p4info)
    rslt = True 

    if 'NEG_ActMem_2' in input_conf:
        members = input_conf['NEG_ActMem_2']
        for entry in members:
            if entry["member_id"] == 29 and entry["entry_oper"] == "MODIFY":
                entry_ins = entry
            elif entry["member_id"] == 29 and entry["entry_oper"] == "NO-ACTION":
                entry_noact = entry

    try:       
        sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
        sw_conn.MasterArbitrationUpdate() 
        # Create Members
        log.info ("NEG_ActMem_2.1: Verifying Error condition scenario of 'NOT_FOUND' ")
        mode = "MODIFY"
        p4TestLib.memberActions(sw_conn,entry_ins,p4info_helper, mode)
        #log.info(str(reply))
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        e_det = parseGrpcError(e)
        print("ERROR DETAILS::")
        print(e_det)
        for item in e_det:
            if (item['code'] == "NOT_FOUND") and (item['message'] == "Member id does not exist: 29"):
                log.info("Test NEG_ActMem_2.1:Passed - received correct error message on trying to Modify Non-Existant Member")
            else:
                log.error("Test NEG_ActMem_2.1:Failed - received incorrect message on trying to Modify Non-Existant Member")
                rslt = False
        sw_conn.shutdown()

    try:
        sw_conn.shutdown()
        sleep(2)       
        sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
        sw_conn.MasterArbitrationUpdate() 
        # Create Members
        log.info ("NEG_ActMem_2.2: Verifying Error condition scenario of 'INVALID_ARGUMENT' ")
        #First Insert the Member which will be used to validate this scenario
        mode = "INSERT"
        p4TestLib.memberActions(sw_conn,entry_ins,p4info_helper, mode)
        sleep(2)
        #Now send the Modify message without any Action Specification
        mode = "MODIFY"
        log.info ("Modifying Member with No Action Specification - %s", entry_noact)
        p4TestLib.memberActions(sw_conn,entry_noact,p4info_helper, mode)
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e2:
        log.error("### GRPC ERROR RECEIVED:: ###")
        e_det = parseGrpcError(e2)
        print("ERROR DETAILS::")
        print(e_det)
        for item in e_det:
            if (item['code'] == "INVALID_ARGUMENT") and (item['message'] == ""):
                log.info("Test NEG_ActMem_2.2:Passed - received correct error message on Modifying Member without Action spec")
            else:
                log.error("Test NEG_ActMem_2.2:Failed - received incorrect message on Member Modify without Action")
                rslt = False
    finally:
        mode = "DELETE"
        p4TestLib.memberActions(sw_conn,entry_ins,p4info_helper, mode)
        sw_conn.shutdown()
        if rslt:
            log.info("Test NEG_ActMem_2:Passed - Error conditions for Action Profile Member with MODIFY")
        else:
            pytest.fail("Test NEG_ActMem_2:Failed - One or More subtests Failed")
        


def _test_actionMem_Neg3():
    log.info("Test: Negative Test:3 for Action profile Members with DELETE Operation")
    tData = ApData.zap.get_testcase_configuration("test_actionMem_Neg3")
    p4info_helper = p4_info_helper.P4InfoHelper(ApData.p4info)
    with open(tData["input_conf_file"], 'r') as ip_conf_file:
        input_conf = p4TestLib.json_load_byteified(ip_conf_file)

    rslt = True 

    if 'NEG_ActMem_3' in input_conf:
        members = input_conf['NEG_ActMem_3']
        for entry in members:
            if "member_id" in entry and entry["member_id"] == 28:
                entry_ins = entry
            elif "group_id" in entry and entry["group_id"] == 28:
                entry_grp = entry       

    try:       
        sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
        sw_conn.MasterArbitrationUpdate() 
        # Create Members
        log.info ("NEG_ActMem_3.1: Verifying Error condition scenario of 'NOT_FOUND' ")
        mode = "DELETE"
        p4TestLib.memberActions(sw_conn,entry_ins,p4info_helper, mode)
        #log.info(str(reply))
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        e_det = parseGrpcError(e)
        print("ERROR DETAILS::")
        print(e_det)
        for item in e_det:
            if (item['code'] == "NOT_FOUND") and (item['message'] == "Member id does not exist: 28"):
                log.info("Test NEG_ActMem_3.1:Passed - received correct error message on trying to DELETE Non-Existant Member")
            else:
                log.error("Test NEG_ActMem_3.1:Failed - received incorrect message on trying to DELETE Non-Existant Member")
                rslt = False
    sw_conn.shutdown()


    try:       
        sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
        sw_conn.MasterArbitrationUpdate() 
        # Create Members
        log.info ("NEG_ActMem_3.2: Verifying Error condition scenario of 'FAILED_PRECONDITION' ")
        mode = "INSERT"
        p4TestLib.memberActions(sw_conn,entry_ins,p4info_helper, mode)
        sleep(2)
        p4TestLib.groupActions(sw_conn,entry_grp,p4info_helper, mode)
        sleep(2)
        mode = "DELETE"
        p4TestLib.memberActions(sw_conn,entry_ins,p4info_helper, mode)
        log.error("Test NEG_ActMem_3.2:Failed - GRPC Error should be received saying FAILED_PRECONDITION")
        rslt = False
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        e_det = parseGrpcError(e)
        print("ERROR DETAILS::")
        print(e_det)
        for item in e_det:
            if (item['code'] == "FAILED_PRECONDITION") and (item['message'] == "Member id does not exist: 28"):
                log.info("Test NEG_ActMem_3.2:Passed - received correct error message on trying to DELETE a member which part of a group")
            else:
                log.error("Test NEG_ActMem_3.2:Failed - received incorrect message on trying to DELETE a member which part of a group")
                rslt = False
    finally:
        mode = "DELETE"
        p4TestLib.groupActions(sw_conn,entry_grp,p4info_helper, mode)
        p4TestLib.memberActions(sw_conn,entry_ins,p4info_helper, mode)
        sw_conn.shutdown()
        if rslt:
            log.info("Test NEG_ActMem_3:Passed - Error conditions for Action Profile Member with DELETE")
        else:
            pytest.fail("Test NEG_ActMem_3:Failed - One or More subtests Failed")
