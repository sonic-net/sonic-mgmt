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
from framework.pytest.cafy import Cafy
import pytest
from logger.cafylog import CafyLog
from topology.zap.zap import Zap
from utils.helper import Helper
from utils.cafyexception import CafyException
from p4_base_ap import ApData, P4ApBase
import marshal
log = CafyLog(name='P4 Sanity script')

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
from p4_error_utils import printGrpcError
import p4_info_helper
import p4_test_lib as p4TestLib
import tc_helper_lib as TchLib

SWITCH_TO_HOST_PORT = 1
SWITCH_TO_SWITCH_PORT = 2

def _test_p4_sanity(sw_conn):

    with open(ApData.input_conf_file, 'r') as ip_conf_file:
        input_conf = p4TestLib.json_load_byteified(ip_conf_file)

    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4_info_helper.P4InfoHelper(ApData.p4info)

    try:
        sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
        sw_conn.MasterArbitrationUpdate()

        if p4info_helper != None: 
            log.info("Getting ForwardingPipelineConfig on switch")
            response = sw_conn.GetForwardingPipelineConfig(resp_typ=0)
            log.info(response)
            sleep(2)

            if 'table_entries' in input_conf:
                log.info(input_conf)
                table_entries = input_conf['table_entries']
                log.info("Inserting %d table entries..." % len(table_entries))
                for entry in table_entries:
                    log.info(p4TestLib.tableEntryToString(entry))
                    #insertTableEntry(sw_conn, entry, p4info_helper)
                    log.info("INSERTING TABLE ENTRIES")
                    p4TestLib.tableEntryActions(sw_conn, entry, p4info_helper, 'INSERT')
                    sleep(1)
                    #removeTableEntry(sw_conn, entry, p4info_helper)
                    log.info("REMOVING TABLE ENTRIES")
                    p4TestLib.tableEntryActions(sw_conn, entry, p4info_helper, 'DELETE')
                    sleep(1)
                    log.info("RE-INSERTING TABLE ENTRIES")
                    p4TestLib.tableEntryActions(sw_conn, entry, p4info_helper, 'INSERT')
                    sleep(1)
                    log.info("READING TABLE ENTRIES")
                    table_name = entry['table']
                    table_id = p4info_helper.get_id("tables", name=table_name)
                    #table_id = 0
                    reply = sw_conn.ReadTableEntries(table_id=table_id)
                    for rep in reply:
                        log.info("Reply: %s" % rep)  
                    sleep(1)

            if 'table_entries' in input_conf:
                log.info(input_conf)
                table_entries = input_conf['table_entries']
                log.info("Inserting %d table entries..." % len(table_entries))
                for entry in table_entries:
                    log.info(p4TestLib.tableEntryToString(entry))
                    #insertTableEntry(sw_conn, entry, p4info_helper)
                    #removeTableEntry(sw_conn, entry, p4info_helper)
                    log.info("REMOVING TABLE ENTRIES")
                    p4TestLib.tableEntryActions(sw_conn, entry, p4info_helper, 'DELETE')
                    sleep(1)

    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error(e)
        printGrpcError(e)
    finally:
        sw_conn.shutdown()

def _test_action_profile_members(mode,sw_conn):
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
        raise CafyException.VerificationError("Test failed due to Grpc Error {err}".format(err=e.details()))
    finally:
        sw_conn.shutdown()

def _test_action_profile_groups(mode,sw_conn):
    log.info("Test: Action profile Groups")
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
        raise CafyException.VerificationError("Test failed due to Grpc Error {err}".format(err=e.details()))
    finally:
        sw_conn.shutdown()
            

def _test_ElectionID():
    log.info("Test: Sending Different Election ID Values & Verify")
    ns1=TchLib.Establish_Switch_Conn(ApData.sw_name)
    try:
        log.info("Sending Election ID High=22 & Low=333")
        reply=ns1.MasterArbitrationUpdate(election_id_high=22, election_id_low=333)
        log.info(str(reply))
        if ((str(reply).find('low: 333') != -1) and (str(reply).find('message: "Is master"') != -1)):
            log.info("P4TEST_1:Passed - received correct message on sending different Election ID")
        else:
            log.info("P4TEST_1:Failed - Did not receive expected message on sending different Election ID")
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        raise CafyException.VerificationError("Test failed due to Grpc Error {err}".format(err=e.details()))
    finally:
        ns1.shutdown()

def _test_deviceID_ACC():
    log.info("Test: Verify changed deviceID on already connected controller")
    ns1=TchLib.Establish_Switch_Conn(ApData.sw_name)
    try:
        log.info("Sending Election ID High=22 & Low=333")
        reply=ns1.MasterArbitrationUpdate(election_id_high=22, election_id_low=333)
        log.info(str(reply))
        if ((str(reply).find('low: 333') != -1) and (str(reply).find('message: "Is master"') != -1)):
            log.info("Received correct message on sending different Election ID")
        else:
            raise CafyException.VerificationError("Test Failed - Did not receive expected message on sending different Election ID")
        log.info("Try changing the device id on an already connected controller")
        reply=ns1.MasterArbitrationUpdate(election_id_high=22, election_id_low=333,device_id=100)
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(printGrpcError(e))
        if ('status = StatusCode.FAILED_PRECONDITION' in str(e)):
            log.info("Test:Passed - received correct error message on changing the device id on an already connected controller")
        else:
            raise CafyException.VerificationError("Test:Failed - received incorrect error message on changing the device id on an already connected \
                controller")
    
    try:
        log.info("Check if the stream channel is still up")
        reply=ns1.MasterArbitrationUpdate(election_id_high=22, election_id_low=333)
        log.info(str(reply))
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as f:
        log.error("### GRPC ERROR RECEIVED: f : ###")
        log.error(f)
        raise CafyException.VerificationError("Test failed due to Grpc Error {err}".format(err=f.details()))
    finally:
        ns1.shutdown()

def _test_existing_ElectionID(sw_conn):
    try:
        log.info("Sending same Election ID High=0 & Low=1 for a different switch connection")
        sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
        sw_conn.MasterArbitrationUpdate()
        try:
            ns1=TchLib.Establish_Switch_Conn("s2")
            log.info("Sending Election ID High=0 & Low=1")
            reply=ns1.MasterArbitrationUpdate()
            log.info(str(reply))
        except KeyboardInterrupt:
            log.info("Shutting down.")
        except grpc.RpcError as e:
            log.error("### GRPC ERROR RECEIVED:: ###")
            if ('details = "Election id already exists"' in str(e)):
                log.info("Test:Passed - received correct error message on sending another switch connection with same Election ID")
            else:
                raise CafyException.VerificationError("Test:Failed - received incorrect message on sending another \
                switch connection with same Election ID")
        finally:
            ns1.shutdown()
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        printGrpcError(e)
    finally:
        ns1.shutdown()
        sw_conn.shutdown()
    

def _test_Master_change(sw_conn):
    try:
        sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
        sw_conn.MasterArbitrationUpdate()
        log.info("Creating a new switch connection")
        ns1=TchLib.Establish_Switch_Conn("s2")
        log.info("Sending with Election ID High=44 & Low=555 for new switch connection")
        reply=ns1.MasterArbitrationUpdate(election_id_high=44, election_id_low=555)
        log.info(str(reply))
        if ('message: "Is master"' in str(reply)):
            log.info("Test Passed as Master has changed")
        else:
            raise CafyException.VerificationError("Test Failed as Master has not changed")
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        printGrpcError(e)
        raise CafyException.VerificationError(e)
    finally:
        ns1.shutdown()
        sw_conn.shutdown()

def _test_max_connections():
    sw_conn = list()
    for i in range(2,17):
        try:
            sw_name = "s" + str(i)
            ns=TchLib.Establish_Switch_Conn(sw_name)
            election_id_low = i
            election_id_high = i + 100
            reply=ns.MasterArbitrationUpdate(election_id_high=election_id_high, election_id_low=election_id_low)
            log.info(reply)
            sw_conn.append(ns)
        except KeyboardInterrupt:
                log.info("Shutting down.")
        except grpc.RpcError as e:
            log.error("### GRPC ERROR RECEIVED:: ###")
            log.error(e)
            for sconn in sw_conn:
                sconn.shutdown()

            raise CafyException.VerificationError(e)

    i = i + 1
    log.info("Max 16 connections done, now lets exceed to see if we hit the error")
    try:
        sw_name = "s" + str(i)
        ns=TchLib.Establish_Switch_Conn(sw_name)
        election_id_low = i
        election_id_high = i + 100
        reply=ns.MasterArbitrationUpdate(election_id_high=election_id_high, election_id_low=election_id_low)
        log.info(reply)
    except KeyboardInterrupt:
            log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        if ('status = StatusCode.RESOURCE_EXHAUSTED' in str(e) and 'details = "Too many connections"' in str(e)):
            log.info("Test:Passed - received correct error message on exceeding the max connection limit")
        else:
            raise CafyException.VerificationError("Test:Failed - received incorrect message on exceeding the max connection limit")
    finally:
        for sconn in sw_conn:
            sconn.shutdown()

def _test_nonZero_DeviceID():
    log.info("Test: Send a Non-Zero Device-ID & Verify")
    try:
        s1 = p4_switch.SwitchConnection(
            name=ApData.sw_name,
            address=ApData.svr_addr+":"+ApData.port_addr,
            device_id=200,
            proto_dump_file=ApData.proto_dump_file)

        s1.MasterArbitrationUpdate()
        log.info("Test:Failed - Switch Connection should not be established with Non-zero Device-ID")

    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        if (str(e).find('details = "Invalid device id"') != -1):
            log.info("Test:Passed - received correct error message on sending Non-zero Device-ID")
        else:
            log.error("Test:Failed - Did not receive expected error message on sending Non-zero Device-ID")
    finally:
        s1.shutdown()

def _test_multicontrollers_blocking_tableEdit():
    p4_switch.ShutdownAllSwitchConnections()
    pool = Pool(processes=2)

    try:
        results = pool.map(TchLib.blocking_table_play,['sw1','sw2'])
        for result in results:
            name = result['sw_name']
            status = result['status']
            if "s1" in name:
                if status:
                    log.info("Test Passed: Expected Controller 1 to succeed in editing the table")
                else:
                    raise CafyException.VerificationError("Test:Failed - Expected Controller 1 to succeed in editing the table but failed due to : \
                    {msg}".format(msg=result['msg']))

            if "s2" in name:
                if not status and 'status = StatusCode.PERMISSION_DENIED' in result['msg'] and 'details = "Not master"' in result['msg']:
                    log.info("Test Passed: Expected Controller 2 to fail in editing the table due to : {msg}".format(msg=result['msg']))
                else:
                    raise CafyException.VerificationError("Test:Failed - Expected Controller 2 to fail in editing the table but was able to do so")
        
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)

def _test_multicontrollers_non_blocking_tableEdit():
    p4_switch.ShutdownAllSwitchConnections()
    pool = Pool(processes=2)

    try:
        results = pool.map(TchLib.non_blocking_table_play,['sw1','sw2'])
        for result in results:
            name = result['sw_name']
            status = result['status']
            if "s1" in name:
                if status:
                    log.info("Test Passed: Expected Controller 1 to succeed in editing the table")
                else:
                    raise CafyException.VerificationError("Test:Failed - Expected Controller 1 to succeed in editing the table but failed due to : \
                    {msg}".format(msg=result['msg']))

            if "s2" in name:
                if status:
                    log.info("Test Passed: Expected Controller 2 to read the table")
                else:
                    raise CafyException.VerificationError("Test:Failed - Expected Controller 2 to read the table but was not able to do so due to : {msg}".format(msg=result['msg']))
        
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)


def _test_setForwarding_pipeline_config():
    p4info_helper = p4_info_helper.P4InfoHelper(ApData.p4info)
    p4_json_file_path = ApData.p4json

    try:

        s1=TchLib.Establish_Switch_Conn(ApData.sw_name)
        s1.MasterArbitrationUpdate(election_id_high=22, election_id_low=333)

        if p4info_helper != None:
            # Install the P4 program on the switches
            log.info("Setting ForwardingPipelineConfig on s1")
            s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                        p4_json_file_path=p4_json_file_path)
            log.info("Installed P4 Program using SetForwardingPipelineConfig on s1")

    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error(e)
        printGrpcError(e)
    finally:
        s1.shutdown()

def _test_ingress_encapIn_ipv4_table_crudTests(self, tbl_ops,sw_conn):
    p4info_helper = p4_info_helper.P4InfoHelper(ApData.p4info)
    tbl_input_file = ApData.zap.get_testcase_configuration("test_ingress_encapIn_ipv4_table_crudTests/input_conf_file")
    with open(tbl_input_file, 'r') as conf_file:
        input_conf = p4TestLib.json_load_byteified(conf_file)
    table_name = input_conf['table_name']
    table_id = p4info_helper.get_id("tables", name=table_name)
    sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
    sw_conn.MasterArbitrationUpdate()

    if tbl_ops == "INSERT":
        try:
            if 'table_entries' in input_conf:
                log.info(input_conf)
                table_entries = input_conf['table_entries']
                insrt_entrs = [x for x in table_entries if x['entry_oper'] == "INSERT"]
                #print (insrt_entrs)
                log.info("Inserting %d table entries..." % len(insrt_entrs))
                for entry in insrt_entrs:
                    log.info(p4TestLib.tableEntryToString(entry))
                    log.info("INSERTING ENTRIES FOR TABLE - ingress_encap_in_ipv4_table")
                    p4TestLib.tableEntryActions(sw_conn, entry, p4info_helper, 'INSERT')
                    sleep(1)

        except KeyboardInterrupt:
            log.info("Shutting down.")
        except grpc.RpcError as e:
            log.error(e)
            printGrpcError(e)
            sw_conn.shutdown()

    elif tbl_ops == "READ":
        log.info("READING TABLE ENTRIES")
        try:
            reply = sw_conn.ReadTableEntries(table_id=table_id)
            for rep in reply:
                log.info(" READ Reply from DUT")
                t_entries = p4TestLib.repr_pretty_p4runtime(rep)
                log.info(t_entries)
            sleep(1)

            print ("Printing Read Entries")
            vr_lst = t_entries.split("entities")
            print(vr_lst[1])
            sleep(2)

        except KeyboardInterrupt:
            log.info("Shutting down.")
        except grpc.RpcError as e:
            log.error(e)
            printGrpcError(e)
            sw_conn.shutdown()


    elif tbl_ops == "MODIFY":
        try:
            if 'table_entries' in input_conf:
                log.info(input_conf)
                table_entries = input_conf['table_entries']
                mod_entrs = [x for x in table_entries if x['entry_oper'] == "MODIFY"]
                #print (mod_entrs)
                log.info("Modifying %d table entries..." % len(table_entries))
                for entry in mod_entrs:
                    log.info(p4TestLib.tableEntryToString(entry))
                    log.info("MODIFYING ENTRIES FOR TABLE - ingress_encap_in_ipv4_table")
                    p4TestLib.tableEntryActions(sw_conn, entry, p4info_helper, 'MODIFY')
                    sleep(1)

                log.info("Subtest: Verify Table Entries after MODIFY table - %s", table_name)
                reply = sw_conn.ReadTableEntries(table_id=table_id)
                for rep in reply:
                    log.info(" READ Reply from DUT")
                    log.info(p4TestLib.repr_pretty_p4runtime(rep))

        except KeyboardInterrupt:
            log.info("Shutting down.")
        except grpc.RpcError as e:
            log.error(e)
            printGrpcError(e)
            sw_conn.shutdown()

    elif tbl_ops == "DELETE":
        try:
            if 'table_entries' in input_conf:
                log.info(input_conf)
                table_entries = input_conf['table_entries']
                del_entrs = [x for x in table_entries if x['entry_oper'] == "INSERT"]
                log.info("Deleting %d table entries..." % len(del_entrs))
                for entry in del_entrs:
                    log.info(p4TestLib.tableEntryToString(entry))
                    log.info("DELETING ENTRIES FOR TABLE - ingress_encap_in_ipv4_table")
                    p4TestLib.tableEntryActions(sw_conn, entry, p4info_helper, 'DELETE')
                    sleep(1)

                log.info("Subtest: Verify Table Entries after DELETE table entries - %s", table_name)
                reply = sw_conn.ReadTableEntries(table_id=table_id)
                for rep in reply:
                    log.info(" READ Reply from DUT")
                    log.info(p4TestLib.repr_pretty_p4runtime(rep))

        except KeyboardInterrupt:
            log.info("Shutting down.")
        except grpc.RpcError as e:
            log.error(e)
            printGrpcError(e)
            sw_conn.shutdown()
    sw_conn.shutdown()


def _test_direct_table_crudTests(self, tbl_name, tbl_ops, sw_conn):
    sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
    sw_conn.MasterArbitrationUpdate()
    p4info_helper = p4_info_helper.P4InfoHelper(ApData.p4info)
    conf_file = "direct_table_tests/" + tbl_name + "/input_conf_file"
    tbl_input_file = ApData.zap.get_testcase_configuration(conf_file)
    with open(tbl_input_file, 'r') as conf_file:
        input_conf = p4TestLib.json_load_byteified(conf_file)
    table_id = p4info_helper.get_id("tables", name=tbl_name)

    if tbl_ops == "INSERT":
        try:
            if 'table_entries' in input_conf:
                log.info(input_conf)
                table_entries = input_conf['table_entries']
                insrt_entrs = [x for x in table_entries if x['entry_oper'] == "INSERT"]
                #print (insrt_entrs)
                log.info("Inserting %d table entries..." % len(insrt_entrs))
                for entry in insrt_entrs:
                    log.info(p4TestLib.tableEntryToString(entry))
                    log.info("INSERTING ENTRIES FOR TABLE - ingress_encap_in_ipv4_table")
                    p4TestLib.tableEntryActions(sw_conn, entry, p4info_helper, 'INSERT')
                    sleep(1)

        except KeyboardInterrupt:
            log.info("Shutting down.")
        except grpc.RpcError as e:
            log.error(e)
            printGrpcError(e)
        finally:
            sw_conn.shutdown()

    elif tbl_ops == "READ":
        log.info("READING TABLE ENTRIES")
        try:
            reply = sw_conn.ReadTableEntries(table_id=table_id)
            for rep in reply:
                log.info(" READ Reply from DUT")
                log.info(p4TestLib.repr_pretty_p4runtime(rep))
            sleep(1)

        except KeyboardInterrupt:
            log.info("Shutting down.")
        except grpc.RpcError as e:
            log.error(e)
            printGrpcError(e)
        finally:
            sw_conn.shutdown()


    elif tbl_ops == "MODIFY":
        try:
            if 'table_entries' in input_conf:
                log.info(input_conf)
                table_entries = input_conf['table_entries']
                mod_entrs = [x for x in table_entries if x['entry_oper'] == "MODIFY"]
                #print (mod_entrs)
                log.info("Modifying %d table entries..." % len(table_entries))
                for entry in mod_entrs:
                    log.info(p4TestLib.tableEntryToString(entry))
                    log.info("MODIFYING ENTRIES FOR TABLE - ingress_encap_in_ipv4_table")
                    p4TestLib.tableEntryActions(sw_conn, entry, p4info_helper, 'MODIFY')
                    sleep(1)

                log.info("Subtest: Verify Table Entries after MODIFY table - %s", tbl_name)
                reply = sw_conn.ReadTableEntries(table_id=table_id)
                for rep in reply:
                    log.info(" READ Reply from DUT")
                    log.info(p4TestLib.repr_pretty_p4runtime(rep))

        except KeyboardInterrupt:
            log.info("Shutting down.")
        except grpc.RpcError as e:
            log.error(e)
            printGrpcError(e)
        finally:
            sw_conn.shutdown()

    elif tbl_ops == "DELETE":
        try:
            if 'table_entries' in input_conf:
                log.info(input_conf)
                table_entries = input_conf['table_entries']
                del_entrs = [x for x in table_entries if x['entry_oper'] == "INSERT"]
                log.info("Deleting %d table entries..." % len(del_entrs))
                for entry in del_entrs:
                    log.info(p4TestLib.tableEntryToString(entry))
                    log.info("DELETING ENTRIES FOR TABLE - ingress_encap_in_ipv4_table")
                    p4TestLib.tableEntryActions(sw_conn, entry, p4info_helper, 'DELETE')
                    sleep(1)

                log.info("Subtest: Verify Table Entries after DELETE table entries - %s", tbl_name)
                reply = sw_conn.ReadTableEntries(table_id=table_id)
                for rep in reply:
                    log.info(" READ Reply from DUT")
                    log.info(p4TestLib.repr_pretty_p4runtime(rep))

        except KeyboardInterrupt:
            log.info("Shutting down.")
        except grpc.RpcError as e:
            log.error(e)
            printGrpcError(e)
        finally:
            sw_conn.shutdown()
    
    sw_conn.shutdown()

def _test_indirect_table_crudTests(self, tbl_name,tbl_ops,sw_conn):
    sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
    sw_conn.MasterArbitrationUpdate()

    p4info_helper = p4_info_helper.P4InfoHelper(ApData.p4info)
    conf_file = "indirect_table_tests/" + tbl_name + "/input_conf_file"
    tbl_input_file = ApData.zap.get_testcase_configuration(conf_file)
    with open(tbl_input_file, 'r') as conf_file:
        input_conf = p4TestLib.json_load_byteified(conf_file)
    table_id = p4info_helper.get_id("tables", name=tbl_name)

    if tbl_ops == "INSERT":
        TchLib.action_profile_members("INSERT",sw_conn,input_conf,p4info_helper)
        try:
            if 'table_entries' in input_conf:
                log.info(input_conf)
                table_entries = input_conf['table_entries']
                insrt_entrs = [x for x in table_entries if x['entry_oper'] == "INSERT"]
                log.info("Inserting %d table entries..." % len(insrt_entrs))
                for entry in insrt_entrs:
                    #log.info(p4TestLib.tableEntryToString(entry))
                    log.info("INSERTING ENTRIES FOR TABLE - {tbl_name}".format(tbl_name=tbl_name))
                    p4TestLib.tableEntryActions(sw_conn, entry, p4info_helper, 'INSERT')
                    sleep(1)

        except KeyboardInterrupt:
            log.info("Shutting down.")
        except grpc.RpcError as e:
            log.error(e)
            printGrpcError(e)
        finally:
            sw_conn.shutdown()

    elif tbl_ops == "READ":
        log.info("READING TABLE ENTRIES")
        try:
            reply = sw_conn.ReadTableEntries(table_id=table_id)
            for rep in reply:
                log.info(" READ Reply from DUT")
                t_entries = p4TestLib.repr_pretty_p4runtime(rep)
                log.info(t_entries)
            sleep(1)

            print ("Printing Read Entries")
            vr_lst = t_entries.split("entities")
            print(*vr_lst, sep = "\n")
            sleep(2)

        except KeyboardInterrupt:
            log.info("Shutting down.")
        except grpc.RpcError as e:
            log.error(e)
            printGrpcError(e)
        finally:
            sw_conn.shutdown()

    elif tbl_ops == "DELETE":
        
        try:
            if 'table_entries' in input_conf:
                log.info(input_conf)
                table_entries = input_conf['table_entries']
                del_entrs = [x for x in table_entries if x['entry_oper'] == "DELETE"]
                log.info("Deleting %d table entries..." % len(del_entrs))
                for entry in del_entrs:
                    #log.info(p4TestLib.tableEntryToString(entry))
                    log.info("DELETING ENTRIES FOR TABLE - {tbl_name}".format(tbl_name=tbl_name))
                    p4TestLib.tableEntryActions(sw_conn, entry, p4info_helper, 'DELETE')
                    sleep(1)

        except KeyboardInterrupt:
            log.info("Shutting down.")
        except grpc.RpcError as e:
            log.error(e)
            printGrpcError(e)
        finally:
            TchLib.action_profile_members("DELETE",sw_conn,input_conf,p4info_helper)
            sw_conn.shutdown()

    
    sw_conn.shutdown()



def _test_Read_wTableId_Zero(sw_conn):
    sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
    sw_conn.MasterArbitrationUpdate()
    p4info_helper = p4_info_helper.P4InfoHelper(ApData.p4info)
    tbl_input_file = ApData.zap.get_testcase_configuration("test_ingress_encapIn_ipv4_table_crudTests/input_conf_file")
    with open(tbl_input_file, 'r') as conf_file:
        input_conf = p4TestLib.json_load_byteified(conf_file)
    table_id = 0

    try:
        if 'table_entries' in input_conf:
            log.info(input_conf)
            table_entries = input_conf['table_entries']
            insrt_entrs = [x for x in table_entries if x['entry_oper'] == "INSERT"]
            log.info("Inserting %d table entries..." % len(insrt_entrs))
            for entry in insrt_entrs:
                log.info(p4TestLib.tableEntryToString(entry))
                log.info("INSERTING ENTRIES FOR TABLE - ingress_encap_in_ipv4_table")
                p4TestLib.tableEntryActions(sw_conn, entry, p4info_helper, 'INSERT')
                sleep(1)

    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error(e)
        printGrpcError(e)
        sw_conn.shutdown()

    log.info("READING TABLE ENTRIES with TABLE-ID ZERO")
    try:
        reply = sw_conn.ReadTableEntries(table_id=table_id)
        for rep in reply:
            log.info(" READ Reply from DUT")
            log.info(p4TestLib.repr_pretty_p4runtime(rep))
        sleep(1)

    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        sw_conn.shutdown()
        raise CafyException.VerificationError(e)
    sw_conn.shutdown()


def teardown_class(self):
    log.info("Teardown class")
    p4_switch.ShutdownAllSwitchConnections()
