#!/usr/bin/env python3
import argparse
import grpc
import os
import sys
import json
import re
import time
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
import google.protobuf.json_format

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
from p4_error_utils import parseGrpcError
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
            #response = sw_conn.GetForwardingPipelineConfig(resp_typ=0)
            #log.info(response)

            if 'table_entries' in input_conf:
                log.info(input_conf)
                table_entries = input_conf['table_entries']
                log.info("Inserting %d table entries..." % len(table_entries))
                for entry in table_entries:
                    log.info(p4TestLib.tableEntryToString(entry))
                    log.info("INSERTING TABLE ENTRIES")
                    p4TestLib.tableEntryActions(sw_conn, entry, p4info_helper, 'INSERT')
                    log.info("REMOVING TABLE ENTRIES")
                    p4TestLib.tableEntryActions(sw_conn, entry, p4info_helper, 'DELETE')
                    log.info("RE-INSERTING TABLE ENTRIES")
                    p4TestLib.tableEntryActions(sw_conn, entry, p4info_helper, 'INSERT')
                    log.info("READING TABLE ENTRIES")
                    table_name = entry['table']
                    table_id = p4info_helper.get_id("tables", name=table_name)
                    #table_id = 0
                    reply = sw_conn.ReadTableEntries(table_id=table_id)
                    for rep in reply:
                        #log.info("Reply: %s" % rep)
                        log.info(p4TestLib.repr_pretty_p4runtime(rep))
                        resp = p4TestLib.repr_pretty_p4runtime(rep)
                        entries = p4TestLib.table_entry_to_dict(resp)
                        log.info(entries)
                

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

    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error(e)
        printGrpcError(e)
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
    for i in range(1,17):
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

def _test_new_master_down():
    p4_switch.ShutdownAllSwitchConnections()
    pool = Pool(processes=2)

    try:
        results = pool.map(TchLib._master_toggle,['sw1','sw2'])
        if results:
            log.info("Test Master down passed")
        else:
            pytest.fail("Test Master down failed")
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)

def _test_multicontrollers_blocking_tableEdit():
    p4_switch.ShutdownAllSwitchConnections()
    pool = Pool(processes=2)

    try:
        results = pool.map(TchLib.blocking_table_play,['sw1','sw2'])
        for result in results:
            name = result['sw_name']
            status = result['status']
            if "sw1" in name:
                if status:
                    log.info("Test Passed: Expected Controller 1 to succeed in editing the table")
                else:
                    raise CafyException.VerificationError("Test:Failed - Expected Controller 1 to succeed in editing the table but failed due to : \
                    {msg}".format(msg=result['msg']))

            if "sw2" in name:
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
            if "sw1" in name:
                if status:
                    log.info("Test Passed: Expected Controller 1 to succeed in editing the table")
                else:
                    raise CafyException.VerificationError("Test:Failed - Expected Controller 1 to succeed in editing the table but failed due to : \
                    {msg}".format(msg=result['msg']))

            if "sw2" in name:
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
        #s1.MasterArbitrationUpdate(election_id_high=22, election_id_low=333)
        s1.MasterArbitrationUpdate(election_id_high=0, election_id_low=1)

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

def _test_table_wildcard_read_test(self, tbl_name, sw_conn):
    sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
    sw_conn.MasterArbitrationUpdate()
    p4info_helper = p4_info_helper.P4InfoHelper(ApData.p4info)
    conf_file = "table_wc_read_tests/" + tbl_name + "/input_conf_file"
    tbl_input_file = ApData.zap.get_testcase_configuration(conf_file)
    with open(tbl_input_file, 'r') as conf_file:
        input_conf = p4TestLib.json_load_byteified(conf_file)
    table_id = p4info_helper.get_id("tables", name=tbl_name)

    log.info("WILDCARD READ TEST FOR TABLE ENTRIES")
    try:
        if 'table_entries' in input_conf:
            log.info(input_conf)
            table_entries = input_conf['table_entries']
            insrt_entrs = [x for x in table_entries if x['entry_oper'] == "INSERT"]
            #print (insrt_entrs)
            log.info("Inserting %d table entries..." % len(insrt_entrs))
            for entry in insrt_entrs:
                p4TestLib.tableEntryActions(sw_conn, entry, p4info_helper, 'INSERT')
            log.info("Wildcard read for %d table entries..." % len(insrt_entrs))
            wc_read_ents = [x for x in table_entries if x['entry_oper'] == "WCREAD"]
            for entry in wc_read_ents:
                log.info(p4TestLib.tableEntryToString(entry))
                log.info("WC read: ")
                reply = p4TestLib.tableWCRead(sw_conn, entry, p4info_helper)
                if reply:
                    for rep in reply:
                        log.info(" READ Reply from DUT")
                        log.info(p4TestLib.repr_pretty_p4runtime(rep))
            log.info("Deleting p4/p4_sanity_tc.py%d table entries..." % len(insrt_entrs))
            for entry in insrt_entrs:
                p4TestLib.tableEntryActions(sw_conn, entry, p4info_helper, 'DELETE')

    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error(e)
        printGrpcError(e)
    finally:
        sw_conn.shutdown()

def _test_direct_table_batched_write_test(self, tbl_name, sw_conn):
    sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
    sw_conn.MasterArbitrationUpdate()
    p4info_helper = p4_info_helper.P4InfoHelper(ApData.p4info)
    conf_file = "dir_table_batched_write_tests/" + tbl_name + "/input_conf_file"
    tbl_input_file = ApData.zap.get_testcase_configuration(conf_file)
    with open(tbl_input_file, 'r') as conf_file:
        input_conf = p4TestLib.json_load_byteified(conf_file)
    table_id = p4info_helper.get_id("tables", name=tbl_name)

    log.info("BATCHED WRITE TEST FOR TABLE ENTRIES")
    try:
        if 'table_entries' in input_conf:
            log.info(input_conf)
            table_entries = input_conf['table_entries']
            insrt_entrs = [x for x in table_entries if x['entry_oper'] == 'INSERT']
            for ents in insrt_entrs:
                ents['operation'] = 'INSERT'

            p4TestLib.tableEntryActionsBatched(sw_conn, insrt_entrs, p4info_helper)
            reply = sw_conn.ReadTableEntries(table_id=table_id)
            for rep in reply:
                log.info(" READ Reply from DUT")
                log.info(p4TestLib.repr_pretty_p4runtime(rep))
            #sleep(1)
            log.info("Deleting p4/p4_sanity_tc.py%d table entries..." % len(insrt_entrs))
            # Delete all the added entries
            for ents in insrt_entrs:
                ents['operation'] = 'DELETE'
            p4TestLib.tableEntryActionsBatched(sw_conn, insrt_entrs, p4info_helper)

    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error(e)
        printGrpcError(e)
    finally:
        sw_conn.shutdown()

def _test_indirect_table_batched_write_test(self, tbl_name, sw_conn):
    sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
    sw_conn.MasterArbitrationUpdate()
    p4info_helper = p4_info_helper.P4InfoHelper(ApData.p4info)
    conf_file = "indir_table_batched_write_tests/" + tbl_name + "/input_conf_file"
    tbl_input_file = ApData.zap.get_testcase_configuration(conf_file)
    with open(tbl_input_file, 'r') as conf_file:
        input_conf = p4TestLib.json_load_byteified(conf_file)
    table_id = p4info_helper.get_id("tables", name=tbl_name)

    log.info("BATCHED WRITE TEST FOR TABLE ENTRIES")
    try:
        if 'member_entries' in input_conf:
            members = input_conf['member_entries']
            for entry in members:
                p4TestLib.memberActions(sw_conn,entry,p4info_helper, 'INSERT')
                member_id = entry["member_id"]

        if 'table_entries' in input_conf:
            log.info(input_conf)
            table_entries = input_conf['table_entries']
            insrt_entrs = [x for x in table_entries if x['entry_oper'] == 'INSERT']
            for ents in insrt_entrs:
                ents['operation'] = 'INSERT'

            tblInsertStart = time.time()
            p4TestLib.tableEntryActionsBatched(sw_conn, insrt_entrs, p4info_helper)
            tblInsertEnd = time.time()
            #sleep(2)
            tblReadStart = time.time()
            #reply = sw_conn.ReadTableEntries(table_id=table_id)
            reply = {}
            tblReadEnd = time.time()
            for rep in reply:
                log.info(" READ Reply from DUT")
                log.info(p4TestLib.repr_pretty_p4runtime(rep))
            log.info("Deleting %d table entries..." % len(insrt_entrs))
            # Delete all the added entries
            for ents in insrt_entrs:
                ents['operation'] = 'DELETE'
            tblDeleteStart = time.time()
            p4TestLib.tableEntryActionsBatched(sw_conn, insrt_entrs, p4info_helper)
            tblDeleteEnd = time.time()
            log.info("[Time taken] Insert time = %f, read time = %f, delete " \
                "time = %f" % (tblInsertEnd-tblInsertStart, \
                tblReadEnd - tblReadStart, tblDeleteEnd - tblDeleteStart));

        if 'member_entries' in input_conf:
            members = input_conf['member_entries']
            for entry in members:
                p4TestLib.memberActions(sw_conn,entry,p4info_helper, 'DELETE')
                member_id = entry["member_id"]

    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error(e)
        printGrpcError(e)
    finally:
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
                resp = p4TestLib.repr_pretty_p4runtime(rep)
                log.info(resp)
                entries = p4TestLib.table_entry_to_dict(resp)
                for entry in entries:
                    for key,value in entry.items():
                        log.info("{}:{}".format(key,value))

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
                    #log.info(p4TestLib.tableEntryToString(entry))
                    log.info("MODIFYING ENTRIES FOR TABLE - ingress_encap_in_ipv4_table")
                    p4TestLib.tableEntryActions(sw_conn, entry, p4info_helper, 'MODIFY')

                log.info("Subtest: Verify Table Entries after MODIFY table - %s", tbl_name)
                reply = sw_conn.ReadTableEntries(table_id=table_id)
                for rep in reply:
                    log.info(" READ Reply from DUT")
                    resp = p4TestLib.repr_pretty_p4runtime(rep)
                    log.info(resp)
                    entries = p4TestLib.table_entry_to_dict(resp)
                    for entry in entries:
                        for key,value in entry.items():
                            log.info("{}:{}".format(key,value))
                    

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

                log.info("Subtest: Verify Table Entries after DELETE table entries - %s", tbl_name)
                reply = sw_conn.ReadTableEntries(table_id=table_id)
                for rep in reply:
                    log.info(" READ Reply from DUT")
                    resp = p4TestLib.repr_pretty_p4runtime(rep)
                    log.info(resp)
                    entries = p4TestLib.table_entry_to_dict(resp)
                    for entry in entries:
                        for key,value in entry.items():
                            log.info("{}:{}".format(key,value))


        except KeyboardInterrupt:
            log.info("Shutting down.")
        except grpc.RpcError as e:
            log.error(e)
            printGrpcError(e)
        finally:
            sw_conn.shutdown()
    
    sw_conn.shutdown()

def _test_indirect_table_crudTests(self, tbl_name,tbl_ops,sw_conn):
    err_msg = list()
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
        TchLib.action_profile_groups("INSERT",sw_conn,input_conf,p4info_helper)
        try:
            if 'table_entries' in input_conf:
                log.info(input_conf)
                table_entries = input_conf['table_entries']
                insrt_entrs = [x for x in table_entries if x['entry_oper'] == "INSERT"]
                log.info("Inserting %d table entries..." % len(insrt_entrs))
                for entry in insrt_entrs:
                    log.info(p4TestLib.tableEntryToString(entry))
                    log.info("INSERTING ENTRIES FOR TABLE - {tbl_name}".format(tbl_name=tbl_name))
                    p4TestLib.tableEntryActions(sw_conn, entry, p4info_helper, 'INSERT')

        except KeyboardInterrupt:
            log.info("Shutting down.")
        except grpc.RpcError as e:
            log.error(e)
            printGrpcError(e)
            err_msg.append("test_indirect_table_crudTests - {tbl_ops} failed due to Grpc Error {err}".format(err=e.details(),tbl_ops=tbl_ops))
        finally:
            sw_conn.shutdown()

    elif tbl_ops == "MODIFY":
        TchLib.action_profile_members("MODIFY",sw_conn,input_conf,p4info_helper)
        TchLib.action_profile_groups("MODIFY",sw_conn,input_conf,p4info_helper)
        try:
            if 'table_entries' in input_conf:
                log.info(input_conf)
                table_entries = input_conf['table_entries']
                insrt_entrs = [x for x in table_entries if x['entry_oper'] == "MODIFY"]
                log.info("Modifying %d table entries..." % len(insrt_entrs))
                for entry in insrt_entrs:
                    log.info(p4TestLib.tableEntryToString(entry))
                    log.info("Modifying ENTRIES FOR TABLE - {tbl_name}".format(tbl_name=tbl_name))
                    p4TestLib.tableEntryActions(sw_conn, entry, p4info_helper, 'MODIFY')
                    sleep(1)

        except KeyboardInterrupt:
            log.info("Shutting down.")
        except grpc.RpcError as e:
            log.error(e)
            printGrpcError(e)
            err_msg.append("test_indirect_table_crudTests - {tbl_ops} failed due to Grpc Error {err}".format(err=e.details(),tbl_ops=tbl_ops))
        finally:
            sw_conn.shutdown()

    elif tbl_ops == "READ":
        log.info("READING TABLE ENTRIES")
        try:
            reply = sw_conn.ReadTableEntries(table_id=table_id)
            for rep in reply:
                log.info(" READ Reply from DUT")
                resp = p4TestLib.repr_pretty_p4runtime(rep)
                log.info(resp)
                entries = p4TestLib.table_entry_to_dict(resp)
                for entry in entries:
                    for key,value in entry.items():
                        log.info("{}:{}".format(key,value))
                


        except KeyboardInterrupt:
            log.info("Shutting down.")
        except grpc.RpcError as e:
            log.error(e)
            printGrpcError(e)
            err_msg.append("test_indirect_table_crudTests - {tbl_ops} failed due to Grpc Error {err}".format(err=e.details(),tbl_ops=tbl_ops))
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
                    log.info(p4TestLib.tableEntryToString(entry))
                    log.info("DELETING ENTRIES FOR TABLE - {tbl_name}".format(tbl_name=tbl_name))
                    p4TestLib.tableEntryActions(sw_conn, entry, p4info_helper, 'DELETE')

        except KeyboardInterrupt:
            log.info("Shutting down.")
        except grpc.RpcError as e:
            log.error(e)
            printGrpcError(e)
            err_msg.append("test_indirect_table_crudTests - {tbl_ops} failed due to Grpc Error {err}".format(err=e.details(),tbl_ops=tbl_ops))
        finally:
            TchLib.action_profile_groups("DELETE",sw_conn,input_conf,p4info_helper)
            TchLib.action_profile_members("DELETE",sw_conn,input_conf,p4info_helper)            
            sw_conn.shutdown()

    
    sw_conn.shutdown()
    if len(err_msg) != 0:
        log.error("test_indirect_table_crudTests failed due to : {}".format(*err_msg))
        pytest.fail("test_indirect_table_crudTests failed due to : {}".format(*err_msg))
    else:
        log.info("test_indirect_table_crudTests - {} Passed".format(tbl_ops))




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

    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        sw_conn.shutdown()
        raise CafyException.VerificationError(e)
    sw_conn.shutdown()

def _test_writeRPC_Neg1():
    log.info("Test: Verify sending unknown deviceID & roleID with WRITE RPC")
    tData = ApData.zap.get_testcase_configuration("test_writeRPC_Neg1")
    p4info_helper = p4_info_helper.P4InfoHelper(ApData.p4info)
    with open(tData["input_conf_file"], 'r') as ip_conf_file:
        input_conf = p4TestLib.json_load_byteified(ip_conf_file)
    rslt = True

    if 'NEG_WriteRPC_1' in input_conf:
        tbl_info = input_conf['NEG_WriteRPC_1']
        for entry in tbl_info:
            if "table" in entry:
                tbl_ins = entry
                tbl_name = entry["table"]
                table_id = p4info_helper.get_id("tables", name=tbl_name)

    try:       
        sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
        sw_conn.MasterArbitrationUpdate()
        log.info ("NEG_WriteRPC_1.1: Verifying sending unknown deviceID in WRITE RPC ")
        log.info(p4TestLib.tableEntryToString(tbl_ins))
        p4TestLib.tableEntryActions(sw_conn, tbl_ins, p4info_helper,'INSERT',device_id=100)
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        print("ERROR DETAILS::")
        log.error(e)
        printGrpcError(e)
        sw_conn.shutdown()
        if ('StatusCode.NOT_FOUND' in str(e) and 'Invalid device id' in str(e)):
            log.info("Test NEG_WriteRPC_1.1:Passed - received correct error message on sending unknown deviceID in WRITE RPC")
        else:
            rslt = False
            log.error("Test NEG_WriteRPC_1.1:Failed - received incorrect error message on sending unknown deviceID")

    try:       
        sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
        sw_conn.MasterArbitrationUpdate()
        log.info ("NEG_WriteRPC_1.2: Verifying sending unknown deviceID in READ RPC ")
        log.info(p4TestLib.tableEntryToString(tbl_ins))
        #p4TestLib.tableEntryActions(sw_conn, tbl_ins, p4info_helper,'INSERT')
        reply = sw_conn.ReadTableEntries(table_id=table_id,device_id=100)
        for rep in reply:
            log.info(" READ Reply from DUT for unknown deviceID")
            log.info(p4TestLib.repr_pretty_p4runtime(rep))
            rslt = False
            log.error("Test NEG_WriteRPC_1.2:Failed - READ RPC should not return data on sending unknown deviceID")
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        print("ERROR DETAILS::")
        log.error(e)
        printGrpcError(e)
        if ('StatusCode.NOT_FOUND' in str(e) and 'Invalid device id' in str(e)):
            log.info("Test NEG_WriteRPC_1.2:Passed - received correct error message on sending unknown deviceID in READ RPC")
        else:
            rslt = False
            log.error("Test NEG_WriteRPC_1.2:Failed - received incorrect error message on sending unknown deviceID in READ RPC")

    finally:
        sw_conn.shutdown()
        if rslt:
            log.info("Test NEG_WriteRPC_1:Passed - Error Scenarios for Write & Read RPC with unknown deviceID Passed")
        else:
            raise CafyException.VerificationError("Test NEG_WriteRPC_1:Failed - One or More Error Scenarios for Write/Read RPC with unknown deviceID")
 


def _test_writeRPC_Neg2():
    log.info("Test: Verify WRITE RPC from a Non-Master Controller")
    tData = ApData.zap.get_testcase_configuration("test_writeRPC_Neg1")
    p4info_helper = p4_info_helper.P4InfoHelper(ApData.p4info)
    with open(tData["input_conf_file"], 'r') as ip_conf_file:
        input_conf = p4TestLib.json_load_byteified(ip_conf_file)
    rslt = True

    if 'NEG_WriteRPC_1' in input_conf:
        tbl_info = input_conf['NEG_WriteRPC_1']
        for entry in tbl_info:
            if "table" in entry:
                tbl_ins = entry
                tbl_name = entry["table"]
                table_id = p4info_helper.get_id("tables", name=tbl_name)

    try:       
        sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
        sw_conn.MasterArbitrationUpdate()
        log.info ("NEG_WriteRPC_2: WRITE RPC from a Non-Master Controller")
        log.info("Creating a new switch connection which will be Master")
        ns1=TchLib.Establish_Switch_Conn("s2")
        log.info("Sending with Election ID High=44 & Low=555 for new switch connection")
        reply=ns1.MasterArbitrationUpdate(election_id_high=44, election_id_low=555)
        log.info(str(reply))
        if ('message: "Is master"' in str(reply)):
            log.info("2nd switch connection is Master")
        else:
            raise CafyException.VerificationError("NEG_WriteRPC_2: Failed as setup with Master & 2nd controller are not present")
        log.info ("NEG_WriteRPC_2: Verifying sending WRITE RPC from Non-Master")
        log.info(p4TestLib.tableEntryToString(tbl_ins))
        p4TestLib.tableEntryActions(sw_conn, tbl_ins, p4info_helper,'INSERT')
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        print("ERROR DETAILS::")
        log.error(e)
        printGrpcError(e)
        if ('StatusCode.PERMISSION_DENIED' in str(e) and 'Not master' in str(e)):
            log.info("Test NEG_WriteRPC_2:Passed - received correct error message on sending WRITE RPC from Non-Master")
        else:
            rslt = False
            raise CafyException.VerificationError("Test NEG_WriteRPC_2:Failed - rcvd incorrect error message on sending WRITE RPC from Non-Master")
    finally:
        sw_conn.shutdown()
        ns1.shutdown()


def _test_writeRPC_Neg3():
    log.info("Test: Verify WRITE RPC without setting Forwarding Pipeline")
    tData = ApData.zap.get_testcase_configuration("test_writeRPC_Neg1")
    p4info_helper = p4_info_helper.P4InfoHelper(ApData.p4info)
    with open(tData["input_conf_file"], 'r') as ip_conf_file:
        input_conf = p4TestLib.json_load_byteified(ip_conf_file)
    rslt = True

    if 'NEG_WriteRPC_1' in input_conf:
        tbl_info = input_conf['NEG_WriteRPC_1']
        for entry in tbl_info:
            if "table" in entry:
                tbl_ins = entry
                tbl_name = entry["table"]
                table_id = p4info_helper.get_id("tables", name=tbl_name)

    try:       
        sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
        sw_conn.MasterArbitrationUpdate()
        log.info ("NEG_WriteRPC_3: Verifying sending WRITE RPC without SetForwardingPipelineConfig")
        log.info(p4TestLib.tableEntryToString(tbl_ins))
        p4TestLib.tableEntryActions(sw_conn, tbl_ins, p4info_helper,'INSERT')
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        print("ERROR DETAILS::")
        log.error(e)
        printGrpcError(e)
        if ('StatusCode.FAILED_PRECONDITION' in str(e) and 'No forwarding pipeline config set' in str(e)):
            log.info("Test NEG_WriteRPC_3:Passed - received correct error message on WRITE RPC without SetForwardingPipelineConfig")
        else:
            rslt = False
            raise CafyException.VerificationError("Test NEG_WriteRPC_3:Failed - rcvd incorrect error message on WRITE RPC without SetForwardingPipelineConfig")
    finally:
        sw_conn.shutdown()        


def _test_writeInsert_Neg1():
    log.info("Test: Verify Insert into a table with Duplicate Entry")
    tData = ApData.zap.get_testcase_configuration("test_writeRPC_Neg1")
    p4info_helper = p4_info_helper.P4InfoHelper(ApData.p4info)
    with open(tData["input_conf_file"], 'r') as ip_conf_file:
        input_conf = p4TestLib.json_load_byteified(ip_conf_file)
    rslt = True

    if 'NEG_WriteRPC_1' in input_conf:
        tbl_info = input_conf['NEG_WriteRPC_1']
        for entry in tbl_info:
            if "table" in entry:
                tbl_ins = entry

    try:       
        sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
        sw_conn.MasterArbitrationUpdate()
        log.info ("NEG_WriteInsert_1: Verifying Insert into a table with Duplicate Entry")
        log.info(p4TestLib.tableEntryToString(tbl_ins))
        p4TestLib.tableEntryActions(sw_conn, tbl_ins, p4info_helper,'INSERT')
        log.info("Inserting the Duplicate Entry")
        p4TestLib.tableEntryActions(sw_conn, tbl_ins, p4info_helper,'INSERT')
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        e_det = parseGrpcError(e)
        print("ERROR DETAILS::")
        print(e_det)
        p4TestLib.tableEntryActions(sw_conn, tbl_ins, p4info_helper,'DELETE')
        sw_conn.shutdown()
        for item in e_det:
            if (item['code'] == "ALREADY_EXISTS") and (item['message'] == "Match entry exists, use MODIFY if you wish to change action"):
                log.info("Test NEG_WriteInsert_1:Passed - received correct error message on Insert into a table with Duplicate Entry")
            else:
                log.error("Test NEG_WriteInsert_1:Failed - rcvd incorrect error message on Insert into a table with Duplicate Entry")
                rslt = False


def _test_writeInsert_Neg2():
    log.info("Test: Verify Insert into a table with Malformed Entry")
    tData = ApData.zap.get_testcase_configuration("test_writeRPC_Neg1")
    p4info_helper = p4_info_helper.P4InfoHelper(ApData.p4info)
    with open(tData["input_conf_file"], 'r') as ip_conf_file:
        input_conf = p4TestLib.json_load_byteified(ip_conf_file)
    rslt = True

    if 'NEG_WriteInsert_2' in input_conf:
        tbl_info = input_conf['NEG_WriteInsert_2']
        for entry in tbl_info:
            if "table" in entry:
                tbl_ins = entry

    try:
        sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
        sw_conn.MasterArbitrationUpdate()
        log.info ("NEG_WriteInsert_2: Verifying Insert into a table with Malformed Entry")
        log.info(p4TestLib.tableEntryToString(tbl_ins))
        p4TestLib.tableEntryActions(sw_conn, tbl_ins, p4info_helper,'INSERT')
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        e_det = parseGrpcError(e)
        print("ERROR DETAILS::")
        print(e_det)
        sw_conn.shutdown()
        for item in e_det:
            if (item['code'] == "INVALID_ARGUMENT") and (item['message'] == "Non-zero priority for non-ternary match"):
                log.info("Test NEG_WriteInsert_2:Passed - received correct error message on Insert into a table with Malformed Entry")
            else:
                log.error("Test NEG_WriteInsert_2:Failed - rcvd incorrect error message on Insert into a table with Malformed Entry")
                rslt = False

def _test_writeModify_Neg1():
    log.info("Test: Verify Modify of table with Malformed Entry")
    tData = ApData.zap.get_testcase_configuration("test_writeRPC_Neg1")
    p4info_helper = p4_info_helper.P4InfoHelper(ApData.p4info)
    with open(tData["input_conf_file"], 'r') as ip_conf_file:
        input_conf = p4TestLib.json_load_byteified(ip_conf_file)
    rslt = True

    if 'NEG_WriteInsert_2' in input_conf:
        tbl_info = input_conf['NEG_WriteInsert_2']
        for entry in tbl_info:
            if "table" in entry:
                tbl_ins = entry

    try:
        sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
        sw_conn.MasterArbitrationUpdate()
        log.info ("NEG_WriteModify_1: Verifying Modify of a table with Malformed Entry")
        log.info(p4TestLib.tableEntryToString(tbl_ins))
        p4TestLib.tableEntryActions(sw_conn, tbl_ins, p4info_helper,'INSERT',priority=0)
        p4TestLib.tableEntryActions(sw_conn, tbl_ins, p4info_helper,'MODIFY')
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        e_det = parseGrpcError(e)
        print("ERROR DETAILS::")
        print(e_det)
        sw_conn.shutdown()
        for item in e_det:
            if (item['code'] == "INVALID_ARGUMENT") and (item['message'] == "Non-zero priority for non-ternary match"):
                log.info("Test NEG_WriteModify_1:Passed - received correct error message on Modify of a table with Malformed Entry")
            else:
                log.error("Test NEG_WriteModify_1:Failed - rcvd incorrect error message on Modify of a table with Malformed Entry")
                rslt = False

def _test_writeUpdnDel_Neg1():
    log.info("Test: Verify Modify of table with Non-existant Entry")
    tData = ApData.zap.get_testcase_configuration("test_writeRPC_Neg1")
    p4info_helper = p4_info_helper.P4InfoHelper(ApData.p4info)
    with open(tData["input_conf_file"], 'r') as ip_conf_file:
        input_conf = p4TestLib.json_load_byteified(ip_conf_file)
    rslt = True

    if 'NEG_WriteInsert_2' in input_conf:
        tbl_info = input_conf['NEG_WriteInsert_2']
        for entry in tbl_info:
            if "table" in entry:
                tbl_ins = entry

    try:
        sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
        sw_conn.MasterArbitrationUpdate()
        log.info ("NEG_WriteModify_2: Verifying Modify of a table with Non-existant Entry")
        log.info(p4TestLib.tableEntryToString(tbl_ins))
        p4TestLib.tableEntryActions(sw_conn, tbl_ins, p4info_helper,'MODIFY',priority=0)
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        e_det = parseGrpcError(e)
        print("ERROR DETAILS::")
        print(e_det)
        sw_conn.shutdown()
        for item in e_det:
            if (item['code'] == "NOT_FOUND") and (item['message'] == "Cannot find match entry"):
                log.info("Test NEG_WriteModify_2:Passed - received correct error message on Modify of a table with Non-existant Entry")
            else:
                log.error("Test NEG_WriteModify_2:Failed - rcvd incorrect error message on Modify of a table with Non-existant Entry")
                rslt = False

    try:
        sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
        sw_conn.MasterArbitrationUpdate()
        log.info ("NEG_WriteDelete_1: Verifying Delete of a table with Non-existant Entry")
        log.info(p4TestLib.tableEntryToString(tbl_ins))
        p4TestLib.tableEntryActions(sw_conn, tbl_ins, p4info_helper,'DELETE',priority=0)
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        e_det = parseGrpcError(e)
        print("ERROR DETAILS::")
        print(e_det)
        sw_conn.shutdown()
        for item in e_det:
            if (item['code'] == "NOT_FOUND") and (item['message'] == "Cannot find match entry"):
                log.info("Test NEG_WriteDelete_1:Passed - received correct error message on Delete of a table with Non-existant Entry")
            else:
                log.error("Test NEG_WriteDelete_1:Failed - rcvd incorrect error message on Delete of a table with Non-existant Entry")
                rslt = False

    finally:
        if rslt:
            log.info("Test NEG_WriteUpdDel_1:Passed - Error Scenarios for Write RPC with Update+Delete Passed")
        else:
            raise CafyException.VerificationError("Test NEG_WriteUpdDel_1:Failed - One or More Error Scenarios for Write RPC with Update+Delete")


def _test_setFrwding_Neg1():
    log.info("Test: Verify SetForwardingPipelineConfig with Unknown deviceID & Non-Master")
    p4info_helper = p4_info_helper.P4InfoHelper(ApData.p4info)
    p4_json_file_path = ApData.p4json
    rslt = True

    try:
        sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
        sw_conn.MasterArbitrationUpdate()
        log.info("Setting ForwardingPipelineConfig on s1")
        sw_conn.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                            p4_json_file_path=p4_json_file_path,device_id=100)
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        print("ERROR DETAILS::")
        log.error(e)
        printGrpcError(e)
        if ('StatusCode.NOT_FOUND' in str(e) and 'Invalid device id' in str(e)):
            log.info("Test NEG_SetFwding_1.1:Passed - rcvd correct error message on sending unknown deviceID in SetForwardingPipelineConfig")
        else:
            rslt = False
            log.error("Test NEG_SetFwding_1.1:Failed - rcvd incorrect error message on sending unknown deviceID")
    finally:
        sw_conn.shutdown()


    try:
        sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
        sw_conn.MasterArbitrationUpdate()
        log.info ("NEG_SetFwding_1.2: SetForwardingPipelineConfig from a Non-Master Controller")
        log.info("Creating a new switch connection which will be Master")
        ns1=TchLib.Establish_Switch_Conn("s2")
        log.info("Sending with Election ID High=44 & Low=555 for new switch connection")
        reply=ns1.MasterArbitrationUpdate(election_id_high=44, election_id_low=555)
        log.info(str(reply))
        if ('message: "Is master"' in str(reply)):
            log.info("2nd switch connection is Master")
        else:
            rslt = False
            log.error("NEG_SetFwding_1.2: Failed as setup with Master & 2nd controller are not present")
        log.info ("NEG_SetFwding_1.2: Verifying SetFwding from Non-Master")
        sw_conn.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                            p4_json_file_path=p4_json_file_path)
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        print("ERROR DETAILS::")
        log.error(e)
        printGrpcError(e)
        if ('StatusCode.PERMISSION_DENIED' in str(e) and 'Not master' in str(e)):
            log.info("Test NEG_SetFwding_1.2:Passed - received correct error message on SetForwardingPipelineConfig from Non-Master")
        else:
            rslt = False
            raise CafyException.VerificationError("Test NEG_SetFwding_1.2:Failed - rcvd incorrect error message on SetFwding from Non-Master")
    finally:
        sw_conn.shutdown()
        ns1.shutdown()


def _test_setFrwding_Act1():
    log.info("Test: Verify SetForwardingPipelineConfig Action Types")
    p4info_helper = p4_info_helper.P4InfoHelper(ApData.p4info)
    p4_json_file_path = ApData.p4json
    rslt = True

    try:
        sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
        sw_conn.MasterArbitrationUpdate()
        log.info("Setting ForwardingPipelineConfig on s1")
        sw_conn.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                            p4_json_file_path=p4_json_file_path)
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        print("ERROR DETAILS::")
        log.error(e)
        printGrpcError(e)
        if ('StatusCode.NOT_FOUND' in str(e) and 'Invalid device id' in str(e)):
            log.info("Test NEG_SetFwding_1.1:Passed - rcvd correct error message on sending unknown deviceID in SetForwardingPipelineConfig")
        else:
            rslt = False
            log.error("Test NEG_SetFwding_1.1:Failed - rcvd incorrect error message on sending unknown deviceID")
    finally:
        sw_conn.shutdown()


def _test_setFwd_Opt1():
    log.info("Test: Verify SetForwardingPipelineConfig with VERIFY Action")
    tData = ApData.zap.get_testcase_configuration("test_setFwd_Opt1")
    p4info_helper = p4_info_helper.P4InfoHelper(ApData.p4info)
    p4_json_file_path = ApData.p4json
    input_conf = p4_info_helper.P4InfoHelper(tData["input_conf_file"])
    rslt = True

    try:
        sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
        sw_conn.MasterArbitrationUpdate()    
        log.info("Setting ForwardingPipelineConfig on s1")
        sw_conn.SetForwardingPipelineConfig(p4info=input_conf.p4info,config=True,
                                            p4_json_file_path=p4_json_file_path,action="VERIFY")
        response = sw_conn.GetForwardingPipelineConfig()
        #log.info(response)
        #Sending SetFwingPipelineCfg with 'VERIFY' option
        foo = p4TestLib.repr_pretty_p4runtime(response)
        for line in foo.splitlines():
            if re.search(r'^.*name:.*encap_in_ipv4_table\"$', line):
                log.error("SFwd_Act_1.1:Failed - This table should not be present in the Set Config")
                log.info(line)
                rslt = False
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        log.error("Test SFwd_Act_1.1:Failed - GRPC error should not be received on SetFwding with VERIFY")
    finally:
        sw_conn.shutdown()

    try:
        sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
        sw_conn.MasterArbitrationUpdate()    
        log.info("Setting ForwardingPipelineConfig on s1")
        sw_conn.SetForwardingPipelineConfig(p4info=input_conf.p4info,config=False,
                                            p4_json_file_path=p4_json_file_path,action="VERIFY")
        response = sw_conn.GetForwardingPipelineConfig()
        log.error("Test SFwd_Act_1.2:Failed - GRPC error should be received on SetFwding with VERIFY & No Config")
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        e_det = parseGrpcError(e)
        print("ERROR DETAILS::")
        print(e_det)
        sw_conn.shutdown()
        for item in e_det:
            if (item['code'] == "INVALID_ARGUMENT") and (item['message'] == "No Config provided for SetFwding"):
                log.info("Test SFwd_Act_1.2:Passed - received correct error message on SetFwding with No config")
            else:
                log.error("Test SFwd_Act_1.2:Failed - rcvd incorrect error message on SetFwding with No config")
                rslt = False
    finally:
        if rslt:
            log.info("Test SFwd_Act_1:Passed - SetFwding with VERIFY action behavior")
        else:
            log.error("Test SFwd_Act_1:Failed - SetFwding with VERIFY action behavior")
        sw_conn.shutdown()
        

def _test_setFwd_Opt2():
    log.info("Test: Verify SetForwardingPipelineConfig with VERIFY_AND_SAVE Action")
    tData = ApData.zap.get_testcase_configuration("test_setFwd_Opt1")
    p4info_helper = p4_info_helper.P4InfoHelper(ApData.p4info)
    p4_json_file_path = ApData.p4json
    input_conf = p4_info_helper.P4InfoHelper(tData["input_conf_file"])
    rslt = True

    try:
        sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
        sw_conn.MasterArbitrationUpdate()    
        log.info("Test SFwd_Act_2.1 - Setting ForwardingPipelineConfig on s1")
        sw_conn.SetForwardingPipelineConfig(p4info=input_conf.p4info,config=False,
                                            p4_json_file_path=p4_json_file_path,action="VERIFY_AND_SAVE")
        response = sw_conn.GetForwardingPipelineConfig()
        log.error("Test SFwd_Act_2.1:Failed - GRPC error should be received on SetFwding with VERIFY_AND_SAVE & No Config")
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        e_det = parseGrpcError(e)
        print("ERROR DETAILS::")
        print(e_det)
        sw_conn.shutdown()
        for item in e_det:
            if (item['code'] == "INVALID_ARGUMENT") and (item['message'] == "No Config provided for SetFwding"):
                log.info("Test SFwd_Act_2.1:Passed - received correct error message on SetFwding with No config")
            else:
                log.error("Test SFwd_Act_2.1:Failed - rcvd incorrect error message on SetFwding with No config")
                rslt = False
    finally:
        sw_conn.shutdown()


    try:
        sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
        sw_conn.MasterArbitrationUpdate()    
        log.info("Test SFwd_Act_2.2 - Setting ForwardingPipelineConfig on s1")
        sw_conn.SetForwardingPipelineConfig(p4info=input_conf.p4info,config=True,
                                            p4_json_file_path=p4_json_file_path,action="VERIFY_AND_SAVE")
        response = sw_conn.GetForwardingPipelineConfig()
        #log.info(response)
        #Sending SetFwingPipelineCfg with 'VERIFY_AND_SAVE' option without v4 table
        foo = p4TestLib.repr_pretty_p4runtime(response)
        rchk_v4 = True
        for line in foo.splitlines():
            if re.search(r'^.*name:.*encap_in_ipv6_table\"$', line):
                log.info(line)
                rchk_v6 = True
            if re.search(r'^.*name:.*encap_in_ipv4_table\"$', line):
                log.error("SFwd_Act_2.2:Failed - This table should not be present in the Set Config")
                log.info(line)
                rchk_v4 = False
                rslt = False
        if rchk_v4 and rchk_v6:
            log.info("SFwd_Act_2.2:Passed - SetFwding with VERIFY_AND_SAVE input is OK")
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        log.error("Test SFwd_Act_2.2:Failed - GRPC error should not be received on SetFwding with VERIFY_AND_SAVE")
    finally:
        sw_conn.shutdown()

    try:
        tData = ApData.zap.get_testcase_configuration("test_writeRPC_Neg1")
        with open(tData["input_conf_file"], 'r') as ip_conf_file:
            input_conf = p4TestLib.json_load_byteified(ip_conf_file)

        if 'NEG_WriteRPC_1' in input_conf:
            tbl_info = input_conf['NEG_WriteRPC_1']
            for entry in tbl_info:
                if "table" in entry:
                    tbl_ins = entry
                    tbl_name = entry['table']
                    table_id = p4info_helper.get_id("tables", name=tbl_name)

        sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
        sw_conn.MasterArbitrationUpdate()    
        log.info("Test SFwd_Act_2.3 - Setting ForwardingPipelineConfig on s1")
        sw_conn.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,config=True,
                                            p4_json_file_path=p4_json_file_path,action="VERIFY_AND_SAVE")
        response = sw_conn.GetForwardingPipelineConfig()
        #log.info(response)
        #Sending SetFwingPipelineCfg with 'VERIFY_AND_SAVE' option with v4 table config now
        foo = p4TestLib.repr_pretty_p4runtime(response)
        rchk_v4 = False
        for line in foo.splitlines():
            if re.search(r'^.*name:.*encap_in_ipv4_table\"$', line):
                rchk_v4 = True
                log.info(line)
        if rchk_v4:
            log.info("SFwd_Act_2.3.1:Passed - encap+in_ipv4 table got correctly saved with SetFwding")
            #Now we will try to insertan entry to the new table
            log.info(p4TestLib.tableEntryToString(tbl_ins))
            p4TestLib.tableEntryActions(sw_conn, tbl_ins, p4info_helper,'INSERT')
            #Read the table to verify if entry was inserted
            reply = sw_conn.ReadTableEntries(table_id=table_id)
            for rep in reply:
                log.info("SFwd_Act_2.3.1 - READ Reply from DUT")
                resp = p4TestLib.repr_pretty_p4runtime(rep)
                log.info(resp)
                entries = p4TestLib.table_entry_to_dict(resp)
                if len(entries) == 1:
                    for entry in entries:
                        for key,value in entry.items():
                            log.info("{}:{}".format(key,value))
                    log.info("SFwd_Act_2.3.2:Passed - entry inserted to encap+in_ipv4 table with VERIFY_AND_SAVE")
                else:
                    log.error("SFwd_Act_2.3.2:Failed - entry inserted to encap+in_ipv4 table with VERIFY_AND_SAVE")
        else:
            log.error("SFwd_Act_2.3.1:Failed - encap+in_ipv4 table did not get saved with SetFwding")
            rslt = False
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        log.error("Test SFwd_Act_2.3:Failed - GRPC error should not be received on SetFwding with VERIFY_AND_SAVE")
    finally:
        sw_conn.shutdown()

    #Setting the Forwarding Pipeline so that no stale config in saved mode is left behind
    try:
        sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
        sw_conn.MasterArbitrationUpdate()
        log.info("Setting ForwardingPipelineConfig")
        sw_conn.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                            p4_json_file_path=p4_json_file_path)    
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        log.error("Test SFwd_Act_2.4:Failed - GRPC error should not be received on SetFwding")
    finally:
        sw_conn.shutdown()


def _test_setFwd_Opt3():
    log.info("Test: Verify SetForwardingPipelineConfig with COMMIT Action")
    tData = ApData.zap.get_testcase_configuration("test_setFwd_Opt1")
    p4info_helper = p4_info_helper.P4InfoHelper(ApData.p4info)
    p4_json_file_path = ApData.p4json
    input_conf = p4_info_helper.P4InfoHelper(tData["input_conf_file"])
    rslt = True

    try:
        sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
        sw_conn.MasterArbitrationUpdate()    
        log.info("Test SFwd_Act_3.1 - Setting ForwardingPipelineConfig on s1")
        sw_conn.SetForwardingPipelineConfig(p4info=input_conf.p4info,
                                            p4_json_file_path=p4_json_file_path)
        response = sw_conn.GetForwardingPipelineConfig()
        #Checking if FwdingPipeline with v4 table config is present
        foo = p4TestLib.repr_pretty_p4runtime(response)
        rchk_v4 = False
        for line in foo.splitlines():
            if re.search(r'^.*name:.*encap_in_ipv6_table\"$', line):
                rchk_v4 = True
                log.info(line)
        if rchk_v4:
            log.info("SFwd_Act_3.1.1:Passed - encap+in_ipv6 table got correctly set with SetFwding")
        else:
            log.error("SFwd_Act_3.1.1:Failed - encap+in_ipv6 table did not get set, Fail and skip rest of test")
        #Now try to SetFwding with COMMIT without saved config
        sw_conn.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,config=False,
                                            p4_json_file_path=p4_json_file_path,action="COMMIT")        
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        e_det = parseGrpcError(e)
        print("ERROR DETAILS::")
        print(e_det)
        sw_conn.shutdown()
        for item in e_det:
            if (item['code'] == "NOT_FOUND") and (item['message'] == "No Verify_and_save action preceeded"):
                log.info("Test SFwd_Act_3.1.2:Passed - received correct error message on SetFwding with COMMIT with no save")
            else:
                log.error("Test SFwd_Act_3.1.2:Failed - rcvd incorrect error message on SetFwding with COMMIT with no save")
                rslt = False
    finally:
        sw_conn.shutdown()

    try:
        sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
        sw_conn.MasterArbitrationUpdate()
        sw_conn.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,config=True,
                                            p4_json_file_path=p4_json_file_path,action="VERIFY_AND_SAVE")
        #Now try to SetFwding with COMMIT with config being provided
        sw_conn.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,config=True,
                                            p4_json_file_path=p4_json_file_path,action="COMMIT")
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        e_det = parseGrpcError(e)
        print("ERROR DETAILS::")
        print(e_det)
        sw_conn.shutdown()
        for item in e_det:
            if (item['code'] == "INVALID_ARGUMENT") and (item['message'] == "Config should not be provided"):
                log.info("Test SFwd_Act_3.2:Passed - received correct error message on SetFwding with COMMIT with no save")
            else:
                log.error("Test SFwd_Act_3.2:Failed - rcvd incorrect error message on SetFwding with COMMIT with no save")
                rslt = False
    finally:
        sw_conn.shutdown()



def _test_setFwd_Opt4():
    log.info("Test: Verify SetForwardingPipelineConfig with COMMIT Action")
    tData = ApData.zap.get_testcase_configuration("test_setFwd_Opt1")
    p4info_helper = p4_info_helper.P4InfoHelper(ApData.p4info)
    p4_json_file_path = ApData.p4json
    input_conf = p4_info_helper.P4InfoHelper(tData["input_conf_file"])
    rslt = True

    try:
        sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
        sw_conn.MasterArbitrationUpdate()
        sw_conn.SetForwardingPipelineConfig(p4info=input_conf.p4info,
                                            p4_json_file_path=p4_json_file_path)

        tData2 = ApData.zap.get_testcase_configuration("test_writeRPC_Neg1")
        with open(tData2["input_conf_file"], 'r') as ip_conf_file:
            input_conf2 = p4TestLib.json_load_byteified(ip_conf_file)

        if 'NEG_WriteRPC_1' in input_conf2:
            tbl_info = input_conf2['NEG_WriteRPC_1']
            for entry in tbl_info:
                if "table" in entry:
                    tbl_ins = entry
                    tbl_name = entry['table']
                    table_id = p4info_helper.get_id("tables", name=tbl_name)

        sw_conn.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,config=True,
                                            p4_json_file_path=p4_json_file_path,action="VERIFY_AND_SAVE")
        #sleep(1)
        p4TestLib.tableEntryActions(sw_conn, tbl_ins, p4info_helper,'INSERT')
        #sleep(1)
        #Now try to SetFwding with COMMIT
        sw_conn.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,config=False,
                                            p4_json_file_path=p4_json_file_path,action="COMMIT")
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        e_det = parseGrpcError(e)
        print("ERROR DETAILS::")
        print(e_det)
        sw_conn.shutdown()
        for item in e_det:
            if (item['code'] == "INVALID_ARGUMENT") and (item['message'] == "Config should not be provided"):
                log.info("Test SFwd_Act_4.1:Passed - received correct error message on SetFwding with COMMIT with no save")
            else:
                log.error("Test SFwd_Act_4.1:Failed - rcvd incorrect error message on SetFwding with COMMIT with no save")
                rslt = False
    finally:
        sw_conn.shutdown()


def _test_getFwd_Neg1():
    log.info("Test: Verify GetForwardingPipelineConfig with Unknown Device-ID")
    p4info_helper = p4_info_helper.P4InfoHelper(ApData.p4info)
    p4_json_file_path = ApData.p4json
    rslt = True

    try:
        sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
        sw_conn.MasterArbitrationUpdate()
        log.info("Get ForwardingPipelineConfig on s1")
        response = sw_conn.GetForwardingPipelineConfig(device_id=100)
        log.info(response)
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        print("ERROR DETAILS::")
        log.error(e)
        printGrpcError(e)
        if ('StatusCode.NOT_FOUND' in str(e) and 'Invalid device id' in str(e)):
            log.info("Test NEG_GetFwding_1.1:Passed - rcvd correct error message on sending unknown deviceID in GetForwardingPipelineConfig")
        else:
            rslt = False
            log.error("Test NEG_GetFwding_1.1:Failed - rcvd incorrect error message on sending unknown deviceID")
    finally:
        sw_conn.shutdown()


def _test_getFwd_Resp1():
    log.info("Test: Verify GetForwardingPipelineConfig with various Response Types")
    p4info_helper = p4_info_helper.P4InfoHelper(ApData.p4info)
    p4_json_file_path = ApData.p4json
    rslt = True


    try:
        sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
        sw_conn.MasterArbitrationUpdate()
        log.info("Setting ForwardingPipelineConfig with Cookie of 333444")
        sw_conn.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                            p4_json_file_path=p4_json_file_path,cookie=333444)
        log.info("Get ForwardingPipelineConfig with ResponeType = COOKIE_ONLY")
        response = sw_conn.GetForwardingPipelineConfig(resp_typ="COOKIE_ONLY")
        log.info(response)
        if ('cookie: 333444' in str(response)):
            log.info("Test GtFwd_Resp_1.1:Passed - GetFwding with COOKIE_ONLY works correctly")
        else:
            log.error("Test GtFwd_Resp_1.1:Failed - GetFwding with COOKIE_ONLY does not return correct COOKIE")
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        print("ERROR DETAILS::")
        log.error(e)
        printGrpcError(e)
        rslt = False
        log.error("Test GtFwd_Resp_1.1:Failed - GetFwding with COOKIE_ONLY should not give error")
    finally:
        sw_conn.shutdown()    

    try:
        sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
        sw_conn.MasterArbitrationUpdate()
        log.info("Setting ForwardingPipelineConfig with Cookie of 333444 is already set in GtFwd_Resp_1.1")
        log.info("Get ForwardingPipelineConfig with ResponeType = P4INFO_AND_COOKIE")
        resp = sw_conn.GetForwardingPipelineConfig(resp_typ="P4INFO_AND_COOKIE")
        log.info(resp)
        if ('cookie: 333444' in str(resp) and 'tables' in str(resp)):
            log.info("Test GtFwd_Resp_1.2:Passed - GetFwding with P4INFO_AND_COOKIE works correctly")
        else:
            log.error("Test GtFwd_Resp_1.2:Failed - GetFwding with P4INFO_AND_COOKIE does not return correct COOKIE")
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        print("ERROR DETAILS::")
        log.error(e)
        printGrpcError(e)
        rslt = False
        log.error("Test GtFwd_Resp_1.2:Failed - GetFwding with P4INFO_AND_COOKIE should not give error")
    finally:
        sw_conn.shutdown() 


    try:
        sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
        sw_conn.MasterArbitrationUpdate()
        log.info("Setting ForwardingPipelineConfig with Cookie of 333444 is already set in GtFwd_Resp_1.1")
        log.info("Get ForwardingPipelineConfig with ResponeType = DEVICE_CONFIG_AND_COOKIE")
        resp = sw_conn.GetForwardingPipelineConfig(resp_typ="DEVICE_CONFIG_AND_COOKIE")
        log.info(resp)
        if ('cookie: 333444' in str(resp) and 'tables' not in str(resp)):
            log.info("Test GtFwd_Resp_1.3:Passed - GetFwding with DEVICE_CONFIG_AND_COOKIE works correctly")
        else:
            log.error("Test GtFwd_Resp_1.3:Failed - GetFwding with DEVICE_CONFIG_AND_COOKIE does not return correct COOKIE")
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        print("ERROR DETAILS::")
        log.error(e)
        printGrpcError(e)
        rslt = False
        log.error("Test GtFwd_Resp_1.3:Failed - GetFwding with DEVICE_CONFIG_AND_COOKIE should not give error")
    finally:
        sw_conn.shutdown()

    try:
        sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
        sw_conn.MasterArbitrationUpdate()
        log.info("Setting ForwardingPipelineConfig with Cookie of 333444 is already set in GtFwd_Resp_1.1")
        log.info("Get ForwardingPipelineConfig with ResponeType = ALL")
        resp = sw_conn.GetForwardingPipelineConfig(resp_typ="ALL")
        log.info(resp)
        if ('cookie: 333444' in str(resp) and 'tables' in str(resp)):
            log.info("Test GtFwd_Resp_1.4:Passed - GetFwding with ALL works correctly")
        else:
            log.error("Test GtFwd_Resp_1.4:Failed - GetFwding with ALL does not return correct COOKIE")
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        print("ERROR DETAILS::")
        log.error(e)
        printGrpcError(e)
        rslt = False
        log.error("Test GtFwd_Resp_1.4:Failed - GetFwding with ALL should not give error")
    finally:
        sw_conn.shutdown()
        
def teardown_class(self):
    log.info("Teardown class")
    p4_switch.ShutdownAllSwitchConnections()
