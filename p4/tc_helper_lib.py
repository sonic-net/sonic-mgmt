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
log = CafyLog(name='P4 Testcase helper lib')

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

def Establish_Switch_Conn(sw_name):
    try:
        # Create a switch connection object for s1 (switch 1)
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt files.
        s1 = p4_switch.SwitchConnection(
            name=sw_name,
            address=ApData.svr_addr+":"+ApData.port_addr,
            device_id=int(ApData.device_id),
            proto_dump_file=ApData.proto_dump_file)

        return s1

    except KeyboardInterrupt:
        log.info("Shutting down.")        
    except grpc.RpcError as e:
        log.error(e)
        printGrpcError(e)

def blocking_table_play(name):
    with open(ApData.input_conf_file, 'r') as ip_conf_file:
        input_conf = p4TestLib.json_load_byteified(ip_conf_file)
    
    p4info_helper = p4_info_helper.P4InfoHelper(ApData.p4info)
    result = dict()
    result['sw_name'] = name

    try:
        ns1=Establish_Switch_Conn(name)
        sw_name = ns1
        if "s1" in name:
            log.info("Controller s1: Sending Election ID High=22 & Low=333")
            ns1.MasterArbitrationUpdate(election_id_high=22, election_id_low=333)
            election_id_low=333
            election_id_high=22
        else:
            #sleep(10)
            log.info("Controller s2: Sending Election ID High=11 & Low=222")
            ns1.MasterArbitrationUpdate(election_id_high=11, election_id_low=222)
            election_id_low=222
            election_id_high=11
        
        if 'table_entries' in input_conf:
                log.info(input_conf)
                table_entries = input_conf['table_entries']
                log.info("Inserting {entries} table entries - Switch {name}".format(entries = len(table_entries), name=name))
                for entry in table_entries:
                    log.info(p4TestLib.tableEntryToString(entry))
                    log.info("INSERTING TABLE ENTRIES - Switch {name}".format(name=name))
                    p4TestLib.tableEntryActions(sw_name, entry, p4info_helper, 'INSERT',election_id_low=election_id_low,election_id_high=election_id_high)
                    log.info("Sleep")
                    sleep(1)
                    log.info("REMOVING TABLE ENTRIES - Switch {name}".format(name=name))
                    p4TestLib.tableEntryActions(sw_name, entry, p4info_helper, 'DELETE',election_id_low=election_id_low,election_id_high=election_id_high)
                    sleep(1)
                    log.info("RE-INSERTING TABLE ENTRIES - Switch {name}".format(name=name))
                    p4TestLib.tableEntryActions(sw_name, entry, p4info_helper, 'INSERT',election_id_low=election_id_low,election_id_high=election_id_high)
                    sleep(1)
                    log.info("READING TABLE ENTRIES - Switch {name}".format(name=name))
                    #readTableRules(p4info_helper, sw_name)
                    sleep(1)

        if 'table_entries' in input_conf:
            log.info(input_conf)
            table_entries = input_conf['table_entries']
            log.info("Inserting {entries} table entries - Switch {name}".format(entries = len(table_entries), name=name))
            for entry in table_entries:
                log.info(p4TestLib.tableEntryToString(entry))
                #insertTableEntry(sw_name, entry, p4info_helper)
                #removeTableEntry(sw_name, entry, p4info_helper)
                log.info("REMOVING TABLE ENTRIES - Switch {name}".format(name=name))
                p4TestLib.tableEntryActions(sw_name, entry, p4info_helper, 'DELETE',election_id_low=election_id_low,election_id_high=election_id_high)
                sleep(1)
    
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error(e)
        printGrpcError(e)
        result["msg"] = str(e)
        result["status"] = False
        return result

    result["status"] = True
    return result

def non_blocking_table_play(name):
    tData = ApData.zap.get_testcase_configuration("test_multicontrollers_non_blocking_tableEdit")
    with open(tData["input_conf_file"], 'r') as ip_conf_file:
        input_conf = p4TestLib.json_load_byteified(ip_conf_file)
    
    p4info_helper = p4_info_helper.P4InfoHelper(ApData.p4info)
    result = dict()
    result['sw_name'] = name

    try:
        ns1=Establish_Switch_Conn(name)
        sw_name = ns1
        if "sw1" in name:
            log.info("Controller sw1: Sending Election ID High=20 & Low=303")
            ns1.MasterArbitrationUpdate(election_id_high=20, election_id_low=303)
            election_id_low=303
            election_id_high=20

            if 'table_entries' in input_conf:
                table_entries = input_conf['table_entries']
                log.info("Inserting {entries} table entries - Switch {name}".format(entries = len(table_entries), name=name))
                for entry in table_entries:
                    log.info(p4TestLib.tableEntryToString(entry))
                    log.info("INSERTING TABLE ENTRIES - Switch {name}".format(name=name))
                    p4TestLib.tableEntryActions(sw_name, entry, p4info_helper, 'INSERT',election_id_low=election_id_low,election_id_high=election_id_high)
                    log.info("Sleep")
                    sleep(1)
                    log.info("REMOVING TABLE ENTRIES - Switch {name}".format(name=name))
                    p4TestLib.tableEntryActions(sw_name, entry, p4info_helper, 'DELETE',election_id_low=election_id_low,election_id_high=election_id_high)
                    sleep(1)
                    log.info("RE-INSERTING TABLE ENTRIES - Switch {name}".format(name=name))
                    p4TestLib.tableEntryActions(sw_name, entry, p4info_helper, 'INSERT',election_id_low=election_id_low,election_id_high=election_id_high)
                    sleep(1)
                    log.info("READING TABLE ENTRIES - Switch {name}".format(name=name))
                    table_name = entry['table']
                    table_id = p4info_helper.get_id("tables", name=table_name)
                    reply = ns1.ReadTableEntries(table_id=table_id)
                    for rep in reply:
                        log.info("Reply: %s" % rep)
                    sleep(1)

            if 'table_entries' in input_conf:
                log.info(input_conf)
                table_entries = input_conf['table_entries']
                log.info("Inserting {entries} table entries - Switch {name}".format(entries = len(table_entries), name=name))
                for entry in table_entries:
                    log.info(p4TestLib.tableEntryToString(entry))
                    #insertTableEntry(sw_name, entry, p4info_helper)
                    #removeTableEntry(sw_name, entry, p4info_helper)
                    log.info("REMOVING TABLE ENTRIES - Switch {name}".format(name=name))
                    p4TestLib.tableEntryActions(sw_name, entry, p4info_helper, 'DELETE',election_id_low=election_id_low,election_id_high=election_id_high)
                    sleep(1)
        else:
            log.info("Controller sw2: Sending Election ID High=10 & Low=201")
            ns1.MasterArbitrationUpdate(election_id_high=10, election_id_low=201)
            election_id_low=201
            election_id_high=10

            for i in range(8):
                if 'table_entries' in input_conf:
                    log.info(input_conf)
                    table_entries = input_conf['table_entries']
                    for entry in table_entries:
                        log.info("READING TABLE ENTRIES - Switch {name}".format(name=name))
                        table_name = entry['table']
                        table_id = p4info_helper.get_id("tables", name=table_name)
                        reply = ns1.ReadTableEntries(table_id=table_id)
                        for rep in reply:
                            log.info("Reply: %s" % rep)
                        sleep(2)

    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error(e)
        printGrpcError(e)
        result["msg"] = str(e)
        result["status"] = False
        return result

    result["status"] = True
    return result