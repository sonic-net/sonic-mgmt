#!/usr/bin/env python3
import argparse
import grpc
import os
import sys
import json
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

SWITCH_TO_HOST_PORT = 1
SWITCH_TO_SWITCH_PORT = 2

def Establish_Switch_Conn():
    try:
        # Create a switch connection object for s1 (switch 1)
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt files.
        s1 = p4_switch.SwitchConnection(
            name=ApData.sw_name,
            address=ApData.svr_addr+":"+ApData.port_addr,
            device_id=int(ApData.device_id),
            proto_dump_file=ApData.proto_dump_file)

        return s1

    except KeyboardInterrupt:
        log.info("Shutting down.")        
    except grpc.RpcError as e:
        log.error(e)
        printGrpcError(e)


def _test_p4_sanity():

    with open(ApData.input_conf_file, 'r') as ip_conf_file:
        input_conf = p4TestLib.json_load_byteified(ip_conf_file)

    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4_info_helper.P4InfoHelper(ApData.p4info)
    p4_json_file_path = ApData.p4json

    try:
        # Create a switch connection object for s1 (switch 1)
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt files.
        s1 = p4_switch.SwitchConnection(
            name=ApData.sw_name,
            address=ApData.svr_addr+":"+ApData.port_addr,
            device_id=int(ApData.device_id),
            proto_dump_file=ApData.proto_dump_file)

        # XXX Does not look like this is setting the role field in
        # message MasterArbitrationUpdate proto/p4/v1/p4runtime.proto

        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        s1.MasterArbitrationUpdate()

        # XXX We need to test several messages simulatenously. Python
        # can only invoke one RPC from one thread (GIL Lock).
        #
        # For example simulatenous stream + Config/Read/Write/etc.
        #
        # Investigate IterableQueue? Also used in p4_switch.py
        #

        if p4info_helper != None: 
            # Install the P4 program on the switches
            s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                        p4_json_file_path=p4_json_file_path)
            log.info("Installed P4 Program using SetForwardingPipelineConfig on s1")

            log.info("Getting ForwardingPipelineConfig on s1")
            response = s1.GetForwardingPipelineConfig(resp_typ=0)
            log.info(response)
            sleep(2)

            if 'table_entries' in input_conf:
                log.info(input_conf)
                table_entries = input_conf['table_entries']
                log.info("Inserting %d table entries..." % len(table_entries))
                for entry in table_entries:
                    log.info(p4TestLib.tableEntryToString(entry))
                    #insertTableEntry(s1, entry, p4info_helper)
                    log.info("INSERTING TABLE ENTRIES")
                    p4TestLib.tableEntryActions(s1, entry, p4info_helper, 'INSERT')
                    sleep(1)
                    #removeTableEntry(s1, entry, p4info_helper)
                    log.info("REMOVING TABLE ENTRIES")
                    p4TestLib.tableEntryActions(s1, entry, p4info_helper, 'DELETE')
                    sleep(1)
                    log.info("RE-INSERTING TABLE ENTRIES")
                    p4TestLib.tableEntryActions(s1, entry, p4info_helper, 'INSERT')
                    sleep(1)
                    log.info("READING TABLE ENTRIES")
                    #readTableRules(p4info_helper, s1)
                    sleep(1)

            if 'table_entries' in input_conf:
                log.info(input_conf)
                table_entries = input_conf['table_entries']
                log.info("Inserting %d table entries..." % len(table_entries))
                for entry in table_entries:
                    log.info(p4TestLib.tableEntryToString(entry))
                    #insertTableEntry(s1, entry, p4info_helper)
                    #removeTableEntry(s1, entry, p4info_helper)
                    log.info("REMOVING TABLE ENTRIES")
                    p4TestLib.tableEntryActions(s1, entry, p4info_helper, 'DELETE')
                    sleep(1)

            # Write the rules that tunnel traffic from h1 to h2
            #writeTunnelRules(p4info_helper, ingress_sw=s1, egress_sw=s1, tunnel_id=100,
            #                 dst_eth_addr="00:00:00:00:02:02", dst_ip_addr="10.0.2.2")

            # TODO Read table entries
            # readTableRules(p4info_helper, s1)

            # Print the tunnel counters every 2 seconds
            #while True:
            #    sleep(2)
            #    log.info('\n----- Reading tunnel counters -----')
            #    printCounter(p4info_helper, s1, "MyIngress.ingressTunnelCounter", 100)
            #    printCounter(p4info_helper, s1, "MyIngress.egressTunnelCounter", 200)

    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error(e)
        printGrpcError(e)

    p4_switch.ShutdownAllSwitchConnections()


def _test_ElectionID():
    log.info("P4TEST_1: Sending Different Election ID Values & Verify")
    ns1=Establish_Switch_Conn()
    try:
        log.info("Sending Election ID High=22 & Low=333")
        reply=ns1.MasterArbitrationUpdate(election_id_high=22, election_id_low=333)
        if ((str(reply).find('low: 333') != -1) and (str(reply).find('message: "Is master"') != -1)):
            log.info("P4TEST_1:PASSED - received correct error message on sending Non-zero Device-ID")
        else:
            log.info("P4TEST_1:FAILED - Did not receive expected error message on sending Non-zero Device-ID")
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)

    p4_switch.ShutdownAllSwitchConnections()


def _test_nonZero_DeviceID():
    log.info("P4TEST_2: Send a Non-Zero Device-ID & Verify")
    try:
        s1 = p4_switch.SwitchConnection(
            name=ApData.sw_name,
            address=ApData.svr_addr+":"+ApData.port_addr,
            device_id=200,
            proto_dump_file=ApData.proto_dump_file)

        s1.MasterArbitrationUpdate()
        log.info("P4TEST_2:FAILED - Switch Connection should not be established with Non-zero Device-ID")

    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        if (str(e).find('details = "Invalid device id"') != -1):
            log.info("P4TEST_2:PASSED - received correct error message on sending Non-zero Device-ID")
        else:
            log.error("P4TEST_2:FAILED - Did not receive expected error message on sending Non-zero Device-ID")

