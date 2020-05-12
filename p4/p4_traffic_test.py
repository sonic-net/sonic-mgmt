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

log = CafyLog(name='P4 Traffic tests')

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

def _test_traffic_l3_fwd_l3_ipv4_vrf_table(self,tc_name,tbl_ops,sw_conn):
    err_msg = list()
    sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
    sw_conn.MasterArbitrationUpdate()

    tbl_name = "ingress.l3_fwd.l3_ipv4_vrf_table"
    p4info_helper = p4_info_helper.P4InfoHelper(ApData.p4info)
    conf_file = tc_name + "/input_conf_file"
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
