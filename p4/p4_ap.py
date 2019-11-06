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
log = CafyLog("P4 AP")


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
import p4_sanity_tc as p4_san_tc
import tc_helper_lib as TchLib


SWITCH_TO_HOST_PORT = 1
SWITCH_TO_SWITCH_PORT = 2

@pytest.fixture(scope="session")
def sw_conn():
    sw_conn = None
    p4info_helper = p4_info_helper.P4InfoHelper(ApData.p4info)
    p4_json_file_path = ApData.p4json

    try:

        sw_conn=TchLib.Establish_Switch_Conn(ApData.sw_name)
        reply = sw_conn.MasterArbitrationUpdate()
        if ((str(reply).find('low: 1') != -1) and (str(reply).find('message: "Is master"') != -1)):
            if p4info_helper != None:
                # Install the P4 program on the switches
                if not ApData.skip_set_pipeline:
                    log.info("Setting ForwardingPipelineConfig on s1")
                    sw_conn.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                                p4_json_file_path=p4_json_file_path)
                    log.info("Installed P4 Program using SetForwardingPipelineConfig on sw_conn")
        else:
            raise CafyException.VerificationError("Test failed due to Election issues")

    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error(e)
        printGrpcError(e)
    finally:
        p4_switch.ShutdownAllSwitchConnections()
    #return sw_conn

class TestP4(P4ApBase):


    def test_writeRPC_Neg3(self):
        p4_san_tc._test_writeRPC_Neg3()

    """
    def test_writeRPC_Neg3(self):
        p4_san_tc._test_writeRPC_Neg3()
    """
    
    def test_setForwarding_pipeline_config(self):
        p4_san_tc._test_setForwarding_pipeline_config()

    @pytest.mark.parametrize("tbl_ops", ["INSERT", "READ", "MODIFY", "DELETE"])
    @pytest.mark.parametrize("tbl_name", ["ingress.encap.encap_in_ipv4_table"])
    def test_direct_table_crudTests(self, tbl_name, tbl_ops,sw_conn):
        p4_san_tc._test_direct_table_crudTests(self, tbl_name, tbl_ops,sw_conn)

    @pytest.mark.parametrize("tbl_ops", ["INSERT", "READ", "MODIFY", "DELETE"])
    @pytest.mark.parametrize("tbl_name", ["ingress.l3_fwd.l3_ipv4_vrf_table"])
    def test_indirect_table_crudTests(self, tbl_name, tbl_ops, sw_conn):
        p4_san_tc._test_indirect_table_crudTests(self, tbl_name, tbl_ops,sw_conn)

    def test_p4_sanity(self,sw_conn):
        p4_san_tc._test_p4_sanity(sw_conn)

    def test_ElectionID(self,sw_conn):
        p4_san_tc._test_ElectionID()

    def test_existing_ElectionID(self,sw_conn):
        p4_san_tc._test_existing_ElectionID(sw_conn)
    
    def test_Master_change(self,sw_conn):
        p4_san_tc._test_Master_change(sw_conn)

    def test_nonZero_DeviceID(self,sw_conn):
        p4_san_tc._test_nonZero_DeviceID()

    def test_deviceID_ACC(self,sw_conn):
        p4_san_tc._test_deviceID_ACC()

    @pytest.mark.parametrize("mode", ["INSERT", "DELETE"])
    def test_action_profile_members(self,mode,sw_conn):
        p4_san_tc._test_action_profile_members(mode,sw_conn)

    @pytest.mark.parametrize("mode", ["INSERT", "DELETE"])
    def test_action_profile_groups(self,mode,sw_conn):
        p4_san_tc._test_action_profile_groups(mode,sw_conn)

    
    def test_Read_wTableId_Zero(self,sw_conn):
        p4_san_tc._test_Read_wTableId_Zero(sw_conn)

    def test_multicontrollers_blocking_tableEdit(self):
        p4_san_tc._test_multicontrollers_blocking_tableEdit()

    def test_multicontrollers_non_blocking_tableEdit(self,sw_conn):
        p4_san_tc._test_multicontrollers_non_blocking_tableEdit()

    @pytest.mark.last
    def test_max_connections(self,sw_conn):
        p4_san_tc._test_max_connections()

    def test_actionMem_Neg1(self,sw_conn):
        p4_san_tc._test_actionMem_Neg1()

    def test_actionMem_Neg2(self,sw_conn):
        p4_san_tc._test_actionMem_Neg2()

    def test_actionMem_Neg3(self,sw_conn):
        p4_san_tc._test_actionMem_Neg3()

    def test_writeRPC_Neg1(self,sw_conn):
        p4_san_tc._test_writeRPC_Neg1()

    def test_writeRPC_Neg2(self,sw_conn):
        p4_san_tc._test_writeRPC_Neg2()

