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
import p4_traffic_test as p4_traffic_tc
import tc_helper_lib as TchLib
import p4_apg_apm
import six
import google.protobuf.json_format

sys.path.append('../gnmi/')
import gnmi_test_lib as gnmiTestLib
from gnmi_test_lib import GnmiConnection
sys.path.append('./../../godiva-test/lib/')
import common_lib as commonLib
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
                try:
                    sw_conn.GetForwardingPipelineConfig()
                except KeyboardInterrupt:
                    log.info("Shutting down.")
                except grpc.RpcError as e:
                    log.info("Setting ForwardingPipelineConfig on s1")
                    sw_conn.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                                p4_json_file_path=p4_json_file_path)
                    log.info("Installed P4 Program using SetForwardingPipelineConfig on sw_conn")
        else:
            raise CafyException.VerificationError("Test failed due to Election issues")
        sw_conn.shutdown()
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error(e)
        printGrpcError(e)
    finally:
        p4_switch.ShutdownAllSwitchConnections()
    #return sw_conn

def port_setup():
    user = None
    password = None
    err_msg = list()
    try:
        conf_file = "p4_port_intf_setup/" + ApData.uut_name + "/gnmi_input_conf_file"
        gnmi_input_conf = json.loads(six.moves.builtins.open(ApData.zap.get_testcase_configuration(conf_file), 'r').read())
        gnmi_conn = GnmiConnection(target=ApData.svr_addr, port=ApData.gnmi_port_addr)
        stub = gnmi_conn.stub
        set_info = gnmi_input_conf['PORT_INTF']['config']
        xpath = "/"
        paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
        reply = gnmiTestLib._set(stub, paths, 'replace', user, password, set_info)
        log.info(str(reply))
        if ('response' in str(reply) and 'op: REPLACE' in str(reply)):
            log.info("test_Get_with_prefix:Passed - was able to do SET-REPLACE with input json")
        else:
            log.info("test_Get_with_prefix:Failed - was unable to do SET-REPLACE with input json")
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        err_msg.append("Port and Interface setup failed due to Grpc Error {err}".format(err=e.details()))
    finally:
        gnmi_conn.shutdown()

def port_cleanup():
    user = None
    password = None
    err_msg = list()
    try:
        conf_file = "p4_port_intf_setup/" + ApData.uut_name + "/gnmi_input_conf_file"
        gnmi_input_conf = json.loads(six.moves.builtins.open(ApData.zap.get_testcase_configuration(conf_file), 'r').read())
        gnmi_conn = GnmiConnection(target=ApData.svr_addr, port=ApData.gnmi_port_addr)
        stub = gnmi_conn.stub
        set_info = gnmi_input_conf['PORT_INTF']['config']
        xpath = "/oc-if:interfaces"
        paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
        reply = gnmiTestLib._set(stub, paths, 'delete', user, password, set_info)
        log.info(str(reply))
        if ('response' in str(reply) and 'op: DELETE' in str(reply)):
            log.info("port_cleanup:success - was able to do SET-DELETE on target")
        else:
            log.error("port_cleanup:Failed - was unable to do SET-DELETE on target")
            err_msg.append("port_cleanup:Failed - was unable to do SET-DELETE on target")
        
        xpath = "/oc-platform:components"
        paths = gnmiTestLib._parse_path(gnmiTestLib._path_names(xpath))
        reply = gnmiTestLib._set(stub, paths, 'delete', user, password, set_info)
        log.info(str(reply))
        if ('response' in str(reply) and 'op: DELETE' in str(reply)):
            log.info("port_cleanup:success - was able to do SET-DELETE on target")
        else:
            log.error("port_cleanup:Failed - was unable to do SET-DELETE on target")
            err_msg.append("port_cleanup:Failed - was unable to do SET-DELETE on target")
    except KeyboardInterrupt:
        log.info("Shutting down.")
    except grpc.RpcError as e:
        log.error("### GRPC ERROR RECEIVED:: ###")
        log.error(e)
        printGrpcError(e)
        err_msg.append("Port and Interface cleanup failed due to Grpc Error {err}".format(err=e.details()))
    finally:
        gnmi_conn.shutdown()

def reset_p4():
    if ApData.svr_addr != "172.17.0.2":
        cmd = "sudo systemctl restart hal_server\n"
        commonLib.node_get(ApData.svr_addr, ApData.uname, ApData.pwd, cmd)
        cmd = "sudo systemctl restart halmgr\n"
        commonLib.node_get(ApData.svr_addr, ApData.uname, ApData.pwd, cmd)
        cmd = "sudo systemctl restart p4rt-agent\n"
        commonLib.node_get(ApData.svr_addr, ApData.uname, ApData.pwd, cmd)
        cmd = "sudo systemctl status p4rt-agent\n"
        reply = commonLib.node_get(ApData.svr_addr, ApData.uname, ApData.pwd, cmd)
        log.info(reply)
    
class TestP4(P4ApBase):

    def setup_method(self):
        log.info("Clean all P4 Switch connections")
        p4_switch.ShutdownAllSwitchConnections()

    def setup_class(self):
        log.info("Clean all P4 Switch connections")
        p4_switch.ShutdownAllSwitchConnections()
        port_setup()
    
    def teardown_class(self):
        log.info("Clean all P4 Switch connections")
        p4_switch.ShutdownAllSwitchConnections()
        #port_cleanup()

    def test_reset_p4(self):
        reset_p4()

    def test_writeRPC_Neg3(self):
        reset_p4()
        p4_san_tc._test_writeRPC_Neg3()

    def test_writeRPC_Neg1(self,sw_conn):
        p4_san_tc._test_writeRPC_Neg1()

    def test_writeRPC_Neg2(self,sw_conn):
        p4_san_tc._test_writeRPC_Neg2()

    def test_setForwarding_pipeline_config(self):
        p4_san_tc._test_setForwarding_pipeline_config()

    @pytest.mark.parametrize("tbl_ops", ["INSERT", "READ", "MODIFY", "DELETE"])
    @pytest.mark.parametrize("tbl_name", ["ingress.encap.encap_in_ipv4_table"])
    def test_direct_table_crudTests(self, tbl_name, tbl_ops,sw_conn):
        p4_san_tc._test_direct_table_crudTests(self, tbl_name, tbl_ops,sw_conn)

    @pytest.mark.parametrize("tbl_name", ["ingress.encap.encap_in_ipv4_table"])
    def test_direct_table_wc_readTest(self, tbl_name, sw_conn):
        p4_san_tc._test_table_wildcard_read_test(self, tbl_name, sw_conn)

    @pytest.mark.parametrize("tbl_name", ["ingress.encap.encap_in_ipv4_table"])
    def test_direct_table_batched_write_test(self, tbl_name, sw_conn):
        p4_san_tc._test_direct_table_batched_write_test(self, tbl_name, sw_conn)

    @pytest.mark.parametrize("tbl_name", ["ingress.l3_fwd.l3_ipv4_vrf_table"])
    def test_indirect_table_batched_write_test(self, tbl_name, sw_conn):
        p4_san_tc._test_indirect_table_batched_write_test(self, tbl_name, sw_conn)

    @pytest.mark.parametrize("tbl_ops", ["INSERT", "READ", "MODIFY", "DELETE"])
    @pytest.mark.parametrize("tbl_name", ["ingress.l3_fwd.l3_ipv4_vrf_table"])
    def test_indirect_table_crudTests(self, tbl_name, tbl_ops, sw_conn):
        p4_san_tc._test_indirect_table_crudTests(self, tbl_name, tbl_ops,sw_conn)

    @pytest.mark.parametrize("tbl_ops", ["INSERT", "READ"])
    #@pytest.mark.parametrize("tbl_ops", ["DELETE"])
    @pytest.mark.parametrize("tc_name", ["test_traffic_l3_fwd_l3_ipv4_vrf_table"])
    def test_traffic_l3_fwd_l3_ipv4_vrf_table(self, tc_name, tbl_ops, sw_conn):
        p4_traffic_tc._test_traffic_l3_fwd_l3_ipv4_vrf_table(self,tc_name,tbl_ops,sw_conn)

    @pytest.mark.parametrize("tbl_ops", ["INSERT", "READ"])
    #@pytest.mark.parametrize("tbl_ops", ["DELETE"])
    @pytest.mark.parametrize("tc_name", ["test_subnet_traffic_l3_fwd_l3_ipv4_vrf_table"])
    def test_subnet_traffic_l3_fwd_l3_ipv4_vrf_table(self, tc_name, tbl_ops, sw_conn):
        p4_traffic_tc._test_traffic_l3_fwd_l3_ipv4_vrf_table(self,tc_name,tbl_ops,sw_conn)

    def test_p4_sanity(self,sw_conn):
        p4_san_tc._test_p4_sanity(sw_conn)

    def test_ElectionID(self,sw_conn):
        p4_san_tc._test_ElectionID()

    def test_existing_ElectionID(self,sw_conn):
        p4_san_tc._test_existing_ElectionID(sw_conn)
    
    def test_Master_change(self,sw_conn):
        p4_san_tc._test_Master_change(sw_conn)
    
    def test_Master_down(self,sw_conn):
        p4_san_tc._test_new_master_down()

    def test_nonZero_DeviceID(self,sw_conn):
        p4_san_tc._test_nonZero_DeviceID()

    def test_deviceID_ACC(self,sw_conn):
        p4_san_tc._test_deviceID_ACC()
    
    def test_Read_wTableId_Zero(self,sw_conn):
        p4_san_tc._test_Read_wTableId_Zero(sw_conn)

    @pytest.mark.parametrize("mode", ["INSERT", "DELETE"])
    def test_action_profile_members(self,mode,sw_conn):
        p4_apg_apm._test_action_profile_members(mode,sw_conn)
    
    def test_actionMem_Neg1(self,sw_conn):
        p4_apg_apm._test_actionMem_Neg1()

    def test_actionMem_Neg2(self,sw_conn):
        p4_apg_apm._test_actionMem_Neg2()

    def test_actionMem_Neg3(self,sw_conn):
        p4_apg_apm._test_actionMem_Neg3()

    @pytest.mark.parametrize("mode", ["INSERT", "MODIFY", "DELETE"])
    def test_action_profile_groups(self,mode,sw_conn):
        p4_apg_apm._test_action_profile_groups(self,mode,sw_conn)
    
    def test_batched_read_apg_apm(self,sw_conn):
        p4_apg_apm._test_batched_read_apg_apm(self,sw_conn)

    def test_negative_action_profile_groups_1(self,sw_conn):
        p4_apg_apm._test_negative_action_profile_groups_1(self,sw_conn)
    
    def test_negative_action_profile_groups_2(self,sw_conn):
        p4_apg_apm._test_negative_action_profile_groups_2(self,sw_conn)

    def test_negative_action_profile_groups_3(self,sw_conn):
        p4_apg_apm._test_negative_action_profile_groups_3(self,sw_conn)
    
    def test_negative_action_profile_groups_4(self,sw_conn):
        p4_apg_apm._test_negative_action_profile_groups_4(self,sw_conn)

    def test_negative_action_profile_groups_5(self,sw_conn):
        p4_apg_apm._test_negative_action_profile_groups_5(self,sw_conn)
    
    def test_negative_action_profile_groups_6(self,sw_conn):
        p4_apg_apm._test_negative_action_profile_groups_6(self,sw_conn)
    
    def test_negative_action_profile_groups_7(self,sw_conn):
        p4_apg_apm._test_negative_action_profile_groups_7(self,sw_conn)
    
    def test_negative_action_profile_groups_8(self,sw_conn):
        p4_apg_apm._test_negative_action_profile_groups_8(self,sw_conn)

    def test_negative_action_profile_groups_9(self,sw_conn):
        p4_apg_apm._test_negative_action_profile_groups_9(self,sw_conn)
    
    def test_negative_action_profile_groups_10(self,sw_conn):
        p4_apg_apm._test_negative_action_profile_groups_10(self)

    def test_writeInsert_Neg1(self,sw_conn):
        p4_san_tc._test_writeInsert_Neg1()
    
    def test_writeInsert_Neg2(self,sw_conn):
        p4_san_tc._test_writeInsert_Neg2()

    def test_writeModify_Neg1(self,sw_conn):
        p4_san_tc._test_writeModify_Neg1()

    def test_writeUpdnDel_Neg1(self,sw_conn):
        p4_san_tc._test_writeUpdnDel_Neg1()

    def test_setFrwding_Neg1(self):
        p4_san_tc._test_setFrwding_Neg1()

    def test_setFrwding_Act1(self):
        p4_san_tc._test_setFrwding_Act1()

    def test_setFwd_Opt1(self):
        p4_san_tc._test_setFwd_Opt1()

    def test_setFwd_Opt2(self):
        p4_san_tc._test_setFwd_Opt2()

    def test_setFwd_Opt3(self):
        p4_san_tc._test_setFwd_Opt3()

    def test_setFwd_Opt4(self):
        p4_san_tc._test_setFwd_Opt4()

    def test_getFwd_Neg1(self):
        p4_san_tc._test_getFwd_Neg1()

    def test_getFwd_Resp1(self):
        p4_san_tc._test_getFwd_Resp1()

    def test_multicontrollers_blocking_tableEdit(self):
        reset_p4()
        p4_san_tc._test_multicontrollers_blocking_tableEdit()

    def test_multicontrollers_non_blocking_tableEdit(self,sw_conn):
        reset_p4()
        p4_san_tc._test_multicontrollers_non_blocking_tableEdit()


    @pytest.mark.last
    def test_max_connections(self,sw_conn):
        reset_p4()
        p4_san_tc._test_max_connections()
