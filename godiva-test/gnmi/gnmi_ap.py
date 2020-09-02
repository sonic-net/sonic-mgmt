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
from gnmi_base_ap import ApData, GnmiApBase
import marshal
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
import gnmi_sanity_tc as gnmi_san_tc

SWITCH_TO_HOST_PORT = 1
SWITCH_TO_SWITCH_PORT = 2
#os.environ['GRPC_TRACE'] = 'all'
#os.environ['GRPC_VERBOSITY'] = 'DEBUG'
os.environ['PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION'] = 'python'


@pytest.fixture(scope="session")
def stub():
    host_override = None
    target = ApData.svr_addr
    port = ApData.port_addr
    notls = True
    get_cert = None
    certs = None
    creds = gnmiTestLib._build_creds(target, port, get_cert, certs, notls)
    return gnmiTestLib._create_stub(creds,target,port,host_override)

@pytest.fixture(scope="session")
def gnmi_conn():
    gnmi_conn = gnmiTestLib.GnmiConnection(target=ApData.svr_addr,port=ApData.port_addr)
    return gnmi_conn

class TestGnmi(GnmiApBase):


    def test_set_unsup_payload_schema(self,stub):
        gnmi_san_tc._test_set_unsup_payload_schema(stub)

    def test_Neg_set_with_vld_del_inv_upd(self,stub):
        gnmi_san_tc._test_Neg_set_with_vld_del_inv_upd(stub)

    def test_set_with_mul_attr_val(self,stub):
        gnmi_san_tc._test_set_with_mul_attr_val(stub)

    def test_Path_with_keys(self,stub):
        gnmi_san_tc._test_Path_with_keys(stub)

    def test_Set_with_partial_val(self,stub):
        gnmi_san_tc._test_Set_with_partial_val(stub)

    def test_GetSet_OC_Components(self,stub):
        gnmi_san_tc._test_GetSet_OC_Components(stub)

    def test_SetReq_Del1(self,stub):
        gnmi_san_tc._test_SetReq_Del1(stub)

    @pytest.mark.parametrize("encoding", ["PROTO", "JSON_IETF"])
    def test_GetSet_Sanity1(self,stub,encoding):
        gnmi_san_tc._test_GetSet_Sanity1(stub,encoding)

    def test_gnmi_get(self,stub):
        gnmi_san_tc._test_gnmi_get(stub)

    def test_gnmi_Capability(self,stub):
        gnmi_san_tc._test_gnmi_Capability(stub)

    @pytest.mark.parametrize("encoding", ["PROTO", "JSON_IETF"])
    def test_get_at_root(self,stub,encoding):
        gnmi_san_tc._test_get_at_root(stub,encoding)

    @pytest.mark.parametrize("encoding", ["PROTO", "JSON_IETF"])
    def test_Get_with_prefix(self,stub,encoding):
        gnmi_san_tc._test_Get_with_prefix(stub,encoding)

    @pytest.mark.parametrize("encoding", ["PROTO", "JSON_IETF"])
    def test_Get_with_type(self,stub,encoding):
        gnmi_san_tc._test_Get_with_type(stub,encoding)

    @pytest.mark.parametrize("encoding", ["PROTO", "JSON_IETF"])
    def test_default_filter(self,stub,encoding):
        gnmi_san_tc._test_default_filter(stub,encoding)

    def test_Get_with_wrong_path(self,stub):
        gnmi_san_tc._test_Get_with_wrong_path(stub)

    def test_Get_with_wrong_encoding(self,stub):
        gnmi_san_tc._test_Get_with_wrong_encoding(stub)
    
    def test_set_unsup_payload(self,stub):
        gnmi_san_tc._test_set_unsup_payload(stub)
    
    def test_set_unsup_payload_schema(self,stub):
        gnmi_san_tc._test_set_unsup_payload_schema(stub)

    def test_gnmi_SetPfxPath(self,stub):
        gnmi_san_tc._test_gnmi_SetPfxPath(stub)

    def test_SetPfxPath_2node(self,stub):
        gnmi_san_tc._test_SetPfxPath_2node(stub)

    def test_MultiSet_Sanity1(self,stub):
        gnmi_san_tc._test_MultiSet_Sanity1(stub)

    def test_PfxPath_MSet1(self,stub):
        gnmi_san_tc._test_PfxPath_MSet1(stub)

    def test_Set_InvldPath1(self,stub):
        gnmi_san_tc._test_Set_InvldPath1(stub)

    def test_SetRpl_Omit1(self,stub):
        gnmi_san_tc._test_SetRpl_Omit1(stub)

    def test_Memory_Usage(self,stub):
        gnmi_san_tc._test_Memory_Usage(stub)
                
    def test_gnmi_intf_scale(self,gnmi_conn):
        gnmi_san_tc._test_gnmi_intf_scale(gnmi_conn)
    
    def test_parallel_set_get(self,gnmi_conn):
        gnmi_san_tc._test_parallel_set_get(gnmi_conn)

    @pytest.mark.parametrize("encoding", ["PROTO", "JSON_IETF"])
    def test_Set_wTgt(self,stub,encoding):
        gnmi_san_tc._test_Set_wTgt(stub,encoding)   

    def test_Tgt_in_NonPfx(self,stub):
        gnmi_san_tc._test_Tgt_in_NonPfx(stub) 

    def test_Path_with_slash(self,stub):
        gnmi_san_tc._test_Path_with_slash(stub)

    def test_PfxPath_with_slash(self,stub):
        gnmi_san_tc._test_PfxPath_with_slash(stub)

    @pytest.mark.parametrize("encoding", ["PROTO","JSON_IETF"])
    def test_MultiKey(self,stub,encoding):
        gnmi_san_tc._test_MultiKey(stub,encoding)

    @pytest.mark.parametrize("encoding", ["PROTO","JSON_IETF"])
    def test_PfxPath_with_MultiKey(self,stub,encoding):
        gnmi_san_tc._test_PfxPath_with_MultiKey(stub,encoding)

    def test_MultiSet_Mkey1(self,stub):
        gnmi_san_tc._test_MultiSet_Mkey1(stub)

    @pytest.mark.parametrize("encoding", ["PROTO", "JSON_IETF"])
    def test_multiple_target_get(self,encoding):
        gnmi_san_tc._test_multiple_target_get(encoding)

