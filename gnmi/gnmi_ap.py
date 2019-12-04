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

class TestGnmi(GnmiApBase):

    def test_gnmi_GetTimestamp(self,stub):
        gnmi_san_tc._test_gnmi_GetTimestamp(stub)

    def test_gnmi_get(self,stub):
        gnmi_san_tc._test_gnmi_get(stub)

    def test_gnmi_Capability(self,stub):
        gnmi_san_tc._test_gnmi_Capability(stub)

    def test_gnmi_GetTimestamp(self,stub):
        gnmi_san_tc._test_gnmi_GetTimestamp(stub)

    def test_GetSet_Sanity1(self,stub):
        gnmi_san_tc._test_GetSet_Sanity1(stub)

