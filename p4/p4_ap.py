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

SWITCH_TO_HOST_PORT = 1
SWITCH_TO_SWITCH_PORT = 2

class TestP4(P4ApBase):

    def test_p4_sanity(self):
        p4_san_tc._test_p4_sanity()

    def test_ElectionID(self):
        p4_san_tc._test_ElectionID()

    def test_existing_ElectionID(self):
        p4_san_tc._test_existing_ElectionID()
    
    def test_Master_change(self):
        p4_san_tc._test_Master_change()

    def test_max_connections(self):
        p4_san_tc._test_max_connections()    

    def test_nonZero_DeviceID(self):
        p4_san_tc._test_nonZero_DeviceID()

    def test_deviceID_ACC(self):
        p4_san_tc._test_deviceID_ACC()

    def test_multicontrollers_blocking_tableEdit(self):
        p4_san_tc._test_multicontrollers_blocking_tableEdit()

    def test_multicontrollers_non_blocking_tableEdit(self):
        p4_san_tc._test_multicontrollers_non_blocking_tableEdit()