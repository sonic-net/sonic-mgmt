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


SWITCH_TO_HOST_PORT = 1
SWITCH_TO_SWITCH_PORT = 2

def _test_gnmi_Capability(stub):
    user = None
    password = None
    log.info('Performing CapabilitiesRequest to target \n')
    response = gnmiTestLib._cap(stub, user, password)
    #log.info('The CapabilitiesRequest response is below\n' + '-'*25 + '\n', response)
    log.info(response)
