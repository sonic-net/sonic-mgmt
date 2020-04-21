# Cafy based Godiva Test
import pytest
import os
from framework.ap_base import ApBase
from logger.cafylog import CafyLog
from topology.topo_mgr.topo_mgr import Topology
from framework.pytest.cafy import Cafy
from topology.zap.zap import Zap

log = CafyLog("Godiva P4 AP")

class ApData:
    
    """
    Definition of ApData Class
    """

    testbed = None
    prefix = os.path.dirname(os.path.abspath(__file__))
    if CafyLog.topology_file:
        test_bed = CafyLog.topology_file
    else:
        test_bed = os.path.join(prefix,"gd_ap_topo.json")

    if CafyLog.test_input_file:
        input_file = CafyLog.test_input_file
    else:
        input_file = os.path.join(prefix,"gd_ap_input_file.json")
    testbed = Topology(topo_file=test_bed)
    uut = testbed.get_device(alias="UUT")
    uut_name = uut.name
    zap = Zap(test_input_file=input_file,topo_file=test_bed)
    p4_feature_dict = zap.get_feature_configuration("p4")

class P4ApBase(ApBase):
    # P4 Base Variables
    ApData.p4info = ApData.p4_feature_dict['p4info']
    ApData.p4json = ApData.p4_feature_dict['p4json']
    ApData.input_conf_file = ApData.p4_feature_dict['input_conf_file']
    ApData.svr_addr = ApData.p4_feature_dict[ApData.uut_name]['svr_addr']
    ApData.gnmi_port_addr = ApData.p4_feature_dict[ApData.uut_name]['svr_gnmi_port']
    ApData.port_addr = ApData.p4_feature_dict[ApData.uut_name]['svr_port']
    ApData.proto_dump_file = ApData.p4_feature_dict[ApData.uut_name]['proto_dump_file']
    ApData.device_id = ApData.p4_feature_dict[ApData.uut_name]['device_id']
    ApData.sw_name = ApData.p4_feature_dict[ApData.uut_name]['name']
    ApData.skip_set_pipeline = 0
    ApData.uname = ApData.p4_feature_dict[ApData.uut_name]['username']
    ApData.pwd = ApData.p4_feature_dict[ApData.uut_name]['password']
    ApData.ssh_port = ApData.p4_feature_dict[ApData.uut_name]['ssh_port']
    # Port Configuration Variables

