# Cafy based Godiva Test
import pytest
import os
from framework.ap_base import ApBase
from logger.cafylog import CafyLog
from topology.topo_mgr.topo_mgr import Topology
from framework.pytest.cafy import Cafy
from topology.zap.zap import Zap

log = CafyLog("Godiva SFLOW AP")

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
    zap = Zap(test_input_file=input_file,topo_file=test_bed)
    sflow_feature_dict = zap.get_feature_configuration("sflow")
    uut = testbed.get_device(alias="UUT")
    uut_name = uut.name
    
    
class SflowApBase(ApBase):
    # SFLOW Base Variables
    ApData.svr_addr = ApData.sflow_feature_dict[ApData.uut_name]['svr_addr']
    log.info(ApData.svr_addr)
    #ApData.svr_addr = "host_b"
    ApData.port_addr = ApData.sflow_feature_dict[ApData.uut_name]['svr_port']
    ApData.gnmi_port_addr = ApData.sflow_feature_dict[ApData.uut_name]['svr_gnmi_port']
    ApData.proto_dump_file = ApData.sflow_feature_dict[ApData.uut_name]['proto_dump_file']
    ApData.input_conf_file = ApData.sflow_feature_dict['input_conf_file']
    ApData.sw_name = ApData.sflow_feature_dict[ApData.uut_name]['name']
    ApData.uname = ApData.sflow_feature_dict[ApData.uut_name]['username']
    ApData.pwd = ApData.sflow_feature_dict[ApData.uut_name]['password']


    # Port Configuration Variables
    

