# Cafy based Godiva Test
import pytest
import os
from framework.ap_base import ApBase
from logger.cafylog import CafyLog
from topology.topo_mgr.topo_mgr import Topology
from framework.pytest.cafy import Cafy
from topology.zap.zap import Zap

log = CafyLog("Godiva GNMI AP")

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
    gnmi_feature_dict = zap.get_feature_configuration("gnmi")  
    
class GnmiApBase(ApBase):
    # GNMI Base Variables
    ApData.svr_addr = ApData.gnmi_feature_dict[ApData.uut_name]['svr_addr']
    ApData.port_addr = ApData.gnmi_feature_dict[ApData.uut_name]['svr_port']
    ApData.input_conf_file = ApData.gnmi_feature_dict['input_conf_file']

    # Port Configuration Variables
    

