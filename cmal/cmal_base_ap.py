# Cafy based Godiva Test
import pytest
import os
from framework.ap_base import ApBase
from logger.cafylog import CafyLog
from topology.topo_mgr.topo_mgr import Topology
from framework.pytest.cafy import Cafy
from topology.zap.zap import Zap

log = CafyLog("Godiva AP")

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
    cmal_feature_dict = zap.get_feature_configuration("cmal")  
    
class CMALApBase(ApBase):
    # CMAL Base Variables
    ApData.lock_id = ApData.cmal_feature_dict['R1']['lock_id']
    ApData.config_name = ApData.cmal_feature_dict['R1']['config_name']
    ApData.copy_overwrite = ApData.cmal_feature_dict['R1']['copy_overwrite']
    ApData.svr_addr = ApData.cmal_feature_dict['R1']['svr_addr']
    ApData.port_addr = ApData.cmal_feature_dict['R1']['svr_port']
    ApData.chassis_id_name = ApData.cmal_feature_dict['R1']['chassis_id_name']
    ApData.node_id = ApData.cmal_feature_dict['R1']['node_id']['name']
    ApData.default_port_params_profile = ApData.cmal_feature_dict['R1']['default_port_params_profile']

    # Port Configuration Variables
    

