# Cafy based Godiva Test
import pytest
import os
from framework.ap_base import ApBase
from logger.cafylog import CafyLog
from topology.topo_mgr.topo_mgr import Topology
from framework.pytest.cafy import Cafy
from topology.zap.zap import Zap
from topology.devices.device import Device
from topology.connection.linuxconnection import LinuxConnection

log = CafyLog("Godiva BSP")

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
    #gd_device = testbed.get_device(alias="R1")
    #handle = gd_device.get_handles()['vty']
    zap = Zap(test_input_file=input_file,topo_file=test_bed)
    gd_device=zap.devices['R1']
    gd_handle = gd_device.get_handles()['vty']
    bsp_feature_dict = zap.get_feature_configuration("bsp")  
    
class Bsp(ApBase):
    # P4 Base Variables
    ApData.svr_addr = ApData.bsp_feature_dict['R1']['svr_addr']
    ApData.port_addr = ApData.bsp_feature_dict['R1']['svr_port']
    ApData.sw_name = ApData.bsp_feature_dict['R1']['name']
    

class TestBsp(Bsp):

    def test_bsp_sanity(self):
        gd = ApData.gd_device
        gd.connect()
        gd.execute("sudo apt-get update\n")
        gd.execute("sudo apt-get -y install lm-sensors\n")
        gd.execute("sensors > sensors.txt\n")
        gd.disconnect()


