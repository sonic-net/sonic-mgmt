import json
import logging
import pytest

from datetime import datetime
from tests.ptf_runner import ptf_runner
from vnet_constants import CLEANUP_KEY, LOWER_BOUND_UDP_PORT_KEY, UPPER_BOUND_UDP_PORT_KEY
from vnet_utils import generate_dut_config_files_ecmp, safe_open_template, \
                       apply_dut_config_files, cleanup_dut_vnets, cleanup_vxlan_tunnels, cleanup_vnet_routes_ecmp

from tests.common.fixtures.ptfhost_utils import remove_ip_addresses, change_mac_addresses, \
                                                copy_arp_responder_py, copy_ptftests_directory
from tests.common.mellanox_data import is_mellanox_device as isMellanoxDevice

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("t0"),
    pytest.mark.sanity_check(post_check=True),
    #pytest.mark.asic("mellanox")
]

vlan_tagging_mode = ""

def test_vnet_vxlan_triggers_1(setup, duthosts, rand_one_dut_hostname, ptfhost, vnet_test_params, creds):
    """
    Test case for VNET VxLAN triggers.

    Args:
        setup: Pytest fixture that sets up PTF and DUT hosts
        vxlan_status: Parameterized pytest fixture used to test different VxLAN configurations
        duthost: DUT host object
        ptfhost: PTF host object
        vnet_test_params: Dictionary containing vnet test parameters
    """
    duthost = duthosts[rand_one_dut_hostname]
    vxlan_srcport_range_enabled =  get_vxlan_srcport_range_enabled(duthost)

    
