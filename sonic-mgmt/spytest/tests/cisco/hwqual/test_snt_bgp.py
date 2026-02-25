#!/usr/bin/env python3
"""
test_snt_bgp.py - System Network Test (SNT) BGP Route Advertisement Test Suite

Copyright (c) 2025 Cisco Systems, Inc. All rights reserved.

Description:
    Platform-agnostic test script for BGP route advertisement testing in VRF-based 
    network environments. This module provides comprehensive BGP prefix advertisement 
    validation for Cisco hardware qualification testing, supporting various platform 
    configurations and route scale testing scenarios.

    The test suite validates BGP route advertisement functionality by:
    - Configuring BGP sessions between traffic generator and DUT
    - Advertising configurable numbers of IPv4 prefixes
    - Verifying route acceptance and propagation
    - Supporting multiple platform variants with different route scales

Test Scope:
    - BGP Route Advertisement (IPv4)
    - VRF-based BGP Configuration
    - Route Scale Validation (100K-300K routes)
    - Multi-Platform Support
    - Hardware Qualification Testing

Configuration Files:
    - platform_snt_cfg.py: Platform-specific BGP and network parameters
    - hwqual-bgp.sh: DUT BGP configuration script
    - Hardware qualification debian packages

Network Topology:
    Traffic Generator Port 1 <---BGP---> DUT Port 1 (VRF Vrf0)
    
    BGP Session Parameters:
    - eBGP peering with configurable ASNs
    - IPv4 unicast address family
    - 4-byte ASN support
    - Graceful restart enabled

Exit Codes:
    0: All tests passed successfully
    1: Test failures detected
    2: Configuration errors
    3: Platform not supported
"""

import os
import re
import time
import pytest
import spytest
import apis.routing.ip as ipapi
import apis.routing.bgp as bgpapi
import apis.system.port as papi
import apis.system.basic as basic_obj
import apis.system.interface as intapi
import apis.system.box_services as boxapi
import tests.cisco.hwqual.test_hwqual_common as hwqual_common
from spytest import st, tgapi
from spytest.dicts import SpyTestDict
from tests.cisco.hwqual.platform_snt_cfg import platform_vrf_config
from tests.cisco.hwqual.platform_snt_cfg import get_platform_bgp_route_config
from apis.common.sonic_hooks import SonicHooks

@pytest.fixture(scope="module", autouse=True)
def snt_bgp_prefix_hooks(request):
    global TBDataG
    global CfgDataG

    TBDataG = st.get_testbed_vars()
    CfgDataG = SpyTestDict()

    CfgDataG.logprefix = "*** SNT BGP *** :"
    CfgDataG.username = st.get_username(TBDataG.D1)
    CfgDataG.password = st.get_password(TBDataG.D1)
    CfgDataG.homedir = "/home/" + CfgDataG.username

    yield

    CfgDataG.tg.clean_all()


def get_platform_config(platform_id):
    """
    Retrieve configuration for a specific platform from platform_vrf_config

    Args:
        platform_id (str): Platform identifier (e.g., "8101-32FH-O")

    Returns:
        dict: Platform configuration or None if not found
    """
    try:
        platforms = platform_vrf_config.get("platforms", {})
        return platforms.get(platform_id)
    except Exception as e:
        st.error(f"{CfgDataG.logprefix} Failed to get platform config for {platform_id}: {e}")
        return None

def get_bgp_route_config(CfgDataG):
    """
    Get bgp route configuration for a platform

    Args:
        platform_id (str): Platform identifier
        bgp_route_type (str): Specific traffic type ("snt_ipv4_300k", "snt_ipv4_100k")

    Returns:
        dict or list: bgp route configuration
    """
    platform_cfg = get_platform_config(CfgDataG.product_id)
    if not platform_cfg:
        return None
    CfgDataG.bgp_route_cfg_type = platform_cfg.get("bgp_route_cfg_type")
    bgp_route_cfg = get_platform_bgp_route_config(CfgDataG.product_id)

    # Return all bgp route configurations
    return bgp_route_cfg

def get_default_ports(platform_id):
    """
    Get default TX/RX ports for a platform

    Args:
        platform_id (str): Platform identifier

    Returns:
        tuple: (tx_port, rx_port) or (None, None) if not found
    """
    platform_cfg = get_platform_config(platform_id)
    if not platform_cfg:
        return None, None

    default_cfg = platform_cfg.get("default", {})
    tx_port = default_cfg.get("tx_port")
    rx_port = default_cfg.get("rx_port")

    return tx_port, rx_port

def report_fail(msg=''):
    st.error(msg)
    st.report_fail('test_case_failed', msg)

def parse_syseeprom_field(syseeprom_output, field_name):
    """
    Generic function to parse any field from syseeprom output

    Args:
        syseeprom_output (str): Raw syseeprom command output
        field_name (str): Name of the field to extract (e.g., "Product Name", "Serial Number")

    Returns:
        str: Field value or None if not found
    """
    if not syseeprom_output or not field_name:
        return None

    # Split output into lines
    lines = syseeprom_output.strip().split('\n')

    # Look for the specified field
    for line in lines:
        # Remove extra whitespace and split by multiple spaces
        parts = re.split(r'\s{2,}', line.strip())

        # Check if this line contains the field
        if len(parts) >= 3 and parts[0] == field_name:
            # Return the value (last part)
            return parts[-1]

    return None

def get_dut_details(mgmt_ip):
    """
    Get comprehensive platform details from syseeprom

    Args:
        mgmt_ip (str): Management IP address

    Returns:
        dict: Platform details
    """
    try:
        syseeprom_out = st.config(CfgDataG.dut, "show platform syseeprom")
        CfgDataG.product_id = parse_syseeprom_field(syseeprom_out, "Product Name")
        CfgDataG.dut_base_mac = parse_syseeprom_field(syseeprom_out, "Base MAC Address")
        details = {
            'product_name': parse_syseeprom_field(syseeprom_out, "Product Name"),
            'part_number': parse_syseeprom_field(syseeprom_out, "Part Number"),
            'serial_number': parse_syseeprom_field(syseeprom_out, "Serial Number"),
            'platform_name': parse_syseeprom_field(syseeprom_out, "Platform Name"),
            'manufacturer': parse_syseeprom_field(syseeprom_out, "Manufacturer"),
        }

        st.log(f"{CfgDataG.logprefix} Platform details: {details}")
        return True

    except Exception as e:
        report_fail(f"{CfgDataG.logprefix} Error getting platform details: {e}")
        return False

def extract_accepted_prefixes(bgp_output):
    """
    Extract the number of accepted prefixes from BGP neighbor output

    Args:
        bgp_output (str): BGP show command output

    Returns:
        dict: Dictionary containing accepted prefixes info or None if not found
    """
    try:
        # Search for the line containing "accepted prefixes"
        accepted_prefixes_pattern = r'(\d+)\s+accepted\s+prefixes'
        match = re.search(accepted_prefixes_pattern, bgp_output, re.IGNORECASE)

        if match:
            accepted_count = int(match.group(1))
            return {
                'accepted_prefixes': accepted_count,
                'line': match.group(0),
                'found': True
            }
        else:
            return {
                'accepted_prefixes': None,
                'line': None,
                'found': False,
                'error': 'accepted prefixes line not found'
            }

    except Exception as e:
        return {
            'accepted_prefixes': None,
            'line': None,
            'found': False,
            'error': f'Error parsing output: {e}'
        }

def verify_prefix_adv(CfgDataG):

    # Retrieve bgp_route_list for intended pid
    bgp_route_cfg = get_bgp_route_config(CfgDataG)
    if bgp_route_cfg is None:
        report_fail(f"{CfgDataG.logprefix} No Valid bgp route cfg for {CfgDataG.product_id}")
        return False

    route_list = bgp_route_cfg.get("routes")
    num_routes = 0
    for routes in route_list:
        num_routes += routes.get("num_routes")

    cmd = "show ip bgp vrf Vrf0 neighbors"
    output = st.config(CfgDataG.dut, cmd)
    ret = extract_accepted_prefixes(output)
    if (ret.get("accepted_prefixes") == num_routes):
        st.log(f"{CfgDataG.logprefix}: ConfiguredRoutes({num_routes}) == AdvertisedRoutes({ret.get('accepted_prefixes')})")
    else:
        st.log(f"{CfgDataG.logprefix}: ConfiguredRoutes({num_routes}) != AdvertisedRoutes({ret.get('accepted_prefixes')})")
        report_fail(f"{CfgDataG.logprefix}: AdvertisedRoutes({ret.get('accepted_prefixes')}) != ConfiguredRoutes({num_routes})")
    return True

def start_prefix_adv(CfgDataG):

    # Retrieve bgp_route_list for intended pid
    bgp_route_cfg = get_bgp_route_config(CfgDataG)
    if bgp_route_cfg is None:
        report_fail(f"{CfgDataG.logprefix} No Valid bgp route cfg for {CfgDataG.product_id}")
        return False

    #Prefix advertisement from TGEN towards DUT 
    st.banner(f"{CfgDataG.logprefix} Prefix advertisement from TGEN towards DUT")
    route_list = bgp_route_cfg.get("routes")
    for routes in route_list:
        bgp_route = CfgDataG.tg.tg_emulation_bgp_route_config(
                    handle=CfgDataG.tg_ph1_bgp, 
                    mode='add',
                    num_routes=routes.get("num_routes"),
                    prefix=routes.get("prefix"))
        st.log(f"{CfgDataG.logprefix}: Advertising {routes.get('num_routes')} routes from {routes.get('prefix')}")
        CfgDataG.tg.tg_emulation_bgp_control(handle=CfgDataG.tg_ph1_bgp, mode='start')
        st.wait(15)

    return True


def setup_tgen_bgp_config(CfgDataG):

    #Configuring BGP on TGEN-T1D1P1 towards DUT-D1T1P1
    st.banner(f"{CfgDataG.logprefix} Configuring BGP on TGEN-T1D1P1 towards DUT-D1T1P1 port")
    tg_ph1_bgp = CfgDataG.tg.tg_emulation_bgp_config(
                    handle=CfgDataG.tg_ipv4h1,
                    mode='enable', 
                    active_connect_enable='1',
                    local_as=CfgDataG.T1D1P1_asn, 
                    remote_as=CfgDataG.D1T1P1_asn, 
                    remote_ip_addr=CfgDataG.D1T1P1_ipv4,
                    enable_4_byte_as='1', 
                    graceful_restart_enable='1')
    CfgDataG.tg_ph1_bgp = tg_ph1_bgp['handle'] 

    #Starting BGP on TGEN
    CfgDataG.tg.tg_emulation_bgp_control(handle=CfgDataG.tg_ph1_bgp, mode='start')
    st.wait(5)
    return True

def setup_tgen_interface_config():

    CfgDataG.tg.tg_traffic_control(
        action='reset',
        #port_handle=[CfgDataG.tg_ph1, CfgDataG.tg_ph2]
        port_handle=[CfgDataG.tg_ph1]
    )

    #Configure tgen interface T1D1P1
    res1=CfgDataG.tg.tg_interface_config(
            port_handle=CfgDataG.tg_ph1,
            mode='config',
            intf_ip_addr=CfgDataG.T1D1P1_ipv4,
            gateway=CfgDataG.D1T1P1_ipv4,
            src_mac_addr=CfgDataG.T1D1P1_mac,
            arp_send_req='1'
    )
    st.log("INTFCONF: "+str(res1))
    CfgDataG.tg_ipv4h1 = res1['ipv4_handle']

    #Configure tgen interface T1D1P2
    #res2=CfgDataG.tg.tg_interface_config(
    #        port_handle=CfgDataG.tg_ph2,
    #        mode='config',
    #        intf_ip_addr=CfgDataG.T1D1P2_ipv4,
    #        gateway=CfgDataG.D1T1P2_ipv4,
    #        src_mac_addr=CfgDataG.T1D1P2_mac,
    #        arp_send_req='1'
    #)
    #st.log("INTFCONF: "+str(res2))
    return True

def setup_dut_bgp_config(CfgDataG):

    bgp_config = "/opt/cisco/bin/hwqual-bgp.sh"
    st.config(CfgDataG.dut, bgp_config, max_time=1800)
    return True

def install_hwqual_pkg(CfgDataG):
    """
    Install hardware qual debian pkg
    """

    try:
        if not hwqual_common.deploy_hwqual_pkg(CfgDataG):
            return False
    except Exception as e:
        report_fail(f"{CfgDataG.logprefix}: HardwareQual Deb Pkg deployment failed: {e}")
        return False

    #st.tg_wait(CfgDataG.cfg_reload_timer)
    return True

def initialize_bgp_cfgdata(CfgDataG, plt_cfg):

    CfgDataG.D1T1P1_asn = plt_cfg.get('dutp1_asn')
    #CfgDataG.D1T1P2_asn = plt_cfg.get('dutp2_asn')
    CfgDataG.T1D1P1_asn = plt_cfg.get('tgenp1_asn')
    #CfgDataG.T1D1P2_asn = plt_cfg.get('tgenp2_asn')

# Initialize configuration data
def initialize_cfgdata():

    # Initialize Platform Details
    CfgDataG.dut = TBDataG.D1
    CfgDataG.mgmt_ipv4=TBDataG.get("mgmt_ipv4").get(CfgDataG.dut)
    if get_dut_details(CfgDataG.mgmt_ipv4) is False:
        return False

    platform_cfg = get_platform_config(CfgDataG.product_id)

    CfgDataG.D1T1P1_ipv4 = platform_cfg.get('dutp1_ipv4')
    #CfgDataG.D1T1P2_ipv4 = platform_cfg.get('dutp2_ipv4')

    # Initialize TGEN details
    #CfgDataG.tg_handler = tgapi.get_handles(TBDataG, [TBDataG.T1D1P1, TBDataG.T1D1P2])
    CfgDataG.tg_handler = tgapi.get_handles(TBDataG, [TBDataG.T1D1P1])
    CfgDataG.tg = CfgDataG.tg_handler["tg"]
    CfgDataG.tg_ph1 = CfgDataG.tg_handler["tg_ph_1"]
    #CfgDataG.tg_ph2 = CfgDataG.tg_handler["tg_ph_2"]

    CfgDataG.T1D1P1_ipv4 = platform_cfg.get('tgenp1_ipv4')
    #CfgDataG.T1D1P2_ipv4 = platform_cfg.get('tgenp2_ipv4')

    CfgDataG.T1D1P1_mac= platform_cfg.get('tgenp1_mac')
    #CfgDataG.T1D1P2_mac= platform_cfg.get('tgenp2_mac')

    initialize_bgp_cfgdata(CfgDataG, platform_cfg)

    return True

def pre_action_bgp_route_adv(CfgDataG, TBDataG):

    try:
        platform_cfg = get_platform_config(CfgDataG.product_id)
        initialize_bgp_cfgdata(CfgDataG, platform_cfg)

        # Setup DUT BGP configuration
        if not setup_dut_bgp_config(CfgDataG):
            report_fail(f"{CfgDataG.logprefix} Setup dut VRF config Failed")
            return False
        st.log(f"{CfgDataG.logprefix} Setup dut BGP config Success")

        # Setup traffic generator BGP config
        if not setup_tgen_bgp_config(CfgDataG):
            report_fail(f"{CfgDataG.logprefix} Tgen BGP config Failed")
            return False
        st.log(f"{CfgDataG.logprefix} Tgen BGP config Success")

    except Exception as e:
        report_fail(f"{CfgDataG.logprefix} pre_action_bgp_adv failed: {e}")
        return False

    return True

def inline_action_bgp_route_adv(CfgDataG, TBDataG):

    try:
        # Start Prefix advertisement
        if not start_prefix_adv(CfgDataG):
            report_fail(f"{CfgDataG.logprefix} BGP prefix adv start Failed")
            return False
        st.log(f"{CfgDataG.logprefix} BGP prefix adv test started successfully")

        # Verify Prefix advertisement
        if not verify_prefix_adv(CfgDataG):
            report_fail(f"{CfgDataG.logprefix} BGP prefix adv test Failed")
            return False
    except Exception as e:
        report_fail(f"{CfgDataG.logprefix} inline_action_bgp_route_adv failed: {e}")
        return False

    return True
    
def test_bgp_prefix_adv():
    """
    Main test function for BGP Prefix advertisement
    """
    st.log(f"{CfgDataG.logprefix} Starting BGP prefix adv test")

    try:
        # Initialize configuration data
        if not initialize_cfgdata():
            report_fail(f"{CfgDataG.logprefix} initialize cfgdata failed")
            return False
        st.log(f"{CfgDataG.logprefix} initialize cfgdata success")

        if not install_hwqual_pkg(CfgDataG):
            report_fail(f"{CfgDataG.logprefix} hwqual dpkg install failed")
            return False
        st.log(f"{CfgDataG.logprefix} hwqual dpkg install success")

        # Setup traffic generator interface
        if not setup_tgen_interface_config():
            report_fail(f"{CfgDataG.logprefix} Tgen interface config Failed")
            return False
        st.log(f"{CfgDataG.logprefix} Tgen interface config Success")

        # Setup DUT BGP configuration
        if not setup_dut_bgp_config(CfgDataG):
            report_fail(f"{CfgDataG.logprefix} Setup dut VRF config Failed")
            return False
        st.log(f"{CfgDataG.logprefix} Setup dut VRF config Success")

        # Setup traffic generator BGP config
        if not setup_tgen_bgp_config(CfgDataG):
            report_fail(f"{CfgDataG.logprefix} Tgen interface config Failed")
            return False
        st.log(f"{CfgDataG.logprefix} Tgen interface config Success")

        # Start Prefix advertisement
        if not start_prefix_adv(CfgDataG):
            report_fail(f"{CfgDataG.logprefix} BGP prefix adv start Failed")
            return False

        # Verify Prefix advertisement
        if not verify_prefix_adv(CfgDataG):
            report_fail(f"{CfgDataG.logprefix} BGP prefix adv test Failed")
            return False

        st.log(f"{CfgDataG.logprefix} BGP prefix adv test completed successfully")
        st.report_pass(f"{CfgDataG.logprefix} Test Passed ")

    except Exception as e:
        report_fail(f"{CfgDataG.logprefix} BGP prefix adv test failed: {e}")
        return False

    return True

if __name__ == "__main__":
    test_bgp_prefix_adv()
