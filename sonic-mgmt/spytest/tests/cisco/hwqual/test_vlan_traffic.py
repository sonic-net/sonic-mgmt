#!/usr/bin/env python3
"""
test_vlan_traffic.py

Description:
    Platform agnostic test script to configure VLAN based snake traffic.
    This module provides functions to consume platform configuration from
    platform_snt_cfg.py and setup traffic streams for hardware qualification testing.

Author: Cisco Systems
Created: October 2025
Version: 1.0

Dependencies:
    - spytest framework
    - platform_snt_cfg.py (configuration file)

Usage:
    This module can be imported and used within the spytest framework for
    SNT (Snake Traffic) VLAN testing on Cisco platforms.
"""

import os
import re
import time
import pytest
import spytest
import apis.routing.ip as ipapi
import apis.system.port as papi
import apis.system.basic as basic_obj
import apis.system.interface as intapi
import apis.system.box_services as boxapi
import tests.cisco.hwqual.test_snt_bgp as snt_bgp
import tests.cisco.hwqual.test_hwqual_common as hwqual_common
from spytest import st, tgapi
from spytest.dicts import SpyTestDict
from tests.cisco.hwqual.platform_snt_cfg import platform_vrf_config
from tests.cisco.hwqual.platform_snt_cfg import get_platform_traffic_config
from apis.common.sonic_hooks import SonicHooks

@pytest.fixture(scope="module", autouse=True)
def snt_vlan_traffic_hooks(request):
    global TBDataG
    global CfgDataG

    TBDataG = st.get_testbed_vars()
    CfgDataG = SpyTestDict()

    CfgDataG.logprefix = "*** VLAN TRAFFIC *** :"
    CfgDataG.username = st.get_username(TBDataG.D1)
    CfgDataG.password = st.get_password(TBDataG.D1)
    CfgDataG.homedir = "/home/" + CfgDataG.username + "/"
    if 'D1T1P1' in TBDataG:
        CfgDataG.D1T1P1 = TBDataG['D1T1P1']
    else:
        CfgDataG.D1T1P1 = None

    if 'D1T1P2' in TBDataG:
        CfgDataG.D1T1P2 = TBDataG['D1T1P2']
    else:
        CfgDataG.D1T1P2 = None

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

def get_traffic_config(platform_id):
    """
    Get traffic configuration for a platform

    Args:
        platform_id (str): Platform identifier
        traffic_type (str): Specific traffic type ("fixed_traffic", "mixed_traffic", "killer_traffic")

    Returns:
        dict or list: Traffic configuration
    """
    platform_cfg = get_platform_config(platform_id)
    if not platform_cfg:
        return None
    CfgDataG.traffic_cfg_type = platform_cfg.get("traffic_cfg_type")
    traffic_cfg = get_platform_traffic_config(platform_id)

    # Return all traffic configurations
    return traffic_cfg

def get_io_ports(platform_id):
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

    default_cfg = platform_cfg.get("io_ports", {})
    tx_port = default_cfg.get("tx_port")
    rx_port = default_cfg.get("rx_port")

    return rx_port, tx_port

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

def get_platform_details(mgmt_ip):
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

# Initialize configuration data
def initialize_cfgdata():

    # Initialize Platform Details
    CfgDataG.dut = TBDataG.D1
    CfgDataG.mgmt_ipv4=TBDataG.get("mgmt_ipv4").get(CfgDataG.dut)

    # Retrieve DUT syseeprom info
    if get_platform_details(CfgDataG.mgmt_ipv4) is False:
        return False

    # Validate DUT ports
    if CfgDataG.D1T1P1 is None or CfgDataG.D1T1P2 is None:
        report_fail(f"{CfgDataG.logprefix} Missing IO_PORT information for PID:{CfgDataG.product_id}")
        return False

    # Retrieve platform configuration
    platform_cfg = get_platform_config(CfgDataG.product_id)
    if not platform_cfg:
        report_fail(f"{CfgDataG.logprefix} Missing platform_cfg information for PID:{CfgDataG.product_id}")
        return False

    CfgDataG.cfg_reload_timer = platform_cfg.get("cfg_reload_timer")
    CfgDataG.util = platform_cfg.get("util")

    # Initialize TGEN details
    CfgDataG.tg_handler = tgapi.get_handles(TBDataG, [TBDataG.T1D1P1, TBDataG.T1D1P2])
    CfgDataG.tg = CfgDataG.tg_handler["tg"]
    CfgDataG.tg_ph1 = CfgDataG.tg_handler["tg_ph_1"]
    CfgDataG.T1D1P1_mac= platform_cfg.get("tgenp1_mac")
    CfgDataG.tg_ph2 = CfgDataG.tg_handler["tg_ph_2"]
    CfgDataG.T1D1P2_mac= platform_cfg.get("tgenp2_mac")

    CfgDataG.is_ext_loop = hwqual_common.is_ext_loop_exist(CfgDataG)
    return True

def setup_dut_vlan_config(dut):

    # Check if Vlan10 with required interfaces exists
    if hwqual_common.is_vlan_configured(CfgDataG.dut, "Vlan10", CfgDataG.D1T1P1):
        st.log(f"{CfgDataG.logprefix} Target already configured for VLAN traffic")
        return True

    traffic_cfggen = "/opt/cisco/bin/traffic-cfggen.py"
    cmd = f"{traffic_cfggen} vlan -p -i {CfgDataG.D1T1P1} -o {CfgDataG.D1T1P2} -a"
    st.config(dut, cmd, max_time=1800)
    return True

def setup_tgen_interface_config():

    CfgDataG.tg.tg_traffic_control(
        action='reset',
        port_handle=[CfgDataG.tg_ph1, CfgDataG.tg_ph2]
    )

    #Configure tgen interface T1D1P1
    res1=CfgDataG.tg.tg_interface_config(
            port_handle=CfgDataG.tg_ph1,
            mode='config',
            src_mac_addr=CfgDataG.T1D1P1_mac
    )
    st.log("INTFCONF: "+str(res1))
    CfgDataG.tg_vlanh1 = res1['ethernet_handle']

    #Configure tgen interface T1D1P2
    res2=CfgDataG.tg.tg_interface_config(
            port_handle=CfgDataG.tg_ph2,
            mode='config',
            src_mac_addr=CfgDataG.T1D1P2_mac
    )
    st.log("INTFCONF: "+str(res2))
    CfgDataG.tg_vlanh2 = res2['ethernet_handle']
    return True

def verify_tgen_traffic_stats(k):

    traffic_drop = False
    ph1_traffic_stats = tgapi.get_traffic_stats(CfgDataG.tg, port_handle=CfgDataG.tg_ph1)
    ph2_traffic_stats = tgapi.get_traffic_stats(CfgDataG.tg, port_handle=CfgDataG.tg_ph2)
    if int(ph2_traffic_stats.rx.total_packets) < int(ph1_traffic_stats.tx.total_packets):
        pkt_loss = int(ph1_traffic_stats.tx.total_packets) - int(ph2_traffic_stats.rx.total_packets)
        report_fail(f" {CfgDataG.logprefix} Traffic drop {CfgDataG.D1T1P1} -> {CfgDataG.D1T1P2}:{CfgDataG.traffic_cfg_type}:{k} - {pkt_loss} packets")
        traffic_drop = True

    if int(ph1_traffic_stats.rx.total_packets) < int(ph2_traffic_stats.tx.total_packets):
        pkt_loss = int(ph2_traffic_stats.tx.total_packets) - int(ph1_traffic_stats.rx.total_packets)
        report_fail(f" {CfgDataG.logprefix} Traffic drop {CfgDataG.D1T1P2} -> {CfgDataG.D1T1P1}:{CfgDataG.traffic_cfg_type}:{k} - {pkt_loss} packets")
        traffic_drop = True

    if not traffic_drop:
        st.log(f" {CfgDataG.logprefix} No Traffic drop for {CfgDataG.traffic_cfg_type}:{k}")

def stop_tgen_traffic(k):
    st.log(f" {CfgDataG.logprefix} Stopping Traffic {CfgDataG.traffic_cfg_type}:{k}")
    CfgDataG.tg.tg_traffic_control(action='stop', handle=CfgDataG.stream_ids)
    time.sleep(15)

def run_tgen_traffic(k, v):

    # Prepare all streams for the traffic
    CfgDataG.stream_ids = []
    streams = v.get('streams')
    for stream in streams:
        #Configure tgen traffic stream
        res = CfgDataG.tg.tg_traffic_config(
            port_handle=CfgDataG.tg_ph1,
            mac_src=CfgDataG.T1D1P1_mac,
	    mac_dst=CfgDataG.T1D1P2_mac,
            rate_percent=CfgDataG.util,
            mode='create',
            l2_encap='ethernet_ii',
            length_mode=stream.get('length_mode'),
	    frame_size_min=stream.get('minframelength'),
	    frame_size_max=stream.get('maxframelength'),
	    transmit_mode='continuous'
        )
        CfgDataG.stream_ids.append(res['stream_id'])

        res = CfgDataG.tg.tg_traffic_config(
            port_handle=CfgDataG.tg_ph2,
            mac_src=CfgDataG.T1D1P2_mac,
	    mac_dst=CfgDataG.T1D1P1_mac,
            rate_percent=CfgDataG.util,
            mode='create',
            l2_encap='ethernet_ii',
            length_mode=stream.get('length_mode'),
	    frame_size_min=stream.get('minframelength'),
	    frame_size_max=stream.get('maxframelength'),
	    transmit_mode='continuous'
        )
        CfgDataG.stream_ids.append(res['stream_id'])

    result=CfgDataG.tg.tg_traffic_control(action='run', handle=CfgDataG.stream_ids)
    if not result:
        report_fail(f"{CfgDataG.logprefix} Traffic control for {CfgDataG.traffic_cfg_type}:{k} Failed")
        return False;
    else:
        st.log(f"{CfgDataG.logprefix} Traffic control for {CfgDataG.traffic_cfg_type}:{k} Success")

    st.log(f"{CfgDataG.logprefix} Running bidirectional traffic {CfgDataG.traffic_cfg_type}:{k} for {v.get('duration')}Sec")
    return True

def start_tgen_traffic():

    # Retrieve traffic_list for intended pid/traffic_type
    traffic_list = get_traffic_config(CfgDataG.product_id)
    if not len(traffic_list):
        report_fail(f"{CfgDataG.logprefix} No Valid traffic cfg for {CfgDataG.product_id}")
        return False


    for traffic_inst in traffic_list:
        # Check traffic config is not empty
        key = next(iter(traffic_inst), None)
        if key is not None:
            traffic_cfg = traffic_inst[key]
            if traffic_cfg is None:
                report_fail(f"{CfgDataG.logprefix} SNT traffic cfg not defined for {CfgDataG.traffic_cfg_type}:{key}")
                continue

            res = run_tgen_traffic(key, traffic_cfg)
            if not res:
                return False

            st.tg_wait(int(traffic_cfg.get('duration')))
            stop_tgen_traffic(key)
            verify_tgen_traffic_stats(key)

    return True

def install_hwqual_pkg():
    """
    Install hardware qual debian pkg
    """

    try:
        if not hwqual_common.deploy_hwqual_pkg(CfgDataG):
            return False
    except Exception as e:
        report_fail(f"{CfgDataG.logprefix} VLAN traffic test failed: {e}")
        return False

    return True

def test_vlan_traffic():
    """
    Main test function for VLAN traffic
    """
    st.log(f"{CfgDataG.logprefix} Starting VLAN traffic test")

    try:
        # Initialize VLAN configuration data
        if not initialize_cfgdata():
            report_fail(f"{CfgDataG.logprefix} VLAN initialize cfgdata failed")
            return False
        st.log(f"{CfgDataG.logprefix} VLAN initialize cfgdata success")

        if not install_hwqual_pkg():
            report_fail(f"{CfgDataG.logprefix} hwqual dpkg install failed")
            return False
        st.log(f"{CfgDataG.logprefix} hwqual dpkg install success")

        # Setup DUT VLAN configuration
        if not setup_dut_vlan_config(TBDataG.D1):
            report_fail(f"{CfgDataG.logprefix} Setup dut VLAN config Failed")
            return False
        st.log(f"{CfgDataG.logprefix} Setup dut VLAN config Success")

        # Setup traffic generator interface
        if not setup_tgen_interface_config():
            report_fail(f"{CfgDataG.logprefix} Tgen interface config Failed")
            return False
        st.log(f"{CfgDataG.logprefix} Tgen interface config Success")

        # Start traffic
        if not start_tgen_traffic():
            report_fail(f"{CfgDataG.logprefix} VLAN traffic test Failed")
            return False
        st.log(f"{CfgDataG.logprefix} VLAN traffic test completed successfully")
        st.report_pass(f"{CfgDataG.logprefix} Test Passed", CfgDataG.dut)

    except Exception as e:
        report_fail(f"{CfgDataG.logprefix} VLAN traffic test failed: {e}")
        return False

    return True

if __name__ == "__main__":
    test_snt_vlan_traffic()
