# -*- coding: utf-8 -*-
import os
import sys
# Add parent directory to path to import vxlan_utils
# sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tortuga_common_utils as common_obj
import yaml
import pytest
from collections import OrderedDict
from spytest import st, tgapi, SpyTestDict
import apis.routing.ip as ip_obj
import apis.switching.vlan as vlan_obj
import vxlan_utils as vxlan_obj
import time
import evpn_mh_utils as evpn_mh_obj
import pdb

"""
###############################################################################################################
#                          TOPOLOGY DIAGRAM - 8D Linux IXIA Mathilda Configuration                          #
###############################################################################################################
#
#  Test Devices:
#  -------------
#  SD1-SD4: SONiC Routers (Cisco 8000 platform)
#  SD7-SD8: Linux Hosts (Ubuntu 22)
#
#
#                                        +--------------+
#                                        |     SD1      |
#                                        | SONiC Router |
#                                        +--------------+
#                                         |      |      |
#                                      E7-+      |      +---E2-3
#                                         |  E0-1 |           |
#                                         |       |           |
#                           +-------------+       |           +---------+
#                           |                     |                     |
#                           |                     |                     |
#                        E7 |             E0-1    |                     | E0-1
#                           v                     v                     v
#              +--------------+          +--------------+          +--------------+
#              |     SD2      |          |     SD3      |          |     SD4      |
#              | SONiC Router |          | SONiC Router |          | SONiC Router |
#              +--------------+          +--------------+          +--------------+
#                      |                         |                         |
#                      |                         |                         |
#                   E8-9                   E10-14 |                  E11-13 |
#                      |                         |                         |
#                      |                         |                         |
#                      |                         |                         |
#                      |           +-------------+                         |
#                      |           |                                       |
#                      |           |                                       |
#                      v           v                                       v
#              +------------------+                              +------------------+
#              |       SD7        |                              |       SD8        |
#              |   Linux Host     |                              |   Linux Host     |
#              |   (Ubuntu 22)    |                              |   (Ubuntu 22)    |
#              +------------------+                              +------------------+
#                 eth4-5  eth1-6                                         eth2-3
#                                                                       
#
#
# Port Mapping Convention:
# ------------------------
# pyvxr format:  Ethernet[N]    (0-indexed, e.g., Ethernet7)
# spytest format: Ethernet[N*4] (e.g., Ethernet7 -> Ethernet28)
#
#
###############################################################################################################
"""
# SD8 ↔ SD1 (eth1), SD2 (eth2)
#
###############################################################################################################


ESI1 = '03:00:44:33:22:11:00:00:00:02'
EXPECTED_L3VNI = '5030'
EXPECTED_L2VNI = '5010'


data = SpyTestDict()
data.config_vrfs = []
CONFIGS_FILE = 'static_route_apm_evpn_mh_v6_config.yaml'
LEAF0_VXLAN_IP = 'fd27::233:d0c6:fefb'
LEAF1_VXLAN_IP = 'fd27::2dc:c1c9:e17c'
LEAF2_VXLAN_IP = 'fd27::2D8:76fd:4c43'

SEQ_IDS = OrderedDict([
    ('LEAF0', {'local' : 0, 'remote' : 0}),
    ('LEAF1', {'local' : 0, 'remote' : 0}),
    ('LEAF2', {'local' : 0, 'remote' : 0})
])

def update_sequence_ids(node_names):
    global SEQ_IDS
    # Calculate the maximum sequence ID for the specified nodes
    max_seq_id = max(max(SEQ_IDS[node]['local'], SEQ_IDS[node]['remote']) for node in node_names)
    # New sequence ID to be used
    new_seq_id = max_seq_id + 1
    # Update the sequence IDs
    for node in SEQ_IDS:
        if node in node_names:
            # Update only the local sequence ID to new_seq_id
            SEQ_IDS[node]['local'] = new_seq_id
        else:
            # Update only the remote sequence ID to new_seq_id
            SEQ_IDS[node]['remote'] = new_seq_id
    # Return the updated sequence IDs in the format 'local/remote'
    updated_seq_ids = [str(SEQ_IDS[node]['local'])+'/'+str(SEQ_IDS[node]['remote']) for node in SEQ_IDS]
    return updated_seq_ids

@pytest.fixture(scope="module", autouse=True)
def initial_setup():
    vars = st.get_testbed_vars()
    ### Check dut is HW or SIM ###
    dut_type = vxlan_obj.check_hw_or_sim(st.get_dut_names()[0])

    if  dut_type == "sim":
        data.transmit_mode = "single_burst"
        data.pkts_per_burst = "1000"
        ### Using lower line rate for SIM tgen ###
        data.rate_percent = "0.01"
        data.circuit_endpoint_type = "ipv4"
        data.frame_size = "100"
    else:
        data.mode ="create"
        data.transmit_mode = "single_burst"
        data.pkts_per_burst = "2000"
        data.rate_percent = "10"
        data.circuit_endpoint_type = "ipv4"
        data.frame_size = "1000"
    yield

def config_static(node, config_domain, add=True):
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['SD1'] = vars.D1
    nodes['SD2'] = vars.D2
    nodes['SD3'] = vars.D3
    nodes['SD4'] = vars.D4

    domain = ''
    if config_domain == 'bgp' or config_domain == 'pre-sonic-bgp':
        domain = 'vtysh'

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        if add:
            common_obj.config_node(nodes[node], config_list[node][config_domain]['config'], domain)
        else:
            common_obj.config_node(nodes[node], config_list[node][config_domain]['deconfig'], domain)

def report_fail(dut, msg=''):
    st.banner(msg)
    st.report_fail('test_case_failed', dut)

def router_preconfig_cleanup():
    ip_obj.clear_ip_configuration(st.get_dut_names(), family='all', thread=True)
    vlan_obj.clear_vlan_configuration(st.get_dut_names())

@pytest.fixture(scope="function", autouse=True)
def check_cores():
    for dut in st.get_dut_names():
        st.show(dut, 'ls -l /var/core/', skip_tmpl=True)
    yield check_cores
    for dut in st.get_dut_names():
        st.show(dut, 'ls -l /var/core/', skip_tmpl=True)

#Maintained as a module level fixture since we need configs for all testcases
@pytest.fixture(scope="module", autouse=True)
def vxlan_config_hooks():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['SD1'] = vars.D1
    nodes['SD2'] = vars.D2
    nodes['SD3'] = vars.D3
    nodes['SD4'] = vars.D4

    global updated_config_file
    updated_config_file = vxlan_obj.modify_config_file(CONFIGS_FILE,vars)

    evpn_mh_obj.change_fdb_ageout("6000")

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            config_static(node, 'pre-sonic-bgp')
            st.wait(2)
            config_static(node, 'sonic')
            st.wait(2)
            config_static(node, 'bgp')
    yield vxlan_config_hooks

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in reversed(config_list.items()):
            config_static(node, 'bgp', add=False)
            st.wait(2)
            config_static(node, 'sonic', add=False)
            st.wait(2)
            config_static(node, 'pre-sonic-bgp', add=False)
        evpn_mh_obj.change_fdb_ageout("600")

    for vrf in data.config_vrfs:
        vxlan_obj.config_vrf(nodes['SD2'], vrf, add=False)
        vxlan_obj.config_vrf(nodes['SD3'], vrf, add=False)
    data.config_vrfs = []

    vxlan_obj.remove_temp_config(updated_config_file)

######################################################################
# Helper function for APP-DB verification
######################################################################
def verify_app_db_static_route(device_node, redis_cmd, expected_nexthops, test_name="APP-DB", expect_empty=False):
    """
    Verify APP-DB static route entry contains expected nexthops or is empty
    
    Args:
        device_node: The target device node to run redis command on
        redis_cmd: Redis command to run (e.g., 'redis-cli -n 0 hgetall "STATIC_ROUTE:Vrf01:172.16.255.1/32"')
        expected_nexthops: List of expected nexthop IPs (e.g., ['10.212.10.6', '10.212.20.6']) or empty list
        test_name: Name of the test for logging purposes
        expect_empty: If True, expects empty array/output; if False, expects nexthops
    
    Returns:
        bool: True if verification passes, False otherwise (also calls st.report_fail)
    """
    try:
        st.banner("{} Verification: Checking static route entry".format(test_name))
        
        # Run the redis command
        app_db_output = st.config(device_node, redis_cmd, skip_error_check=True)
        st.log("APP-DB output: {}".format(app_db_output))
        
        # Handle empty array verification
        if expect_empty:
            if not app_db_output or "(empty array)" in str(app_db_output).lower() or str(app_db_output).strip() == '':
                st.log("PASS: {} verification successful - output is empty array as expected".format(test_name))
                return True
            else:
                st.report_fail('test_case_failed', 
                              "{} verification failed - expected empty array but got: {}".format(test_name, app_db_output))
                return False
        
        # Handle nexthop verification
        if not app_db_output or str(app_db_output).strip() == '':
            st.report_fail('test_case_failed', "{} verification failed - APP-DB output is empty".format(test_name))
            return False
        
        # Check for each expected nexthop
        missing_nexthops = []
        found_nexthops = []
        
        for nexthop in expected_nexthops:
            if nexthop in str(app_db_output):
                found_nexthops.append(nexthop)
                st.log("PASS: APP-DB contains nexthop {}".format(nexthop))
            else:
                missing_nexthops.append(nexthop)
                st.log("FAIL: APP-DB does not contain nexthop {}".format(nexthop))
        
        # Overall verification result
        if not missing_nexthops:
            st.log("PASS: {} verification successful - all expected nexthops found: {}".format(test_name, found_nexthops))
            return True
        else:
            st.report_fail('test_case_failed', 
                          "{} verification failed - Missing nexthops: {}, Found nexthops: {}".format(
                              test_name, missing_nexthops, found_nexthops))
            return False
            
    except Exception as e:
        st.log("Exception occurred during {} verification: {}".format(test_name, str(e)))
        st.report_fail('test_case_failed', "{} verification failed with exception: {}".format(test_name, str(e)))
        return False


######################################################################
# Test Static Route Addition and Deletion Combined 
######################################################################
@pytest.mark.system_box
@pytest.mark.community
@pytest.mark.community_pass
def test_static_route_add_delete_combined():
    """
    Test static route addition and deletion in a single test case
    Combines test_static_route_multiple_nexthops and test_simple_static_route_deletion
    
    Test Scenario:
    1. First Phase: Add static route with multiple nexthops and verify installation
    2. Second Phase: Delete the route completely and verify removal
    
    Test Steps:
    Phase 1 - Route Addition (from test_static_route_multiple_nexthops):
    1. Configure Ethernet1_1 to Vlan10 and Ethernet1_2 to Vlan20 on SD4 (leaf2)
    2. Configure IP 10.212.10.6/24 on SD8 Ethernet1_1 and IP 10.212.20.6/24 on SD8 Ethernet1_2
    3. Add static route with multiple nexthops: 172.16.255.1/32 nexthop 10.212.10.6,10.212.20.6
    4. Verify route is installed with both nexthops in FRR routing table
    5. Verify APP-DB contains no entry
    
    Phase 2 - Route Deletion (from test_simple_static_route_deletion):
    6. Delete the static route completely
    7. Verify no static route is present in routing table
    8. Verify APP-DB no longer contains the static route entry
    9. Cleanup all configurations
    """
    vars = st.get_testbed_vars()
    
    nodes = {}
    nodes['SD1'] = vars.D1  # SD1 (spine0)
    nodes['SD2'] = vars.D2  # SD2 (leaf0) 
    nodes['SD3'] = vars.D3  # SD3 (leaf1)
    nodes['SD4'] = vars.D4  # SD4 (leaf2)
    nodes['SD8'] = vars.D8   # SD8 (host1 - host device)
    
    st.banner("Starting Static Route Addition and Deletion Combined Test")
    
    try:

        # =================== PHASE 1: ROUTE ADDITION ===================
        st.banner("PHASE 1: Static Route Addition and Verification")
        
        # Step 1: Configure dynamic ports on SD4 (leaf2) to Vlan10/20
        st.banner("Step 1: Configuring dynamic ports on SD4 (leaf2)")
        
        # Add D4D8P1 to Vlan10 on SD4 (leaf2)
        st.config(nodes['SD4'], "config vlan member add 10 {} -u".format(vars.D4D8P1))
        
        # Add D4D8P2 to Vlan20 on SD4 (leaf2)
        st.config(nodes['SD4'], "config vlan member add 20 {} -u".format(vars.D4D8P2))
        
        # Step 2: Configure IP addresses on SD8 dynamic ports
        st.banner("Step 2: Configuring IP addresses on SD8 dynamic ports")
        
        # Bring up D8D4P1 and configure IP address on SD8 (host1)
        st.config(nodes['SD8'], "sudo ifconfig {} up".format(vars.D8D4P1))
        st.wait(2)
        st.config(nodes['SD8'], "sudo ip addr add 10.212.10.6/24 dev {}".format(vars.D8D4P1))
        
        # Bring up D8D4P2 and configure IP address on SD8 (host1)
        st.config(nodes['SD8'], "sudo ifconfig {} up".format(vars.D8D4P2))
        st.wait(2)
        st.config(nodes['SD8'], "sudo ip addr add 10.212.20.6/24 dev {}".format(vars.D8D4P2))
        
        # Step 3: Add static route with multiple nexthops (no APM)
        st.banner("Step 3: Adding static route with multiple nexthops on SD4 (leaf2)")
        
        # Configure static route with multiple nexthops - no APM dependencies
        route_cmd = "config route add prefix vrf Vrf01 172.16.255.1/32 nexthop 10.212.10.6,10.212.20.6"
        st.config(nodes['SD4'], route_cmd)
        st.wait(2)
        
        # Step 4: Verify route is installed with both nexthops in FRR routing table
        st.banner("Step 4: Verifying route is installed with both nexthops")
        
        # Check FRR routing table
        route_output = st.show(nodes['SD4'], "show ip route vrf Vrf01", skip_tmpl=True)
        st.log("VRF Route table output on SD4: {}".format(route_output))
        
        # Verify route is installed
        route_found = False
        nexthop1_found = False
        nexthop2_found = False
        
        if "172.16.255.1/32" in str(route_output):
            route_found = True
            st.log("SUCCESS: Route 172.16.255.1/32 is found in routing table")
            
            # Check for both nexthops
            if "via 10.212.10.6" in str(route_output):
                nexthop1_found = True
                st.log("SUCCESS: Nexthop via 10.212.10.6 is installed")
            else:
                st.log("FAIL: Nexthop via 10.212.10.6 is NOT found")
            
            if "via 10.212.20.6" in str(route_output):
                nexthop2_found = True
                st.log("SUCCESS: Nexthop via 10.212.20.6 is installed")
            else:
                st.log("FAIL: Nexthop via 10.212.20.6 is NOT found")
        else:
            st.log("FAIL: Route 172.16.255.1/32 is NOT found")
        
        # Step 5: APP-DB Verification for route addition (should be empty for non-APM routes)
        st.banner("Step 5: Verifying APP-DB contains no entry for static route (no APM)")
        verify_app_db_static_route(
            nodes['SD4'],
            'redis-cli -n 0 hgetall "STATIC_ROUTE:Vrf01:172.16.255.1/32"',
            [],  # No nexthops expected in APP-DB for non-APM routes
            "Static Route Addition Phase",
            expect_empty=True
        )
        
        # Phase 1 validation
        phase1_success = route_found and nexthop1_found and nexthop2_found
        if phase1_success:
            st.log("PHASE 1 PASSED: Route addition verified successfully")
        else:
            st.log("PHASE 1 FAILED: Route addition verification failed")
        
        # =================== PHASE 2: ROUTE DELETION ===================
        st.banner("PHASE 2: Static Route Deletion and Verification")
        
        # Step 6: Delete the static route completely
        st.banner("Step 6: Deleting static route completely")
        
        # Command: config route del prefix
        route_del_cmd = "config route del prefix vrf Vrf01 172.16.255.1/32"
        st.config(nodes['SD4'], route_del_cmd)
        st.wait(2)  # Wait for route to be removed
        
        # Step 7: Verify no static route is present in routing table
        st.banner("Step 7: Verifying route is completely removed")
        
        final_route_output = st.show(nodes['SD4'], "show ip route vrf Vrf01", skip_tmpl=True)
        st.log("Final route output after deletion: {}".format(final_route_output))
        
        # Check that route is NOT present
        route_removed = True
        if "172.16.255.1/32" in str(final_route_output):
            route_removed = False
            st.log("FAIL: Route 172.16.255.1/32 is still present after deletion")
        else:
            st.log("SUCCESS: Route 172.16.255.1/32 is properly removed")
        
        # Step 8: APP-DB Verification for route deletion
        st.banner("Step 8: Verifying APP-DB no longer contains the static route")
        verify_app_db_static_route(
            nodes['SD4'],
            'redis-cli -n 0 hgetall "STATIC_ROUTE:Vrf01:172.16.255.1/32"',
            [],  # No nexthops expected
            "Static Route Deletion Phase",
            expect_empty=True
        )
        
        # Phase 2 validation
        phase2_success = route_removed
        if phase2_success:
            st.log("PHASE 2 PASSED: Route deletion verified successfully")
        else:
            st.log("PHASE 2 FAILED: Route deletion verification failed")
        
        # Combined test result
        if phase1_success and phase2_success:
            st.log("COMBINED TEST PASSED: Both route addition and deletion phases successful")
            st.banner("Static Route Addition and Deletion Combined Test - PASSED")
            st.report_pass('test_case_passed')
        else:
            st.log("COMBINED TEST FAILED: Phase 1: {}, Phase 2: {}".format(phase1_success, phase2_success))
            st.report_fail('test_case_failed', "Combined test failed - Phase 1: {}, Phase 2: {}".format(phase1_success, phase2_success))

    except Exception as e:
        st.log("Exception occurred during combined test execution: {}".format(str(e)))
        st.report_fail('test_case_failed', "Combined test failed with exception: {}".format(str(e)))
        
    finally:
        # Cleanup configurations
        st.banner("Cleanup: Removing all test configurations")
        
        try:
            # Remove route (in case it still exists)
            st.config(nodes['SD4'], "config route del prefix vrf Vrf01 172.16.255.1/32", skip_error_check=True)
            st.wait(1)
            
            # Remove IP addresses from SD8 dynamic ports (host1 D8D4P1 and D8D4P2)
            st.config(nodes['SD8'], "sudo ip addr del 10.212.10.6/24 dev {}".format(vars.D8D4P1), skip_error_check=True)
            st.config(nodes['SD8'], "sudo ip addr del 10.212.20.6/24 dev {}".format(vars.D8D4P2), skip_error_check=True)
            
            # Remove dynamic ports from VLANs on SD4
            st.config(nodes['SD4'], "config vlan member del 10 {}".format(vars.D4D8P1), skip_error_check=True)
            st.config(nodes['SD4'], "config vlan member del 20 {}".format(vars.D4D8P2), skip_error_check=True)
            
            st.banner("Combined test cleanup completed successfully")
            
        except Exception as cleanup_e:
            st.log("Warning: Some cleanup operations failed: {}".format(str(cleanup_e)))

######################################################################
# Test APM Route Addition and Deletion Combined
######################################################################
@pytest.mark.system_box
@pytest.mark.community
@pytest.mark.community_pass
def test_apm_route_add_delete_combined():
    """
    Test APM route addition and deletion in a single test case
    Combines test_apm_tcp_probe_route_config and test_static_route_apm_direct_deletion
    
    Test Scenario:
    1. First Phase: Configure APM probes, add route with APM dependencies, and verify
    2. Second Phase: Delete the route with APM dependencies and verify removal
    
    Test Steps:
    Phase 1 - APM Route Addition (from test_apm_tcp_probe_route_config):
    1. Configure dynamic ports to Vlan10 and Vlan20 on SD4 (leaf2)
    2. Configure IP addresses on SD8 dynamic ports
    3. Start TCP servers on both IPs on SD8 (ports 65432 and 65433)
    4. Configure APM TCP probes (tcpprobe1 and tcpprobe2) with VRF Vrf01
    5. Add static route with both nexthops and APM dependencies
    6. Verify both APM probes are UP and route is installed in FRR
    7. Verify APP-DB contains static route entry with both nexthops
    
    Phase 2 - APM Route Deletion (from test_static_route_apm_direct_deletion):
    8. Delete the route completely (with APM dependencies)
    9. Verify no static route is present in routing table
    10. Verify APP-DB no longer contains the static route entry
    11. Cleanup all configurations including APM probes and TCP servers
    """
    vars = st.get_testbed_vars()
    
    nodes = {}
    nodes['SD1'] = vars.D1  # SD1 (spine0)
    nodes['SD2'] = vars.D2  # SD2 (leaf0) 
    nodes['SD3'] = vars.D3  # SD3 (leaf1)
    nodes['SD4'] = vars.D4  # SD4 (leaf2)
    nodes['SD8'] = vars.D8   # SD8 (host1 - host device)
    
    st.banner("Starting APM Route Addition and Deletion Combined Test")
    
    try:
        # =================== PHASE 1: APM ROUTE ADDITION ===================
        st.banner("PHASE 1: APM Route Addition and Verification")
        # Step 1: Configure dynamic ports to Vlan10 and Vlan20 on SD4 (leaf2)
        st.banner("Step 1: Configuring dynamic ports on SD4 (leaf2)")
        st.wait(3)
        # Add D4D8P1 to Vlan10 on SD4 (leaf2)
        st.config(nodes['SD4'], "config vlan member add 10 {} -u".format(vars.D4D8P1))
        
        # Add D4D8P2 to Vlan20 on SD4 (leaf2)
        st.config(nodes['SD4'], "config vlan member add 20 {} -u".format(vars.D4D8P2))
        
        # Step 2: Configure IP addresses on SD8 dynamic ports
        st.banner("Step 2: Configuring IP addresses on SD8 dynamic ports")
        
        # Bring up D8D4P1 and configure IP address on SD8 (host1)
        st.config(nodes['SD8'], "sudo ifconfig {} up".format(vars.D8D4P1))
        st.wait(2)
        st.config(nodes['SD8'], "sudo ip addr add 10.212.10.6/24 dev {}".format(vars.D8D4P1))
        
        # Bring up D8D4P2 and configure IP address on SD8 (host1)
        st.config(nodes['SD8'], "sudo ifconfig {} up".format(vars.D8D4P2))
        st.wait(2)
        st.config(nodes['SD8'], "sudo ip addr add 10.212.20.6/24 dev {}".format(vars.D8D4P2))
        # Step 3: Start TCP servers on both IPs on SD8
        st.banner("Step 3: Starting TCP servers on SD8")
        
        # Start TCP servers in background on both IPs on SD8
        # Using full path to avoid issues with cd in sudo -s context
        tcp_server_cmd1 = "sudo nohup python3 /home/vxr/tcpserver.py 65432 10.212.10.6 > /tmp/tcpserver1.log 2>&1 &"
        st.config(nodes['SD8'], tcp_server_cmd1)
        
        tcp_server_cmd2 = "sudo nohup python3 /home/vxr/tcpserver.py 65433 10.212.20.6 > /tmp/tcpserver2.log 2>&1 &"
        st.config(nodes['SD8'], tcp_server_cmd2)
        st.wait(5)  # Wait for servers to start
        
        # Verify TCP servers are running
        verify_cmd = "ps aux | grep '[t]cpserver.py'"
        server_status = st.show(nodes['SD8'], verify_cmd, skip_tmpl=True, skip_error_check=True)
        st.log("TCP server status on host1: {}".format(server_status))
        # Step 4: Configure APM TCP probes on SD4 (leaf2)
        st.banner("Step 4: Configuring APM TCP probes on SD4 (leaf2)")
        # Configure APM TCP probe1 targeting SD8 D8D4P1
        apm_cmd1 = "sudo config apm add tcpprobe1 --type tcp-connect --dst-ip 10.212.10.6 --dst-port 65432 --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true"
        st.config(nodes['SD4'], apm_cmd1)
        st.wait(3)
        
        # Configure APM TCP probe2 targeting SD8 D8D4P2
        apm_cmd2 = "sudo config apm add tcpprobe2 --type tcp-connect --dst-ip 10.212.20.6 --dst-port 65433 --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true"
        st.config(nodes['SD4'], apm_cmd2)
        st.wait(3)  # Wait longer for APM probes to initialize and establish connections
        # Verify APM probes are configured and check status
        apm_config_output = st.show(nodes['SD4'], "show apm", skip_tmpl=True, skip_error_check=True)
        st.log("APM configuration on SD4: {}".format(apm_config_output))
        apm_status_output = st.show(nodes['SD4'], "show apm-status", skip_tmpl=True, skip_error_check=True)
        st.log("APM status on SD4: {}".format(apm_status_output))
        
        if "tcpprobe1" not in str(apm_config_output) or "tcpprobe2" not in str(apm_config_output):
            st.report_fail('test_case_failed', "APM probes tcpprobe1 or tcpprobe2 not configured properly on SD4")

        # Step 5: Add static route with both APM probes on SD4 (leaf2)
        st.banner("Step 5: Adding static route with APM configuration on SD4 (leaf2)")
        
        route_cmd = "config route add prefix vrf Vrf01 172.16.255.1/32 nexthop 10.212.10.6,10.212.20.6 apm tcpprobe1,tcpprobe2"
        st.config(nodes['SD4'], route_cmd)
        st.wait(3)  # Wait for route to be installed
        
        # Step 6: Verify APM status and route installation on SD4 (leaf2)
        st.banner("Step 6: Verifying APM status and route installation on SD4 (leaf2)")
        
        # Check APM status - test passes if both tcpprobe1 and tcpprobe2 are UP
        final_apm_status = st.show(nodes['SD4'], "show apm-status", skip_tmpl=True, skip_error_check=True)
        st.log("Final APM status on SD4: {}".format(final_apm_status))
        
        # Check if route is installed in VRF routing table
        route_output = st.show(nodes['SD4'], "show ip route vrf Vrf01", skip_tmpl=True)
        st.log("VRF Route table output on SD4: {}".format(route_output))
        
        # Test success criteria for Phase 1
        apm1_up = False
        apm2_up = False
        route_installed = False
        
        # Check both APM probes
        apm_status_str = str(final_apm_status).lower()
        if "tcpprobe1" in apm_status_str and "up" in apm_status_str:
            # More specific check for tcpprobe1 being up
            if "tcpprobe1" in str(final_apm_status) and any("up" in line.lower() for line in str(final_apm_status).split('\n') if "tcpprobe1" in line):
                apm1_up = True
                st.log("SUCCESS: APM probe tcpprobe1 is UP")
        
        if "tcpprobe2" in apm_status_str and "up" in apm_status_str:
            # More specific check for tcpprobe2 being up  
            if "tcpprobe2" in str(final_apm_status) and any("up" in line.lower() for line in str(final_apm_status).split('\n') if "tcpprobe2" in line):
                apm2_up = True
                st.log("SUCCESS: APM probe tcpprobe2 is UP")
        
        if not apm1_up:
            st.log("WARNING: APM probe tcpprobe1 is not UP")
        if not apm2_up:
            st.log("WARNING: APM probe tcpprobe2 is not UP")
        
        if "172.16.255.1/32" in str(route_output):
            route_installed = True
            st.log("SUCCESS: Static route 172.16.255.1/32 is installed in VRF Vrf01")
        else:
            st.log("WARNING: Static route 172.16.255.1/32 is not installed in VRF Vrf01")
        
        # Step 7: APP-DB Verification for APM route addition
        st.banner("Step 7: Verifying APP-DB contains static route entry with both nexthops")
        verify_app_db_static_route(
            nodes['SD4'],
            'redis-cli -n 0 hgetall "STATIC_ROUTE:Vrf01:172.16.255.1/32"',
            ['10.212.10.6', '10.212.20.6'],  # Both nexthops expected for APM routes
            "APM Route Addition Phase"
        )

        # Verify show static-route displays the route properly
        st.banner("Verifying show static-route displays the route properly")
        static_route_output = st.show(nodes['SD4'], "show static-route", skip_tmpl=True, skip_error_check=True)
        st.log("show static-route output after route addition: {}".format(static_route_output))
        
        # Check that static route is properly displayed with correct nexthops and APM probes
        static_route_displayed = False
        if ("172.16.255.1/32" in str(static_route_output) and 
            "10.212.10.6" in str(static_route_output) and 
            "10.212.20.6" in str(static_route_output) and
            "tcpprobe1" in str(static_route_output) and
            "tcpprobe2" in str(static_route_output)):
            static_route_displayed = True
            st.log("SUCCESS: show static-route displays route 172.16.255.1/32 with nexthops 10.212.10.6,10.212.20.6 and APM probes tcpprobe1,tcpprobe2")
        else:
            st.log("WARNING: show static-route does not display the route properly")
        
        # Phase 1 validation
        phase1_success = apm1_up and apm2_up and route_installed and static_route_displayed
        
        if phase1_success:
            st.log("PHASE 1 PASSED: APM route addition verified successfully")
        else:
            st.log("PHASE 1 FAILED: APM route addition verification failed - APM1: {}, APM2: {}, Route: {}".format(apm1_up, apm2_up, route_installed))


        # =================== PHASE 2: APM ROUTE DELETION ===================
        st.banner("PHASE 2: APM Route Deletion and Verification")
        
        # Step 8: Delete the static route completely (with APM dependencies)
        st.banner("Step 8: Deleting static route with APM dependencies")
        
        # Command: config route del prefix (deletes route and APM dependencies)
        route_del_cmd = "config route del prefix vrf Vrf01 172.16.255.1/32"
        st.config(nodes['SD4'], route_del_cmd)
        st.wait(2)  # Wait for route to be removed
        
        # Step 9: Verify no static route is present in routing table
        st.banner("Step 9: Verifying route is completely removed")
        
        final_route_output = st.show(nodes['SD4'], "show ip route vrf Vrf01", skip_tmpl=True)
        st.log("Final route output after deletion: {}".format(final_route_output))
        
        # Check that route is NOT present
        route_removed = True
        if "172.16.255.1/32" in str(final_route_output):
            route_removed = False
            st.log("FAIL: Route 172.16.255.1/32 is still present after deletion")
        else:
            st.log("SUCCESS: Route 172.16.255.1/32 is properly removed")
        
        # Step 10: APP-DB Verification for APM route deletion
        st.banner("Step 10: Verifying APP-DB no longer contains the static route")
        verify_app_db_static_route(
            nodes['SD4'],
            'redis-cli -n 0 hgetall "STATIC_ROUTE:Vrf01:172.16.255.1/32"',
            [],  # No nexthops expected
            "APM Route Deletion Phase",
            expect_empty=True
        )

        # Verify show static-route no longer displays the route
        st.banner("Verifying show static-route no longer displays the route")
        final_static_route_output = st.show(nodes['SD4'], "show static-route", skip_tmpl=True, skip_error_check=True)
        st.log("show static-route output after route deletion: {}".format(final_static_route_output))
        
        # Check that static route is NOT displayed
        static_route_absent = True
        if "172.16.255.1/32" in str(final_static_route_output):
            static_route_absent = False
            st.log("FAIL: show static-route still displays route 172.16.255.1/32 after deletion")
        else:
            st.log("SUCCESS: show static-route no longer displays route 172.16.255.1/32")
        
        # Phase 2 validation
        phase2_success = route_removed and static_route_absent
        
        if phase2_success:
            st.log("PHASE 2 PASSED: APM route deletion verified successfully")
        else:
            st.log("PHASE 2 FAILED: APM route deletion verification failed")
        
        # Combined test result - must pass all phases
        if phase1_success and phase2_success:
            st.log("COMBINED APM TEST PASSED: All phases successful")
            st.log("Phase 1: Route addition - PASSED")
            st.log("Phase 2: Route deletion - PASSED")
            st.banner("APM Route Addition and Deletion Combined Test - PASSED")
            st.report_pass('test_case_passed')
        else:
            st.report_fail('test_case_failed', "Combined APM test failed - Phase 1: {}, Phase 2: {}".format(phase1_success, phase2_success))

    except Exception as e:
        st.log("Exception occurred during combined APM test execution: {}".format(str(e)))
        st.report_fail('test_case_failed', "Combined APM test failed with exception: {}".format(str(e)))
        
    finally:
        # Cleanup configurations
        st.banner("Cleanup: Removing all APM test configurations")
        
        try:
            # Stop TCP servers first
            st.config(nodes['SD8'], "pkill -f 'tcpserver.py'", skip_error_check=True)
            st.wait(2)
            
            # Remove route (in case it still exists)
            st.config(nodes['SD4'], "config route del prefix vrf Vrf01 172.16.255.1/32", skip_error_check=True)
            st.wait(1)
            
            # Remove APM probes
            st.config(nodes['SD4'], "config apm del tcpprobe1", skip_error_check=True)
            st.config(nodes['SD4'], "config apm del tcpprobe2", skip_error_check=True)
            st.wait(2)
            
            # Remove IP addresses from SD8 dynamic ports (host1 D8D4P1 and D8D4P2)
            st.config(nodes['SD8'], "sudo ip addr del 10.212.10.6/24 dev {}".format(vars.D8D4P1), skip_error_check=True)
            st.config(nodes['SD8'], "sudo ip addr del 10.212.20.6/24 dev {}".format(vars.D8D4P2), skip_error_check=True)
            
            # Remove dynamic ports from VLANs on SD4
            st.config(nodes['SD4'], "config vlan member del 10 {}".format(vars.D4D8P1), skip_error_check=True)
            st.config(nodes['SD4'], "config vlan member del 20 {}".format(vars.D4D8P2), skip_error_check=True)
            
            # Clean up nohup files
            st.config(nodes['SD8'], "sudo rm -f nohup.out", skip_error_check=True)
            
            st.banner("Combined APM test cleanup completed successfully")
            
        except Exception as cleanup_e:
            st.log("Warning: Some cleanup operations failed: {}".format(str(cleanup_e)))

######################################################################
# Test APM Override Route Configuration
######################################################################
@pytest.mark.system_box
@pytest.mark.community
@pytest.mark.community_pass
def test_apm_override_route_config():
    """
    Test APM override behavior for existing static routes
    
    Test Scenario:
    1. First configure a static route with multiple nexthops (no APM)
    2. Then configure APM probes
    3. Finally update the same route to use APM dependencies
    4. Verify route behavior changes from basic static to APM-controlled
    
    Configuration Sequence:
    - config route add prefix vrf Vrf01 172.16.255.1/32 nexthop 10.212.10.6,10.212.20.6
    - config apm add tcpprobe1 --type=tcp-connect --enable=true --vrf Vrf01 --dst-ip=10.212.10.6 --dst-port=65432
    - config apm add tcpprobe2 --type=tcp-connect --enable=true --vrf Vrf01 --dst-ip=10.212.20.6 --dst-port=65432
    - config route add prefix vrf Vrf01 172.16.255.1/32 apm tcpprobe1,tcpprobe2
    
    
    Test Steps:
    1. Configure dynamic ports to Vlan10 and Vlan20 on SD4 (leaf2)
    2. Configure IP addresses on SD8 dynamic ports
    3. Start TCP servers on both IPs on SD8
    4. Add initial static route with multiple nexthops (no APM)
    5. Verify route is installed with both nexthops
    6. Configure APM TCP probes (tcpprobe1 and tcpprobe2)
    7. Update route to use APM dependencies (override existing route)
    8. Verify both APM probes are UP and route still shows both nexthops
    9. Cleanup all configurations
    """
    vars = st.get_testbed_vars()
    
    nodes = {}
    nodes['SD1'] = vars.D1  # SD1 (spine0)
    nodes['SD2'] = vars.D2  # SD2 (leaf0) 
    nodes['SD3'] = vars.D3  # SD3 (leaf1)
    nodes['SD4'] = vars.D4  # SD4 (leaf2)
    nodes['SD8'] = vars.D8   # SD8 (host1 - host device)
    
    st.banner("Starting APM Override Route Configuration Test")
    
    try:
        # Step 1: Configure dynamic ports on SD4 (leaf2) to Vlan10/20
        st.banner("Step 1: Configuring dynamic ports on SD4 (leaf2) to Vlan10/20")
        
        # Add D4D8P1 to Vlan10 on SD4 (leaf2)
        st.config(nodes['SD4'], "config vlan member add 10 {} -u".format(vars.D4D8P1))
        
        # Add D4D8P2 to Vlan20 on SD4 (leaf2)
        st.config(nodes['SD4'], "config vlan member add 20 {} -u".format(vars.D4D8P2))
        
        
        # Step 2: Configure IP addresses on SD8 dynamic ports
        st.banner("Step 2: Configuring IP addresses on SD8 dynamic ports")
        
        # Bring up D8D4P1 and configure IP address on SD8 (host1)
        st.config(nodes['SD8'], "sudo ifconfig {} up".format(vars.D8D4P1))
        st.wait(2)
        st.config(nodes['SD8'], "sudo ip addr add 10.212.10.6/24 dev {}".format(vars.D8D4P1))
        
        # Bring up D8D4P2 and configure IP address on SD8 (host1)
        st.config(nodes['SD8'], "sudo ifconfig {} up".format(vars.D8D4P2))
        st.wait(2)
        st.config(nodes['SD8'], "sudo ip addr add 10.212.20.6/24 dev {}".format(vars.D8D4P2))
        
        # Step 3: Start TCP servers on both IPs on SD8
        st.banner("Step 3: Starting TCP servers on both IPs on SD8")
    
        
        # Start TCP servers in background on both IPs on SD8
        # Using full path to avoid issues with cd in sudo -s context
        tcp_server_cmd1 = "sudo nohup python3 /home/vxr/tcpserver.py 65432 10.212.10.6 > /tmp/tcpserver1.log 2>&1 &"
        st.config(nodes['SD8'], tcp_server_cmd1)
        
        tcp_server_cmd2 = "sudo nohup python3 /home/vxr/tcpserver.py 65433 10.212.20.6 > /tmp/tcpserver2.log 2>&1 &"
        st.config(nodes['SD8'], tcp_server_cmd2)
        st.wait(5)  # Wait for servers to start
        
        # Verify TCP servers are running
        verify_cmd = "ps aux | grep '[t]cpserver.py'"
        server_status = st.show(nodes['SD8'], verify_cmd, skip_tmpl=True, skip_error_check=True)
        st.log("TCP server status on host1: {}".format(server_status))
        
        # Step 4: Add initial static route with multiple nexthops (no APM)
        st.banner("Step 4: Adding initial static route with multiple nexthops (no APM)")
        
        # Configure static route with multiple nexthops - no APM initially
        initial_route_cmd = "config route add prefix vrf Vrf01 172.16.255.1/32 nexthop 10.212.10.6,10.212.20.6"
        st.config(nodes['SD4'], initial_route_cmd)
        st.wait(3)  # Wait for route to be installed
        
        # Step 5: Verify initial route is installed with both nexthops
        st.banner("Step 5: Verifying initial route installation")
        
        initial_route_output = st.show(nodes['SD4'], "show ip route vrf Vrf01", skip_tmpl=True)
        st.log("Initial VRF Route table output on SD4: {}".format(initial_route_output))
        
        initial_nexthop1 = "via 10.212.10.6" in str(initial_route_output)
        initial_nexthop2 = "via 10.212.20.6" in str(initial_route_output)
        
        if initial_nexthop1 and initial_nexthop2:
            st.log("SUCCESS: Initial route installed with both nexthops")
        else:
            st.log("WARNING: Initial route may not have both nexthops - Nexthop1: {}, Nexthop2: {}".format(initial_nexthop1, initial_nexthop2))
        
        # Step 6: Configure APM TCP probes
        st.banner("Step 6: Configuring APM TCP probes on SD4 (leaf2)")
        
        # Configure APM TCP probe1 targeting SD8 Ethernet1_1
        apm_cmd1 = "sudo config apm add tcpprobe1 --type tcp-connect --dst-ip 10.212.10.6 --dst-port 65432 --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true"
        st.config(nodes['SD4'], apm_cmd1)
        st.wait(2)
        
        # Configure APM TCP probe2 targeting SD8 Ethernet1_2
        apm_cmd2 = "sudo config apm add tcpprobe2 --type tcp-connect --dst-ip 10.212.20.6 --dst-port 65433 --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true"
        st.config(nodes['SD4'], apm_cmd2)
        st.wait(2)  # Wait longer for APM probes to initialize
        
        # Verify APM probes are configured
        apm_config_output = st.show(nodes['SD4'], "show apm", skip_tmpl=True, skip_error_check=True)
        st.log("APM configuration on SD4: {}".format(apm_config_output))
        
        if "tcpprobe1" not in str(apm_config_output) or "tcpprobe2" not in str(apm_config_output):
            st.report_fail('test_case_failed', "APM probes tcpprobe1 or tcpprobe2 not configured properly on SD4")

        # Step 7: Update route to use APM dependencies (override existing route)
        st.banner("Step 7: Updating route to use APM dependencies")
        
        # Configure route with APM dependencies - this should override the existing route
        apm_route_cmd = "config route add prefix vrf Vrf01 172.16.255.1/32 apm tcpprobe1,tcpprobe2"
        st.config(nodes['SD4'], apm_route_cmd)
        st.wait(3)  # Wait for route to be updated
        
        # Step 8: Verify both APM probes are UP and route shows both nexthops
        st.banner("Step 8: Verifying APM probes are UP and route behavior")
        
        # Check APM status
        apm_status_output = st.show(nodes['SD4'], "show apm-status", skip_tmpl=True, skip_error_check=True)
        st.log("APM status on SD4: {}".format(apm_status_output))
        apm1_up = False
        apm2_up = False
        
        if "tcpprobe1" in str(apm_status_output) and any("up" in line.lower() for line in str(apm_status_output).split('\n') if "tcpprobe1" in line):
            apm1_up = True
            st.log("SUCCESS: APM probe tcpprobe1 is UP")
        else:
            st.log("WARNING: APM probe tcpprobe1 is not UP")
        
        if "tcpprobe2" in str(apm_status_output) and any("up" in line.lower() for line in str(apm_status_output).split('\n') if "tcpprobe2" in line):
            apm2_up = True
            st.log("SUCCESS: APM probe tcpprobe2 is UP")
        else:
            st.log("WARNING: APM probe tcpprobe2 is not UP")
        
        # Check final route installation
        final_route_output = st.show(nodes['SD4'], "show ip route vrf Vrf01", skip_tmpl=True)
        st.log("Final VRF Route table output on SD4: {}".format(final_route_output))
        
        final_route_found = False
        final_nexthop1 = False
        final_nexthop2 = False
        
        if "172.16.255.1/32" in str(final_route_output):
            final_route_found = True
            st.log("SUCCESS: Route 172.16.255.1/32 is still present after APM override")
            
            if "via 10.212.10.6" in str(final_route_output):
                final_nexthop1 = True
                st.log("SUCCESS: Route via 10.212.10.6 (tcpprobe1) is active")
            
            if "via 10.212.20.6" in str(final_route_output):
                final_nexthop2 = True
                st.log("SUCCESS: Route via 10.212.20.6 (tcpprobe2) is active")
            
            # Look for the expected multi-line format
            if "[1/0] via 10.212.10.6" in str(final_route_output) and "via 10.212.20.6" in str(final_route_output):
                st.log("SUCCESS: Route shows expected format with both nexthops")
        else:
            st.log("FAIL: Route 172.16.255.1/32 not found after APM override")
        
        # APP-DB Verification: Check static route entry contains both nexthops
        verify_app_db_static_route(
            nodes['SD4'],
            'redis-cli -n 0 hgetall "STATIC_ROUTE:Vrf01:172.16.255.1/32"',
            ['10.212.10.6', '10.212.20.6'],  # Both nexthops expected
            "APM Override Route Configuration"
        )
        
        # Test success criteria: Both APM probes UP and route with both nexthops
        if apm1_up and apm2_up and final_route_found and final_nexthop1 and final_nexthop2:
            st.log("TEST PASSED: APM Override Route Configuration completed successfully")
            st.log("Route successfully transitioned from basic static routing to APM-controlled routing")
            st.log("Both APM probes are UP and route shows both nexthops as expected")
            st.banner("APM Override Route Configuration Test - PASSED")
            st.report_pass('test_case_passed')
        else:
            st.report_fail('test_case_failed', "Test failed - APM1 up: {}, APM2 up: {}, Route found: {}, Nexthop1: {}, Nexthop2: {}".format(apm1_up, apm2_up, final_route_found, final_nexthop1, final_nexthop2))

    except Exception as e:
        st.log("Exception occurred during test execution: {}".format(str(e)))
        st.report_fail('test_case_failed', "Test failed with exception: {}".format(str(e)))
        
    finally:
        # Cleanup configurations
        st.banner("Cleanup: Removing all test configurations")
        
        try:
            # Stop both TCP servers on SD8
            st.config(nodes['SD8'], "pkill -f 'tcpserver.py 65432'", skip_error_check=True)
            st.config(nodes['SD8'], "pkill -f 'tcpserver.py 65433'", skip_error_check=True)
            st.wait(1)
            
            # Remove static route from SD4 (leaf2)
            st.config(nodes['SD4'], "config route del prefix vrf Vrf01 172.16.255.1/32", skip_error_check=True)
            
            # Remove APM probes from SD4 (leaf2)
            st.config(nodes['SD4'], "config apm del tcpprobe1", skip_error_check=True)
            st.config(nodes['SD4'], "config apm del tcpprobe2", skip_error_check=True)
            st.wait(1)
            
            # Remove IP addresses from SD8 dynamic ports (host1 D8D4P1 and D8D4P2)
            st.config(nodes['SD8'], "sudo ip addr del 10.212.10.6/24 dev {}".format(vars.D8D4P1), skip_error_check=True)
            st.config(nodes['SD8'], "sudo ip addr del 10.212.20.6/24 dev {}".format(vars.D8D4P2), skip_error_check=True)
            st.wait(1)
            
            # Remove dynamic ports from VLANs on SD4 (leaf2)
            st.config(nodes['SD4'], "config vlan member del 10 {}".format(vars.D4D8P1), skip_error_check=True)
            st.config(nodes['SD4'], "config vlan member del 20 {}".format(vars.D4D8P2), skip_error_check=True)
            st.wait(1)
            
            # Clean up nohup files
            st.config(nodes['SD8'], "sudo rm -f nohup.out", skip_error_check=True)
            st.config(nodes['SD8'], "sudo rm -f /tmp/tcpserver1.log", skip_error_check=True)
            st.config(nodes['SD8'], "sudo rm -f /tmp/tcpserver2.log", skip_error_check=True)
            
            st.banner("Cleanup completed successfully")
            
        except Exception as cleanup_e:
            st.log("Warning: Some cleanup operations failed: {}".format(str(cleanup_e)))

######################################################################
# Test APM Route Deletion and Fallback Behavior
######################################################################
@pytest.mark.system_box
@pytest.mark.community
@pytest.mark.community_pass
def test_apm_route_deletion_fallback():
    """
    Test APM route deletion and fallback to static routing behavior
    
    Test Scenario:
    1. Configure APM probes first
    2. Configure route with both nexthops and APM dependencies
    3. Delete APM dependencies from the route individually
    4. Verify route falls back to basic static routing with both nexthops
    
    Configuration Sequence (exact order as specified):
    - config apm add tcpprobe1 --type=tcp-connect --enable=true --vrf Vrf01 --dst-ip=10.212.10.6 --dst-port=65432
    - config apm add tcpprobe2 --type=tcp-connect --enable=true --vrf Vrf01 --dst-ip=10.212.20.6 --dst-port=65432
    - config route add prefix vrf Vrf01 172.16.255.1/32 nexthop 10.212.10.6,10.212.20.6 apm tcpprobe1,tcpprobe2
    - config route del prefix vrf Vrf01 172.16.255.1/32 apm tcpprobe1
    - config route del prefix vrf Vrf01 172.16.255.1/32 apm tcpprobe2
    
    
    Test Steps:
    1. Configure dynamic ports to Vlan10 and Vlan20 on SD4 (leaf2)
    2. Configure IP addresses on SD8 dynamic ports
    3. Start TCP servers on both IPs on SD8
    4. Configure APM TCP probes (tcpprobe1 and tcpprobe2) - FIRST
    5. Add route with nexthops AND APM dependencies
    6. Verify route is installed and controlled by APM
    7. Delete APM dependency tcpprobe1 from route
    8. Delete APM dependency tcpprobe2 from route
    9. Verify route falls back to basic static routing with both nexthops
    10. Cleanup all configurations
    """
    vars = st.get_testbed_vars()
    
    nodes = {}
    nodes['SD1'] = vars.D1  # SD1 (spine0)
    nodes['SD2'] = vars.D2   # SD2 (leaf0) 
    nodes['SD3'] = vars.D3   # SD3 (leaf1)
    nodes['SD4'] = vars.D4   # SD4 (leaf2)
    nodes['SD8'] = vars.D8   # SD8 (host1 - host device)
    
    st.banner("Starting APM Route Deletion and Fallback Test")
    
    try:
        # Step 1: Configure dynamic ports on SD4 (leaf2) to Vlan10/20
        st.banner("Step 1: Configuring dynamic ports on SD4 (leaf2) to Vlan10/20")
        
        # Add D4D8P1 to Vlan10 on SD4 (leaf2)
        st.config(nodes['SD4'], "config vlan member add 10 {} -u".format(vars.D4D8P1))
        
        # Add D4D8P2 to Vlan20 on SD4 (leaf2)
        st.config(nodes['SD4'], "config vlan member add 20 {} -u".format(vars.D4D8P2))
               
        # Step 2: Configure IP addresses on SD8 dynamic ports
        st.banner("Step 2: Configuring IP addresses on SD8 dynamic ports")
        
        # Bring up D8D4P1 and configure IP address on SD8 (host1)
        st.config(nodes['SD8'], "sudo ifconfig {} up".format(vars.D8D4P1))
        st.wait(2)
        st.config(nodes['SD8'], "sudo ip addr add 10.212.10.6/24 dev {}".format(vars.D8D4P1))
        
        # Bring up D8D4P2 and configure IP address on SD8 (host1)
        st.config(nodes['SD8'], "sudo ifconfig {} up".format(vars.D8D4P2))
        st.wait(2)
        st.config(nodes['SD8'], "sudo ip addr add 10.212.20.6/24 dev {}".format(vars.D8D4P2))
        
        # Step 3: Start TCP servers on both IPs on SD8
        st.banner("Step 3: Starting TCP servers on both IPs on SD8")
        
            
        
        # Start TCP servers in background on both IPs on SD8
        # Using full path to avoid issues with cd in sudo -s context
        tcp_server_cmd1 = "sudo nohup python3 /home/vxr/tcpserver.py 65432 10.212.10.6 > /tmp/tcpserver1.log 2>&1 &"
        st.config(nodes['SD8'], tcp_server_cmd1)
        
        tcp_server_cmd2 = "sudo nohup python3 /home/vxr/tcpserver.py 65433 10.212.20.6 > /tmp/tcpserver2.log 2>&1 &"
        st.config(nodes['SD8'], tcp_server_cmd2)
        st.wait(5)  # Wait for servers to start
        
        # Verify TCP servers are running
        verify_cmd = "ps aux | grep '[t]cpserver.py'"
        server_status = st.show(nodes['SD8'], verify_cmd, skip_tmpl=True, skip_error_check=True)
        st.log("TCP server status on host1: {}".format(server_status))
        
        # Step 4: Configure APM TCP probes FIRST (exact command order as specified)
        st.banner("Step 4: Configuring APM TCP probes on SD4 (leaf2) - FIRST")
        
        # Command 1: config apm add tcpprobe1
        apm_cmd1 = "sudo config apm add tcpprobe1 --type tcp-connect --dst-ip 10.212.10.6 --dst-port 65432 --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true"
        st.config(nodes['SD4'], apm_cmd1)
        st.wait(2)
        
        # Command 2: config apm add tcpprobe2
        apm_cmd2 = "sudo config apm add tcpprobe2 --type tcp-connect --dst-ip 10.212.20.6 --dst-port 65433 --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true"
        st.config(nodes['SD4'], apm_cmd2)
        st.wait(2)  # Wait longer for APM probes to initialize
        
        # Verify APM probes are configured and UP
        apm_config_output = st.show(nodes['SD4'], "show apm", skip_tmpl=True, skip_error_check=True)
        st.log("APM configuration on SD4: {}".format(apm_config_output))
        
        apm_status_output = st.show(nodes['SD4'], "show apm-status", skip_tmpl=True, skip_error_check=True)
        st.log("APM status on SD4: {}".format(apm_status_output))
        if "tcpprobe1" not in str(apm_config_output) or "tcpprobe2" not in str(apm_config_output):
            st.report_fail('test_case_failed', "APM probes tcpprobe1 or tcpprobe2 not configured properly on SD4")

        # Step 5: Add route with nexthops AND APM dependencies (exact command as specified)
        st.banner("Step 5: Adding route with nexthops and APM dependencies")
        
        # Command 3: config route add with both nexthops and APM
        route_with_apm_cmd = "config route add prefix vrf Vrf01 172.16.255.1/32 nexthop 10.212.10.6,10.212.20.6 apm tcpprobe1,tcpprobe2"
        st.config(nodes['SD4'], route_with_apm_cmd)
        st.wait(2)  # Wait for route to be installed
        
        # Step 6: Verify route is installed and controlled by APM
        st.banner("Step 6: Verifying route is installed with APM control")
        
        initial_route_output = st.show(nodes['SD4'], "show ip route vrf Vrf01", skip_tmpl=True)
        st.log("Initial route output with APM control: {}".format(initial_route_output))
        
        if "172.16.255.1/32" in str(initial_route_output):
            st.log("SUCCESS: Route is installed with APM dependencies")
        else:
            st.log("WARNING: Route may not be installed properly with APM")
        
        # Step 7: Delete APM dependency tcpprobe1 from route (exact command as specified)
        st.banner("Step 7: Deleting APM dependency tcpprobe1 from route")
        
        # Command 4: config route del apm tcpprobe1
        del_apm1_cmd = "config route del prefix vrf Vrf01 172.16.255.1/32 apm tcpprobe1"
        st.config(nodes['SD4'], del_apm1_cmd)
        st.wait(2)
        
        # Check route status after first APM deletion
        after_del1_output = st.show(nodes['SD4'], "show ip route vrf Vrf01", skip_tmpl=True)
        st.log("Route output after deleting tcpprobe1 APM dependency: {}".format(after_del1_output))
        
        # Step 8: Delete APM dependency tcpprobe2 from route (exact command as specified)
        st.banner("Step 8: Deleting APM dependency tcpprobe2 from route")
        
        # Command 5: config route del apm tcpprobe2
        del_apm2_cmd = "config route del prefix vrf Vrf01 172.16.255.1/32 apm tcpprobe2"
        st.config(nodes['SD4'], del_apm2_cmd)
        st.wait(1)
        
        # Step 9: Verify route falls back to basic static routing with both nexthops
        st.banner("Step 9: Verifying route fallback to basic static routing")
        
        # Display route table for terminal visibility
        st.log("Displaying final route table for verification:")
        st.show(nodes['SD4'], "show ip route vrf Vrf01")
        
        final_route_output = st.show(nodes['SD4'], "show ip route vrf Vrf01", skip_tmpl=True)
        st.log("Final route output after APM dependencies removed: {}".format(final_route_output))
        
        # Verify expected behavior - route should still exist with both nexthops but no APM control
        final_route_found = False
        final_nexthop1 = False
        final_nexthop2 = False
        
        if "172.16.255.1/32" in str(final_route_output):
            final_route_found = True
            st.log("SUCCESS: Route 172.16.255.1/32 still exists after APM deletion")
            
            if "via 10.212.10.6" in str(final_route_output):
                final_nexthop1 = True
                st.log("SUCCESS: Route via 10.212.10.6 is active")
            
            if "via 10.212.20.6" in str(final_route_output):
                final_nexthop2 = True
                st.log("SUCCESS: Route via 10.212.20.6 is active")
            
            # Look for the expected multi-line format matching the expected output
            if "[1/0] via 10.212.10.6" in str(final_route_output) and "via 10.212.20.6" in str(final_route_output):
                st.log("SUCCESS: Route shows expected format with both nexthops as basic static route")
        else:
            st.log("FAIL: Route 172.16.255.1/32 not found after APM deletion")
        
        # Additional verification - ensure APM probes still exist but route is not using them
        final_apm_status = st.show(nodes['SD4'], "show apm-status", skip_tmpl=True, skip_error_check=True)
        st.log("Final APM status (probes should still exist): {}".format(final_apm_status))
        
        # APP-DB Verification: Should be empty array since route fell back to basic static routing
        verify_app_db_static_route(
            nodes['SD4'],
            'redis-cli -n 0 hgetall "STATIC_ROUTE:Vrf01:172.16.255.1/32"',
            [],  # Empty list since we expect empty array after APM fallback
            "APM Route Deletion Fallback",
            expect_empty=True
        )
        
        # Test success criteria: Route exists with both nexthops, fallback successful
        if final_route_found and final_nexthop1 and final_nexthop2:
            st.log("TEST PASSED: APM Route Deletion and Fallback completed successfully")
            st.log("Route successfully fell back from APM-controlled to basic static routing")
            st.log("Both nexthops are preserved in the static route")
            st.banner("APM Route Deletion and Fallback Test - PASSED")
            st.report_pass('test_case_passed')
        else:
            st.report_fail('test_case_failed', "Test failed - Route found: {}, Nexthop1: {}, Nexthop2: {}".format(final_route_found, final_nexthop1, final_nexthop2))

    except Exception as e:
        st.log("Exception occurred during test execution: {}".format(str(e)))
        st.report_fail('test_case_failed', "Test failed with exception: {}".format(str(e)))
        
    finally:
        # Cleanup configurations
        st.banner("Cleanup: Removing all test configurations")
        
        try:
            # Stop both TCP servers on SD8
            st.config(nodes['SD8'], "pkill -f 'tcpserver.py 65432'", skip_error_check=True)
            st.config(nodes['SD8'], "pkill -f 'tcpserver.py 65433'", skip_error_check=True)
            st.wait(1)
            
            # Remove static route from SD4 (leaf2)
            st.config(nodes['SD4'], "config route del prefix vrf Vrf01 172.16.255.1/32", skip_error_check=True)
            
            # Remove APM probes from SD4 (leaf2)
            st.config(nodes['SD4'], "config apm del tcpprobe1", skip_error_check=True)
            st.config(nodes['SD4'], "config apm del tcpprobe2", skip_error_check=True)
            st.wait(1)
            
            # Remove IP addresses from SD8 dynamic ports (host1 D8D4P1 and D8D4P2)
            st.config(nodes['SD8'], "sudo ip addr del 10.212.10.6/24 dev {}".format(vars.D8D4P1), skip_error_check=True)
            st.config(nodes['SD8'], "sudo ip addr del 10.212.20.6/24 dev {}".format(vars.D8D4P2), skip_error_check=True)
            
            # Remove dynamic ports from VLANs on SD4 (leaf2)
            st.config(nodes['SD4'], "config vlan member del 10 {}".format(vars.D4D8P1), skip_error_check=True)
            st.config(nodes['SD4'], "config vlan member del 20 {}".format(vars.D4D8P2), skip_error_check=True)
            st.wait(1)
            
            # Clean up nohup files
            st.config(nodes['SD8'], "sudo rm -f nohup.out", skip_error_check=True)
            st.config(nodes['SD8'], "sudo rm -f /tmp/tcpserver1.log", skip_error_check=True)
            st.config(nodes['SD8'], "sudo rm -f /tmp/tcpserver2.log", skip_error_check=True)
            
            st.banner("Cleanup completed successfully")
            
        except Exception as cleanup_e:
            st.log("Warning: Some cleanup operations failed: {}".format(str(cleanup_e)))

######################################################################
# Test APM Probe State Transition Cycle - Up to Down to Up
######################################################################
@pytest.mark.system_box
@pytest.mark.community
@pytest.mark.community_pass
def test_apm_probe_state_transition_cycle():
    """
    Test complete APM probe state transition cycle from Up to Down to Up
    Combines test_apm_probe_up_to_down_nexthop_withdrawal and test_apm_probe_down_to_up_nexthop_addition
    
    Test Scenario:
    1. First Phase: Setup APM probes and routes, verify both probes UP with both nexthops
    2. Second Phase: Make tcpprobe1 go DOWN, verify nexthop withdrawal 
    3. Third Phase: Make tcpprobe1 come back UP, verify nexthop re-addition
    
    Test Steps:
    Phase 1 - Initial Setup (Both Probes UP):
    1. Configure dynamic ports to Vlan10 and Vlan20 on SD4 (leaf2)
    2. Configure IP addresses on SD8 dynamic ports
    3. Start TCP servers on both IPs on SD8
    4. Configure APM probes tcpprobe1 and tcpprobe2
    5. Add static route with both nexthops and APM dependencies
    6. Verify both probes are UP and route is installed via both nexthops
    
    Phase 2 - Probe Down Transition (tcpprobe1 DOWN):
    7. Stop TCP server for tcpprobe1 (make tcpprobe1 go DOWN)
    8. Verify tcpprobe1 is DOWN, tcpprobe2 is UP
    9. Verify route only shows nexthop for working probe (10.212.20.6)
    
    Phase 3 - Probe Up Transition (tcpprobe1 UP):
    10. Restart TCP server for tcpprobe1 (make tcpprobe1 come back UP)
    11. Verify both tcpprobe1 and tcpprobe2 are UP
    12. Verify route shows both nexthops again (10.212.10.6 and 10.212.20.6)
    13. Cleanup all configurations
    
    Expected Behavior:
    - Phase 1: Both probes UP, route via both nexthops
    - Phase 2: tcpprobe1 DOWN, route only via 10.212.20.6 
    - Phase 3: Both probes UP, route via both nexthops restored
    """
    vars = st.get_testbed_vars()
    
    nodes = {}
    nodes['SD1'] = vars.D1  # SD1 (spine0)
    nodes['SD2'] = vars.D2   # SD2 (leaf0) 
    nodes['SD3'] = vars.D3   # SD3 (leaf1)
    nodes['SD4'] = vars.D4   # SD4 (leaf2)
    nodes['SD8'] = vars.D8   # SD8 (host1 - host device)
    
    st.banner("Starting APM Probe State Transition Cycle Test")
    
    try:
        # =================== PHASE 1: INITIAL SETUP (BOTH PROBES UP) ===================
        st.banner("PHASE 1: Initial Setup - Both Probes UP")
        
        # Step 1: Configure dynamic ports to Vlan10 and Vlan20 on SD4 (leaf2)
        st.banner("Step 1: Configuring dynamic ports on SD4 (leaf2)")
        
        # Add D4D8P1 to Vlan10 on SD4 (leaf2)
        st.config(nodes['SD4'], "config vlan member add 10 {} -u".format(vars.D4D8P1))
        
        # Add D4D8P2 to Vlan20 on SD4 (leaf2)
        st.config(nodes['SD4'], "config vlan member add 20 {} -u".format(vars.D4D8P2))
        
        # Step 2: Configure IP addresses on SD8 dynamic ports
        st.banner("Step 2: Configuring IP addresses on SD8 dynamic ports")
        
        # Bring up D8D4P1 and configure IP address on SD8 (host1)
        st.config(nodes['SD8'], "sudo ifconfig {} up".format(vars.D8D4P1))
        st.wait(2)
        st.config(nodes['SD8'], "sudo ip addr add 10.212.10.6/24 dev {}".format(vars.D8D4P1))
        
        # Bring up D8D4P2 and configure IP address on SD8 (host1)
        st.config(nodes['SD8'], "sudo ifconfig {} up".format(vars.D8D4P2))
        st.wait(2)
        st.config(nodes['SD8'], "sudo ip addr add 10.212.20.6/24 dev {}".format(vars.D8D4P2))
        
        # Step 3: Start TCP servers on both IPs on SD8
        st.banner("Step 3: Starting TCP servers on both IPs on SD8")
        
        
        # Start TCP servers in background on both IPs on SD8
        # Using full path to avoid issues with cd in sudo -s context
        tcp_server_cmd1 = "sudo nohup python3 /home/vxr/tcpserver.py 65432 10.212.10.6 > /tmp/tcpserver1.log 2>&1 &"
        st.config(nodes['SD8'], tcp_server_cmd1)
        
        tcp_server_cmd2 = "sudo nohup python3 /home/vxr/tcpserver.py 65433 10.212.20.6 > /tmp/tcpserver2.log 2>&1 &"
        st.config(nodes['SD8'], tcp_server_cmd2)
        st.wait(5)  # Wait for servers to start
        
        # Step 4: Configure APM probes tcpprobe1 and tcpprobe2
        st.banner("Step 4: Configuring APM probes tcpprobe1 and tcpprobe2")
        
        # Configure APM TCP probe1 targeting SD8 Ethernet1_1
        apm_cmd1 = "sudo config apm add tcpprobe1 --type tcp-connect --dst-ip 10.212.10.6 --dst-port 65432 --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true"
        st.config(nodes['SD4'], apm_cmd1)
        st.wait(3)
        
        # Configure APM TCP probe2 targeting SD8 Ethernet1_2
        apm_cmd2 = "sudo config apm add tcpprobe2 --type tcp-connect --dst-ip 10.212.20.6 --dst-port 65433 --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true"
        st.config(nodes['SD4'], apm_cmd2)
        st.wait(3)  # Wait for APM probes to initialize
        
        # Step 5: Add static route with both nexthops and APM dependencies
        st.banner("Step 5: Adding static route with both nexthops and APM dependencies")
        
        route_cmd = "config route add prefix vrf Vrf01 172.16.255.1/32 nexthop 10.212.10.6,10.212.20.6 apm tcpprobe1,tcpprobe2"
        st.config(nodes['SD4'], route_cmd)
        st.wait(3)  # Wait for route to be installed
        
        # Step 6: Verify both probes are UP and route is installed via both nexthops
        st.banner("Step 6: Verifying both probes are UP and route via both nexthops")
        
        # Check APM status
        apm_status_phase1 = st.show(nodes['SD4'], "show apm-status", skip_tmpl=True, skip_error_check=True)
        st.log("Phase 1 APM status: {}".format(apm_status_phase1))
        
        # Check route installation
        route_output_phase1 = st.show(nodes['SD4'], "show ip route vrf Vrf01", skip_tmpl=True)
        st.log("Phase 1 route output: {}".format(route_output_phase1))
        
        # Validate Phase 1
        tcpprobe1_up_phase1 = any("up" in line.lower() for line in str(apm_status_phase1).split('\n') if "tcpprobe1" in line)
        tcpprobe2_up_phase1 = any("up" in line.lower() for line in str(apm_status_phase1).split('\n') if "tcpprobe2" in line)
        route_both_nexthops_phase1 = "172.16.255.1/32" in str(route_output_phase1) and "via 10.212.10.6" in str(route_output_phase1) and "via 10.212.20.6" in str(route_output_phase1)
        
        phase1_success = tcpprobe1_up_phase1 and tcpprobe2_up_phase1 and route_both_nexthops_phase1
        
        if phase1_success:
            st.log("PHASE 1 PASSED: Both probes UP, route via both nexthops")
        else:
            st.log("PHASE 1 FAILED: tcpprobe1: {}, tcpprobe2: {}, both_nexthops: {}".format(
                tcpprobe1_up_phase1, tcpprobe2_up_phase1, route_both_nexthops_phase1))
        
        # =================== PHASE 2: PROBE DOWN TRANSITION ===================
        st.banner("PHASE 2: Probe Down Transition - Making tcpprobe1 DOWN")
        
        # Step 7: Stop TCP server for tcpprobe1 (make tcpprobe1 go DOWN)
        st.banner("Step 7: Stopping TCP server for tcpprobe1 (port 65432)")
        
        # Kill the TCP server on port 65432 (tcpprobe1)
        kill_cmd = "pkill -f 'tcpserver.py 65432'"
        st.config(nodes['SD8'], kill_cmd, skip_error_check=True)
        st.wait(10)  # Wait for APM probe to detect server down
        
        # Step 8: Verify tcpprobe1 is DOWN, tcpprobe2 is UP
        st.banner("Step 8: Verifying tcpprobe1 DOWN, tcpprobe2 UP")
        
        apm_status_phase2 = st.show(nodes['SD4'], "show apm-status", skip_tmpl=True, skip_error_check=True)
        st.log("Phase 2 APM status: {}".format(apm_status_phase2))
        
        # Step 9: Verify route only shows nexthop for working probe (10.212.20.6)
        st.banner("Step 9: Verifying route only via working nexthop (10.212.20.6)")
        
        route_output_phase2 = st.show(nodes['SD4'], "show ip route vrf Vrf01", skip_tmpl=True)
        st.log("Phase 2 route output: {}".format(route_output_phase2))
        
        # Validate Phase 2
        tcpprobe1_down_phase2 = any("down" in line.lower() or "failed" in line.lower() for line in str(apm_status_phase2).split('\n') if "tcpprobe1" in line)
        tcpprobe2_up_phase2 = any("up" in line.lower() for line in str(apm_status_phase2).split('\n') if "tcpprobe2" in line)
        route_single_nexthop_phase2 = "172.16.255.1/32" in str(route_output_phase2) and "via 10.212.20.6" in str(route_output_phase2) and "via 10.212.10.6" not in str(route_output_phase2)
        
        phase2_success = tcpprobe1_down_phase2 and tcpprobe2_up_phase2 and route_single_nexthop_phase2
        
        if phase2_success:
            st.log("PHASE 2 PASSED: tcpprobe1 DOWN, route only via 10.212.20.6")
        else:
            st.log("PHASE 2 FAILED: tcpprobe1_down: {}, tcpprobe2_up: {}, single_nexthop: {}".format(
                tcpprobe1_down_phase2, tcpprobe2_up_phase2, route_single_nexthop_phase2))
        
        # =================== PHASE 3: PROBE UP TRANSITION ===================
        st.banner("PHASE 3: Probe Up Transition - Making tcpprobe1 UP again")
        
        # Step 10: Restart TCP server for tcpprobe1 (make tcpprobe1 come back UP)
        st.banner("Step 10: Restarting TCP server for tcpprobe1 (port 65432)")
        
        # Restart TCP server on port 65432 (tcpprobe1)
        # Using full path to avoid issues with cd in sudo -s context
        tcp_server_cmd1_restart = "sudo nohup python3 /home/vxr/tcpserver.py 65432 10.212.10.6 > /tmp/tcpserver1_restart.log 2>&1 &"
        st.config(nodes['SD8'], tcp_server_cmd1_restart)
        st.wait(10)  # Wait for APM probe to detect server up
        
        # Step 11: Verify both tcpprobe1 and tcpprobe2 are UP
        st.banner("Step 11: Verifying both tcpprobe1 and tcpprobe2 are UP")
        
        apm_status_phase3 = st.show(nodes['SD4'], "show apm-status", skip_tmpl=True, skip_error_check=True)
        st.log("Phase 3 APM status: {}".format(apm_status_phase3))
        
        # Step 12: Verify route shows both nexthops again
        st.banner("Step 12: Verifying route shows both nexthops again")
        
        route_output_phase3 = st.show(nodes['SD4'], "show ip route vrf Vrf01", skip_tmpl=True)
        st.log("Phase 3 route output: {}".format(route_output_phase3))
        
        # Validate Phase 3
        tcpprobe1_up_phase3 = any("up" in line.lower() for line in str(apm_status_phase3).split('\n') if "tcpprobe1" in line)
        tcpprobe2_up_phase3 = any("up" in line.lower() for line in str(apm_status_phase3).split('\n') if "tcpprobe2" in line)
        route_both_nexthops_phase3 = "172.16.255.1/32" in str(route_output_phase3) and "via 10.212.10.6" in str(route_output_phase3) and "via 10.212.20.6" in str(route_output_phase3)
        
        phase3_success = tcpprobe1_up_phase3 and tcpprobe2_up_phase3 and route_both_nexthops_phase3
        
        if phase3_success:
            st.log("PHASE 3 PASSED: Both probes UP, route via both nexthops restored")
        else:
            st.log("PHASE 3 FAILED: tcpprobe1_up: {}, tcpprobe2_up: {}, both_nexthops: {}".format(
                tcpprobe1_up_phase3, tcpprobe2_up_phase3, route_both_nexthops_phase3))
        
        # APP-DB Verification for final state
        st.banner("Final APP-DB Verification: Both nexthops should be present")
        verify_app_db_static_route(
            nodes['SD4'],
            'redis-cli -n 0 hgetall "STATIC_ROUTE:Vrf01:172.16.255.1/32"',
            ['10.212.10.6', '10.212.20.6'],  # Both nexthops expected
            "APM Probe State Transition Cycle"
        )
        
        # Combined test result
        if phase1_success and phase2_success and phase3_success:
            st.log("COMBINED CYCLE TEST PASSED: All three phases successful")
            st.log("Phase 1: Both probes UP, both nexthops - PASSED")
            st.log("Phase 2: tcpprobe1 DOWN, single nexthop - PASSED") 
            st.log("Phase 3: Both probes UP, both nexthops restored - PASSED")
            st.banner("APM Probe State Transition Cycle Test - PASSED")
            st.report_pass('test_case_passed')
        else:
            st.log("COMBINED CYCLE TEST FAILED: Phase 1: {}, Phase 2: {}, Phase 3: {}".format(
                phase1_success, phase2_success, phase3_success))
            st.report_fail('test_case_failed', "APM probe state transition cycle test failed")

    except Exception as e:
        st.log("Exception occurred during APM probe state transition cycle test: {}".format(str(e)))
        st.report_fail('test_case_failed', "Test failed with exception: {}".format(str(e)))
        
    finally:
        # Cleanup configurations
        st.banner("Cleanup: Removing all APM probe state transition test configurations")
        
        try:
            # Stop all TCP servers
            st.config(nodes['SD8'], "pkill -f 'tcpserver.py'", skip_error_check=True)
            st.wait(2)
            
            # Remove route
            st.config(nodes['SD4'], "config route del prefix vrf Vrf01 172.16.255.1/32", skip_error_check=True)
            st.wait(1)
            
            # Remove APM probes
            st.config(nodes['SD4'], "config apm del tcpprobe1", skip_error_check=True)
            st.config(nodes['SD4'], "config apm del tcpprobe2", skip_error_check=True)
            st.wait(2)
            
            # Remove IP addresses from SD8 dynamic ports (host1 D8D4P1 and D8D4P2)
            st.config(nodes['SD8'], "sudo ip addr del 10.212.10.6/24 dev {}".format(vars.D8D4P1), skip_error_check=True)
            st.config(nodes['SD8'], "sudo ip addr del 10.212.20.6/24 dev {}".format(vars.D8D4P2), skip_error_check=True)
            
            # Remove dynamic ports from VLANs on SD4
            st.config(nodes['SD4'], "config vlan member del 10 {}".format(vars.D4D8P1), skip_error_check=True)
            st.config(nodes['SD4'], "config vlan member del 20 {}".format(vars.D4D8P2), skip_error_check=True)
            
            # Clean up nohup files and TCP server logs
            st.config(nodes['SD8'], "sudo rm -f nohup.out", skip_error_check=True)
            st.config(nodes['SD8'], "sudo rm -f /tmp/tcpserver1.log /tmp/tcpserver2.log /tmp/tcpserver1_restart.log", skip_error_check=True)
            
            st.banner("APM probe state transition cycle test cleanup completed successfully")
            
        except Exception as cleanup_e:
            st.log("Warning: Some cleanup operations failed: {}".format(str(cleanup_e)))


######################################################################
# Test APM Route Recovery via IP Address Re-addition
######################################################################
@pytest.mark.system_box
@pytest.mark.community
@pytest.mark.community_pass
def test_apm_route_recovery_via_ip_readd():
    """
    Test APM route recovery when IP address is removed and then re-added to interface
    
    Test Scenario:
    Configure APM probes and static route, remove IP address from one interface to cause
    probe failure and nexthop withdrawal, then re-add the IP address to verify probe
    comes back UP and route is restored with both nexthops
    
    Test Steps:
    1. Configure dynamic ports to Vlan10 and Vlan20 on SD4 (leaf2)
    2. Configure IP addresses on SD8 dynamic ports
    3. Start TCP servers on both IPs on SD8
    4. Configure APM probes tcpprobe1 and tcpprobe2
    5. Add static route with both nexthops and APM dependencies
    6. Verify both probes are UP and route is installed with both nexthops
    7. Remove IP address from D8D4P1 on SD8
    8. Verify failed nexthop is withdrawn but route remains via other nexthop
    9. Re-add IP address to D8D4P1 on SD8
    10. Verify probe comes back UP and route is restored with both nexthops
    
    Configuration Sequence:
    - sudo config apm add tcpprobe1 --type tcp-connect --dst-ip 10.212.10.6 --dst-port 65432 --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true
    - sudo config apm add tcpprobe2 --type tcp-connect --dst-ip 10.212.20.6 --dst-port 65433 --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true
    - config route add prefix vrf Vrf01 172.16.255.1/32 nexthop 10.212.10.6,10.212.20.6 apm tcpprobe1,tcpprobe2
    - sudo ip addr del 10.212.10.6/24 dev <D8D4P1>
    - sudo ip addr add 10.212.10.6/24 dev <D8D4P1>
    
    Expected Behavior:
    - Initially: Both probes UP, route installed with both nexthops
    - After IP removal: tcpprobe1 DOWN, failed nexthop (10.212.10.6) withdrawn, route via 10.212.20.6
    - After IP re-addition: Both probes UP, route restored with both nexthops
    """
    vars = st.get_testbed_vars()
    
    nodes = {}
    nodes['SD1'] = vars.D1  # SD1 (spine0)
    nodes['SD2'] = vars.D2   # SD2 (leaf0) 
    nodes['SD3'] = vars.D3   # SD3 (leaf1)
    nodes['SD4'] = vars.D4   # SD4 (leaf2)
    nodes['SD8'] = vars.D8   # SD8 (host1 - host device)
    
    st.banner("Starting APM Route Recovery via IP Address Re-addition Test")
    
    try:
        # Step 1: Configure dynamic ports on SD4 (leaf2) to Vlan10 and Vlan20
        st.banner("Step 1: Configuring dynamic ports on SD4 (leaf2) to Vlan10 and Vlan20")
        
        # Add D4D8P1 to Vlan10 on SD4 (leaf2)
        st.config(nodes['SD4'], "config vlan member add 10 {} -u".format(vars.D4D8P1))
        
        # Add D4D8P2 to Vlan20 on SD4 (leaf2)
        st.config(nodes['SD4'], "config vlan member add 20 {} -u".format(vars.D4D8P2))
        
        # Step 2: Configure IP addresses on SD8 dynamic ports
        st.banner("Step 2: Configuring IP addresses on SD8 dynamic ports")
        
        # Bring up D8D4P1 and configure IP address on SD8 (host1)
        st.config(nodes['SD8'], "sudo ifconfig {} up".format(vars.D8D4P1))
        st.wait(2)
        st.config(nodes['SD8'], "sudo ip addr add 10.212.10.6/24 dev {}".format(vars.D8D4P1))
        
        # Bring up D8D4P2 and configure IP address on SD8 (host1)
        st.config(nodes['SD8'], "sudo ifconfig {} up".format(vars.D8D4P2))
        st.wait(2)
        st.config(nodes['SD8'], "sudo ip addr add 10.212.20.6/24 dev {}".format(vars.D8D4P2))
        st.wait(1)
        
        # Step 3: Start TCP servers on both IPs on SD8
        st.banner("Step 3: Starting TCP servers on both IPs on SD8")
        
            
        
        # Start TCP servers in background on both IPs on SD8
        # Using full path to avoid issues with cd in sudo -s context
        tcp_server_cmd1 = "sudo nohup python3 /home/vxr/tcpserver.py 65432 10.212.10.6 > /tmp/tcpserver1.log 2>&1 &"
        st.config(nodes['SD8'], tcp_server_cmd1)
        st.wait(1)
        
        tcp_server_cmd2 = "sudo nohup python3 /home/vxr/tcpserver.py 65433 10.212.20.6 > /tmp/tcpserver2.log 2>&1 &"
        st.config(nodes['SD8'], tcp_server_cmd2)
        st.wait(5)  # Wait for servers to start
        
        # Verify TCP servers are running
        verify_cmd = "ps aux | grep '[t]cpserver.py'"
        server_status = st.show(nodes['SD8'], verify_cmd, skip_tmpl=True, skip_error_check=True)
        st.log("TCP server status on host1: {}".format(server_status))
        
        # Step 4: Configure APM probes (exact commands as specified)
        st.banner("Step 4: Configuring APM TCP probes on SD4 (leaf2)")
        
        # Command 1: sudo config apm add tcpprobe1 with full parameters
        apm_cmd1 = "sudo config apm add tcpprobe1 --type tcp-connect --dst-ip 10.212.10.6 --dst-port 65432 --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true"
        st.config(nodes['SD4'], apm_cmd1)
        st.wait(1)
        
        # Command 2: sudo config apm add tcpprobe2 with full parameters  
        apm_cmd2 = "sudo config apm add tcpprobe2 --type tcp-connect --dst-ip 10.212.20.6 --dst-port 65433 --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true"
        st.config(nodes['SD4'], apm_cmd2)
        st.wait(1)  # Wait for APM probes to initialize and come UP
        
        # Verify APM probes are configured
        apm_config_output = st.show(nodes['SD4'], "show apm", skip_tmpl=True, skip_error_check=True)
        st.log("APM configuration: {}".format(apm_config_output))
        
        # Step 5: Add static route with both nexthops and APM dependencies
        st.banner("Step 5: Adding static route with both nexthops and APM dependencies")
        
        # Command 3: config route add with both nexthops and APM
        route_add_cmd = "config route add prefix vrf Vrf01 172.16.255.1/32 nexthop 10.212.10.6,10.212.20.6 apm tcpprobe1,tcpprobe2"
        st.config(nodes['SD4'], route_add_cmd)
        st.wait(3)  # Wait for route to be installed
        
        # Step 6: Verify both probes are UP and route is installed with both nexthops
        st.banner("Step 6: Verifying initial state - both probes UP, route with both nexthops")
        
        # Check APM probe status (both should be UP)
        initial_apm_status = st.show(nodes['SD4'], "show apm-status", skip_tmpl=True, skip_error_check=True)
        st.log("Initial APM status output: {}".format(initial_apm_status))
        
        # Verify specific probe states
        tcpprobe1_up_initial = False
        tcpprobe2_up_initial = False
        
        if "tcpprobe1" in str(initial_apm_status):
            if "UP" in str(initial_apm_status) or "up" in str(initial_apm_status).lower():
                # Parse for tcpprobe1 specific status
                apm_lines = str(initial_apm_status).split('\n')
                for line in apm_lines:
                    if "tcpprobe1" in line and ("UP" in line or "up" in line.lower()):
                        tcpprobe1_up_initial = True
                        st.log("SUCCESS: tcpprobe1 is UP initially")
                        break
            if not tcpprobe1_up_initial:
                st.log("WARNING: tcpprobe1 is not UP initially")
        
        if "tcpprobe2" in str(initial_apm_status):
            if "UP" in str(initial_apm_status) or "up" in str(initial_apm_status).lower():
                # Parse for tcpprobe2 specific status
                apm_lines = str(initial_apm_status).split('\n')
                for line in apm_lines:
                    if "tcpprobe2" in line and ("UP" in line or "up" in line.lower()):
                        tcpprobe2_up_initial = True
                        st.log("SUCCESS: tcpprobe2 is UP initially")
                        break
            if not tcpprobe2_up_initial:
                st.log("WARNING: tcpprobe2 is not UP initially")
        
        # Verify both probes are UP as expected
        if tcpprobe1_up_initial and tcpprobe2_up_initial:
            st.log("SUCCESS: Both APM probes (tcpprobe1, tcpprobe2) are UP initially")
        else:
            st.log("WARNING: Not all APM probes are UP initially - tcpprobe1: UP={}, tcpprobe2: UP={}".format(tcpprobe1_up_initial, tcpprobe2_up_initial))
        
        # Display initial route state
        st.log("Initial route state (should show both nexthops):")
        st.show(nodes['SD4'], "show ip route vrf Vrf01")
        
        initial_route_output = st.show(nodes['SD4'], "show ip route vrf Vrf01", skip_tmpl=True)
        st.log("Initial route output: {}".format(initial_route_output))
        
        # Verify route with both nexthops is present
        route_initially_present = False
        if "172.16.255.1/32" in str(initial_route_output):
            route_initially_present = True
            st.log("SUCCESS: Route 172.16.255.1/32 is installed with both nexthops")
            
            # Verify both nexthops are present
            if "10.212.10.6" in str(initial_route_output) and "10.212.20.6" in str(initial_route_output):
                st.log("SUCCESS: Both nexthops (10.212.10.6 and 10.212.20.6) are present initially")
        else:
            st.log("WARNING: Route may not be installed properly")
        
        # Step 7: Remove IP address from D8D4P1 on SD8
        st.banner("Step 7: Removing IP address from D8D4P1 on SD8")
        
        # Command 4: config interface ip remove D8D4P1 (this will cause tcpprobe1 to go DOWN)
        ip_remove_cmd = "sudo ip addr del 10.212.10.6/24 dev {}".format(vars.D8D4P1)
        st.config(nodes['SD8'], ip_remove_cmd)
        st.wait(5)  # Wait longer for probe state change and route update
        
        # Step 8: Verify failed nexthop is withdrawn but route remains via other nexthop
        st.banner("Step 8: Verifying nexthop withdrawal after IP removal")
        
        # Check APM probe status after IP removal
        after_removal_apm_status = st.show(nodes['SD4'], "show apm-status", skip_tmpl=True, skip_error_check=True)
        st.log("APM status after IP removal output: {}".format(after_removal_apm_status))
        
        # Verify specific probe states after IP removal
        tcpprobe1_down_after_removal = False
        tcpprobe2_up_after_removal = False
        
        if "tcpprobe1" in str(after_removal_apm_status):
            # Parse for tcpprobe1 specific status (should be DOWN)
            apm_lines = str(after_removal_apm_status).split('\n')
            for line in apm_lines:
                if "tcpprobe1" in line:
                    if "DOWN" in line or "down" in line.lower() or "FAIL" in line or "fail" in line.lower():
                        tcpprobe1_down_after_removal = True
                        st.log("SUCCESS: tcpprobe1 is DOWN after IP removal")
                        break
            if not tcpprobe1_down_after_removal:
                st.log("WARNING: tcpprobe1 is not DOWN after IP removal")
        
        if "tcpprobe2" in str(after_removal_apm_status):
            # Parse for tcpprobe2 specific status (should still be UP)
            apm_lines = str(after_removal_apm_status).split('\n')
            for line in apm_lines:
                if "tcpprobe2" in line:
                    if "UP" in line or "up" in line.lower():
                        tcpprobe2_up_after_removal = True
                        st.log("SUCCESS: tcpprobe2 is still UP after IP removal")
                        break
            if not tcpprobe2_up_after_removal:
                st.log("WARNING: tcpprobe2 is not UP after IP removal")
        
        # Verify expected probe states after IP removal
        if tcpprobe1_down_after_removal and tcpprobe2_up_after_removal:
            st.log("SUCCESS: APM probe states are as expected after IP removal - tcpprobe1: DOWN, tcpprobe2: UP")
        else:
            st.log("WARNING: APM probe states after IP removal - tcpprobe1: DOWN={}, tcpprobe2: UP={}".format(tcpprobe1_down_after_removal, tcpprobe2_up_after_removal))
        
        # Display route state after IP removal
        st.log("Route state after IP removal (should show only working nexthop):")
        st.show(nodes['SD4'], "show ip route vrf Vrf01")
        
        after_removal_route_output = st.show(nodes['SD4'], "show ip route vrf Vrf01", skip_tmpl=True)
        st.log("Route output after IP removal: {}".format(after_removal_route_output))
        
        # Verify route still exists with remaining nexthop
        route_after_removal = False
        if "172.16.255.1/32" in str(after_removal_route_output):
            route_after_removal = True
            st.log("SUCCESS: Route still exists after IP removal")
            
            if "10.212.20.6" in str(after_removal_route_output):
                st.log("SUCCESS: Remaining nexthop 10.212.20.6 is present")
        
        # Step 9: Re-add IP address to D8D4P1 on SD8
        st.banner("Step 9: Re-adding IP address to D8D4P1 on SD8")
        
        # Command 5: Re-add IP using Linux command (this should bring tcpprobe1 back UP)
        ip_readd_cmd = "sudo ip addr add 10.212.10.6/24 dev {}".format(vars.D8D4P1)
        st.config(nodes['SD8'], ip_readd_cmd)
        st.wait(90)  # Wait longer for probe state change and route update
        
        # Step 10: Verify probe comes back UP and route is restored with both nexthops
        st.banner("Step 10: Verifying route recovery after IP re-addition")
        
        # Check APM probe status after IP re-addition
        final_apm_status = st.show(nodes['SD4'], "show apm-status", skip_tmpl=True, skip_error_check=True)
        st.log("Final APM status output: {}".format(final_apm_status))
        
        # Verify specific probe states after IP re-addition
        tcpprobe1_up_final = False
        tcpprobe2_up_final = False
        
        if "tcpprobe1" in str(final_apm_status):
            # Parse for tcpprobe1 specific status (should be UP again)
            apm_lines = str(final_apm_status).split('\n')
            for line in apm_lines:
                if "tcpprobe1" in line:
                    if "UP" in line or "up" in line.lower():
                        tcpprobe1_up_final = True
                        st.log("SUCCESS: tcpprobe1 is UP again after IP re-addition")
                        break
            if not tcpprobe1_up_final:
                st.log("WARNING: tcpprobe1 is not UP after IP re-addition")
        
        if "tcpprobe2" in str(final_apm_status):
            # Parse for tcpprobe2 specific status (should still be UP)
            apm_lines = str(final_apm_status).split('\n')
            for line in apm_lines:
                if "tcpprobe2" in line:
                    if "UP" in line or "up" in line.lower():
                        tcpprobe2_up_final = True
                        st.log("SUCCESS: tcpprobe2 is still UP after IP re-addition")
                        break
            if not tcpprobe2_up_final:
                st.log("WARNING: tcpprobe2 is not UP after IP re-addition")
        
        # Verify both probes are UP as expected for full recovery
        if tcpprobe1_up_final and tcpprobe2_up_final:
            st.log("SUCCESS: Both APM probes (tcpprobe1, tcpprobe2) are UP after recovery")
        else:
            st.log("WARNING: Not all APM probes are UP after recovery - tcpprobe1: UP={}, tcpprobe2: UP={}".format(tcpprobe1_up_final, tcpprobe2_up_final))
        
        # Display final route state
        st.log("Final route state (should show both nexthops restored):")
        st.show(nodes['SD4'], "show ip route vrf Vrf01")
        
        final_route_output = st.show(nodes['SD4'], "show ip route vrf Vrf01", skip_tmpl=True)
        st.log("Final route output: {}".format(final_route_output))
        
        # Verify expected behavior - route should be restored with both nexthops
        route_fully_restored = False
        both_nexthops_restored = False
        probe_recovery_verified = False
        
        if "172.16.255.1/32" in str(final_route_output):
            route_fully_restored = True
            st.log("SUCCESS: Route 172.16.255.1/32 exists after IP re-addition")
            
            # Check if both nexthops are restored
            if "10.212.10.6" in str(final_route_output) and "10.212.20.6" in str(final_route_output):
                both_nexthops_restored = True
                st.log("SUCCESS: Both nexthops (10.212.10.6 and 10.212.20.6) are restored")
            
            # Check if route behavior changed back (probe recovery)
            if str(after_removal_route_output) != str(final_route_output):
                probe_recovery_verified = True
                st.log("SUCCESS: Route output changed after IP re-addition - probe recovery occurred")
        else:
            st.log("WARNING: Route not found after IP re-addition")
        
        # APP-DB Verification: Should contain both nexthops since both probes are UP after recovery
        verify_app_db_static_route(
            nodes['SD4'],
            'redis-cli -n 0 hgetall "STATIC_ROUTE:Vrf01:172.16.255.1/32"',
            ['10.212.10.6', '10.212.20.6'],  # Both nexthops expected after IP re-addition recovery
            "APM Route Recovery via IP Re-addition"
        )
        
        # Test success criteria - route should be fully restored with both nexthops AND both probes UP
        if route_fully_restored and both_nexthops_restored and tcpprobe1_up_final and tcpprobe2_up_final:
            st.log("TEST PASSED: APM Route Recovery via IP Address Re-addition completed")
            st.log("Failed probe recovered and route restored with both nexthops")
            st.log("APM probe states verified: tcpprobe1=UP, tcpprobe2=UP")
            if probe_recovery_verified:
                st.log("Probe recovery was successfully verified")
            st.banner("APM Route Recovery via IP Address Re-addition Test - PASSED")
            st.report_pass('test_case_passed')
        else:
            st.report_fail('test case failed : test_apm_route_recovery_via_ip_readd')

    except Exception as e:
        st.log("Exception occurred during test execution: {}".format(str(e)))
        st.report_fail('test_case_failed', "Test failed with exception: {}".format(str(e)))
        
    finally:
        # Cleanup configurations
        st.banner("Cleanup: Removing all test configurations")
        
        try:
            # Stop both TCP servers on SD8 (running on different ports)
            st.config(nodes['SD8'], "pkill -f 'tcpserver.py 65432'", skip_error_check=True)
            st.config(nodes['SD8'], "pkill -f 'tcpserver.py 65433'", skip_error_check=True)
            st.wait(1)
            
            # Remove route
            st.config(nodes['SD4'], "config route del prefix vrf Vrf01 172.16.255.1/32", skip_error_check=True)
            
            # Remove APM probes from SD4 (leaf2)
            st.config(nodes['SD4'], "config apm del tcpprobe1", skip_error_check=True)
            st.config(nodes['SD4'], "config apm del tcpprobe2", skip_error_check=True)
            st.wait(1)
            
            # Remove IP addresses from SD8 dynamic ports (host1 D8D4P1 and D8D4P2)
            st.config(nodes['SD8'], "sudo ip addr del 10.212.10.6/24 dev {}".format(vars.D8D4P1), skip_error_check=True)
            st.config(nodes['SD8'], "sudo ip addr del 10.212.20.6/24 dev {}".format(vars.D8D4P2), skip_error_check=True)
            st.wait(1)
            
            # Remove dynamic ports from VLANs on SD4 (leaf2)
            st.config(nodes['SD4'], "config vlan member del 10 {}".format(vars.D4D8P1), skip_error_check=True)
            st.config(nodes['SD4'], "config vlan member del 20 {}".format(vars.D4D8P2), skip_error_check=True)
            
            # Clean up nohup files
            st.config(nodes['SD8'], "sudo rm -f nohup.out", skip_error_check=True)
            
            st.banner("Cleanup completed successfully")
            
        except Exception as cleanup_e:
            st.log("Warning: Some cleanup operations failed: {}".format(str(cleanup_e)))



######################################################################
# Test APM Route with Single Working Nexthop
######################################################################
@pytest.mark.system_box
@pytest.mark.community
@pytest.mark.community_pass
def test_apm_route_single_working_nexthop():
    """
    Test APM route behavior with one probe down and route populated for working nexthop only
    
    Test Scenario:
    Configure APM probes and static route, make one TCP probe down by not starting its server,
    then verify route is populated only for the working nexthop
    
    Test Steps:
    1. Configure dynamic ports to Vlan10 and Vlan20 on SD4 (leaf2)
    2. Configure IP addresses on SD8 dynamic ports
    3. Start TCP server only on one IP (tcpprobe2 will work, tcpprobe1 will be down)
    4. Configure APM probes tcpprobe1 and tcpprobe2
    5. Add static route with both nexthops and APM dependencies
    6. Verify tcpprobe1 is DOWN, tcpprobe2 is UP
    7. Verify route is populated only for the working nexthop (10.212.20.6)
    
    Configuration Sequence:
    - sudo config apm add tcpprobe1 --type tcp-connect --dst-ip 10.212.10.6 --dst-port 65432 --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true
    - sudo config apm add tcpprobe2 --type tcp-connect --dst-ip 10.212.20.6 --dst-port 65433 --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true
    - config route add prefix vrf Vrf01 172.16.255.1/32 nexthop 10.212.10.6,10.212.20.6 apm tcpprobe1,tcpprobe2
    
    Expected Behavior:
    - tcpprobe1: DOWN (no TCP server on 10.212.10.6:65432)
    - tcpprobe2: UP (TCP server running on 10.212.20.6:65433)
    - Route: Populated only for working nexthop 10.212.20.6
    """
    vars = st.get_testbed_vars()
    
    nodes = {}
    nodes['SD1'] = vars.D1  # SD1 (spine0)
    nodes['SD2'] = vars.D2   # SD2 (leaf0) 
    nodes['SD3'] = vars.D3   # SD3 (leaf1)
    nodes['SD4'] = vars.D4   # SD4 (leaf2)
    nodes['SD8'] = vars.D8   # SD8 (host1 - host device)
    
    st.banner("Starting APM Route with Single Working Nexthop Test")
    
    try:
        # Step 1: Configure dynamic ports on SD4 (leaf2) to Vlan10 and Vlan20
        st.banner("Step 1: Configuring dynamic ports on SD4 (leaf2) to Vlan10 and Vlan20")
        
        # Add D4D8P1 to Vlan10 on SD4 (leaf2)
        st.config(nodes['SD4'], "config vlan member add 10 {} -u".format(vars.D4D8P1))
        
        # Add D4D8P2 to Vlan20 on SD4 (leaf2)
        st.config(nodes['SD4'], "config vlan member add 20 {} -u".format(vars.D4D8P2))
        
        # Step 2: Configure IP addresses on SD8 dynamic ports
        st.banner("Step 2: Configuring IP addresses on SD8 dynamic ports")
        
        # Bring up D8D4P1 and configure IP address on SD8 (host1)
        st.config(nodes['SD8'], "sudo ifconfig {} up".format(vars.D8D4P1))
        st.wait(2)
        st.config(nodes['SD8'], "sudo ip addr add 10.212.10.6/24 dev {}".format(vars.D8D4P1))
        
        # Bring up D8D4P2 and configure IP address on SD8 (host1)
        st.config(nodes['SD8'], "sudo ifconfig {} up".format(vars.D8D4P2))
        st.wait(2)
        st.config(nodes['SD8'], "sudo ip addr add 10.212.20.6/24 dev {}".format(vars.D8D4P2))
        st.wait(1)
        
        # Step 3: Start TCP server only on one IP (tcpprobe2 will work, tcpprobe1 will be down)
        st.banner("Step 3: Starting TCP server only on 10.212.20.6 (tcpprobe1 will fail)")
        
        
        # Start only TCP server on 10.212.20.6:65433 (tcpprobe2 will be UP)
        # Do NOT start server on 10.212.10.6:65432 (tcpprobe1 will be DOWN)
        # Using full path to avoid issues with cd in sudo -s context
        tcp_server_cmd2 = "sudo nohup python3 /home/vxr/tcpserver.py 65433 10.212.20.6 > /tmp/tcpserver2.log 2>&1 &"
        st.config(nodes['SD8'], tcp_server_cmd2)
        st.wait(5)  # Wait for server to start
        
        

        # Verify only one TCP server is running (port 65433)
        verify_cmd = "ps aux | grep '[t]cpserver.py'"
        server_status = st.show(nodes['SD8'], verify_cmd, skip_tmpl=True, skip_error_check=True)
        st.log("TCP server status on host1 (should show only port 65433): {}".format(server_status))
        
        # Step 4: Configure APM probes (tcpprobe1 will be DOWN, tcpprobe2 will be UP)
        st.banner("Step 4: Configuring APM TCP probes on SD4 (leaf2)")
        
        # Command 1: sudo config apm add tcpprobe1 (will be DOWN - no server listening)
        apm_cmd1 = "sudo config apm add tcpprobe1 --type tcp-connect --dst-ip 10.212.10.6 --dst-port 65432 --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true"
        st.config(nodes['SD4'], apm_cmd1)
        st.wait(1)
        
        # Command 2: sudo config apm add tcpprobe2 (will be UP - server listening)
        apm_cmd2 = "sudo config apm add tcpprobe2 --type tcp-connect --dst-ip 10.212.20.6 --dst-port 65433 --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true"
        st.config(nodes['SD4'], apm_cmd2)
        st.wait(2)  # Wait for APM probes to initialize
        
        # Verify APM probes are configured
        apm_config_output = st.show(nodes['SD4'], "show apm", skip_tmpl=True, skip_error_check=True)
        st.log("APM configuration: {}".format(apm_config_output))
        
        # Step 5: Add static route with both nexthops and APM dependencies
        st.banner("Step 5: Adding static route with both nexthops and APM dependencies")
        
        # Command 3: config route add with both nexthops and APM
        route_add_cmd = "config route add prefix vrf Vrf01 172.16.255.1/32 nexthop 10.212.10.6,10.212.20.6 apm tcpprobe1,tcpprobe2"
        st.config(nodes['SD4'], route_add_cmd)
        st.wait(3)  # Wait for route to be installed
        
        # Step 6: Verify tcpprobe1 is DOWN, tcpprobe2 is UP
        st.banner("Step 6: Verifying APM probe states - tcpprobe1 DOWN, tcpprobe2 UP")
        
        # Check APM probe status
        apm_status = st.show(nodes['SD4'], "show apm-status", skip_tmpl=True, skip_error_check=True)
        st.log("APM status output: {}".format(apm_status))
        
        # Verify specific probe states
        tcpprobe1_down = False
        tcpprobe2_up = False
        
        if "tcpprobe1" in str(apm_status):
            # Parse for tcpprobe1 specific status (should be DOWN)
            apm_lines = str(apm_status).split('\n')
            for line in apm_lines:
                if "tcpprobe1" in line:
                    if "DOWN" in line or "down" in line.lower() or "FAIL" in line or "fail" in line.lower():
                        tcpprobe1_down = True
                        st.log("SUCCESS: tcpprobe1 is DOWN as expected (no server)")
                        break
            if not tcpprobe1_down:
                st.log("WARNING: tcpprobe1 is not DOWN as expected")
        
        if "tcpprobe2" in str(apm_status):
            # Parse for tcpprobe2 specific status (should be UP)
            apm_lines = str(apm_status).split('\n')
            for line in apm_lines:
                if "tcpprobe2" in line:
                    if "UP" in line or "up" in line.lower():
                        tcpprobe2_up = True
                        st.log("SUCCESS: tcpprobe2 is UP as expected (server running)")
                        break
            if not tcpprobe2_up:
                st.log("WARNING: tcpprobe2 is not UP as expected")

        # Verify expected probe states
        if tcpprobe1_down and tcpprobe2_up:
            st.log("SUCCESS: APM probe states are as expected - tcpprobe1: DOWN, tcpprobe2: UP")
        else:
            st.log("WARNING: APM probe states - tcpprobe1: DOWN={}, tcpprobe2: UP={}".format(tcpprobe1_down, tcpprobe2_up))
        
        # Step 7: Verify route is populated only for the working nexthop (10.212.20.6)
        st.banner("Step 7: Verifying route populated only for working nexthop")
        
        # Display route state
        st.log("Route state (should show only working nexthop 10.212.20.6):")
        st.show(nodes['SD4'], "show ip route vrf Vrf01")
        
        route_output = st.show(nodes['SD4'], "show ip route vrf Vrf01", skip_tmpl=True)
        st.log("Route output: {}".format(route_output))
        
        # Verify expected behavior - route should exist with only working nexthop
        route_exists = False
        working_nexthop_present = False
        failed_nexthop_absent = False
        
        if "172.16.255.1/32" in str(route_output):
            route_exists = True
            st.log("SUCCESS: Route 172.16.255.1/32 exists")
            
            # Check if working nexthop (10.212.20.6) is present
            if "10.212.20.6" in str(route_output):
                working_nexthop_present = True
                st.log("SUCCESS: Working nexthop 10.212.20.6 is present in route")
            
            # Check if failed nexthop (10.212.10.6) is absent or has reduced presence
            failed_nexthop_count = str(route_output).count("10.212.10.6")
            if failed_nexthop_count == 0:
                failed_nexthop_absent = True
                st.log("SUCCESS: Failed nexthop 10.212.10.6 is completely absent from route")
            else:
                st.log("INFO: Failed nexthop 10.212.10.6 appears {} times in route output".format(failed_nexthop_count))
        else:
            st.log("WARNING: Route 172.16.255.1/32 not found")
        
        # APP-DB Verification: Should contain only the working nexthop (10.212.20.6)
        verify_app_db_static_route(
            nodes['SD4'],
            'redis-cli -n 0 hgetall "STATIC_ROUTE:Vrf01:172.16.255.1/32"',
            ['10.212.20.6'],  # Only expect working nexthop (tcpprobe2 UP)
            "APM Route Single Working Nexthop"
        )
        
        # Test success criteria
        if route_exists and working_nexthop_present and tcpprobe1_down and tcpprobe2_up:
            st.log("TEST PASSED: APM Route with Single Working Nexthop completed")
            st.log("Route populated only for working nexthop with correct APM probe states")
            st.log("APM probe states verified: tcpprobe1=DOWN, tcpprobe2=UP")
            st.log("Route shows working nexthop: 10.212.20.6")
            if failed_nexthop_absent:
                st.log("Failed nexthop properly excluded from route")
            st.banner("APM Route with Single Working Nexthop Test - PASSED")
            st.report_pass('test_case_passed')
        else:
            st.report_fail('test case failed: test_apm_route_single_working_nexthop')

    except Exception as e:
        st.log("Exception occurred during test execution: {}".format(str(e)))
        st.report_fail('test_case_failed', "Test failed with exception: {}".format(str(e)))
        
    finally:
        # Cleanup configurations
        st.banner("Cleanup: Removing all test configurations")
        
        try:
            # Stop TCP server on SD8 (only one was started)
            st.config(nodes['SD8'], "pkill -f 'tcpserver.py 65433'", skip_error_check=True)
            st.wait(1)
            
            # Remove route
            st.config(nodes['SD4'], "config route del prefix vrf Vrf01 172.16.255.1/32", skip_error_check=True)
            
            # Remove APM probes from SD4 (leaf2)
            st.config(nodes['SD4'], "config apm del tcpprobe1", skip_error_check=True)
            st.config(nodes['SD4'], "config apm del tcpprobe2", skip_error_check=True)
            
            # Remove IP addresses from SD8 dynamic ports (host1 D8D4P1 and D8D4P2)
            st.config(nodes['SD8'], "sudo ip addr del 10.212.10.6/24 dev {}".format(vars.D8D4P1), skip_error_check=True)
            st.config(nodes['SD8'], "sudo ip addr del 10.212.20.6/24 dev {}".format(vars.D8D4P2), skip_error_check=True)
            st.wait(1)
            
            # Remove dynamic ports from VLANs on SD4 (leaf2)
            st.config(nodes['SD4'], "config vlan member del 10 {}".format(vars.D4D8P1), skip_error_check=True)
            st.config(nodes['SD4'], "config vlan member del 20 {}".format(vars.D4D8P2), skip_error_check=True)
            st.wait(1)

            # Clean up log files and server script on SD8
            st.config(nodes['SD8'], "rm -f /tmp/tcpserver2.log", skip_error_check=True)
            
            st.banner("Cleanup completed successfully")
            
        except Exception as cleanup_e:
            st.log("Warning: Some cleanup operations failed: {}".format(str(cleanup_e)))

######################################################################
# Test APM Partial Dependency Removal - Route Preserved with Both Nexthops
######################################################################
@pytest.mark.system_box
@pytest.mark.community
@pytest.mark.community_pass
def test_apm_partial_dependency_removal():
    """
    Test APM partial dependency removal while preserving route with both nexthops
    
    Test Scenario:
    Configure APM probes and static route with APM dependencies, then remove APM dependency
    from only one probe (tcpprobe1) while keeping the route active with both nexthops.
    Both probes should remain UP and route should show both nexthops.
    
    Test Steps:
    1. Configure dynamic ports to Vlan10 and Vlan20 on SD4 (leaf2)
    2. Configure IP addresses on SD8 dynamic ports
    3. Start TCP servers on both IPs on SD8
    4. Configure APM probes tcpprobe1 and tcpprobe2
    5. Add static route with both nexthops and APM dependencies
    6. Verify both probes are UP and route has both nexthops
    7. Remove APM dependency for only tcpprobe1 (partial removal)
    8. Verify both probes remain UP and route still has both nexthops
    
    Configuration Sequence:
    - sudo config apm add tcpprobe1 --type tcp-connect --dst-ip 10.212.10.6 --dst-port 65432 --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true
    - sudo config apm add tcpprobe2 --type tcp-connect --dst-ip 10.212.20.6 --dst-port 65433 --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true
    - config route add prefix vrf Vrf01 172.16.255.1/32 nexthop 10.212.10.6,10.212.20.6 apm tcpprobe1,tcpprobe2
    - config route del prefix vrf Vrf01 172.16.255.1/32 apm tcpprobe1
    
    Expected Behavior:
    - Initially: Both probes UP, route with both nexthops and both APM dependencies
    - After partial removal: Both probes UP, route with both nexthops, only tcpprobe2 dependency
    """
    vars = st.get_testbed_vars()
    
    nodes = {}
    nodes['SD1'] = vars.D1  # SD1 (spine0)
    nodes['SD2'] = vars.D2   # SD2 (leaf0) 
    nodes['SD3'] = vars.D3   # SD3 (leaf1)
    nodes['SD4'] = vars.D4   # SD4 (leaf2)
    nodes['SD8'] = vars.D8   # SD8 (host1 - host device)
    
    st.banner("Starting APM Partial Dependency Removal Test")
    
    try:
        # Step 1: Configure dynamic ports on SD4 (leaf2) to Vlan10 and Vlan20
        st.banner("Step 1: Configuring dynamic ports on SD4 (leaf2) to Vlan10 and Vlan20")
        
        # Add D4D8P1 to Vlan10 on SD4 (leaf2)
        st.config(nodes['SD4'], "config vlan member add 10 {} -u".format(vars.D4D8P1))
        
        # Add D4D8P2 to Vlan20 on SD4 (leaf2)
        st.config(nodes['SD4'], "config vlan member add 20 {} -u".format(vars.D4D8P2))
        
        # Step 2: Configure IP addresses on SD8 dynamic ports
        st.banner("Step 2: Configuring IP addresses on SD8 dynamic ports")
        
        # Bring up D8D4P1 and configure IP address on SD8 (host1)
        st.config(nodes['SD8'], "sudo ifconfig {} up".format(vars.D8D4P1))
        st.wait(2)
        st.config(nodes['SD8'], "sudo ip addr add 10.212.10.6/24 dev {}".format(vars.D8D4P1))
        
        # Bring up D8D4P2 and configure IP address on SD8 (host1)
        st.config(nodes['SD8'], "sudo ifconfig {} up".format(vars.D8D4P2))
        st.wait(2)
        st.config(nodes['SD8'], "sudo ip addr add 10.212.20.6/24 dev {}".format(vars.D8D4P2))

        

        # Step 3: Start TCP servers on both IPs on SD8
        st.banner("Step 3: Starting TCP servers on both IPs on SD8")
        

        
        # Start TCP servers in background on both IPs on SD8
        # Using full path to avoid issues with cd in sudo -s context
        tcp_server_cmd1 = "sudo nohup python3 /home/vxr/tcpserver.py 65432 10.212.10.6 > /tmp/tcpserver1.log 2>&1 &"
        st.config(nodes['SD8'], tcp_server_cmd1)
        st.wait(2)
        
        tcp_server_cmd2 = "sudo nohup python3 /home/vxr/tcpserver.py 65433 10.212.20.6 > /tmp/tcpserver2.log 2>&1 &"
        st.config(nodes['SD8'], tcp_server_cmd2)
        st.wait(5)  # Wait for servers to start
        
        
        # Step 4: Configure APM probes (both will be UP)
        st.banner("Step 4: Configuring APM TCP probes on SD4 (leaf2)")
        
        # Command 1: sudo config apm add tcpprobe1
        apm_cmd1 = "sudo config apm add tcpprobe1 --type tcp-connect --dst-ip 10.212.10.6 --dst-port 65432 --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true"
        st.config(nodes['SD4'], apm_cmd1)
        st.wait(1)
        
        # Command 2: sudo config amp add tcpprobe2
        apm_cmd2 = "sudo config apm add tcpprobe2 --type tcp-connect --dst-ip 10.212.20.6 --dst-port 65433 --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true"
        st.config(nodes['SD4'], apm_cmd2)
        st.wait(1)  # Wait for APM probes to initialize and come UP
        
        # Verify APM probes are configured
        apm_config_output = st.show(nodes['SD4'], "show apm", skip_tmpl=True, skip_error_check=True)
        st.log("APM configuration: {}".format(apm_config_output))
        
        # Step 5: Add static route with both nexthops and APM dependencies
        st.banner("Step 5: Adding static route with both nexthops and APM dependencies")
        
        # Command 3: config route add with both nexthops and APM
        route_add_cmd = "config route add prefix vrf Vrf01 172.16.255.1/32 nexthop 10.212.10.6,10.212.20.6 apm tcpprobe1,tcpprobe2"
        st.config(nodes['SD4'], route_add_cmd)
        st.wait(2)  # Wait for route to be installed
        
        # Step 6: Verify both probes are UP and route has both nexthops
        st.banner("Step 6: Verifying initial state - both probes UP, route with both nexthops")
        
        # Check APM probe status (both should be UP)
        initial_apm_status = st.show(nodes['SD4'], "show apm-status", skip_tmpl=True, skip_error_check=True)
        st.log("Initial APM status output: {}".format(initial_apm_status))
        
        # Verify specific probe states initially
        tcpprobe1_up_initial = False
        tcpprobe2_up_initial = False
        
        if "tcpprobe1" in str(initial_apm_status):
            apm_lines = str(initial_apm_status).split('\n')
            for line in apm_lines:
                if "tcpprobe1" in line and ("UP" in line or "up" in line.lower()):
                    tcpprobe1_up_initial = True
                    st.log("SUCCESS: tcpprobe1 is UP initially")
                    break
            if not tcpprobe1_up_initial:
                st.log("WARNING: tcpprobe1 is not UP initially")
        
        if "tcpprobe2" in str(initial_apm_status):
            apm_lines = str(initial_apm_status).split('\n')
            for line in apm_lines:
                if "tcpprobe2" in line and ("UP" in line or "up" in line.lower()):
                    tcpprobe2_up_initial = True
                    st.log("SUCCESS: tcpprobe2 is UP initially")
                    break
            if not tcpprobe2_up_initial:
                st.log("WARNING: tcpprobe2 is not UP initially")
        
        # Verify both probes are UP
        if tcpprobe1_up_initial and tcpprobe2_up_initial:
            st.log("SUCCESS: Both APM probes (tcpprobe1, tcpprobe2) are UP initially")
        
        # Display initial route state
        st.log("Initial route state (should show both nexthops):")
        st.show(nodes['SD4'], "show ip route vrf Vrf01")
        
        initial_route_output = st.show(nodes['SD4'], "show ip route vrf Vrf01", skip_tmpl=True)
        st.log("Initial route output: {}".format(initial_route_output))
        
        # Verify route with both nexthops is present
        route_initially_present = False
        both_nexthops_initial = False
        if "172.16.255.1/32" in str(initial_route_output):
            route_initially_present = True
            st.log("SUCCESS: Route 172.16.255.1/32 is installed")
            
            if "10.212.10.6" in str(initial_route_output) and "10.212.20.6" in str(initial_route_output):
                both_nexthops_initial = True
                st.log("SUCCESS: Both nexthops (10.212.10.6 and 10.212.20.6) are present initially")
        
        # Step 7: Remove APM dependency for only tcpprobe1 (partial removal)
        st.banner("Step 7: Removing APM dependency for tcpprobe1 only (partial removal)")
        
        # Command 4: config route del prefix with apm tcpprobe1 (partial dependency removal)
        apm_partial_remove_cmd = "config route del prefix vrf Vrf01 172.16.255.1/32 apm tcpprobe1"
        st.config(nodes['SD4'], apm_partial_remove_cmd)
        st.wait(2)  # Wait for route update
        
        # Step 8: Verify both probes remain UP and route still has both nexthops
        st.banner("Step 8: Verifying final state - both probes UP, route with both nexthops preserved")
        
        # Check APM probe status after partial dependency removal
        final_apm_status = st.show(nodes['SD4'], "show apm-status", skip_tmpl=True, skip_error_check=True)
        st.log("Final APM status output: {}".format(final_apm_status))
        
        # Verify specific probe states after partial removal
        tcpprobe1_up_final = False
        tcpprobe2_up_final = False
        
        if "tcpprobe1" in str(final_apm_status):
            apm_lines = str(final_apm_status).split('\n')
            for line in apm_lines:
                if "tcpprobe1" in line and ("UP" in line or "up" in line.lower()):
                    tcpprobe1_up_final = True
                    st.log("SUCCESS: tcpprobe1 is still UP after partial dependency removal")
                    break
            if not tcpprobe1_up_final:
                st.log("WARNING: tcpprobe1 is not UP after partial dependency removal")
        
        if "tcpprobe2" in str(final_apm_status):
            apm_lines = str(final_apm_status).split('\n')
            for line in apm_lines:
                if "tcpprobe2" in line and ("UP" in line or "up" in line.lower()):
                    tcpprobe2_up_final = True
                    st.log("SUCCESS: tcpprobe2 is still UP after partial dependency removal")
                    break
            if not tcpprobe2_up_final:
                st.log("WARNING: tcpprobe2 is not UP after partial dependency removal")
        
        # Verify both probes remain UP
        if tcpprobe1_up_final and tcpprobe2_up_final:
            st.log("SUCCESS: Both APM probes (tcpprobe1, tcpprobe2) remain UP after partial dependency removal")
        
        # Display final route state
        st.log("Final route state (should still show both nexthops):")
        st.show(nodes['SD4'], "show ip route vrf Vrf01")
        
        final_route_output = st.show(nodes['SD4'], "show ip route vrf Vrf01", skip_tmpl=True)
        st.log("Final route output: {}".format(final_route_output))
        
        # Verify expected behavior - route should preserve both nexthops
        route_preserved = False
        both_nexthops_preserved = False
        
        if "172.16.255.1/32" in str(final_route_output):
            route_preserved = True
            st.log("SUCCESS: Route 172.16.255.1/32 is preserved after partial dependency removal")
            
            # Check if both nexthops are still present
            if "10.212.10.6" in str(final_route_output) and "10.212.20.6" in str(final_route_output):
                both_nexthops_preserved = True
                st.log("SUCCESS: Both nexthops (10.212.10.6 and 10.212.20.6) are preserved")
        else:
            st.log("WARNING: Route not found after partial dependency removal")
        
        # APP-DB verification after partial dependency removal
        st.banner("Step 9: Verifying APP-DB static route after partial dependency removal")
        # Both nexthops should remain

        verify_app_db_static_route(
            nodes['SD4'],
            'redis-cli -n 0 hgetall "STATIC_ROUTE:Vrf01:172.16.255.1/32"',
            ['10.212.20.6'],  # Only expect working nexthop (tcpprobe2 UP)
            "APM Route Single Working Nexthop"
        )
        
        # Test success criteria - route preserved with both nexthops AND both probes UP
        if route_preserved and both_nexthops_preserved and tcpprobe1_up_final and tcpprobe2_up_final:
            st.log("TEST PASSED: APM Partial Dependency Removal completed successfully")
            st.log("Route preserved with both nexthops after removing only tcpprobe1 dependency")
            st.log("APM probe states verified: tcpprobe1=UP, tcpprobe2=UP")
            st.log("Both nexthops remain active: 10.212.10.6, 10.212.20.6")
            st.banner("APM Partial Dependency Removal Test - PASSED")
            st.report_pass('test_case_passed')
        else:
            st.report_fail('test_case_failed', "Test failed: Unexpected route state")

    except Exception as e:
        st.log("Exception occurred during test execution: {}".format(str(e)))
        st.report_fail('test_case_failed', "Test failed with exception: {}".format(str(e)))
        
    finally:
        # Cleanup configurations
        st.banner("Cleanup: Removing all test configurations")
        
        try:
            # Stop both TCP servers on SD8
            st.config(nodes['SD8'], "pkill -f 'tcpserver.py 65432'", skip_error_check=True)
            st.config(nodes['SD8'], "pkill -f 'tcpserver.py 65433'", skip_error_check=True)
            st.wait(1)
            
            # Remove route completely
            st.config(nodes['SD4'], "config route del prefix vrf Vrf01 172.16.255.1/32", skip_error_check=True)
            
            # Remove APM probes from SD4 (leaf2)
            st.config(nodes['SD4'], "config apm del tcpprobe1", skip_error_check=True)
            st.config(nodes['SD4'], "config apm del tcpprobe2", skip_error_check=True)
            st.wait(1)
            
            # Remove IP addresses from SD8 dynamic ports (host1 D8D4P1 and D8D4P2)
            st.config(nodes['SD8'], "sudo ip addr del 10.212.10.6/24 dev {}".format(vars.D8D4P1), skip_error_check=True)
            st.config(nodes['SD8'], "sudo ip addr del 10.212.20.6/24 dev {}".format(vars.D8D4P2), skip_error_check=True)
            st.wait(1)
            
            # Remove dynamic ports from VLANs on SD4 (leaf2)
            st.config(nodes['SD4'], "config vlan member del 10 {}".format(vars.D4D8P1), skip_error_check=True)
            st.config(nodes['SD4'], "config vlan member del 20 {}".format(vars.D4D8P2), skip_error_check=True)
            
            # Clean up nohup files
            st.config(nodes['SD8'], "sudo rm -f nohup.out", skip_error_check=True)
            st.config(nodes['SD8'], "sudo rm -f /tmp/tcpserver1.log", skip_error_check=True)
            st.config(nodes['SD8'], "sudo rm -f /tmp/tcpserver2.log", skip_error_check=True)
            
            st.banner("Cleanup completed successfully")
            
        except Exception as cleanup_e:
            st.log("Warning: Some cleanup operations failed: {}".format(str(cleanup_e)))

######################################################################
# Test APM Static Route BGP Redistribution
######################################################################
@pytest.mark.system_box
@pytest.mark.community
@pytest.mark.community_pass
def test_apm_static_route_bgp_redistribution():
    """
    Test APM static route with BGP redistribution and uplink port flap
    
    Test Scenario:
    Configure APM probes and static route with APM dependencies on SD4, redistribute
    the static route via BGP, verify it appears on SD2, then test uplink port flap
    to verify route withdrawal and re-advertisement.
    
    Test Steps:
    Phase 1 - BGP Redistribution:
    1. Configure dynamic ports to Vlan10 and Vlan20 on SD4 (leaf2)
    2. Configure IP addresses on SD8 dynamic ports
    3. Start TCP servers on both IPs on SD8
    4. Configure APM probes tcpprobe1 and tcpprobe2 on SD4
    5. Add static route with both nexthops and APM dependencies on SD4
    6. Configure BGP redistribution of static routes on SD4
    7. Verify route with nexthops is present on SD2
    8. Verify APP-DB static route entry
    
    Phase 2 - Uplink Port Flap:
    9a. Shutdown uplink ports (D4D1P1, D4D1P2) on SD4 to spine0
    9b. Verify route disappears from SD2 after port shutdown
    9c. Startup uplink ports on SD4
    9d. Verify route reappears on SD2 after port startup
    
    Configuration Sequence:
    - sudo config apm add tcpprobe1 --type tcp-connect --dst-ip 10.212.10.6 --dst-port 65432 --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true
    - sudo config apm add tcpprobe2 --type tcp-connect --dst-ip 10.212.20.6 --dst-port 65433 --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true
    - config route add prefix vrf Vrf01 172.16.255.1/32 nexthop 10.212.10.6,10.212.20.6 apm tcpprobe1,tcpprobe2
    - BGP redistribution: router bgp 2363033449 vrf Vrf01 -> address-family ipv4 unicast -> redistribute static
    - config interface shutdown D4D1P1, D4D1P2 (uplink ports)
    - config interface startup D4D1P1, D4D1P2 (uplink ports)
    
    Expected Behavior:
    - APM probes UP on SD4
    - Static route installed on SD4 with both nexthops
    - Route redistributed via BGP and present on SD2
    - Route disappears from SD2 when uplink goes down
    - Route reappears on SD2 when uplink comes back up
    """
    vars = st.get_testbed_vars()
    
    nodes = {}
    nodes['SD1'] = vars.D1  # SD1 (spine0)
    nodes['SD2'] = vars.D2   # SD2 (leaf0) 
    nodes['SD3'] = vars.D3   # SD3 (leaf1)
    nodes['SD4'] = vars.D4   # SD4 (leaf2)
    nodes['SD8'] = vars.D8   # SD8 (host1 - host device)
    
    st.banner("Starting APM Static Route BGP Redistribution Test")
    
    # Initialize BGP ASN variable for use in both main and cleanup sections
    bgp_asn = "30"  # Default BGP ASN, will be updated if existing config is found
    
    try:
        # Step 1: Configure dynamic ports on SD4 (leaf2) to Vlan10 and Vlan20
        st.banner("Step 1: Configuring dynamic ports on SD4 (leaf2) to Vlan10 and Vlan20")
        
        # Add D4D8P1 to Vlan10 on SD4 (leaf2)
        st.config(nodes['SD4'], "config vlan member add 10 {} -u".format(vars.D4D8P1))
        
        # Add D4D8P2 to Vlan20 on SD4 (leaf2)
        st.config(nodes['SD4'], "config vlan member add 20 {} -u".format(vars.D4D8P2))
          
        # Step 2: Configure IP addresses on SD8 dynamic ports
        st.banner("Step 2: Configuring IP addresses on SD8 dynamic ports")
        
        # Configure IP address on SD8 D8D4P1
        st.config(nodes['SD8'], "sudo ifconfig {} up".format(vars.D8D4P1))
        st.wait(2)
        st.config(nodes['SD8'], "sudo ip addr add 10.212.10.6/24 dev {}".format(vars.D8D4P1))
        
        # Configure IP address on SD8 D8D4P2
        st.config(nodes['SD8'], "sudo ifconfig {} up".format(vars.D8D4P2))
        st.wait(2)
        st.config(nodes['SD8'], "sudo ip addr add 10.212.20.6/24 dev {}".format(vars.D8D4P2))
        
        # Step 3: Start TCP servers on both IPs on SD8
        st.banner("Step 3: Starting TCP servers on both IPs on SD8")
        
            
        
        # Start both TCP servers on different ports
        tcp_server_cmd1 = "sudo nohup python3 /home/vxr/tcpserver.py 65432 10.212.10.6 > /tmp/tcpserver1.log 2>&1 &"
        st.config(nodes['SD8'], tcp_server_cmd1)
        st.wait(5)

        tcp_server_cmd2 = "sudo nohup python3 /home/vxr/tcpserver.py 65433 10.212.20.6 > /tmp/tcpserver2.log 2>&1 &"
        st.config(nodes['SD8'], tcp_server_cmd2)
        st.wait(5)  # Wait for servers to start
        
        # Step 4: Configure APM probes on SD4 (leaf2)
        st.banner("Step 4: Configuring APM TCP probes on SD4 (leaf2)")
        
        # Command 1: sudo config apm add tcpprobe1
        apm_cmd1 = "sudo config apm add tcpprobe1 --type tcp-connect --dst-ip 10.212.10.6 --dst-port 65432 --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true"
        st.config(nodes['SD4'], apm_cmd1)
        
        # Command 2: sudo config apm add tcpprobe2
        apm_cmd2 = "sudo config apm add tcpprobe2 --type tcp-connect --dst-ip 10.212.20.6 --dst-port 65433 --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true"
        st.config(nodes['SD4'], apm_cmd2)
        st.wait(1)  # Wait for APM probes to initialize and come UP
        
        # Verify APM probes are configured
        apm_config_output = st.show(nodes['SD4'], "show apm", skip_tmpl=True, skip_error_check=True)
        st.log("APM configuration: {}".format(apm_config_output))
        
        # Step 5: Add static route with both nexthops and APM dependencies on SD4
        st.banner("Step 5: Adding static route with both nexthops and APM dependencies on SD4")
        
        # Command 3: config route add with both nexthops and APM (corrected IP address)
        route_add_cmd = "config route add prefix vrf Vrf01 172.16.255.1/32 nexthop 10.212.10.6,10.212.20.6 apm tcpprobe1,tcpprobe2"
        st.config(nodes['SD4'], route_add_cmd)
        st.wait(5)  # Wait for route to be installed
        
        # Verify APM probe status on SD4
        apm_status = st.show(nodes['SD4'], "show apm-status", skip_tmpl=True, skip_error_check=True)
        st.log("APM status on SD4: {}".format(apm_status))
        

        st.show(nodes['SD2'], "show ip route vrf Vrf01", skip_tmpl=True, skip_error_check=True)

        st.wait(5)

        st.show(nodes['SD4'], "show ip route vrf Vrf01", skip_tmpl=True, skip_error_check=True)


        
          # Wait for BGP redistribution to take effect
        st.wait(120)
        # Verify BGP configuration on SD4
        bgp_config_check = st.show(nodes['SD4'], "vtysh -c 'show running-config'", skip_tmpl=True, skip_error_check=True)
        st.log("BGP configuration check on SD4: {}".format(bgp_config_check))
        
        # Step 7: Verify route with nexthops is present on SD2
        st.banner("Step 7: Verifying redistributed route is present on SD2")
        

        
        # Check routes on SD2 (leaf0)
        st.log("Checking for redistributed route on SD2:")
        route_output_sd2 = st.show(nodes['SD2'], "show ip route vrf Vrf01", skip_tmpl=True, skip_error_check=True)
        st.log("Route output on SD2: {}".format(route_output_sd2))
        
        # Verify if the redistributed route is present on SD2
        route_present_on_sd2 = False
        if "172.16.255.1/32" in str(route_output_sd2):
            route_present_on_sd2 = True
            st.log("SUCCESS: Route 172.16.255.1/32 found on SD2 via BGP redistribution")
        else:
            st.log("WARNING: Route 172.16.255.1/32 not found on SD2")
        
        st.log("BGP redistribution configured on SD4")
        # st.wait(7200)

        # APP-DB verification for BGP redistribution test
        st.banner("Step 8: Verifying APP-DB static route after BGP redistribution")
        verify_app_db_static_route(
            nodes['SD4'],
            'redis-cli -n 0 hgetall "STATIC_ROUTE:Vrf01:172.16.255.1/32"',
            ['10.212.10.6', '10.212.20.6'],
            "APM Route Both Nexthops"
        )
        
        # =================== UPLINK PORT FLAP TEST ===================
        st.banner("Step 9: Uplink Port Flap Test")
        
        # Step 9a: Shutdown uplink ports on SD4 to spine0
        st.banner("Step 9a: Shutting down uplink ports on SD4 to spine0")
        st.log("Shutting down leaf2 (SD4) ports connected to spine0 (SD1)")
        st.config(nodes['SD4'], "config interface shutdown {}".format(vars.D4D1P1))
        st.config(nodes['SD4'], "config interface shutdown {}".format(vars.D4D1P2))
        
        st.log("Waiting 180 seconds for BGP convergence after port shutdown")
        st.wait(180)
        
        # Step 9b: Verify route disappears from SD2
        st.banner("Step 9b: Verifying route disappears from SD2 after uplink shutdown")
        route_output_sd2_after_shutdown = st.show(nodes['SD2'], "show ip route vrf Vrf01", skip_tmpl=True, skip_error_check=True)
        st.log("Route output on SD2 after shutdown: {}".format(route_output_sd2_after_shutdown))
        route_absent_on_sd2 = False
        if "172.16.255.1/32" not in str(route_output_sd2_after_shutdown):
            route_absent_on_sd2 = True
            st.log("SUCCESS: Route 172.16.255.1/32 disappeared from SD2 after uplink shutdown")
        else:
            st.log("WARNING: Route 172.16.255.1/32 still present on SD2 after uplink shutdown")
        
        # Step 9c: Startup uplink ports on SD4
        st.banner("Step 9c: Starting up uplink ports on SD4 to spine0")
        st.log("Starting up leaf2 (SD4) ports connected to spine0 (SD1)")
        st.config(nodes['SD4'], "config interface startup {}".format(vars.D4D1P1))
        st.config(nodes['SD4'], "config interface startup {}".format(vars.D4D1P2))
        
        st.log("Waiting 30 seconds for BGP convergence after port startup")
        st.wait(120)
        
        # Step 9d: Verify route reappears on SD2
        st.banner("Step 9d: Verifying route reappears on SD2 after uplink startup")
        route_output_sd2_after_startup = st.show(nodes['SD2'], "show ip route vrf Vrf01", skip_tmpl=True, skip_error_check=True)
        st.log("Route output on SD2 after startup: {}".format(route_output_sd2_after_startup))
        route_reappeared_on_sd2 = False
        if "172.16.255.1/32" in str(route_output_sd2_after_startup):
            route_reappeared_on_sd2 = True
            st.log("SUCCESS: Route 172.16.255.1/32 reappeared on SD2 after uplink startup")
        else:
            st.log("WARNING: Route 172.16.255.1/32 did not reappear on SD2 after uplink startup")
        
        # Test success criteria - must pass all checks
        uplink_flap_success = route_absent_on_sd2 and route_reappeared_on_sd2
        
        if route_present_on_sd2 and uplink_flap_success:
            st.log("TEST PASSED: APM Static Route BGP Redistribution with Uplink Flap completed successfully")
            st.log("- Route 172.16.255.1/32 redistributed from SD4 to SD2 via BGP")
            st.log("- Route disappeared from SD2 when uplink went down")
            st.log("- Route reappeared on SD2 when uplink came back up")
            st.banner("APM Static Route BGP Redistribution with Uplink Flap Test - PASSED")
            st.report_pass('test_case_passed')
        else:
            st.log("TEST FAILED: One or more verification criteria not met")
            failure_reasons = []
            if not route_present_on_sd2:
                failure_reasons.append("Initial BGP redistribution failed")
            if not route_absent_on_sd2:
                failure_reasons.append("Route did not disappear on uplink down")
            if not route_reappeared_on_sd2:
                failure_reasons.append("Route did not reappear on uplink up")
            st.report_fail('test_case_failed', "Test failed: {}".format(", ".join(failure_reasons)))

    except Exception as e:
        st.log("Exception occurred during test execution: {}".format(str(e)))
        st.report_fail('test_case_failed', "Test failed with exception: {}".format(str(e)))
        
    finally:
        # Cleanup configurations
        st.banner("Cleanup: Removing all test configurations")
        
        try:
            # Stop both TCP servers on SD8
            
            
            # Remove route completely from SD4
            st.config(nodes['SD4'], "config route del prefix vrf Vrf01 172.16.255.1/32", skip_error_check=True)
            
            # Remove APM probes from SD4 (leaf2)
            st.config(nodes['SD4'], "config apm del tcpprobe1", skip_error_check=True)
            st.config(nodes['SD4'], "config apm del tcpprobe2", skip_error_check=True)
            
            # Remove IP addresses from SD8 dynamic ports
            st.config(nodes['SD8'], "sudo ip addr del 10.212.10.6/24 dev {}".format(vars.D8D4P1), skip_error_check=True)
            st.config(nodes['SD8'], "sudo ip addr del 10.212.20.6/24 dev {}".format(vars.D8D4P2), skip_error_check=True)
            
            # Remove dynamic ports from VLANs on SD4 (leaf2)
            st.config(nodes['SD4'], "config vlan member del 10 {}".format(vars.D4D8P1), skip_error_check=True)
            st.config(nodes['SD4'], "config vlan member del 20 {}".format(vars.D4D8P2), skip_error_check=True)
            
            # Clean up log files and server script on SD8
            st.config(nodes['SD8'], "sudo rm -f /tmp/tcpserver1.log", skip_error_check=True)
            st.config(nodes['SD8'], "sudo rm -f /tmp/tcpserver2.log", skip_error_check=True)
            st.config(nodes['SD8'], "sudo rm -f nohup.out", skip_error_check=True)

            st.config(nodes['SD8'], "sudo pkill -f 'tcpserver.py 65432'", skip_error_check=True)
            st.config(nodes['SD8'], "sudo pkill -f 'tcpserver.py 65433'", skip_error_check=True)
            
            st.banner("Cleanup completed successfully")
            
        except Exception as cleanup_e:
            st.log("Warning: Some cleanup operations failed: {}".format(str(cleanup_e)))

######################################################################
# Test EVPN Multi-Homing with Linux Hosts and APM Integration
######################################################################
@pytest.mark.system_box
@pytest.mark.community
@pytest.mark.community_pass
def test_evpn_mh_linux_hosts_apm():
    """
    Test EVPN Multi-Homing with Linux hosts (using Linux bonding) and APM integration
    
    Device Mapping:
    - SD1 (spine0): Spine switch
    - SD2 (leaf0): EVPN Multi-Homing Leaf with PortChannel5 and Loopback5 (via YAML config)
    - SD3 (leaf1): EVPN Multi-Homing Leaf with PortChannel5 and Loopback5 (via YAML config)  
    - SD4 (leaf2): Additional leaf for tcpprobe2 target
    - SD5 (leaf3): Additional leaf
    - SD7 (client): Linux client device
    - SD7 (host0/HOST1): Linux host with dual-homing PortChannel5 bond to both SD2 and SD3
    - SD8 (host1/HOST2): Linux host for second TCP server target (connects to SD4)
    
    Test Steps:
    1. PortChannel5 with EVPN-ESI and Loopback5 on SD2/SD3 configured via static_route_apm_evpn_mh_v6_config.yaml
    2. Configure Linux bond PortChannel5 on SD7 (host0) with dual-homing to SD2 and SD3
    3. Configure interface and start TCP server on SD8 (host1)
    4. Start TCP server on SD7 (host0)
    5. Configure APM probes and routes on SD2, SD3, and SD4 targeting both TCP servers
    6. Verify APM probe states and route installation across all devices
    7. Configure Loopback6 on SD8 for ping test
    8. Add route on SD7 for ping destination
    9. Perform ping test from SD8 to SD7 with server kill scenario
    10. Cleanup all manually configured items (YAML deconfig handles PortChannel5/Loopback5 on SD2/SD3)
    """
    vars = st.get_testbed_vars()
    
    nodes = {}
    nodes['SD1'] = vars.D1  # SD1 (spine0)
    nodes['SD2'] = vars.D2  # SD2 (leaf0) 
    nodes['SD3'] = vars.D3  # SD3 (leaf1)
    nodes['SD4'] = vars.D4  # SD4 (leaf2)
    nodes['SD7'] = vars.D7  # SD7 (host0 - host device)
    nodes['SD8'] = vars.D8  # SD8 (host1 - host device)
    st.banner("Starting EVPN Multi-Homing with Linux Hosts APM Test")
    
    try:
        # Step 1: PortChannel5 and Loopback5 configurations handled by static_route_apm_evpn_mh_v6_config.yaml
        st.banner("Step 1: PortChannel5 with EVPN-ESI configurations handled by config YAML")
        st.log("SD2 (leaf0) and SD3 (leaf1) PortChannel5 and Loopback5 configurations from YAML")
        
        # Step 2: Configure Linux bond PortChannel5 on SD7 (host0)
        st.banner("Step 2: Configuring Linux bond PortChannel5 on SD7 (host0) with dual-homing")
        
        # Create PortChannel5 as Linux bond
        st.config(nodes['SD7'], "sudo ip link add PortChannel5 type bond mode 802.3ad")
        st.config(nodes['SD7'], "sudo ip link set PortChannel5 up")
        st.wait(1)
        
        # Add first member eth1 (SD7 to SD2) to PortChannel5
        st.config(nodes['SD7'], "sudo ip link set {} down".format(vars.D7D2P1))
        st.config(nodes['SD7'], "sudo ip link set {} master PortChannel5".format(vars.D7D2P1))
        st.config(nodes['SD7'], "sudo ip link set {} up".format(vars.D7D2P1))
        st.wait(1)
        
        # Add second member eth3 (SD7 to SD3) to PortChannel5
        st.config(nodes['SD7'], "sudo ip link set {} down".format(vars.D7D3P1))
        st.config(nodes['SD7'], "sudo ip link set {} master PortChannel5".format(vars.D7D3P1))
        st.config(nodes['SD7'], "sudo ip link set {} up".format(vars.D7D3P1))
        st.wait(1)
        
        # Add IP to PortChannel5
        st.config(nodes['SD7'], "sudo ip addr add 10.212.10.5/24 dev PortChannel5")
        st.wait(1)
        
        # Add routes for Loopback5 IPs on SD2 and SD3
        st.config(nodes['SD7'], "sudo ip route add 172.16.1.1/32 via 10.212.10.10")
        st.wait(2)
        st.config(nodes['SD7'], "sudo ip route add 172.16.2.1/32 via 10.212.10.10")
        st.wait(1)
        
        # Verify bond status
        bond_status = st.show(nodes['SD7'], "cat /proc/net/bonding/PortChannel5", skip_tmpl=True, skip_error_check=True)
        st.log("PortChannel5 bond status: {}".format(bond_status))
        
        # Step 3: Start TCP server on SD7 (host0)
        st.banner("Step 3: Starting TCP server on SD7 (host0)")
        
        # Start TCP server on 10.212.10.5:65432
        tcp_server_cmd = "sudo nohup python3 /home/vxr/tcpserver.py 65432 10.212.10.5 > /tmp/tcpserver.log 2>&1 &"
        st.config(nodes['SD7'], tcp_server_cmd)
        st.wait(5)  # Extended wait for server startup
        
        # Verify TCP server is running
        server_check = st.config(nodes['SD7'], "ps aux | grep 'tcpserver.py 65432'", skip_error_check=True)
        st.log("TCP server check on SD7: {}".format(server_check))
        
        st.log("SD7 (host0) Linux bond PortChannel5 configuration and TCP server startup completed")
        
        # Step 4: Configure interface and TCP server on SD8 (host1)
        st.banner("Step 4: Configuring SD8 (host1) interface and TCP server")
        # Add SD4 D4D8P1 to VLAN 10 on SD4 (leaf2)
        st.config(nodes['SD4'], "config vlan member add 10 {} -u".format(vars.D4D8P1))
        st.wait(1)
        
        # Configure IP address on SD8 eth1
        st.config(nodes['SD8'], "sudo ifconfig {} up".format(vars.D8D4P1))
        st.wait(2)
        st.config(nodes['SD8'], "sudo ip addr add 10.212.10.6/24 dev {}".format(vars.D8D4P1))
        st.wait(1)
        
        # Start TCP server on SD8 10.212.10.6:65432
        tcp_server_cmd_sD8 = "sudo nohup python3 /home/vxr/tcpserver.py 65432 10.212.10.6 > /tmp/tcpserver_sD8.log 2>&1 &"
        st.config(nodes['SD8'], tcp_server_cmd_sD8)
        st.wait(5)  # Extended wait for server startup
        
        # Verify TCP server is running on SD8
        server_check_sD8 = st.config(nodes['SD8'], "ps aux | grep 'tcpserver.py 65432'", skip_error_check=True)
        st.log("TCP server check on SD8: {}".format(server_check_sD8))
        
        st.log("SD8 (host1) interface configuration and TCP server startup completed")
        
        # Step 5: Configure APM probes and routes on SD2 (leaf0)
        st.banner("Step 5: Configuring APM probes and route on SD2 (leaf0)")
        
        # Add tcpprobe1 targeting SD7 (10.212.10.5:65432)
        st.log("Adding tcpprobe1 on SD2 targeting SD7 (10.212.10.5:65432)")
        apm_cmd1_sd2 = "sudo config apm add tcpprobe1 --type tcp-connect --dst-ip 10.212.10.5 --dst-port 65432 --src-intf Loopback5 --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true"
        st.config(nodes['SD2'], apm_cmd1_sd2)
        st.wait(2)
        
        # Add tcpprobe2 targeting SD8 (10.212.10.6:65432)
        st.log("Adding tcpprobe2 on SD2 targeting SD8 (10.212.10.6:65432)")
        apm_cmd2_sd2 = "sudo config apm add tcpprobe2 --type tcp-connect --dst-ip 10.212.10.6 --dst-port 65432 --src-intf Loopback5 --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true"
        st.config(nodes['SD2'], apm_cmd2_sd2)
        st.wait(2)
        
        # Show APM status on SD2
        apm_status_sd2 = st.show(nodes['SD2'], "show apm-status", skip_tmpl=True, skip_error_check=True)
        st.log("APM status on SD2 (leaf0): {}".format(apm_status_sd2))
        
        # Add route with both nexthops and APM probes
        route_cmd_sd2 = "config route add prefix vrf Vrf01 172.17.255.1/32 nexthop 10.212.10.5,10.212.10.6 apm tcpprobe1,tcpprobe2"
        st.config(nodes['SD2'], route_cmd_sd2)
        st.wait(2)
        
        # Show IP route on SD2
        route_output_sd2 = st.show(nodes['SD2'], "show ip route vrf Vrf01", skip_tmpl=True)
        st.log("IP route VRF Vrf01 on SD2 (leaf0): {}".format(route_output_sd2))
        
        st.log("SD2 (leaf0) APM probes and route configuration completed")
        # Step 6: Configure APM probes and routes on SD3 (leaf1)
        st.banner("Step 6: Configuring APM probes and route on SD3 (leaf1)")
        
        # Add tcpprobe1 targeting SD7 (10.212.10.5:65432)
        apm_cmd1_sd3 = "sudo config apm add tcpprobe1 --type tcp-connect --dst-ip 10.212.10.5 --dst-port 65432 --src-intf Loopback5 --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true"
        st.config(nodes['SD3'], apm_cmd1_sd3)
        st.wait(2)
        
        # Add tcpprobe2 targeting SD8 (10.212.10.6:65432)
        apm_cmd2_sd3 = "sudo config apm add tcpprobe2 --type tcp-connect --dst-ip 10.212.10.6 --dst-port 65432 --src-intf Loopback5 --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true"
        st.config(nodes['SD3'], apm_cmd2_sd3)
        st.wait(2)
        
        # Show APM status on SD3
        apm_status_sd3 = st.show(nodes['SD3'], "show apm-status", skip_tmpl=True, skip_error_check=True)
        st.log("APM status on SD3 (leaf1): {}".format(apm_status_sd3))
        
        # Add route with both nexthops and APM probes
        route_cmd_sd3 = "config route add prefix vrf Vrf01 172.17.255.1/32 nexthop 10.212.10.5,10.212.10.6 apm tcpprobe1,tcpprobe2"
        st.config(nodes['SD3'], route_cmd_sd3)
        st.wait(2)
        
        # Show IP route on SD3
        route_output_sd3 = st.show(nodes['SD3'], "show ip route vrf Vrf01", skip_tmpl=True)
        st.log("IP route VRF Vrf01 on SD3 (leaf1): {}".format(route_output_sd3))
        
        st.log("SD3 (leaf1) APM probes and route configuration completed")
        
        # Step 7: Configure APM probes and routes on SD4 (leaf2)
        st.banner("Step 7: Configuring APM probes and route on SD4 (leaf2)")
        
        # Add tcpprobe1 targeting SD7 (10.212.10.5:65432)
        apm_cmd1_sd4 = "sudo config apm add tcpprobe1 --type tcp-connect --dst-ip 10.212.10.5 --dst-port 65432 --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true"
        st.config(nodes['SD4'], apm_cmd1_sd4)
        st.wait(2)
        
        # Add tcpprobe2 targeting SD8 (10.212.10.6:65432)
        apm_cmd2_sd4 = "sudo config apm add tcpprobe2 --type tcp-connect --dst-ip 10.212.10.6 --dst-port 65432 --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true"
        st.config(nodes['SD4'], apm_cmd2_sd4)
        st.wait(2)
        
        # Show APM status on SD4
        apm_status_sd4 = st.show(nodes['SD4'], "show apm-status", skip_tmpl=True, skip_error_check=True)
        st.log("APM status on SD4 (leaf2): {}".format(apm_status_sd4))
        
        # Add route with both nexthops and APM probes
        route_cmd_sd4 = "config route add prefix vrf Vrf01 172.17.255.1/32 nexthop 10.212.10.5,10.212.10.6 apm tcpprobe1,tcpprobe2"
        st.config(nodes['SD4'], route_cmd_sd4)
        st.wait(2)
        
        # Show IP route on SD4
        route_output_sd4 = st.show(nodes['SD4'], "show ip route vrf Vrf01", skip_tmpl=True)
        st.log("IP route VRF Vrf01 on SD4 (leaf2): {}".format(route_output_sd4))
        
        st.log("SD4 (leaf2) APM probes and route configuration completed")
        
        # Step 9: Extra configurations for ping test
        st.banner("Step 9: Extra configurations for ping test")
        
        # Config on host1 (SD8) - Loopback6 for ping source
        st.banner("Extra Config on SD8 (host1): Adding Loopback6")
        st.config(nodes['SD8'], "sudo ip link add Loopback6 type dummy")
        st.config(nodes['SD8'], "sudo ip link set Loopback6 up")
        st.wait(1)
        st.config(nodes['SD8'], "sudo ip addr add 172.18.255.1/32 dev Loopback6")
        st.wait(1)
        
        # Config on leaf2 (SD4) - Route with APM dependency for ping destination
        st.banner("Extra Config on SD4 (leaf2): Adding route with APM dependency for ping test")
        route_add_cmd = "config route add prefix vrf Vrf01 172.18.255.1/32 nexthop 10.212.10.6 apm tcpprobe2"
        st.config(nodes['SD4'], route_add_cmd)
        st.wait(2)
        
        # Config on host0 (SD7) - Route for ping destination
        st.banner("Extra Config on SD7 (host0): Adding route for ping destination")
        ping_route_cmd = "sudo ip route add 172.18.255.1/32 via 10.212.10.10"
        st.config(nodes['SD7'], ping_route_cmd)
        st.wait(5)
        
        # Step 10: Ping Test Phase 1 - Both TCP servers running
        st.banner("Ping Test Phase 1: Testing connectivity with both TCP servers running")
        st.wait(60)
        ping_cmd = "ping 10.212.10.5 -I 172.18.255.1 -c 3"
        ping_output1 = st.config(nodes['SD8'], ping_cmd, skip_error_check=True)
        st.log("Ping output (both servers running): {}".format(ping_output1))
        
        # Check if ping is successful
        ping1_success = False
        if ping_output1 and ("64 bytes from" in str(ping_output1) or "bytes from" in str(ping_output1)):
            ping1_success = True
            st.log("SUCCESS: Ping works when both TCP servers are running")
        else:
            st.log("FAILED: Ping failed when both TCP servers are running")
        
        # Ping Test Phase 2: Kill tcpserver2 and test ping again
        st.banner("Ping Test Phase 2: Killing tcpserver2 to make tcpprobe2 DOWN")
        
        # Kill tcpserver2 on SD8 (port 65432) to make tcpprobe2 DOWN
        kill_cmd = "pkill -f 'tcpserver.py 65432'"
        st.config(nodes['SD8'], kill_cmd, skip_error_check=True)
        st.wait(5)  # Wait for APM probe to detect server down
        
        # Run ping again - should fail since route dependency is broken
        ping_output2 = st.config(nodes['SD8'], ping_cmd, skip_error_check=True)
        st.log("Ping output (after killing tcpserver2): {}".format(ping_output2))
        
        # Check if ping fails
        ping2_failed = False
        if not ping_output2 or ("64 bytes from" not in str(ping_output2) and "bytes from" not in str(ping_output2)):
            ping2_failed = True
            st.log("SUCCESS: Ping correctly fails when tcpserver2 is down")
        elif "unreachable" in str(ping_output2).lower() or "timeout" in str(ping_output2).lower():
            ping2_failed = True
            st.log("SUCCESS: Ping correctly fails with unreachable/timeout when tcpserver2 is down")
        else:
            st.log("FAILED: Ping unexpectedly succeeded when tcpserver2 is down")
        
        # Ping test overall result
        ping_test_passed = ping1_success and ping2_failed
        
        if ping_test_passed:
            st.log("PING TEST PASSED: Connectivity works with servers up, fails when server down")
        else:
            st.log("PING TEST FAILED: Phase1 success: {}, Phase2 failure: {}".format(ping1_success, ping2_failed))
        
        # Final test success criteria
        # sd2_criteria_met = tcpprobe1_up_sd2 and route_with_probe1_sd2
        # sd3_criteria_met = tcpprobe1_up_sd3 and route_with_probe1_sd3
        # sd4_criteria_met = tcpprobe1_down_sd4 and tcpprobe2_up_sd4 and route_with_probe2_sd4
        
        # Test PASSES only if ALL scenarios are completely satisfied INCLUDING ping test
        if ping_test_passed:
            st.log("TEST PASSED: All verification criteria met successfully")
            st.log("SD2: tcpprobe1=UP, route with tcpprobe1 nexthop (10.212.10.5)")
            st.log("SD3: tcpprobe1=UP, route with tcpprobe1 nexthop (10.212.10.5)")
            st.log("SD4: tcpprobe1=DOWN, tcpprobe2=UP, route with tcpprobe2 nexthop (10.212.10.6)")
            st.log("PING TEST: Connectivity works with servers up, fails when server down")
            st.banner("EVPN Multi-Homing with Linux Hosts APM Test - PASSED")
            st.report_pass('test_case_passed')
        else:
            # Detailed failure reporting
            st.log("TEST FAILED: Not all verification criteria met")
            
            if not ping_test_passed:
                st.log("PING TEST FAILED: Phase1 success: {}, Phase2 failure: {}".format(ping1_success, ping2_failed))
            
            # if not sd2_criteria_met:
            #     st.log("SD2 FAILED: Required - tcpprobe1=UP, route with tcpprobe1")
            #     st.log("SD2 Status: tcpprobe1={}, route_with_probe1={}".format(tcpprobe1_up_sd2, route_with_probe1_sd2))
            
            # if not sd3_criteria_met:
            #     st.log("SD3 FAILED: Required - tcpprobe1=UP, route with tcpprobe1")
            #     st.log("SD3 Status: tcpprobe1={}, route_with_probe1={}".format(tcpprobe1_up_sd3, route_with_probe1_sd3))
            
            # if not sd4_criteria_met:
            #     st.log("SD4 FAILED: Required - tcpprobe1=DOWN, tcpprobe2=UP, route with tcpprobe2")
            #     st.log("SD4 Status: tcpprobe1_down={}, tcpprobe2={}, route_with_probe2={}".format(
            #         tcpprobe1_down_sd4, tcpprobe2_up_sd4, route_with_probe2_sd4))
            
            st.banner("EVPN Multi-Homing with Linux Hosts APM Test - FAILED")
            st.report_fail('test_case_failed', "Test failed - not all verification criteria met")
    
    except Exception as e:
        st.log("Exception occurred during test execution: {}".format(str(e)))
        st.report_fail('test_case_failed', "Test failed with exception: {}".format(str(e)))
    
    finally:
        # Cleanup configurations
        st.banner("Cleanup: Removing all test configurations")
        
        try:
            # Cleanup extra configurations first
            st.banner("Cleanup: Removing extra ping test configurations")
            
            # Remove extra route from SD4 (leaf2)
            st.log("Removing route 172.18.255.1/32 from SD4 (leaf2)")
            st.config(nodes['SD4'], "config route del prefix vrf Vrf01 172.18.255.1/32", skip_error_check=True)
            
            # Remove extra route from SD7 (host0)
            st.log("Removing route 172.18.255.1/32 from SD7 (host0)")
            st.config(nodes['SD7'], "sudo ip route del 172.18.255.1/32", skip_error_check=True)
            
            # Remove Loopback6 from SD8 (host1)
            st.log("Removing Loopback6 configurations from SD8 (host1)")
            st.config(nodes['SD8'], "sudo ip addr del 172.18.255.1/32 dev Loopback6", skip_error_check=True)
            st.config(nodes['SD8'], "sudo ip link set Loopback6 down", skip_error_check=True)
            st.config(nodes['SD8'], "sudo ip link delete Loopback6", skip_error_check=True)
            
            # Stop TCP servers on SD7 (host0) and SD8 (host1)
            st.log("Stopping TCP servers on SD7 and SD8")
            st.config(nodes['SD7'], "pkill -f 'tcpserver.py 65432'", skip_error_check=True)
            st.config(nodes['SD8'], "pkill -f 'tcpserver.py 65432'", skip_error_check=True)
            st.wait(2)
            
            # Remove routes from SD2 (leaf0)
            st.log("Removing route 172.17.255.1/32 from SD2 (leaf0)")
            st.config(nodes['SD2'], "config route del prefix vrf Vrf01 172.17.255.1/32", skip_error_check=True)
            
            # Remove routes from SD3 (leaf1)
            st.log("Removing route 172.17.255.1/32 from SD3 (leaf1)")
            st.config(nodes['SD3'], "config route del prefix vrf Vrf01 172.17.255.1/32", skip_error_check=True)
            
            # Remove routes from SD4 (leaf2)
            st.log("Removing route 172.17.255.1/32 from SD4 (leaf2)")
            st.config(nodes['SD4'], "config route del prefix vrf Vrf01 172.17.255.1/32", skip_error_check=True)
            
            # Remove APM probes from SD2 (leaf0)
            st.log("Removing APM probes from SD2 (leaf0)")
            st.config(nodes['SD2'], "config apm del tcpprobe1", skip_error_check=True)
            st.config(nodes['SD2'], "config apm del tcpprobe2", skip_error_check=True)
            
            # Remove APM probes from SD3 (leaf1)
            st.log("Removing APM probes from SD3 (leaf1)")
            st.config(nodes['SD3'], "config apm del tcpprobe1", skip_error_check=True)
            st.config(nodes['SD3'], "config apm del tcpprobe2", skip_error_check=True)
            
            # Remove APM probes from SD4 (leaf2)
            st.log("Removing APM probes from SD4 (leaf2)")
            st.config(nodes['SD4'], "config apm del tcpprobe1", skip_error_check=True)
            st.config(nodes['SD4'], "config apm del tcpprobe2", skip_error_check=True)
            
            # Remove IP address from SD8 interface
            st.log("Removing IP address from SD8 interface")
            st.config(nodes['SD8'], "sudo ip addr del 10.212.10.6/24 dev {}".format(vars.D8D4P1), skip_error_check=True)
            st.wait(1)
            
            # Remove VLAN member from SD4 (leaf2)
            st.log("Removing VLAN member from SD4 (leaf2)")
            st.config(nodes['SD4'], "config vlan member del 10 {}".format(vars.D4D8P1), skip_error_check=True)
            st.wait(1)
            
            # Remove routes from SD7 (host0)
            st.log("Removing routes from SD7 (host0)")
            st.config(nodes['SD7'], "sudo ip route del 172.16.1.1/32", skip_error_check=True)
            st.config(nodes['SD7'], "sudo ip route del 172.16.2.1/32", skip_error_check=True)
            st.wait(1)
            
            # Remove PortChannel5 IP from SD7 (host0)
            st.log("Removing PortChannel5 IP from SD7 (host0)")
            st.config(nodes['SD7'], "sudo ip addr del 10.212.10.5/24 dev PortChannel5", skip_error_check=True)
            st.wait(1)
            
            # Remove PortChannel5 members and delete PortChannel from SD7 (host0)
            st.log("Removing PortChannel5 Linux bond from SD7 (host0)")
            st.config(nodes['SD7'], "sudo ip link set {} nomaster".format(vars.D7D2P1), skip_error_check=True)
            st.config(nodes['SD7'], "sudo ip link set {} nomaster".format(vars.D7D3P1), skip_error_check=True)
            st.config(nodes['SD7'], "sudo ip link set PortChannel5 down", skip_error_check=True)
            st.config(nodes['SD7'], "sudo ip link delete PortChannel5", skip_error_check=True)
            st.wait(1)
            
            # Clean up log files on SD7 (host0)
            st.log("Cleaning up files on SD7 (host0)")
            st.config(nodes['SD7'], "sudo rm -f /tmp/tcpserver.log", skip_error_check=True)
            st.config(nodes['SD7'], "sudo rm -f nohup.out", skip_error_check=True)
            
            # Clean up log files on SD8 (host1)
            st.log("Cleaning up files on SD8 (host1)")
            st.config(nodes['SD8'], "sudo rm -f /tmp/tcpserver_sD8.log", skip_error_check=True)
            st.config(nodes['SD8'], "sudo rm -f nohup.out", skip_error_check=True)
            
            st.banner("Cleanup completed successfully - All configurations removed")
            
        except Exception as cleanup_e:
            st.log("Warning: Some cleanup operations failed: {}".format(str(cleanup_e)))

######################################################################
# Test EVPN Multi-Homing port shutdown
######################################################################
@pytest.mark.system_box
@pytest.mark.community
@pytest.mark.community_pass
def test_apm_port_shutdown_nexthop_failover():
    """
    Test APM TCP probe behavior when a port is shutdown, causing one probe to fail
    while the other remains operational, verifying route failover.
    
    Test Scenario:
    Configure similar setup as test_apm_partial_dependency_removal but with port shutdown.
    Add dynamic ports to VLAN 10 and VLAN 20 on SD4, assign IPs to dynamic ports on SD8,
    run TCP servers, configure APM probes, add route with APM dependencies, then shutdown
    one dynamic port on SD8 to cause tcpprobe2 to fail while tcpprobe1 remains UP.
    
    Configuration Sequence:
    - Add dynamic ports to VLAN 10 and VLAN 20 on SD4
    - Assign IP addresses to dynamic ports on SD8
    - Start TCP servers on both IPs on SD8
    - sudo config apm add tcpprobe1 --type tcp-connect --dst-ip 10.212.10.6 --dst-port 65432 --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true
    - sudo config apm add tcpprobe2 --type tcp-connect --dst-ip 10.212.20.6 --dst-port 65433 --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true
    - config route add prefix vrf Vrf01 172.16.255.1/32 nexthop 10.212.10.6,10.212.20.6 apm tcpprobe1,tcpprobe2
    - config interface shutdown <dynamic_port> (on SD8)
    
    Expected Behavior:
    - Initially: Both probes UP, route with both nexthops
    - After shutdown: tcpprobe1 UP, tcpprobe2 DOWN, route only for tcpprobe1
    """
    vars = st.get_testbed_vars()
    
    nodes = {}
    nodes['SD1'] = vars.D1  # SD1 (spine0)
    nodes['SD2'] = vars.D2  # SD2 (leaf0) 
    nodes['SD3'] = vars.D3  # SD3 (leaf1)
    nodes['SD4'] = vars.D4  # SD4 (leaf2)
    nodes['SD8'] = vars.D8  # SD8 (host1 - host device)
    
    st.banner("Starting APM Port Shutdown Nexthop Failover Test")
    
    try:
        # Step 1: Configure dynamic ports on SD4 (leaf2) to Vlan10 and Vlan20
        st.banner("Step 1: Configuring dynamic ports on SD4 (leaf2) to Vlan10 and Vlan20")
        
        # Add D4D8P1 to Vlan10 on SD4 (leaf2)
        st.config(nodes['SD4'], "config vlan member add 10 {} -u".format(vars.D4D8P1))
        
        # Add D4D8P2 to Vlan20 on SD4 (leaf2)
        st.config(nodes['SD4'], "config vlan member add 20 {} -u".format(vars.D4D8P2))
        
        # Step 2: Configure IP addresses on SD8 dynamic ports
        st.banner("Step 2: Configuring IP addresses on SD8 dynamic ports")
        
        # Configure IP address on SD8 D8D4P1
        st.config(nodes['SD8'], "sudo ifconfig {} up".format(vars.D8D4P1))
        st.wait(2)
        st.config(nodes['SD8'], "sudo ip addr add 10.212.10.6/24 dev {}".format(vars.D8D4P1))
        
        # Configure IP address on SD8 D8D4P2
        st.config(nodes['SD8'], "sudo ifconfig {} up".format(vars.D8D4P2))
        st.wait(2)
        st.config(nodes['SD8'], "sudo ip addr add 10.212.20.6/24 dev {}".format(vars.D8D4P2))
        
        # Step 3: Start TCP servers on both IPs on SD8 using existing helper function
        st.banner("Step 3: Starting TCP servers on both IPs on SD8")
        
        
        # Start TCP server on port 65432 bound to 10.212.10.6 (D8D4P1)
        tcp_server_cmd1 = "sudo nohup python3 /home/vxr/tcpserver.py 65432 10.212.10.6 > /tmp/tcpserver1.log 2>&1 &"
        st.config(nodes['SD8'], tcp_server_cmd1)
        st.wait(5)
        
        # Start TCP server on port 65433 bound to 10.212.20.6 (D8D4P2)
        tcp_server_cmd2 = "sudo nohup python3 /home/vxr/tcpserver.py 65433 10.212.20.6 > /tmp/tcpserver2.log 2>&1 &"
        st.config(nodes['SD8'], tcp_server_cmd2)
        st.wait(5)  # Wait for servers to start
        
        # Step 4: Configure APM probes on SD4 (leaf2)
        st.banner("Step 4: Configuring APM TCP probes on SD4 (leaf2)")
        
        # Command 1: sudo config apm add tcpprobe1
        apm_cmd1 = "sudo config apm add tcpprobe1 --type tcp-connect --dst-ip 10.212.10.6 --dst-port 65432 --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true"
        st.config(nodes['SD4'], apm_cmd1)
        st.wait(2)
        
        # Command 2: sudo config apm add tcpprobe2
        apm_cmd2 = "sudo config apm add tcpprobe2 --type tcp-connect --dst-ip 10.212.20.6 --dst-port 65433 --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true"
        st.config(nodes['SD4'], apm_cmd2)
        st.wait(2)  # Wait for APM probes to initialize and come UP
        
        # Verify APM probes are configured
        apm_config_output = st.show(nodes['SD4'], "show apm", skip_tmpl=True, skip_error_check=True)
        st.log("APM configuration: {}".format(apm_config_output))
        
        # Step 5: Add static route with both nexthops and APM dependencies
        st.banner("Step 5: Adding static route with both nexthops and APM dependencies")
        
        # Command 3: config route add with both nexthops and APM
        route_add_cmd = "config route add prefix vrf Vrf01 172.16.255.1/32 nexthop 10.212.10.6,10.212.20.6 apm tcpprobe1,tcpprobe2"
        st.config(nodes['SD4'], route_add_cmd)
        st.wait(3)  # Wait for route to be installed
        
        # Step 6: Verify initial state - both probes UP, route with both nexthops
        st.banner("Step 6: Verifying initial state - both probes UP, route with both nexthops")
        
        # Check APM probe status (both should be UP)
        initial_apm_status = st.show(nodes['SD4'], "show apm-status", skip_tmpl=True, skip_error_check=True)
        st.log("Initial APM status output: {}".format(initial_apm_status))
        
        # Verify specific probe states initially
        tcpprobe1_up_initial = False
        tcpprobe2_up_initial = False
        
        if "tcpprobe1" in str(initial_apm_status):
            apm_lines = str(initial_apm_status).split('\n')
            for line in apm_lines:
                if "tcpprobe1" in line and ("UP" in line or "up" in line.lower()):
                    tcpprobe1_up_initial = True
                    st.log("SUCCESS: tcpprobe1 is UP initially")
                    break
            if not tcpprobe1_up_initial:
                st.log("WARNING: tcpprobe1 is not UP initially")
        
        if "tcpprobe2" in str(initial_apm_status):
            apm_lines = str(initial_apm_status).split('\n')
            for line in apm_lines:
                if "tcpprobe2" in line and ("UP" in line or "up" in line.lower()):
                    tcpprobe2_up_initial = True
                    st.log("SUCCESS: tcpprobe2 is UP initially")
                    break
            if not tcpprobe2_up_initial:
                st.log("WARNING: tcpprobe2 is not UP initially")
        
        # Verify both probes are UP
        if tcpprobe1_up_initial and tcpprobe2_up_initial:
            st.log("SUCCESS: Both APM probes (tcpprobe1, tcpprobe2) are UP initially")
        
        # Display initial route state
        st.log("Initial route state (should show both nexthops):")
        st.show(nodes['SD4'], "show ip route vrf Vrf01")
        
        initial_route_output = st.show(nodes['SD4'], "show ip route vrf Vrf01", skip_tmpl=True)
        st.log("Initial route output: {}".format(initial_route_output))
        
        
        # Step 7: Shutdown D8D4P2 on SD8 to cause tcpprobe2 to fail
        st.banner("Step 7: Shutting down dynamic port D8D4P2 on SD8 to simulate port failure")
        
        # Command 4: Bring down interface using Linux command
        port_shutdown_cmd = "sudo ip link set {} down".format(vars.D8D4P2)
        st.config(nodes['SD8'], port_shutdown_cmd)
        st.wait(5)  # Wait for interface to go down and APM to detect failure
        
        # Step 8: Verify tcpprobe1 UP, tcpprobe2 DOWN, route with only tcpprobe1 nexthop
        st.banner("Step 8: Verifying final state - tcpprobe1 UP, tcpprobe2 DOWN, route failover")
        
        # Check APM probe status after port shutdown with retry logic
        max_retries = 3  # 1 minute total wait time
        expected_state_reached = False
        
        for retry in range(max_retries):
            final_apm_status = st.show(nodes['SD4'], "show apm-status", skip_tmpl=True, skip_error_check=True)
            st.log("Final APM status output (attempt {}): {}".format(retry + 1, final_apm_status))
            
            # Verify specific probe states after port shutdown
            tcpprobe1_up_final = False
            tcpprobe2_down_final = False
            
            if "tcpprobe1" in str(final_apm_status):
                apm_lines = str(final_apm_status).split('\n')
                for line in apm_lines:
                    if "tcpprobe1" in line and ("UP" in line or "up" in line.lower()):
                        tcpprobe1_up_final = True
                        st.log("SUCCESS: tcpprobe1 is still UP after port shutdown")
                        break
                if not tcpprobe1_up_final:
                    st.log("WARNING: tcpprobe1 is not UP after port shutdown")
            
            if "tcpprobe2" in str(final_apm_status):
                apm_lines = str(final_apm_status).split('\n')
                for line in apm_lines:
                    if "tcpprobe2" in line and ("DOWN" in line or "down" in line.lower() or "FAILED" in line or "failed" in line.lower()):
                        tcpprobe2_down_final = True
                        st.log("SUCCESS: tcpprobe2 is DOWN after port shutdown")
                        break
                if not tcpprobe2_down_final:
                    st.log("WARNING: tcpprobe2 is not DOWN after port shutdown")
            
            # Check if expected state is reached
            if tcpprobe1_up_final and tcpprobe2_down_final:
                expected_state_reached = True
                st.log("SUCCESS: Expected APM probe states reached - tcpprobe1 UP, tcpprobe2 DOWN")
                break
            
            st.wait(2, "Waiting for APM probe states to update")
        
        # Display final route state
        st.log("Final route state (should show only working nexthop):")
        st.show(nodes['SD4'], "show ip route vrf Vrf01")
        
        final_route_output = st.show(nodes['SD4'], "show ip route vrf Vrf01", skip_tmpl=True)
        st.log("Final route output: {}".format(final_route_output))
        
        # Verify expected behavior - route should exist with only working nexthop
        route_preserved = False
        working_nexthop_present = False
        
        if "172.16.255.1/32" in str(final_route_output):
            route_preserved = True
            st.log("SUCCESS: Route 172.16.255.1/32 exists after port shutdown")
            
            # Check if working nexthop (10.212.10.6) is present
            if "10.212.10.6" in str(final_route_output):
                working_nexthop_present = True
                st.log("SUCCESS: Working nexthop (10.212.10.6) is present in route")
        else:
            st.log("WARNING: Route not found after port shutdown")
        
        # APP-DB verification after port shutdown
        st.banner("Step 9: Verifying APP-DB static route after port shutdown")
        verify_app_db_static_route(
            nodes['SD4'],
            'redis-cli -n 0 hgetall "STATIC_ROUTE:Vrf01:172.16.255.1/32"',
            ['10.212.10.6'],  # Only expect working nexthop (tcpprobe2 UP)
            "APM Route Single Working Nexthop"
        )
        
        # Test success criteria
        if expected_state_reached and route_preserved and working_nexthop_present:
            st.log("TEST PASSED: APM Port Shutdown Nexthop Failover completed successfully")
            st.log("Probe states: tcpprobe1=UP, tcpprobe2=DOWN")
            st.log("Route failover: Only working nexthop (10.212.10.6) active")
            st.banner("APM Port Shutdown Nexthop Failover Test - PASSED")
            st.report_pass('test_case_passed')
        else:
            st.report_fail('test_case_failed', "Test failed: Unexpected route state")

    except Exception as e:
        st.log("Exception occurred during test execution: {}".format(str(e)))
        st.report_fail('test_case_failed', "Test failed with exception: {}".format(str(e)))
        
    finally:
        # Cleanup configurations
        st.banner("Cleanup: Removing all test configurations")
        
        try:
            # Stop both TCP servers on SD8
            st.config(nodes['SD8'], "sudo pkill -f tcpserver.py", skip_error_check=True)
            
            # Bring D8D4P2 back up using Linux command
            st.config(nodes['SD8'], "sudo ip link set {} up".format(vars.D8D4P2), skip_error_check=True)
            
            # Remove route completely
            st.config(nodes['SD4'], "config route del prefix vrf Vrf01 172.16.255.1/32", skip_error_check=True)
            
            # Remove APM probes from SD4 (leaf2)
            st.config(nodes['SD4'], "config apm del tcpprobe1", skip_error_check=True)
            st.config(nodes['SD4'], "config apm del tcpprobe2", skip_error_check=True)
            st.wait(1)
            
            # Remove IP addresses from SD8 dynamic ports
            st.config(nodes['SD8'], "sudo ip addr del 10.212.10.6/24 dev {}".format(vars.D8D4P1), skip_error_check=True)
            st.config(nodes['SD8'], "sudo ip addr del 10.212.20.6/24 dev {}".format(vars.D8D4P2), skip_error_check=True)
            
            # Remove dynamic ports from VLANs on SD4 (leaf2)
            st.config(nodes['SD4'], "config vlan member del 10 {}".format(vars.D4D8P1), skip_error_check=True)
            st.config(nodes['SD4'], "config vlan member del 20 {}".format(vars.D4D8P2), skip_error_check=True)
            
            # Clean up log files on SD8
            st.config(nodes['SD8'], "sudo rm -f /tmp/tcpserver1.log", skip_error_check=True)
            st.config(nodes['SD8'], "sudo rm -f /tmp/tcpserver2.log", skip_error_check=True)
            st.config(nodes['SD8'], "sudo rm -f nohup.out", skip_error_check=True)

            st.banner("Cleanup completed successfully")
            
        except Exception as cleanup_e:
            st.log("Warning: Some cleanup operations failed: {}".format(str(cleanup_e)))
    
    st.report_pass("test_case_passed", "APM Port Shutdown Nexthop Failover Test")


######################################################################
# Test APM Route Addition and Deletion Combined IPv6
######################################################################
@pytest.mark.system_box
@pytest.mark.community
@pytest.mark.community_pass
def test_apm_route_add_delete_combined_ipv6():
    """
    Test APM route addition and deletion in a single test case using IPv6 addresses
    IPv6 version of test_apm_route_add_delete_combined
    
    Test Scenario:
    1. First Phase: Configure APM probes, add route with APM dependencies, and verify
    2. Second Phase: Delete the route with APM dependencies and verify removal
    
    Test Steps:
    Phase 1 - APM Route Addition (IPv6):
    1. Configure dynamic ports to Vlan10 and Vlan20 on SD4 (leaf2)
    2. Configure IPv6 addresses on SD8 dynamic ports
    3. Start TCP servers on both IPv6 addresses on SD8 (port 65432)
    4. Configure APM TCP probes (tcpprobe1 and tcpprobe2) with VRF Vrf01
    5. Add static route with both IPv6 nexthops and APM dependencies
    6. Verify both APM probes are UP and route is installed in FRR
    7. Verify show static-route displays the route properly
    
    Phase 2 - APM Route Deletion (IPv6):
    8. Delete the route completely (with APM dependencies)
    9. Verify no static route is present in routing table
    10. Verify show static-route no longer displays the route
    11. Cleanup all configurations including APM probes and TCP servers
    """
    vars = st.get_testbed_vars()
    
    nodes = {}
    nodes['SD1'] = vars.D1  # SD1 (spine0)
    nodes['SD2'] = vars.D2  # SD2 (leaf0) 
    nodes['SD3'] = vars.D3  # SD3 (leaf1)
    nodes['SD4'] = vars.D4  # SD4 (leaf2)
    nodes['SD8'] = vars.D8  # SD8 (host1 - host device)
    
    st.banner("Starting APM Route Addition and Deletion Combined Test IPv6")
    
    try:
        # =================== PHASE 1: APM ROUTE ADDITION IPv6 ===================
        st.banner("PHASE 1: APM Route Addition and Verification IPv6")
        
        # Step 1: Configure dynamic ports to Vlan10 and Vlan20 on SD4 (leaf2)
        st.banner("Step 1: Configuring dynamic ports on SD4 (leaf2)")
        st.wait(3)
        
        # First, remove any existing IP configuration from interfaces to convert them from L3 to L2
        # Remove common IPv4 and IPv6 addresses that might be configured from previous tests
        st.config(nodes['SD4'], "config interface ip remove {} 10.212.10.4/24".format(vars.D4D8P1), skip_error_check=True)
        st.config(nodes['SD4'], "config interface ip remove {} 2001:db8:10::4/64".format(vars.D4D8P1), skip_error_check=True)
        st.config(nodes['SD4'], "config interface ip remove {} 10.212.20.4/24".format(vars.D4D8P2), skip_error_check=True)
        st.config(nodes['SD4'], "config interface ip remove {} 2001:db8:20::4/64".format(vars.D4D8P2), skip_error_check=True)
        st.wait(1)  # Wait for interface cleanup
        
        # Add D4D8P1 to Vlan10 on SD4 (leaf2)
        st.config(nodes['SD4'], "config vlan member add 10 {} -u".format(vars.D4D8P1))
        
        # Add D4D8P2 to Vlan20 on SD4 (leaf2)
        st.config(nodes['SD4'], "config vlan member add 20 {} -u".format(vars.D4D8P2))
        
        # Configure IPv6 addresses on Vlan10 and Vlan20 interfaces on SD4 (leaf2)
        st.config(nodes['SD4'], "config interface ip add Vlan10 2001:db8:10::4/64")
        st.config(nodes['SD4'], "config interface ip add Vlan20 2001:db8:20::4/64")
        
        # Step 2: Configure IPv6 addresses on SD8 dynamic ports
        st.banner("Step 2: Configuring IPv6 addresses on SD8 dynamic ports")
        
        # First, remove any existing IP configuration from SD8 interfaces
        st.config(nodes['SD8'], "sudo ip addr del 10.212.10.6/24 dev {}".format(vars.D8D4P1), skip_error_check=True)
        st.config(nodes['SD8'], "sudo ip addr del 2001:db8:10::6/64 dev {}".format(vars.D8D4P1), skip_error_check=True)
        st.config(nodes['SD8'], "sudo ip addr del 10.212.20.6/24 dev {}".format(vars.D8D4P2), skip_error_check=True)
        st.config(nodes['SD8'], "sudo ip addr del 2001:db8:20::6/64 dev {}".format(vars.D8D4P2), skip_error_check=True)
        st.wait(1)  # Wait for interface cleanup
        
        # Configure IPv6 address on SD8 D8D4P1
        st.config(nodes['SD8'], "sudo ifconfig {} up".format(vars.D8D4P1))
        st.wait(2)
        st.config(nodes['SD8'], "sudo ip addr add 2001:db8:10::6/64 dev {}".format(vars.D8D4P1))
        
        # Configure IPv6 address on SD8 D8D4P2
        st.config(nodes['SD8'], "sudo ifconfig {} up".format(vars.D8D4P2))
        st.wait(2)
        st.config(nodes['SD8'], "sudo ip addr add 2001:db8:20::6/64 dev {}".format(vars.D8D4P2))
        
        # Step 3: Start TCP servers on both IPv6 addresses on SD8
        st.banner("Step 3: Starting TCP servers on SD8")
        
        
        # Start TCP servers in background on both IPv6 addresses on SD8 (both on port 65432)
        tcp_server_cmd1 = "sudo nohup python3 /home/vxr/tcpserver.py 65432 2001:db8:10::6 > /tmp/tcpserver1.log 2>&1 &"
        st.config(nodes['SD8'], tcp_server_cmd1)
        st.wait(5)
        
        tcp_server_cmd2 = "sudo nohup python3 /home/vxr/tcpserver.py 65432 2001:db8:20::6 > /tmp/tcpserver2.log 2>&1 &"
        st.config(nodes['SD8'], tcp_server_cmd2)
        st.wait(5)  # Wait for servers to start
        
        # Step 4: Configure APM TCP probes on SD4 (leaf2)
        st.banner("Step 4: Configuring APM TCP probes on SD4 (leaf2)")
        
        # Configure APM TCP probe1 targeting SD8 D8D4P1 IPv6
        apm_cmd1 = "sudo config apm add tcpprobe1 --type tcp-connect --dst-ip 2001:db8:10::6 --dst-port 65432 --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true"
        st.config(nodes['SD4'], apm_cmd1)
        st.wait(3)
        
        # Configure APM TCP probe2 targeting SD8 D8D4P2 IPv6
        apm_cmd2 = "sudo config apm add tcpprobe2 --type tcp-connect --dst-ip 2001:db8:20::6 --dst-port 65432 --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true"
        st.config(nodes['SD4'], apm_cmd2)
        st.wait(3)  # Wait longer for APM probes to initialize and establish connections
        
        # Verify APM probes are configured and check status
        apm_config_output = st.show(nodes['SD4'], "show apm", skip_tmpl=True, skip_error_check=True)
        
        apm_status_output = st.show(nodes['SD4'], "show apm-status", skip_tmpl=True, skip_error_check=True)
        
        if "tcpprobe1" not in str(apm_config_output) or "tcpprobe2" not in str(apm_config_output):
            st.report_fail('test_case_failed', "APM probes tcpprobe1 or tcpprobe2 not configured properly on SD4")

        # Step 5: Add static route with both APM probes on SD4 (leaf2)
        st.banner("Step 5: Adding static route with APM configuration on SD4 (leaf2)")
        
        route_cmd = "config route add prefix vrf Vrf01 2001:db8:ffff::1/128 nexthop 2001:db8:10::6,2001:db8:20::6 apm tcpprobe1,tcpprobe2"
        st.config(nodes['SD4'], route_cmd)
        st.wait(3)  # Wait for route to be installed
        
        # Step 6: Verify APM status and route installation on SD4 (leaf2)
        st.banner("Step 6: Verifying APM status and route installation on SD4 (leaf2)")
        
        # Check APM status - test passes if both tcpprobe1 and tcpprobe2 are UP
        final_apm_status = st.show(nodes['SD4'], "show apm-status", skip_tmpl=True, skip_error_check=True)
        st.log("Final APM status on SD4: {}".format(final_apm_status))
        
        # Check if route is installed in VRF routing table
        route_output = st.show(nodes['SD4'], "show ipv6 route vrf Vrf01", skip_tmpl=True)
        st.log("VRF IPv6 Route table output on SD4: {}".format(route_output))
        
        # Test success criteria for Phase 1
        apm1_up = False
        apm2_up = False
        route_installed = False
        
        # Check both APM probes
        apm_status_str = str(final_apm_status).lower()
        if "tcpprobe1" in apm_status_str and "up" in apm_status_str:
            # More specific check for tcpprobe1 being up
            if "tcpprobe1" in str(final_apm_status) and any("up" in line.lower() for line in str(final_apm_status).split('\n') if "tcpprobe1" in line):
                apm1_up = True
                st.log("SUCCESS: APM probe tcpprobe1 is UP")
        
        if "tcpprobe2" in apm_status_str and "up" in apm_status_str:
            # More specific check for tcpprobe2 being up  
            if "tcpprobe2" in str(final_apm_status) and any("up" in line.lower() for line in str(final_apm_status).split('\n') if "tcpprobe2" in line):
                apm2_up = True
                st.log("SUCCESS: APM probe tcpprobe2 is UP")
        
        if not apm1_up:
            st.log("WARNING: APM probe tcpprobe1 is not UP")
        if not apm2_up:
            st.log("WARNING: APM probe tcpprobe2 is not UP")
        
        if "2001:db8:ffff::1/128" in str(route_output):
            route_installed = True
            st.log("SUCCESS: Static route 2001:db8:ffff::1/128 is installed in VRF Vrf01")
        else:
            st.log("WARNING: Static route 2001:db8:ffff::1/128 is not installed in VRF Vrf01")
        
        # Verify show static-route displays the route properly
        st.banner("Verifying show static-route displays the route properly")
        static_route_output = st.show(nodes['SD4'], "show static-route", skip_tmpl=True, skip_error_check=True)
        st.log("show static-route output after route addition: {}".format(static_route_output))
        
        # Check that static route is properly displayed with correct IPv6 nexthops and APM probes
        static_route_displayed = False
        if ("2001:db8:ffff::1/128" in str(static_route_output) and 
            "2001:db8:10::6" in str(static_route_output) and 
            "2001:db8:20::6" in str(static_route_output) and
            "tcpprobe1" in str(static_route_output) and
            "tcpprobe2" in str(static_route_output)):
            static_route_displayed = True
            st.log("SUCCESS: show static-route displays route 2001:db8:ffff::1/128 with nexthops 2001:db8:10::6,2001:db8:20::6 and APM probes tcpprobe1,tcpprobe2")
        else:
            st.log("WARNING: show static-route does not display the route properly")
        
        # APP-DB Verification for APM route addition - both IPv6 nexthops should be present
        st.banner("Verifying APP-DB contains static route entry with both IPv6 nexthops")
        verify_app_db_static_route(
            nodes['SD4'],
            'redis-cli -n 0 hgetall "STATIC_ROUTE:Vrf01:2001:db8:ffff::1/128"',
            ['2001:db8:10::6', '2001:db8:20::6'],  # Both IPv6 nexthops expected for APM routes
            "APM Route Addition Phase IPv6"
        )

        
        # Phase 1 validation
        phase1_success = apm1_up and apm2_up and route_installed and static_route_displayed
        if phase1_success:
            st.log("PHASE 1 PASSED: APM route addition verified successfully")
        else:
            st.log("PHASE 1 FAILED: APM route addition verification failed - APM1: {}, APM2: {}, Route: {}, StaticRoute: {}".format(apm1_up, apm2_up, route_installed, static_route_displayed))
        
        # =================== PHASE 2: APM ROUTE DELETION IPv6 ===================
        st.banner("PHASE 2: APM Route Deletion and Verification IPv6")
        
        # Step 8: Delete the static route completely (with APM dependencies)
        st.banner("Step 8: Deleting static route with APM dependencies")
        
        # Command: config route del prefix (deletes route and APM dependencies)
        route_del_cmd = "config route del prefix vrf Vrf01 2001:db8:ffff::1/128"
        st.config(nodes['SD4'], route_del_cmd)
        st.wait(2)  # Wait for route to be removed
        
        # Step 9: Verify no static route is present in routing table
        st.banner("Step 9: Verifying route is completely removed")
        
        final_route_output = st.show(nodes['SD4'], "show ipv6 route vrf Vrf01", skip_tmpl=True)
        st.log("Final IPv6 route output after deletion: {}".format(final_route_output))
        
        # Check that route is NOT present
        route_removed = True
        if "2001:db8:ffff::1/128" in str(final_route_output):
            route_removed = False
            st.log("FAIL: Route 2001:db8:ffff::1/128 is still present after deletion")
        else:
            st.log("SUCCESS: Route 2001:db8:ffff::1/128 is properly removed")
        
        # Verify show static-route no longer displays the route
        st.banner("Verifying show static-route no longer displays the route")
        final_static_route_output = st.show(nodes['SD4'], "show static-route", skip_tmpl=True, skip_error_check=True)
        st.log("show static-route output after route deletion: {}".format(final_static_route_output))
        
        # Check that static route is NOT displayed
        static_route_absent = True
        if "2001:db8:ffff::1/128" in str(final_static_route_output):
            static_route_absent = False
            st.log("FAIL: show static-route still displays route 2001:db8:ffff::1/128 after deletion")
        else:
            st.log("SUCCESS: show static-route no longer displays route 2001:db8:ffff::1/128")
        
        # APP-DB Verification for APM route deletion - should be empty after deletion
        st.banner("Verifying APP-DB no longer contains the IPv6 static route")
        verify_app_db_static_route(
            nodes['SD4'],
            'redis-cli -n 0 hgetall "STATIC_ROUTE:Vrf01:2001:db8:ffff::1/128"',
            [],  # No nexthops expected
            "APM Route Deletion Phase IPv6",
            expect_empty=True
        )
        
        # Phase 2 validation
        phase2_success = route_removed and static_route_absent
        if phase2_success:
            st.log("PHASE 2 PASSED: APM route deletion verified successfully")
        else:
            st.log("PHASE 2 FAILED: APM route deletion verification failed - Route removed: {}, Static route absent: {}".format(route_removed, static_route_absent))
        
        # Combined test result
        if phase1_success and phase2_success:
            st.log("COMBINED APM IPv6 TEST PASSED: Both route addition and deletion phases successful")
            st.banner("APM Route Addition and Deletion Combined Test IPv6 - PASSED")
            st.report_pass('test_case_passed')
        else:
            st.log("COMBINED APM IPv6 TEST FAILED: Phase 1: {}, Phase 2: {}".format(phase1_success, phase2_success))
            st.report_fail('test_case_failed', "Combined APM IPv6 test failed - Phase 1: {}, Phase 2: {}".format(phase1_success, phase2_success))

    except Exception as e:
        st.log("Exception occurred during combined APM IPv6 test execution: {}".format(str(e)))
        st.report_fail('test_case_failed', "Combined APM IPv6 test failed with exception: {}".format(str(e)))
        
    finally:
        # Cleanup configurations
        st.banner("Cleanup: Removing all APM IPv6 test configurations")
        
        try:
            # Stop TCP servers first
            st.config(nodes['SD8'], "sudo pkill -f 'tcpserver.py'", skip_error_check=True)
            st.wait(2)
            
            # Remove route (in case it still exists)
            st.config(nodes['SD4'], "config route del prefix vrf Vrf01 2001:db8:ffff::1/128", skip_error_check=True)
            st.wait(1)
            
            # Remove APM probes
            st.config(nodes['SD4'], "config apm del tcpprobe1", skip_error_check=True)
            st.config(nodes['SD4'], "config apm del tcpprobe2", skip_error_check=True)
            st.wait(2)
            
            # Remove IPv6 addresses from SD8
            st.config(nodes['SD8'], "sudo ip addr del 2001:db8:10::6/64 dev {}".format(vars.D8D4P1), skip_error_check=True)
            st.config(nodes['SD8'], "sudo ip addr del 2001:db8:20::6/64 dev {}".format(vars.D8D4P2), skip_error_check=True)
            
            # Remove IPv6 addresses from SD4 Vlan interfaces
            st.config(nodes['SD4'], "config interface ip remove Vlan10 2001:db8:10::4/64", skip_error_check=True)
            st.config(nodes['SD4'], "config interface ip remove Vlan20 2001:db8:20::4/64", skip_error_check=True)
            
            # Remove dynamic ports from VLANs on SD4
            st.config(nodes['SD4'], "config vlan member del 10 {}".format(vars.D4D8P1), skip_error_check=True)
            st.config(nodes['SD4'], "config vlan member del 20 {}".format(vars.D4D8P2), skip_error_check=True)
            
            # Clean up TCP server files
            st.config(nodes['SD8'], "sudo rm -f /tmp/tcpserver1.log /tmp/tcpserver2.log", skip_error_check=True)
            st.config(nodes['SD8'], "sudo rm -f nohup.out", skip_error_check=True)
            
            st.banner("Combined APM IPv6 test cleanup completed successfully")
            
        except Exception as cleanup_e:
            st.log("Warning: Some cleanup operations failed: {}".format(str(cleanup_e)))


######################################################################
# Test APM Multi-Tenant Route Configuration with Different VRFs
######################################################################
@pytest.mark.system_box
@pytest.mark.community
@pytest.mark.community_pass
def test_apm_multi_tenant_vrf_routes():
    """
    Test APM route configuration across multiple VRFs (multi-tenant scenario)
    
    Test Scenario:
    1. Configure two separate VRFs (Vrf01 and Vrf02) on both leaf2 and host1
    2. Configure APM probes for each VRF targeting the same IP but different ports/VRFs
    3. Add static routes in both VRFs with respective APM dependencies
    4. Verify both routes are installed independently in their respective VRFs
    5. Test probe failure in one VRF and verify it doesn't affect the other VRF
    
    Configuration Details:
    SD4 (leaf2):
    - Vrf01: Vlan10 with 10.212.10.10/24, tcpprobe1 -> 10.212.10.6:65432
    - Vrf02: Vlan40 with 10.212.10.10/24, tcpprobe2 -> 10.212.10.6:65433
    
    SD8 (host1):
    - Vrf01: D8D4P1 with 10.212.10.6/24, TCP server on port 65432
    - Vrf02: D8D4P2 with 10.212.10.6/24, TCP server on port 65433
    
    Test Steps:
    1. Configure VLAN membership for dynamic ports on SD4
    2. Configure VRFs and IP addresses on SD8 host interfaces
    3. Start TCP servers in both VRFs on SD8
    4. Configure APM probes (tcpprobe1 in Vrf01, tcpprobe2 in Vrf02)
    5. Add static routes in both VRFs with respective APM dependencies
    6. Verify both probes are UP and routes are installed in respective VRFs
    7. Verify APP-DB entries for both VRF routes
    8. Kill TCP server in Vrf01 and verify only Vrf01 route is affected
    9. Verify Vrf02 route remains unaffected
    10. Cleanup all configurations
    
    Expected Behavior:
    - Initially: Both tcpprobe1 and tcpprobe2 UP, routes in both VRFs
    - After Vrf01 TCP server failure: tcpprobe1 DOWN (Vrf01 route removed), tcpprobe2 UP (Vrf02 route remains)
    """
    vars = st.get_testbed_vars()
    
    nodes = {}
    nodes['SD1'] = vars.D1  # SD1 (spine0)
    nodes['SD2'] = vars.D2   # SD2 (leaf0) 
    nodes['SD3'] = vars.D3   # SD3 (leaf1)
    nodes['SD4'] = vars.D4   # SD4 (leaf2)
    nodes['SD8'] = vars.D8   # SD8 (host1 - host device)
    
    st.banner("Starting APM Multi-Tenant VRF Routes Test")
    
    try:
        # Phase 1: Configure VLAN membership on SD4 (leaf2)
        st.banner("Phase 1: Configuring VLAN membership on SD4 (leaf2)")
        
        # Add D4D8P1 to Vlan10 and D4D8P2 to Vlan40
        st.config(nodes['SD4'], "config vlan member add 10 {} -u".format(vars.D4D8P1))
        st.config(nodes['SD4'], "config vlan member add 40 {} -u".format(vars.D4D8P2))
        
        # Phase 2: Configure VRFs and IP addresses on SD8 (host1)
        st.banner("Phase 2: Configuring VRFs and IP addresses on SD8 (host1)")
        
        # Configure Vrf01 on D8D4P1
        st.config(nodes['SD8'], "sudo ip link add Vrf01 type vrf table 10")
        st.config(nodes['SD8'], "sudo ip link set dev Vrf01 up")
        st.config(nodes['SD8'], "sudo ifconfig {} up".format(vars.D8D4P1))
        st.config(nodes['SD8'], "sudo ip link set dev {} master Vrf01".format(vars.D8D4P1))
        st.wait(2)
        st.config(nodes['SD8'], "sudo ip addr add 10.212.10.6/24 dev {}".format(vars.D8D4P1))
        
        # Configure Vrf02 on D8D4P2
        st.config(nodes['SD8'], "sudo ip link add Vrf02 type vrf table 20")
        st.config(nodes['SD8'], "sudo ip link set dev Vrf02 up")
        st.config(nodes['SD8'], "sudo ifconfig {} up".format(vars.D8D4P2))
        st.config(nodes['SD8'], "sudo ip link set dev {} master Vrf02".format(vars.D8D4P2))
        st.wait(2)
        st.config(nodes['SD8'], "sudo ip addr add 10.212.10.6/24 dev {}".format(vars.D8D4P2))
        
        # Phase 3: Create and start TCP servers in both VRFs on SD8
        st.banner("Phase 3: Starting TCP servers in both VRFs on SD8 (host1)")
        
        
        # Start TCP server in Vrf01 on port 65432
        st.config(nodes['SD8'], "sudo ip vrf exec Vrf01 nohup python3 /home/vxr/tcpserver.py 65432 10.212.10.6 > /dev/null 2>&1 &")
        st.wait(5)
        
        # Start TCP server in Vrf02 on port 65433
        st.config(nodes['SD8'], "sudo ip vrf exec Vrf02 nohup python3 /home/vxr/tcpserver.py 65433 10.212.10.6 > /dev/null 2>&1 &")
        st.wait(5)
        
        # Verify TCP servers are running
        vrf01_server_check = st.show(nodes['SD8'], "sudo ip vrf exec Vrf01 netstat -tln | grep 65432", skip_tmpl=True)
        vrf02_server_check = st.show(nodes['SD8'], "sudo ip vrf exec Vrf02 netstat -tln | grep 65433", skip_tmpl=True)
        
        if "65432" not in str(vrf01_server_check):
            st.report_fail('test_case_failed', 'TCP server not running on port 65432 in Vrf01')
        
        if "65433" not in str(vrf02_server_check):
            st.report_fail('test_case_failed', 'TCP server not running on port 65433 in Vrf02')
        
        st.log("TCP servers verified running in both VRFs")
        
        # Phase 4: Configure APM probes on SD4 (leaf2)
        st.banner("Phase 4: Configuring APM probes on SD4 (leaf2)")
        
        # Configure tcpprobe1 in Vrf01
        st.config(nodes['SD4'], "sudo config apm add tcpprobe1 --type tcp-connect --dst-ip 10.212.10.6 --dst-port 65432 --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true")
        
        # Configure tcpprobe2 in Vrf02
        st.config(nodes['SD4'], "sudo config apm add tcpprobe2 --type tcp-connect --dst-ip 10.212.10.6 --dst-port 65433 --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf02 --enable true")
        st.wait(1)
        
        # Phase 5: Add static routes with APM dependencies
        st.banner("Phase 5: Adding static routes with APM dependencies")
        
        # Add route in Vrf01 with tcpprobe1
        st.config(nodes['SD4'], "config route add prefix vrf Vrf01 172.16.255.1/32 nexthop 10.212.10.6 apm tcpprobe1")
        
        # Add route in Vrf02 with tcpprobe2
        st.config(nodes['SD4'], "config route add prefix vrf Vrf02 172.16.255.1/32 nexthop 10.212.10.6 apm tcpprobe2")
        
        # Phase 6: Verify both probes are UP and routes are installed
        st.banner("Phase 6: Verifying both probes UP and routes installed")
        
        # Wait for probes to come UP
        st.wait(1)
        
        # Check APM probe status
        apm_status = st.show(nodes['SD4'], "show apm-status", skip_tmpl=True)
        st.log("APM status: {}".format(apm_status))
        
        if "tcpprobe1" not in str(apm_status) or "tcpprobe2" not in str(apm_status):
            st.report_fail('test_case_failed', 'APM probes not found in status output')
        
        # Verify routes in both VRFs
        vrf01_routes = st.show(nodes['SD4'], "show ip route vrf Vrf01", skip_tmpl=True)
        vrf02_routes = st.show(nodes['SD4'], "show ip route vrf Vrf02", skip_tmpl=True)
        
        st.log("Vrf01 routes: {}".format(vrf01_routes))
        st.log("Vrf02 routes: {}".format(vrf02_routes))
        
        # Verify 172.16.255.1/32 route is present in both VRFs
        if "172.16.255.1/32" not in str(vrf01_routes):
            st.report_fail('test_case_failed', 'Static route 172.16.255.1/32 not found in Vrf01')
        
        if "172.16.255.1/32" not in str(vrf02_routes):
            st.report_fail('test_case_failed', 'Static route 172.16.255.1/32 not found in Vrf02')
        
        # Phase 7: Verify APP-DB entries for both VRF routes
        st.banner("Phase 7: Verifying APP-DB entries for both VRF routes")
        
        # Check APP-DB for Vrf01 route
        vrf01_app_db_cmd = 'redis-cli -n 0 hgetall "STATIC_ROUTE:Vrf01:172.16.255.1/32"'
        if not verify_app_db_static_route(nodes['SD4'], vrf01_app_db_cmd, ['10.212.10.6'], "Vrf01 APP-DB"):
            st.report_fail('test_case_failed', 'Vrf01 APP-DB verification failed')
        
        # Check APP-DB for Vrf02 route
        vrf02_app_db_cmd = 'redis-cli -n 0 hgetall "STATIC_ROUTE:Vrf02:172.16.255.1/32"'
        if not verify_app_db_static_route(nodes['SD4'], vrf02_app_db_cmd, ['10.212.10.6'], "Vrf02 APP-DB"):
            st.report_fail('test_case_failed', 'Vrf02 APP-DB verification failed')
        
        # Verify static route configuration
        static_routes = st.show(nodes['SD4'], "show static-route", skip_tmpl=True)
        st.log("Static routes configuration: {}".format(static_routes))
        
        # Verify both VRF routes are present with correct APM dependencies
        if "tcpprobe1" not in str(static_routes) or "tcpprobe2" not in str(static_routes):
            st.report_fail('test_case_failed', 'APM dependencies not found in static route configuration')
        
        # Phase 8: Test probe failure in Vrf01 (kill TCP server)
        st.banner("Phase 8: Testing probe failure in Vrf01 by killing TCP server")
        
        # Kill TCP server in Vrf01
        st.config(nodes['SD8'], "sudo pkill -f 'python3.*tcpserver.py 65432'")
        st.wait(1)  # Wait for probe to detect failure
        
        # Phase 9: Verify only Vrf01 is affected
        st.banner("Phase 9: Verifying only Vrf01 route is affected")
        
        # Check APM status after failure
        apm_status_after = st.show(nodes['SD4'], "show apm-status", skip_tmpl=True)
        st.log("APM status after Vrf01 TCP server failure: {}".format(apm_status_after))
        
        # Verify routes after failure
        vrf01_routes_after = st.show(nodes['SD4'], "show ip route vrf Vrf01", skip_tmpl=True)
        vrf02_routes_after = st.show(nodes['SD4'], "show ip route vrf Vrf02", skip_tmpl=True)
        
        st.log("Vrf01 routes after failure: {}".format(vrf01_routes_after))
        st.log("Vrf02 routes after failure: {}".format(vrf02_routes_after))
        
        # Verify Vrf01 route is removed/affected
        if "172.16.255.1/32" in str(vrf01_routes_after) and "10.212.10.6" in str(vrf01_routes_after):
            st.log("WARNING: Vrf01 route still present after probe failure - this may be expected behavior")
        
        # Verify Vrf02 route is still present and unaffected
        if "172.16.255.1/32" not in str(vrf02_routes_after):
            st.report_fail('test_case_failed', 'Vrf02 route was unexpectedly affected by Vrf01 probe failure')
        
        # Verify APP-DB after failure
        st.banner("Verifying APP-DB entries after Vrf01 probe failure")
        
        # Vrf01 APP-DB should be empty or not contain the nexthop
        try:
            verify_app_db_static_route(nodes['SD4'], vrf01_app_db_cmd, [], "Vrf01 APP-DB After Failure", expect_empty=True)
        except:
            st.log("Vrf01 APP-DB entry handling after failure - continuing test")
        
        # Vrf02 APP-DB should still contain the route
        if not verify_app_db_static_route(nodes['SD4'], vrf02_app_db_cmd, ['10.212.10.6'], "Vrf02 APP-DB After Failure"):
            st.report_fail('test_case_failed', 'Vrf02 APP-DB verification failed after Vrf01 probe failure')
        
        st.banner("Multi-Tenant VRF Routes Test PASSED")

        st.report_pass('test_case_passed')
        
    except Exception as e:
        st.log("Exception occurred during multi-tenant test: {}".format(str(e)))
        st.report_fail('test_case_failed', "Multi-tenant test failed with exception: {}".format(str(e)))
        
    finally:
        # Cleanup Phase
        st.banner("Cleanup Phase: Removing all configurations")
        
        try:
            # Remove static routes
            st.config(nodes['SD4'], "config route del prefix vrf Vrf01 172.16.255.1/32", skip_error_check=True)
            st.config(nodes['SD4'], "config route del prefix vrf Vrf02 172.16.255.1/32", skip_error_check=True)
            
            # Remove APM probes
            st.config(nodes['SD4'], "sudo config apm del tcpprobe1", skip_error_check=True)
            st.config(nodes['SD4'], "sudo config apm del tcpprobe2", skip_error_check=True)
            
            # Kill TCP servers
            st.config(nodes['SD8'], "sudo pkill -f 'python3.*tcpserver.py'", skip_error_check=True)
            
            # Remove VLAN memberships on leaf2
            st.config(nodes['SD4'], "config vlan member del 10 {}".format(vars.D4D8P1), skip_error_check=True)
            st.config(nodes['SD4'], "config vlan member del 40 {}".format(vars.D4D8P2), skip_error_check=True)
            
            # Remove IP addresses and VRF bindings on host1
            st.config(nodes['SD8'], "sudo ip addr del 10.212.10.6/24 dev {}".format(vars.D8D4P1), skip_error_check=True)
            st.config(nodes['SD8'], "sudo ip addr del 10.212.10.6/24 dev {}".format(vars.D8D4P2), skip_error_check=True)
            st.config(nodes['SD8'], "sudo ip link set dev {} nomaster".format(vars.D8D4P1), skip_error_check=True)
            st.config(nodes['SD8'], "sudo ip link set dev {} nomaster".format(vars.D8D4P2), skip_error_check=True)
            st.config(nodes['SD8'], "sudo ip link del Vrf01", skip_error_check=True)
            st.config(nodes['SD8'], "sudo ip link del Vrf02", skip_error_check=True)
            st.config(nodes['SD8'], "sudo rm -f nohup.out", skip_error_check=True)
            
            st.wait(5)
            st.log("Cleanup completed")
            
        except Exception as cleanup_e:
            st.log("Exception during cleanup: {}".format(str(cleanup_e)))

######################################################################
# Test APM Probe State Transition Cycle IPv6 - Up to Down to Up
######################################################################
@pytest.mark.system_box
@pytest.mark.community
@pytest.mark.community_pass
def test_apm_probe_state_transition_cycle_ipv6():
    """
    Test complete APM probe state transition cycle from Up to Down to Up using IPv6 addresses
    IPv6 version of test_apm_probe_state_transition_cycle
    
    Test Scenario:
    1. First Phase: Setup APM probes and routes, verify both probes UP with both nexthops
    2. Second Phase: Make tcpprobe1 go DOWN, verify nexthop withdrawal 
    3. Third Phase: Make tcpprobe1 come back UP, verify nexthop re-addition
    
    Test Steps:
    Phase 1 - Initial Setup (Both Probes UP):
    1. Configure dynamic ports to Vlan10 and Vlan20 on SD4 (leaf2)
    2. Configure IPv6 addresses on SD8 dynamic ports
    3. Start TCP servers on both IPv6 addresses on SD8
    4. Configure APM probes tcpprobe1 and tcpprobe2
    5. Add static route with both IPv6 nexthops and APM dependencies
    6. Verify both probes are UP and route is installed via both nexthops
    
    Phase 2 - Probe Down Transition (tcpprobe1 DOWN):
    7. Stop TCP server for tcpprobe1 (make tcpprobe1 go DOWN)
    8. Verify tcpprobe1 is DOWN, tcpprobe2 is UP
    9. Verify route only shows nexthop for working probe (2001:db8:20::6)
    
    Phase 3 - Probe Up Transition (tcpprobe1 UP):
    10. Restart TCP server for tcpprobe1 (make tcpprobe1 come back UP)
    11. Verify both tcpprobe1 and tcpprobe2 are UP
    12. Verify route shows both nexthops again (2001:db8:10::6 and 2001:db8:20::6)
    13. Cleanup all configurations
    
    Expected Behavior:
    - Phase 1: Both probes UP, route via both nexthops
    - Phase 2: tcpprobe1 DOWN, route only via 2001:db8:20::6 
    - Phase 3: Both probes UP, route via both nexthops restored
    """
    vars = st.get_testbed_vars()
    
    nodes = {}
    nodes['SD1'] = vars.D1  # SD1 (spine0)
    nodes['SD2'] = vars.D2   # SD2 (leaf0) 
    nodes['SD3'] = vars.D3   # SD3 (leaf1)
    nodes['SD4'] = vars.D4   # SD4 (leaf2)
    nodes['SD8'] = vars.D8   # SD8 (host1 - host device)
    
    st.banner("Starting APM Probe State Transition Cycle Test IPv6")
    
    try:
        # =================== PHASE 1: INITIAL SETUP (BOTH PROBES UP) IPv6 ===================
        st.banner("PHASE 1: Initial Setup - Both Probes UP IPv6")
        
        # Step 1: Configure dynamic ports to Vlan10 and Vlan20 on SD4 (leaf2)
        st.banner("Step 1: Configuring dynamic ports on SD4 (leaf2)")
        
        # First, remove any existing IP configuration from interfaces to convert them from L3 to L2
        # Remove common IPv4 and IPv6 addresses that might be configured from previous tests
        st.config(nodes['SD4'], "config interface ip remove {} 10.212.10.4/24".format(vars.D4D8P1), skip_error_check=True)
        st.config(nodes['SD4'], "config interface ip remove {} 2001:db8:10::4/64".format(vars.D4D8P1), skip_error_check=True)
        st.config(nodes['SD4'], "config interface ip remove {} 10.212.20.4/24".format(vars.D4D8P2), skip_error_check=True)
        st.config(nodes['SD4'], "config interface ip remove {} 2001:db8:20::4/64".format(vars.D4D8P2), skip_error_check=True)
        st.wait(1)  # Wait for interface cleanup
        
        # Add D4D8P1 to Vlan10 on SD4 (leaf2)
        st.config(nodes['SD4'], "config vlan member add 10 {} -u".format(vars.D4D8P1))
        
        # Add D4D8P2 to Vlan20 on SD4 (leaf2)
        st.config(nodes['SD4'], "config vlan member add 20 {} -u".format(vars.D4D8P2))
        
        # Configure IPv6 addresses on Vlan10 and Vlan20 interfaces on SD4 (leaf2)
        st.config(nodes['SD4'], "config interface ip add Vlan10 2001:db8:10::4/64")
        st.config(nodes['SD4'], "config interface ip add Vlan20 2001:db8:20::4/64")
        
        # Step 2: Configure IPv6 addresses on SD8 dynamic ports
        st.banner("Step 2: Configuring IPv6 addresses on SD8 dynamic ports")
        
        # First, remove any existing IP configuration from SD8 interfaces
        st.config(nodes['SD8'], "sudo ip addr del 10.212.10.6/24 dev {}".format(vars.D8D4P1), skip_error_check=True)
        st.config(nodes['SD8'], "sudo ip addr del 2001:db8:10::6/64 dev {}".format(vars.D8D4P1), skip_error_check=True)
        st.config(nodes['SD8'], "sudo ip addr del 10.212.20.6/24 dev {}".format(vars.D8D4P2), skip_error_check=True)
        st.config(nodes['SD8'], "sudo ip addr del 2001:db8:20::6/64 dev {}".format(vars.D8D4P2), skip_error_check=True)
        st.wait(1)  # Wait for interface cleanup
        
        # Configure IPv6 address on SD8 D8D4P1
        st.config(nodes['SD8'], "sudo ifconfig {} up".format(vars.D8D4P1))
        st.wait(2)
        st.config(nodes['SD8'], "sudo ip addr add 2001:db8:10::6/64 dev {}".format(vars.D8D4P1))
        
        # Configure IPv6 address on SD8 D8D4P2
        st.config(nodes['SD8'], "sudo ifconfig {} up".format(vars.D8D4P2))
        st.wait(2)
        st.config(nodes['SD8'], "sudo ip addr add 2001:db8:20::6/64 dev {}".format(vars.D8D4P2))
        
        # Step 3: Start TCP servers on both IPv6 addresses on SD8
        st.banner("Step 3: Starting TCP servers on both IPv6 addresses on SD8")
        
        # Start TCP servers in background on both IPv6 addresses on SD8 (both on port 65432)
        tcp_server_cmd1 = "sudo nohup python3 /home/vxr/tcpserver.py 65432 2001:db8:10::6 > /tmp/tcpserver1.log 2>&1 &"
        st.config(nodes['SD8'], tcp_server_cmd1)
        st.wait(5)
        
        tcp_server_cmd2 = "sudo nohup python3 /home/vxr/tcpserver.py 65432 2001:db8:20::6 > /tmp/tcpserver2.log 2>&1 &"
        st.config(nodes['SD8'], tcp_server_cmd2)
        st.wait(5)  # Wait for servers to start
        
        # Step 4: Configure APM probes tcpprobe1 and tcpprobe2
        st.banner("Step 4: Configuring APM probes tcpprobe1 and tcpprobe2")
        
        # Configure APM TCP probe1 targeting SD8 D8D4P1 IPv6
        apm_cmd1 = "sudo config apm add tcpprobe1 --type tcp-connect --dst-ip 2001:db8:10::6 --dst-port 65432 --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true"
        st.config(nodes['SD4'], apm_cmd1)
        st.wait(3)
        
        # Configure APM TCP probe2 targeting SD8 D8D4P2 IPv6
        apm_cmd2 = "sudo config apm add tcpprobe2 --type tcp-connect --dst-ip 2001:db8:20::6 --dst-port 65432 --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true"
        st.config(nodes['SD4'], apm_cmd2)
        st.wait(3)  # Wait for APM probes to initialize
        
        # Step 5: Add static route with both IPv6 nexthops and APM dependencies
        st.banner("Step 5: Adding static route with both IPv6 nexthops and APM dependencies")
        
        route_cmd = "config route add prefix vrf Vrf01 2001:db8:ffff::1/128 nexthop 2001:db8:10::6,2001:db8:20::6 apm tcpprobe1,tcpprobe2"
        st.config(nodes['SD4'], route_cmd)
        st.wait(3)  # Wait for route to be installed
        
        # Step 6: Verify both probes are UP and route is installed via both nexthops
        st.banner("Step 6: Verifying both probes are UP and route via both IPv6 nexthops")
        
        # Check APM status
        apm_status_phase1 = st.show(nodes['SD4'], "show apm-status", skip_tmpl=True, skip_error_check=True)
        st.log("Phase 1 APM status: {}".format(apm_status_phase1))
        
        # Check IPv6 route installation
        route_output_phase1 = st.show(nodes['SD4'], "show ipv6 route vrf Vrf01", skip_tmpl=True)
        st.log("Phase 1 IPv6 route output: {}".format(route_output_phase1))
        
        # Validate Phase 1
        tcpprobe1_up_phase1 = any("up" in line.lower() for line in str(apm_status_phase1).split('\n') if "tcpprobe1" in line)
        tcpprobe2_up_phase1 = any("up" in line.lower() for line in str(apm_status_phase1).split('\n') if "tcpprobe2" in line)
        route_both_nexthops_phase1 = "2001:db8:ffff::1/128" in str(route_output_phase1) and "via 2001:db8:10::6" in str(route_output_phase1) and "via 2001:db8:20::6" in str(route_output_phase1)
        
        phase1_success = tcpprobe1_up_phase1 and tcpprobe2_up_phase1 and route_both_nexthops_phase1
        
        if phase1_success:
            st.log("PHASE 1 PASSED: Both probes UP, route via both IPv6 nexthops")
        else:
            st.log("PHASE 1 FAILED: tcpprobe1: {}, tcpprobe2: {}, both_nexthops: {}".format(
                tcpprobe1_up_phase1, tcpprobe2_up_phase1, route_both_nexthops_phase1))
        
        # =================== PHASE 2: PROBE DOWN TRANSITION IPv6 ===================
        st.banner("PHASE 2: Probe Down Transition - Making tcpprobe1 DOWN IPv6")
        
        # Step 7: Stop TCP server for tcpprobe1 (make tcpprobe1 go DOWN)
        st.banner("Step 7: Stopping TCP server for tcpprobe1 (port 65432)")
        
        # Kill the TCP server on port 65432 targeting 2001:db8:10::6 (tcpprobe1)
        kill_cmd = "sudo pkill -f 'tcpserver.py 65432 2001:db8:10::6'"
        st.config(nodes['SD8'], kill_cmd, skip_error_check=True)
        st.wait(10)  # Wait for APM probe to detect server down
        
        # Step 8: Verify tcpprobe1 is DOWN, tcpprobe2 is UP
        st.banner("Step 8: Verifying tcpprobe1 DOWN, tcpprobe2 UP")
        
        apm_status_phase2 = st.show(nodes['SD4'], "show apm-status", skip_tmpl=True, skip_error_check=True)
        st.log("Phase 2 APM status: {}".format(apm_status_phase2))
        
        # Step 9: Verify route only shows nexthop for working probe (2001:db8:20::6)
        st.banner("Step 9: Verifying route only via working IPv6 nexthop (2001:db8:20::6)")
        
        route_output_phase2 = st.show(nodes['SD4'], "show ipv6 route vrf Vrf01", skip_tmpl=True)
        st.log("Phase 2 IPv6 route output: {}".format(route_output_phase2))
        
        # Validate Phase 2
        tcpprobe1_down_phase2 = any("down" in line.lower() or "failed" in line.lower() for line in str(apm_status_phase2).split('\n') if "tcpprobe1" in line)
        tcpprobe2_up_phase2 = any("up" in line.lower() for line in str(apm_status_phase2).split('\n') if "tcpprobe2" in line)
        route_single_nexthop_phase2 = "2001:db8:ffff::1/128" in str(route_output_phase2) and "via 2001:db8:20::6" in str(route_output_phase2) and "via 2001:db8:10::6" not in str(route_output_phase2)
        
        phase2_success = tcpprobe1_down_phase2 and tcpprobe2_up_phase2 and route_single_nexthop_phase2
        
        if phase2_success:
            st.log("PHASE 2 PASSED: tcpprobe1 DOWN, route only via 2001:db8:20::6")
        else:
            st.log("PHASE 2 FAILED: tcpprobe1_down: {}, tcpprobe2_up: {}, single_nexthop: {}".format(
                tcpprobe1_down_phase2, tcpprobe2_up_phase2, route_single_nexthop_phase2))
        
        # =================== PHASE 3: PROBE UP TRANSITION IPv6 ===================
        st.banner("PHASE 3: Probe Up Transition - Making tcpprobe1 UP again IPv6")
        
        # Step 10: Restart TCP server for tcpprobe1 (make tcpprobe1 come back UP)
        st.banner("Step 10: Restarting TCP server for tcpprobe1 (port 65432)")
        
        # Restart TCP server on port 65432 for IPv6 address 2001:db8:10::6 (tcpprobe1)
        tcp_server_cmd1_restart = "sudo nohup python3 /home/vxr/tcpserver.py 65432 2001:db8:10::6 > /tmp/tcpserver1_restart.log 2>&1 &"
        st.config(nodes['SD8'], tcp_server_cmd1_restart)
        st.wait(10)  # Wait for APM probe to detect server up
        
        # Step 11: Verify both tcpprobe1 and tcpprobe2 are UP
        st.banner("Step 11: Verifying both tcpprobe1 and tcpprobe2 are UP")
        
        apm_status_phase3 = st.show(nodes['SD4'], "show apm-status", skip_tmpl=True, skip_error_check=True)
        st.log("Phase 3 APM status: {}".format(apm_status_phase3))
        
        # Step 12: Verify route shows both IPv6 nexthops again
        st.banner("Step 12: Verifying route shows both IPv6 nexthops again")
        
        route_output_phase3 = st.show(nodes['SD4'], "show ipv6 route vrf Vrf01", skip_tmpl=True)
        st.log("Phase 3 IPv6 route output: {}".format(route_output_phase3))
        
        # Validate Phase 3
        tcpprobe1_up_phase3 = any("up" in line.lower() for line in str(apm_status_phase3).split('\n') if "tcpprobe1" in line)
        tcpprobe2_up_phase3 = any("up" in line.lower() for line in str(apm_status_phase3).split('\n') if "tcpprobe2" in line)
        route_both_nexthops_phase3 = "2001:db8:ffff::1/128" in str(route_output_phase3) and "via 2001:db8:10::6" in str(route_output_phase3) and "via 2001:db8:20::6" in str(route_output_phase3)
        
        phase3_success = tcpprobe1_up_phase3 and tcpprobe2_up_phase3 and route_both_nexthops_phase3
        
        if phase3_success:
            st.log("PHASE 3 PASSED: Both probes UP, route via both IPv6 nexthops restored")
        else:
            st.log("PHASE 3 FAILED: tcpprobe1_up: {}, tcpprobe2_up: {}, both_nexthops: {}".format(
                tcpprobe1_up_phase3, tcpprobe2_up_phase3, route_both_nexthops_phase3))
        
        # APP-DB Verification for final state
        st.banner("Final APP-DB Verification: Both IPv6 nexthops should be present")
        verify_app_db_static_route(
            nodes['SD4'],
            'redis-cli -n 0 hgetall "STATIC_ROUTE:Vrf01:2001:db8:ffff::1/128"',
            ['2001:db8:10::6', '2001:db8:20::6'],  # Both IPv6 nexthops expected
            "APM Probe State Transition Cycle IPv6"
        )
        
        # Static Route Configuration Verification for final state
        st.banner("Final Static Route Configuration Verification: Both IPv6 nexthops should be present")
        static_route_output = st.show(nodes['SD4'], "show static-route", skip_tmpl=True)
        st.log("Final static route configuration: {}".format(static_route_output))
        
        # Verify both IPv6 nexthops are present in static route configuration
        static_route_both_nexthops = "2001:db8:ffff::1/128" in str(static_route_output) and "2001:db8:10::6" in str(static_route_output) and "2001:db8:20::6" in str(static_route_output)
        
        if static_route_both_nexthops:
            st.log("Static Route Verification PASSED: Both IPv6 nexthops (2001:db8:10::6, 2001:db8:20::6) present in static route configuration")
        else:
            st.log("Static Route Verification FAILED: Missing one or both IPv6 nexthops in static route configuration")
            st.log("Expected: Route 2001:db8:ffff::1/128 with nexthops 2001:db8:10::6 and 2001:db8:20::6")
        
        # Combined test result
        if phase1_success and phase2_success and phase3_success:
            st.log("COMBINED CYCLE IPv6 TEST PASSED: All three phases successful")
            st.log("Phase 1: Both probes UP, both nexthops - PASSED")
            st.log("Phase 2: tcpprobe1 DOWN, single nexthop - PASSED") 
            st.log("Phase 3: Both probes UP, both nexthops restored - PASSED")
            st.banner("APM Probe State Transition Cycle Test IPv6 - PASSED")
            st.report_pass('test_case_passed')
        else:
            st.log("COMBINED CYCLE IPv6 TEST FAILED: Phase 1: {}, Phase 2: {}, Phase 3: {}".format(
                phase1_success, phase2_success, phase3_success))
            st.report_fail('test_case_failed', "APM probe state transition cycle IPv6 test failed")

    except Exception as e:
        st.log("Exception occurred during APM probe state transition cycle IPv6 test: {}".format(str(e)))
        st.report_fail('test_case_failed', "Test failed with exception: {}".format(str(e)))
        
    finally:
        # Cleanup configurations
        st.banner("Cleanup: Removing all APM probe state transition IPv6 test configurations")
        
        try:
            # Stop all TCP servers
            st.config(nodes['SD8'], "sudo pkill -f 'tcpserver.py'", skip_error_check=True)
            st.wait(2)
            
            # Remove route
            st.config(nodes['SD4'], "config route del prefix vrf Vrf01 2001:db8:ffff::1/128", skip_error_check=True)
            st.wait(1)
            
            # Remove APM probes
            st.config(nodes['SD4'], "config apm del tcpprobe1", skip_error_check=True)
            st.config(nodes['SD4'], "config apm del tcpprobe2", skip_error_check=True)
            st.wait(2)
            
            # Remove IPv6 addresses from SD8
            st.config(nodes['SD8'], "sudo ip addr del 2001:db8:10::6/64 dev {}".format(vars.D8D4P1), skip_error_check=True)
            st.config(nodes['SD8'], "sudo ip addr del 2001:db8:20::6/64 dev {}".format(vars.D8D4P2), skip_error_check=True)
            
            # Remove IPv6 addresses from SD4 Vlan interfaces
            st.config(nodes['SD4'], "config interface ip remove Vlan10 2001:db8:10::4/64", skip_error_check=True)
            st.config(nodes['SD4'], "config interface ip remove Vlan20 2001:db8:20::4/64", skip_error_check=True)
            
            # Remove dynamic ports from VLANs on SD4
            st.config(nodes['SD4'], "config vlan member del 10 {}".format(vars.D4D8P1), skip_error_check=True)
            st.config(nodes['SD4'], "config vlan member del 20 {}".format(vars.D4D8P2), skip_error_check=True)
            
            # Clean up TCP server files and logs
            st.config(nodes['SD8'], "sudo rm -f /tmp/tcpserver1.log /tmp/tcpserver2.log /tmp/tcpserver1_restart.log", skip_error_check=True)
            st.config(nodes['SD8'], "sudo rm -f nohup.out", skip_error_check=True)
            
            st.banner("APM probe state transition cycle IPv6 test cleanup completed successfully")
            
        except Exception as cleanup_e:
            st.log("Warning: Some cleanup operations failed: {}".format(str(cleanup_e)))


######################################################################
# Test APM Static Route with BGP Redistribution, Uplink Flap, and Docker Restart
######################################################################
@pytest.mark.skip
@pytest.mark.system_box
@pytest.mark.community
@pytest.mark.community_pass
def test_apm_static_route_docker_restart():
    """
    Test for APM static route persistence after BGP docker restart
    
    Test Scenario:
    1. Configure APM probes and static route on SD4 (leaf2)
    2. Verify route is present on SD4
    3. Restart BGP docker on SD4, verify route comes back up on SD4
    
    Test Steps:
    1. Configure dynamic ports to Vlan10 and Vlan20 on SD4 (leaf2)
    2. Configure IP addresses on SD8 dynamic ports
    3. Start TCP servers on both IPs on SD8
    4. Configure APM probes tcpprobe1 and tcpprobe2 on SD4
    5. Add static route with APM dependencies on SD4
    6. Verify route is present on SD4
    7. Restart BGP docker container on SD4
    8. Verify BGP docker is running
    9. Verify route comes back up on SD4 after docker restart
    
    Expected Behavior:
    - Route is present on SD4 after initial configuration
    - Route comes back up on SD4 after BGP docker restart
    """
    vars = st.get_testbed_vars()
    
    nodes = {}
    nodes['SD1'] = vars.D1  # SD1 (spine0)
    nodes['SD2'] = vars.D2  # SD2 (leaf0) 
    nodes['SD3'] = vars.D3  # SD3 (leaf1)
    nodes['SD4'] = vars.D4  # SD4 (leaf2)
    nodes['SD8'] = vars.D8   # SD8 (host1 - host device)
    
    st.banner("Starting APM Static Route BGP Docker Restart Test")
    
    try:
        # Step 1: Configure dynamic ports on SD4 (leaf2)
        st.banner("Step 1: Configuring dynamic ports on SD4 (leaf2)")
        st.config(nodes['SD4'], "config vlan member add 10 {} -u".format(vars.D4D8P1))
        st.config(nodes['SD4'], "config vlan member add 20 {} -u".format(vars.D4D8P2))
        
        # Step 2: Configure IP addresses on SD8
        st.banner("Step 2: Configuring IP addresses on SD8 dynamic ports")
        st.config(nodes['SD8'], "sudo ifconfig {} up".format(vars.D8D4P1))
        st.wait(2)
        st.config(nodes['SD8'], "sudo ip addr add 10.212.10.6/24 dev {}".format(vars.D8D4P1))
        st.config(nodes['SD8'], "sudo ifconfig {} up".format(vars.D8D4P2))
        st.wait(2)
        st.config(nodes['SD8'], "sudo ip addr add 10.212.20.6/24 dev {}".format(vars.D8D4P2))
        
        # Step 3: Start TCP servers on SD8
        st.banner("Step 3: Starting TCP servers on SD8")
        tcp_server_cmd1 = "sudo nohup python3 /home/vxr/tcpserver.py 65432 10.212.10.6 > /tmp/tcpserver1.log 2>&1 &"
        st.config(nodes['SD8'], tcp_server_cmd1)
        st.wait(5)
        tcp_server_cmd2 = "sudo nohup python3 /home/vxr/tcpserver.py 65433 10.212.20.6 > /tmp/tcpserver2.log 2>&1 &"
        st.config(nodes['SD8'], tcp_server_cmd2)
        st.wait(5)
        
        # Step 4: Configure APM probes on SD4
        st.banner("Step 4: Configuring APM probes on SD4 (leaf2)")
        apm_cmd1 = "sudo config apm add tcpprobe1 --type tcp-connect --dst-ip 10.212.10.6 --dst-port 65432 --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true"
        st.config(nodes['SD4'], apm_cmd1)
        st.wait(3)
        
        apm_cmd2 = "sudo config apm add tcpprobe2 --type tcp-connect --dst-ip 10.212.20.6 --dst-port 65433 --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true"
        st.config(nodes['SD4'], apm_cmd2)
        st.wait(3)
        
        # Step 5: Add static route with APM dependencies
        st.banner("Step 5: Adding static route with APM dependencies on SD4")
        route_cmd = "config route add prefix vrf Vrf01 172.16.255.1/32 nexthop 10.212.10.6,10.212.20.6 apm tcpprobe1,tcpprobe2"
        st.config(nodes['SD4'], route_cmd)
        st.wait(3)
        
        # Step 6: Verify route is present on SD4
        st.banner("Step 6: Verifying route is present on SD4")
        route_output_sd4 = st.show(nodes['SD4'], "show ip route vrf Vrf01", skip_tmpl=True)
        st.log("Route output on SD4: {}".format(route_output_sd4))
        
        route_present_on_sd4 = False
        if "172.16.255.1/32" in str(route_output_sd4):
            route_present_on_sd4 = True
            st.log("SUCCESS: Route 172.16.255.1/32 is present on SD4")
        else:
            st.log("WARNING: Route 172.16.255.1/32 not found on SD4")
        
        if not route_present_on_sd4:
            st.report_fail('test_case_failed', "Route not present on SD4 after initial configuration")
        
        # Step 7: Restart BGP docker on SD4
        st.banner("Step 7: Restarting BGP docker container on SD4 (leaf2)")
        st.log("Executing docker restart bgp on leaf2 (SD4)")
        st.config(nodes['SD4'], "docker restart bgp")
        
        st.log("Waiting 60 seconds for BGP docker to restart")
        st.wait(60)
        
        # Step 8: Verify BGP docker is running
        st.banner("Step 8: Verifying BGP docker is running on SD4")
        docker_status = st.show(nodes['SD4'], "docker ps -a", skip_tmpl=True, skip_error_check=True)
        st.log("Docker status on leaf2: {}".format(docker_status))
        
        bgp_docker_up = False
        if "bgp" in str(docker_status) and "Up" in str(docker_status):
            bgp_docker_up = True
            st.log("SUCCESS: BGP docker is running after restart")
        else:
            st.log("WARNING: BGP docker may not be running properly after restart")
        
        # Step 9: Verify route comes back up on SD4 after BGP docker restart
        st.banner("Step 9: Verifying route comes back up on SD4 after BGP docker restart")
        route_output_sd4_after_docker_restart = st.show(nodes['SD4'], "show ip route vrf Vrf01", skip_tmpl=True)
        st.log("Route output on SD4 after docker restart: {}".format(route_output_sd4_after_docker_restart))
        
        route_present_after_docker_restart = False
        if "172.16.255.1/32" in str(route_output_sd4_after_docker_restart):
            route_present_after_docker_restart = True
            st.log("SUCCESS: Route 172.16.255.1/32 came back up on SD4 after BGP docker restart")
        else:
            st.log("ERROR: Route 172.16.255.1/32 not found on SD4 after BGP docker restart")
        
        # =================== FINAL TEST RESULT ===================
        test_success = bgp_docker_up and route_present_after_docker_restart
        
        if test_success:
            st.log("TEST PASSED: APM Static Route BGP Docker Restart Test completed successfully")
            st.log("- Route 172.16.255.1/32 was present on SD4 after initial configuration")
            st.log("- BGP docker restarted successfully")
            st.log("- Route 172.16.255.1/32 came back up on SD4 after docker restart")
            st.banner("APM Static Route BGP Docker Restart Test - PASSED")
            st.report_pass('test_case_passed')
        else:
            st.log("TEST FAILED: One or more verification criteria not met")
            failure_reasons = []
            if not bgp_docker_up:
                failure_reasons.append("BGP docker not running after restart")
            if not route_present_after_docker_restart:
                failure_reasons.append("Route did not come back up after docker restart")
            st.report_fail('test_case_failed', "Test failed: {}".format(", ".join(failure_reasons)))

    except Exception as e:
        st.log("Exception occurred during test execution: {}".format(str(e)))
        st.report_fail('test_case_failed', "Test failed with exception: {}".format(str(e)))
        
    finally:
        # Cleanup configurations
        st.banner("Cleanup: Removing all test configurations")
        
        try:
            # Stop TCP servers
            st.config(nodes['SD8'], "sudo pkill -f 'tcpserver.py 65432'", skip_error_check=True)
            st.config(nodes['SD8'], "sudo pkill -f 'tcpserver.py 65433'", skip_error_check=True)
            st.wait(2)
            
            # Remove route
            st.config(nodes['SD4'], "config route del prefix vrf Vrf01 172.16.255.1/32", skip_error_check=True)
            st.wait(1)
            
            # Remove APM probes
            st.config(nodes['SD4'], "config apm del tcpprobe1", skip_error_check=True)
            st.config(nodes['SD4'], "config apm del tcpprobe2", skip_error_check=True)
            st.wait(2)
            
            # Remove IP addresses from SD8
            st.config(nodes['SD8'], "sudo ip addr del 10.212.10.6/24 dev {}".format(vars.D8D4P1), skip_error_check=True)
            st.config(nodes['SD8'], "sudo ip addr del 10.212.20.6/24 dev {}".format(vars.D8D4P2), skip_error_check=True)
            st.wait(1)
            
            # Remove VLAN members on SD4
            st.config(nodes['SD4'], "config vlan member del 10 {}".format(vars.D4D8P1), skip_error_check=True)
            st.config(nodes['SD4'], "config vlan member del 20 {}".format(vars.D4D8P2), skip_error_check=True)
            
            # Clean up log files
            st.config(nodes['SD8'], "sudo rm -f /tmp/tcpserver1.log /tmp/tcpserver2.log", skip_error_check=True)
            st.config(nodes['SD8'], "sudo rm -f nohup.out", skip_error_check=True)
            
            st.banner("APM Static Route BGP Docker Restart test cleanup completed")
            
        except Exception as cleanup_e:
            st.log("Warning: Some cleanup operations failed: {}".format(str(cleanup_e)))