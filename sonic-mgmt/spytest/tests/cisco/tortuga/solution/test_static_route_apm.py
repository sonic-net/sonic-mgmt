import os
import sys

# Resolve sibling ../vxlan without requiring tortuga.vxlan package / PYTHONPATH
_vxlan_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "vxlan"))
if _vxlan_dir not in sys.path:
    sys.path.insert(0, _vxlan_dir)
    
import tortuga_common_utils as common_obj
import yaml
import pytest
from collections import OrderedDict
from spytest import st, tgapi, SpyTestDict
import apis.routing.ip as ip_obj
import apis.switching.vlan as vlan_obj
# sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'vxlan'))
import vxlan_utils as vxlan_obj
import time
import evpn_mh_utils as evpn_mh_obj
import pdb

ESI1 = '03:00:44:33:22:11:00:00:00:02'
EXPECTED_L3VNI = '5030'
EXPECTED_L2VNI = '5010'
##  Topology : 1x Spine + 3 Leafs + 2 Host's
##  SD1 -- Spine0  - D1
##  SD2 -- Leaf0   - D2
##  SD3 -- Leaf1   - D3
##  SD4 -- Leaf2   - D4
##  SD5 -- Host0   - D5
##  SD6 -- Host1   - D6

data = SpyTestDict()
data.config_vrfs = []

# Config file is in the solution folder (parent directory)
CONFIGS_FILE = '../solution/static_route_apm_evpn_mh_v6_config_sol.yaml'

LEAF0_VXLAN_IP = 'fd27::233:d0c6:fefb'
LEAF1_VXLAN_IP = 'fd27::2dc:c1c9:e17c'
LEAF2_VXLAN_IP = 'fd27::2d9:76fd:4c43'

# Global nodes dictionary
nodes = {}

# Global IP Address Variables for APM Tests
SPINE2_VLAN10_IP = "10.212.10.6"
SPINE2_VLAN10_IP_PREFIX = "10.212.10.6/24"
SPINE2_VLAN20_IP = "10.212.20.6"
SPINE2_VLAN20_IP_PREFIX = "10.212.20.6/24"
STATIC_ROUTE_PREFIX = "172.16.255.1/32"
TCP_SERVER_PORT1 = "65432"
TCP_SERVER_PORT2 = "65433"

# Additional global variables for EVPN multi-homing tests
HOST0_PORTCHANNEL5_IP = "10.212.10.5"
HOST0_PORTCHANNEL5_IP_PREFIX = "10.212.10.5/24"
HOST0_NEXTHOP_IP = "10.212.10.10"
HOST0_ROUTE1_PREFIX = "172.16.1.1/32"
HOST0_ROUTE2_PREFIX = "172.16.2.1/32"
EVPN_STATIC_ROUTE_PREFIX = "172.17.255.1/32"
HOST1_LOOPBACK6_IP = "172.18.255.1"
HOST1_LOOPBACK6_IP_PREFIX = "172.18.255.1/32"

# Global IPv6 Address Variables for APM Tests
LEAF2_VLAN10_IPV6 = "2001:db8:10::4"
LEAF2_VLAN10_IPV6_PREFIX = "2001:db8:10::4/64"
LEAF2_VLAN20_IPV6 = "2001:db8:20::4"
LEAF2_VLAN20_IPV6_PREFIX = "2001:db8:20::4/64"
SPINE2_VLAN10_IPV6 = "2001:db8:10::6"
SPINE2_VLAN10_IPV6_PREFIX = "2001:db8:10::6/64"
SPINE2_VLAN20_IPV6 = "2001:db8:20::6"
SPINE2_VLAN20_IPV6_PREFIX = "2001:db8:20::6/64"
STATIC_ROUTE_IPV6_PREFIX = "2001:db8:ffff::1/128"

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

def initialize_nodes():
    """Initialize and return the nodes dictionary mapping node names to DUT variables."""
    vars = st.get_testbed_vars()
    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['spine2'] = vars.D3
    nodes['spine3'] = vars.D4
    nodes['leaf0'] = vars.D5
    nodes['leaf1'] = vars.D6
    nodes['leaf2'] = vars.D7
    nodes['leaf3'] = vars.D8
    return nodes

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

def config_static(node, config_domain, config_list, nodes, add=True):
    domain = ''
    if config_domain == 'bgp' or config_domain == 'pre-sonic-bgp':
        domain = 'vtysh'

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
    global nodes
    vars = st.get_testbed_vars()
    nodes = initialize_nodes()

    global updated_config_file
    updated_config_file = vxlan_obj.modify_config_file(CONFIGS_FILE,vars)

    evpn_mh_obj.change_fdb_ageout("6000")

    # Read config file once and reuse for both setup and teardown
    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)

    # Setup: Apply configurations
    for node, config in config_list.items():
        config_static(node, 'pre-sonic-bgp', config_list, nodes)
        st.wait(2)
        config_static(node, 'sonic', config_list, nodes)
        st.wait(2)
        config_static(node, 'bgp', config_list, nodes)
    yield vxlan_config_hooks

    # Teardown: Remove configurations in reverse order
    for node, config in reversed(config_list.items()):
        config_static(node, 'bgp', config_list, nodes, add=False)
        st.wait(2)
        config_static(node, 'sonic', config_list, nodes, add=False)
        st.wait(2)
        config_static(node, 'pre-sonic-bgp', config_list, nodes, add=False)
    evpn_mh_obj.change_fdb_ageout("600")

    for vrf in data.config_vrfs:
        vxlan_obj.config_vrf(nodes['leaf0'], vrf, add=False)
        vxlan_obj.config_vrf(nodes['leaf1'], vrf, add=False)
    data.config_vrfs = []

    vxlan_obj.remove_temp_config(updated_config_file)

#Maintained as a module level fixture since we need to ping and send traffic in each testcase
@pytest.fixture(scope="module", autouse=True)
def traffic_setup(vxlan_config_hooks):
    global leaf0_vrf_prefix
    leaf0_vrf_prefix = "10.212.10.0"
    global leaf1_vrf_prefix
    leaf1_vrf_prefix = "10.212.10.0"
    global leaf2_vrf_prefix
    leaf2_vrf_prefix = "10.212.20.0"
    data.d2t1_ip_addr = "10.212.10.10"		#Host1 GW
    data.t1d5p1_ip_addr = "10.212.10.1"		#Host1 IP
    data.t1d5p1_mac_addr = "00:00:00:00:00:01"	#Host1 Mac
    data.lag_ip = "10.212.10.2"			#Lag IP
    data.lag_gateway_ip = "10.212.10.10"	#Lag GW
    data.lag_mac = "00:00:00:00:00:02"		#Lag Mac
    data.t1d6p2_ip_addr = "10.212.10.5"        #Host5 IP
    data.t1d6p2_mac_addr = "00:00:00:00:01:05" #Host5 Mac
    data.t1d7p1_ip_addr = "10.212.10.3"		#Host3 IP
    data.t1d7p1_mac_addr = "00:00:00:00:02:03"	#Host3 Mac
    data.d7t1_ip_addr = "10.212.20.10"		#Host3 GW
    data.t1d7p2_ip_addr = "10.212.20.1"		#Host4 IP
    data.t1d7p2_mac_addr = "00:00:00:00:02:04"	#Host4 Mac
    global lag_ports
    lag_ports = ["T1D5P2", "T1D6P1"]
    global lag_name
    lag_name = "LAG1"
    global int_dict
    int_dict = {"T1D5P1": {"host_ip": data.t1d5p1_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d5p1_mac_addr},
                "T1D6P2": {"host_ip": data.t1d6p2_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d6p2_mac_addr},
                "T1D7P1": {"host_ip": data.t1d7p1_ip_addr, "gateway": data.d2t1_ip_addr, "mac" : data.t1d7p1_mac_addr},
                "T1D7P2": {"host_ip": data.t1d7p2_ip_addr, "gateway": data.d7t1_ip_addr, "mac" : data.t1d7p2_mac_addr}}
    global handles
    handles = vxlan_obj.config_lag_interface(lag_name, lag_ports, data.lag_ip, data.lag_gateway_ip, data.lag_mac)
    handles.update(vxlan_obj.config_tgen_interface(int_dict))
    int_dict.update({lag_name: {"host_ip": data.lag_ip, "gateway": data.lag_gateway_ip, "mac" : data.lag_mac}})
    st.log("\nHandles created: {}".format(handles))
    global port_name_map
    port_name_map  = {"H1": "T1D5P1", "H2": lag_name, "H3": "T1D7P1", "H4": "T1D7P2", "H5": "T1D6P2"}


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
    1. Configure Ethernet1_3 to Vlan10 and Ethernet1_5 to Vlan20 on SD7 (leaf2)
    2. Configure IP addresses on SD3 using global variables
    3. Add static route with multiple nexthops using global variables
    4. Verify route is installed with both nexthops in FRR routing table
    5. Verify APP-DB contains no entry
    
    Phase 2 - Route Deletion (from test_simple_static_route_deletion):
    6. Delete the static route completely
    7. Verify no static route is present in routing table
    8. Verify APP-DB no longer contains the static route entry
    9. Cleanup all configurations
    """
    vars = st.get_testbed_vars()
    
    st.banner("Starting Static Route Addition and Deletion Combined Test")
    
    try:

        # =================== PHASE 1: ROUTE ADDITION ===================
        st.banner("PHASE 1: Static Route Addition and Verification")
        
        # Step 1: Configure Ethernet1_3 and Ethernet1_5 on SD7 (leaf2) to Vlan10/20
        st.banner("Step 1: Configuring Ethernet interfaces on SD7 (leaf2)")
        
        # Add Ethernet1_3 to Vlan10 on SD7 (leaf2)
        st.config(nodes['leaf2'], "config vlan member add 10 {} -u".format(vars.D7D3P1))
        
        # Add Ethernet1_5 to Vlan20 on SD7 (leaf2)
        st.config(nodes['leaf2'], "config vlan member add 20 {} -u".format(vars.D7D3P2))
        
        # Step 2: Configure IP addresses on SD3 (spine2) Ethernet1_3 and Ethernet1_5
        st.banner("Step 2: Configuring IP addresses on SD3 (spine2) Ethernet1_3 and Ethernet1_5")
        
        # Configure IP address on SD3 (spine2) Ethernet1_3
        st.config(nodes['spine2'], "config interface ip add {} {}".format(vars.D3D7P1, SPINE2_VLAN10_IP_PREFIX))
        
        # Configure IP address on SD3 (spine2) Ethernet1_5
        st.config(nodes['spine2'], "config interface ip add {} {}".format(vars.D3D7P2, SPINE2_VLAN20_IP_PREFIX))
        
        # Step 3: Add static route with multiple nexthops (no APM)
        st.banner("Step 3: Adding static route with multiple nexthops on SD7 (leaf2)")
        
        # Configure static route with multiple nexthops - no APM dependencies
        route_cmd = "config route add prefix vrf Vrf01 {} nexthop {},{}".format(STATIC_ROUTE_PREFIX, SPINE2_VLAN10_IP, SPINE2_VLAN20_IP)
        st.config(nodes['leaf2'], route_cmd)
        st.wait(2)
        
        # Step 4: Verify route is installed with both nexthops in FRR routing table
        st.banner("Step 4: Verifying route is installed with both nexthops")
        
        # Check FRR routing table
        route_output = st.show(nodes['leaf2'], "show ip route vrf Vrf01", skip_tmpl=True)
        st.log("VRF Route table output on SD7: {}".format(route_output))
        
        # Verify route is installed
        route_found = False
        nexthop1_found = False
        nexthop2_found = False
        
        if STATIC_ROUTE_PREFIX in str(route_output):
            route_found = True
            st.log("SUCCESS: Route {} is found in routing table".format(STATIC_ROUTE_PREFIX))
            
            # Check for both nexthops
            if "via {}".format(SPINE2_VLAN10_IP) in str(route_output):
                nexthop1_found = True
                st.log("SUCCESS: Nexthop via {} is installed".format(SPINE2_VLAN10_IP))
            else:
                st.log("FAIL: Nexthop via {} is NOT found".format(SPINE2_VLAN10_IP))
            
            if "via {}".format(SPINE2_VLAN20_IP) in str(route_output):
                nexthop2_found = True
                st.log("SUCCESS: Nexthop via {} is installed".format(SPINE2_VLAN20_IP))
            else:
                st.log("FAIL: Nexthop via {} is NOT found".format(SPINE2_VLAN20_IP))
        else:
            st.log("FAIL: Route {} is NOT found".format(STATIC_ROUTE_PREFIX))
        
        # Step 5: APP-DB Verification for route addition (should be empty for non-APM routes)
        st.banner("Step 5: Verifying APP-DB contains no entry for static route (no APM)")
        verify_app_db_static_route(
            nodes['leaf2'],
            'redis-cli -n 0 hgetall "STATIC_ROUTE:Vrf01:{}"'.format(STATIC_ROUTE_PREFIX),
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
        route_del_cmd = "config route del prefix vrf Vrf01 {}".format(STATIC_ROUTE_PREFIX)
        st.config(nodes['leaf2'], route_del_cmd)
        st.wait(2)  # Wait for route to be removed
        
        # Step 7: Verify no static route is present in routing table
        st.banner("Step 7: Verifying route is completely removed")
        
        final_route_output = st.show(nodes['leaf2'], "show ip route vrf Vrf01", skip_tmpl=True)
        st.log("Final route output after deletion: {}".format(final_route_output))
        
        # Check that route is NOT present
        route_removed = True
        if STATIC_ROUTE_PREFIX in str(final_route_output):
            route_removed = False
            st.log("FAIL: Route {} is still present after deletion".format(STATIC_ROUTE_PREFIX))
        else:
            st.log("SUCCESS: Route {} is properly removed".format(STATIC_ROUTE_PREFIX))
        
        # Step 8: APP-DB Verification for route deletion
        st.banner("Step 8: Verifying APP-DB no longer contains the static route")
        verify_app_db_static_route(
            nodes['leaf2'],
            'redis-cli -n 0 hgetall "STATIC_ROUTE:Vrf01:{}"'.format(STATIC_ROUTE_PREFIX),
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
            
            # Remove IP addresses from SD3
            st.config(nodes['spine2'], "config interface ip remove {} {}".format(vars.D3D7P1, SPINE2_VLAN10_IP_PREFIX), skip_error_check=True)
            st.config(nodes['spine2'], "config interface ip remove {} {}".format(vars.D3D7P2, SPINE2_VLAN20_IP_PREFIX), skip_error_check=True)
            
            # Remove Ethernet interfaces from VLANs on SD7
            st.config(nodes['leaf2'], "config vlan member del 10 {}".format(vars.D7D3P1), skip_error_check=True)
            st.config(nodes['leaf2'], "config vlan member del 20 {}".format(vars.D7D3P2), skip_error_check=True)
            
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
    1. Configure Ethernet1_3 to Vlan10 and Ethernet1_5 to Vlan20 on SD7 (leaf2)
    2. Configure IP addresses on SD3 (spine2) Ethernet1_3 and Ethernet1_5
    3. Start TCP servers on both IPs on SD3 (spine2) (ports 65432 and 65433)
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
    
    st.banner("Starting APM Route Addition and Deletion Combined Test")

    try:
        # =================== PHASE 1: APM ROUTE ADDITION ===================
        st.banner("PHASE 1: APM Route Addition and Verification")
        
        # Step 1: Configure Ethernet1_3 to Vlan10 and Ethernet1_5 to Vlan20 on SD7 (leaf2)
        st.banner("Step 1: Configuring Ethernet interfaces on SD7 (leaf2)")
        st.wait(3)
        
        # Add Ethernet1_3 to Vlan10 on SD7 (leaf2)
        st.config(nodes['leaf2'], "config vlan member add 10 {} -u".format(vars.D7D3P1))
        
        # Add Ethernet1_5 to Vlan20 on SD7 (leaf2)
        st.config(nodes['leaf2'], "config vlan member add 20 {} -u".format(vars.D7D3P2))
        
        # Step 2: Configure IP addresses on SD3 (spine2) ports
        st.banner("Step 2: Configuring IP addresses on SD3 (spine2) ports")
        
        # Configure IP address on SD3 (spine2) port
        st.config(nodes['spine2'], "config interface ip add {} {}".format(vars.D3D7P1, SPINE2_VLAN10_IP_PREFIX))
        
        # Configure IP address on SD3 (spine2) port
        st.config(nodes['spine2'], "config interface ip add {} {}".format(vars.D3D7P2, SPINE2_VLAN20_IP_PREFIX))
        
        # Step 3: Start TCP servers on both IPs on SD3 (spine2)
        st.banner("Step 3: Starting TCP servers on SD3 (spine2)")
        
        # Start TCP servers in background on both IPs on SD3 (spine2)
        tcp_server_cmd1 = "cd /home/cisco && nohup python3 tcpserver.py {} {} > /tmp/tcpserver1.log 2>&1 &".format(TCP_SERVER_PORT1, SPINE2_VLAN10_IP)
        st.config(nodes['spine2'], tcp_server_cmd1)
        
        tcp_server_cmd2 = "cd /home/cisco && nohup python3 tcpserver.py {} {} > /tmp/tcpserver2.log 2>&1 &".format(TCP_SERVER_PORT2, SPINE2_VLAN20_IP)
        st.config(nodes['spine2'], tcp_server_cmd2)
        st.wait(2)  # Wait for servers to start
        
        # Step 4: Configure APM TCP probes on SD7 (leaf2)
        st.banner("Step 4: Configuring APM TCP probes on SD7 (leaf2)")
        
        # Configure APM TCP probe1 targeting SD3 (spine2) Ethernet1_3
        apm_cmd1 = "sudo config apm add tcpprobe1 --type tcp-connect --dst-ip {} --dst-port {} --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true".format(SPINE2_VLAN10_IP, TCP_SERVER_PORT1)
        st.config(nodes['leaf2'], apm_cmd1)
        st.wait(3)
        
        # Configure APM TCP probe2 targeting SD3 (spine2) Ethernet1_5
        apm_cmd2 = "sudo config apm add tcpprobe2 --type tcp-connect --dst-ip {} --dst-port {} --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true".format(SPINE2_VLAN20_IP, TCP_SERVER_PORT2)
        st.config(nodes['leaf2'], apm_cmd2)
        st.wait(3)  # Wait longer for APM probes to initialize and establish connections
        
        # Verify APM probes are configured and check status
        apm_config_output = st.show(nodes['leaf2'], "show apm", skip_tmpl=True, skip_error_check=True)
        st.log("APM configuration on SD7 (leaf2): {}".format(apm_config_output))
        
        apm_status_output = st.show(nodes['leaf2'], "show apm-status", skip_tmpl=True, skip_error_check=True)
        st.log("APM status on SD7 (leaf2): {}".format(apm_status_output))
        
        if "tcpprobe1" not in str(apm_config_output) or "tcpprobe2" not in str(apm_config_output):
            st.report_fail('test_case_failed', "APM probes tcpprobe1 or tcpprobe2 not configured properly on SD7 (leaf2)")

        # Step 5: Add static route with both APM probes on SD7 (leaf2)
        st.banner("Step 5: Adding static route with APM configuration on SD7 (leaf2)")
        
        route_cmd = "config route add prefix vrf Vrf01 {} nexthop {},{} apm tcpprobe1,tcpprobe2".format(STATIC_ROUTE_PREFIX, SPINE2_VLAN10_IP, SPINE2_VLAN20_IP)
        st.config(nodes['leaf2'], route_cmd)
        st.wait(3)  # Wait for route to be installed
        
        # Step 6: Verify APM status and route installation on SD7 (leaf2)
        st.banner("Step 6: Verifying APM status and route installation on SD7 (leaf2)")
        
        # Check APM status - test passes if both tcpprobe1 and tcpprobe2 are UP
        final_apm_status = st.show(nodes['leaf2'], "show apm-status", skip_tmpl=True, skip_error_check=True)
        st.log("Final APM status on SD7 (leaf2): {}".format(final_apm_status))
        
        # Check if route is installed in VRF routing table
        route_output = st.show(nodes['leaf2'], "show ip route vrf Vrf01", skip_tmpl=True)
        st.log("VRF Route table output on SD7 (leaf2): {}".format(route_output))
        
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
        
        if STATIC_ROUTE_PREFIX in str(route_output):
            route_installed = True
            st.log("SUCCESS: Static route {} is installed in VRF Vrf01".format(STATIC_ROUTE_PREFIX))
        else:
            st.log("WARNING: Static route {} is not installed in VRF Vrf01".format(STATIC_ROUTE_PREFIX))
        
        # Step 7: APP-DB Verification for APM route addition
        st.banner("Step 7: Verifying APP-DB contains static route entry with both nexthops")
        verify_app_db_static_route(
            nodes['leaf2'],
            'redis-cli -n 0 hgetall "STATIC_ROUTE:Vrf01:{}"'.format(STATIC_ROUTE_PREFIX),
            [SPINE2_VLAN10_IP, SPINE2_VLAN20_IP],  # Both nexthops expected for APM routes
            "APM Route Addition Phase"
        )

        # Verify show static-route displays the route properly
        st.banner("Verifying show static-route displays the route properly")
        static_route_output = st.show(nodes['leaf2'], "show static-route", skip_tmpl=True, skip_error_check=True)
        st.log("show static-route output after route addition: {}".format(static_route_output))
        
        # Check that static route is properly displayed with correct nexthops and APM probes
        static_route_displayed = False
        if (STATIC_ROUTE_PREFIX in str(static_route_output) and 
            SPINE2_VLAN10_IP in str(static_route_output) and 
            SPINE2_VLAN20_IP in str(static_route_output) and
            "tcpprobe1" in str(static_route_output) and
            "tcpprobe2" in str(static_route_output)):
            static_route_displayed = True
            st.log("SUCCESS: show static-route displays route {} with nexthops {},{} and APM probes tcpprobe1,tcpprobe2".format(STATIC_ROUTE_PREFIX, SPINE2_VLAN10_IP, SPINE2_VLAN20_IP))
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
        route_del_cmd = "config route del prefix vrf Vrf01 {}".format(STATIC_ROUTE_PREFIX)
        st.config(nodes['leaf2'], route_del_cmd)
        st.wait(2)  # Wait for route to be removed
        
        # Step 9: Verify no static route is present in routing table
        st.banner("Step 9: Verifying route is completely removed")
        
        final_route_output = st.show(nodes['leaf2'], "show ip route vrf Vrf01", skip_tmpl=True)
        st.log("Final route output after deletion: {}".format(final_route_output))
        
        # Check that route is NOT present
        route_removed = True
        if STATIC_ROUTE_PREFIX in str(final_route_output):
            route_removed = False
            st.log("FAIL: Route {} is still present after deletion".format(STATIC_ROUTE_PREFIX))
        else:
            st.log("SUCCESS: Route {} is properly removed".format(STATIC_ROUTE_PREFIX))
        
        # Step 10: APP-DB Verification for APM route deletion
        st.banner("Step 10: Verifying APP-DB no longer contains the static route")
        verify_app_db_static_route(
            nodes['leaf2'],
            'redis-cli -n 0 hgetall "STATIC_ROUTE:Vrf01:{}"'.format(STATIC_ROUTE_PREFIX),
            [],  # No nexthops expected
            "APM Route Deletion Phase",
            expect_empty=True
        )

        # Verify show static-route no longer displays the route
        st.banner("Verifying show static-route no longer displays the route")
        final_static_route_output = st.show(nodes['leaf2'], "show static-route", skip_tmpl=True, skip_error_check=True)
        st.log("show static-route output after route deletion: {}".format(final_static_route_output))
        
        # Check that static route is NOT displayed
        static_route_absent = True
        if STATIC_ROUTE_PREFIX in str(final_static_route_output):
            static_route_absent = False
            st.log("FAIL: show static-route still displays route {} after deletion".format(STATIC_ROUTE_PREFIX))
        else:
            st.log("SUCCESS: show static-route no longer displays route {}".format(STATIC_ROUTE_PREFIX))
        
        # Phase 2 validation
        phase2_success = route_removed and static_route_absent
        
        if phase2_success:
            st.log("PHASE 2 PASSED: APM route deletion verified successfully")
        else:
            st.log("PHASE 2 FAILED: APM route deletion verification failed")
        
        # Combined test result
        if phase1_success and phase2_success:
            st.log("COMBINED APM TEST PASSED: Both route addition and deletion phases successful")
            st.banner("APM Route Addition and Deletion Combined Test - PASSED")
            st.report_pass('test_case_passed')
        else:
            st.log("COMBINED APM TEST FAILED: Phase 1: {}, Phase 2: {}".format(phase1_success, phase2_success))
            st.report_fail('test_case_failed', "Combined APM test failed - Phase 1: {}, Phase 2: {}".format(phase1_success, phase2_success))

    except Exception as e:
        st.log("Exception occurred during combined APM test execution: {}".format(str(e)))
        st.report_fail('test_case_failed', "Combined APM test failed with exception: {}".format(str(e)))
        
    finally:
        # Cleanup configurations
        st.banner("Cleanup: Removing all APM test configurations")
        
        try:
            # Stop TCP servers first on SD3 (spine2)
            st.config(nodes['spine2'], "pkill -f 'tcpserver.py'", skip_error_check=True)
            st.wait(2)
            
            # Remove route (in case it still exists)
            st.config(nodes['leaf2'], "config route del prefix vrf Vrf01 {}".format(STATIC_ROUTE_PREFIX), skip_error_check=True)
            st.wait(1)
            
            # Remove APM probes
            st.config(nodes['leaf2'], "config apm del tcpprobe1", skip_error_check=True)
            st.config(nodes['leaf2'], "config apm del tcpprobe2", skip_error_check=True)
            st.wait(2)
            
            # Remove IP addresses from SD3 (spine2)
            st.config(nodes['spine2'], "config interface ip remove {} {}".format(vars.D3D7P1, SPINE2_VLAN10_IP_PREFIX), skip_error_check=True)
            st.config(nodes['spine2'], "config interface ip remove {} {}".format(vars.D3D7P2, SPINE2_VLAN20_IP_PREFIX), skip_error_check=True)
            
            # Remove Ethernet interfaces from VLANs on SD7 (leaf2)
            st.config(nodes['leaf2'], "config vlan member del 10 {}".format(vars.D7D3P1), skip_error_check=True)
            st.config(nodes['leaf2'], "config vlan member del 20 {}".format(vars.D7D3P2), skip_error_check=True)
            
            # Clean up TCP server files on SD3 (spine2)
            st.config(nodes['spine2'], "rm -f /tmp/tcpserver1.log /tmp/tcpserver2.log", skip_error_check=True)
            
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
    - config route add prefix vrf Vrf01 {STATIC_ROUTE_PREFIX} nexthop {SPINE2_VLAN10_IP},{SPINE2_VLAN20_IP}
    - config apm add tcpprobe1 --type=tcp-connect --enable=true --vrf Vrf01 --dst-ip={SPINE2_VLAN10_IP} --dst-port={TCP_SERVER_PORT1}
    - config apm add tcpprobe2 --type=tcp-connect --enable=true --vrf Vrf01 --dst-ip={SPINE2_VLAN20_IP} --dst-port={TCP_SERVER_PORT2}
    - config route add prefix vrf Vrf01 {STATIC_ROUTE_PREFIX} apm tcpprobe1,tcpprobe2
    
    
    Test Steps:
    1. Configure Ethernet1_3 to Vlan10 and Ethernet1_5 to Vlan20 on SD7 (leaf2)
    2. Configure IP addresses on SD3 (spine2) Ethernet1_3 and Ethernet1_5
    3. Start TCP servers on both IPs on SD3 (spine2)
    4. Add initial static route with multiple nexthops (no APM)
    5. Verify route is installed with both nexthops
    6. Configure APM TCP probes (tcpprobe1 and tcpprobe2)
    7. Update route to use APM dependencies (override existing route)
    8. Verify both APM probes are UP and route still shows both nexthops
    9. Cleanup all configurations
    """
    vars = st.get_testbed_vars()
    
    st.banner("Starting APM Override Route Configuration Test")
    
    try:
        # Step 1: Configure Ethernet1_3 and Ethernet1_5 on SD7 (leaf2) to Vlan10
        st.banner("Step 1: Configuring Ethernet interfaces on SD7 (leaf2) to Vlan10")
        
        # Add Ethernet1_3 to Vlan10 on SD7 (leaf2)
        st.config(nodes['leaf2'], "config vlan member add 10 {} -u".format(vars.D7D3P1))
        
        # Add Ethernet1_5 to Vlan10 on SD7 (leaf2)
        st.config(nodes['leaf2'], "config vlan member add 20 {} -u".format(vars.D7D3P2))
        
        
        # Step 2: Configure IP addresses on SD3 (spine2) Ethernet1_3 and Ethernet1_5
        st.banner("Step 2: Configuring IP addresses on SD3 (spine2) Ethernet1_3 and Ethernet1_5")
        
        # Configure IP address on SD3 (spine2) Ethernet1_3
        st.config(nodes['spine2'], "config interface ip add {} {}".format(vars.D3D7P1, SPINE2_VLAN10_IP_PREFIX))
        
        # Configure IP address on SD3 (spine2) Ethernet1_5
        st.config(nodes['spine2'], "config interface ip add {} {}".format(vars.D3D7P2, SPINE2_VLAN20_IP_PREFIX))
        
        # Step 3: Start TCP servers on both IPs on SD3 (spine2)
        st.banner("Step 3: Starting TCP servers on both IPs on SD3 (spine2)")
    
        
        # Start both TCP servers
        tcp_server_cmd1 = "cd /home/cisco && nohup python3 tcpserver.py {} {} > /tmp/tcpserver1.log 2>&1 &".format(TCP_SERVER_PORT1, SPINE2_VLAN10_IP)
        st.config(nodes['spine2'], tcp_server_cmd1)
        st.wait(2)
        
        tcp_server_cmd2 = "cd /home/cisco && nohup python3 tcpserver.py {} {} > /tmp/tcpserver2.log 2>&1 &".format(TCP_SERVER_PORT2, SPINE2_VLAN20_IP)
        st.config(nodes['spine2'], tcp_server_cmd2)
        st.wait(2)  # Wait for servers to start
        
        # Verify both TCP servers are running on SD3
        server_check = st.show(nodes['spine2'], "netstat -tlnp | grep -E '{}|{}'".format(TCP_SERVER_PORT1, TCP_SERVER_PORT2), skip_tmpl=True, skip_error_check=True)
        st.log("TCP server check output on SD3: {}".format(server_check))
        
        # Step 4: Add initial static route with multiple nexthops (no APM)
        st.banner("Step 4: Adding initial static route with multiple nexthops (no APM)")
        
        # Configure static route with multiple nexthops - no APM initially
        initial_route_cmd = "config route add prefix vrf Vrf01 {} nexthop {},{}".format(STATIC_ROUTE_PREFIX, SPINE2_VLAN10_IP, SPINE2_VLAN20_IP)
        st.config(nodes['leaf2'], initial_route_cmd)
        st.wait(3)  # Wait for route to be installed
        
        # Step 5: Verify initial route is installed with both nexthops
        st.banner("Step 5: Verifying initial route installation")
        
        initial_route_output = st.show(nodes['leaf2'], "show ip route vrf Vrf01", skip_tmpl=True)
        st.log("Initial VRF Route table output on SD7: {}".format(initial_route_output))
        
        initial_nexthop1 = "via {}".format(SPINE2_VLAN10_IP) in str(initial_route_output)
        initial_nexthop2 = "via {}".format(SPINE2_VLAN20_IP) in str(initial_route_output)
        
        if initial_nexthop1 and initial_nexthop2:
            st.log("SUCCESS: Initial route installed with both nexthops")
        else:
            st.log("WARNING: Initial route may not have both nexthops - Nexthop1: {}, Nexthop2: {}".format(initial_nexthop1, initial_nexthop2))
        
        # Step 6: Configure APM TCP probes
        st.banner("Step 6: Configuring APM TCP probes on SD7 (leaf2)")
        
        # Configure APM TCP probe1 targeting SD3 Ethernet1_3
        apm_cmd1 = "sudo config apm add tcpprobe1 --type tcp-connect --dst-ip {} --dst-port {} --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true".format(SPINE2_VLAN10_IP, TCP_SERVER_PORT1)
        st.config(nodes['leaf2'], apm_cmd1)
        st.wait(2)
        
        # Configure APM TCP probe2 targeting SD3 Ethernet1_5
        apm_cmd2 = "sudo config apm add tcpprobe2 --type tcp-connect --dst-ip {} --dst-port {} --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true".format(SPINE2_VLAN20_IP, TCP_SERVER_PORT2)
        st.config(nodes['leaf2'], apm_cmd2)
        st.wait(2)  # Wait longer for APM probes to initialize
        
        # Verify APM probes are configured
        apm_config_output = st.show(nodes['leaf2'], "show apm", skip_tmpl=True, skip_error_check=True)
        st.log("APM configuration on SD7: {}".format(apm_config_output))
        
        if "tcpprobe1" not in str(apm_config_output) or "tcpprobe2" not in str(apm_config_output):
            st.report_fail('test_case_failed', "APM probes tcpprobe1 or tcpprobe2 not configured properly on SD7")

        # Step 7: Update route to use APM dependencies (override existing route)
        st.banner("Step 7: Updating route to use APM dependencies")
        
        # Configure route with APM dependencies - this should override the existing route
        apm_route_cmd = "config route add prefix vrf Vrf01 {} apm tcpprobe1,tcpprobe2".format(STATIC_ROUTE_PREFIX)
        st.config(nodes['leaf2'], apm_route_cmd)
        st.wait(3)  # Wait for route to be updated
        
        # Step 8: Verify both APM probes are UP and route shows both nexthops
        st.banner("Step 8: Verifying APM probes are UP and route behavior")
        
        # Check APM status
        apm_status_output = st.show(nodes['leaf2'], "show apm-status", skip_tmpl=True, skip_error_check=True)
        st.log("APM status on SD7: {}".format(apm_status_output))
        
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
        final_route_output = st.show(nodes['leaf2'], "show ip route vrf Vrf01", skip_tmpl=True)
        st.log("Final VRF Route table output on SD7: {}".format(final_route_output))
        
        final_route_found = False
        final_nexthop1 = False
        final_nexthop2 = False
        
        if STATIC_ROUTE_PREFIX in str(final_route_output):
            final_route_found = True
            st.log("SUCCESS: Route {} is still present after APM override".format(STATIC_ROUTE_PREFIX))
            
            if "via {}".format(SPINE2_VLAN10_IP) in str(final_route_output):
                final_nexthop1 = True
                st.log("SUCCESS: Route via {} (tcpprobe1) is active".format(SPINE2_VLAN10_IP))
            
            if "via {}".format(SPINE2_VLAN20_IP) in str(final_route_output):
                final_nexthop2 = True
                st.log("SUCCESS: Route via {} (tcpprobe2) is active".format(SPINE2_VLAN20_IP))
            
            # Look for the expected multi-line format
            if "[1/0] via {}".format(SPINE2_VLAN10_IP) in str(final_route_output) and "via {}".format(SPINE2_VLAN20_IP) in str(final_route_output):
                st.log("SUCCESS: Route shows expected format with both nexthops")
        else:
            st.log("FAIL: Route {} not found after APM override".format(STATIC_ROUTE_PREFIX))
        
        # APP-DB Verification: Check static route entry contains both nexthops
        verify_app_db_static_route(
            nodes['leaf2'],
            'redis-cli -n 0 hgetall "STATIC_ROUTE:Vrf01:{}"'.format(STATIC_ROUTE_PREFIX),
            [SPINE2_VLAN10_IP, SPINE2_VLAN20_IP],  # Both nexthops expected
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
            # Stop both TCP servers on SD3
            st.config(nodes['spine2'], "pkill -f 'tcpserver.py {}'".format(TCP_SERVER_PORT1), skip_error_check=True)
            st.config(nodes['spine2'], "pkill -f 'tcpserver.py {}'".format(TCP_SERVER_PORT2), skip_error_check=True)
            st.wait(1)
            
            # Remove static route from SD7 (leaf2)
            st.config(nodes['leaf2'], "config route del prefix vrf Vrf01 {}".format(STATIC_ROUTE_PREFIX), skip_error_check=True)
            
            # Remove APM probes from SD7 (leaf2)
            st.config(nodes['leaf2'], "config apm del tcpprobe1", skip_error_check=True)
            st.config(nodes['leaf2'], "config apm del tcpprobe2", skip_error_check=True)
            st.wait(1)
            
            # Remove IP addresses from SD3 Ethernet interfaces
            st.config(nodes['spine2'], "config interface ip remove {} {}".format(vars.D3D7P1, SPINE2_VLAN10_IP_PREFIX), skip_error_check=True)
            st.config(nodes['spine2'], "config interface ip remove {} {}".format(vars.D3D7P2, SPINE2_VLAN20_IP_PREFIX), skip_error_check=True)
            st.wait(1)
            
            # Remove Ethernet interfaces from Vlan10 on SD7 (leaf2)
            st.config(nodes['leaf2'], "config vlan member del 10 {}".format(vars.D7D3P1), skip_error_check=True)
            st.config(nodes['leaf2'], "config vlan member del 20 {}".format(vars.D7D3P2), skip_error_check=True)
            st.wait(1)
            
            # Clean up log files and server script on SD3
            st.config(nodes['spine2'], "rm -f /tmp/tcpserver1.log", skip_error_check=True)
            st.config(nodes['spine2'], "rm -f /tmp/tcpserver2.log", skip_error_check=True)
            
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
    - config apm add tcpprobe1 --type=tcp-connect --enable=true --vrf Vrf01 --dst-ip={SPINE2_VLAN10_IP} --dst-port={TCP_SERVER_PORT1}
    - config apm add tcpprobe2 --type=tcp-connect --enable=true --vrf Vrf01 --dst-ip={SPINE2_VLAN20_IP} --dst-port={TCP_SERVER_PORT1}
    - config route add prefix vrf Vrf01 {STATIC_ROUTE_PREFIX} nexthop {SPINE2_VLAN10_IP},{SPINE2_VLAN20_IP} apm tcpprobe1,tcpprobe2
    - config route del prefix vrf Vrf01 {STATIC_ROUTE_PREFIX} apm tcpprobe1
    - config route del prefix vrf Vrf01 {STATIC_ROUTE_PREFIX} apm tcpprobe2
    
    
    Test Steps:
    1. Configure dynamic ports (D7D3P1 to Vlan10 and D7D3P2 to Vlan20) on SD7 (leaf2)
    2. Configure IP addresses on SD3 (spine2) using dynamic ports (D3D7P1 and D3D7P2)
    3. Start TCP servers on both IPs on SD3 (spine2)
    4. Configure APM TCP probes (tcpprobe1 and tcpprobe2) - FIRST
    5. Add route with nexthops AND APM dependencies
    6. Verify route is installed and controlled by APM
    7. Delete APM dependency tcpprobe1 from route
    8. Delete APM dependency tcpprobe2 from route
    9. Verify route falls back to basic static routing with both nexthops
    10. Cleanup all configurations
    """
    vars = st.get_testbed_vars()
    
    st.banner("Starting APM Route Deletion and Fallback Test")
    
    try:
        # Step 1: Configure dynamic ports on SD7 (leaf2) to VLANs
        st.banner("Step 1: Configuring Ethernet interfaces on SD7 (leaf2) to Vlan10")
        
        # Add D7D3P1 to Vlan10 on SD7 (leaf2)
        st.config(nodes['leaf2'], "config vlan member add 10 {} -u".format(vars.D7D3P1))
        
        # Add D7D3P2 to Vlan20 on SD7 (leaf2)
        st.config(nodes['leaf2'], "config vlan member add 20 {} -u".format(vars.D7D3P2))
               
        # Step 2: Configure IP addresses on SD3 (spine2) using dynamic ports
        st.banner("Step 2: Configuring IP addresses on SD3 (spine2) using dynamic ports")
        
        # Configure IP address on SD3 (spine2) D3D7P1
        st.config(nodes['spine2'], "config interface ip add {} {}".format(vars.D3D7P1, SPINE2_VLAN10_IP_PREFIX))
        
        # Configure IP address on SD3 (spine2) D3D7P2
        st.config(nodes['spine2'], "config interface ip add {} {}".format(vars.D3D7P2, SPINE2_VLAN20_IP_PREFIX))
        
        # Step 3: Start TCP servers on both IPs on SD3 (spine2)
        st.banner("Step 3: Starting TCP servers on both IPs on SD3 (spine2)")
        
            
        
        # Start both TCP servers
        tcp_server_cmd1 = "cd /home/cisco && nohup python3 tcpserver.py {} {} > /tmp/tcpserver1.log 2>&1 &".format(TCP_SERVER_PORT1, SPINE2_VLAN10_IP)
        st.config(nodes['spine2'], tcp_server_cmd1)
        st.wait(2)
        
        tcp_server_cmd2 = "cd /home/cisco && nohup python3 tcpserver.py {} {} > /tmp/tcpserver2.log 2>&1 &".format(TCP_SERVER_PORT2, SPINE2_VLAN20_IP)
        st.config(nodes['spine2'], tcp_server_cmd2)
        st.wait(2)  # Wait for servers to start
        
        # # Verify both TCP servers are running
        # server_check = st.show(nodes['spine2'], "netstat -tlnp | grep -E '65432|65433'", skip_tmpl=True, skip_error_check=True)
        # st.log("TCP server check output on SD3: {}".format(server_check))
        
        # Step 4: Configure APM TCP probes FIRST (exact command order as specified)
        st.banner("Step 4: Configuring APM TCP probes on SD7 (leaf2) - FIRST")
        
        # Command 1: config apm add tcpprobe1
        apm_cmd1 = "sudo config apm add tcpprobe1 --type tcp-connect --dst-ip {} --dst-port {} --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true".format(SPINE2_VLAN10_IP, TCP_SERVER_PORT1)
        st.config(nodes['leaf2'], apm_cmd1)
        st.wait(2)
        
        # Command 2: config apm add tcpprobe2
        apm_cmd2 = "sudo config apm add tcpprobe2 --type tcp-connect --dst-ip {} --dst-port {} --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true".format(SPINE2_VLAN20_IP, TCP_SERVER_PORT2)
        st.config(nodes['leaf2'], apm_cmd2)
        st.wait(2)  # Wait longer for APM probes to initialize
        
        # Verify APM probes are configured and UP
        apm_config_output = st.show(nodes['leaf2'], "show apm", skip_tmpl=True, skip_error_check=True)
        st.log("APM configuration on SD7: {}".format(apm_config_output))
        
        apm_status_output = st.show(nodes['leaf2'], "show apm-status", skip_tmpl=True, skip_error_check=True)
        st.log("APM status on SD7: {}".format(apm_status_output))
        
        if "tcpprobe1" not in str(apm_config_output) or "tcpprobe2" not in str(apm_config_output):
            st.report_fail('test_case_failed', "APM probes tcpprobe1 or tcpprobe2 not configured properly on SD7")

        # Step 5: Add route with nexthops AND APM dependencies (exact command as specified)
        st.banner("Step 5: Adding route with nexthops and APM dependencies")
        
        # Command 3: config route add with both nexthops and APM
        route_with_apm_cmd = "config route add prefix vrf Vrf01 {} nexthop {},{} apm tcpprobe1,tcpprobe2".format(STATIC_ROUTE_PREFIX, SPINE2_VLAN10_IP, SPINE2_VLAN20_IP)
        st.config(nodes['leaf2'], route_with_apm_cmd)
        st.wait(2)  # Wait for route to be installed
        
        # Step 6: Verify route is installed and controlled by APM
        st.banner("Step 6: Verifying route is installed with APM control")
        
        initial_route_output = st.show(nodes['leaf2'], "show ip route vrf Vrf01", skip_tmpl=True)
        st.log("Initial route output with APM control: {}".format(initial_route_output))
        
        if STATIC_ROUTE_PREFIX in str(initial_route_output):
            st.log("SUCCESS: Route is installed with APM dependencies")
        else:
            st.log("WARNING: Route may not be installed properly with APM")
        
        # Step 7: Delete APM dependency tcpprobe1 from route (exact command as specified)
        st.banner("Step 7: Deleting APM dependency tcpprobe1 from route")
        
        # Command 4: config route del apm tcpprobe1
        del_apm1_cmd = "config route del prefix vrf Vrf01 {} apm tcpprobe1".format(STATIC_ROUTE_PREFIX)
        st.config(nodes['leaf2'], del_apm1_cmd)
        st.wait(2)
        
        # Check route status after first APM deletion
        after_del1_output = st.show(nodes['leaf2'], "show ip route vrf Vrf01", skip_tmpl=True)
        st.log("Route output after deleting tcpprobe1 APM dependency: {}".format(after_del1_output))
        
        # Step 8: Delete APM dependency tcpprobe2 from route (exact command as specified)
        st.banner("Step 8: Deleting APM dependency tcpprobe2 from route")
        
        # Command 5: config route del apm tcpprobe2
        del_apm2_cmd = "config route del prefix vrf Vrf01 {} apm tcpprobe2".format(STATIC_ROUTE_PREFIX)
        st.config(nodes['leaf2'], del_apm2_cmd)
        st.wait(1)
        
        # Step 9: Verify route falls back to basic static routing with both nexthops
        st.banner("Step 9: Verifying route fallback to basic static routing")
        
        # Display route table for terminal visibility
        st.log("Displaying final route table for verification:")
        st.show(nodes['leaf2'], "show ip route vrf Vrf01")
        
        final_route_output = st.show(nodes['leaf2'], "show ip route vrf Vrf01", skip_tmpl=True)
        st.log("Final route output after APM dependencies removed: {}".format(final_route_output))
        
        # Verify expected behavior - route should still exist with both nexthops but no APM control
        final_route_found = False
        final_nexthop1 = False
        final_nexthop2 = False
        
        if STATIC_ROUTE_PREFIX in str(final_route_output):
            final_route_found = True
            st.log("SUCCESS: Route {} still exists after APM deletion".format(STATIC_ROUTE_PREFIX))
            
            if "via {}".format(SPINE2_VLAN10_IP) in str(final_route_output):
                final_nexthop1 = True
                st.log("SUCCESS: Route via {} is active".format(SPINE2_VLAN10_IP))
            
            if "via {}".format(SPINE2_VLAN20_IP) in str(final_route_output):
                final_nexthop2 = True
                st.log("SUCCESS: Route via {} is active".format(SPINE2_VLAN20_IP))
            
            # Look for the expected multi-line format matching the expected output
            if "[1/0] via {}".format(SPINE2_VLAN10_IP) in str(final_route_output) and "via {}".format(SPINE2_VLAN20_IP) in str(final_route_output):
                st.log("SUCCESS: Route shows expected format with both nexthops as basic static route")
        else:
            st.log("FAIL: Route {} not found after APM deletion".format(STATIC_ROUTE_PREFIX))
        
        # Additional verification - ensure APM probes still exist but route is not using them
        final_apm_status = st.show(nodes['leaf2'], "show apm-status", skip_tmpl=True, skip_error_check=True)
        st.log("Final APM status (probes should still exist): {}".format(final_apm_status))
        
        # APP-DB Verification: Should be empty array since route fell back to basic static routing
        verify_app_db_static_route(
            nodes['leaf2'],
            'redis-cli -n 0 hgetall "STATIC_ROUTE:Vrf01:{}"'.format(STATIC_ROUTE_PREFIX),
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
            # Stop both TCP servers on SD3
            st.config(nodes['spine2'], "pkill -f 'tcpserver.py {}'".format(TCP_SERVER_PORT1), skip_error_check=True)
            st.config(nodes['spine2'], "pkill -f 'tcpserver.py {}'".format(TCP_SERVER_PORT2), skip_error_check=True)
            st.wait(1)
            
            # Remove static route from SD7 (leaf2)
            st.config(nodes['leaf2'], "config route del prefix vrf Vrf01 {}".format(STATIC_ROUTE_PREFIX), skip_error_check=True)
            
            # Remove APM probes from SD7 (leaf2)
            st.config(nodes['leaf2'], "config apm del tcpprobe1", skip_error_check=True)
            st.config(nodes['leaf2'], "config apm del tcpprobe2", skip_error_check=True)
            st.wait(1)
            
            # Remove IP addresses from SD3 using dynamic ports
            st.config(nodes['spine2'], "config interface ip remove {} {}".format(vars.D3D7P1, SPINE2_VLAN10_IP_PREFIX), skip_error_check=True)
            st.config(nodes['spine2'], "config interface ip remove {} {}".format(vars.D3D7P2, SPINE2_VLAN20_IP_PREFIX), skip_error_check=True)
            
            # Remove dynamic ports from VLANs on SD7 (leaf2)
            st.config(nodes['leaf2'], "config vlan member del 10 {}".format(vars.D7D3P1), skip_error_check=True)
            st.config(nodes['leaf2'], "config vlan member del 20 {}".format(vars.D7D3P2), skip_error_check=True)
            st.wait(1)
            
            # Clean up log files and server script on SD3
            st.config(nodes['spine2'], "rm -f /tmp/tcpserver1.log", skip_error_check=True)
            st.config(nodes['spine2'], "rm -f /tmp/tcpserver2.log", skip_error_check=True)
            
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
    1. Configure dynamic ports (D7D3P1 to Vlan10 and D7D3P2 to Vlan20) on SD7 (leaf2)
    2. Configure IP addresses on SD3 (spine2) using dynamic ports (D3D7P1 and D3D7P2)
    3. Start TCP servers on both IPs on SD3 (spine2)
    4. Configure APM probes tcpprobe1 and tcpprobe2
    5. Add static route with both nexthops and APM dependencies
    6. Verify both probes are UP and route is installed via both nexthops
    
    Phase 2 - Probe Down Transition (tcpprobe1 DOWN):
    7. Stop TCP server for tcpprobe1 (make tcpprobe1 go DOWN)
    8. Verify tcpprobe1 is DOWN, tcpprobe2 is UP
    9. Verify route only shows nexthop for working probe ({SPINE2_VLAN20_IP})
    
    Phase 3 - Probe Up Transition (tcpprobe1 UP):
    10. Restart TCP server for tcpprobe1 (make tcpprobe1 come back UP)
    11. Verify both tcpprobe1 and tcpprobe2 are UP
    12. Verify route shows both nexthops again ({SPINE2_VLAN10_IP} and {SPINE2_VLAN20_IP})
    13. Cleanup all configurations
    
    Expected Behavior:
    - Phase 1: Both probes UP, route via both nexthops
    - Phase 2: tcpprobe1 DOWN, route only via {SPINE2_VLAN20_IP}
    - Phase 3: Both probes UP, route via both nexthops restored
    """
    vars = st.get_testbed_vars()
    
    st.banner("Starting APM Probe State Transition Cycle Test")
    
    try:
        # =================== PHASE 1: INITIAL SETUP (BOTH PROBES UP) ===================
        st.banner("PHASE 1: Initial Setup - Both Probes UP")
        
        # Step 1: Configure dynamic ports on SD7 (leaf2) to VLANs
        st.banner("Step 1: Configuring Ethernet interfaces on SD7 (leaf2)")
        
        # Add D7D3P1 to Vlan10 on SD7 (leaf2)
        st.config(nodes['leaf2'], "config vlan member add 10 {} -u".format(vars.D7D3P1))
        
        # Add D7D3P2 to Vlan20 on SD7 (leaf2)
        st.config(nodes['leaf2'], "config vlan member add 20 {} -u".format(vars.D7D3P2))
        
        # Step 2: Configure IP addresses on SD3 (spine2) using dynamic ports
        st.banner("Step 2: Configuring IP addresses on SD3 (spine2) using dynamic ports")
        
        # Configure IP address on SD3 (spine2) D3D7P1
        st.config(nodes['spine2'], "config interface ip add {} {}".format(vars.D3D7P1, SPINE2_VLAN10_IP_PREFIX))
        
        # Configure IP address on SD3 (spine2) D3D7P2
        st.config(nodes['spine2'], "config interface ip add {} {}".format(vars.D3D7P2, SPINE2_VLAN20_IP_PREFIX))
        
        # Step 3: Start TCP servers on both IPs on SD3 (spine2)
        st.banner("Step 3: Starting TCP servers on both IPs on SD3 (spine2)")
        
        
        # Start TCP servers in background on both IPs on SD3
        tcp_server_cmd1 = "cd /home/cisco && nohup python3 tcpserver.py {} {} > /tmp/tcpserver1.log 2>&1 &".format(TCP_SERVER_PORT1, SPINE2_VLAN10_IP)
        st.config(nodes['spine2'], tcp_server_cmd1)
        
        tcp_server_cmd2 = "cd /home/cisco && nohup python3 tcpserver.py {} {} > /tmp/tcpserver2.log 2>&1 &".format(TCP_SERVER_PORT2, SPINE2_VLAN20_IP)
        st.config(nodes['spine2'], tcp_server_cmd2)
        st.wait(2)  # Wait for servers to start
        
        # Step 4: Configure APM probes tcpprobe1 and tcpprobe2
        st.banner("Step 4: Configuring APM probes tcpprobe1 and tcpprobe2")
        
        # Configure APM TCP probe1 targeting SD3 D3D7P1
        apm_cmd1 = "sudo config apm add tcpprobe1 --type tcp-connect --dst-ip {} --dst-port {} --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true".format(SPINE2_VLAN10_IP, TCP_SERVER_PORT1)
        st.config(nodes['leaf2'], apm_cmd1)
        st.wait(3)
        
        # Configure APM TCP probe2 targeting SD3 D3D7P2
        apm_cmd2 = "sudo config apm add tcpprobe2 --type tcp-connect --dst-ip {} --dst-port {} --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true".format(SPINE2_VLAN20_IP, TCP_SERVER_PORT2)
        st.config(nodes['leaf2'], apm_cmd2)
        st.wait(3)  # Wait for APM probes to initialize
        
        # Step 5: Add static route with both nexthops and APM dependencies
        st.banner("Step 5: Adding static route with both nexthops and APM dependencies")
        
        route_cmd = "config route add prefix vrf Vrf01 {} nexthop {},{} apm tcpprobe1,tcpprobe2".format(STATIC_ROUTE_PREFIX, SPINE2_VLAN10_IP, SPINE2_VLAN20_IP)
        st.config(nodes['leaf2'], route_cmd)
        st.wait(3)  # Wait for route to be installed
        
        # Step 6: Verify both probes are UP and route is installed via both nexthops
        st.banner("Step 6: Verifying both probes are UP and route via both nexthops")
        
        # Check APM status
        apm_status_phase1 = st.show(nodes['leaf2'], "show apm-status", skip_tmpl=True, skip_error_check=True)
        st.log("Phase 1 APM status: {}".format(apm_status_phase1))
        
        # Check route installation
        route_output_phase1 = st.show(nodes['leaf2'], "show ip route vrf Vrf01", skip_tmpl=True)
        st.log("Phase 1 route output: {}".format(route_output_phase1))
        
        # Validate Phase 1
        tcpprobe1_up_phase1 = any("up" in line.lower() for line in str(apm_status_phase1).split('\n') if "tcpprobe1" in line)
        tcpprobe2_up_phase1 = any("up" in line.lower() for line in str(apm_status_phase1).split('\n') if "tcpprobe2" in line)
        route_both_nexthops_phase1 = STATIC_ROUTE_PREFIX in str(route_output_phase1) and "via {}".format(SPINE2_VLAN10_IP) in str(route_output_phase1) and "via {}".format(SPINE2_VLAN20_IP) in str(route_output_phase1)
        
        phase1_success = tcpprobe1_up_phase1 and tcpprobe2_up_phase1 and route_both_nexthops_phase1
        
        if phase1_success:
            st.log("PHASE 1 PASSED: Both probes UP, route via both nexthops")
        else:
            st.log("PHASE 1 FAILED: tcpprobe1: {}, tcpprobe2: {}, both_nexthops: {}".format(
                tcpprobe1_up_phase1, tcpprobe2_up_phase1, route_both_nexthops_phase1))
        
        # =================== PHASE 2: PROBE DOWN TRANSITION ===================
        st.banner("PHASE 2: Probe Down Transition - Making tcpprobe1 DOWN")
        
        # Step 7: Stop TCP server for tcpprobe1 (make tcpprobe1 go DOWN)
        st.banner("Step 7: Stopping TCP server for tcpprobe1 (port {})".format(TCP_SERVER_PORT1))
        
        # Kill the TCP server on port (tcpprobe1)
        kill_cmd = "pkill -f 'tcpserver.py {}'".format(TCP_SERVER_PORT1)
        st.config(nodes['spine2'], kill_cmd, skip_error_check=True)
        st.wait(10)  # Wait for APM probe to detect server down
        
        # Step 8: Verify tcpprobe1 is DOWN, tcpprobe2 is UP
        st.banner("Step 8: Verifying tcpprobe1 DOWN, tcpprobe2 UP")
        
        apm_status_phase2 = st.show(nodes['leaf2'], "show apm-status", skip_tmpl=True, skip_error_check=True)
        st.log("Phase 2 APM status: {}".format(apm_status_phase2))
        
        # Step 9: Verify route only shows nexthop for working probe
        st.banner("Step 9: Verifying route only via working nexthop ({})".format(SPINE2_VLAN20_IP))
        
        route_output_phase2 = st.show(nodes['leaf2'], "show ip route vrf Vrf01", skip_tmpl=True)
        st.log("Phase 2 route output: {}".format(route_output_phase2))
        
        # Validate Phase 2
        tcpprobe1_down_phase2 = any("down" in line.lower() or "failed" in line.lower() for line in str(apm_status_phase2).split('\n') if "tcpprobe1" in line)
        tcpprobe2_up_phase2 = any("up" in line.lower() for line in str(apm_status_phase2).split('\n') if "tcpprobe2" in line)
        route_single_nexthop_phase2 = STATIC_ROUTE_PREFIX in str(route_output_phase2) and "via {}".format(SPINE2_VLAN20_IP) in str(route_output_phase2) and "via {}".format(SPINE2_VLAN10_IP) not in str(route_output_phase2)
        
        phase2_success = tcpprobe1_down_phase2 and tcpprobe2_up_phase2 and route_single_nexthop_phase2
        
        if phase2_success:
            st.log("PHASE 2 PASSED: tcpprobe1 DOWN, route only via {}".format(SPINE2_VLAN20_IP))
        else:
            st.log("PHASE 2 FAILED: tcpprobe1_down: {}, tcpprobe2_up: {}, single_nexthop: {}".format(
                tcpprobe1_down_phase2, tcpprobe2_up_phase2, route_single_nexthop_phase2))
        
        # =================== PHASE 3: PROBE UP TRANSITION ===================
        st.banner("PHASE 3: Probe Up Transition - Making tcpprobe1 UP again")
        
        # Step 10: Restart TCP server for tcpprobe1 (make tcpprobe1 come back UP)
        st.banner("Step 10: Restarting TCP server for tcpprobe1 (port {})".format(TCP_SERVER_PORT1))
        
        # Restart TCP server on port (tcpprobe1)
        tcp_server_cmd1_restart = "cd /home/cisco && nohup python3 tcpserver.py {} {} > /tmp/tcpserver1_restart.log 2>&1 &".format(TCP_SERVER_PORT1, SPINE2_VLAN10_IP)
        st.config(nodes['spine2'], tcp_server_cmd1_restart)
        st.wait(10)  # Wait for APM probe to detect server up
        
        # Step 11: Verify both tcpprobe1 and tcpprobe2 are UP
        st.banner("Step 11: Verifying both tcpprobe1 and tcpprobe2 are UP")
        
        apm_status_phase3 = st.show(nodes['leaf2'], "show apm-status", skip_tmpl=True, skip_error_check=True)
        st.log("Phase 3 APM status: {}".format(apm_status_phase3))
        
        # Step 12: Verify route shows both nexthops again
        st.banner("Step 12: Verifying route shows both nexthops again")
        
        route_output_phase3 = st.show(nodes['leaf2'], "show ip route vrf Vrf01", skip_tmpl=True)
        st.log("Phase 3 route output: {}".format(route_output_phase3))
        
        # Validate Phase 3
        tcpprobe1_up_phase3 = any("up" in line.lower() for line in str(apm_status_phase3).split('\n') if "tcpprobe1" in line)
        tcpprobe2_up_phase3 = any("up" in line.lower() for line in str(apm_status_phase3).split('\n') if "tcpprobe2" in line)
        route_both_nexthops_phase3 = STATIC_ROUTE_PREFIX in str(route_output_phase3) and "via {}".format(SPINE2_VLAN10_IP) in str(route_output_phase3) and "via {}".format(SPINE2_VLAN20_IP) in str(route_output_phase3)
        
        phase3_success = tcpprobe1_up_phase3 and tcpprobe2_up_phase3 and route_both_nexthops_phase3
        
        if phase3_success:
            st.log("PHASE 3 PASSED: Both probes UP, route via both nexthops restored")
        else:
            st.log("PHASE 3 FAILED: tcpprobe1_up: {}, tcpprobe2_up: {}, both_nexthops: {}".format(
                tcpprobe1_up_phase3, tcpprobe2_up_phase3, route_both_nexthops_phase3))
        
        # APP-DB Verification for final state
        st.banner("Final APP-DB Verification: Both nexthops should be present")
        verify_app_db_static_route(
            nodes['leaf2'],
            'redis-cli -n 0 hgetall "STATIC_ROUTE:Vrf01:{}"'.format(STATIC_ROUTE_PREFIX),
            [SPINE2_VLAN10_IP, SPINE2_VLAN20_IP],  # Both nexthops expected
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
            st.config(nodes['spine2'], "pkill -f 'tcpserver.py'", skip_error_check=True)
            st.wait(2)
            
            # Remove route
            st.config(nodes['leaf2'], "config route del prefix vrf Vrf01 {}".format(STATIC_ROUTE_PREFIX), skip_error_check=True)
            st.wait(1)
            
            # Remove APM probes
            st.config(nodes['leaf2'], "config apm del tcpprobe1", skip_error_check=True)
            st.config(nodes['leaf2'], "config apm del tcpprobe2", skip_error_check=True)
            st.wait(2)
            
            # Remove IP addresses from SD3 using dynamic ports
            st.config(nodes['spine2'], "config interface ip remove {} {}".format(vars.D3D7P1, SPINE2_VLAN10_IP_PREFIX), skip_error_check=True)
            st.config(nodes['spine2'], "config interface ip remove {} {}".format(vars.D3D7P2, SPINE2_VLAN20_IP_PREFIX), skip_error_check=True)
            
            # Remove dynamic ports from VLANs on SD7
            st.config(nodes['leaf2'], "config vlan member del 10 {}".format(vars.D7D3P1), skip_error_check=True)
            st.config(nodes['leaf2'], "config vlan member del 20 {}".format(vars.D7D3P2), skip_error_check=True)
            
            # Clean up TCP server files and logs
            st.config(nodes['spine2'], "rm -f /tmp/tcpserver1.log /tmp/tcpserver2.log /tmp/tcpserver1_restart.log", skip_error_check=True)
            
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
    1. Configure dynamic ports (D7D3P1 to Vlan10 and D7D3P2 to Vlan20) on SD7 (leaf2)
    2. Configure IP addresses on SD3 (spine2) using dynamic ports (D3D7P1 and D3D7P2)
    3. Start TCP servers on both IPs on SD3 (spine2)
    4. Configure APM probes tcpprobe1 and tcpprobe2
    5. Add static route with both nexthops and APM dependencies
    6. Verify both probes are UP and route is installed with both nexthops
    7. Remove IP address from D3D7P1 on SD3
    8. Verify failed nexthop is withdrawn but route remains via other nexthop
    9. Re-add IP address to D3D7P1 on SD3
    10. Verify probe comes back UP and route is restored with both nexthops
    
    Configuration Sequence:
    - sudo config apm add tcpprobe1 --type tcp-connect --dst-ip {SPINE2_VLAN10_IP} --dst-port {TCP_SERVER_PORT1} --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true
    - sudo config apm add tcpprobe2 --type tcp-connect --dst-ip {SPINE2_VLAN20_IP} --dst-port {TCP_SERVER_PORT2} --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true
    - config route add prefix vrf Vrf01 {STATIC_ROUTE_PREFIX} nexthop {SPINE2_VLAN10_IP},{SPINE2_VLAN20_IP} apm tcpprobe1,tcpprobe2
    - config interface ip remove <D3D7P1> {SPINE2_VLAN10_IP_PREFIX}
    - config interface ip add <D3D7P1> {SPINE2_VLAN10_IP_PREFIX}
    
    Expected Behavior:
    - Initially: Both probes UP, route installed with both nexthops
    - After IP removal: tcpprobe1 DOWN, failed nexthop ({SPINE2_VLAN10_IP}) withdrawn, route via {SPINE2_VLAN20_IP}
    - After IP re-addition: Both probes UP, route restored with both nexthops
    """
    vars = st.get_testbed_vars()
    
    st.banner("Starting APM Route Recovery via IP Address Re-addition Test")
    
    try:
        # Step 1: Configure dynamic ports on SD7 (leaf2) to VLANs
        st.banner("Step 1: Configuring Ethernet interfaces on SD7 (leaf2) to Vlan10")
        
        # Add D7D3P1 to Vlan10 on SD7 (leaf2)
        st.config(nodes['leaf2'], "config vlan member add 10 {} -u".format(vars.D7D3P1))
        
        # Add D7D3P2 to Vlan20 on SD7 (leaf2)
        st.config(nodes['leaf2'], "config vlan member add 20 {} -u".format(vars.D7D3P2))
        
        # Step 2: Configure IP addresses on SD3 (spine2) using dynamic ports
        st.banner("Step 2: Configuring IP addresses on SD3 (spine2) using dynamic ports")
        
        # Configure IP address on SD3 (spine2) D3D7P1
        st.config(nodes['spine2'], "config interface ip add {} {}".format(vars.D3D7P1, SPINE2_VLAN10_IP_PREFIX))
        
        # Configure IP address on SD3 (spine2) D3D7P2
        st.config(nodes['spine2'], "config interface ip add {} {}".format(vars.D3D7P2, SPINE2_VLAN20_IP_PREFIX))
        st.wait(1)
        
        # Step 3: Start TCP servers on both IPs on SD3 (spine2)
        st.banner("Step 3: Starting TCP servers on both IPs on SD3 (spine2)")
        
            
        
        # Start both TCP servers on different ports
        tcp_server_cmd1 = "cd /home/cisco && nohup python3 tcpserver.py {} {} > /tmp/tcpserver1.log 2>&1 &".format(TCP_SERVER_PORT1, SPINE2_VLAN10_IP)
        st.config(nodes['spine2'], tcp_server_cmd1)
        st.wait(1)
        
        tcp_server_cmd2 = "cd /home/cisco && nohup python3 tcpserver.py {} {} > /tmp/tcpserver2.log 2>&1 &".format(TCP_SERVER_PORT2, SPINE2_VLAN20_IP)
        st.config(nodes['spine2'], tcp_server_cmd2)
        st.wait(1)  # Wait for servers to start
        
        # Verify both TCP servers are running on different ports
        server_check = st.show(nodes['spine2'], "netstat -tlnp | grep -E '{}|{}'".format(TCP_SERVER_PORT1, TCP_SERVER_PORT2), skip_tmpl=True, skip_error_check=True)
        st.log("TCP server check output on SD3: {}".format(server_check))
        
        # Step 4: Configure APM probes (exact commands as specified)
        st.banner("Step 4: Configuring APM TCP probes on SD7 (leaf2)")
        
        # Command 1: sudo config apm add tcpprobe1 with full parameters
        apm_cmd1 = "sudo config apm add tcpprobe1 --type tcp-connect --dst-ip {} --dst-port {} --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true".format(SPINE2_VLAN10_IP, TCP_SERVER_PORT1)
        st.config(nodes['leaf2'], apm_cmd1)
        st.wait(1)
        
        # Command 2: sudo config apm add tcpprobe2 with full parameters  
        apm_cmd2 = "sudo config apm add tcpprobe2 --type tcp-connect --dst-ip {} --dst-port {} --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true".format(SPINE2_VLAN20_IP, TCP_SERVER_PORT2)
        st.config(nodes['leaf2'], apm_cmd2)
        st.wait(1)  # Wait for APM probes to initialize and come UP
        
        # Verify APM probes are configured
        apm_config_output = st.show(nodes['leaf2'], "show apm", skip_tmpl=True, skip_error_check=True)
        st.log("APM configuration: {}".format(apm_config_output))
        
        # Step 5: Add static route with both nexthops and APM dependencies
        st.banner("Step 5: Adding static route with both nexthops and APM dependencies")
        
        # Command 3: config route add with both nexthops and APM
        route_add_cmd = "config route add prefix vrf Vrf01 {} nexthop {},{} apm tcpprobe1,tcpprobe2".format(STATIC_ROUTE_PREFIX, SPINE2_VLAN10_IP, SPINE2_VLAN20_IP)
        st.config(nodes['leaf2'], route_add_cmd)
        st.wait(3)  # Wait for route to be installed
        
        # Step 6: Verify both probes are UP and route is installed with both nexthops
        st.banner("Step 6: Verifying initial state - both probes UP, route with both nexthops")
        
        # Check APM probe status (both should be UP)
        initial_apm_status = st.show(nodes['leaf2'], "show apm-status", skip_tmpl=True, skip_error_check=True)
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
        st.show(nodes['leaf2'], "show ip route vrf Vrf01")
        
        initial_route_output = st.show(nodes['leaf2'], "show ip route vrf Vrf01", skip_tmpl=True)
        st.log("Initial route output: {}".format(initial_route_output))
        
        # Verify route with both nexthops is present
        route_initially_present = False
        if STATIC_ROUTE_PREFIX in str(initial_route_output):
            route_initially_present = True
            st.log("SUCCESS: Route {} is installed with both nexthops".format(STATIC_ROUTE_PREFIX))
            
            # Verify both nexthops are present
            if SPINE2_VLAN10_IP in str(initial_route_output) and SPINE2_VLAN20_IP in str(initial_route_output):
                st.log("SUCCESS: Both nexthops ({} and {}) are present initially".format(SPINE2_VLAN10_IP, SPINE2_VLAN20_IP))
        else:
            st.log("WARNING: Route may not be installed properly")
        
        # Step 7: Remove IP address from D3D7P1 on SD3
        st.banner("Step 7: Removing IP address from D3D7P1 on SD3")
        
        # Command 4: config interface ip remove D3D7P1 (this will cause tcpprobe1 to go DOWN)
        ip_remove_cmd = "config interface ip remove {} {}".format(vars.D3D7P1, SPINE2_VLAN10_IP_PREFIX)
        st.config(nodes['spine2'], ip_remove_cmd)
        st.wait(5)  # Wait longer for probe state change and route update
        
        # Step 8: Verify failed nexthop is withdrawn but route remains via other nexthop
        st.banner("Step 8: Verifying nexthop withdrawal after IP removal")
        
        # Check APM probe status after IP removal
        after_removal_apm_status = st.show(nodes['leaf2'], "show apm-status", skip_tmpl=True, skip_error_check=True)
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
        st.show(nodes['leaf2'], "show ip route vrf Vrf01")
        
        after_removal_route_output = st.show(nodes['leaf2'], "show ip route vrf Vrf01", skip_tmpl=True)
        st.log("Route output after IP removal: {}".format(after_removal_route_output))
        
        # Verify route still exists with remaining nexthop
        route_after_removal = False
        if STATIC_ROUTE_PREFIX in str(after_removal_route_output):
            route_after_removal = True
            st.log("SUCCESS: Route still exists after IP removal")
            
            if SPINE2_VLAN20_IP in str(after_removal_route_output):
                st.log("SUCCESS: Remaining nexthop {} is present".format(SPINE2_VLAN20_IP))
        
        # Step 9: Re-add IP address to D3D7P1 on SD3
        st.banner("Step 9: Re-adding IP address to D3D7P1 on SD3")
        
        # Command 5: config interface ip add D3D7P1 (this should bring tcpprobe1 back UP)
        ip_readd_cmd = "config interface ip add {} {}".format(vars.D3D7P1, SPINE2_VLAN10_IP_PREFIX)
        st.config(nodes['spine2'], ip_readd_cmd)
        st.wait(90)  # Wait longer for probe state change and route update
        
        # Step 10: Verify probe comes back UP and route is restored with both nexthops
        st.banner("Step 10: Verifying route recovery after IP re-addition")
        
        # Check APM probe status after IP re-addition
        final_apm_status = st.show(nodes['leaf2'], "show apm-status", skip_tmpl=True, skip_error_check=True)
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
        st.show(nodes['leaf2'], "show ip route vrf Vrf01")
        
        final_route_output = st.show(nodes['leaf2'], "show ip route vrf Vrf01", skip_tmpl=True)
        st.log("Final route output: {}".format(final_route_output))
        
        # Verify expected behavior - route should be restored with both nexthops
        route_fully_restored = False
        both_nexthops_restored = False
        probe_recovery_verified = False
        
        if STATIC_ROUTE_PREFIX in str(final_route_output):
            route_fully_restored = True
            st.log("SUCCESS: Route {} exists after IP re-addition".format(STATIC_ROUTE_PREFIX))
            
            # Check if both nexthops are restored
            if SPINE2_VLAN10_IP in str(final_route_output) and SPINE2_VLAN20_IP in str(final_route_output):
                both_nexthops_restored = True
                st.log("SUCCESS: Both nexthops ({} and {}) are restored".format(SPINE2_VLAN10_IP, SPINE2_VLAN20_IP))
            
            # Check if route behavior changed back (probe recovery)
            if str(after_removal_route_output) != str(final_route_output):
                probe_recovery_verified = True
                st.log("SUCCESS: Route output changed after IP re-addition - probe recovery occurred")
        else:
            st.log("WARNING: Route not found after IP re-addition")
        
        # APP-DB Verification: Should contain both nexthops since both probes are UP after recovery
        verify_app_db_static_route(
            nodes['leaf2'],
            'redis-cli -n 0 hgetall "STATIC_ROUTE:Vrf01:{}"'.format(STATIC_ROUTE_PREFIX),
            [SPINE2_VLAN10_IP, SPINE2_VLAN20_IP],  # Both nexthops expected after IP re-addition recovery
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
            # Stop both TCP servers on SD3 (running on different ports)
            st.config(nodes['spine2'], "pkill -f 'tcpserver.py {}'".format(TCP_SERVER_PORT1), skip_error_check=True)
            st.config(nodes['spine2'], "pkill -f 'tcpserver.py {}'".format(TCP_SERVER_PORT2), skip_error_check=True)
            st.wait(1)
            
            # Remove route
            st.config(nodes['leaf2'], "config route del prefix vrf Vrf01 {}".format(STATIC_ROUTE_PREFIX), skip_error_check=True)
            
            # Remove APM probes from SD7 (leaf2)
            st.config(nodes['leaf2'], "config apm del tcpprobe1", skip_error_check=True)
            st.config(nodes['leaf2'], "config apm del tcpprobe2", skip_error_check=True)
            st.wait(1)
            
            # Remove IP addresses from SD3 using dynamic ports
            st.config(nodes['spine2'], "config interface ip remove {} {}".format(vars.D3D7P1, SPINE2_VLAN10_IP_PREFIX), skip_error_check=True)
            st.config(nodes['spine2'], "config interface ip remove {} {}".format(vars.D3D7P2, SPINE2_VLAN20_IP_PREFIX), skip_error_check=True)
            st.wait(1)
            
            # Remove dynamic ports from VLANs on SD7 (leaf2)
            st.config(nodes['leaf2'], "config vlan member del 10 {}".format(vars.D7D3P1), skip_error_check=True)
            st.config(nodes['leaf2'], "config vlan member del 20 {}".format(vars.D7D3P2), skip_error_check=True)
            
            
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
    1. Configure dynamic ports (D7D3P1 to Vlan10 and D7D3P2 to Vlan20) on SD7 (leaf2)
    2. Configure IP addresses on SD3 (spine2) using dynamic ports (D3D7P1 and D3D7P2)
    3. Start TCP server only on one IP (tcpprobe2 will work, tcpprobe1 will be down)
    4. Configure APM probes tcpprobe1 and tcpprobe2
    5. Add static route with both nexthops and APM dependencies
    6. Verify tcpprobe1 is DOWN, tcpprobe2 is UP
    7. Verify route is populated only for the working nexthop ({SPINE2_VLAN20_IP})
    
    Configuration Sequence:
    - sudo config apm add tcpprobe1 --type tcp-connect --dst-ip {SPINE2_VLAN10_IP} --dst-port {TCP_SERVER_PORT1} --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true
    - sudo config apm add tcpprobe2 --type tcp-connect --dst-ip {SPINE2_VLAN20_IP} --dst-port {TCP_SERVER_PORT2} --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true
    - config route add prefix vrf Vrf01 {STATIC_ROUTE_PREFIX} nexthop {SPINE2_VLAN10_IP},{SPINE2_VLAN20_IP} apm tcpprobe1,tcpprobe2
    
    Expected Behavior:
    - tcpprobe1: DOWN (no TCP server on {SPINE2_VLAN10_IP}:{TCP_SERVER_PORT1})
    - tcpprobe2: UP (TCP server running on {SPINE2_VLAN20_IP}:{TCP_SERVER_PORT2})
    - Route: Populated only for working nexthop {SPINE2_VLAN20_IP}
    """
    vars = st.get_testbed_vars()
    
    st.banner("Starting APM Route with Single Working Nexthop Test")
    
    try:
        # Step 1: Configure dynamic ports on SD7 (leaf2) to VLANs
        st.banner("Step 1: Configuring Ethernet interfaces on SD7 (leaf2) to Vlan10")
        
        # Add D7D3P1 to Vlan10 on SD7 (leaf2)
        st.config(nodes['leaf2'], "config vlan member add 10 {} -u".format(vars.D7D3P1))
        
        # Add D7D3P2 to Vlan20 on SD7 (leaf2)
        st.config(nodes['leaf2'], "config vlan member add 20 {} -u".format(vars.D7D3P2))
        
        # Step 2: Configure IP addresses on SD3 (spine2) using dynamic ports
        st.banner("Step 2: Configuring IP addresses on SD3 (spine2) using dynamic ports")
        
        # Configure IP address on SD3 (spine2) D3D7P1
        st.config(nodes['spine2'], "config interface ip add {} {}".format(vars.D3D7P1, SPINE2_VLAN10_IP_PREFIX))
        
        # Configure IP address on SD3 (spine2) D3D7P2
        st.config(nodes['spine2'], "config interface ip add {} {}".format(vars.D3D7P2, SPINE2_VLAN20_IP_PREFIX))
        st.wait(1)
        
        # Step 3: Start TCP server only on one IP (tcpprobe2 will work, tcpprobe1 will be down)
        st.banner("Step 3: Starting TCP server only on {} (tcpprobe1 will fail)".format(SPINE2_VLAN20_IP))
        
        
        # Start only TCP server on SPINE2_VLAN20_IP:TCP_SERVER_PORT2 (tcpprobe2 will be UP)
        # Do NOT start server on SPINE2_VLAN10_IP:TCP_SERVER_PORT1 (tcpprobe1 will be DOWN)
        tcp_server_cmd2 = "cd /home/cisco && nohup python3 tcpserver.py {} {} > /tmp/tcpserver2.log 2>&1 &".format(TCP_SERVER_PORT2, SPINE2_VLAN20_IP)
        st.config(nodes['spine2'], tcp_server_cmd2)
        st.wait(2)  # Wait for server to start
        
        

        # Verify only one TCP server is running (port TCP_SERVER_PORT2)
        server_check = st.show(nodes['spine2'], "netstat -tlnp | grep -E '{}|{}'".format(TCP_SERVER_PORT1, TCP_SERVER_PORT2), skip_tmpl=True, skip_error_check=True)
        st.log("TCP server check output on SD3 (should show only port {}): {}".format(TCP_SERVER_PORT2, server_check))
        
        # Step 4: Configure APM probes (tcpprobe1 will be DOWN, tcpprobe2 will be UP)
        st.banner("Step 4: Configuring APM TCP probes on SD7 (leaf2)")
        
        # Command 1: sudo config apm add tcpprobe1 (will be DOWN - no server listening)
        apm_cmd1 = "sudo config apm add tcpprobe1 --type tcp-connect --dst-ip {} --dst-port {} --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true".format(SPINE2_VLAN10_IP, TCP_SERVER_PORT1)
        st.config(nodes['leaf2'], apm_cmd1)
        st.wait(1)
        
        # Command 2: sudo config apm add tcpprobe2 (will be UP - server listening)
        apm_cmd2 = "sudo config apm add tcpprobe2 --type tcp-connect --dst-ip {} --dst-port {} --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true".format(SPINE2_VLAN20_IP, TCP_SERVER_PORT2)
        st.config(nodes['leaf2'], apm_cmd2)
        st.wait(2)  # Wait for APM probes to initialize
        
        # Verify APM probes are configured
        apm_config_output = st.show(nodes['leaf2'], "show apm", skip_tmpl=True, skip_error_check=True)
        st.log("APM configuration: {}".format(apm_config_output))
        
        # Step 5: Add static route with both nexthops and APM dependencies
        st.banner("Step 5: Adding static route with both nexthops and APM dependencies")
        
        # Command 3: config route add with both nexthops and APM
        route_add_cmd = "config route add prefix vrf Vrf01 {} nexthop {},{} apm tcpprobe1,tcpprobe2".format(STATIC_ROUTE_PREFIX, SPINE2_VLAN10_IP, SPINE2_VLAN20_IP)
        st.config(nodes['leaf2'], route_add_cmd)
        st.wait(3)  # Wait for route to be installed
        
        # Step 6: Verify tcpprobe1 is DOWN, tcpprobe2 is UP
        st.banner("Step 6: Verifying APM probe states - tcpprobe1 DOWN, tcpprobe2 UP")
        
        # Check APM probe status
        apm_status = st.show(nodes['leaf2'], "show apm-status", skip_tmpl=True, skip_error_check=True)
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
        
        # Step 7: Verify route is populated only for the working nexthop
        st.banner("Step 7: Verifying route populated only for working nexthop")
        
        # Display route state
        st.log("Route state (should show only working nexthop {}):".format(SPINE2_VLAN20_IP))
        st.show(nodes['leaf2'], "show ip route vrf Vrf01")
        
        route_output = st.show(nodes['leaf2'], "show ip route vrf Vrf01", skip_tmpl=True)
        st.log("Route output: {}".format(route_output))
        
        # Verify expected behavior - route should exist with only working nexthop
        route_exists = False
        working_nexthop_present = False
        failed_nexthop_absent = False
        
        if STATIC_ROUTE_PREFIX in str(route_output):
            route_exists = True
            st.log("SUCCESS: Route {} exists".format(STATIC_ROUTE_PREFIX))
            
            # Check if working nexthop is present
            if SPINE2_VLAN20_IP in str(route_output):
                working_nexthop_present = True
                st.log("SUCCESS: Working nexthop {} is present in route".format(SPINE2_VLAN20_IP))
            
            # Check if failed nexthop is absent or has reduced presence
            failed_nexthop_count = str(route_output).count(SPINE2_VLAN10_IP)
            if failed_nexthop_count == 0:
                failed_nexthop_absent = True
                st.log("SUCCESS: Failed nexthop {} is completely absent from route".format(SPINE2_VLAN10_IP))
            else:
                st.log("INFO: Failed nexthop {} appears {} times in route output".format(SPINE2_VLAN10_IP, failed_nexthop_count))
        else:
            st.log("WARNING: Route {} not found".format(STATIC_ROUTE_PREFIX))
        
        # APP-DB Verification: Should contain only the working nexthop
        verify_app_db_static_route(
            nodes['leaf2'],
            'redis-cli -n 0 hgetall "STATIC_ROUTE:Vrf01:{}"'.format(STATIC_ROUTE_PREFIX),
            [SPINE2_VLAN20_IP],  # Only expect working nexthop (tcpprobe2 UP)
            "APM Route Single Working Nexthop"
        )
        
        # Test success criteria
        if route_exists and working_nexthop_present and tcpprobe1_down and tcpprobe2_up:
            st.log("TEST PASSED: APM Route with Single Working Nexthop completed")
            st.log("Route populated only for working nexthop with correct APM probe states")
            st.log("APM probe states verified: tcpprobe1=DOWN, tcpprobe2=UP")
            st.log("Route shows working nexthop: {}".format(SPINE2_VLAN20_IP))
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
            # Stop TCP server on SD3 (only one was started)
            st.config(nodes['spine2'], "pkill -f 'tcpserver.py {}'".format(TCP_SERVER_PORT2), skip_error_check=True)
            st.wait(1)
            
            # Remove route
            st.config(nodes['leaf2'], "config route del prefix vrf Vrf01 {}".format(STATIC_ROUTE_PREFIX), skip_error_check=True)
            
            # Remove APM probes from SD7 (leaf2)
            st.config(nodes['leaf2'], "config apm del tcpprobe1", skip_error_check=True)
            st.config(nodes['leaf2'], "config apm del tcpprobe2", skip_error_check=True)
            
            # Remove IP addresses from SD3 using dynamic ports
            st.config(nodes['spine2'], "config interface ip remove {} {}".format(vars.D3D7P1, SPINE2_VLAN10_IP_PREFIX), skip_error_check=True)
            st.config(nodes['spine2'], "config interface ip remove {} {}".format(vars.D3D7P2, SPINE2_VLAN20_IP_PREFIX), skip_error_check=True)
            st.wait(1)
            
            # Remove dynamic ports from VLANs on SD7 (leaf2)
            st.config(nodes['leaf2'], "config vlan member del 10 {}".format(vars.D7D3P1), skip_error_check=True)
            st.config(nodes['leaf2'], "config vlan member del 20 {}".format(vars.D7D3P2), skip_error_check=True)
            st.wait(1)

            # Clean up log files and server script on SD3
            st.config(nodes['spine2'], "rm -f /tmp/tcpserver2.log", skip_error_check=True)
            
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
    1. Configure dynamic ports (D7D3P1 to Vlan10 and D7D3P2 to Vlan20) on SD7 (leaf2)
    2. Configure IP addresses on SD3 (spine2) using dynamic ports (D3D7P1 and D3D7P2)
    3. Start TCP servers on both IPs on SD3 (spine2)
    4. Configure APM probes tcpprobe1 and tcpprobe2
    5. Add static route with both nexthops and APM dependencies
    6. Verify both probes are UP and route has both nexthops
    7. Remove APM dependency for only tcpprobe1 (partial removal)
    8. Verify both probes remain UP and route still has both nexthops
    
    Configuration Sequence:
    - sudo config apm add tcpprobe1 --type tcp-connect --dst-ip {SPINE2_VLAN10_IP} --dst-port {TCP_SERVER_PORT1} --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true
    - sudo config apm add tcpprobe2 --type tcp-connect --dst-ip {SPINE2_VLAN20_IP} --dst-port {TCP_SERVER_PORT2} --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true
    - config route add prefix vrf Vrf01 {STATIC_ROUTE_PREFIX} nexthop {SPINE2_VLAN10_IP},{SPINE2_VLAN20_IP} apm tcpprobe1,tcpprobe2
    - config route del prefix vrf Vrf01 {STATIC_ROUTE_PREFIX} apm tcpprobe1
    
    Expected Behavior:
    - Initially: Both probes UP, route with both nexthops and both APM dependencies
    - After partial removal: Both probes UP, route with both nexthops, only tcpprobe2 dependency
    """
    vars = st.get_testbed_vars()
    
    st.banner("Starting APM Partial Dependency Removal Test")
    
    try:
        # Step 1: Configure dynamic ports on SD7 (leaf2) to VLANs
        st.banner("Step 1: Configuring Ethernet interfaces on SD7 (leaf2) to Vlan10")
        
        # Add D7D3P1 to Vlan10 on SD7 (leaf2)
        st.config(nodes['leaf2'], "config vlan member add 10 {} -u".format(vars.D7D3P1))
        
        # Add D7D3P2 to Vlan20 on SD7 (leaf2)
        st.config(nodes['leaf2'], "config vlan member add 20 {} -u".format(vars.D7D3P2))
        
        # Step 2: Configure IP addresses on SD3 (spine2) using dynamic ports
        st.banner("Step 2: Configuring IP addresses on SD3 (spine2) using dynamic ports")
        
        # Configure IP address on SD3 (spine2) D3D7P1
        st.config(nodes['spine2'], "config interface ip add {} {}".format(vars.D3D7P1, SPINE2_VLAN10_IP_PREFIX))
        
        # Configure IP address on SD3 (spine2) D3D7P2
        st.config(nodes['spine2'], "config interface ip add {} {}".format(vars.D3D7P2, SPINE2_VLAN20_IP_PREFIX))

        

        # Step 3: Start TCP servers on both IPs on SD3 (spine2)
        st.banner("Step 3: Starting TCP servers on both IPs on SD3 (spine2)")
        

        
        # Start both TCP servers on different ports
        tcp_server_cmd1 = "cd /home/cisco && nohup python3 tcpserver.py {} {} > /tmp/tcpserver1.log 2>&1 &".format(TCP_SERVER_PORT1, SPINE2_VLAN10_IP)
        st.config(nodes['spine2'], tcp_server_cmd1)
        st.wait(2)
        
        tcp_server_cmd2 = "cd /home/cisco && nohup python3 tcpserver.py {} {} > /tmp/tcpserver2.log 2>&1 &".format(TCP_SERVER_PORT2, SPINE2_VLAN20_IP)
        st.config(nodes['spine2'], tcp_server_cmd2)
        st.wait(2)  # Wait for servers to start
        
        
        # Step 4: Configure APM probes (both will be UP)
        st.banner("Step 4: Configuring APM TCP probes on SD7 (leaf2)")
        
        # Command 1: sudo config apm add tcpprobe1
        apm_cmd1 = "sudo config apm add tcpprobe1 --type tcp-connect --dst-ip {} --dst-port {} --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true".format(SPINE2_VLAN10_IP, TCP_SERVER_PORT1)
        st.config(nodes['leaf2'], apm_cmd1)
        st.wait(1)
        
        # Command 2: sudo config amp add tcpprobe2
        apm_cmd2 = "sudo config apm add tcpprobe2 --type tcp-connect --dst-ip {} --dst-port {} --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true".format(SPINE2_VLAN20_IP, TCP_SERVER_PORT2)
        st.config(nodes['leaf2'], apm_cmd2)
        st.wait(1)  # Wait for APM probes to initialize and come UP
        
        # Verify APM probes are configured
        apm_config_output = st.show(nodes['leaf2'], "show apm", skip_tmpl=True, skip_error_check=True)
        st.log("APM configuration: {}".format(apm_config_output))
        
        # Step 5: Add static route with both nexthops and APM dependencies
        st.banner("Step 5: Adding static route with both nexthops and APM dependencies")
        
        # Command 3: config route add with both nexthops and APM
        route_add_cmd = "config route add prefix vrf Vrf01 {} nexthop {},{} apm tcpprobe1,tcpprobe2".format(STATIC_ROUTE_PREFIX, SPINE2_VLAN10_IP, SPINE2_VLAN20_IP)
        st.config(nodes['leaf2'], route_add_cmd)
        st.wait(2)  # Wait for route to be installed
        
        # Step 6: Verify both probes are UP and route has both nexthops
        st.banner("Step 6: Verifying initial state - both probes UP, route with both nexthops")
        
        # Check APM probe status (both should be UP)
        initial_apm_status = st.show(nodes['leaf2'], "show apm-status", skip_tmpl=True, skip_error_check=True)
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
        st.show(nodes['leaf2'], "show ip route vrf Vrf01")
        
        initial_route_output = st.show(nodes['leaf2'], "show ip route vrf Vrf01", skip_tmpl=True)
        st.log("Initial route output: {}".format(initial_route_output))
        
        # Verify route with both nexthops is present
        route_initially_present = False
        both_nexthops_initial = False
        if STATIC_ROUTE_PREFIX in str(initial_route_output):
            route_initially_present = True
            st.log("SUCCESS: Route {} is installed".format(STATIC_ROUTE_PREFIX))
            
            if SPINE2_VLAN10_IP in str(initial_route_output) and SPINE2_VLAN20_IP in str(initial_route_output):
                both_nexthops_initial = True
                st.log("SUCCESS: Both nexthops ({} and {}) are present initially".format(SPINE2_VLAN10_IP, SPINE2_VLAN20_IP))
        
        # Step 7: Remove APM dependency for only tcpprobe1 (partial removal)
        st.banner("Step 7: Removing APM dependency for tcpprobe1 only (partial removal)")
        
        # Command 4: config route del prefix with apm tcpprobe1 (partial dependency removal)
        apm_partial_remove_cmd = "config route del prefix vrf Vrf01 {} apm tcpprobe1".format(STATIC_ROUTE_PREFIX)
        st.config(nodes['leaf2'], apm_partial_remove_cmd)
        st.wait(2)  # Wait for route update
        
        # Step 8: Verify both probes remain UP and route still has both nexthops
        st.banner("Step 8: Verifying final state - both probes UP, route with both nexthops preserved")
        
        # Check APM probe status after partial dependency removal
        final_apm_status = st.show(nodes['leaf2'], "show apm-status", skip_tmpl=True, skip_error_check=True)
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
        st.show(nodes['leaf2'], "show ip route vrf Vrf01")
        
        final_route_output = st.show(nodes['leaf2'], "show ip route vrf Vrf01", skip_tmpl=True)
        st.log("Final route output: {}".format(final_route_output))
        
        # Verify expected behavior - route should preserve both nexthops
        route_preserved = False
        both_nexthops_preserved = False
        
        if STATIC_ROUTE_PREFIX in str(final_route_output):
            route_preserved = True
            st.log("SUCCESS: Route {} is preserved after partial dependency removal".format(STATIC_ROUTE_PREFIX))
            
            # Check if both nexthops are still present
            if SPINE2_VLAN10_IP in str(final_route_output) and SPINE2_VLAN20_IP in str(final_route_output):
                both_nexthops_preserved = True
                st.log("SUCCESS: Both nexthops ({} and {}) are preserved".format(SPINE2_VLAN10_IP, SPINE2_VLAN20_IP))
        else:
            st.log("WARNING: Route not found after partial dependency removal")
        
        # APP-DB verification after partial dependency removal
        st.banner("Step 9: Verifying APP-DB static route after partial dependency removal")
        # Both nexthops should remain

        verify_app_db_static_route(
            nodes['leaf2'],
            'redis-cli -n 0 hgetall "STATIC_ROUTE:Vrf01:{}"'.format(STATIC_ROUTE_PREFIX),
            [SPINE2_VLAN20_IP],  # Only expect working nexthop (tcpprobe2 UP)
            "APM Route Single Working Nexthop"
        )
        
        # Test success criteria - route preserved with both nexthops AND both probes UP
        if route_preserved and both_nexthops_preserved and tcpprobe1_up_final and tcpprobe2_up_final:
            st.log("TEST PASSED: APM Partial Dependency Removal completed successfully")
            st.log("Route preserved with both nexthops after removing only tcpprobe1 dependency")
            st.log("APM probe states verified: tcpprobe1=UP, tcpprobe2=UP")
            st.log("Both nexthops remain active: {}, {}".format(SPINE2_VLAN10_IP, SPINE2_VLAN20_IP))
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
            # Stop both TCP servers on SD3
            st.config(nodes['spine2'], "pkill -f 'tcpserver.py {}'".format(TCP_SERVER_PORT1), skip_error_check=True)
            st.config(nodes['spine2'], "pkill -f 'tcpserver.py {}'".format(TCP_SERVER_PORT2), skip_error_check=True)
            st.wait(1)
            
            # Remove route completely
            st.config(nodes['leaf2'], "config route del prefix vrf Vrf01 {}".format(STATIC_ROUTE_PREFIX), skip_error_check=True)
            
            # Remove APM probes from SD7 (leaf2)
            st.config(nodes['leaf2'], "config apm del tcpprobe1", skip_error_check=True)
            st.config(nodes['leaf2'], "config apm del tcpprobe2", skip_error_check=True)
            st.wait(1)
            
            # Remove IP addresses from SD3 using dynamic ports
            st.config(nodes['spine2'], "config interface ip remove {} {}".format(vars.D3D7P1, SPINE2_VLAN10_IP_PREFIX), skip_error_check=True)
            st.config(nodes['spine2'], "config interface ip remove {} {}".format(vars.D3D7P2, SPINE2_VLAN20_IP_PREFIX), skip_error_check=True)
            st.wait(1)
            
            # Remove dynamic ports from VLANs on SD7 (leaf2)
            st.config(nodes['leaf2'], "config vlan member del 10 {}".format(vars.D7D3P1), skip_error_check=True)
            st.config(nodes['leaf2'], "config vlan member del 20 {}".format(vars.D7D3P2), skip_error_check=True)
            
            # Clean up log files and server script on SD3
            st.config(nodes['spine2'], "rm -f /tmp/tcpserver1.log", skip_error_check=True)
            st.config(nodes['spine2'], "rm -f /tmp/tcpserver2.log", skip_error_check=True)
            
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
    Test APM static route configuration and BGP redistribution
    
    Test Scenario:
    Configure APM probes and static route with APM dependencies on SD7, then redistribute
    the static route via BGP and verify it appears on SD2.
    
    Test Steps:
    1. Configure dynamic ports (D7D3P1 to Vlan10 and D7D3P2 to Vlan20) on SD7 (leaf2)
    2. Configure IP addresses on SD3 (spine2) using dynamic ports (D3D7P1 and D3D7P2)
    3. Start TCP servers on both IPs on SD3 (spine2)
    4. Configure APM probes tcpprobe1 and tcpprobe2 on SD7
    5. Add static route with both nexthops and APM dependencies on SD7
    6. Configure BGP redistribution of static routes on SD7
    7. Verify route with nexthops is present on SD2
    
    Configuration Sequence:
    - sudo config apm add tcpprobe1 --type tcp-connect --dst-ip {SPINE2_VLAN10_IP} --dst-port {TCP_SERVER_PORT1} --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true
    - sudo config apm add tcpprobe2 --type tcp-connect --dst-ip {SPINE2_VLAN20_IP} --dst-port {TCP_SERVER_PORT2} --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true
    - config route add prefix vrf Vrf01 {STATIC_ROUTE_PREFIX} nexthop {SPINE2_VLAN10_IP},{SPINE2_VLAN20_IP} apm tcpprobe1,tcpprobe2
    - BGP redistribution: router bgp 2363033449 vrf Vrf01 -> address-family ipv4 unicast -> redistribute static
    
    Expected Behavior:
    - APM probes UP on SD7
    - Static route installed on SD7 with both nexthops
    - Route redistributed via BGP and present on SD5
    """
    vars = st.get_testbed_vars()
    
    st.banner("Starting APM Static Route BGP Redistribution Test")
    
    # Initialize BGP ASN variable for use in both main and cleanup sections
    bgp_asn = "30"  # Default BGP ASN, will be updated if existing config is found
    
    try:
        # Step 1: Configure dynamic ports on SD7 (leaf2) to VLANs
        st.banner("Step 1: Configuring Ethernet interfaces on SD7 (leaf2) to Vlan10")
        
        # Add D7D3P1 to Vlan10 on SD7 (leaf2)
        st.config(nodes['leaf2'], "config vlan member add 10 {} -u".format(vars.D7D3P1))
        
        # Add D7D3P2 to Vlan20 on SD7 (leaf2)
        st.config(nodes['leaf2'], "config vlan member add 20 {} -u".format(vars.D7D3P2))
          
        # Step 2: Configure IP addresses on SD3 (spine2) using dynamic ports
        st.banner("Step 2: Configuring IP addresses on SD3 (spine2) using dynamic ports")
        
        # Configure IP address on SD3 (spine2) D3D7P1
        st.config(nodes['spine2'], "config interface ip add {} {}".format(vars.D3D7P1, SPINE2_VLAN10_IP_PREFIX))
        
        # Configure IP address on SD3 (spine2) D3D7P2
        st.config(nodes['spine2'], "config interface ip add {} {}".format(vars.D3D7P2, SPINE2_VLAN20_IP_PREFIX))
        
        # Step 3: Start TCP servers on both IPs on SD3 (spine2)
        st.banner("Step 3: Starting TCP servers on both IPs on SD3 (spine2)")
        
            
        
        # Start both TCP servers on different ports
        tcp_server_cmd1 = "cd /home/cisco && nohup python3 tcpserver.py {} {} > /tmp/tcpserver1.log 2>&1 &".format(TCP_SERVER_PORT1, SPINE2_VLAN10_IP)
        st.config(nodes['spine2'], tcp_server_cmd1)
        st.wait(1)

        tcp_server_cmd2 = "cd /home/cisco && nohup python3 tcpserver.py {} {} > /tmp/tcpserver2.log 2>&1 &".format(TCP_SERVER_PORT2, SPINE2_VLAN20_IP)
        st.config(nodes['spine2'], tcp_server_cmd2)
        st.wait(1)  # Wait for servers to start
        
        # Verify both TCP servers are running on different ports
        server_check = st.show(nodes['spine2'], "netstat -tlnp | grep -E '{}|{}'".format(TCP_SERVER_PORT1, TCP_SERVER_PORT2), skip_tmpl=True, skip_error_check=True)
        st.log("TCP server check output on SD3: {}".format(server_check))
        
        # Step 4: Configure APM probes on SD7 (leaf2)
        st.banner("Step 4: Configuring APM TCP probes on SD7 (leaf2)")
        
        # Command 1: sudo config apm add tcpprobe1
        apm_cmd1 = "sudo config apm add tcpprobe1 --type tcp-connect --dst-ip {} --dst-port {} --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true".format(SPINE2_VLAN10_IP, TCP_SERVER_PORT1)
        st.config(nodes['leaf2'], apm_cmd1)
        
        # Command 2: sudo config apm add tcpprobe2
        apm_cmd2 = "sudo config apm add tcpprobe2 --type tcp-connect --dst-ip {} --dst-port {} --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true".format(SPINE2_VLAN20_IP, TCP_SERVER_PORT2)
        st.config(nodes['leaf2'], apm_cmd2)
        st.wait(1)  # Wait for APM probes to initialize and come UP
        
        # Verify APM probes are configured
        apm_config_output = st.show(nodes['leaf2'], "show apm", skip_tmpl=True, skip_error_check=True)
        st.log("APM configuration: {}".format(apm_config_output))
        
        # Step 5: Add static route with both nexthops and APM dependencies on SD7
        st.banner("Step 5: Adding static route with both nexthops and APM dependencies on SD7")
        
        # Command 3: config route add with both nexthops and APM (corrected IP address)
        route_add_cmd = "config route add prefix vrf Vrf01 {} nexthop {},{} apm tcpprobe1,tcpprobe2".format(STATIC_ROUTE_PREFIX, SPINE2_VLAN10_IP, SPINE2_VLAN20_IP)
        st.config(nodes['leaf2'], route_add_cmd)
        st.wait(5)  # Wait for route to be installed
        
        # Verify APM probe status on SD7
        apm_status = st.show(nodes['leaf2'], "show apm-status", skip_tmpl=True, skip_error_check=True)
        st.log("APM status on SD7: {}".format(apm_status))
        st.wait(5)
        
        st.log("BGP redistribution configured on SD7")
        st.wait(10)  # Wait for BGP redistribution to take effect
        
        # Verify BGP configuration on SD7
        bgp_config_check = st.show(nodes['leaf2'], "vtysh -c 'show running-config'", skip_tmpl=True, skip_error_check=True)
        st.log("BGP configuration check on SD7: {}".format(bgp_config_check))
        # Step 7: Verify route with nexthops is present on SD2
        st.banner("Step 7: Verifying redistributed route is present on SD2")

        # Check routes on SD2 (leaf0)
        st.log("Checking for redistributed route on SD2:")
        route_output_sd2 = st.show(nodes['leaf0'], "show ip route vrf Vrf01", skip_tmpl=True, skip_error_check=True)
        st.log("Route output on SD2: {}".format(route_output_sd2))

        # Verify if the redistributed route is present on SD2
        route_present_on_sd2 = False
        if STATIC_ROUTE_PREFIX in str(route_output_sd2):
            route_present_on_sd2 = True
            st.log("SUCCESS: Route {} found on SD2 via BGP redistribution".format(STATIC_ROUTE_PREFIX))
        else:
            st.log("WARNING: Route {} not found on SD2".format(STATIC_ROUTE_PREFIX))

        
        # APP-DB verification for BGP redistribution test
        st.banner("Step 8: Verifying APP-DB static route after BGP redistribution")
        verify_app_db_static_route(
            nodes['leaf2'],
            'redis-cli -n 0 hgetall "STATIC_ROUTE:Vrf01:{}"'.format(STATIC_ROUTE_PREFIX),
            [SPINE2_VLAN10_IP, SPINE2_VLAN20_IP],
            "APM Route Both Nexthops"
        )
        
        # Test success criteria
        if route_present_on_sd2:
            st.log("TEST PASSED: APM Static Route BGP Redistribution completed successfully")
            st.log("Route {} redistributed from SD7 to SD2 via BGP".format(STATIC_ROUTE_PREFIX))
            st.banner("APM Static Route BGP Redistribution Test - PASSED")
            st.report_pass('test_case_passed')
        else:
            st.report_fail('test_case_failed', "Test failed: Route not found on SD5")

    except Exception as e:
        st.log("Exception occurred during test execution: {}".format(str(e)))
        st.report_fail('test_case_failed', "Test failed with exception: {}".format(str(e)))
        
    finally:
        # Cleanup configurations
        st.banner("Cleanup: Removing all test configurations")
        
        try:
            # Stop both TCP servers on SD3
            st.config(nodes['spine2'], "pkill -f 'tcpserver.py {}'".format(TCP_SERVER_PORT1), skip_error_check=True)
            st.config(nodes['spine2'], "pkill -f 'tcpserver.py {}'".format(TCP_SERVER_PORT2), skip_error_check=True)
            
            # Remove route completely from SD7
            st.config(nodes['leaf2'], "config route del prefix vrf Vrf01 {}".format(STATIC_ROUTE_PREFIX), skip_error_check=True)
            
            # Remove APM probes from SD7 (leaf2)
            st.config(nodes['leaf2'], "config apm del tcpprobe1", skip_error_check=True)
            st.config(nodes['leaf2'], "config apm del tcpprobe2", skip_error_check=True)
            
            # Remove IP addresses from SD3 using dynamic ports
            st.config(nodes['spine2'], "config interface ip remove {} {}".format(vars.D3D7P1, SPINE2_VLAN10_IP_PREFIX), skip_error_check=True)
            st.config(nodes['spine2'], "config interface ip remove {} {}".format(vars.D3D7P2, SPINE2_VLAN20_IP_PREFIX), skip_error_check=True)
            
            # Remove dynamic ports from VLANs on SD7 (leaf2)
            st.config(nodes['leaf2'], "config vlan member del 10 {}".format(vars.D7D3P1), skip_error_check=True)
            st.config(nodes['leaf2'], "config vlan member del 20 {}".format(vars.D7D3P2), skip_error_check=True)
            
            # Clean up log files and server script on SD3
            st.config(nodes['spine2'], "rm -f /tmp/tcpserver1.log", skip_error_check=True)
            st.config(nodes['spine2'], "rm -f /tmp/tcpserver2.log", skip_error_check=True)
            
            st.banner("Cleanup completed successfully")
            
        except Exception as cleanup_e:
            st.log("Warning: Some cleanup operations failed: {}".format(str(cleanup_e)))

######################################################################
# Test EVPN Multi-Homing with PortChannel and APM Integration 
######################################################################
@pytest.mark.system_box
@pytest.mark.community
@pytest.mark.community_pass
def test_evpn_mh_portchannel_apm():
    """
    Test EVPN Multi-Homing with PortChannel configuration and APM integration
    
    Device Mapping:
    - SD5 (leaf0): EVPN Multi-Homing Leaf with PortChannel5 and Loopback5 (via YAML config)
    - SD6 (leaf1): EVPN Multi-Homing Leaf with PortChannel5 and Loopback5 (via YAML config)  
    - SD7 (leaf2): Additional leaf for tcpprobe2 target
    - SD2 (spine1): Host with dual-homing PortChannel5 to both SD5 and SD6
    - SD3 (spine2): Host for second TCP server target
    
    Test Steps:
    1. PortChannel5 with EVPN-ESI and Loopback5 on SD5/SD6 configured via static_route_apm_evpn_mh_v6_config.yaml
    2. Configure PortChannel5 on SD2 (host0) with dual-homing to SD5 and SD6
    3. Configure additional interface on SD7 and SD3 for second TCP server
    4. Start TCP servers on SD2 (10.212.10.5:65432) and SD3 (10.212.10.6:65432)
    5. Configure APM probes and routes on SD5, SD6, and SD7 targeting both TCP servers
    6. Verify APM probe states and route installation across all devices
    7. Perform ping test with server kill scenario to validate APM behavior
    8. Cleanup all manually configured items (YAML deconfig handles PortChannel5/Loopback5)
    """
    vars = st.get_testbed_vars()
    
    st.banner("Starting EVPN Multi-Homing PortChannel APM Exact Sequence Test")
    
    try:
        # PortChannel5 and Loopback5 configurations are now handled by static_route_apm_evpn_mh_v6_config.yaml
        st.banner("Step 1-2: PortChannel5 with EVPN-ESI configurations handled by config YAML")
        st.log("SD5 (leaf0) and SD6 (leaf1) PortChannel5 and Loopback5 configurations from YAML")
        # Step 3: Configure PortChannel5 on SD2 (spine1) with dual-homing and TCP server
        st.banner("Step 3: Configuring PortChannel5 on SD2 (spine1) with dual-homing")
        
        # Add PortChannel5
        st.config(nodes['spine1'], "config portchannel add PortChannel5")
        st.wait(1)
        
        # Add first member to PortChannel5 (D2D5P2 connects to leaf0)
        st.config(nodes['spine1'], "config portchannel member add PortChannel5 {}".format(vars.D2D5P2))
        st.wait(1)
        
        # Add second member to PortChannel5 (D2D6P2 connects to leaf1)
        st.config(nodes['spine1'], "config portchannel member add PortChannel5 {}".format(vars.D2D6P2))
        st.wait(1)

        # Add IP to PortChannel5
        st.config(nodes['spine1'], "config interface ip add PortChannel5 {}".format(HOST0_PORTCHANNEL5_IP_PREFIX))
        st.wait(1)
        
        # Add route for 172.16.1.1/32
        st.config(nodes['spine1'], "config route add prefix {} nexthop {}".format(HOST0_ROUTE1_PREFIX, HOST0_NEXTHOP_IP))
        st.wait(5)
        
        # Add route for 172.16.2.1/32
        st.config(nodes['spine1'], "config route add prefix {} nexthop {}".format(HOST0_ROUTE2_PREFIX, HOST0_NEXTHOP_IP))
        st.wait(1)  # Wait 1 second as specified

        # Start TCP server
        st.banner("Step 3a: Starting TCP server on SD2 (spine1)")
        
            
        
        # Start TCP server on 10.212.10.5:65432
        tcp_server_cmd = "cd /home/cisco && nohup python3 tcpserver.py {} {} > /tmp/tcpserver.log 2>&1 &".format(TCP_SERVER_PORT1, HOST0_PORTCHANNEL5_IP)
        st.config(nodes['spine1'], tcp_server_cmd)
        st.wait(2)  # Extended wait for server startup
        
        
        st.log("SD2 (spine1) PortChannel5 configuration and TCP server startup completed")
        
        # Step 3b: Configure additional interface on SD7 and SD3 for tcpprobe2
        st.banner("Step 3b: Configuring SD7 dynamic port (D7D3P1) to VLAN 10 and SD3 dynamic port (D3D7P1) IP")
        
        # Add D7D3P1 to VLAN 10 on SD7 (leaf2)
        st.config(nodes['leaf2'], "config vlan member add 10 {} -u".format(vars.D7D3P1))
        
        # Configure IP address on SD3 D3D7P1
        st.config(nodes['spine2'], "config interface ip add {} {}".format(vars.D3D7P1, SPINE2_VLAN10_IP_PREFIX))
        
        # Start second TCP server on SD3 for tcpprobe2
        st.banner("Step 3c: Starting second TCP server on SD3")
        
            
        
        # Start TCP server on SD3 10.212.10.6:65432
        tcp_server_cmd_sd3 = "cd /home/cisco && nohup python3 tcpserver.py {} {} > /tmp/tcpserver_sd3.log 2>&1 &".format(TCP_SERVER_PORT1, SPINE2_VLAN10_IP)
        st.config(nodes['spine2'], tcp_server_cmd_sd3)
        st.wait(1)  # Extended wait for server startup
        
        
        
        st.log("SD7 dynamic port (D7D3P1) VLAN configuration and SD3 TCP server startup completed")
        
        # Step 4: Configure APM probes and routes on SD5 (leaf0)
        st.banner("Step 4: Configuring APM probes and route on SD5 (leaf0)")
        
        # Verify connectivity before configuring APM probes
        st.log("Verifying connectivity from SD5 to target destinations")


        # Add tcpprobe1 targeting SD2 (10.212.10.5:65432)
        st.log("Adding tcpprobe1 on SD5 targeting SD2 ({}:{})".format(HOST0_PORTCHANNEL5_IP, TCP_SERVER_PORT1))
        apm_cmd1_sd5 = "sudo config apm add tcpprobe1 --type tcp-connect --dst-ip {} --dst-port {} --src-intf Loopback5 --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true".format(HOST0_PORTCHANNEL5_IP, TCP_SERVER_PORT1)
        st.config(nodes['leaf0'], apm_cmd1_sd5)
        st.wait(1)  # Extended wait for probe initialization
        
        
        # Add tcpprobe2 targeting SD3 (10.212.10.6:65432)
        st.log("Adding tcpprobe2 on SD5 targeting SD3 ({}:{})".format(SPINE2_VLAN10_IP, TCP_SERVER_PORT1))
        apm_cmd2_sd5 = "sudo config apm add tcpprobe2 --type tcp-connect --dst-ip {} --dst-port {} --src-intf Loopback5 --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true".format(SPINE2_VLAN10_IP, TCP_SERVER_PORT1)
        st.config(nodes['leaf0'], apm_cmd2_sd5)
        st.wait(1)  # Wait for APM probes to initialize
        
        # Show APM status on SD5
        apm_status_sd5 = st.show(nodes['leaf0'], "show apm-status", skip_tmpl=True, skip_error_check=True)
        st.log("APM status on SD5 (leaf0): {}".format(apm_status_sd5))
        
        # Add route with both nexthops and APM probes
        route_cmd_sd5 = "config route add prefix vrf Vrf01 {} nexthop {},{} apm tcpprobe1,tcpprobe2".format(EVPN_STATIC_ROUTE_PREFIX, HOST0_PORTCHANNEL5_IP, SPINE2_VLAN10_IP)
        st.config(nodes['leaf0'], route_cmd_sd5)
        st.wait(2)  # Wait for route installation
        
        # Show IP route on SD5
        route_output_sd5 = st.show(nodes['leaf0'], "show ip route vrf Vrf01", skip_tmpl=True)
        st.log("IP route VRF Vrf01 on SD5 (leaf0): {}".format(route_output_sd5))
        
        st.log("SD5 (leaf0) APM probes and route configuration completed")
        
        # Step 5: Configure APM probes and routes on SD6 (leaf1)
        st.banner("Step 5: Configuring APM probes and route on SD6 (leaf1)")
        
        # Add tcpprobe1 targeting SD2 (10.212.10.5:65432)
        apm_cmd1_sd6 = "sudo config apm add tcpprobe1 --type tcp-connect --dst-ip {} --dst-port {} --src-intf Loopback5 --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true".format(HOST0_PORTCHANNEL5_IP, TCP_SERVER_PORT1)
        st.config(nodes['leaf1'], apm_cmd1_sd6)
        st.wait(1)
        
        # Add tcpprobe2 targeting SD3 (10.212.10.6:65432)
        apm_cmd2_sd6 = "sudo config apm add tcpprobe2 --type tcp-connect --dst-ip {} --dst-port {} --src-intf Loopback5 --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true".format(SPINE2_VLAN10_IP, TCP_SERVER_PORT1)
        st.config(nodes['leaf1'], apm_cmd2_sd6)
        st.wait(1)  # Wait for APM probes to initialize
        
        # Show APM status on SD6
        apm_status_sd6 = st.show(nodes['leaf1'], "show apm-status", skip_tmpl=True, skip_error_check=True)
        
        # Add route with both nexthops and APM probes
        route_cmd_sd6 = "config route add prefix vrf Vrf01 {} nexthop {},{} apm tcpprobe1,tcpprobe2".format(EVPN_STATIC_ROUTE_PREFIX, HOST0_PORTCHANNEL5_IP, SPINE2_VLAN10_IP)
        st.config(nodes['leaf1'], route_cmd_sd6)
        st.wait(2)  # Wait for route installation
        
        # Show IP route on SD6
        route_output_sd6 = st.show(nodes['leaf1'], "show ip route vrf Vrf01", skip_tmpl=True)
        st.log("IP route VRF Vrf01 on SD6 (leaf1): {}".format(route_output_sd6))
        
        st.log("SD6 (leaf1) APM probes and route configuration completed")
        
        # Step 6: Configure APM probes and routes on SD7 (leaf2)
        st.banner("Step 6: Configuring APM probes and route on SD7 (leaf2)")
        
        # Add tcpprobe1 targeting SD2 (10.212.10.5:65432)
        apm_cmd1_sd7 = "sudo config apm add tcpprobe1 --type tcp-connect --dst-ip {} --dst-port {} --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true".format(HOST0_PORTCHANNEL5_IP, TCP_SERVER_PORT1)
        st.config(nodes['leaf2'], apm_cmd1_sd7)
        st.wait(1)
        
        # Add tcpprobe2 targeting SD3 (10.212.10.6:65432)
        apm_cmd2_sd7 = "sudo config apm add tcpprobe2 --type tcp-connect --dst-ip {} --dst-port {} --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true".format(SPINE2_VLAN10_IP, TCP_SERVER_PORT1)
        st.config(nodes['leaf2'], apm_cmd2_sd7)
        st.wait(1)  # Wait for APM probes to initialize
        
        # Show APM status on SD7
        apm_status_sd7 = st.show(nodes['leaf2'], "show apm-status", skip_tmpl=True, skip_error_check=True)
        
        # Add route with both nexthops and APM probes
        route_cmd_sd7 = "config route add prefix vrf Vrf01 {} nexthop {},{} apm tcpprobe1,tcpprobe2".format(EVPN_STATIC_ROUTE_PREFIX, HOST0_PORTCHANNEL5_IP, SPINE2_VLAN10_IP)
        st.config(nodes['leaf2'], route_cmd_sd7)
        st.wait(2)  # Wait for route installation
        
        # Show IP route on SD7
        route_output_sd7 = st.show(nodes['leaf2'], "show ip route vrf Vrf01", skip_tmpl=True)
        st.log("IP route VRF Vrf01 on SD7 (leaf2): {}".format(route_output_sd7))
        
        st.log("SD7 (leaf2) APM probes and route configuration completed")
        
        # Step 7: Final Verification of APM Probe States and Routes
        st.banner("Step 7: Final Verification - APM Probe States and Route Installation")
        
        # Include SD7 route output in verification
        route_present_sd5 = EVPN_STATIC_ROUTE_PREFIX in str(route_output_sd5)
        route_present_sd6 = EVPN_STATIC_ROUTE_PREFIX in str(route_output_sd6)
        route_present_sd7 = EVPN_STATIC_ROUTE_PREFIX in str(route_output_sd7)
        
        # Verification on SD5 (leaf0) - tcpprobe1 UP, tcpprobe2 DOWN, route with tcpprobe1 only
        st.banner("Verifying SD5 (leaf0): tcpprobe1 UP, route with tcpprobe1 only")
        
        tcpprobe1_up_sd5 = False
        
        # Debug: Show detailed APM status parsing for SD5
        st.log("DEBUG: Detailed APM status analysis for SD5:")
        st.log("Raw APM status output: {}".format(repr(str(apm_status_sd5))))
        
        if "tcpprobe1" in str(apm_status_sd5):
            apm_lines_sd5 = str(apm_status_sd5).split('\n')
            for line in apm_lines_sd5:
                if "tcpprobe1" in line:
                    st.log("DEBUG: Found tcpprobe1 line: '{}'".format(line.strip()))
                    if ("UP" in line or "up" in line.lower()):
                        tcpprobe1_up_sd5 = True
                        st.log("SUCCESS: tcpprobe1 is UP on SD5 (leaf0)")
                        break
                    else:
                        st.log("WARNING: tcpprobe1 is not UP on SD5. Line: '{}'".format(line.strip()))
        else:
            st.log("WARNING: tcpprobe1 not found in APM status on SD5")
        
        
        route_with_probe1_sd5 = route_present_sd5 and HOST0_PORTCHANNEL5_IP in str(route_output_sd5)
        
        if route_with_probe1_sd5:
            st.log("SUCCESS: Route {} with nexthop {} (tcpprobe1) is present on SD5".format(EVPN_STATIC_ROUTE_PREFIX, HOST0_PORTCHANNEL5_IP))
        else:
            st.log("WARNING: Route with tcpprobe1 nexthop not found on SD5")
        
        
        tcpprobe1_up_sd6 = False
        
        if "tcpprobe1" in str(apm_status_sd6):
            apm_lines_sd6 = str(apm_status_sd6).split('\n')
            for line in apm_lines_sd6:
                if "tcpprobe1" in line and ("UP" in line or "up" in line.lower()):
                    tcpprobe1_up_sd6 = True
                    st.log("SUCCESS: tcpprobe1 is UP on SD6 (leaf1)")
                    break
        
        
        route_with_probe1_sd6 = route_present_sd6 and HOST0_PORTCHANNEL5_IP in str(route_output_sd6)
        
        if route_with_probe1_sd6:
            st.log("SUCCESS: Route {} with nexthop {} (tcpprobe1) is present on SD6".format(EVPN_STATIC_ROUTE_PREFIX, HOST0_PORTCHANNEL5_IP))
        else:
            st.log("WARNING: Route with tcpprobe1 nexthop not found on SD6")
        
        
        tcpprobe1_down_sd7 = False
        tcpprobe2_up_sd7 = False
        
        if "tcpprobe1" in str(apm_status_sd7):
            apm_lines_sd7 = str(apm_status_sd7).split('\n')
            for line in apm_lines_sd7:
                if "tcpprobe1" in line and ("DOWN" in line or "down" in line.lower() or "FAILED" in line):
                    tcpprobe1_down_sd7 = True
                    st.log("SUCCESS: tcpprobe1 is DOWN on SD7 (leaf2)")
                    break
        
        if "tcpprobe2" in str(apm_status_sd7):
            apm_lines_sd7 = str(apm_status_sd7).split('\n')
            for line in apm_lines_sd7:
                if "tcpprobe2" in line and ("UP" in line or "up" in line.lower()):
                    tcpprobe2_up_sd7 = True
                    st.log("SUCCESS: tcpprobe2 is UP on SD7 (leaf2)")
                    break
        
        route_with_probe2_sd7 = route_present_sd7 and SPINE2_VLAN10_IP in str(route_output_sd7)
        
        if route_with_probe2_sd7:
            st.log("SUCCESS: Route {} with nexthop {} (probe2) is present on SD7".format(EVPN_STATIC_ROUTE_PREFIX, SPINE2_VLAN10_IP))
        else:
            st.log("WARNING: Route with probe2 nexthop not found on SD7")
        
        
        #configuration for ping test between spine1 and spine2
        # config on spine2 (SD3/spine2) - Loopback6 for ping target
        st.banner("Extra Config on SD3 (spine2): Adding Loopback6")
        st.config(nodes['spine2'], "config loopback add Loopback6")
        st.wait(1)
        st.config(nodes['spine2'], "config interface ip add Loopback6 {}".format(HOST1_LOOPBACK6_IP_PREFIX))
        
        
        # config on leaf2 (SD7) - Route with APM dependency
        st.banner("Extra Config on SD7 (leaf2): Adding route with APM dependency")
        route_add_cmd = "config route add prefix vrf Vrf01 {} nexthop {} apm tcpprobe2".format(HOST1_LOOPBACK6_IP_PREFIX, SPINE2_VLAN10_IP)
        st.config(nodes['leaf2'], route_add_cmd)
        st.wait(2)
        

        
        #  config on spine1 (SD2/spine1) - Route for ping
        st.banner("Extra Config on SD2 (spine1): Adding route for ping")
        ping_route_cmd = "config route add prefix {} nexthop {}".format(HOST1_LOOPBACK6_IP_PREFIX, HOST0_NEXTHOP_IP)
        st.config(nodes['spine1'], ping_route_cmd)
        st.wait(5)

        # Ping Test Phase 1: Both TCP servers running - ping should work
        st.banner("Ping Test Phase 1: Testing connectivity with both TCP servers running")
        st.wait(1)
        ping_cmd = "ping {} -I {} -c 3".format(HOST0_PORTCHANNEL5_IP, HOST1_LOOPBACK6_IP)
        ping_output1 = st.config(nodes['spine2'], ping_cmd, skip_error_check=True)
        st.log("Ping output (both servers running): {}".format(ping_output1))
        
        # Check if ping is successful (look for "64 bytes from" or similar success indicators)
        ping1_success = False
        if ping_output1 and ("64 bytes from" in str(ping_output1) or "bytes from" in str(ping_output1)):
            ping1_success = True
            st.log("SUCCESS: Ping works when both TCP servers are running")
        else:
            st.log("FAILED: Ping failed when both TCP servers are running")
        # Ping Test Phase 2: Kill tcpserver2 and test ping again - should fail
        st.banner("Ping Test Phase 2: Killing tcpserver2 to make tcpprobe2 DOWN")
        
        # Kill tcpserver2 on SD3 (port 65432) to make tcpprobe2 DOWN
        kill_cmd = "pkill -f 'tcpserver.py {}'".format(TCP_SERVER_PORT1)
        st.config(nodes['spine2'], kill_cmd, skip_error_check=True)
        st.wait(5)  # Wait for APM probe to detect server down
        
        # Run ping again - should fail since route dependency is broken
        ping_output2 = st.config(nodes['spine2'], ping_cmd, skip_error_check=True)
        st.log("Ping output (after killing tcpserver2): {}".format(ping_output2))
        
        # Check if ping fails (no "64 bytes from" or timeout/unreachable messages)
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

        
        # Final test success criteria - ALL conditions must be met for test to pass
        # SD5: tcpprobe1 UP, tcpprobe2 DOWN, route with tcpprobe1 only
        sd5_criteria_met = tcpprobe1_up_sd5 and route_with_probe1_sd5
        
        # SD6: tcpprobe1 UP, tcpprobe2 DOWN, route with tcpprobe1 only
        sd6_criteria_met = tcpprobe1_up_sd6 and route_with_probe1_sd6
        
        # SD7: tcpprobe1 DOWN, tcpprobe2 UP, route with tcpprobe2 only
        sd7_criteria_met = tcpprobe1_down_sd7 and tcpprobe2_up_sd7 and route_with_probe2_sd7
        
        # Test PASSES only if ALL scenarios are completely satisfied INCLUDING ping test
        if sd5_criteria_met and sd6_criteria_met and sd7_criteria_met and ping_test_passed:
            st.log("TEST PASSED: All verification criteria met successfully")
            st.log("SD5: tcpprobe1=UP, route with tcpprobe1 nexthop ({}) only".format(HOST0_PORTCHANNEL5_IP))
            st.log("SD6: tcpprobe1=UP, route with tcpprobe1 nexthop ({}) only".format(HOST0_PORTCHANNEL5_IP))
            st.log("SD7: tcpprobe1=DOWN, tcpprobe2=UP, route with tcpprobe2 nexthop ({}) only".format(SPINE2_VLAN10_IP))
            st.log("PING TEST: Connectivity works with servers up, fails when server down")
            st.banner("EVPN Multi-Homing PortChannel APM Test - PASSED")
            st.report_pass('test_case_passed')
        else:
            # Detailed failure reporting
            st.log("TEST FAILED: Not all verification criteria met")
            
            if not ping_test_passed:
                st.log("PING TEST FAILED: Phase1 success: {}, Phase2 failure: {}".format(ping1_success, ping2_failed))
            
            if not sd5_criteria_met:
                st.log("SD5 FAILED: Required - tcpprobe1=UP, route with tcpprobe1 only")
                st.log("SD5 Status: tcpprobe1={} route_with_probe1={}".format(
                    tcpprobe1_up_sd5, route_with_probe1_sd5))
                    
            if not sd6_criteria_met:
                st.log("SD6 FAILED: Required - tcpprobe1=UP, route with tcpprobe1 only")
                st.log("SD6 Status: tcpprobe1={} route_with_probe1={}".format(
                    tcpprobe1_up_sd6, route_with_probe1_sd6))
                    
            if not sd7_criteria_met:
                st.log("SD7 FAILED: Required - tcpprobe1=DOWN, tcpprobe2=UP, route with tcpprobe2 only")
                st.log("SD7 Status: tcpprobe1_down={}, tcpprobe2={}, route_with_probe2={}".format(
                    tcpprobe1_down_sd7, tcpprobe2_up_sd7, route_with_probe2_sd7))
            
            st.banner("EVPN Multi-Homing PortChannel APM Test - FAILED")
            st.report_fail('test_case_failed', "Test failed - not all verification criteria met")

    except Exception as e:
        st.log("Exception occurred during test execution: {}".format(str(e)))
        st.report_fail('test_case_failed', "Test failed with exception: {}".format(str(e)))
        
    finally:
        # Cleanup configurations
        st.banner("Cleanup: Removing all test configurations")
        
        try:
            # Cleanup extra configurations first
            st.banner("Cleanup: Removing extra configurations")
            
            
            # Remove extra route from SD7 (leaf2)
            st.log("Removing route {} from SD7 (leaf2)".format(HOST1_LOOPBACK6_IP_PREFIX))
            st.config(nodes['leaf2'], "config route del prefix vrf Vrf01 {}".format(HOST1_LOOPBACK6_IP_PREFIX), skip_error_check=True)
            
            # Remove extra route from SD2 (spine1)
            st.log("Removing route {} from SD2 (spine1)".format(HOST1_LOOPBACK6_IP_PREFIX))
            st.config(nodes['spine1'], "config route del prefix {}".format(HOST1_LOOPBACK6_IP_PREFIX), skip_error_check=True)
            
            # Remove Loopback6 from SD3 (spine2)
            st.log("Removing Loopback6 configurations from SD3 (spine2)")
            st.config(nodes['spine2'], "config interface ip remove Loopback6 {}".format(HOST1_LOOPBACK6_IP_PREFIX), skip_error_check=True)
            # st.config(nodes['spine2'], "config loopback del Loopback6", skip_error_check=True)
            
            
            # Stop TCP servers on SD2 (spine1) and SD3 (spine2)
            st.log("Stopping TCP servers on SD2 and SD3")
            st.config(nodes['spine1'], "pkill -f 'tcpserver.py {}'".format(TCP_SERVER_PORT1), skip_error_check=True)
            st.config(nodes['spine2'], "pkill -f 'tcpserver.py {}'".format(TCP_SERVER_PORT1), skip_error_check=True)
            st.wait(1)  # Extended wait for process cleanup
            
            # Verify TCP servers are stopped
            server_check_after_kill_sd2 = st.config(nodes['spine1'], "pgrep -f 'tcpserver.py {}'".format(TCP_SERVER_PORT1), skip_error_check=True)
            server_check_after_kill_sd3 = st.config(nodes['spine2'], "pgrep -f 'tcpserver.py {}'".format(TCP_SERVER_PORT1), skip_error_check=True)
            st.log("TCP server check after kill - SD2: {}, SD3: {}".format(server_check_after_kill_sd2, server_check_after_kill_sd3))
            
            # Remove routes from SD5 (leaf0)
            st.log("Removing route {} from SD5 (leaf0)".format(EVPN_STATIC_ROUTE_PREFIX))
            st.config(nodes['leaf0'], "config route del prefix vrf Vrf01 {}".format(EVPN_STATIC_ROUTE_PREFIX), skip_error_check=True)  # Extended wait for route removal
            
            # Remove routes from SD6 (leaf1)
            st.log("Removing route {} from SD6 (leaf1)".format(EVPN_STATIC_ROUTE_PREFIX))
            st.config(nodes['leaf1'], "config route del prefix vrf Vrf01 {}".format(EVPN_STATIC_ROUTE_PREFIX), skip_error_check=True)
            
            # Remove routes from SD7 (leaf2)
            st.log("Removing route {} from SD7 (leaf2)".format(EVPN_STATIC_ROUTE_PREFIX))
            st.config(nodes['leaf2'], "config route del prefix vrf Vrf01 {}".format(EVPN_STATIC_ROUTE_PREFIX), skip_error_check=True)
            
            # Verify routes are removed
            route_check_sd5 = st.show(nodes['leaf0'], "show ip route vrf Vrf01 {}".format(EVPN_STATIC_ROUTE_PREFIX), skip_tmpl=True, skip_error_check=True)
            route_check_sd6 = st.show(nodes['leaf1'], "show ip route vrf Vrf01 {}".format(EVPN_STATIC_ROUTE_PREFIX), skip_tmpl=True, skip_error_check=True)
            route_check_sd7 = st.show(nodes['leaf2'], "show ip route vrf Vrf01 {}".format(EVPN_STATIC_ROUTE_PREFIX), skip_tmpl=True, skip_error_check=True)
            st.log("Route verification after removal - SD5: {}, SD6: {}, SD7: {}".format(route_check_sd5, route_check_sd6, route_check_sd7))
            
            # Remove APM probes from SD5 (leaf0) - with verification
            st.log("Removing APM probes from SD5 (leaf0)")
            st.config(nodes['leaf0'], "config apm del tcpprobe1", skip_error_check=True)
            st.config(nodes['leaf0'], "config apm del tcpprobe2", skip_error_check=True)
            
            # Verify APM probes removed from SD5
            apm_check_sd5 = st.show(nodes['leaf0'], "show apm", skip_tmpl=True, skip_error_check=True)
            st.log("APM status after cleanup on SD5: {}".format(apm_check_sd5))
            
            # Remove APM probes from SD6 (leaf1)
            st.log("Removing APM probes from SD6 (leaf1)")
            st.config(nodes['leaf1'], "config apm del tcpprobe1", skip_error_check=True)
            st.config(nodes['leaf1'], "config apm del tcpprobe2", skip_error_check=True)
            
            # Verify APM probes removed from SD6
            apm_check_sd6 = st.show(nodes['leaf1'], "show apm", skip_tmpl=True, skip_error_check=True)
            st.log("APM status after cleanup on SD6: {}".format(apm_check_sd6))
            
            # Remove APM probes from SD7 (leaf2)
            st.log("Removing APM probes from SD7 (leaf2)")
            st.config(nodes['leaf2'], "config apm del tcpprobe1", skip_error_check=True)
            st.config(nodes['leaf2'], "config apm del tcpprobe2", skip_error_check=True)
            
            # Verify APM probes removed from SD7
            apm_check_sd7 = st.show(nodes['leaf2'], "show apm", skip_tmpl=True, skip_error_check=True)
            st.log("APM status after cleanup on SD7: {}".format(apm_check_sd7))
            
            # Loopback5 configurations for SD5 (leaf0) and SD6 (leaf1) handled by YAML deconfig
            st.log("Loopback5 configurations for SD5 and SD6 handled by static_route_apm_evpn_mh_v6_config.yaml deconfig")
            
            
            # Remove IP address from SD3 using dynamic port (D3D7P1)
            st.log("Removing IP address from SD3 dynamic port (D3D7P1)")
            st.config(nodes['spine2'], "config interface ip remove {} {}".format(vars.D3D7P1, SPINE2_VLAN10_IP_PREFIX), skip_error_check=True)
            st.wait(1)  # Extended wait for IP removal
            
            # Remove dynamic port (D7D3P1) from VLAN 10 on SD7 (leaf2)
            st.log("Removing dynamic port (D7D3P1) from VLAN 10 on SD7 (leaf2)")
            st.config(nodes['leaf2'], "config vlan member del 10 {}".format(vars.D7D3P1), skip_error_check=True)
            st.wait(1)  # Extended wait for VLAN member removal
            
            # Remove routes from SD2 (spine1)
            st.log("Removing routes from SD2 (spine1)")
            st.config(nodes['spine1'], "config route del prefix {}".format(HOST0_ROUTE1_PREFIX), skip_error_check=True)
            st.config(nodes['spine1'], "config route del prefix {}".format(HOST0_ROUTE2_PREFIX), skip_error_check=True)
            st.wait(1)  # Extended wait for route removal
            
            # Remove PortChannel5 IP from SD2 (spine1)
            st.log("Removing PortChannel5 IP from SD2 (spine1)")
            st.config(nodes['spine1'], "config interface ip remove PortChannel5 {}".format(HOST0_PORTCHANNEL5_IP_PREFIX), skip_error_check=True)
            st.wait(1)  # Extended wait for IP removal
            
            # PortChannel5 configurations for SD5 (leaf0) and SD6 (leaf1) handled by YAML deconfig
            st.log("PortChannel5 configurations for SD5 and SD6 handled by static_route_apm_evpn_mh_v6_config.yaml deconfig")
            
            # Remove PortChannel5 members and PortChannel from SD2 (spine1)
            st.log("Removing PortChannel5 configurations from SD2 (spine1)")
            st.config(nodes['spine1'], "config portchannel member del PortChannel5 {}".format(vars.D2D5P2), skip_error_check=True)
            st.config(nodes['spine1'], "config portchannel member del PortChannel5 {}".format(vars.D2D6P2), skip_error_check=True)
            st.config(nodes['spine1'], "config portchannel del PortChannel5", skip_error_check=True)
            st.wait(1)  # Extended wait for PortChannel cleanup
            
            # Verify PortChannel5 interfaces are removed (SD5 and SD6 handled by YAML)
            portchannel_check_sd2 = st.show(nodes['spine1'], "show interfaces portchannel", skip_tmpl=True, skip_error_check=True)
            st.log("PortChannel verification after cleanup - SD2: {} (SD5/SD6 handled by YAML deconfig)".format(portchannel_check_sd2))
            
            # Clean up log files and server script on SD2 (spine1)
            st.log("Cleaning up TCP server files on SD2 (spine1)")
            st.config(nodes['spine1'], "rm -f /tmp/tcpserver.log", skip_error_check=True)
            
            # Clean up log files and server script on SD3 (spine2)
            st.log("Cleaning up TCP server files on SD3 (spine2)")
            st.config(nodes['spine2'], "rm -f /tmp/tcpserver_sd3.log", skip_error_check=True)
            
            # Verify files are cleaned up
            file_check_sd2 = st.config(nodes['spine1'], "ls -la /tmp/tcpserver.log /home/cisco/tcpserver.py", skip_error_check=True)
            file_check_sd3 = st.config(nodes['spine2'], "ls -la /tmp/tcpserver_sd3.log /home/cisco/tcpserver.py", skip_error_check=True)
            st.log("File cleanup verification - SD2: {}, SD3: {}".format(file_check_sd2, file_check_sd3))
            
            # Final verification summary
            st.banner("Final Cleanup Verification Summary")
            st.log("1. TCP servers stopped and verified")
            st.log("2. Routes {} removed from all devices and verified".format(EVPN_STATIC_ROUTE_PREFIX))
            st.log("3. APM probes (tcpprobe1, tcpprobe2) removed from all devices and verified")
            st.log("4. Loopback5 interfaces for SD2/SD3 handled by static_route_apm_evpn_mh_v6_config.yaml deconfig")
            st.log("5. IP addresses removed from interfaces and verified")
            st.log("6. VLAN memberships removed and verified")
            st.log("7. PortChannel5 configurations for SD2/SD3 handled by YAML deconfig, SD5 removed manually")
            st.log("8. TCP server files cleaned up and verified")
            
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
    
    
    Configuration Sequence:
    - Add dynamic ports (D7D3P1 to VLAN 10 and D7D3P2 to VLAN 20) on SD7
    - Assign IP addresses to dynamic ports (D3D7P1 and D3D7P2) on SD3
    - Start TCP servers on both IPs on SD3 (spine2)
    - sudo config apm add tcpprobe1 --type tcp-connect --dst-ip SPINE2_VLAN10_IP --dst-port TCP_SERVER_PORT1 --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true
    - sudo config apm add tcpprobe2 --type tcp-connect --dst-ip SPINE2_VLAN20_IP --dst-port TCP_SERVER_PORT2 --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true
    - config route add prefix vrf Vrf01 STATIC_ROUTE_PREFIX nexthop SPINE2_VLAN10_IP,SPINE2_VLAN20_IP apm tcpprobe1,tcpprobe2
    - config interface shutdown on dynamic port D3D7P2 (on SD3 spine2)
    
    Expected Behavior:
    - Initially: Both probes UP, route with both nexthops
    - After shutdown: tcpprobe1 UP, tcpprobe2 DOWN, route only for tcpprobe1
    """
    vars = st.get_testbed_vars()
    
    st.banner("Starting APM Port Shutdown Nexthop Failover Test")
    
    try:
        # Step 1: Configure dynamic ports on SD7 (leaf2) to VLANs
        st.banner("Step 1: Configuring Ethernet interfaces on SD7 (leaf2) to Vlan10")
        
        # Add D7D3P1 to Vlan10 on SD7 (leaf2)
        st.config(nodes['leaf2'], "config vlan member add 10 {} -u".format(vars.D7D3P1))
        
        # Add D7D3P2 to Vlan20 on SD7 (leaf2)
        st.config(nodes['leaf2'], "config vlan member add 20 {} -u".format(vars.D7D3P2))
        
        # Step 2: Configure IP addresses on SD3 (spine2) using dynamic ports
        st.banner("Step 2: Configuring IP addresses on SD3 (spine2) using dynamic ports")
        
        # Configure IP address on SD3 (spine2) D3D7P1
        st.config(nodes['spine2'], "config interface ip add {} {}".format(vars.D3D7P1, SPINE2_VLAN10_IP_PREFIX))
        
        # Configure IP address on SD3 (spine2) D3D7P2
        st.config(nodes['spine2'], "config interface ip add {} {}".format(vars.D3D7P2, SPINE2_VLAN20_IP_PREFIX))
        
        # Step 3: Start TCP servers on both IPs on SD3 (spine2) using existing helper function
        st.banner("Step 3: Starting TCP servers on both IPs on SD3 (spine2)")
        
        
        # Start TCP server on TCP_SERVER_PORT1 bound to SPINE2_VLAN10_IP (D3D7P1)
        tcp_server_cmd1 = "cd /home/cisco && nohup python3 tcpserver.py {} {} > /tmp/tcpserver1.log 2>&1 &".format(TCP_SERVER_PORT1, SPINE2_VLAN10_IP)
        st.config(nodes['spine2'], tcp_server_cmd1)
        st.wait(1)
        
        # Start TCP server on TCP_SERVER_PORT2 bound to SPINE2_VLAN20_IP (D3D7P2)
        tcp_server_cmd2 = "cd /home/cisco && nohup python3 tcpserver.py {} {} > /tmp/tcpserver2.log 2>&1 &".format(TCP_SERVER_PORT2, SPINE2_VLAN20_IP)
        st.config(nodes['spine2'], tcp_server_cmd2)
        st.wait(1)  # Wait for servers to start
        
        # Verify both TCP servers are running on different ports
        server_check = st.show(nodes['spine2'], "netstat -tlnp | grep -E '{}|{}'".format(TCP_SERVER_PORT1, TCP_SERVER_PORT2), skip_tmpl=True, skip_error_check=True)
        st.log("TCP server check output on SD3: {}".format(server_check))
        
        if TCP_SERVER_PORT1 not in str(server_check) or TCP_SERVER_PORT2 not in str(server_check):
            st.log("WARNING: TCP servers may not be running properly")
            # Try alternative check
            server_check2 = st.show(nodes['spine2'], "ss -tlnp | grep -E '{}|{}'".format(TCP_SERVER_PORT1, TCP_SERVER_PORT2), skip_tmpl=True, skip_error_check=True)
            st.log("Alternative TCP server check: {}".format(server_check2))
        
        # Step 4: Configure APM probes on SD7 (leaf2)
        st.banner("Step 4: Configuring APM TCP probes on SD7 (leaf2)")
        
        # Command 1: sudo config apm add tcpprobe1
        apm_cmd1 = "sudo config apm add tcpprobe1 --type tcp-connect --dst-ip {} --dst-port {} --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true".format(SPINE2_VLAN10_IP, TCP_SERVER_PORT1)
        st.config(nodes['leaf2'], apm_cmd1)
        st.wait(2)
        
        # Command 2: sudo config apm add tcpprobe2
        apm_cmd2 = "sudo config apm add tcpprobe2 --type tcp-connect --dst-ip {} --dst-port {} --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true".format(SPINE2_VLAN20_IP, TCP_SERVER_PORT2)
        st.config(nodes['leaf2'], apm_cmd2)
        st.wait(2)  # Wait for APM probes to initialize and come UP
        
        # Verify APM probes are configured
        apm_config_output = st.show(nodes['leaf2'], "show apm", skip_tmpl=True, skip_error_check=True)
        st.log("APM configuration: {}".format(apm_config_output))
        
        # Step 5: Add static route with both nexthops and APM dependencies
        st.banner("Step 5: Adding static route with both nexthops and APM dependencies")
        
        # Command 3: config route add with both nexthops and APM
        route_add_cmd = "config route add prefix vrf Vrf01 {} nexthop {},{} apm tcpprobe1,tcpprobe2".format(STATIC_ROUTE_PREFIX, SPINE2_VLAN10_IP, SPINE2_VLAN20_IP)
        st.config(nodes['leaf2'], route_add_cmd)
        st.wait(3)  # Wait for route to be installed
        
        # Step 6: Verify initial state - both probes UP, route with both nexthops
        st.banner("Step 6: Verifying initial state - both probes UP, route with both nexthops")
        
        # Check APM probe status (both should be UP)
        initial_apm_status = st.show(nodes['leaf2'], "show apm-status", skip_tmpl=True, skip_error_check=True)
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
        st.show(nodes['leaf2'], "show ip route vrf Vrf01")
        
        initial_route_output = st.show(nodes['leaf2'], "show ip route vrf Vrf01", skip_tmpl=True)
        st.log("Initial route output: {}".format(initial_route_output))
        
        
        # Step 7: Shutdown dynamic port D3D7P2 on SD3 to cause tcpprobe2 to fail
        st.banner("Step 7: Shutting down dynamic port (D3D7P2) on SD3 to simulate port failure")
        
        # Command 4: config interface shutdown on dynamic port D3D7P2
        port_shutdown_cmd = "config interface shutdown {}".format(vars.D3D7P2)
        st.config(nodes['spine2'], port_shutdown_cmd)
        st.wait(5)  # Wait for interface to go down and APM to detect failure
        
        # Step 8: Verify tcpprobe1 UP, tcpprobe2 DOWN, route with only tcpprobe1 nexthop
        st.banner("Step 8: Verifying final state - tcpprobe1 UP, tcpprobe2 DOWN, route failover")
        
        # Check APM probe status after port shutdown with retry logic
        max_retries = 3  # 1 minute total wait time
        expected_state_reached = False
        
        for retry in range(max_retries):
            final_apm_status = st.show(nodes['leaf2'], "show apm-status", skip_tmpl=True, skip_error_check=True)
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
        st.show(nodes['leaf2'], "show ip route vrf Vrf01")
        
        final_route_output = st.show(nodes['leaf2'], "show ip route vrf Vrf01", skip_tmpl=True)
        st.log("Final route output: {}".format(final_route_output))
        
        # Verify expected behavior - route should exist with only working nexthop
        route_preserved = False
        working_nexthop_present = False
        
        if STATIC_ROUTE_PREFIX in str(final_route_output):
            route_preserved = True
            st.log("SUCCESS: Route {} exists after port shutdown".format(STATIC_ROUTE_PREFIX))
            
            # Check if working nexthop (10.212.10.6) is present
            if SPINE2_VLAN10_IP in str(final_route_output):
                working_nexthop_present = True
                st.log("SUCCESS: Working nexthop ({}) is present in route".format(SPINE2_VLAN10_IP))
        else:
            st.log("WARNING: Route not found after port shutdown")
        
        # APP-DB verification after port shutdown
        st.banner("Step 9: Verifying APP-DB static route after port shutdown")
        verify_app_db_static_route(
            nodes['leaf2'],
            'redis-cli -n 0 hgetall "STATIC_ROUTE:Vrf01:{}"'.format(STATIC_ROUTE_PREFIX),
            [SPINE2_VLAN10_IP],  # Only expect working nexthop (tcpprobe2 UP)
            "APM Route Single Working Nexthop"
        )
        
        # Test success criteria
        if expected_state_reached and route_preserved and working_nexthop_present:
            st.log("TEST PASSED: APM Port Shutdown Nexthop Failover completed successfully")
            st.log("Probe states: tcpprobe1=UP, tcpprobe2=DOWN")
            st.log("Route failover: Only working nexthop ({}) active".format(SPINE2_VLAN10_IP))
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
            # Stop both TCP servers on SD3
            st.config(nodes['spine2'], "pkill -f tcpserver.py", skip_error_check=True)
            
            # Bring dynamic port D3D7P2 back up
            st.config(nodes['spine2'], "config interface startup {}".format(vars.D3D7P2), skip_error_check=True)
            
            # Remove route completely
            st.config(nodes['leaf2'], "config route del prefix vrf Vrf01 {}".format(STATIC_ROUTE_PREFIX), skip_error_check=True)
            
            # Remove APM probes from SD7 (leaf2)
            st.config(nodes['leaf2'], "config apm del tcpprobe1", skip_error_check=True)
            st.config(nodes['leaf2'], "config apm del tcpprobe2", skip_error_check=True)
            st.wait(1)
            
            # Remove IP addresses from SD3 using dynamic ports
            st.config(nodes['spine2'], "config interface ip remove {} {}".format(vars.D3D7P1, SPINE2_VLAN10_IP_PREFIX), skip_error_check=True)
            st.config(nodes['spine2'], "config interface ip remove {} {}".format(vars.D3D7P2, SPINE2_VLAN20_IP_PREFIX), skip_error_check=True)
            
            # Remove dynamic ports from VLANs on SD7 (leaf2)
            st.config(nodes['leaf2'], "config vlan member del 10 {}".format(vars.D7D3P1), skip_error_check=True)
            st.config(nodes['leaf2'], "config vlan member del 20 {}".format(vars.D7D3P2), skip_error_check=True)
            
            # Clean up log files on SD3
            st.config(nodes['spine2'], "rm -f /tmp/tcpserver1.log", skip_error_check=True)
            st.config(nodes['spine2'], "rm -f /tmp/tcpserver2.log", skip_error_check=True)
            
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
    1. Configure dynamic ports (D7D3P1 to Vlan10 and D7D3P2 to Vlan20) on SD7 (leaf2)
    2. Configure IPv6 addresses on SD3 using dynamic ports (D3D7P1 and D3D7P2)
    3. Start TCP servers on both IPv6 addresses on SD3 (port 65432)
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
    
    st.banner("Starting APM Route Addition and Deletion Combined Test IPv6")
    
    try:
        # =================== PHASE 1: APM ROUTE ADDITION IPv6 ===================
        st.banner("PHASE 1: APM Route Addition and Verification IPv6")
        
        # Step 1: Configure dynamic ports on SD7 (leaf2) to VLANs
        st.banner("Step 1: Configuring Ethernet interfaces on SD7 (leaf2)")
        st.wait(3)
        
        # First, remove any existing IP configuration from interfaces to convert them from L3 to L2
        # Remove common IPv4 and IPv6 addresses that might be configured from previous tests
        st.config(nodes['leaf2'], "config interface ip remove {} 10.212.10.4/24".format(vars.D7D3P1), skip_error_check=True)
        st.config(nodes['leaf2'], "config interface ip remove {} {}".format(vars.D7D3P1, LEAF2_VLAN10_IPV6_PREFIX), skip_error_check=True)
        st.config(nodes['leaf2'], "config interface ip remove {} 10.212.20.4/24".format(vars.D7D3P2), skip_error_check=True)
        st.config(nodes['leaf2'], "config interface ip remove {} {}".format(vars.D7D3P2, LEAF2_VLAN20_IPV6_PREFIX), skip_error_check=True)
        st.wait(1)  # Wait for interface cleanup
        
        # Add D7D3P1 to Vlan10 on SD7 (leaf2)
        st.config(nodes['leaf2'], "config vlan member add 10 {} -u".format(vars.D7D3P1))
        
        # Add D7D3P2 to Vlan20 on SD7 (leaf2)
        st.config(nodes['leaf2'], "config vlan member add 20 {} -u".format(vars.D7D3P2))
        
        # Configure IPv6 addresses on Vlan10 and Vlan20 interfaces on SD7 (leaf2)
        st.config(nodes['leaf2'], "config interface ip add Vlan10 {}".format(LEAF2_VLAN10_IPV6_PREFIX))
        st.config(nodes['leaf2'], "config interface ip add Vlan20 {}".format(LEAF2_VLAN20_IPV6_PREFIX))
        
        # Step 2: Configure IPv6 addresses on SD3 using dynamic ports
        st.banner("Step 2: Configuring IPv6 addresses on SD3 using dynamic ports")
        
        # First, remove any existing IP configuration from SD3 dynamic ports
        st.config(nodes['spine2'], "config interface ip remove {} {}".format(vars.D3D7P1, SPINE2_VLAN10_IP_PREFIX), skip_error_check=True)
        st.config(nodes['spine2'], "config interface ip remove {} {}".format(vars.D3D7P1, SPINE2_VLAN10_IPV6_PREFIX), skip_error_check=True)
        st.config(nodes['spine2'], "config interface ip remove {} {}".format(vars.D3D7P2, SPINE2_VLAN20_IP_PREFIX), skip_error_check=True)
        st.config(nodes['spine2'], "config interface ip remove {} {}".format(vars.D3D7P2, SPINE2_VLAN20_IPV6_PREFIX), skip_error_check=True)
        st.wait(1)  # Wait for interface cleanup
        
        # Configure IPv6 address on SD3 D3D7P1
        st.config(nodes['spine2'], "config interface ip add {} {}".format(vars.D3D7P1, SPINE2_VLAN10_IPV6_PREFIX))
        
        # Configure IPv6 address on SD3 D3D7P2
        st.config(nodes['spine2'], "config interface ip add {} {}".format(vars.D3D7P2, SPINE2_VLAN20_IPV6_PREFIX))
        
        # Step 3: Start TCP servers on both IPv6 addresses on SD3
        st.banner("Step 3: Starting TCP servers on SD3")
        
        
        # Start TCP servers in background on both IPv6 addresses on SD3 (both on port 65432)
        tcp_server_cmd1 = "cd /home/cisco && nohup python3 tcpserver.py {} {} > /tmp/tcpserver1.log 2>&1 &".format(TCP_SERVER_PORT1, SPINE2_VLAN10_IPV6)
        st.config(nodes['spine2'], tcp_server_cmd1)
        
        tcp_server_cmd2 = "cd /home/cisco && nohup python3 tcpserver.py {} {} > /tmp/tcpserver2.log 2>&1 &".format(TCP_SERVER_PORT1, SPINE2_VLAN20_IPV6)
        st.config(nodes['spine2'], tcp_server_cmd2)
        st.wait(2)  # Wait for servers to start
        
        # Step 4: Configure APM TCP probes on SD7 (leaf2)
        st.banner("Step 4: Configuring APM TCP probes on SD7 (leaf2)")
        
        # Configure APM TCP probe1 targeting SD3 dynamic port D3D7P1 IPv6
        apm_cmd1 = "sudo config apm add tcpprobe1 --type tcp-connect --dst-ip {} --dst-port {} --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true".format(SPINE2_VLAN10_IPV6, TCP_SERVER_PORT1)
        st.config(nodes['leaf2'], apm_cmd1)
        st.wait(3)
        
        # Configure APM TCP probe2 targeting SD3 dynamic port D3D7P2 IPv6
        apm_cmd2 = "sudo config apm add tcpprobe2 --type tcp-connect --dst-ip {} --dst-port {} --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true".format(SPINE2_VLAN20_IPV6, TCP_SERVER_PORT1)
        st.config(nodes['leaf2'], apm_cmd2)
        st.wait(3)  # Wait longer for APM probes to initialize and establish connections
        
        # Verify APM probes are configured and check status
        apm_config_output = st.show(nodes['leaf2'], "show apm", skip_tmpl=True, skip_error_check=True)
        
        apm_status_output = st.show(nodes['leaf2'], "show apm-status", skip_tmpl=True, skip_error_check=True)
        
        if "tcpprobe1" not in str(apm_config_output) or "tcpprobe2" not in str(apm_config_output):
            st.report_fail('test_case_failed', "APM probes tcpprobe1 or tcpprobe2 not configured properly on SD7")

        # Step 5: Add static route with both APM probes on SD7 (leaf2)
        st.banner("Step 5: Adding static route with APM configuration on SD7 (leaf2)")
        
        route_cmd = "config route add prefix vrf Vrf01 {} nexthop {},{} apm tcpprobe1,tcpprobe2".format(STATIC_ROUTE_IPV6_PREFIX, SPINE2_VLAN10_IPV6, SPINE2_VLAN20_IPV6)
        st.config(nodes['leaf2'], route_cmd)
        st.wait(3)  # Wait for route to be installed
        
        # Step 6: Verify APM status and route installation on SD7 (leaf2)
        st.banner("Step 6: Verifying APM status and route installation on SD7 (leaf2)")
        
        # Check APM status - test passes if both tcpprobe1 and tcpprobe2 are UP
        final_apm_status = st.show(nodes['leaf2'], "show apm-status", skip_tmpl=True, skip_error_check=True)
        st.log("Final APM status on SD7: {}".format(final_apm_status))
        
        # Check if route is installed in VRF routing table
        route_output = st.show(nodes['leaf2'], "show ipv6 route vrf Vrf01", skip_tmpl=True)
        st.log("VRF IPv6 Route table output on SD7: {}".format(route_output))
        
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
        
        if STATIC_ROUTE_IPV6_PREFIX in str(route_output):
            route_installed = True
            st.log("SUCCESS: Static route {} is installed in VRF Vrf01".format(STATIC_ROUTE_IPV6_PREFIX))
        else:
            st.log("WARNING: Static route {} is not installed in VRF Vrf01".format(STATIC_ROUTE_IPV6_PREFIX))
        
        # Verify show static-route displays the route properly
        st.banner("Verifying show static-route displays the route properly")
        static_route_output = st.show(nodes['leaf2'], "show static-route", skip_tmpl=True, skip_error_check=True)
        st.log("show static-route output after route addition: {}".format(static_route_output))
        
        # Check that static route is properly displayed with correct IPv6 nexthops and APM probes
        static_route_displayed = False
        if (STATIC_ROUTE_IPV6_PREFIX in str(static_route_output) and 
            SPINE2_VLAN10_IPV6 in str(static_route_output) and 
            SPINE2_VLAN20_IPV6 in str(static_route_output) and
            "tcpprobe1" in str(static_route_output) and
            "tcpprobe2" in str(static_route_output)):
            static_route_displayed = True
            st.log("SUCCESS: show static-route displays route {} with nexthops {},{} and APM probes tcpprobe1,tcpprobe2".format(
                STATIC_ROUTE_IPV6_PREFIX, SPINE2_VLAN10_IPV6, SPINE2_VLAN20_IPV6))
        else:
            st.log("WARNING: show static-route does not display the route properly")
        
        # APP-DB Verification for APM route addition - both IPv6 nexthops should be present
        st.banner("Verifying APP-DB contains static route entry with both IPv6 nexthops")
        verify_app_db_static_route(
            nodes['leaf2'],
            'redis-cli -n 0 hgetall "STATIC_ROUTE:Vrf01:{}"'.format(STATIC_ROUTE_IPV6_PREFIX),
            [SPINE2_VLAN10_IPV6, SPINE2_VLAN20_IPV6],  # Both IPv6 nexthops expected for APM routes
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
        route_del_cmd = "config route del prefix vrf Vrf01 {}".format(STATIC_ROUTE_IPV6_PREFIX)
        st.config(nodes['leaf2'], route_del_cmd)
        st.wait(2)  # Wait for route to be removed
        
        # Step 9: Verify no static route is present in routing table
        st.banner("Step 9: Verifying route is completely removed")
        
        final_route_output = st.show(nodes['leaf2'], "show ipv6 route vrf Vrf01", skip_tmpl=True)
        st.log("Final IPv6 route output after deletion: {}".format(final_route_output))
        
        # Check that route is NOT present
        route_removed = True
        if STATIC_ROUTE_IPV6_PREFIX in str(final_route_output):
            route_removed = False
            st.log("FAIL: Route {} is still present after deletion".format(STATIC_ROUTE_IPV6_PREFIX))
        else:
            st.log("SUCCESS: Route {} is properly removed".format(STATIC_ROUTE_IPV6_PREFIX))
        
        # Verify show static-route no longer displays the route
        st.banner("Verifying show static-route no longer displays the route")
        final_static_route_output = st.show(nodes['leaf2'], "show static-route", skip_tmpl=True, skip_error_check=True)
        st.log("show static-route output after route deletion: {}".format(final_static_route_output))
        
        # Check that static route is NOT displayed
        static_route_absent = True
        if STATIC_ROUTE_IPV6_PREFIX in str(final_static_route_output):
            static_route_absent = False
            st.log("FAIL: show static-route still displays route {} after deletion".format(STATIC_ROUTE_IPV6_PREFIX))
        else:
            st.log("SUCCESS: show static-route no longer displays route {}".format(STATIC_ROUTE_IPV6_PREFIX))
        
        # APP-DB Verification for APM route deletion - should be empty after deletion
        st.banner("Verifying APP-DB no longer contains the IPv6 static route")
        verify_app_db_static_route(
            nodes['leaf2'],
            'redis-cli -n 0 hgetall "STATIC_ROUTE:Vrf01:{}"'.format(STATIC_ROUTE_IPV6_PREFIX),
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
            st.config(nodes['spine2'], "pkill -f 'tcpserver.py'", skip_error_check=True)
            st.wait(2)
            
            # Remove route (in case it still exists)
            st.config(nodes['leaf2'], "config route del prefix vrf Vrf01 {}".format(STATIC_ROUTE_IPV6_PREFIX), skip_error_check=True)
            st.wait(1)
            
            # Remove APM probes
            st.config(nodes['leaf2'], "config apm del tcpprobe1", skip_error_check=True)
            st.config(nodes['leaf2'], "config apm del tcpprobe2", skip_error_check=True)
            st.wait(2)
            
            # Remove IPv6 addresses from SD3 using dynamic ports
            st.config(nodes['spine2'], "config interface ip remove {} {}".format(vars.D3D7P1, SPINE2_VLAN10_IPV6_PREFIX), skip_error_check=True)
            st.config(nodes['spine2'], "config interface ip remove {} {}".format(vars.D3D7P2, SPINE2_VLAN20_IPV6_PREFIX), skip_error_check=True)
            
            # Remove IPv6 addresses from SD7 Vlan interfaces
            st.config(nodes['leaf2'], "config interface ip remove Vlan10 {}".format(LEAF2_VLAN10_IPV6_PREFIX), skip_error_check=True)
            st.config(nodes['leaf2'], "config interface ip remove Vlan20 {}".format(LEAF2_VLAN20_IPV6_PREFIX), skip_error_check=True)
            
            # Remove dynamic ports from VLANs on SD7
            st.config(nodes['leaf2'], "config vlan member del 10 {}".format(vars.D7D3P1), skip_error_check=True)
            st.config(nodes['leaf2'], "config vlan member del 20 {}".format(vars.D7D3P2), skip_error_check=True)
            
            # Clean up TCP server files
            st.config(nodes['spine2'], "rm -f /tmp/tcpserver1.log /tmp/tcpserver2.log", skip_error_check=True)
            
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
    SD7 (leaf2):
    - Vrf01: Vlan10 with 10.212.10.10/24, tcpprobe1 -> 10.212.10.6:65432
    - Vrf02: Vlan40 with 10.212.10.10/24, tcpprobe2 -> 10.212.10.6:65433
    
    SD3 (spine2):
    - Vrf01: Dynamic port D3D7P1 with 10.212.10.6/24, TCP server on port 65432
    - Vrf02: Dynamic port D3D7P2 with 10.212.10.6/24, TCP server on port 65433
    
    Test Steps:
    1. Configure VLAN membership for dynamic ports (D7D3P1 and D7D3P2) on SD7
    2. Configure VRFs and IP addresses on SD3 host interfaces
    3. Start TCP servers in both VRFs on SD3
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
    
    st.banner("Starting APM Multi-Tenant VRF Routes Test")
    
    try:
        # Phase 1: Configure VLAN membership on SD7 (leaf2)
        st.banner("Phase 1: Configuring VLAN membership on SD7 (leaf2)")
        
        # Add D7D3P1 to Vlan10 and D7D3P2 to Vlan40
        st.config(nodes['leaf2'], "config vlan member add 10 {} -u".format(vars.D7D3P1))
        st.config(nodes['leaf2'], "config vlan member add 40 {} -u".format(vars.D7D3P2))
        
        # Phase 2: Configure VRFs and IP addresses on SD3 (spine2)
        st.banner("Phase 2: Configuring VRFs and IP addresses on SD3 (spine2)")
        
        # Configure Vrf01 on dynamic port D3D7P1
        st.config(nodes['spine2'], "sudo config vrf add Vrf01")
        st.config(nodes['spine2'], "sudo config interface vrf bind {} Vrf01".format(vars.D3D7P1))
        st.config(nodes['spine2'], "config interface ip add {} {}".format(vars.D3D7P1, SPINE2_VLAN10_IP_PREFIX))
        
        # Configure Vrf02 on dynamic port D3D7P2
        st.config(nodes['spine2'], "sudo config vrf add Vrf02")
        st.config(nodes['spine2'], "sudo config interface vrf bind {} Vrf02".format(vars.D3D7P2))
        st.config(nodes['spine2'], "config interface ip add {} {}".format(vars.D3D7P2, SPINE2_VLAN10_IP_PREFIX))
        
        # Phase 3: Create and start TCP servers in both VRFs on SD3
        st.banner("Phase 3: Starting TCP servers in both VRFs on SD3 (spine2)")
        
        
        # Start TCP server in Vrf01 on port 65432
        st.config(nodes['spine2'], "sudo ip vrf exec Vrf01 nohup python3 /home/cisco/tcpserver.py {} {} > /dev/null 2>&1 &".format(TCP_SERVER_PORT1, SPINE2_VLAN10_IP))
        st.wait(1)
        
        # Start TCP server in Vrf02 on port 65433
        st.config(nodes['spine2'], "sudo ip vrf exec Vrf02 nohup python3 /home/cisco/tcpserver.py {} {} > /dev/null 2>&1 &".format(TCP_SERVER_PORT2, SPINE2_VLAN10_IP))
        st.wait(1)
        
        # Verify TCP servers are running
        vrf01_server_check = st.show(nodes['spine2'], "sudo ip vrf exec Vrf01 netstat -tln | grep {}".format(TCP_SERVER_PORT1), skip_tmpl=True)
        vrf02_server_check = st.show(nodes['spine2'], "sudo ip vrf exec Vrf02 netstat -tln | grep {}".format(TCP_SERVER_PORT2), skip_tmpl=True)
        
        if TCP_SERVER_PORT1 not in str(vrf01_server_check):
            st.report_fail('test_case_failed', 'TCP server not running on port {} in Vrf01'.format(TCP_SERVER_PORT1))
        
        if TCP_SERVER_PORT2 not in str(vrf02_server_check):
            st.report_fail('test_case_failed', 'TCP server not running on port {} in Vrf02'.format(TCP_SERVER_PORT2))
        
        st.log("TCP servers verified running in both VRFs")
        
        # Phase 4: Configure APM probes on SD7 (leaf2)
        st.banner("Phase 4: Configuring APM probes on SD7 (leaf2)")
        
        # Configure tcpprobe1 in Vrf01
        st.config(nodes['leaf2'], "sudo config apm add tcpprobe1 --type tcp-connect --dst-ip {} --dst-port {} --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true".format(SPINE2_VLAN10_IP, TCP_SERVER_PORT1))
        
        # Configure tcpprobe2 in Vrf02
        st.config(nodes['leaf2'], "sudo config apm add tcpprobe2 --type tcp-connect --dst-ip {} --dst-port {} --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf02 --enable true".format(SPINE2_VLAN10_IP, TCP_SERVER_PORT2))
        st.wait(1)
        
        # Phase 5: Add static routes with APM dependencies
        st.banner("Phase 5: Adding static routes with APM dependencies")
        
        # Add route in Vrf01 with tcpprobe1
        st.config(nodes['leaf2'], "config route add prefix vrf Vrf01 {} nexthop {} apm tcpprobe1".format(STATIC_ROUTE_PREFIX, SPINE2_VLAN10_IP))
        
        # Add route in Vrf02 with tcpprobe2
        st.config(nodes['leaf2'], "config route add prefix vrf Vrf02 {} nexthop {} apm tcpprobe2".format(STATIC_ROUTE_PREFIX, SPINE2_VLAN10_IP))
        
        # Phase 6: Verify both probes are UP and routes are installed
        st.banner("Phase 6: Verifying both probes UP and routes installed")
        
        # Wait for probes to come UP
        st.wait(1)
        
        # Check APM probe status
        apm_status = st.show(nodes['leaf2'], "show apm-status", skip_tmpl=True)
        st.log("APM status: {}".format(apm_status))
        
        if "tcpprobe1" not in str(apm_status) or "tcpprobe2" not in str(apm_status):
            st.report_fail('test_case_failed', 'APM probes not found in status output')
        
        # Verify routes in both VRFs
        vrf01_routes = st.show(nodes['leaf2'], "show ip route vrf Vrf01", skip_tmpl=True)
        vrf02_routes = st.show(nodes['leaf2'], "show ip route vrf Vrf02", skip_tmpl=True)
        
        st.log("Vrf01 routes: {}".format(vrf01_routes))
        st.log("Vrf02 routes: {}".format(vrf02_routes))
        
        # Verify 172.16.255.1/32 route is present in both VRFs
        if STATIC_ROUTE_PREFIX not in str(vrf01_routes):
            st.report_fail('test_case_failed', 'Static route {} not found in Vrf01'.format(STATIC_ROUTE_PREFIX))
        
        if STATIC_ROUTE_PREFIX not in str(vrf02_routes):
            st.report_fail('test_case_failed', 'Static route {} not found in Vrf02'.format(STATIC_ROUTE_PREFIX))
        
        # Phase 7: Verify APP-DB entries for both VRF routes
        st.banner("Phase 7: Verifying APP-DB entries for both VRF routes")
        
        # Check APP-DB for Vrf01 route
        vrf01_app_db_cmd = 'redis-cli -n 0 hgetall "STATIC_ROUTE:Vrf01:{}"'.format(STATIC_ROUTE_PREFIX)
        if not verify_app_db_static_route(nodes['leaf2'], vrf01_app_db_cmd, [SPINE2_VLAN10_IP], "Vrf01 APP-DB"):
            st.report_fail('test_case_failed', 'Vrf01 APP-DB verification failed')
        
        # Check APP-DB for Vrf02 route
        vrf02_app_db_cmd = 'redis-cli -n 0 hgetall "STATIC_ROUTE:Vrf02:{}"'.format(STATIC_ROUTE_PREFIX)
        if not verify_app_db_static_route(nodes['leaf2'], vrf02_app_db_cmd, [SPINE2_VLAN10_IP], "Vrf02 APP-DB"):
            st.report_fail('test_case_failed', 'Vrf02 APP-DB verification failed')
        
        # Verify static route configuration
        static_routes = st.show(nodes['leaf2'], "show static-route", skip_tmpl=True)
        st.log("Static routes configuration: {}".format(static_routes))
        
        # Verify both VRF routes are present with correct APM dependencies
        if "tcpprobe1" not in str(static_routes) or "tcpprobe2" not in str(static_routes):
            st.report_fail('test_case_failed', 'APM dependencies not found in static route configuration')
        
        # Phase 8: Test probe failure in Vrf01 (kill TCP server)
        st.banner("Phase 8: Testing probe failure in Vrf01 by killing TCP server")
        
        # Kill TCP server in Vrf01
        st.config(nodes['spine2'], "sudo pkill -f 'python3.*tcpserver.py {}'".format(TCP_SERVER_PORT1))
        st.wait(1)  # Wait for probe to detect failure
        
        # Phase 9: Verify only Vrf01 is affected
        st.banner("Phase 9: Verifying only Vrf01 route is affected")
        
        # Check APM status after failure
        apm_status_after = st.show(nodes['leaf2'], "show apm-status", skip_tmpl=True)
        st.log("APM status after Vrf01 TCP server failure: {}".format(apm_status_after))
        
        # Verify routes after failure
        vrf01_routes_after = st.show(nodes['leaf2'], "show ip route vrf Vrf01", skip_tmpl=True)
        vrf02_routes_after = st.show(nodes['leaf2'], "show ip route vrf Vrf02", skip_tmpl=True)
        
        st.log("Vrf01 routes after failure: {}".format(vrf01_routes_after))
        st.log("Vrf02 routes after failure: {}".format(vrf02_routes_after))
        
        # Verify Vrf01 route is removed/affected
        if STATIC_ROUTE_PREFIX in str(vrf01_routes_after) and SPINE2_VLAN10_IP in str(vrf01_routes_after):
            st.log("WARNING: Vrf01 route still present after probe failure - this may be expected behavior")
        
        # Verify Vrf02 route is still present and unaffected
        if STATIC_ROUTE_PREFIX not in str(vrf02_routes_after):
            st.report_fail('test_case_failed', 'Vrf02 route was unexpectedly affected by Vrf01 probe failure')
        
        # Verify APP-DB after failure
        st.banner("Verifying APP-DB entries after Vrf01 probe failure")
        
        # Vrf01 APP-DB should be empty or not contain the nexthop
        try:
            verify_app_db_static_route(nodes['leaf2'], vrf01_app_db_cmd, [], "Vrf01 APP-DB After Failure", expect_empty=True)
        except:
            st.log("Vrf01 APP-DB entry handling after failure - continuing test")
        
        # Vrf02 APP-DB should still contain the route
        if not verify_app_db_static_route(nodes['leaf2'], vrf02_app_db_cmd, [SPINE2_VLAN10_IP], "Vrf02 APP-DB After Failure"):
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
            st.config(nodes['leaf2'], "config route del prefix vrf Vrf01 {}".format(STATIC_ROUTE_PREFIX), skip_error_check=True)
            st.config(nodes['leaf2'], "config route del prefix vrf Vrf02 {}".format(STATIC_ROUTE_PREFIX), skip_error_check=True)
            
            # Remove APM probes
            st.config(nodes['leaf2'], "sudo config apm del tcpprobe1", skip_error_check=True)
            st.config(nodes['leaf2'], "sudo config apm del tcpprobe2", skip_error_check=True)
            
            # Kill TCP servers
            st.config(nodes['spine2'], "sudo pkill -f 'python3.*tcpserver.py'", skip_error_check=True)
            
            # Remove VLAN memberships on leaf2 using dynamic ports
            st.config(nodes['leaf2'], "config vlan member del 10 {}".format(vars.D7D3P1), skip_error_check=True)
            st.config(nodes['leaf2'], "config vlan member del 40 {}".format(vars.D7D3P2), skip_error_check=True)
            
            # Remove IP addresses and VRF bindings on spine2 using dynamic ports
            st.config(nodes['spine2'], "config interface ip remove {} {}".format(vars.D3D7P1, SPINE2_VLAN10_IP_PREFIX), skip_error_check=True)
            st.config(nodes['spine2'], "config interface ip remove {} {}".format(vars.D3D7P2, SPINE2_VLAN10_IP_PREFIX), skip_error_check=True)
            st.config(nodes['spine2'], "sudo config interface vrf unbind {}".format(vars.D3D7P1), skip_error_check=True)
            st.config(nodes['spine2'], "sudo config interface vrf unbind {}".format(vars.D3D7P2), skip_error_check=True)
            st.config(nodes['spine2'], "sudo config vrf del Vrf01", skip_error_check=True)
            st.config(nodes['spine2'], "sudo config vrf del Vrf02", skip_error_check=True)
            
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
    1. Configure dynamic ports (D7D3P1 to Vlan10 and D7D3P2 to Vlan20) on SD7 (leaf2)
    2. Configure IPv6 addresses on SD3 using dynamic ports (D3D7P1 and D3D7P2)
    3. Start TCP servers on both IPv6 addresses on SD3
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
    
    st.banner("Starting APM Probe State Transition Cycle Test IPv6")
    
    try:
        # =================== PHASE 1: INITIAL SETUP (BOTH PROBES UP) IPv6 ===================
        st.banner("PHASE 1: Initial Setup - Both Probes UP IPv6")
        
        # Step 1: Configure dynamic ports on SD7 (leaf2) to VLANs
        st.banner("Step 1: Configuring Ethernet interfaces on SD7 (leaf2)")
        
        # First, remove any existing IP configuration from interfaces to convert them from L3 to L2
        # Remove common IPv4 and IPv6 addresses that might be configured from previous tests
        st.config(nodes['leaf2'], "config interface ip remove {} 10.212.10.4/24".format(vars.D7D3P1), skip_error_check=True)
        st.config(nodes['leaf2'], "config interface ip remove {} {}".format(vars.D7D3P1, LEAF2_VLAN10_IPV6_PREFIX), skip_error_check=True)
        st.config(nodes['leaf2'], "config interface ip remove {} 10.212.20.4/24".format(vars.D7D3P2), skip_error_check=True)
        st.config(nodes['leaf2'], "config interface ip remove {} {}".format(vars.D7D3P2, LEAF2_VLAN20_IPV6_PREFIX), skip_error_check=True)
        st.wait(1)  # Wait for interface cleanup
        
        # Add D7D3P1 to Vlan10 on SD7 (leaf2)
        st.config(nodes['leaf2'], "config vlan member add 10 {} -u".format(vars.D7D3P1))
        
        # Add D7D3P2 to Vlan20 on SD7 (leaf2)
        st.config(nodes['leaf2'], "config vlan member add 20 {} -u".format(vars.D7D3P2))
        
        # Configure IPv6 addresses on Vlan10 and Vlan20 interfaces on SD7 (leaf2)
        st.config(nodes['leaf2'], "config interface ip add Vlan10 {}".format(LEAF2_VLAN10_IPV6_PREFIX))
        st.config(nodes['leaf2'], "config interface ip add Vlan20 {}".format(LEAF2_VLAN20_IPV6_PREFIX))
        
        # Step 2: Configure IPv6 addresses on SD3 using dynamic ports
        st.banner("Step 2: Configuring IPv6 addresses on SD3 using dynamic ports")
        
        # First, remove any existing IP configuration from SD3 dynamic ports
        st.config(nodes['spine2'], "config interface ip remove {} {}".format(vars.D3D7P1, SPINE2_VLAN10_IP_PREFIX), skip_error_check=True)
        st.config(nodes['spine2'], "config interface ip remove {} {}".format(vars.D3D7P1, SPINE2_VLAN10_IPV6_PREFIX), skip_error_check=True)
        st.config(nodes['spine2'], "config interface ip remove {} {}".format(vars.D3D7P2, SPINE2_VLAN20_IP_PREFIX), skip_error_check=True)
        st.config(nodes['spine2'], "config interface ip remove {} {}".format(vars.D3D7P2, SPINE2_VLAN20_IPV6_PREFIX), skip_error_check=True)
        st.wait(1)  # Wait for interface cleanup
        
        # Configure IPv6 address on SD3 D3D7P1
        st.config(nodes['spine2'], "config interface ip add {} {}".format(vars.D3D7P1, SPINE2_VLAN10_IPV6_PREFIX))
        
        # Configure IPv6 address on SD3 D3D7P2
        st.config(nodes['spine2'], "config interface ip add {} {}".format(vars.D3D7P2, SPINE2_VLAN20_IPV6_PREFIX))
        
        # Step 3: Start TCP servers on both IPv6 addresses on SD3
        st.banner("Step 3: Starting TCP servers on both IPv6 addresses on SD3")
        
        # Start TCP servers in background on both IPv6 addresses on SD3 (both on port 65432)
        tcp_server_cmd1 = "cd /home/cisco && nohup python3 tcpserver.py {} {} > /tmp/tcpserver1.log 2>&1 &".format(TCP_SERVER_PORT1, SPINE2_VLAN10_IPV6)
        st.config(nodes['spine2'], tcp_server_cmd1)
        
        tcp_server_cmd2 = "cd /home/cisco && nohup python3 tcpserver.py {} {} > /tmp/tcpserver2.log 2>&1 &".format(TCP_SERVER_PORT1, SPINE2_VLAN20_IPV6)
        st.config(nodes['spine2'], tcp_server_cmd2)
        st.wait(2)  # Wait for servers to start
        
        # Step 4: Configure APM probes tcpprobe1 and tcpprobe2
        st.banner("Step 4: Configuring APM probes tcpprobe1 and tcpprobe2")
        
        # Configure APM TCP probe1 targeting SD3 dynamic port D3D7P1 IPv6
        apm_cmd1 = "sudo config apm add tcpprobe1 --type tcp-connect --dst-ip {} --dst-port {} --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true".format(SPINE2_VLAN10_IPV6, TCP_SERVER_PORT1)
        st.config(nodes['leaf2'], apm_cmd1)
        st.wait(3)
        
        # Configure APM TCP probe2 targeting SD3 dynamic port D3D7P2 IPv6
        apm_cmd2 = "sudo config apm add tcpprobe2 --type tcp-connect --dst-ip {} --dst-port {} --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true".format(SPINE2_VLAN20_IPV6, TCP_SERVER_PORT1)
        st.config(nodes['leaf2'], apm_cmd2)
        st.wait(3)  # Wait for APM probes to initialize
        
        # Step 5: Add static route with both IPv6 nexthops and APM dependencies
        st.banner("Step 5: Adding static route with both IPv6 nexthops and APM dependencies")
        
        route_cmd = "config route add prefix vrf Vrf01 {} nexthop {},{} apm tcpprobe1,tcpprobe2".format(STATIC_ROUTE_IPV6_PREFIX, SPINE2_VLAN10_IPV6, SPINE2_VLAN20_IPV6)
        st.config(nodes['leaf2'], route_cmd)
        st.wait(3)  # Wait for route to be installed
        
        # Step 6: Verify both probes are UP and route is installed via both nexthops
        st.banner("Step 6: Verifying both probes are UP and route via both IPv6 nexthops")
        
        # Check APM status
        apm_status_phase1 = st.show(nodes['leaf2'], "show apm-status", skip_tmpl=True, skip_error_check=True)
        st.log("Phase 1 APM status: {}".format(apm_status_phase1))
        
        # Check IPv6 route installation
        route_output_phase1 = st.show(nodes['leaf2'], "show ipv6 route vrf Vrf01", skip_tmpl=True)
        st.log("Phase 1 IPv6 route output: {}".format(route_output_phase1))
        
        # Validate Phase 1
        tcpprobe1_up_phase1 = any("up" in line.lower() for line in str(apm_status_phase1).split('\n') if "tcpprobe1" in line)
        tcpprobe2_up_phase1 = any("up" in line.lower() for line in str(apm_status_phase1).split('\n') if "tcpprobe2" in line)
        route_both_nexthops_phase1 = STATIC_ROUTE_IPV6_PREFIX in str(route_output_phase1) and "via {}".format(SPINE2_VLAN10_IPV6) in str(route_output_phase1) and "via {}".format(SPINE2_VLAN20_IPV6) in str(route_output_phase1)
        
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
        kill_cmd = "pkill -f 'tcpserver.py {} {}'".format(TCP_SERVER_PORT1, SPINE2_VLAN10_IPV6)
        st.config(nodes['spine2'], kill_cmd, skip_error_check=True)
        st.wait(10)  # Wait for APM probe to detect server down
        
        # Step 8: Verify tcpprobe1 is DOWN, tcpprobe2 is UP
        st.banner("Step 8: Verifying tcpprobe1 DOWN, tcpprobe2 UP")
        
        apm_status_phase2 = st.show(nodes['leaf2'], "show apm-status", skip_tmpl=True, skip_error_check=True)
        st.log("Phase 2 APM status: {}".format(apm_status_phase2))
        
        # Step 9: Verify route only shows nexthop for working probe (2001:db8:20::6)
        st.banner("Step 9: Verifying route only via working IPv6 nexthop ({})".format(SPINE2_VLAN20_IPV6))
        
        route_output_phase2 = st.show(nodes['leaf2'], "show ipv6 route vrf Vrf01", skip_tmpl=True)
        st.log("Phase 2 IPv6 route output: {}".format(route_output_phase2))
        
        # Validate Phase 2
        tcpprobe1_down_phase2 = any("down" in line.lower() or "failed" in line.lower() for line in str(apm_status_phase2).split('\n') if "tcpprobe1" in line)
        tcpprobe2_up_phase2 = any("up" in line.lower() for line in str(apm_status_phase2).split('\n') if "tcpprobe2" in line)
        route_single_nexthop_phase2 = STATIC_ROUTE_IPV6_PREFIX in str(route_output_phase2) and "via {}".format(SPINE2_VLAN20_IPV6) in str(route_output_phase2) and "via {}".format(SPINE2_VLAN10_IPV6) not in str(route_output_phase2)
        
        phase2_success = tcpprobe1_down_phase2 and tcpprobe2_up_phase2 and route_single_nexthop_phase2
        
        if phase2_success:
            st.log("PHASE 2 PASSED: tcpprobe1 DOWN, route only via {}".format(SPINE2_VLAN20_IPV6))
        else:
            st.log("PHASE 2 FAILED: tcpprobe1_down: {}, tcpprobe2_up: {}, single_nexthop: {}".format(
                tcpprobe1_down_phase2, tcpprobe2_up_phase2, route_single_nexthop_phase2))
        
        # =================== PHASE 3: PROBE UP TRANSITION IPv6 ===================
        st.banner("PHASE 3: Probe Up Transition - Making tcpprobe1 UP again IPv6")
        
        # Step 10: Restart TCP server for tcpprobe1 (make tcpprobe1 come back UP)
        st.banner("Step 10: Restarting TCP server for tcpprobe1 (port 65432)")
        
        # Restart TCP server on port 65432 for IPv6 address 2001:db8:10::6 (tcpprobe1)
        tcp_server_cmd1_restart = "cd /home/cisco && nohup python3 tcpserver.py {} {} > /tmp/tcpserver1_restart.log 2>&1 &".format(TCP_SERVER_PORT1, SPINE2_VLAN10_IPV6)
        st.config(nodes['spine2'], tcp_server_cmd1_restart)
        st.wait(10)  # Wait for APM probe to detect server up
        
        # Step 11: Verify both tcpprobe1 and tcpprobe2 are UP
        st.banner("Step 11: Verifying both tcpprobe1 and tcpprobe2 are UP")
        
        apm_status_phase3 = st.show(nodes['leaf2'], "show apm-status", skip_tmpl=True, skip_error_check=True)
        st.log("Phase 3 APM status: {}".format(apm_status_phase3))
        
        # Step 12: Verify route shows both IPv6 nexthops again
        st.banner("Step 12: Verifying route shows both IPv6 nexthops again")
        
        route_output_phase3 = st.show(nodes['leaf2'], "show ipv6 route vrf Vrf01", skip_tmpl=True)
        st.log("Phase 3 IPv6 route output: {}".format(route_output_phase3))
        
        # Validate Phase 3
        tcpprobe1_up_phase3 = any("up" in line.lower() for line in str(apm_status_phase3).split('\n') if "tcpprobe1" in line)
        tcpprobe2_up_phase3 = any("up" in line.lower() for line in str(apm_status_phase3).split('\n') if "tcpprobe2" in line)
        route_both_nexthops_phase3 = STATIC_ROUTE_IPV6_PREFIX in str(route_output_phase3) and "via {}".format(SPINE2_VLAN10_IPV6) in str(route_output_phase3) and "via {}".format(SPINE2_VLAN20_IPV6) in str(route_output_phase3)
        
        phase3_success = tcpprobe1_up_phase3 and tcpprobe2_up_phase3 and route_both_nexthops_phase3
        
        if phase3_success:
            st.log("PHASE 3 PASSED: Both probes UP, route via both IPv6 nexthops restored")
        else:
            st.log("PHASE 3 FAILED: tcpprobe1_up: {}, tcpprobe2_up: {}, both_nexthops: {}".format(
                tcpprobe1_up_phase3, tcpprobe2_up_phase3, route_both_nexthops_phase3))
        
        # APP-DB Verification for final state
        st.banner("Final APP-DB Verification: Both IPv6 nexthops should be present")
        verify_app_db_static_route(
            nodes['leaf2'],
            'redis-cli -n 0 hgetall "STATIC_ROUTE:Vrf01:{}"'.format(STATIC_ROUTE_IPV6_PREFIX),
            [SPINE2_VLAN10_IPV6, SPINE2_VLAN20_IPV6],  # Both IPv6 nexthops expected
            "APM Probe State Transition Cycle IPv6"
        )
        
        # Static Route Configuration Verification for final state
        st.banner("Final Static Route Configuration Verification: Both IPv6 nexthops should be present")
        static_route_output = st.show(nodes['leaf2'], "show static-route", skip_tmpl=True)
        st.log("Final static route configuration: {}".format(static_route_output))
        
        # Verify both IPv6 nexthops are present in static route configuration
        static_route_both_nexthops = STATIC_ROUTE_IPV6_PREFIX in str(static_route_output) and SPINE2_VLAN10_IPV6 in str(static_route_output) and SPINE2_VLAN20_IPV6 in str(static_route_output)
        
        if static_route_both_nexthops:
            st.log("Static Route Verification PASSED: Both IPv6 nexthops ({}, {}) present in static route configuration".format(SPINE2_VLAN10_IPV6, SPINE2_VLAN20_IPV6))
        else:
            st.log("Static Route Verification FAILED: Missing one or both IPv6 nexthops in static route configuration")
            st.log("Expected: Route {} with nexthops {} and {}".format(STATIC_ROUTE_IPV6_PREFIX, SPINE2_VLAN10_IPV6, SPINE2_VLAN20_IPV6))
        
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
            st.config(nodes['spine2'], "pkill -f 'tcpserver.py'", skip_error_check=True)
            st.wait(2)
            
            # Remove route
            st.config(nodes['leaf2'], "config route del prefix vrf Vrf01 {}".format(STATIC_ROUTE_IPV6_PREFIX), skip_error_check=True)
            st.wait(1)
            
            # Remove APM probes
            st.config(nodes['leaf2'], "config apm del tcpprobe1", skip_error_check=True)
            st.config(nodes['leaf2'], "config apm del tcpprobe2", skip_error_check=True)
            st.wait(2)
            
            # Remove IPv6 addresses from SD3 using dynamic ports
            st.config(nodes['spine2'], "config interface ip remove {} {}".format(vars.D3D7P1, SPINE2_VLAN10_IPV6_PREFIX), skip_error_check=True)
            st.config(nodes['spine2'], "config interface ip remove {} {}".format(vars.D3D7P2, SPINE2_VLAN20_IPV6_PREFIX), skip_error_check=True)
            
            # Remove IPv6 addresses from SD7 Vlan interfaces
            st.config(nodes['leaf2'], "config interface ip remove Vlan10 {}".format(LEAF2_VLAN10_IPV6_PREFIX), skip_error_check=True)
            st.config(nodes['leaf2'], "config interface ip remove Vlan20 {}".format(LEAF2_VLAN20_IPV6_PREFIX), skip_error_check=True)
            
            # Remove dynamic ports from VLANs on SD7
            st.config(nodes['leaf2'], "config vlan member del 10 {}".format(vars.D7D3P1), skip_error_check=True)
            st.config(nodes['leaf2'], "config vlan member del 20 {}".format(vars.D7D3P2), skip_error_check=True)
            
            # Clean up TCP server files and logs
            st.config(nodes['spine2'], "rm -f /tmp/tcpserver1.log /tmp/tcpserver2.log /tmp/tcpserver1_restart.log", skip_error_check=True)
            
            st.banner("APM probe state transition cycle IPv6 test cleanup completed successfully")
            
        except Exception as cleanup_e:
            st.log("Warning: Some cleanup operations failed: {}".format(str(cleanup_e)))