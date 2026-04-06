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
import vxlan_utils as vxlan_obj
import time
import evpn_mh_utils as evpn_mh_obj
import pdb

ESI1 = '03:00:44:33:22:11:00:00:00:02'
EXPECTED_L3VNI = '5030'
EXPECTED_L2VNI = '5010'
##  Topology : 4x Spine + 4 Leafs
##  SD1 -- Spine0  - D1
##  SD2 -- Spine1  - D2
##  SD3 -- Spine2  - D3
##  SD4 -- Spine3  - D4
##  SD5 -- Leaf0   - D5
##  SD6 -- Leaf1   - D6
##  SD7 -- Leaf2   - D7
##  SD8 -- Leaf3   - D8

data = SpyTestDict()
data.config_vrfs = []
CONFIGS_FILE = '../solution/static_route_apm_evpn_mh_v6_config_sol.yaml'

# Global nodes dictionary
nodes = {}

# Global IP Address Variables for APM Basic Tests
SPINE2_VLAN10_IP = "10.212.10.6"
SPINE2_VLAN10_IP_PREFIX = "10.212.10.6/24"
SPINE2_VLAN20_IP = "10.212.20.6"
SPINE2_VLAN20_IP_PREFIX = "10.212.20.6/24"
STATIC_ROUTE_PREFIX = "172.16.255.1/32"
TCP_SERVER_PORT1 = "65432"
TCP_SERVER_PORT2 = "65433"

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
# Test APM Route with Distance and Tag Values
######################################################################
@pytest.mark.system_box
@pytest.mark.community
@pytest.mark.community_pass
def test_apm_route_distance_tag_values():
    """
    Test APM route configuration with distance and tag values
    
    Test Scenario:
    Configure APM probes and static route with distance and tag values, then verify
    the route is properly installed in APP-DB and FRR with correct distance and tag values.
    
    Test Steps:
    1. Configure dynamic ports (D7D3P1 to Vlan10 and D7D3P2 to Vlan20) on SD7 (leaf2)
    2. Configure IP addresses on SD3 (spine2) using dynamic ports (D3D7P1 and D3D7P2)
    3. Start TCP servers on both IPs on SD3 (spine2)
    4. Configure APM TCP probes (tcpprobe1 and tcpprobe2) with VRF Vrf01
    5. Add static route with both nexthops, APM dependencies, distance, and tag values
    6. Verify both APM probes are UP and route is installed in FRR
    7. Verify APP-DB contains static route entry with both nexthops
    8. Verify FRR running config shows routes with correct distance and tag values
    9. Cleanup all configurations
    
    Configuration Sequence:
    - Add dynamic ports (D7D3P1 to VLAN 10 and D7D3P2 to VLAN 20) on SD7 (leaf2)
    - Assign IP addresses to dynamic ports (D3D7P1 and D3D7P2) on SD3 (spine2)
    - Start TCP servers on both IPs on SD3 (spine2, ports 65432 and 65433)
    - sudo config apm add tcpprobe1 --type tcp-connect --dst-ip 10.212.10.6 --dst-port 65432 --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true
    - sudo config apm add tcpprobe2 --type tcp-connect --dst-ip 10.212.20.6 --dst-port 65433 --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true
    - config route add prefix vrf Vrf01 172.16.255.1/32 nexthop 10.212.10.6,10.212.20.6 apm tcpprobe1,tcpprobe2 distance 10,20 tag 3,4
    
    Expected Behavior:
    - Both APM probes UP
    - Route installed with both nexthops in FRR
    - APP-DB contains route entry with both nexthops
    - FRR config shows: ip route 172.16.255.1/32 10.212.10.6 tag 3 10
    - FRR config shows: ip route 172.16.255.1/32 10.212.20.6 tag 4 20
    """
    vars = st.get_testbed_vars()
    
    st.banner("Starting APM Route with Distance and Tag Values Test")
    
    try:
        # Step 1: Configure dynamic ports on SD7 (leaf2) to VLANs
        st.banner("Step 1: Configuring Ethernet interfaces on SD7 (leaf2)")
        st.wait(3)
        
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
        st.banner("Step 3: Starting TCP servers on SD3 (spine2)")
        
        # Start TCP servers in background on both IPs on SD3 (spine2)
        tcp_server_cmd1 = "cd /home/cisco && nohup python3 tcpserver.py {} {} > /tmp/tcpserver1.log 2>&1 &".format(TCP_SERVER_PORT1, SPINE2_VLAN10_IP)
        st.config(nodes['spine2'], tcp_server_cmd1)
        
        tcp_server_cmd2 = "cd /home/cisco && nohup python3 tcpserver.py {} {} > /tmp/tcpserver2.log 2>&1 &".format(TCP_SERVER_PORT2, SPINE2_VLAN20_IP)
        st.config(nodes['spine2'], tcp_server_cmd2)
        st.wait(2)  # Wait for servers to start
        
        # Step 4: Configure APM TCP probes on SD7 (leaf2)
        st.banner("Step 4: Configuring APM TCP probes on SD7 (leaf2)")
        
        # Configure APM TCP probe1 targeting SD3 (spine2) dynamic port D3D7P1
        apm_cmd1 = "sudo config apm add tcpprobe1 --type tcp-connect --dst-ip {} --dst-port {} --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true".format(SPINE2_VLAN10_IP, TCP_SERVER_PORT1)
        st.config(nodes['leaf2'], apm_cmd1)
        st.wait(3)
        
        # Configure APM TCP probe2 targeting SD3 (spine2) dynamic port D3D7P2
        apm_cmd2 = "sudo config apm add tcpprobe2 --type tcp-connect --dst-ip {} --dst-port {} --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true".format(SPINE2_VLAN20_IP, TCP_SERVER_PORT2)
        st.config(nodes['leaf2'], apm_cmd2)
        st.wait(3)  # Wait longer for APM probes to initialize and establish connections
        
        # Step 5: Adding static route with nexthops, APM, distance, and tag values
        st.banner("Step 5: Adding static route with nexthops, APM, distance, and tag values")
        
        # Command: config route add with nexthops, APM, distance, and tag values
        route_add_cmd = "config route add prefix vrf Vrf01 {} nexthop {},{} apm tcpprobe1,tcpprobe2 distance 10,20 tag 3,4".format(STATIC_ROUTE_PREFIX, SPINE2_VLAN10_IP, SPINE2_VLAN20_IP)
        st.config(nodes['leaf2'], route_add_cmd)
        st.wait(2)  # Wait for route to be installed
        
        # Step 6: Verify both APM probes are UP and route is installed
        st.banner("Step 6: Verifying APM probe states and route installation")
        
        # Check APM probe status - both should be UP
        apm_status = st.show(nodes['leaf2'], "show apm-status", skip_tmpl=True, skip_error_check=True)
        st.log("APM status output: {}".format(apm_status))
        
        # Verify specific probe states
        tcpprobe1_up = False
        tcpprobe2_up = False
        
        if "tcpprobe1" in str(apm_status):
            apm_lines = str(apm_status).split('\n')
            for line in apm_lines:
                if "tcpprobe1" in line and ("UP" in line or "up" in line.lower()):
                    tcpprobe1_up = True
                    st.log("SUCCESS: tcpprobe1 is UP")
                    break
        
        if "tcpprobe2" in str(apm_status):
            apm_lines = str(apm_status).split('\n')
            for line in apm_lines:
                if "tcpprobe2" in line and ("UP" in line or "up" in line.lower()):
                    tcpprobe2_up = True
                    st.log("SUCCESS: tcpprobe2 is UP")
                    break
        
        if not (tcpprobe1_up and tcpprobe2_up):
            st.log("WARNING: One or both APM probes are not UP")
        
        # Check route installation in FRR
        route_output = st.show(nodes['leaf2'], "show ip route vrf Vrf01", skip_tmpl=True)
        st.log("Route table output: {}".format(route_output))
        
        route_present = STATIC_ROUTE_PREFIX in str(route_output)
        nexthop1_present = SPINE2_VLAN10_IP in str(route_output)
        nexthop2_present = SPINE2_VLAN20_IP in str(route_output)
        
        if route_present:
            st.log("SUCCESS: Route {} is present in routing table".format(STATIC_ROUTE_PREFIX))
        if nexthop1_present:
            st.log("SUCCESS: Nexthop {} is present".format(SPINE2_VLAN10_IP))
        if nexthop2_present:
            st.log("SUCCESS: Nexthop {} is present".format(SPINE2_VLAN20_IP))
        
        # Step 7: Verify APP-DB contains static route entry with both nexthops
        st.banner("Step 7: Verifying APP-DB static route entry")
        verify_app_db_static_route(
            nodes['leaf2'],
            'redis-cli -n 0 hgetall "STATIC_ROUTE:Vrf01:{}"'.format(STATIC_ROUTE_PREFIX),
            [SPINE2_VLAN10_IP, SPINE2_VLAN20_IP],  # Expected nexthops
            "APM Route with Distance and Tag"
        )
        
        # Step 8: Verify FRR running config shows routes with correct distance and tag values
        st.banner("Step 8: Verifying FRR running config with distance and tag values")
        
        # Get FRR running configuration
        frr_config_cmd = 'sudo vtysh -c "show running-config"'
        frr_config = st.show(nodes['leaf2'], frr_config_cmd, skip_tmpl=True, skip_error_check=True)
        st.log("FRR running config: {}".format(frr_config))
        
        # Expected FRR entries:
        # ip route 172.16.255.1/32 10.212.10.6 tag 3 10
        # ip route 172.16.255.1/32 10.212.20.6 tag 4 20
        expected_route1 = "ip route {} {} tag 3 10".format(STATIC_ROUTE_PREFIX, SPINE2_VLAN10_IP)
        expected_route2 = "ip route {} {} tag 4 20".format(STATIC_ROUTE_PREFIX, SPINE2_VLAN20_IP)
        
        route1_found = expected_route1 in str(frr_config)
        route2_found = expected_route2 in str(frr_config)
        
        if route1_found:
            st.log("SUCCESS: Found expected FRR route entry: {}".format(expected_route1))
        else:
            st.log("WARNING: Expected FRR route entry not found: {}".format(expected_route1))
        
        if route2_found:
            st.log("SUCCESS: Found expected FRR route entry: {}".format(expected_route2))
        else:
            st.log("WARNING: Expected FRR route entry not found: {}".format(expected_route2))
        

        # Test success criteria
        test_success = (tcpprobe1_up and tcpprobe2_up and 
                       route_present and nexthop1_present and nexthop2_present and
                       route1_found and route2_found)
        
        if test_success:
            st.log("TEST PASSED: APM Route with Distance and Tag Values completed successfully")
            st.log("- Both APM probes are UP")
            st.log("- Route present with both nexthops")
            st.log("- FRR config shows correct distance and tag values")
            st.banner("APM Route with Distance and Tag Values Test - PASSED")
            st.report_pass('test_case_passed')
        else:
            st.log("TEST FAILED: One or more verification criteria not met")
            failure_reasons = []
            if not (tcpprobe1_up and tcpprobe2_up):
                failure_reasons.append("APM probes not UP")
            if not (route_present and nexthop1_present and nexthop2_present):
                failure_reasons.append("Route or nexthops missing")
            if not (route1_found and route2_found):
                failure_reasons.append("FRR config entries missing or incorrect")
            st.report_fail('test_case_failed', "Test failed: {}".format(", ".join(failure_reasons)))

    except Exception as e:
        st.log("Exception occurred during test execution: {}".format(str(e)))
        st.report_fail('test_case_failed', "Test failed with exception: {}".format(str(e)))
        
    finally:
        # Cleanup configurations
        st.banner("Cleanup: Removing all test configurations")
        
        try:
            # Stop TCP servers on SD3
            st.config(nodes['spine2'], "pkill -f tcpserver.py", skip_error_check=True)
            st.wait(1)
            
            # Remove route completely
            st.config(nodes['leaf2'], "config route del prefix vrf Vrf01 {}".format(STATIC_ROUTE_PREFIX), skip_error_check=True)
            st.wait(2)
            
            # Remove APM probes from SD7 (leaf2)
            st.config(nodes['leaf2'], "config apm del tcpprobe1", skip_error_check=True)
            st.config(nodes['leaf2'], "config apm del tcpprobe2", skip_error_check=True)
            st.wait(1)
            
            # Remove IP addresses from SD3 (spine2) using dynamic ports
            st.config(nodes['spine2'], "config interface ip remove {} {}".format(vars.D3D7P1, SPINE2_VLAN10_IP_PREFIX), skip_error_check=True)
            st.config(nodes['spine2'], "config interface ip remove {} {}".format(vars.D3D7P2, SPINE2_VLAN20_IP_PREFIX), skip_error_check=True)
            
            # Remove dynamic ports from VLANs on SD7 (leaf2)
            st.config(nodes['leaf2'], "config vlan member del 10 {}".format(vars.D7D3P1), skip_error_check=True)
            st.config(nodes['leaf2'], "config vlan member del 20 {}".format(vars.D7D3P2), skip_error_check=True)
            
            # Clean up log files and TCP server file on SD3
            st.config(nodes['spine2'], "rm -f /tmp/tcpserver1.log", skip_error_check=True)
            st.config(nodes['spine2'], "rm -f /tmp/tcpserver2.log", skip_error_check=True)
            
            st.log("Cleanup completed successfully")
            
        except Exception as cleanup_e:
            st.log("Warning: Some cleanup operations failed: {}".format(str(cleanup_e)))
    
    st.report_pass("test_case_passed", "APM Route with Distance and Tag Values Test")


######################################################################
# Test APM Route Update with Distance and Tag Values
######################################################################
@pytest.mark.system_box
@pytest.mark.community
@pytest.mark.community_pass
def test_apm_route_update_distance_tag():
    """
    Test APM route configuration followed by separate distance and tag value updates
    
    Test Scenario:
    Configure APM probes and static route with APM dependencies first, then update the route
    separately with distance and tag values, verifying the route is properly updated in 
    APP-DB and FRR with correct distance and tag values.
    
    Test Steps:
    1. Configure dynamic ports (D7D3P1 to Vlan10 and D7D3P2 to Vlan20) on SD7 (leaf2)
    2. Configure IP addresses on SD3 (spine2) using dynamic ports (D3D7P1 and D3D7P2)
    3. Start TCP servers on both IPs on SD3 (spine2)
    4. Configure APM TCP probes (tcpprobe1 and tcpprobe2) with VRF Vrf01
    5. Add static route with both nexthops and APM dependencies (no distance/tag initially)
    6. Update route with distance values separately
    7. Update route with tag values separately
    8. Verify both APM probes are UP and route is installed in FRR
    9. Verify APP-DB contains static route entry with both nexthops
    10. Verify FRR running config shows routes with correct distance and tag values
    11. Cleanup all configurations
    
    Configuration Sequence:
    - Add dynamic ports (D7D3P1 to VLAN 10 and D7D3P2 to VLAN 20) on SD7 (leaf2)
    - Assign IP addresses to dynamic ports (D3D7P1 and D3D7P2) on SD3 (spine2)
    - Start TCP servers on both IPs on SD3 (spine2, ports 65432 and 65433)
    - sudo config apm add tcpprobe1 --type tcp-connect --dst-ip 10.212.10.6 --dst-port 65432 --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true
    - sudo config apm add tcpprobe2 --type tcp-connect --dst-ip 10.212.20.6 --dst-port 65433 --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true
    - config route add prefix vrf Vrf01 172.16.255.1/32 nexthop 10.212.10.6,10.212.20.6 apm tcpprobe1,tcpprobe2
    - config route add prefix vrf Vrf01 172.16.255.1/32 distance 10,20
    - config route add prefix vrf Vrf01 172.16.255.1/32 tag 3,4
    
    Expected Behavior:
    - Both APM probes UP
    - Route installed with both nexthops in FRR
    - APP-DB contains route entry with both nexthops
    - FRR config shows: ip route 172.16.255.1/32 10.212.10.6 tag 3 10
    - FRR config shows: ip route 172.16.255.1/32 10.212.20.6 tag 4 20
    """
    vars = st.get_testbed_vars()
    
    st.banner("Starting APM Route Update with Distance and Tag Values Test")
    
    try:
        # Step 1: Configure dynamic ports on SD7 (leaf2) to VLANs
        st.banner("Step 1: Configuring Ethernet interfaces on SD7 (leaf2)")
        st.wait(3)
        
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
        st.banner("Step 3: Starting TCP servers on SD3 (spine2)")
        
        # Start TCP servers in background on both IPs on SD3 (spine2)
        tcp_server_cmd1 = "cd /home/cisco && nohup python3 tcpserver.py {} {} > /tmp/tcpserver1.log 2>&1 &".format(TCP_SERVER_PORT1, SPINE2_VLAN10_IP)
        st.config(nodes['spine2'], tcp_server_cmd1)
        
        tcp_server_cmd2 = "cd /home/cisco && nohup python3 tcpserver.py {} {} > /tmp/tcpserver2.log 2>&1 &".format(TCP_SERVER_PORT2, SPINE2_VLAN20_IP)
        st.config(nodes['spine2'], tcp_server_cmd2)
        st.wait(2)  # Wait for servers to start
        
        # Step 4: Configure APM TCP probes on SD7 (leaf2)
        st.banner("Step 4: Configuring APM TCP probes on SD7 (leaf2)")
        
        # Configure APM TCP probe1 targeting SD3 (spine2) dynamic port D3D7P1
        apm_cmd1 = "sudo config apm add tcpprobe1 --type tcp-connect --dst-ip {} --dst-port {} --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true".format(SPINE2_VLAN10_IP, TCP_SERVER_PORT1)
        st.config(nodes['leaf2'], apm_cmd1)
        st.wait(3)
        
        # Configure APM TCP probe2 targeting SD3 (spine2) dynamic port D3D7P2
        apm_cmd2 = "sudo config apm add tcpprobe2 --type tcp-connect --dst-ip {} --dst-port {} --frequency 1000 --timeout 500 --multiplier 3 --vrf Vrf01 --enable true".format(SPINE2_VLAN20_IP, TCP_SERVER_PORT2)
        st.config(nodes['leaf2'], apm_cmd2)
        st.wait(3)  # Wait for APM probes to initialize and come UP
        
        # Step 5: Add static route with both nexthops and APM dependencies (no distance/tag initially)
        st.banner("Step 5: Adding initial static route with nexthops and APM dependencies")
        
        # Command: config route add with nexthops and APM (no distance/tag yet)
        route_add_cmd = "config route add prefix vrf Vrf01 {} nexthop {},{} apm tcpprobe1,tcpprobe2".format(STATIC_ROUTE_PREFIX, SPINE2_VLAN10_IP, SPINE2_VLAN20_IP)
        st.config(nodes['leaf2'], route_add_cmd)
        
        # Verify initial route installation
        initial_route_output = st.show(nodes['leaf2'], "show ip route vrf Vrf01", skip_tmpl=True)
        st.log("Initial route output (before distance/tag): {}".format(initial_route_output))
        
        # Step 6: Update route with distance values separately
        st.banner("Step 6: Updating route with distance values")
        
        # Command: config route add with distance values only
        route_distance_cmd = "config route add prefix vrf Vrf01 {} distance 10,20".format(STATIC_ROUTE_PREFIX)
        st.config(nodes['leaf2'], route_distance_cmd)
        
        # Verify route after distance update
        distance_route_output = st.show(nodes['leaf2'], "show ip route vrf Vrf01", skip_tmpl=True)
        st.log("Route output after distance update: {}".format(distance_route_output))
        
        # Step 7: Update route with tag values separately
        st.banner("Step 7: Updating route with tag values")
        
        # Command: config route add with tag values only
        route_tag_cmd = "config route add prefix vrf Vrf01 {} tag 3,4".format(STATIC_ROUTE_PREFIX)
        st.config(nodes['leaf2'], route_tag_cmd)
        st.wait(1)  # Wait for route to be updated
        
        # Step 8: Verify both APM probes are UP and route is installed
        st.banner("Step 8: Verifying APM probe states and final route installation")
        
        # Check APM probe status - both should be UP
        apm_status = st.show(nodes['leaf2'], "show apm-status", skip_tmpl=True, skip_error_check=True)
        st.log("APM status output: {}".format(apm_status))
        
        # Verify specific probe states
        tcpprobe1_up = False
        tcpprobe2_up = False
        
        if "tcpprobe1" in str(apm_status):
            apm_lines = str(apm_status).split('\n')
            for line in apm_lines:
                if "tcpprobe1" in line and ("UP" in line or "up" in line.lower()):
                    tcpprobe1_up = True
                    st.log("SUCCESS: tcpprobe1 is UP")
                    break
        
        if "tcpprobe2" in str(apm_status):
            apm_lines = str(apm_status).split('\n')
            for line in apm_lines:
                if "tcpprobe2" in line and ("UP" in line or "up" in line.lower()):
                    tcpprobe2_up = True
                    st.log("SUCCESS: tcpprobe2 is UP")
                    break
        
        if not (tcpprobe1_up and tcpprobe2_up):
            st.log("WARNING: One or both APM probes are not UP")
        
        # Check final route installation in FRR
        final_route_output = st.show(nodes['leaf2'], "show ip route vrf Vrf01", skip_tmpl=True)
        st.log("Final route table output: {}".format(final_route_output))
        
        route_present = STATIC_ROUTE_PREFIX in str(final_route_output)
        nexthop1_present = SPINE2_VLAN10_IP in str(final_route_output)
        nexthop2_present = SPINE2_VLAN20_IP in str(final_route_output)
        
        if route_present:
            st.log("SUCCESS: Route {} is present in routing table".format(STATIC_ROUTE_PREFIX))
        if nexthop1_present:
            st.log("SUCCESS: Nexthop {} is present".format(SPINE2_VLAN10_IP))
        if nexthop2_present:
            st.log("SUCCESS: Nexthop {} is present".format(SPINE2_VLAN20_IP))
        
        # Step 9: Verify APP-DB contains static route entry with both nexthops
        st.banner("Step 9: Verifying APP-DB static route entry")
        verify_app_db_static_route(
            nodes['leaf2'],
            'redis-cli -n 0 hgetall "STATIC_ROUTE:Vrf01:{}"'.format(STATIC_ROUTE_PREFIX),
            [SPINE2_VLAN10_IP, SPINE2_VLAN20_IP],  # Expected nexthops
            "APM Route Update with Distance and Tag"
        )
        
        # Step 10: Verify FRR running config shows routes with correct distance and tag values
        st.banner("Step 10: Verifying FRR running config with distance and tag values")
        
        # Get FRR running configuration
        frr_config_cmd = 'sudo vtysh -c "show running-config"'
        frr_config = st.show(nodes['leaf2'], frr_config_cmd, skip_tmpl=True, skip_error_check=True)
        st.log("FRR running config: {}".format(frr_config))
        
        # Expected FRR entries after updates:
        # ip route 172.16.255.1/32 10.212.10.6 tag 3 10
        # ip route 172.16.255.1/32 10.212.20.6 tag 4 20
        expected_route1 = "ip route {} {} tag 3 10".format(STATIC_ROUTE_PREFIX, SPINE2_VLAN10_IP)
        expected_route2 = "ip route {} {} tag 4 20".format(STATIC_ROUTE_PREFIX, SPINE2_VLAN20_IP)
        
        route1_found = expected_route1 in str(frr_config)
        route2_found = expected_route2 in str(frr_config)
        
        if route1_found:
            st.log("SUCCESS: Found expected FRR route entry: {}".format(expected_route1))
        else:
            st.log("WARNING: Expected FRR route entry not found: {}".format(expected_route1))
        
        if route2_found:
            st.log("SUCCESS: Found expected FRR route entry: {}".format(expected_route2))
        else:
            st.log("WARNING: Expected FRR route entry not found: {}".format(expected_route2))
        
        # Test success criteria
        test_success = (tcpprobe1_up and tcpprobe2_up and 
                       route_present and nexthop1_present and nexthop2_present and
                       route1_found and route2_found)
        
        if test_success:
            st.log("TEST PASSED: APM Route Update with Distance and Tag Values completed successfully")
            st.log("- Both APM probes are UP")
            st.log("- Route present with both nexthops")
            st.log("- FRR config shows correct distance and tag values after separate updates")
            st.banner("APM Route Update with Distance and Tag Values Test - PASSED")
            st.report_pass('test_case_passed')
        else:
            st.log("TEST FAILED: One or more verification criteria not met")
            failure_reasons = []
            if not (tcpprobe1_up and tcpprobe2_up):
                failure_reasons.append("APM probes not UP")
            if not (route_present and nexthop1_present and nexthop2_present):
                failure_reasons.append("Route or nexthops missing")
            if not (route1_found and route2_found):
                failure_reasons.append("FRR config entries missing or incorrect")
            st.report_fail('test_case_failed', "Test failed: {}".format(", ".join(failure_reasons)))

    except Exception as e:
        st.log("Exception occurred during test execution: {}".format(str(e)))
        st.report_fail('test_case_failed', "Test failed with exception: {}".format(str(e)))
        
    finally:
        # Cleanup configurations
        st.banner("Cleanup: Removing all test configurations")
        
        try:
            # Stop TCP servers on SD3 (spine2)
            st.config(nodes['spine2'], "pkill -f tcpserver.py", skip_error_check=True)
            st.wait(1)
            
            # Remove route completely
            st.config(nodes['leaf2'], "config route del prefix vrf Vrf01 {}".format(STATIC_ROUTE_PREFIX), skip_error_check=True)
            st.wait(2)
            
            # Remove APM probes from SD7 (leaf2)
            st.config(nodes['leaf2'], "config apm del tcpprobe1", skip_error_check=True)
            st.config(nodes['leaf2'], "config apm del tcpprobe2", skip_error_check=True)
            st.wait(1)
            
            # Remove IP addresses from SD3 (spine2) using dynamic ports
            st.config(nodes['spine2'], "config interface ip remove {} {}".format(vars.D3D7P1, SPINE2_VLAN10_IP_PREFIX), skip_error_check=True)
            st.config(nodes['spine2'], "config interface ip remove {} {}".format(vars.D3D7P2, SPINE2_VLAN20_IP_PREFIX), skip_error_check=True)
            
            # Remove dynamic ports from VLANs on SD7 (leaf2)
            st.config(nodes['leaf2'], "config vlan member del 10 {}".format(vars.D7D3P1), skip_error_check=True)
            st.config(nodes['leaf2'], "config vlan member del 20 {}".format(vars.D7D3P2), skip_error_check=True)
            
            # Clean up log files on SD3 (spine2)
            st.config(nodes['spine2'], "rm -f /tmp/tcpserver1.log", skip_error_check=True)
            st.config(nodes['spine2'], "rm -f /tmp/tcpserver2.log", skip_error_check=True)
            
            st.log("Cleanup completed successfully")
            
        except Exception as cleanup_e:
            st.log("Warning: Some cleanup operations failed: {}".format(str(cleanup_e)))
    
    st.report_pass("test_case_passed", "APM Route Update with Distance and Tag Values Test")


######################################################################
# Test Static Route with Distance and Tag Values (No APM)
######################################################################
@pytest.mark.system_box
@pytest.mark.community
@pytest.mark.community_pass
def test_static_route_distance_tag_no_apm():
    """
    Test static route configuration with distance and tag values without APM dependencies
    
    Test Scenario:
    Configure a static route with distance and tag values but without APM dependencies,
    then verify that there's no APP-DB entry (since it's not an APM route), but the route
    appears correctly in FRR running config and the routing table with proper distance and tag values.
    
    Test Steps:
    1. Configure dynamic ports (D7D3P1 to Vlan10 and D7D3P2 to Vlan20) on SD7 (leaf2)
    2. Configure IP addresses on SD3 (spine2) using dynamic ports (D3D7P1 and D3D7P2)
    3. Add static route with both nexthops, distance, and tag values (no APM)
    4. Verify route is present in routing table with both nexthops
    5. Verify APP-DB has NO entry for this route (since no APM dependencies)
    6. Verify FRR running config shows routes with correct distance and tag values
    7. Cleanup all configurations
    
    Configuration Sequence:
    - Add dynamic ports (D7D3P1 to VLAN 10 and D7D3P2 to VLAN 20) on SD7 (leaf2)
    - Assign IP addresses to dynamic ports (D3D7P1 and D3D7P2) on SD3 (spine2)
    - config route add prefix vrf Vrf01 172.16.255.1/32 nexthop 10.212.10.6,10.212.20.6 distance 10,20 tag 3,4
    
    Expected Behavior:
    - Route present with both nexthops in routing table
    - NO APP-DB entry (since no APM dependencies)
    - FRR config shows: ip route 172.16.255.1/32 10.212.10.6 tag 3 10
    - FRR config shows: ip route 172.16.255.1/32 10.212.20.6 tag 4 20
    """
    vars = st.get_testbed_vars()
    
    st.banner("Starting Static Route with Distance and Tag Values (No APM) Test")
    
    try:
        # Step 1: Configure dynamic ports on SD7 (leaf2) to VLANs
        st.banner("Step 1: Configuring Ethernet interfaces on SD7 (leaf2)")
        st.wait(3)
        
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
        
        # Step 3: Add static route with both nexthops, distance, and tag values (no APM)
        st.banner("Step 3: Adding static route with nexthops, distance, and tag values (no APM)")
        
        # Command: config route add with nexthops, distance, and tag values (no APM dependencies)
        route_add_cmd = "config route add prefix vrf Vrf01 {} nexthop {},{} distance 10,20 tag 3,4".format(STATIC_ROUTE_PREFIX, SPINE2_VLAN10_IP, SPINE2_VLAN20_IP)
        st.config(nodes['leaf2'], route_add_cmd)
        st.wait(2)  # Wait for route to be installed
        # Step 4: Verify route is present in routing table with both nexthops
        st.banner("Step 4: Verifying route is present in routing table with both nexthops")
        
        # Check route installation in FRR
        route_output = st.show(nodes['leaf2'], "show ip route vrf Vrf01", skip_tmpl=True)
        st.log("Route table output: {}".format(route_output))
        
        route_present = STATIC_ROUTE_PREFIX in str(route_output)
        nexthop1_present = SPINE2_VLAN10_IP in str(route_output)
        nexthop2_present = SPINE2_VLAN20_IP in str(route_output)
        
        if route_present:
            st.log("SUCCESS: Route {} is present in routing table".format(STATIC_ROUTE_PREFIX))
        else:
            st.log("FAIL: Route {} is NOT present in routing table".format(STATIC_ROUTE_PREFIX))
        
        if nexthop1_present:
            st.log("SUCCESS: Nexthop {} is present".format(SPINE2_VLAN10_IP))
        else:
            st.log("FAIL: Nexthop {} is NOT present".format(SPINE2_VLAN10_IP))
        
        if nexthop2_present:
            st.log("SUCCESS: Nexthop {} is present".format(SPINE2_VLAN20_IP))
        else:
            st.log("FAIL: Nexthop {} is NOT present".format(SPINE2_VLAN20_IP))
        
        # Step 5: Verify APP-DB has NO entry for this route (since no APM dependencies)
        st.banner("Step 5: Verifying APP-DB has NO entry (no APM dependencies)")
        
        # Check APP-DB - should have no entry since this is not an APM route
        app_db_cmd = 'redis-cli -n 0 hgetall "STATIC_ROUTE:Vrf01:{}"'.format(STATIC_ROUTE_PREFIX)
        app_db_output = st.config(nodes['leaf2'], app_db_cmd, skip_error_check=True)
        st.log("APP-DB output: {}".format(app_db_output))
        # Verify APP-DB is empty for this route (no APM dependencies)
        app_db_empty = not app_db_output or "(empty array)" in str(app_db_output).lower() or str(app_db_output).strip() == ''
        
        if app_db_empty:
            st.log("SUCCESS: APP-DB has no entry (expected for non-APM route)")
        else:
            st.log("WARNING: APP-DB has entry for non-APM route: {}".format(app_db_output))
        
        # Step 6: Verify FRR running config shows routes with correct distance and tag values
        st.banner("Step 6: Verifying FRR running config with distance and tag values")
        
        # Get FRR running configuration
        frr_config_cmd = 'sudo vtysh -c "show running-config"'
        frr_config = st.show(nodes['leaf2'], frr_config_cmd, skip_tmpl=True, skip_error_check=True)
        st.log("FRR running config: {}".format(frr_config))
        
        # Expected FRR entries:
        # ip route 172.16.255.1/32 10.212.10.6 tag 3 10
        # ip route 172.16.255.1/32 10.212.20.6 tag 4 20
        expected_route1 = "ip route {} {} tag 3 10".format(STATIC_ROUTE_PREFIX, SPINE2_VLAN10_IP)
        expected_route2 = "ip route {} {} tag 4 20".format(STATIC_ROUTE_PREFIX, SPINE2_VLAN20_IP)
        
        route1_found = expected_route1 in str(frr_config)
        route2_found = expected_route2 in str(frr_config)
        
        if route1_found:
            st.log("SUCCESS: Found expected FRR route entry: {}".format(expected_route1))
        else:
            st.log("FAIL: Expected FRR route entry not found: {}".format(expected_route1))
        
        if route2_found:
            st.log("SUCCESS: Found expected FRR route entry: {}".format(expected_route2))
        else:
            st.log("FAIL: Expected FRR route entry not found: {}".format(expected_route2))
        
        # Test success criteria
        test_success = (route_present and nexthop1_present and nexthop2_present and
                       app_db_empty and route1_found and route2_found)
        
        if test_success:
            st.log("TEST PASSED: Static Route with Distance and Tag Values (No APM) completed successfully")
            st.log("- Route present with both nexthops in routing table")
            st.log("- APP-DB has no entry (expected for non-APM route)")
            st.log("- FRR config shows correct distance and tag values")
            st.banner("Static Route with Distance and Tag Values (No APM) Test - PASSED")
            st.report_pass('test_case_passed')
        else:
            st.log("TEST FAILED: One or more verification criteria not met")
            failure_reasons = []
            if not (route_present and nexthop1_present and nexthop2_present):
                failure_reasons.append("Route or nexthops missing from routing table")
            if not app_db_empty:
                failure_reasons.append("Unexpected APP-DB entry found")
            if not (route1_found and route2_found):
                failure_reasons.append("FRR config entries missing or incorrect")
            st.report_fail('test_case_failed', "Test failed: {}".format(", ".join(failure_reasons)))

    except Exception as e:
        st.log("Exception occurred during test execution: {}".format(str(e)))
        st.report_fail('test_case_failed', "Test failed with exception: {}".format(str(e)))
        
    finally:
        # Cleanup configurations
        st.banner("Cleanup: Removing all test configurations")
        
        try:
            # Remove route completely
            st.config(nodes['leaf2'], "config route del prefix vrf Vrf01 {}".format(STATIC_ROUTE_PREFIX), skip_error_check=True)
            st.wait(2)
            
            # Remove IP addresses from SD3 (spine2) using dynamic ports
            st.config(nodes['spine2'], "config interface ip remove {} {}".format(vars.D3D7P1, SPINE2_VLAN10_IP_PREFIX), skip_error_check=True)
            st.config(nodes['spine2'], "config interface ip remove {} {}".format(vars.D3D7P2, SPINE2_VLAN20_IP_PREFIX), skip_error_check=True)
            
            # Remove dynamic ports from VLANs on SD7 (leaf2)
            st.config(nodes['leaf2'], "config vlan member del 10 {}".format(vars.D7D3P1), skip_error_check=True)
            st.config(nodes['leaf2'], "config vlan member del 20 {}".format(vars.D7D3P2), skip_error_check=True)
            
            st.log("Cleanup completed successfully")
            
        except Exception as cleanup_e:
            st.log("Warning: Some cleanup operations failed: {}".format(str(cleanup_e)))
    
    st.report_pass("test_case_passed", "Static Route with Distance and Tag Values (No APM) Test")



######################################################################
# Test FRR Route Override and Split-Unified Config Mode
######################################################################
@pytest.mark.skip
@pytest.mark.system_box
@pytest.mark.community
@pytest.mark.community_pass
def test_frr_route_override_split_unified_mode():
    """
    Test FRR route configuration override and split-unified config mode persistence
    
    Test Scenario:
    Configure a route directly in FRR, then override it via SONiC CLI with different
    distance and tag values, enable split-unified mode, save config, reload, and verify
    the overridden route persists with correct values.
    
    Test Steps:
    1. Configure dynamic port (D7D3P1 to Vlan10) on SD7 (leaf2)
    2. Configure IP address on SD3 (spine2) using dynamic port (D3D7P1)
    3. Configure route directly in FRR via vtysh with tag 2 and distance 20
    4. Save FRR config to memory
    5. Override route via SONiC CLI with tag 3 and distance 30
    6. Verify overridden route in FRR config
    7. Enable split-unified mode in Redis
    8. Save config and reload
    9. Wait for system to come up (120 seconds)
    10. Verify route persists with overridden values (tag 3, distance 30)
    11. Cleanup all configurations including config_db.json
    
    Configuration Sequence:
    - Add dynamic port (D7D3P1 to VLAN 10) on SD7 (leaf2)
    - Assign IP address to dynamic port (D3D7P1) on SD3 (spine2)
    - sudo vtysh -c "configure terminal" -c "ip route 172.16.255.1/32 10.212.10.6 tag 2 20" -c "exit"
    - sudo vtysh -c "write memory"
    - config route add prefix 172.16.255.1/32 nexthop 10.212.10.6 distance 30 tag 3
    - sudo redis-cli -n 4 hset "DEVICE_METADATA|localhost" "docker_routing_config_mode" "split-unified"
    - config save
    - config reload
    
    Expected Behavior:
    - Initial FRR route: ip route 172.16.255.1/32 10.212.10.6 tag 2 20
    - After override: ip route 172.16.255.1/32 10.212.10.6 tag 3 30
    - After reload: Route persists with tag 3 and distance 30
    """
    vars = st.get_testbed_vars()
    
    st.banner("Starting FRR Route Override and Split-Unified Config Mode Test")
    
    try:
        # Step 1: Configure dynamic port to Vlan10 on SD7 (leaf2)
        st.banner("Step 1: Configuring dynamic port to Vlan10 on SD7 (leaf2)")
        
        # Add D7D3P1 to Vlan10 on SD7 (leaf2)
        st.config(nodes['leaf2'], "config vlan member add 10 {} -u".format(vars.D7D3P1))
        
        # Step 2: Configure IP address on SD3 (spine2) using dynamic port
        st.banner("Step 2: Configuring IP address on SD3 (spine2) using dynamic port")
        
        # Configure IP address on SD3 (spine2) D3D7P1
        st.config(nodes['spine2'], "config interface ip add {} {}".format(vars.D3D7P1, SPINE2_VLAN10_IP_PREFIX))
        
        # Step 3: Configure route directly in FRR via vtysh with tag 2 and distance 20
        st.banner("Step 3: Configuring route directly in FRR via vtysh")
        
        # Configure route directly in FRR
        frr_route_cmd = 'sudo vtysh -c "configure terminal" -c "ip route {} {} tag 2 20" -c "exit"'.format(STATIC_ROUTE_PREFIX, SPINE2_VLAN10_IP)
        st.config(nodes['leaf2'], frr_route_cmd)
        
        # Step 4: Save FRR config to memory
        st.banner("Step 4: Saving FRR config to memory")
        
        # Save FRR configuration
        frr_save_cmd = 'sudo vtysh -c "write memory"'
        st.config(nodes['leaf2'], frr_save_cmd)
        st.wait(2)
        
        # Verify initial FRR route
        initial_frr_config = st.show(nodes['leaf2'], 'sudo vtysh -c "show running-config"', skip_tmpl=True, skip_error_check=True)
        st.log("Initial FRR config after direct configuration: {}".format(initial_frr_config))
        
        # Verify initial route is present
        initial_route_expected = "ip route {} {} tag 2 20".format(STATIC_ROUTE_PREFIX, SPINE2_VLAN10_IP)
        initial_route_found = initial_route_expected in str(initial_frr_config)
        
        if initial_route_found:
            st.log("SUCCESS: Initial FRR route found: {}".format(initial_route_expected))
        else:
            st.log("WARNING: Initial FRR route not found: {}".format(initial_route_expected))
        
        # Step 5: Override route via SONiC CLI with tag 3 and distance 30
        st.banner("Step 5: Overriding route via SONiC CLI with different tag and distance")
        
        # Override route via SONiC CLI
        sonic_route_cmd = "config route add prefix {} nexthop {} distance 30 tag 3".format(STATIC_ROUTE_PREFIX, SPINE2_VLAN10_IP)
        st.config(nodes['leaf2'], sonic_route_cmd)
        st.wait(2)  # Wait for route to be overridden
        
        # Step 6: Verify overridden route in FRR config
        st.banner("Step 6: Verifying overridden route in FRR config")
        
        # Check FRR config after override
        override_frr_config = st.show(nodes['leaf2'], 'sudo vtysh -c "show running-config"', skip_tmpl=True, skip_error_check=True)
        st.log("FRR config after SONiC CLI override: {}".format(override_frr_config))
        
        # Verify overridden route
        override_route_expected = "ip route {} {} tag 3 30".format(STATIC_ROUTE_PREFIX, SPINE2_VLAN10_IP)
        override_route_found = override_route_expected in str(override_frr_config)
        
        if override_route_found:
            st.log("SUCCESS: Overridden route found in FRR: {}".format(override_route_expected))
        else:
            st.log("WARNING: Overridden route not found in FRR: {}".format(override_route_expected))
        
        # Also verify route in routing table
        route_table_output = st.show(nodes['leaf2'], "show ip route", skip_tmpl=True)
        st.log("Route table after override: {}".format(route_table_output))
        
        route_in_table = STATIC_ROUTE_PREFIX in str(route_table_output)
        nexthop_in_table = SPINE2_VLAN10_IP in str(route_table_output)
        
        # Step 7: Enable split-unified mode in Redis
        st.banner("Step 7: Enabling split-unified mode in Redis")
        
        # Set split-unified mode
        redis_cmd = 'sudo redis-cli -n 4 hset "DEVICE_METADATA|localhost" "docker_routing_config_mode" "split-unified"'
        st.config(nodes['leaf2'], redis_cmd)
        st.wait(2)
        
        # Verify Redis setting
        redis_check_cmd = 'sudo redis-cli -n 4 hget "DEVICE_METADATA|localhost" "docker_routing_config_mode"'
        redis_output = st.config(nodes['leaf2'], redis_check_cmd, skip_error_check=True)
        st.log("Redis split-unified mode setting: {}".format(redis_output))
        
        # Step 8: Save config and reload
        st.banner("Step 8: Saving config and initiating reload")
        
        # Save configuration
        st.config(nodes['leaf2'], "config save -y")
        st.wait(3)
        
        # Initiate config reload
        st.config(nodes['leaf2'], "config reload -y", skip_error_check=True)
        
        # Step 9: Wait for system to come up (120 seconds)
        st.banner("Step 9: Waiting for system to come up after reload (120 seconds)")
        st.wait(120)  # Wait for system to fully reload
        
        # Verify system is responsive
        system_check = st.show(nodes['leaf2'], "show version", skip_tmpl=True, skip_error_check=True)
        st.log("System status after reload: {}".format(system_check))
        
        # Step 10: Verify route persists with overridden values (tag 3, distance 30)
        st.banner("Step 10: Verifying route persistence after reload")
        
        # Check FRR config after reload
        final_frr_config = st.show(nodes['leaf2'], 'sudo vtysh -c "show running-config"', skip_tmpl=True, skip_error_check=True)
        st.log("Final FRR config after reload: {}".format(final_frr_config))
        
        # Verify persistent route
        persistent_route_expected = "ip route {} {} tag 3 30".format(STATIC_ROUTE_PREFIX, SPINE2_VLAN10_IP)
        persistent_route_found = persistent_route_expected in str(final_frr_config)
        
        if persistent_route_found:
            st.log("SUCCESS: Route persisted after reload: {}".format(persistent_route_expected))
        else:
            st.log("FAIL: Route did not persist after reload: {}".format(persistent_route_expected))
        
        # Also verify route in final routing table
        final_route_table = st.show(nodes['leaf2'], "show ip route", skip_tmpl=True)
        st.log("Final route table after reload: {}".format(final_route_table))
        
        final_route_in_table = STATIC_ROUTE_PREFIX in str(final_route_table)
        final_nexthop_in_table = SPINE2_VLAN10_IP in str(final_route_table)
        
        # Test success criteria
        test_success = (initial_route_found and override_route_found and 
                       route_in_table and nexthop_in_table and
                       persistent_route_found and final_route_in_table and final_nexthop_in_table)
        
        if test_success:
            st.log("TEST PASSED: FRR Route Override and Split-Unified Config Mode completed successfully")
            st.log("- Initial FRR route configured correctly")
            st.log("- Route successfully overridden via SONiC CLI")
            st.log("- Route persisted after config reload with correct values")
            st.banner("FRR Route Override and Split-Unified Config Mode Test - PASSED")
            st.report_pass('test_case_passed')
        else:
            st.log("TEST FAILED: One or more verification criteria not met")
            failure_reasons = []
            if not initial_route_found:
                failure_reasons.append("Initial FRR route not found")
            if not override_route_found:
                failure_reasons.append("Override route not found")
            if not (route_in_table and nexthop_in_table):
                failure_reasons.append("Route not in routing table")
            if not persistent_route_found:
                failure_reasons.append("Route did not persist after reload")
            if not (final_route_in_table and final_nexthop_in_table):
                failure_reasons.append("Route not in final routing table")
            st.report_fail('test_case_failed', "Test failed: {}".format(", ".join(failure_reasons)))

    except Exception as e:
        st.log("Exception occurred during test execution: {}".format(str(e)))
        st.report_fail('test_case_failed', "Test failed with exception: {}".format(str(e)))
        
    finally:
        # Step 11: Cleanup all configurations including config_db.json
        st.banner("Cleanup: Removing all test configurations")
        
        try:
            
            # Remove route via SONiC CLI
            st.config(nodes['leaf2'], "config route del prefix {}".format(STATIC_ROUTE_PREFIX), skip_error_check=True)
            st.wait(2)
            
            # Reset docker routing config mode
            # redis_reset_cmd = 'sudo redis-cli -n 4 hdel "DEVICE_METADATA|localhost" "docker_routing_config_mode"'
            # st.config(nodes['leaf2'], redis_reset_cmd, skip_error_check=True)
            
            # Remove IP address from SD3 (spine2) using dynamic port
            st.config(nodes['spine2'], "config interface ip remove {} {}".format(vars.D3D7P1, SPINE2_VLAN10_IP_PREFIX), skip_error_check=True)
            
            # Remove dynamic port from Vlan10 on SD7 (leaf2)
            st.config(nodes['leaf2'], "config vlan member del 10 {}".format(vars.D7D3P1), skip_error_check=True)
            
            # Remove config_db.json 
            st.config(nodes['leaf2'], "rm -f /etc/sonic/config_db.json", skip_error_check=True)
            
            
            st.log("Cleanup completed successfully")
            
        except Exception as cleanup_e:
            st.log("Warning: Some cleanup operations failed: {}".format(str(cleanup_e)))
    
    st.report_pass("test_case_passed", "FRR Route Override and Split-Unified Config Mode Test")