import pytest
import time
import logging
from ptf_runner import ptf_runner
from platform_fixtures import conn_graph_facts

@pytest.fixture(scope="module")
def common_setup_teardown(duthost, ptfhost, conn_graph_facts):
    # TODO: get the testbed_type

    lag_facts = duthost.lag_facts(host = duthost.hostname)['ansible_facts']
    if lag_facts['names'] == []:
        pytest.skip("No lag configuration found in %s" % duthost.hostname)

    test_minlink = True
    test_rate = True

    # Add/update the public key
    # TODO: convert add_container_to_inventory.yml

    mg_facts = duthost.minigraph_facts(host=hostname)['ansible_facts']
    fanout_neighbors = conn_graph_facts['device_conn']
    vm_neighbors = mg_facts['minigraph_neighbors']

    # Copy PTF test into PTF-docker for test LACP DU
    test_files = ['lag_test.py', 'acs_base_test.py', 'router_utils.py']
    for test_file in test_files:
        src = "roles/test/files/acstests/%s" % test_file
        dst = "/tmp/%s" % test_file
        ptfhost.copy(src=src, dest=dst)
    
    # Copy tests to the PTF-docker
    ptfhost.copy(src="ptftests", dest="/root")

    # Inlucde testbed topology configuration
    if testbed_type == 't1-lag':
        # TODO
    elif testbed_type == 't0':
        # TODO
    elif testbed_type == 't0-116'
        # TODO

    dut_mac = duthost['ansible_Ethernet0']['macaddress']

    # Test each lag interface
    for lag_name in lag_facts['names']
        yield ptfhost, fanout_neighbors, vm_neighbors, mg_facts, lag_facts, lag_name

def test_single_lag_lacp_rate(common_setup_teardown, testbed_devices):
    ptfhost, fanout_neighbors, vm_neighbors, mg_facts, lag_facts, lag_name = common_setup_teardown

    po = lag_name
    po_interfaces = lag_facts[lag_name]['po_config']['ports']
    po_intf_num = len(po_interfaces)
    po_min_links = lag_facts[lag_name]['po_config']['runner']['min_ports']

    # Pick flap interface name and calculate when it flaps, should portchannel interface flap or not
    po_flap = float(po_intf_num - 1) / po_min_links * 100 < 75
    flap_intf = lag_facts[lag_name]['po_config']['ports'].keys()[0]
    if not po_flap:
        pytest.skip("The interface [%s] is not flap" % flap_intf)

    # Figure out fanout switches info for the flapping lag member
    peer_device = fanout_neighbors[flap_intf]['peerdevice']
    neighbor_interface = fanout_neighbors[flap_intf]['peerport']
    conn_graph_facts = get_conn_graph_facts(testbed_devices, host=peer_device)

    # Figure out remote VM and interface info for the flapping lag member and run minlink test
    peer_device = vm_neighbors[flap_intf]['name']
    neighbor_interface = vm_neighbors[flap_intf]['port']
    peer_hwsku = 'Arista-VM'
    peer_host = mg_facts['minigraph_devices']

    # Prepare for the remote VM interfaces that using PTF docker to check if the LACP DU packet rate is correct
    iface_behind_lag_member = []
    for minigraph_neighbor in minigraph_neighbors:
        if peer_device == minigraph_neighbor.value.name:
            iface_behind_lag_member.append(mg_facts['minigraph_port_indices'][minigraph_neighbor.key])

    neighbor_lag_intfs = []
    for po_interface in po_interfaces:
        neighbor_lag_intfs.append(vm_neighbors[po_interface]['port'])
    
    try:
        lag_rate_current_setting = None

        # Make sure all lag members on VM are set to fast
        # TODO: login peer_host and use action [apswitch]
        lag_rate_current_setting = 'fast'
        time.sleep(5)
        verify_lag_lacp_timing(peer_device, 1, iface_behind_lag_member[0])
        verify_lag_lacp_timing(peer_device, 1, iface_behind_lag_member[1])

        # Make sure all lag members on VM are set to slow
        # TODO: login peer_host and use action [apswitch]
        lag_rate_current_setting = 'slow'
        time.sleep(5)
        verify_lag_lacp_timing(peer_device, 30, iface_behind_lag_member[0])
        verify_lag_lacp_timing(peer_device, 30, iface_behind_lag_member[1])
    finally:
        # Restore lag rate setting on VM in case of failure
        if lag_rate_current_setting == 'fast':
            # TODO: login peer_host and use action [apswitch]

def verify_lag_lacp_timing(vm_name, lacp_timer, exp_iface):
    if exp_iface is None:
        return

    # Check LACP timing
    params = {
        'exp_iface': exp_iface,
        'timeout': 35,
        'packet_timing': lacp_timer,
        'ether_type': '0x8809',
        'interval_count': 3
    }
    ptf_runner(ptfhost, '.', "lag_test.LacpTimingTest", 'ptftests', params=params)

def verify_lag_run_ptf(ptfhost, lag_ptf_test_name, params, change_dir):
    # ptf_runner
    # Send traffic from PTF docker and verify all the packets arrived
    ptfhost.shell("ptf --test-dir . --platform-dir /root/ptftests --platform remote lag_test.%s -t \"%s\"" % (lag_ptf_test_name, params))

def get_conn_graph_facts(testbed_devices, host):
    base_path = os.path.dirname(os.path.realpath(__file__))
    lab_conn_graph_file = os.path.join(base_path, "../../ansible/files/lab_connection_graph.xml")
    result = localhost.conn_graph_facts(host=host, filename=lab_conn_graph_file)['ansible_facts']
    return result