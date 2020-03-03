import pytest

import time
import logging
import os

from ptf_runner import ptf_runner

@pytest.fixture(scope="module")
def common_setup_teardown(duthost, ptfhost, testbed, conn_graph_facts):
    logging.info("########### Setup for lag testing ###########")

    lag_facts = duthost.lag_facts(host = duthost.hostname)['ansible_facts']['lag_facts']

    if lag_facts['names'] == []:
        pytest.skip("No lag configuration found in %s" % duthost.hostname)

    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
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
    testbed_type = testbed['topo']['name']
    support_testbed_types = frozenset(['t1-lag', 't0', 't0-116'])
    if testbed_type in support_testbed_types:
        # TODO: Not sure why need to load vars
        logging.info("Load vars for %s" % testbed_type)
    else:
        pytest.skip("Not support given test bed type %s" % testbed_type)

    host_facts  = duthost.setup()['ansible_facts']
    dut_mac = host_facts['ansible_Ethernet0']['macaddress']

    # Test each lag interface
    for lag_name in lag_facts['names']:
        yield ptfhost, fanout_neighbors, vm_neighbors, mg_facts, lag_facts, lag_name

def test_single_lag_lacp_rate(common_setup_teardown, testbed_devices):
    ptfhost, fanout_neighbors, vm_neighbors, mg_facts, lag_facts, lag_name = common_setup_teardown

    pytest.skip("Skip test: %s" % lag_name)
    po_interfaces = lag_facts[lag_name]['po_config']['ports']

    intf = lag_facts[lag_name]['po_config']['ports'].keys()[0]

    # Figure out fanout switches info for the flapping lag member
    peer_device = fanout_neighbors[intf]['peerdevice']
    neighbor_interface = fanout_neighbors[intf]['peerport']
    conn_graph_facts = get_conn_graph_facts(testbed_devices, host=peer_device)

    # Figure out remote VM and interface info for the flapping lag member and run minlink test
    peer_device = vm_neighbors[intf]['name']
    neighbor_interface = vm_neighbors[intf]['port']
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
        # Use arista.py - e.g. advanced-reboot.py instead
        # Another choice: eos_config ansible
        # Login information //labinfo.json
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
            print "fast"

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

@pytest.fixture(scope="module")
def conn_graph_facts(testbed_devices):
    dut = testbed_devices["dut"]
    return get_conn_graph_facts(testbed_devices, dut.hostname)

def get_conn_graph_facts(testbed_devices, host):
    localhost = testbed_devices["localhost"]

    base_path = os.path.dirname(os.path.realpath(__file__))
    lab_conn_graph_file = os.path.join(base_path, "../../ansible/files/lab_connection_graph.xml")
    result = localhost.conn_graph_facts(host=host, filename=lab_conn_graph_file)['ansible_facts']
    return result