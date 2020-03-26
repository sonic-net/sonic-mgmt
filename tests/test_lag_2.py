import pytest

import json
import time
import logging
import os

from ptf_runner import ptf_runner
from common.devices import AnsibleHostBase

@pytest.fixture(scope="module")
def common_setup_teardown(duthost, ptfhost, testbed, conn_graph_facts):
    logging.info("########### Setup for lag testing ###########")

    lag_facts = duthost.lag_facts(host = duthost.hostname)['ansible_facts']['lag_facts']

    if lag_facts['names'] == []:
        pytest.skip("No lag configuration found in %s" % duthost.hostname)

    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
    logging.info("dut hostname: %s" % mg_facts)
    vm_neighbors = mg_facts['minigraph_neighbors']

    # Copy PTF test into PTF-docker for test LACP DU
    test_files = ['lag_test.py', 'acs_base_test.py', 'router_utils.py']
    for test_file in test_files:
        src = "../ansible/roles/test/files/acstests/%s" % test_file
        dst = "/tmp/%s" % test_file
        ptfhost.copy(src=src, dest=dst)

    # Copy tests to the PTF-docker
    ptfhost.copy(src="ptftests", dest="/root")

    # Inlucde testbed topology configuration
    testbed_type = testbed['topo']['name']
    
    support_testbed_types = frozenset(['t1-lag', 't0', 't0-116'])
    if testbed_type not in support_testbed_types:
        pytest.skip("Not support given test bed type %s" % testbed_type)

    yield ptfhost, testbed, vm_neighbors, mg_facts, lag_facts

def test_lag_2(common_setup_teardown, nbrhosts):
    ptfhost, testbed, vm_neighbors, mg_facts, lag_facts = common_setup_teardown

    # Test for each lag
    for lag_name in lag_facts['names']:
        check_single_lag_lacp_rate(common_setup_teardown, nbrhosts, lag_name)

def check_single_lag_lacp_rate(common_setup_teardown, nbrhosts, lag_name):
    ptfhost, testbed, vm_neighbors, mg_facts, lag_facts = common_setup_teardown
    logging.info("Start checking single lap lacp rate for: %s" % lag_name)
    
    po_interfaces = lag_facts['lags'][lag_name]['po_config']['ports']
    intf = lag_facts['lags'][lag_name]['po_config']['ports'].keys()[0]

    # Figure out remote VM and interface info
    peer_device = vm_neighbors[intf]['name']

    # Prepare for the remote VM interfaces that using PTF docker to check if the LACP DU packet rate is correct
    iface_behind_lag_member = []
    for neighbor_int in mg_facts['minigraph_neighbors'].keys():
        if peer_device == mg_facts['minigraph_neighbors'][neighbor_int]['name']:
            iface_behind_lag_member.append(mg_facts['minigraph_port_indices'][neighbor_int])

    neighbor_lag_intfs = []
    for po_interface in po_interfaces:
        neighbor_lag_intfs.append(vm_neighbors[po_interface]['port'])

    try:
        lag_rate_current_setting = None

        # Get the vm host(veos) by it host name
        vm_host = nbrhosts[peer_device]

        # Make sure all lag members on VM are set to fast
        logging.info("Changing lacp rate to fast for %s" % neighbor_lag_intfs[0])
        set_interface_lacp_rate(vm_host, neighbor_lag_intfs[0], 'fast')
        lag_rate_current_setting = 'fast'
        time.sleep(5)
        for iface_behind_lag in iface_behind_lag_member:
            verify_lag_lacp_timing(ptfhost, peer_device, 1, iface_behind_lag)

        # Make sure all lag members on VM are set to slow
        set_interface_lacp_rate(vm_host, neighbor_lag_intfs[0], 'normal')
        lag_rate_current_setting = 'slow'
        time.sleep(5)
        for iface_behind_lag in iface_behind_lag_member:
            verify_lag_lacp_timing(ptfhost, peer_device, 30, iface_behind_lag)
    finally:
        # Restore lag rate setting on VM in case of failure
        if lag_rate_current_setting == 'fast':
            set_interface_lacp_rate(vm_host, neighbor_lag_intfs[0], 'normal')

def verify_lag_lacp_timing(ptfhost, vm_name, lacp_timer, exp_iface):
    if exp_iface is None:
        return

    # Check LACP timing
    params = {
        'exp_iface': exp_iface,
        'timeout': 35,
        'packet_timing': lacp_timer,
        'ether_type': 0x8809,
        'interval_count': 3
    }
    ptf_runner(ptfhost, '/tmp', "lag_test.LacpTimingTest", '/root/ptftests', params=params)

@pytest.fixture(scope="module")
def conn_graph_facts(testbed_devices):
    dut = testbed_devices["dut"]
    return get_conn_graph_facts(testbed_devices, dut.hostname)

def get_conn_graph_facts(testbed_devices, host):
    localhost = testbed_devices["localhost"]

    base_path = os.path.dirname(os.path.realpath(__file__))
    lab_conn_graph_file = os.path.join(base_path, "../ansible/files/lab_connection_graph.xml")
    result = localhost.conn_graph_facts(host=host, filename=lab_conn_graph_file)['ansible_facts']
    return result

def set_interface_lacp_rate(vm_host, intf, mode):
    vm_host.eos_config(
        lines=['lacp rate %s' % mode],
        parents='interface %s' % intf)
    logging.info("Set interface [%s] lacp rate to [%s]" % (intf, mode))