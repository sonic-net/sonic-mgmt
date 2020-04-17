import pytest

import json
import time
import logging
import os

from ptf_runner import ptf_runner
from common.devices import AnsibleHostBase
from common.fixtures.conn_graph_facts import conn_graph_facts
from common.utilities import wait_until

@pytest.fixture(scope="module")
def common_setup_teardown(duthost, ptfhost, testbed, conn_graph_facts):
    logging.info("########### Setup for lag testing ###########")

    lag_facts = duthost.lag_facts(host = duthost.hostname)['ansible_facts']['lag_facts']
    fanout_neighbors = conn_graph_facts['device_conn']

    if lag_facts['names'] == []:
        pytest.skip("No lag configuration found in %s" % duthost.hostname)

    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
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

    yield duthost, ptfhost, vm_neighbors, mg_facts, lag_facts, fanout_neighbors

def test_lag_2(common_setup_teardown, nbrhosts):
    duthost, ptfhost, vm_neighbors, mg_facts, lag_facts, fanout_neighbors = common_setup_teardown

    # Test for each lag
    for lag_name in lag_facts['names']:
        try:
            lag_facts['lags'][lag_name]['po_config']['runner']['min_ports']
        except:
            logging.info("Skip [check_single_lag_lacp_rate] for lag (%s) due to min_ports not exists" % lag_name)
            logging.info("Skip [check_single_lag] for lag (%s) due to min_ports not exists" % lag_name)
            continue
        else:
            check_single_lag_lacp_rate(common_setup_teardown, nbrhosts, lag_name)
            check_single_lag(common_setup_teardown, nbrhosts, lag_name)

        try:
            lag_facts['lags'][lag_name]['po_config']['runner']['fallback']
        except:
            logging.info("Skip [check_lag_fallback] for lag (%s) due to fallback was not set for it" % lag_name)
        else:
            check_lag_fallback(common_setup_teardown, nbrhosts, lag_name)

def check_single_lag_lacp_rate(common_setup_teardown, nbrhosts, lag_name):
    duthost, ptfhost, vm_neighbors, mg_facts, lag_facts, fanout_neighbors = common_setup_teardown
    logging.info("Start checking single lag lacp rate for: %s" % lag_name)
    
    intf, po_interfaces = get_lag_intfs(lag_facts, lag_name)
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

def check_single_lag(common_setup_teardown, nbrhosts, lag_name):
    duthost, ptfhost, vm_neighbors, mg_facts, lag_facts, fanout_neighbors = common_setup_teardown
    logging.info("Start checking single lag for: %s" % lag_name)

    intf, po_interfaces = get_lag_intfs(lag_facts, lag_name)
    po_flap = check_flap(lag_facts, lag_name)

    # Figure out fanout switches info if exists for the lag member and run minlink test
    if intf in fanout_neighbors.keys():
        peer_device = fanout_neighbors[intf]['peerdevice']
        neighbor_interface = fanout_neighbors[intf]['peerport']
        vm_host = nbrhosts[peer_device]
        verify_lag_minlink(duthost, vm_host, lag_name, peer_device, intf, neighbor_interface, po_interfaces, po_flap, deselect_time=5)

    # Figure out remote VM and interface info for the lag member and run minlink test
    peer_device = vm_neighbors[intf]['name']
    neighbor_interface = vm_neighbors[intf]['port']
    vm_host = nbrhosts[peer_device]
    verify_lag_minlink(duthost, vm_host, lag_name, peer_device, intf, neighbor_interface, po_interfaces, po_flap, deselect_time=95)

def check_lag_fallback(common_setup_teardown, nbrhosts, lag_name):
    duthost, ptfhost, vm_neighbors, mg_facts, lag_facts, fanout_neighbors = common_setup_teardown
    logging.info("Start checking lag fall back for: %s" % lag_name)
    intf, po_interfaces = get_lag_intfs(lag_facts, lag_name)
    po_fallback = lag_facts['lags'][lag_name]['po_config']['runner']['fallback']

    # Figure out remote VM and interface info for the lag member and run lag fallback test
    peer_device = vm_neighbors[intf]['name']
    neighbor_interface = vm_neighbors[intf]['port']
    vm_host = nbrhosts[peer_device]

    try:
        # Shut down neighbor interface
        vm_host.shutdown(neighbor_interface)
        time.sleep(120)

        # Refresh lag facts
        lag_facts = duthost.lag_facts(host = duthost.hostname)['ansible_facts']['lag_facts']

        # Get teamshow result
        teamshow_result = duthost.shell('teamshow')
        logging.info("Teamshow result: %s" % teamshow_result)

        # Verify lag members
        # 1. All other lag should keep selected state
        # 2. Shutdown port should keep selected state if fallback enabled
        # 3. Shutdown port should marded as deselected if fallback disabled
        #  is marked deselected for the shutdown port and all other lag member interfaces are marked selected
        for po_intf in po_interfaces.keys():
            if po_intf != intf or po_fallback:
                assert lag_facts['lags'][lag_name]['po_stats']['ports'][po_intf]['runner']['selected']
            else:
                assert not lag_facts['lags'][lag_name]['po_stats']['ports'][po_intf]['runner']['selected']

        # The portchannel should marked Up/Down correctly according to po fallback setting
        if po_fallback:
            assert lag_facts['lags'][lag_name]['po_intf_stat'] == 'Up'
        else:
            assert lag_facts['lags'][lag_name]['po_intf_stat'] == 'Down'

    finally:
        # Bring up neighbor interface
        vm_host.no_shutdown(neighbor_interface)
        time.sleep(30)

        # Refresh lag facts
        lag_facts = duthost.lag_facts(host = duthost.hostname)['ansible_facts']['lag_facts']

        # Verify all interfaces in port_channel are marked up
        for po_intf in po_interfaces.keys():
            assert lag_facts['lags'][lag_name]['po_stats']['ports'][po_intf]['link']['up'] == True
        
        # Verify portchannel interface are marked up correctly
        assert lag_facts['lags'][lag_name]['po_intf_stat'] == 'Up'


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

def verify_lag_minlink(
    duthost,
    vm_host,
    lag_name,
    peer_device,
    intf,
    neighbor_interface,
    po_interfaces,
    po_flap,
    deselect_time,
    wait_timeout = 30):

    delay = 5
    retries = wait_timeout / delay
    try:
        set_neighbor_interface(vm_host, neighbor_interface, shut=True)

        # Let PortalChannel react to neighbor interface shutdown
        time.sleep(deselect_time)

        # Verify PortChannel interfaces are up correctly
        for po_intf in po_interfaces.keys():
            if po_intf != intf:
                command = 'bash -c "teamdctl %s state dump" | python -c "import sys, json; print json.load(sys.stdin)[\'ports\'][\'%s\'][\'runner\'][\'selected\']"' % (lag_name, po_intf)
                wait_until(wait_timeout, delay, check_shell_output, duthost, command)

        # Refresh lag facts
        lag_facts = duthost.lag_facts(host = duthost.hostname)['ansible_facts']['lag_facts']

        # Verify lag member is marked deselected for the shutdown port and all other lag member interfaces are marked selected
        for po_intf in po_interfaces.keys():
            if po_intf != intf:
                assert lag_facts['lags'][lag_name]['po_stats']['ports'][po_intf]['runner']['selected']
            else:
                assert not lag_facts['lags'][lag_name]['po_stats']['ports'][po_intf]['runner']['selected']

        # Verify PortChannel's interface are marked down/up correctly if it should down/up
        if po_flap == True:
            assert lag_facts['lags'][lag_name]['po_intf_stat'] == 'Down'
        else:
            assert lag_facts['lags'][lag_name]['po_intf_stat'] == 'Up'
    finally:
        # Bring back port in case test error and left testbed in unknow stage
        # Bring up neighbor interface
        set_neighbor_interface(vm_host, neighbor_interface, shut=False)

        # Verify PortChannel interfaces are up correctly
        for po_intf in po_interfaces.keys():
            if po_intf != intf:
                command = 'bash -c "teamdctl %s state dump" | python -c "import sys, json; print json.load(sys.stdin)[\'ports\'][\'%s\'][\'link\'][\'up\']"' % (lag_name, po_intf)
                wait_until(wait_timeout, delay, check_shell_output, duthost, command)

        # Refresh lag facts
        lag_facts = duthost.lag_facts(host = duthost.hostname)['ansible_facts']['lag_facts']
        for po_intf in po_interfaces.keys():
            assert lag_facts['lags'][lag_name]['po_stats']['ports'][po_intf]['runner']['selected'] == True
        
        assert lag_facts['lags'][lag_name]['po_intf_stat'] == 'Up'

def get_lag_intfs(lag_facts, lag_name):
    # Figure out interface informations
    po_interfaces = lag_facts['lags'][lag_name]['po_config']['ports']
    intf = lag_facts['lags'][lag_name]['po_config']['ports'].keys()[0]
    return intf, po_interfaces

def check_flap(lag_facts, lag_name):
    po_intf_num = len(lag_facts['lags'][lag_name]['po_config']['ports'])
    po_min_links = lag_facts['lags'][lag_name]['po_config']['runner']['min_ports']
    return ((po_intf_num - 1) * 100 / po_min_links) < 75

def set_interface_lacp_rate(vm_host, intf, mode):
    vm_host.eos_config(
        lines=['lacp rate %s' % mode],
        parents='interface %s' % intf)
    logging.info("Set interface [%s] lacp rate to [%s]" % (intf, mode))

def set_neighbor_interface(vm_host, neighbor_interface, shut):
    vm_host.eos_config(
        lines=['%sshutdown' % ('' if shut else 'no ')],
        parents='interface %s' % neighbor_interface)
    logging.info('%s interface [%s]' % ('Shut' if shut else 'No shut', neighbor_interface))

def check_shell_output(host, command):
    out = host.shell(command)
    return out['stdout'] == 'True'