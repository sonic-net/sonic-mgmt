import pytest
import json
import logging

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory, skip_traffic_test   # noqa F401
from tests.ptf_runner import ptf_runner
from datetime import datetime
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor_m    # noqa F401
from tests.common.utilities import get_neighbor_ptf_port_list
from tests.common.helpers.constants import UPSTREAM_NEIGHBOR_MAP
pytestmark = [
    pytest.mark.topology('t0', 'm0', 'mx')
]

logger = logging.getLogger(__name__)

PTF_TEST_PORT_MAP = '/root/ptf_test_port_map.json'


def get_ptf_src_ports(tbinfo, duthost):
    # Source ports are upstream ports
    upstream_neightbor_name = UPSTREAM_NEIGHBOR_MAP[tbinfo["topo"]["type"]]
    ptf_src_ports = get_neighbor_ptf_port_list(duthost, upstream_neightbor_name, tbinfo)
    return ptf_src_ports


def get_ptf_dst_ports(duthost, mg_facts, testbed_type):
    if "dualtor" in testbed_type:
        # In dualtor, only active port in active tor could be dst port
        mux_status_out = duthost.show_and_parse("show mux status")
        mux_active_ports = []
        for mux_info in mux_status_out:
            if mux_info['status'] == 'active':
                mux_active_ports.append(mux_info['port'])

    vlan_ip_port_pair = {}
    for vlan_intf in mg_facts['minigraph_vlan_interfaces']:
        vlan_subnet = vlan_intf["subnet"]
        vlan_name = vlan_intf["attachto"]

        ptf_dst_ports = []
        for member in mg_facts['minigraph_vlans'][vlan_name]['members']:
            if "Ethernet" in member:
                if "dualtor" not in testbed_type:
                    ptf_dst_ports.append(mg_facts['minigraph_port_indices'][member])
                elif member in mux_active_ports:
                    ptf_dst_ports.append(mg_facts['minigraph_port_indices'][member])

        if ptf_dst_ports:
            vlan_ip_port_pair[vlan_subnet] = ptf_dst_ports

    return vlan_ip_port_pair


def ptf_test_port_map(duthost, ptfhost, mg_facts, testbed_type, tbinfo):
    ptf_test_port_map = {}
    ptf_src_ports = get_ptf_src_ports(tbinfo, duthost)
    vlan_ip_port_pair = get_ptf_dst_ports(duthost, mg_facts, testbed_type)

    ptf_test_port_map = {
        'ptf_src_ports': ptf_src_ports,
        'vlan_ip_port_pair': vlan_ip_port_pair
    }
    ptfhost.copy(content=json.dumps(ptf_test_port_map), dest=PTF_TEST_PORT_MAP)


def test_dir_bcast(duthosts, rand_one_dut_hostname, ptfhost, tbinfo,
                   toggle_all_simulator_ports_to_rand_selected_tor_m, skip_traffic_test):      # noqa F811
    duthost = duthosts[rand_one_dut_hostname]
    testbed_type = tbinfo['topo']['name']

    # Copy VLAN information file to PTF-docker
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    ptf_test_port_map(duthost, ptfhost, mg_facts, testbed_type, tbinfo)

    # Start PTF runner
    params = {
        'testbed_type': testbed_type,
        'router_mac': duthost.facts['router_mac'],
        'ptf_test_port_map': PTF_TEST_PORT_MAP
    }
    log_file = "/tmp/dir_bcast.BcastTest.{}.log".format(datetime.now().strftime("%Y-%m-%d-%H:%M:%S"))
    if skip_traffic_test is True:
        return
    ptf_runner(
        ptfhost,
        'ptftests',
        'dir_bcast_test.BcastTest',
        '/root/ptftests',
        params=params,
        log_file=log_file,
        is_python3=True)
