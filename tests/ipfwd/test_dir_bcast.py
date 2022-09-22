import pytest
import os
import yaml
import json
import logging

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # lgtm[py/unused-import]
from tests.common.portstat_utilities import parse_column_positions
from tests.ptf_runner import ptf_runner
from datetime import datetime
from tests.common.dualtor.mux_simulator_control import mux_server_url, toggle_all_simulator_ports_to_rand_selected_tor_m

pytestmark = [
    pytest.mark.topology('t0', 'm0')
]

logger = logging.getLogger(__name__)

PTF_TEST_PORT_MAP = '/root/ptf_test_port_map.json'

def parse_mux_status(output_lines):
    '''Parse the output of "show mux status" command
    Args:
        output_lines (list): The output lines of "show mux status" command
    Returns:
        list: A dictionary, key is interface name, value is a dictionary of fields/values
    '''

    header_line = ''
    separation_line = ''
    separation_line_number = 0
    for idx, line in enumerate(output_lines):
        if line.find('----') >= 0:
            header_line = output_lines[idx-1]
            separation_line = output_lines[idx]
            separation_line_number = idx
            break

    try:
        positions = parse_column_positions(separation_line)
    except Exception:
        logger.error('Possibly bad command output')
        return {}

    headers = []
    for pos in positions:
        header = header_line[pos[0]:pos[1]].strip().lower()
        headers.append(header)

    if not headers:
        return {}

    results = {}
    for line in output_lines[separation_line_number+1:]:
        mux_status = []
        for pos in positions:
            port_status = line[pos[0]:pos[1]].strip()
            mux_status.append(port_status)

        intf = mux_status[0]
        results[intf] = {}
        for idx in range(1, len(mux_status)):    # Skip the first column interface name
            results[intf][headers[idx]] = mux_status[idx]

    return results


def get_ptf_src_ports(mg_facts):
    ptf_src_ports = []
    for pc in mg_facts['minigraph_portchannels']:
        for member in mg_facts['minigraph_portchannels'][pc]['members']:
            ptf_src_ports.append(mg_facts['minigraph_ptf_indices'][member])
    return ptf_src_ports

def get_ptf_dst_ports(duthost, mg_facts, testbed_type):
    if "dualtor" in testbed_type:
        mux_status_out = parse_mux_status(duthost.command("show mux status")["stdout_lines"])
    ptf_dst_ports = []
    for vlan in mg_facts['minigraph_vlans']:
        for member in mg_facts['minigraph_vlans'][vlan]['members']:
            if "dualtor" not in testbed_type:
                ptf_dst_ports.append(mg_facts['minigraph_port_indices'][member])
            elif mux_status_out[member]["status"].replace(",", "") == 'active':
                ptf_dst_ports.append(mg_facts['minigraph_port_indices'][member])
    return ptf_dst_ports

def ptf_test_port_map(duthost, ptfhost, mg_facts, testbed_type):
    ptf_test_port_map = {}
    ptf_src_ports = get_ptf_src_ports(mg_facts)
    ptf_dst_ports = get_ptf_dst_ports(duthost, mg_facts, testbed_type)
    ptf_test_port_map = {
        'ptf_src_ports': ptf_src_ports,
        'ptf_dst_ports': ptf_dst_ports
    }
    ptfhost.copy(content=json.dumps(ptf_test_port_map), dest=PTF_TEST_PORT_MAP)


@pytest.mark.xfail
def test_dir_bcast(duthosts, rand_one_dut_hostname, ptfhost, tbinfo, toggle_all_simulator_ports_to_rand_selected_tor_m):
    duthost = duthosts[rand_one_dut_hostname]
    testbed_type = tbinfo['topo']['name']

    # Copy VLAN information file to PTF-docker
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    extra_vars = {
        'minigraph_vlan_interfaces': mg_facts['minigraph_vlan_interfaces'],
        'minigraph_vlans':           mg_facts['minigraph_vlans'],
        'minigraph_port_indices':    mg_facts['minigraph_ptf_indices'],
        'minigraph_portchannels':    mg_facts['minigraph_portchannels']
    }
    ptfhost.host.options['variable_manager'].extra_vars.update(extra_vars)
    ptfhost.template(src="../ansible/roles/test/templates/fdb.j2", dest="/root/vlan_info.txt")

    ptf_test_port_map(duthost, ptfhost, mg_facts, testbed_type)

    # Start PTF runner
    params = {
        'testbed_type': testbed_type,
        'router_mac': duthost.facts['router_mac'],
        'vlan_info': '/root/vlan_info.txt',
        'ptf_test_port_map': PTF_TEST_PORT_MAP
    }
    log_file = "/tmp/dir_bcast.BcastTest.{}.log".format(datetime.now().strftime("%Y-%m-%d-%H:%M:%S"))
    ptf_runner(
        ptfhost,
        'ptftests',
        'dir_bcast_test.BcastTest',
        '/root/ptftests',
        params=params,
        log_file=log_file,
        is_python3=True)
