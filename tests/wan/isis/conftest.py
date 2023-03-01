import re
import pytest
import functools

from isis_helpers import setup_isis
from isis_helpers import teardown_isis


def pytest_addoption(parser):
    """
    Adds pytest options that are used by swan agent tests
    """
    parser.addoption("--swan_agent", action="store_true", default=False,
                     help="Enable swan agent test on wan testbed")


def get_target_dut_port(mg_facts, dut_intf):
    for k, v in mg_facts['minigraph_portchannels'].items():
        if dut_intf in v['members']:
            dut_port = k
            # One member interface would only exist in one Portchannel.
            break
    return dut_port


def get_dut_port_p2p(mg_facts, dut_port):
    for p2p in mg_facts['minigraph_portchannel_interfaces']:
        if p2p['attachto'] == dut_port:
            return (p2p['subnet'], p2p['peer_addr'])


def parse_vm_vlan_port(vlan):
    if isinstance(vlan, int):
        dut_index = 0
        vlan_index = vlan
        ptf_index = vlan
    else:
        m = re.match(r"(\d+)\.(\d+)@(\d+)", vlan)
        (dut_index, vlan_index, ptf_index) = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    return (dut_index, vlan_index, ptf_index)


def port_indice_to_name(dut_host, tbinfo, port_indice):
    mg_facts = dut_host.get_extended_minigraph_facts(tbinfo)
    indice_port_map = dict(zip(mg_facts['minigraph_port_indices'].values(), mg_facts['minigraph_port_indices'].keys()))
    return indice_port_map[port_indice]


def get_dut_isis_dpg_topo(dut_host, nbrhosts, duts_interconnects, tbinfo):
    connections = []
    mg_facts = dut_host.get_extended_minigraph_facts(tbinfo)
    for k, v in mg_facts['minigraph_neighbors'].items():
        if v['name'] in nbrhosts:
            dut_port = get_target_dut_port(mg_facts, k)
            nbr_port = nbrhosts[v['name']]['host'].get_portchannel_by_member(v['port'])
            if nbr_port and dut_port:
                connections.append((dut_host, dut_port, nbrhosts[v['name']]['host'], nbr_port))

    for (dut1_host, dut1_port_index, dut2_host, dut2_port_index) in duts_interconnects:
        if dut1_host == dut_host:
            dut1_port = get_target_dut_port(
                mg_facts,
                port_indice_to_name(dut1_host, tbinfo, dut1_port_index))
            dut2_port = get_target_dut_port(
                dut2_host.get_extended_minigraph_facts(tbinfo),
                port_indice_to_name(dut2_host, tbinfo, dut2_port_index))
            connections.append((dut1_host, dut1_port, dut2_host, dut2_port))

    return connections


@pytest.fixture(scope="session")
def duts_interconnects(duthosts, tbinfo):
    connections = []
    dut_names = [dut.hostname for dut in duthosts]
    dut_index_map = dict(zip(tbinfo['duts_map'].values(), tbinfo['duts_map'].keys()))
    if 'devices_interconnect_interfaces' in tbinfo['topo']['properties']['topology']:
        for _, items in tbinfo['topo']['properties']['topology']['devices_interconnect_interfaces'].items():
            assert(len(items) == 2)
            connect = []
            for item in items:
                (dut_index, vlan_index, _) = parse_vm_vlan_port(item)
                if dut_index not in dut_index_map or dut_index_map[dut_index] not in dut_names:
                    break
                connect.extend([duthosts[dut_index_map[dut_index]], vlan_index])
            else:
                connections.append(tuple(connect))
    return connections


@pytest.fixture(scope="session")
def isis_dpg_topo(duthosts, nbrhosts, duts_interconnects, tbinfo):
    dpg_topo_list = []
    for dut_host in duthosts:
        dpg_topo_list.extend(get_dut_isis_dpg_topo(dut_host, nbrhosts, duts_interconnects, tbinfo))
    return list(dict.fromkeys(dpg_topo_list))


@pytest.fixture(scope="module")
def isis_common_setup_teardown(isis_dpg_topo, request, rand_selected_dut):
    dut_host = rand_selected_dut
    selected_connections = []
    if request.config.getoption("--swan_agent"):
        selected_connections = isis_dpg_topo
    else:
        for item in isis_dpg_topo:
            if dut_host == item[0]:
                selected_connections.append(item)
                break

    if not selected_connections:
        pytest.skip('No target device found in isis testcase {}.'.format(request.node.name))

    setup_isis(selected_connections)
    request.addfinalizer(functools.partial(teardown_isis, selected_connections))
    yield selected_connections
