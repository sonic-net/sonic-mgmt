import pytest
import functools

from isis_helpers import setup_isis
from isis_helpers import teardown_isis


def get_target_dut_port(mg_facts, dut_intf):
    for k, v in mg_facts['minigraph_portchannels'].items():
        if dut_intf in v['members']:
            dut_port = k
            # One member interface would only exist in one Portchannel.
            break
    return dut_port


def get_dut_isis_dpg_topo(dut_host, nbrhosts, tbinfo):
    connections = []
    mg_facts = dut_host.get_extended_minigraph_facts(tbinfo)
    for k, v in mg_facts['minigraph_neighbors'].items():
        if v['name'] in nbrhosts.keys():
            dut_port = get_target_dut_port(mg_facts, k)
            nbr_port = nbrhosts[v['name']]['host'].get_portchannel_by_member(v['port'])
            if nbr_port and dut_port:
                connections.append((dut_host, dut_port, nbrhosts[v['name']]['host'], nbr_port))
    return connections


@pytest.fixture(scope="session")
def isis_dpg_topo(duthosts, nbrhosts, tbinfo):
    dpg_topo_list = []
    for dut_host in duthosts:
        dpg_topo_list.extend(get_dut_isis_dpg_topo(dut_host, nbrhosts, tbinfo))
    return list(dict.fromkeys(dpg_topo_list))


@pytest.fixture(scope="module")
def isis_common_setup_teardown(isis_dpg_topo, request, rand_selected_dut):
    dut_host = rand_selected_dut
    selected_connections = []
    for item in isis_dpg_topo:
        if dut_host == item[0]:
            selected_connections.append(item)
            break

    if not selected_connections:
        pytest.skip('No target device found in isis testcase {}.'.format(request.node.name))

    setup_isis(selected_connections)
    request.addfinalizer(functools.partial(teardown_isis, selected_connections))
    yield selected_connections
