import pytest


@pytest.fixture(scope="module")
def get_connected_dut_intf_to_ptf_index(duthost, tbinfo):
    disabled_host_interfaces = tbinfo['topo']['properties']['topology'].get('disabled_host_interfaces', [])
    connected_ptf_ports_idx = [interface for interface in
                               tbinfo['topo']['properties']['topology'].get('host_interfaces', [])
                               if interface not in disabled_host_interfaces]
    dut_intf_to_ptf_index = duthost.get_extended_minigraph_facts(tbinfo)['minigraph_ptf_indices']
    connected_dut_intf_to_ptf_index = [(k, v) for k, v in dut_intf_to_ptf_index.items() if v in connected_ptf_ports_idx]

    yield connected_dut_intf_to_ptf_index
