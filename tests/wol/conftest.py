import pytest
import random
import logging


@pytest.fixture(scope="module")
def get_connected_dut_intf_to_ptf_index(duthost, tbinfo):
    disabled_host_interfaces = tbinfo['topo']['properties']['topology'].get('disabled_host_interfaces', [])
    connected_ptf_ports_idx = [interface for interface in
                               tbinfo['topo']['properties']['topology'].get('host_interfaces', [])
                               if interface not in disabled_host_interfaces]
    dut_intf_to_ptf_index = duthost.get_extended_minigraph_facts(tbinfo)['minigraph_ptf_indices']
    connected_dut_intf_to_ptf_index = [(k, v) for k, v in dut_intf_to_ptf_index.items() if v in connected_ptf_ports_idx]

    yield connected_dut_intf_to_ptf_index


@pytest.fixture(scope="function")
def random_intf_pair(get_connected_dut_intf_to_ptf_index):
    connected_dut_intf_to_ptf_index = get_connected_dut_intf_to_ptf_index
    random_dut_intf, random_ptf_intf = random.choice(connected_dut_intf_to_ptf_index)
    logging.info("Test with random dut intf {} and ptf intf index {}"
                 .format(random_dut_intf, random_ptf_intf))
    return (random_dut_intf, random_ptf_intf)


@pytest.fixture(scope="function")
def dst_ip(request, random_intf_pair, ptfhost):
    ip = request.param
    if ip:
        ptfhost.shell("ifconfig eth{} {}".format(random_intf_pair[1], ip))
        yield ip
        ptfhost.shell("ifconfig eth{} 0.0.0.0".format(random_intf_pair[1]))
