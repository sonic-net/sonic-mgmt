import logging
import pytest
from .args.qos_sai_args import add_qos_sai_args
from .args.buffer_args import add_dynamic_buffer_calculation_args
from tests.common.errors import RunAnsibleModuleFail

# QoS pytest arguments
def pytest_addoption(parser):
    '''
        Adds option to QoS pytest

        Args:
            parser: pytest parser object

        Returns:
            None
    '''
    add_qos_sai_args(parser)
    add_dynamic_buffer_calculation_args(parser)

@pytest.fixture(scope="function")
def singleMemberPort(duthost, mg_facts):
    '''
        Installs static route for a port that is either a single-member lag or not part of a port channel.
    '''
    dst_port = None
    # Try to find a port with no port channel
    all_lag_members = []
    for lag_dict in mg_facts["minigraph_portchannels"].values():
        all_lag_members += lag_dict["members"]
    all_ports = mg_facts["minigraph_ports"].keys()
    non_lag_ports = set(all_ports) - set(all_lag_members)
    assert len(non_lag_ports) > 0, "Failed to find either a single-member lag or a non-lag port"
    dst_port = non_lag_ports.pop()
    if dst_port == None:
        # Only port-channels were found, so try to find a single-member LAG
        for lag_dict in mg_facts["minigraph_portchannels"].values():
            if len(lag_dict["members"]) == 1:
                dst_port = lag_dict["members"][0]
                break
    assert dst_port != None, "Failed to find an invidivual port for testing"
    yield dst_port

@pytest.fixture(scope='class', autouse=False)
def static_route_for_splitvoq(self, dutConfig):
    """
        Add a static route for split-voq testing.
    """
    duthost = dutConfig['dutInstance']
    asic =  duthost.asic_instance().asic_index
    try:
        duthost.shell("ip netns exec asic{} config route add prefix 40.0.0.0/24 nexthop {}".format(
            asic, dutConfig['testPortIps'][dutConfig["testPorts"]["dst_port_id"]]['peer_addr']))
    except RunAnsibleModuleFail:
        duthost.shell("config route add prefix 40.0.0.0/24 nexthop {}".format(
            dutConfig['testPortIps'][dutConfig["testPorts"]["dst_port_id"]]['peer_addr']))

    yield "40.0.0.4"

    try:
        duthost.shell("ip netns exec asic{} config route del prefix 40.0.0.0/24 nexthop {}".format(
            asic, dutConfig['testPortIps'][dutConfig["testPorts"]["dst_port_id"]]['peer_addr']))
    except RunAnsibleModuleFail:
        duthost.shell("config route del prefix 40.0.0.0/24 nexthop {}".format(
            dutConfig['testPortIps'][dutConfig["testPorts"]["dst_port_id"]]['peer_addr']))
    return


@pytest.fixture(scope="function")
def nearbySourcePorts(duthost, mg_facts, singleMemberPort, tbinfo):
    # Find 2 appropriate source ports, starting from the lowest IDs for testing
    # consistency, and avoiding the singleMemberPort
    ports_and_ids = mg_facts["minigraph_port_indices"].items()
    ports_and_ids.sort(key=lambda tup: tup[1])
    all_ports = [tup[0] for tup in ports_and_ids]
    # Remove extra ports that are in same lag
    for lag_dict in mg_facts["minigraph_portchannels"].values():
        for extra_lag_member in lag_dict["members"][1:]:
            all_ports.remove(extra_lag_member)
    all_ports.remove(singleMemberPort)
    # Find nearby ports
    nearby_ports = []
    single_slc = None
    for intf in all_ports:
        if '-BP' in intf:
            # Can't use BackPlane ports.
            next
        try:
            asic = duthost.asic_instance().asic_index
            lanes = duthost.shell('sonic-db-cli -n asic{} CONFIG_DB hget "PORT|{}" lanes'.format(asic, intf))['stdout'].split(',')
        except RunAnsibleModuleFail:
            lanes = duthost.shell('sonic-db-cli CONFIG_DB hget "PORT|{}" lanes'.format(intf))['stdout'].split(',')
        assert len(lanes) > 0, "Lanes not found for port {}".format(port)
        slc = int(lanes[0]) >> 9
        if single_slc == None:
            single_slc = slc
            nearby_ports.append(intf)
        elif slc == single_slc:
            nearby_ports.append(intf)
            break
    assert len(nearby_ports) >= 2, "Failed to find 2 nearby ports, found {}".format(str(nearby_ports))
    extended_minigraph_facts = duthost.get_extended_minigraph_facts(tbinfo)
    nearby_port_id_1 = extended_minigraph_facts["minigraph_ptf_indices"][nearby_ports[0]]
    nearby_port_id_2 = extended_minigraph_facts["minigraph_ptf_indices"][nearby_ports[1]]
    yield (nearby_port_id_1, nearby_port_id_2)

