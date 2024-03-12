import logging
import os
import pytest
import yaml
from .args.qos_sai_args import add_qos_sai_args
from .args.buffer_args import add_dynamic_buffer_calculation_args

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
    assert len(
        non_lag_ports) > 0, "Failed to find either a single-member lag or a non-lag port"
    dst_port = non_lag_ports.pop()
    if dst_port is None:
        # Only port-channels were found, so try to find a single-member LAG
        for lag_dict in mg_facts["minigraph_portchannels"].values():
            if len(lag_dict["members"]) == 1:
                dst_port = lag_dict["members"][0]
                break
    assert dst_port is not None, "Failed to find an invidivual port for testing"
    yield dst_port


@pytest.fixture(scope="function")
def singleMemberPortStaticRoute(duthost, singleMemberPort, mg_facts):
    port = singleMemberPort
    port_id = mg_facts["minigraph_port_indices"][port]
    # Injected traffic should use this IP as the destination to use the static route
    static_route_ip = "40.0.0.0"
    # Find peer addr for dest port
    port_peer_addr = None
    for intf_dict in mg_facts["minigraph_interfaces"]:
        if intf_dict["attachto"] == port:
            port_peer_addr = intf_dict["peer_addr"]
            break
    assert port_peer_addr is not None, "Failed to find peer address for port {}".format(
        port)

    def insert_prefix(add):
        command = 'config route {} prefix {}/24 nexthop {} {}'.format(
            "add" if add else "del", static_route_ip, port_peer_addr, port)
        logging.debug("Configuring static route: {}".format(command))
        duthost.shell(command)
        # Some tests reboot after this fixture, so save config
        duthost.shell("config save -y")
    insert_prefix(True)
    yield port_id, static_route_ip
    insert_prefix(False)


@pytest.fixture(scope="function")
def nearbySourcePorts(duthost, mg_facts, singleMemberPort):
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
        lanes = duthost.shell(
            'redis-cli -n 4 hget "PORT|{}" lanes'.format(intf))['stdout'].split(',')
        assert len(lanes) > 0, "Lanes not found for port {}".format(intf)
        slc = int(lanes[0]) >> 9
        if single_slc is None:
            single_slc = slc
            nearby_ports.append(intf)
        elif slc == single_slc:
            nearby_ports.append(intf)
            break
    assert len(nearby_ports) >= 2, "Failed to find 2 nearby ports, found {}".format(
        str(nearby_ports))
    nearby_port_id_1 = mg_facts["minigraph_port_indices"][nearby_ports[0]]
    nearby_port_id_2 = mg_facts["minigraph_port_indices"][nearby_ports[1]]
    yield (nearby_port_id_1, nearby_port_id_2)


@pytest.fixture(scope="module", autouse=True)
def combine_qos_parameter():

    def merge_dicts(dict1, dict2):
        merged_dict = dict1.copy()
        for key, value in dict2.items():
            if key in merged_dict and isinstance(merged_dict[key], dict) and isinstance(value, dict):
                merged_dict[key] = merge_dicts(merged_dict[key], value)
            else:
                merged_dict[key] = value
        return merged_dict

    folder_path = "qos/files"
    output_file = "qos/files/qos.yml"
    yaml_files = [file for file in os.listdir(folder_path) if file.endswith(".yaml")]

    combined_yaml = {}
    for file in yaml_files:
        file_path = os.path.join(folder_path, file)
        with open(file_path, "r") as ifp:
            part_dict = yaml.safe_load(ifp)
            combined_yaml = merge_dicts(combined_yaml, part_dict)

    with open(output_file, "w") as ofp:
        yaml.dump(combined_yaml, ofp, default_flow_style=False)
