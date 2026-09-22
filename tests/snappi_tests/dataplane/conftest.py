"""Pytest fixtures for snappi dataplane tests."""
import pytest


@pytest.fixture(scope="module")
def set_primary_chassis(snappi_api, fanout_graph_facts_multidut, duthosts):
    """Set primary chassis for multi-chassis Ixia setups."""
    from tests.common.helpers.assertions import pytest_assert

    primary_chassis = duthosts[0].host.options['variable_manager'] \
        ._hostvars[duthosts[0].hostname].get('chassis_chain_primary', None)
    if len(fanout_graph_facts_multidut) == 1 and primary_chassis:
        slave_chassis = [
            fanout_graph_facts_multidut[fanout]['device_info']['mgmtip']
            for fanout in fanout_graph_facts_multidut
        ]
    elif len(fanout_graph_facts_multidut) > 1:
        slave_chassis = []
        for fanout in fanout_graph_facts_multidut:
            if 'primary' in fanout_graph_facts_multidut[fanout]['device_info']['Type'].lower():
                primary_chassis = fanout_graph_facts_multidut[fanout]['device_info']['mgmtip']
            else:
                slave_chassis.append(fanout_graph_facts_multidut[fanout]['device_info']['mgmtip'])
        if not primary_chassis:
            pytest_assert(False, "No primary chassis found in the ansible/ devices.csv file")
    else:
        return False
    ixnconfig = snappi_api.ixnet_specific_config
    chassis_chain1 = ixnconfig.chassis_chains.add()
    chassis_chain1.primary = primary_chassis
    chassis_chain1.topology = chassis_chain1.STAR
    slaves = [    # noqa F841
        chassis_chain1.secondary.add(
            location=slave,
            sequence_id=index,
            cable_length='6'
        )
        for index, slave in enumerate(slave_chassis, start=2)
    ]
    return snappi_api


@pytest.fixture(scope="module")
def create_snappi_config(snappi_api, get_snappi_ports):
    """Create snappi configuration builder."""
    from tests.snappi_tests.dataplane.files.helper import create_snappi_l1config
    from tests.common.helpers.assertions import pytest_assert

    def _create_snappi_config(snappi_extra_params):
        pytest_assert(snappi_extra_params.protocol_config, "No protocol configuration provided in snappi_extra_params")

        # Extract actual ports from protocol_config instead of using all get_snappi_ports
        actual_ports = []
        for role, pconfig in snappi_extra_params.protocol_config.items():
            actual_ports.extend(pconfig['ports'])

        config = create_snappi_l1config(snappi_api, actual_ports, snappi_extra_params)
        snappi_obj_handles = {k: {"ip": [], "network_group": []} for k in snappi_extra_params.protocol_config}

        for role, pconfig in snappi_extra_params.protocol_config.items():
            is_ipv4 = True if pconfig['subnet_type'] == 'IPv4' else False
            for index, port_data in enumerate(pconfig['ports']):
                device = config.devices.device(name=f"{role} Topology {index}")[-1]
                eth = device.ethernets.add(name=f"{role} Ethernet_{index}", mac=port_data["src_mac_address"])
                eth.connection.port_name = f"Port_{port_data['port_id']}"
                ip_name = f"{role} {'IPv4' if is_ipv4 else 'IPv6'}_{index}"
                ip_layer = getattr(eth, 'ipv4_addresses' if is_ipv4 else 'ipv6_addresses').add(
                    name=ip_name,
                    address=port_data["ipAddress"],
                    gateway=port_data["ipGateway"],
                    prefix=int(port_data["prefix"])
                )
                snappi_obj_handles[role]["ip"].append(ip_layer.name)

                if pconfig.get("protocol_type", False) and pconfig['protocol_type'] == "bgp":
                    bgp = device.bgp
                    bgp.router_id = port_data["ipGateway"] if is_ipv4 else '1.1.1.1'
                    iface = bgp.ipv4_interfaces.add() if is_ipv4 else bgp.ipv6_interfaces.add()
                    setattr(iface, 'ipv4_name' if is_ipv4 else 'ipv6_name', ip_layer.name)
                    peer = iface.peers.add(
                        name=f"{role} BGP{'' if is_ipv4 else '+'}_{index}",
                        as_type='ebgp',
                        peer_address=port_data["ipGateway"],
                        as_number=port_data["asn"]
                    )

                    if 'route_ranges' in pconfig and pconfig['route_ranges']:
                        for route_range in pconfig['route_ranges']:
                            v4_routes = peer.v4_routes.add(
                                name=f"{role} Network Group {index}",
                                addresses=route_range
                            )
                            v4_routes.addresses.add(
                                address=route_range[0],
                                prefix=route_range[1],
                                count=route_range[2]
                            )
                            snappi_obj_handles[role]["network_group"].append(v4_routes.name)

        return config, snappi_obj_handles

    return _create_snappi_config
