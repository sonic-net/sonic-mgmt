import pytest
import logging
from tests.common.helpers.assertions import pytest_require, pytest_assert                            # noqa: F401
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, \
     fanout_graph_facts_multidut                                                                     # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
     snappi_api, multidut_snappi_ports_for_bgp                                                       # noqa: F401
from tests.snappi_tests.variables import (
    TOPOLOGY_T2_PIZZABOX,
    detect_topology_and_vendor, get_device_hostnames,
    get_lower_tier_snappi_ports, get_uplink_portchannel_members
)                                                                                                    # noqa: F401
from tests.snappi_tests.bgp.files.bgp_outbound_helper import run_bgp_outbound_link_flap_test         # noqa: F401
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams                           # noqa: F401

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology('multidut-tgen')]

FLAP_DETAILS = {
        'device_name': 'Ixia',
        'port_name': 'Snappi_Uplink_PO_1_Link_1'
    }

ITERATION = 1
ROUTE_RANGES = [{
                    'IPv4': [
                        ['100.1.1.1', 24, 15000],
                        ['200.1.1.1', 24, 15000]
                    ],
                    'IPv6': [
                        ['5000::1', 64, 15000],
                        ['4000::1', 64, 15000]
                    ],
                }]


def test_bgp_outbound_uplink_po_member_flap(snappi_api,                                     # noqa: F811
                                            multidut_snappi_ports_for_bgp,                # noqa: F811
                                            conn_graph_facts,                             # noqa: F811
                                            fanout_graph_facts_multidut,                   # noqa: F811
                                            duthosts,
                                            creds,
                                            record_property):
    """
    Gets the packet loss duration on flapping portchannel member in uplink side

    Args:
        snappi_api (pytest fixture): SNAPPI session
        multidut_snappi_ports_for_bgp (pytest fixture):  Port mapping info on multidut testbed
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        creds (pytest fixture): DUT credentials
    Returns:
        N/A
    """
    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.ROUTE_RANGES = ROUTE_RANGES
    snappi_extra_params.iteration = ITERATION
    snappi_extra_params.test_name = "T2 Uplink Portchannel Member Flap"
    snappi_extra_params.multi_dut_params.flap_details = FLAP_DETAILS

    ansible_dut_hostnames = [duthost.hostname for duthost in duthosts]
    topology_type, vendor = detect_topology_and_vendor(ansible_dut_hostnames)
    if vendor is None:
        pytest_require(False, "Unknown Vendor/HW Platform")
    logger.info("Vendor: {}".format(vendor))
    logger.info("Topology Type: {}".format(topology_type))

    device_hostnames = get_device_hostnames(topology_type, vendor)
    lower_tier_snappi_port_list = get_lower_tier_snappi_ports(topology_type, vendor)

    # Skip the test if the uplink_portchannels has less than 2 members
    portchannel_data = get_uplink_portchannel_members(topology_type, vendor)

    po0_list = []
    if 'asic0' in portchannel_data:
        po0_list = portchannel_data['asic0']['PortChannel0']
    elif None in portchannel_data:
        po0_list = portchannel_data[None]['PortChannel0']
    else:
        po0_list = portchannel_data.get('PortChannel0', [])

    pytest_require(len(po0_list) >= 2, "Portchannel has less than 2 members")

    if topology_type == TOPOLOGY_T2_PIZZABOX:
        # Pizzabox: Single DUT handles both uplink and downlink
        snappi_extra_params.multi_dut_params.duthost1 = duthosts[0]
        snappi_extra_params.multi_dut_params.t1_hostname = device_hostnames[0]  # Lower Tier
    else:
        # T2 Chassis: Multiple DUTs
        for duthost in duthosts:
            if device_hostnames[1] in duthost.hostname:  # Uplink LC
                snappi_extra_params.multi_dut_params.duthost1 = duthost
            elif device_hostnames[2] in duthost.hostname:  # Downlink LC
                snappi_extra_params.multi_dut_params.duthost2 = duthost
        snappi_extra_params.multi_dut_params.t1_hostname = device_hostnames[0]  # T1

    snappi_extra_params.multi_dut_params.multi_dut_ports = list(multidut_snappi_ports_for_bgp)
    snappi_extra_params.multi_dut_params.multi_dut_ports.extend(lower_tier_snappi_port_list)
    snappi_extra_params.multi_dut_params.vendor = vendor
    run_bgp_outbound_link_flap_test(api=snappi_api,
                                    creds=creds,
                                    snappi_extra_params=snappi_extra_params,
                                    record_property=record_property)
