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
    get_lower_tier_snappi_ports
)                                                                                                    # noqa: F401
from tests.snappi_tests.bgp.files.bgp_outbound_helper import run_bgp_outbound_ungraceful_restart     # noqa: F401
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams                           # noqa: F401

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology('multidut-tgen')]

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


def test_bgp_outbound_uplink_ungraceful_restart(snappi_api,                                     # noqa: F811
                                                multidut_snappi_ports_for_bgp,                  # noqa: F811
                                                conn_graph_facts,                             # noqa: F811
                                                fanout_graph_facts_multidut,                  # noqa: F811
                                                duthosts,
                                                creds,
                                                record_property):                                # noqa: F811

    """
    Gets the packet loss duration on issuing ungraceful restart in uplink

    Args:
        snappi_api (pytest fixture): SNAPPI session
        multidut_snappi_ports_for_bgp (pytest fixture):  Port mapping info on multidut testbed
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
    Returns:
        N/A
    """
    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.ROUTE_RANGES = ROUTE_RANGES
    snappi_extra_params.iteration = ITERATION
    snappi_extra_params.test_name = "Uplink Ungraceful Re-start"

    ansible_dut_hostnames = [duthost.hostname for duthost in duthosts]
    topology_type, vendor = detect_topology_and_vendor(ansible_dut_hostnames)
    if vendor is None:
        pytest_require(False, "Unknown Vendor/HW Platform")
    logger.info("Vendor: {}".format(vendor))
    logger.info("Topology Type: {}".format(topology_type))

    device_hostnames = get_device_hostnames(topology_type, vendor)
    lower_tier_snappi_port_list = get_lower_tier_snappi_ports(topology_type, vendor)

    if topology_type == TOPOLOGY_T2_PIZZABOX:
        # Pizzabox: Single DUT for both uplink and downlink
        snappi_extra_params.multi_dut_params.duthost1 = duthosts[0]
        snappi_extra_params.multi_dut_params.t1_hostname = device_hostnames[0]  # Lower Tier
        snappi_extra_params.device_name = device_hostnames[1]  # T2 Pizzabox
    else:
        # T2 Chassis: Multiple DUTs
        for duthost in duthosts:
            if device_hostnames[1] in duthost.hostname:  # Uplink LC
                snappi_extra_params.multi_dut_params.duthost1 = duthost
            elif device_hostnames[2] in duthost.hostname:  # Downlink LC
                snappi_extra_params.multi_dut_params.duthost2 = duthost
            elif device_hostnames[3] in duthost.hostname:  # Supervisor
                snappi_extra_params.multi_dut_params.duthost3 = duthost
        snappi_extra_params.multi_dut_params.t1_hostname = device_hostnames[0]  # T1
        snappi_extra_params.device_name = device_hostnames[1]  # Uplink LC

    snappi_extra_params.multi_dut_params.vendor = vendor
    snappi_extra_params.multi_dut_params.multi_dut_ports = list(multidut_snappi_ports_for_bgp)
    snappi_extra_params.multi_dut_params.multi_dut_ports.extend(lower_tier_snappi_port_list)

    run_bgp_outbound_ungraceful_restart(api=snappi_api,
                                        creds=creds,
                                        is_supervisor=False,
                                        snappi_extra_params=snappi_extra_params,
                                        record_property=record_property)


def test_bgp_outbound_downlink_ungraceful_restart(snappi_api,                                     # noqa: F811
                                                  multidut_snappi_ports_for_bgp,                  # noqa: F811
                                                  conn_graph_facts,                             # noqa: F811
                                                  fanout_graph_facts_multidut,                  # noqa: F811
                                                  duthosts,
                                                  creds,
                                                  record_property):                                # noqa: F811

    """
    Gets the packet loss duration on issuing ungraceful restart in downlink

    Args:
        snappi_api (pytest fixture): SNAPPI session
        multidut_snappi_ports_for_bgp (pytest fixture):  Port mapping info on multidut testbed
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
    Returns:
        N/A
    """
    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.ROUTE_RANGES = ROUTE_RANGES
    snappi_extra_params.iteration = ITERATION
    snappi_extra_params.test_name = "Downlink Ungraceful Re-start"

    ansible_dut_hostnames = [duthost.hostname for duthost in duthosts]
    topology_type, vendor = detect_topology_and_vendor(ansible_dut_hostnames)
    if vendor is None:
        pytest_require(False, "Unknown Vendor/HW Platform")
    logger.info("Vendor: {}".format(vendor))
    logger.info("Topology Type: {}".format(topology_type))

    # Skip on pizzabox - no separate downlink LC
    if topology_type == TOPOLOGY_T2_PIZZABOX:
        pytest.skip("Downlink ungraceful restart test not applicable to T2 pizzabox topology (no separate downlink LC)")

    device_hostnames = get_device_hostnames(topology_type, vendor)
    lower_tier_snappi_port_list = get_lower_tier_snappi_ports(topology_type, vendor)

    # T2 Chassis: Multiple DUTs
    for duthost in duthosts:
        if device_hostnames[1] in duthost.hostname:  # Uplink LC
            snappi_extra_params.multi_dut_params.duthost1 = duthost
        elif device_hostnames[2] in duthost.hostname:  # Downlink LC
            snappi_extra_params.multi_dut_params.duthost2 = duthost
        elif device_hostnames[3] in duthost.hostname:  # Supervisor
            snappi_extra_params.multi_dut_params.duthost3 = duthost

    snappi_extra_params.multi_dut_params.t1_hostname = device_hostnames[0]  # T1
    snappi_extra_params.device_name = device_hostnames[2]  # Downlink LC
    snappi_extra_params.multi_dut_params.vendor = vendor
    snappi_extra_params.multi_dut_params.multi_dut_ports = list(multidut_snappi_ports_for_bgp)
    snappi_extra_params.multi_dut_params.multi_dut_ports.extend(lower_tier_snappi_port_list)

    run_bgp_outbound_ungraceful_restart(api=snappi_api,
                                        creds=creds,
                                        is_supervisor=False,
                                        snappi_extra_params=snappi_extra_params,
                                        record_property=record_property)


def test_bgp_outbound_supervisor_ungraceful_restart(snappi_api,                                     # noqa: F811
                                                    multidut_snappi_ports_for_bgp,                  # noqa: F811
                                                    conn_graph_facts,                             # noqa: F811
                                                    fanout_graph_facts_multidut,                  # noqa: F811
                                                    duthosts,
                                                    creds,
                                                    record_property):                                # noqa: F811

    """
    Gets the packet loss duration on issuing ungraceful restart in supervisor

    Args:
        snappi_api (pytest fixture): SNAPPI session
        multidut_snappi_ports_for_bgp (pytest fixture):  Port mapping info on multidut testbed
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
    Returns:
        N/A
    """
    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.ROUTE_RANGES = ROUTE_RANGES
    snappi_extra_params.iteration = ITERATION
    snappi_extra_params.test_name = "Supervisor Ungraceful Re-start"

    ansible_dut_hostnames = [duthost.hostname for duthost in duthosts]
    topology_type, vendor = detect_topology_and_vendor(ansible_dut_hostnames)
    if vendor is None:
        pytest_require(False, "Unknown Vendor/HW Platform")
    logger.info("Vendor: {}".format(vendor))
    logger.info("Topology Type: {}".format(topology_type))

    # Skip on pizzabox - no supervisor card
    if topology_type == TOPOLOGY_T2_PIZZABOX:
        pytest.skip("Supervisor ungraceful restart test not applicable to T2 pizzabox topology (no supervisor card)")

    device_hostnames = get_device_hostnames(topology_type, vendor)
    lower_tier_snappi_port_list = get_lower_tier_snappi_ports(topology_type, vendor)

    # T2 Chassis: Multiple DUTs
    for duthost in duthosts:
        if device_hostnames[1] in duthost.hostname:  # Uplink LC
            snappi_extra_params.multi_dut_params.duthost1 = duthost
        elif device_hostnames[2] in duthost.hostname:  # Downlink LC
            snappi_extra_params.multi_dut_params.duthost2 = duthost
        elif device_hostnames[3] in duthost.hostname:  # Supervisor
            snappi_extra_params.multi_dut_params.duthost3 = duthost

    snappi_extra_params.multi_dut_params.t1_hostname = device_hostnames[0]  # T1
    snappi_extra_params.device_name = device_hostnames[3]  # Supervisor
    snappi_extra_params.multi_dut_params.vendor = vendor
    snappi_extra_params.multi_dut_params.multi_dut_ports = list(multidut_snappi_ports_for_bgp)
    snappi_extra_params.multi_dut_params.multi_dut_ports.extend(lower_tier_snappi_port_list)

    run_bgp_outbound_ungraceful_restart(api=snappi_api,
                                        creds=creds,
                                        is_supervisor=True,
                                        snappi_extra_params=snappi_extra_params,
                                        record_property=record_property)
