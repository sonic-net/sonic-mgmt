import pytest
import logging
from tabulate import tabulate # noqa F401
from tests.common.helpers.assertions import pytest_assert     # noqa: F401
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts_multidut         # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
    snappi_api, snappi_dut_base_config, get_snappi_ports, get_snappi_ports_for_rdma, cleanup_config, \
    is_snappi_multidut, get_snappi_ports_multi_dut   # noqa: F401
from tests.common.snappi_tests.qos_fixtures import prio_dscp_map, \
    lossless_prio_list, disable_pfcwd   # noqa F401
from tests.snappi_tests.files.helper import multidut_port_info, setup_ports_and_dut  # noqa: F401
from tests.snappi_tests.multidut.ecn.files.multidut_helper import run_ecn_marking_test, run_ecn_marking_port_toggle_test
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
from tests.common.cisco_data import is_cisco_device
logger = logging.getLogger(__name__)
pytestmark = [pytest.mark.topology('multidut-tgen')]


def validate_snappi_ports(snappi_ports):

    if not is_cisco_device(snappi_ports[0]['duthost']):
        return True

    '''
        One ingress port and the egress port should be on the same DUT and asic.
        The second ingress port can be on diff asic or DUT.
        This is needed to avoid tail drops caused by use of default voq in case
        both the BP ports of egress port are on the same slice

        All ingress and egress port on the same DUT and asic is fine.
    '''

    # Extract duthost and peer_port values for rx_dut and tx_dut configurations
    rx_dut = snappi_ports[0]['duthost']
    rx_peer_port = snappi_ports[0]['peer_port']
    tx_dut_1 = snappi_ports[1]['duthost']
    tx_peer_port_1 = snappi_ports[1]['peer_port']
    tx_dut_2 = snappi_ports[2]['duthost']
    tx_peer_port_2 = snappi_ports[2]['peer_port']

    # get the ASIC namespace for a given duthost and peer_port
    def get_asic(duthost, peer_port):
        return duthost.get_port_asic_instance(peer_port).namespace

    # Retrieve ASIC namespace
    rx_asic = get_asic(rx_dut, rx_peer_port)
    tx_asic_1 = get_asic(tx_dut_1, tx_peer_port_1)
    tx_asic_2 = get_asic(tx_dut_2, tx_peer_port_2)

    # Check if all duthosts and their ASICs are the same
    if (rx_dut == tx_dut_1 == tx_dut_2) and (rx_asic == tx_asic_1 == tx_asic_2):
        return True

    # Check if rx_dut and its ASIC matches either of the tx_dut and their ASIC
    if (rx_dut == tx_dut_1 and rx_asic == tx_asic_1) or (rx_dut == tx_dut_2 and rx_asic == tx_asic_2):
        return True

    return False


@pytest.fixture(autouse=True)
def number_of_tx_rx_ports():
    yield (2, 1)


def test_ecn_marking_port_toggle(
                                snappi_api,                       # noqa: F811
                                conn_graph_facts,                 # noqa: F811
                                fanout_graph_facts_multidut,               # noqa: F811
                                duthosts,
                                lossless_prio_list,     # noqa: F811
                                get_snappi_ports,     # noqa: F811
                                tbinfo,      # noqa: F811
                                disable_pfcwd,  # noqa: F811
                                setup_ports_and_dut,     # noqa: F811
                                prio_dscp_map):                    # noqa: F811
    """
    Verify ECN marking both pre and post port shut/no shut toggle
    Args:
        request (pytest fixture): pytest request object
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        lossless_prio_list (pytest fixture): list of all the lossless priorities
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).
        tbinfo (pytest fixture): fixture provides information about testbed
        get_snappi_ports (pytest fixture): gets snappi ports and connected DUT port info and returns as a list
    Returns:
        N/A
    """

    testbed_config, port_config_list, snappi_ports = setup_ports_and_dut

    logger.info("Snappi Ports : {}".format(snappi_ports))
    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

    try:
        run_ecn_marking_port_toggle_test(
                                api=snappi_api,
                                testbed_config=testbed_config,
                                port_config_list=port_config_list,
                                dut_port=snappi_ports[0]['peer_port'],
                                test_prio_list=lossless_prio_list,
                                prio_dscp_map=prio_dscp_map,
                                snappi_extra_params=snappi_extra_params)
    finally:
        cleanup_config(duthosts, snappi_ports)


test_flow_percent_list = [[90, 15], [53, 49], [15, 90], [49, 49], [50, 50]]


@pytest.mark.parametrize("test_flow_percent", test_flow_percent_list)
def test_ecn_marking_lossless_prio(
                                snappi_api,                       # noqa: F811
                                conn_graph_facts,                 # noqa: F811
                                fanout_graph_facts_multidut,               # noqa: F811
                                duthosts,
                                lossless_prio_list,     # noqa: F811
                                get_snappi_ports,     # noqa: F811
                                tbinfo,      # noqa: F811
                                disable_pfcwd,     # noqa: F811
                                test_flow_percent,
                                prio_dscp_map,  # noqa: F811
                                setup_ports_and_dut):                    # noqa: F811
    """
    Verify ECN marking on lossless prio with same DWRR weight

    Args:
        request (pytest fixture): pytest request object
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        lossless_prio_list (pytest fixture): list of all the lossless priorities
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).
        tbinfo (pytest fixture): fixture provides information about testbed
        test_flow_percent: Percentage of flow rate used for the two lossless prio
        get_snappi_ports (pytest fixture): gets snappi ports and connected DUT port info and returns as a list
    Returns:
        N/A
    """

    testbed_config, port_config_list, snappi_ports = setup_ports_and_dut

    pytest_assert(validate_snappi_ports(snappi_ports), "Invalid combination of duthosts or ASICs in snappi_ports")

    logger.info("Snappi Ports : {}".format(snappi_ports))
    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

    try:
        run_ecn_marking_test(
                                api=snappi_api,
                                testbed_config=testbed_config,
                                port_config_list=port_config_list,
                                dut_port=snappi_ports[0]['peer_port'],
                                test_prio_list=lossless_prio_list,
                                prio_dscp_map=prio_dscp_map,
                                test_flow_percent=test_flow_percent,
                                snappi_extra_params=snappi_extra_params)
    finally:
        cleanup_config(duthosts, snappi_ports)
