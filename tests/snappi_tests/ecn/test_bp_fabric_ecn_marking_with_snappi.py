import pytest
import logging
import random
from tabulate import tabulate  # noqa: F401
from tests.common.helpers.assertions import pytest_assert, pytest_require     # noqa: F401
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts, \
    fanout_graph_facts_multidut         # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
    snappi_api, snappi_dut_base_config, get_snappi_ports, get_snappi_ports_for_rdma, cleanup_config, \
    is_snappi_multidut, get_snappi_ports_multi_dut, get_snappi_ports_single_dut   # noqa: F401
from tests.common.snappi_tests.qos_fixtures import prio_dscp_map, \
    lossless_prio_list, disable_pfcwd   # noqa: F401
from tests.snappi_tests.files.helper import setup_ports_and_dut, enable_debug_shell  # noqa: F401
from tests.snappi_tests.ecn.files.bpfabric_helper import run_fabric_ecn_marking_test, run_backplane_ecn_marking_test
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
from tests.common.cisco_data import is_cisco_device
logger = logging.getLogger(__name__)
pytestmark = [pytest.mark.topology('multidut-tgen')]


@pytest.fixture(autouse=True)
def number_of_tx_rx_ports():
    yield (1, 1)


def validate_snappi_ports(snappi_ports):
    '''
        To use Backplane and fabric ports for traffic
         - the ingress port and the egress port should be on diff DUT.
         - or they both should be on diff asic instance on same DUT
    '''

    # Extract duthost and peer_port values for rx_dut and tx_dut configurations
    rx_dut = snappi_ports[0]['duthost']
    rx_peer_port = snappi_ports[0]['peer_port']
    tx_dut = snappi_ports[1]['duthost']
    tx_peer_port = snappi_ports[1]['peer_port']

    # get the ASIC namespace for a given duthost and peer_port
    def get_asic(duthost, peer_port):
        return duthost.get_port_asic_instance(peer_port).namespace

    # Retrieve ASIC namespace
    rx_asic = get_asic(rx_dut, rx_peer_port)
    tx_asic = get_asic(tx_dut, tx_peer_port)

    if (rx_dut != tx_dut) or (rx_asic != tx_asic):
        pytest_require(is_cisco_device(rx_dut) and is_cisco_device(tx_dut), "Test supported on Cisco DUT only")
        return True

    return False


def test_fabric_ecn_marking_lossless_prio(
                                snappi_api,                       # noqa: F811
                                conn_graph_facts,                 # noqa: F811
                                fanout_graph_facts_multidut,               # noqa: F811
                                duthosts,
                                lossless_prio_list,     # noqa: F811
                                get_snappi_ports,     # noqa: F811
                                tbinfo,      # noqa: F811
                                disable_pfcwd,     # noqa: F811
                                prio_dscp_map,  # noqa: F811
                                setup_ports_and_dut):                    # noqa: F811
    """
    Verify Egress Fabric port to Egress DUT ECN marking on lossless prio

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        lossless_prio_list (pytest fixture): list of all the lossless priorities
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).
        tbinfo (pytest fixture): fixture provides information about testbed
    Returns:
        N/A
    """

    testbed_config, port_config_list, snappi_ports = setup_ports_and_dut

    # find the supervisor DUT as the fabric ports are available in it.
    supervisor_dut = next((duthost for duthost in duthosts if duthost.is_supervisor_node()), None)

    pytest_assert(supervisor_dut, "Supervisor DUT not found")

    pytest_require(is_cisco_device(supervisor_dut), "Test supported on Cisco Supervisor DUT only")

    pytest_require(validate_snappi_ports(snappi_ports), "Invalid combination of duthosts or ASICs in snappi_ports")

    logger.info("Snappi Ports : {}".format(snappi_ports))
    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

    run_fabric_ecn_marking_test(
                            api=snappi_api,
                            testbed_config=testbed_config,
                            port_config_list=port_config_list,
                            dut_port=snappi_ports[0]['peer_port'],
                            test_prio_list=random.sample(lossless_prio_list, 1),
                            prio_dscp_map=prio_dscp_map,
                            supervisor_dut=supervisor_dut,
                            snappi_extra_params=snappi_extra_params)


def test_backplane_ecn_marking_lossless_prio(
                                snappi_api,                       # noqa: F811
                                conn_graph_facts,                 # noqa: F811
                                fanout_graph_facts_multidut,               # noqa: F811
                                duthosts,
                                lossless_prio_list,     # noqa: F811
                                get_snappi_ports,     # noqa: F811
                                tbinfo,      # noqa: F811
                                disable_pfcwd,     # noqa: F811
                                prio_dscp_map,  # noqa: F811
                                setup_ports_and_dut):                    # noqa: F811
    """
    Verify Ingress DUT Egress backplane port ECN marking on lossless prio

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        lossless_prio_list (pytest fixture): list of all the lossless priorities
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).
        tbinfo (pytest fixture): fixture provides information about testbed
    Returns:
        N/A
    """

    testbed_config, port_config_list, snappi_ports = setup_ports_and_dut

    pytest_require(validate_snappi_ports(snappi_ports), "Invalid combination of duthosts or ASICs in snappi_ports")

    logger.info("Snappi Ports : {}".format(snappi_ports))
    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

    run_backplane_ecn_marking_test(
                            api=snappi_api,
                            testbed_config=testbed_config,
                            port_config_list=port_config_list,
                            dut_port=snappi_ports[0]['peer_port'],
                            test_prio_list=random.sample(lossless_prio_list, 1),
                            prio_dscp_map=prio_dscp_map,
                            snappi_extra_params=snappi_extra_params)
