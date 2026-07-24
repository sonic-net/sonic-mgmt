import pytest
import logging
import random
from tests.common.helpers.assertions import pytest_require
from tests.snappi_tests.ecn.files.bpfabric_helper import (
    run_fabric_ecn_marking_test,
    run_backplane_ecn_marking_test)
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
from tests.common.cisco_data import is_cisco_device
logger = logging.getLogger(__name__)
pytestmark = [pytest.mark.topology('multidut-tgen')]


@pytest.fixture(autouse=True, scope="module")
def number_of_tx_rx_ports():
    yield (1, 1)


@pytest.fixture
def validate_snappi_ports(tgen_port_info):
    '''
        To use Backplane and fabric ports for traffic
         - the ingress port and the egress port should be on diff DUT.
         - or they both should be on diff asic instance on same DUT
    '''
    _, _, snappi_ports = tgen_port_info

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
        pytest_require(
            is_cisco_device(rx_dut) and is_cisco_device(tx_dut),
            "Test supported on Cisco DUT, multi-asic mode only.")
        return True

    pytest.skip(
        "Test supported on Cisco DUT, multi-asic mode only. Current combination:"
        f"tx_dut:{tx_dut}, rx_dut:{rx_dut}, tx_asic:{tx_asic}, rx_asic:{rx_asic}"
        )
    # To overcome CodeQL mixed-returns error.
    return False


@pytest.fixture
def supervisor_dut_cisco(duthosts):
    dut = next((duthost for duthost in duthosts if duthost.is_supervisor_node()), None)
    pytest_require(dut, "Supervisor DUT not found")
    pytest_require(is_cisco_device(dut), "Test supported on Cisco Supervisor DUT only")
    yield dut


def test_fabric_ecn_marking_lossless_prio(
                                snappi_api,
                                conn_graph_facts,
                                fanout_graph_facts_multidut,
                                duthosts,
                                lossless_prio_list,
                                get_snappi_ports,
                                tbinfo,
                                disable_pfcwd,
                                prio_dscp_map,
                                tgen_port_info,
                                supervisor_dut_cisco,
                                validate_snappi_ports
                                ):
    """
    Verify Egress Fabric port to Egress DUT ECN marking on lossless prio

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        lossless_prio_list (pytest fixture): list of all the lossless priorities
        get_snappi_ports (pytest fixture): Snappi port fixture
        tbinfo (pytest fixture): fixture provides information about testbed
        disable_pfcwd (pytest fixture): disables PFC watchdog
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority)
        tgen_port_info (pytest fixture): Snappi testbed and port details
        supervisor_dut_cisco (pytest fixture): Cisco supervisor DUT handle
        validate_snappi_ports (pytest fixture): validates selected Snappi ports
    Returns:
        N/A
    """

    testbed_config, port_config_list, snappi_ports = tgen_port_info

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
                            supervisor_dut=supervisor_dut_cisco,
                            snappi_extra_params=snappi_extra_params)


def test_backplane_ecn_marking_lossless_prio(
                                snappi_api,
                                conn_graph_facts,
                                fanout_graph_facts_multidut,
                                duthosts,
                                lossless_prio_list,
                                get_snappi_ports,
                                tbinfo,
                                disable_pfcwd,
                                prio_dscp_map,
                                tgen_port_info,
                                validate_snappi_ports):
    """
    Verify Ingress DUT Egress backplane port ECN marking on lossless prio

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        lossless_prio_list (pytest fixture): list of all the lossless priorities
        get_snappi_ports (pytest fixture): Snappi port fixture
        tbinfo (pytest fixture): fixture provides information about testbed
        disable_pfcwd (pytest fixture): disables PFC watchdog
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority)
        tgen_port_info (pytest fixture): Snappi testbed and port details
        validate_snappi_ports (pytest fixture): validates selected Snappi ports
    Returns:
        N/A
    """

    testbed_config, port_config_list, snappi_ports = tgen_port_info

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
