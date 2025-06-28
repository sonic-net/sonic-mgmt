import pytest
import logging
from tabulate import tabulate  # noqa: F401
from tests.common.helpers.assertions import pytest_assert, pytest_require     # noqa: F401
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts, \
    fanout_graph_facts_multidut         # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
    snappi_api, snappi_dut_base_config, get_snappi_ports, get_snappi_ports_for_rdma, cleanup_config, \
    is_snappi_multidut, get_snappi_ports_multi_dut, get_snappi_ports_single_dut   # noqa: F401
from tests.common.snappi_tests.qos_fixtures import prio_dscp_map, \
    lossless_prio_list, disable_pfcwd   # noqa: F401
from tests.snappi_tests.files.helper import multidut_port_info, setup_ports_and_dut, enable_debug_shell  # noqa: F401
from tests.snappi_tests.ecn.files.helper import run_ecn_marking_test, \
    run_ecn_marking_port_toggle_test, run_ecn_marking_ect_marked_pkts
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
from tests.common.cisco_data import is_cisco_device
logger = logging.getLogger(__name__)
pytestmark = [pytest.mark.topology('multidut-tgen', 'tgen')]


def snappi_port_dut_info(snappi_ports):
    # Extract duthost and peer_port values for rx_dut and tx_dut configurations
    rx_dut = snappi_ports[0]['duthost']
    rx_peer_port = snappi_ports[0]['peer_port']
    tx_dut_1 = snappi_ports[1]['duthost']
    tx_peer_port_1 = snappi_ports[1]['peer_port']
    tx_dut_2 = snappi_ports[2]['duthost']
    tx_peer_port_2 = snappi_ports[2]['peer_port']

    input_ports_same_asic = False
    input_ports_same_dut = False
    single_dut = False
    egress_port_short_link = True

    # get the ASIC namespace for a given duthost and peer_port
    def get_asic(duthost, peer_port):
        return duthost.get_port_asic_instance(peer_port).namespace

    # Retrieve ASIC namespace
    rx_asic = get_asic(rx_dut, rx_peer_port)
    tx_asic_1 = get_asic(tx_dut_1, tx_peer_port_1)
    tx_asic_2 = get_asic(tx_dut_2, tx_peer_port_2)

    if (tx_asic_1 == tx_asic_2):
        input_ports_same_asic = True

    if (tx_dut_1 == tx_dut_2):
        input_ports_same_dut = True

    def check_dut_short_link(dut_asic, dut, dut_port):
        cmd_part = f"-n {dut_asic}"
        if dut_asic is None:
            cmd_part = ""
        cmd = 'sonic-db-cli ' + f'{cmd_part}' + ' CONFIG_DB hget "CABLE_LENGTH|AZURE" ' + dut_port

        len_str = dut.shell(cmd)['stdout_lines']
        cable_len = int(len_str[0][:-1])
        # 120000m -> 120000
        return True if cable_len < 1000 else False

    egress_port_short_link = check_dut_short_link(rx_asic, rx_dut, rx_peer_port)

    # Check if ingress ports are short link
    ingress_ports_1_short_link = check_dut_short_link(tx_asic_1, tx_dut_1, tx_peer_port_1)
    ingress_ports_2_short_link = check_dut_short_link(tx_asic_2, tx_dut_2, tx_peer_port_2)

    # ECN mark check on bp or fabric port only when both ingress are on short and egress is on long link
    is_bp_fabric_ecn_check_required = ingress_ports_1_short_link and ingress_ports_2_short_link \
        and not egress_port_short_link

    return input_ports_same_asic, input_ports_same_dut, single_dut, \
        is_bp_fabric_ecn_check_required, egress_port_short_link


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
    if (tx_asic_1 == tx_asic_2):
        return True

    if (tx_dut_1 == tx_dut_2) and (rx_dut != tx_dut_1):
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

    _, _, _, is_bp_fabric_ecn_check_required, _ = snappi_port_dut_info(snappi_ports)

    supervisor_dut = None
    if is_bp_fabric_ecn_check_required:
        supervisor_dut = next((duthost for duthost in duthosts if duthost.is_supervisor_node()), None)

    logger.info("Snappi Ports : {}".format(snappi_ports))
    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

    run_ecn_marking_port_toggle_test(
                            api=snappi_api,
                            testbed_config=testbed_config,
                            port_config_list=port_config_list,
                            dut_port=snappi_ports[0]['peer_port'],
                            test_prio_list=lossless_prio_list,
                            prio_dscp_map=prio_dscp_map,
                            supervisor_dut=supervisor_dut,
                            is_bp_fabric_ecn_check_required=is_bp_fabric_ecn_check_required,
                            snappi_extra_params=snappi_extra_params)


test_flow_percent_list = [[90, 15], [53, 49], [15, 90], [49, 49], [50, 50], [60, 60], [60, 90], [90, 60]]


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

    input_port_same_asic, input_port_same_dut, single_dut, _, \
        egress_port_short_link = snappi_port_dut_info(snappi_ports)
    pytest_require(egress_port_short_link, "Egress port must be on short link")

    logger.info("Snappi Ports : {}".format(snappi_ports))
    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

    run_ecn_marking_test(
                            api=snappi_api,
                            testbed_config=testbed_config,
                            port_config_list=port_config_list,
                            dut_port=snappi_ports[0]['peer_port'],
                            test_prio_list=lossless_prio_list,
                            prio_dscp_map=prio_dscp_map,
                            test_flow_percent=test_flow_percent,
                            number_of_streams=10,
                            input_port_same_asic=input_port_same_asic,
                            input_port_same_dut=input_port_same_dut,
                            single_dut=single_dut,
                            snappi_extra_params=snappi_extra_params)


def test_ecn_marking_ect_marked_pkts(
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
    Verify ECN marking for ECT marked pkts
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

    _, _, _, is_bp_fabric_ecn_check_required, _ = snappi_port_dut_info(snappi_ports)

    supervisor_dut = None
    if is_bp_fabric_ecn_check_required:
        supervisor_dut = next((duthost for duthost in duthosts if duthost.is_supervisor_node()), None)

    logger.info("Snappi Ports : {}".format(snappi_ports))
    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

    run_ecn_marking_ect_marked_pkts(
                            api=snappi_api,
                            testbed_config=testbed_config,
                            port_config_list=port_config_list,
                            dut_port=snappi_ports[0]['peer_port'],
                            test_prio_list=lossless_prio_list,
                            prio_dscp_map=prio_dscp_map,
                            supervisor_dut=supervisor_dut,
                            is_bp_fabric_ecn_check_required=is_bp_fabric_ecn_check_required,
                            snappi_extra_params=snappi_extra_params)
