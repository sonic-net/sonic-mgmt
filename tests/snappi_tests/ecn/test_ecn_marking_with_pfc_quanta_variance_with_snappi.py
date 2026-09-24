import pytest
import logging
import os
from tabulate import tabulate  # noqa: F401
from tests.common.helpers.assertions import pytest_assert     # noqa: F401
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts, \
                fanout_graph_facts_multidut         # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
    snappi_api, snappi_dut_base_config, get_snappi_ports, get_snappi_ports_for_rdma, cleanup_config, \
    is_snappi_multidut, get_snappi_ports_multi_dut, get_snappi_ports_single_dut, \
    snappi_port_selection, tgen_port_info   # noqa: F401
from tests.common.snappi_tests.qos_fixtures import prio_dscp_map, \
    lossless_prio_list, disable_pfcwd   # noqa: F401
from tests.snappi_tests.ecn.files.helper import run_ecn_marking_with_pfc_quanta_variance
from tests.common.snappi_tests.common_helpers import config_wred, get_wred_profiles
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
logger = logging.getLogger(__name__)
pytestmark = [pytest.mark.topology('multidut-tgen', 'tgen')]


@pytest.fixture(autouse=True, scope='module')
def number_of_tx_rx_ports():
    yield (1, 1)


@pytest.fixture
def restore_wred_ecn_config(tgen_port_info, snappi_api):    # noqa: F811
    """
    Capture the WRED/ECN profile thresholds before the test runs and restore
    them after it completes.

    The quanta variance test modifies the WRED/ECN profiles on the DUT. Without
    restoring them, the DUT is left in a state that breaks subsequent ECN tests.
    This fixture also resets the traffic generator config so no stale flows are
    left transmitting on the tester.
    """
    _, _, snappi_ports = tgen_port_info
    duthost = snappi_ports[0]['duthost']
    dut_port = snappi_ports[0]['peer_port']

    asic_namespace = None
    if duthost.is_multi_asic:
        asic = duthost.get_port_asic_instance(dut_port)
        asic_namespace = asic.namespace

    color = 'green'
    if "platform_asic" in duthost.facts and duthost.facts["platform_asic"] == "broadcom-dnx":
        color = 'red'

    original_wred_profiles = get_wred_profiles(host_ans=duthost, asic_value=asic_namespace)

    yield

    # Restore the original WRED/ECN thresholds so that subsequent tests
    # start from a clean DUT state.
    if original_wred_profiles:
        logger.info("Restoring original WRED/ECN thresholds")
        for profile_name, profile in original_wred_profiles.items():
            try:
                kmin_old = int(profile['{}_min_threshold'.format(color)])
                kmax_old = int(profile['{}_max_threshold'.format(color)])
                kdrop_old = int(profile['{}_drop_probability'.format(color)])
            except (KeyError, ValueError):
                logger.warning("Could not parse original thresholds for WRED profile {}".format(profile_name))
                continue

            restore_result = config_wred(host_ans=duthost,
                                         kmin=kmin_old,
                                         kmax=kmax_old,
                                         pmax=0,
                                         kdrop=kdrop_old,
                                         profile=profile_name,
                                         asic_value=asic_namespace)
            if restore_result is not True:
                logger.warning("Failed to restore WRED profile {}".format(profile_name))

    # Reset the traffic generator config so that no stale flows are left
    # transmitting on the tester after this test completes. Explicitly stop
    # transmission first: if the test aborted early the flows may still be
    # running, and set_config() alone is not guaranteed to halt them before
    # the tgen_port_info fixture removes the DUT static route/ARP entry for
    # their destination, which would leave the tester sending to an
    # unrouted destination.
    try:
        cs = snappi_api.control_state()
        cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.STOP
        snappi_api.set_control_state(cs)
    except Exception as exc:
        logger.error("Failed to stop traffic generator flows before cleanup: {}".format(exc))

    try:
        snappi_api.set_config(snappi_api.config())
    except Exception as exc:
        logger.warning("Failed to reset traffic generator config: {}".format(exc))


# tuple of -gmin in MB, -gmax in MB and -gdrop in percentage
test_ecn_config = [(1, 4, 5), (1, 4, 10), (2, 4, 5), (2, 4, 10)]


@pytest.mark.parametrize("test_ecn_config", test_ecn_config)
def test_ecn_marking_with_pfc_quanta_variance(
                                request,
                                snappi_api,                       # noqa: F811
                                conn_graph_facts,                 # noqa: F811
                                fanout_graph_facts_multidut,               # noqa: F811
                                duthosts,
                                lossless_prio_list,     # noqa: F811
                                tbinfo,      # noqa: F811
                                test_ecn_config,
                                prio_dscp_map,  # noqa: F811
                                tgen_port_info,
                                restore_wred_ecn_config):                    # noqa: F811

    """
    Verify ECN marking on lossless prio with varying XOFF quanta

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
    Returns:
        N/A
    """

    testbed_config, port_config_list, snappi_ports = tgen_port_info
    log_file_path = request.config.getoption("--log-file", default=None)

    logger.info("Snappi Ports : {}".format(snappi_ports))
    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

    run_ecn_marking_with_pfc_quanta_variance(
                            api=snappi_api,
                            testbed_config=testbed_config,
                            port_config_list=port_config_list,
                            dut_port=snappi_ports[0]['peer_port'],
                            test_prio_list=lossless_prio_list,
                            prio_dscp_map=prio_dscp_map,
                            log_dir=os.path.dirname(log_file_path) if log_file_path else None,
                            test_ecn_config=test_ecn_config,
                            snappi_extra_params=snappi_extra_params)
