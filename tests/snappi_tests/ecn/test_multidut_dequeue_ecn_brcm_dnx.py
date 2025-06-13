import pytest
import random
import logging

from tests.common.helpers.assertions import pytest_assert
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts, \
    fanout_graph_facts_multidut                                                                     # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
    get_snappi_ports_single_dut, snappi_testbed_config, \
    get_snappi_ports_multi_dut, is_snappi_multidut, snappi_port_selection, tgen_port_info, \
    snappi_api, snappi_dut_base_config, get_snappi_ports, get_snappi_ports_for_rdma, cleanup_config  # noqa: F401
from tests.common.snappi_tests.qos_fixtures import prio_dscp_map, lossless_prio_list, disable_pfcwd  # noqa: F401

from tests.snappi_tests.ecn.files.restpy_multidut_helper import run_ecn_test
from tests.common.snappi_tests.read_pcap import is_ecn_marked
from tests.snappi_tests.files.helper import skip_ecn_tests
from tests.common.snappi_tests.common_helpers import packet_capture, get_wred_profiles
from tests.common.config_reload import config_reload
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
logger = logging.getLogger(__name__)
pytestmark = [pytest.mark.topology('multidut-tgen')]


@pytest.fixture(autouse=True, scope='module')
def number_of_tx_rx_ports():
    yield (1, 1)


@pytest.mark.disable_loganalyzer
@pytest.mark.parametrize('data_flow_pkt_count', [800, 1800, 2400])
@pytest.mark.parametrize('pmax', [25, 50, 75, 100])
def test_dequeue_ecn(request,
                     snappi_api,                    # noqa: F811
                     conn_graph_facts,              # noqa: F811
                     fanout_graph_facts_multidut,   # noqa: F811
                     duthosts,
                     lossless_prio_list,            # noqa: F811
                     data_flow_pkt_count,
                     tbinfo,
                     number_of_tx_rx_ports,
                     get_snappi_ports,              # noqa: F811
                     disable_pfcwd,                 # noqa: F811
                     tgen_port_info,                # noqa: F811
                     pmax,                          # noqa: F811
                     prio_dscp_map):                # noqa: F811
    """
    Test if the device under test (DUT) performs ECN marking at the egress.
    Test uses has Kmix and Kmax set to 800000 and 2000000 respectively.
    Test case checks ECN marking probability based on different value of Pmax and
    for different packet counts. Test checks ECN probabilities for packet counts
    - below Kmin, between Kmix and Kmax, and slightly above Kmax.

    Args:
        request (pytest fixture): pytest request object
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        lossless_prio_list (fixture): list of lossless priorities
        data_flow_pkt_count (list): various packet counts parameterized for the test.
        tbinfo (string):  setup name as defined in testbed.csv
        number_of_tx_rx_ports(fixture): determines number of Tx and Rx port for test.
        get_snappi_ports (fixture): list of snappi ports based on setup used
        disable_pfcwd (fixture): disables PFCWD and Credit-WD.
        tgen_port_info (fixture): Dynamic port selection.
        pmax (list): list with various values of Pmax parameterized.
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).

    Returns:
        N/A
    """

    # Skip the test if the platform is NOT Broadcom-DNX.
    if ("platform_asic" in duthosts[0].facts and duthosts[0].facts["platform_asic"] != "broadcom-dnx"):
        pytest.skip("Test is specific to Broadcom-DNX platform. Skipping for other platforms.")

    # Selecting Tx and Rx ports for the test based on port_map definitions.
    testbed_config, port_config_list, snappi_ports = tgen_port_info

    # Selecting lossless priority for the test.
    lossless_prio = random.sample(lossless_prio_list, 1)[0]
    logger.info('Selected lossless priority:{}'.format(lossless_prio))
    skip_ecn_tests(snappi_ports[0]['duthost'])
    skip_ecn_tests(snappi_ports[1]['duthost'])

    # Defining snappi parameters for the test.
    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.duthost1 = snappi_ports[0]['duthost']
    snappi_extra_params.multi_dut_params.duthost2 = snappi_ports[1]['duthost']
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports
    snappi_extra_params.packet_capture_type = packet_capture.IP_CAPTURE
    snappi_extra_params.is_snappi_ingress_port_cap = True

    # Creating dut_list for identifying unique duthosts to be used for the test.
    dut_list = []
    if (snappi_ports[0]['duthost'].hostname == snappi_ports[1]['duthost'].hostname):
        dut_list.append(snappi_ports[0]['duthost'])
    else:
        dut_list = [snappi_ports[0]['duthost'], snappi_ports[1]['duthost']]

    # Selecting Kmin, Kmax and Pmax for the test.
    logger.info('Selecting different Kmin, Kmax and Pmax for DNX based platform')
    snappi_extra_params.ecn_params = {'kmin': 800000, 'kmax': 2000000, 'pmax': pmax}
    data_flow_pkt_size = 1024
    kmin = snappi_extra_params.ecn_params['kmin']
    kmax = snappi_extra_params.ecn_params['kmax']
    pmax = snappi_extra_params.ecn_params['pmax']
    logger.info('Running ECN dequeue test with params: {} and {} packets'.
                format(snappi_extra_params.ecn_params, data_flow_pkt_count))

    snappi_extra_params.traffic_flow_config.data_flow_config = {
            "flow_pkt_size": data_flow_pkt_size,
            "flow_pkt_count": data_flow_pkt_count
        }

    ip_pkts = run_ecn_test(api=snappi_api,
                           testbed_config=testbed_config,
                           port_config_list=port_config_list,
                           conn_data=conn_graph_facts,
                           fanout_data=fanout_graph_facts_multidut,
                           dut_port=snappi_ports[0]['peer_port'],
                           lossless_prio=lossless_prio,
                           prio_dscp_map=prio_dscp_map,
                           default_ecn=False,
                           iters=1,
                           snappi_extra_params=snappi_extra_params)[0]

    verify_ecn(ip_pkts=ip_pkts,
               kmin=kmin,
               kmax=kmax,
               pmax=pmax,
               dut_list=dut_list,
               data_flow_pkt_size=data_flow_pkt_size,
               data_flow_pkt_count=data_flow_pkt_count)


@pytest.mark.disable_loganalyzer
@pytest.mark.parametrize('data_flow_pkt_count', [8500])
def test_dequeue_ecn_default(request,
                             snappi_api,                    # noqa: F811
                             conn_graph_facts,              # noqa: F811
                             fanout_graph_facts_multidut,   # noqa: F811
                             duthosts,
                             lossless_prio_list,            # noqa: F811
                             data_flow_pkt_count,
                             tbinfo,
                             number_of_tx_rx_ports,
                             get_snappi_ports,              # noqa: F811
                             disable_pfcwd,                 # noqa: F811
                             tgen_port_info,                # noqa: F811
                             prio_dscp_map):                # noqa: F811
    """
    Test if the device under test (DUT) performs ECN marking at the egress.
    Test uses default values for Kmin, Kmax and Pmax.
    Test case checks ECN marking probability for packet count between Kmin and Kmax.
    Expectation is that marking % should be between 0 and Pmax.

    Args:
        request (pytest fixture): pytest request object
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        lossless_prio_list (fixture): list of lossless priorities
        data_flow_pkt_count (list): various packet counts parameterized for the test.
        tbinfo (string):  setup name as defined in testbed.csv
        number_of_tx_rx_ports(fixture): determines number of Tx and Rx port for test.
        get_snappi_ports (fixture): list of snappi ports based on setup used
        disable_pfcwd (fixture): disables PFCWD and Credit-WD.
        tgen_port_info (fixture): Dynamic port selection.
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).

    Returns:
        N/A
    """

    # Skip the test if the platform is NOT Broadcom-DNX.
    if ("platform_asic" in duthosts[0].facts and duthosts[0].facts["platform_asic"] != "broadcom-dnx"):
        pytest.skip("Test is specific to Broadcom-DNX platform. Skipping for other platforms.")

    # Selecting Tx and Rx ports for the test based on port_map definitions.
    testbed_config, port_config_list, snappi_ports = tgen_port_info

    # Selecting lossless priority for the test.
    lossless_prio = random.sample(lossless_prio_list, 1)[0]
    logger.info('Selected lossless priority:{}'.format(lossless_prio))
    skip_ecn_tests(snappi_ports[0]['duthost'])
    skip_ecn_tests(snappi_ports[1]['duthost'])

    # Defining snappi parameters for the test.
    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.duthost1 = snappi_ports[0]['duthost']
    snappi_extra_params.multi_dut_params.duthost2 = snappi_ports[1]['duthost']
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports
    snappi_extra_params.packet_capture_type = packet_capture.IP_CAPTURE
    snappi_extra_params.is_snappi_ingress_port_cap = True

    # Creating dut_list for identifying unique duthosts to be used for the test.
    dut_list = []
    if (snappi_ports[0]['duthost'].hostname == snappi_ports[1]['duthost'].hostname):
        dut_list.append(snappi_ports[0]['duthost'])
    else:
        dut_list = [snappi_ports[0]['duthost'], snappi_ports[1]['duthost']]

    # Reading WRED profile to get the default values.
    asic_value = 'asic{}'.format(duthosts[0].get_asic_ids()[0])
    wred_profile = get_wred_profiles(duthosts[0], asic_value=asic_value)

    # Selecting DEFAULT Kmin, Kmax and Pmax for the test.
    for _, value in wred_profile.items():
        pmax = int(value['red_drop_probability'])
        kmax = int(value['red_max_threshold'])
        kmin = int(value['red_min_threshold'])

    logger.info('Selecting DEFAULT Kmin, Kmax and Pmax for DNX based platform')
    snappi_extra_params.ecn_params = {'kmin': kmin, 'kmax': kmax, 'pmax': pmax}
    data_flow_pkt_size = 1024
    kmin = snappi_extra_params.ecn_params['kmin']
    kmax = snappi_extra_params.ecn_params['kmax']
    pmax = snappi_extra_params.ecn_params['pmax']
    logger.info('Running ECN dequeue test with params: {} and {} packets'.
                format(snappi_extra_params.ecn_params, data_flow_pkt_count))

    snappi_extra_params.traffic_flow_config.data_flow_config = {
            "flow_pkt_size": data_flow_pkt_size,
            "flow_pkt_count": data_flow_pkt_count
        }

    ip_pkts = run_ecn_test(api=snappi_api,
                           testbed_config=testbed_config,
                           port_config_list=port_config_list,
                           conn_data=conn_graph_facts,
                           fanout_data=fanout_graph_facts_multidut,
                           dut_port=snappi_ports[0]['peer_port'],
                           lossless_prio=lossless_prio,
                           prio_dscp_map=prio_dscp_map,
                           default_ecn=True,
                           iters=1,
                           snappi_extra_params=snappi_extra_params)[0]

    verify_ecn(ip_pkts=ip_pkts,
               kmin=kmin,
               kmax=kmax,
               pmax=pmax,
               dut_list=dut_list,
               data_flow_pkt_size=data_flow_pkt_size,
               data_flow_pkt_count=data_flow_pkt_count)


def verify_ecn(ip_pkts,
               kmin,
               kmax,
               pmax,
               dut_list,
               data_flow_pkt_size,
               data_flow_pkt_count):
    """
    Function does following tasks:
        - Reads the PCAP returned from the test.
        - Determines and counts if packet is ECN marked or not.
        - Determines ECN marked packet less than Kmin, between Kmin and Kmax and more than Kmax.

    Returns:
        N/A
    """
    logger.info("Running verification for ECN dequeue test")
    # Check if all the packets are captured
    pytest_assert(len(ip_pkts) == data_flow_pkt_count,
                  'Only capture {}/{} IP packets'.format(len(ip_pkts), data_flow_pkt_count))

    ecn_set = 0
    logger.info('Analyzing PCAP with {} pkts'.format(data_flow_pkt_count))
    pkts_mrk_bfr_kmin = 0
    pkts_mrk_in_range = 0
    pkts_mrk_aft_kmax = 0
    logger.info('Checking the packets for the ECN markings')
    for i in range(data_flow_pkt_count):
        ecn_set_flag = False

        # Identifying first packet ECN-marked.
        if is_ecn_marked(ip_pkts[i]):
            ecn_set_flag = True

        if (ecn_set_flag and not ecn_set):
            logger.info('First packet to be ECN-Marked:{}'.format(i+1))
            ecn_set = 1

        # Counting packets ECN marked - before Kmin, between Kmix-Kmax and after Kmax.
        if (ecn_set_flag):
            if (i < (kmin/data_flow_pkt_size)):
                pkts_mrk_bfr_kmin += 1
            if (i >= (kmin/data_flow_pkt_size) and (i < (kmax)/data_flow_pkt_size)):
                pkts_mrk_in_range += 1
            if (i >= (kmax/data_flow_pkt_size)):
                pkts_mrk_aft_kmax += 1

        # Identifying last packet ECN-marked.
        if (not ecn_set_flag and ecn_set):
            logger.info('Last packet to be ECN-Marked:{}'.format(i))
            ecn_set = 0

    logger.info('Result - Pkts marked before Kmin:{}'.format(pkts_mrk_bfr_kmin))
    logger.info('Result - Pkts marked between Kmin and Kmax :{}'.format(pkts_mrk_in_range))
    logger.info('Result - Pkts marked after Kmax:{}'.format(pkts_mrk_aft_kmax))

    # Validation checks
    # If packet count is less than Kmin, no packets should be ECN marked.
    if (data_flow_pkt_count < (kmin/data_flow_pkt_size)):
        pytest_assert(pkts_mrk_bfr_kmin == 0, 'If pkt_count is less than Kmin, no packets should be ECN-marked')

    # If packet count is in range of Kmin and Kmax, ECN-marking should follow Pmax probability.
    if ((data_flow_pkt_count > (kmin/data_flow_pkt_size) + 100)
            and (data_flow_pkt_count < (kmax/data_flow_pkt_size + 500))):
        pkts_ecn_range = (kmax - kmin)/data_flow_pkt_size
        logger.info('ECN Marking range:{}'.format(pkts_ecn_range))
        # Calculating probability of ECN marking between Kmin and Kmax.
        pkts_marked_prob = round((float(pkts_mrk_in_range) / pkts_ecn_range * 100), 2)
        logger.info('ECN Marking Probability between Kmin-Kmax for pmax of {} : {}%'.format(pmax, pkts_marked_prob))
        pytest_assert(0 < pkts_marked_prob <= pmax,
                      'For packet count between Kmin-Kmax, ECN marking prob should be less than or equal to Pmax')

    # If packet is way beyond Kmax value, then almost all packets should be ECN marked.
    if ((data_flow_pkt_count > (kmax/data_flow_pkt_size + 1000))):
        pkts_marked = round((pkts_mrk_bfr_kmin + pkts_mrk_in_range + pkts_mrk_aft_kmax) / data_flow_pkt_count * 100, 2)
        logger.info('ECN Marking % with {} packets > Kmax of {} is {}'.
                    format(data_flow_pkt_count, kmax/data_flow_pkt_size, pkts_marked))
        pytest_assert(0 < pkts_marked_prob <= pmax,
                      'For packet count between Kmin-Kmax, ECN marking prob should be less than or equal to Pmax')

    # Teardown ECN config through a reload
    logger.info("Reloading config to teardown ECN config")
    for dut in dut_list:
        logger.info('Reloading configDB for dut:{}'.format(dut.hostname))
        config_reload(sonic_host=dut, config_source='config_db', safe_reload=True)
