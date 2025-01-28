from tests.snappi_tests.dataplane.imports import *        # noqa: F401
from tests.common.snappi_tests.traffic_generation import setup_base_traffic_config     # noqa: F401
from tests.common.snappi_tests.common_helpers import traffic_flow_mode      # noqa: F401
from tests.common.snappi_tests.snappi_helpers import wait_for_arp, fetch_snappi_flow_metrics      # noqa: F401
logger = logging.getLogger(__name__)
pytestmark = [pytest.mark.topology('tgen')]

ErrorTypes = ['codeWords',
              'laneMarkers',
              'minConsecutiveUncorrectableWithLossOfLink',
              'maxConsecutiveUncorrectableWithoutLossOfLink'
              ]


def get_ti_stats(ixnet):
    tiStatistics = StatViewAssistant(ixnet, 'Traffic Item Statistics')
    tdf = pd.DataFrame(tiStatistics.Rows.RawData, columns=tiStatistics.ColumnHeaders)
    selected_columns = ['Tx Frames', 'Rx Frames', 'Frames Delta', 'Loss %', 'Tx Frame Rate', 'Rx Frame Rate']
    tmp = tdf[selected_columns]
    return tmp


@pytest.fixture(scope="function", autouse=True)
def setup_config(snappi_api,
                 snappi_testbed_config,
                 conn_graph_facts,
                 fanout_graph_facts,
                 duthosts,
                 rand_one_dut_portname_oper_up,
                 rand_one_dut_hostname):
    """
    Fixture to initialize resources for the test.
    """
    dut_hostname, dut_port = rand_one_dut_portname_oper_up.split('|')
    testbed_config, port_config_list = snappi_testbed_config
    duthost = duthosts[rand_one_dut_hostname]
    api = snappi_api
    conn_data = conn_graph_facts
    fanout_data = fanout_graph_facts
    snappi_extra_params = None    

    if snappi_extra_params is None:
        snappi_extra_params = SnappiTestParams()
    port_id = get_dut_port_id(duthost.hostname,
                              dut_port,
                              conn_data,
                              fanout_data)

    pytest_assert(port_id is not None,
                'Fail to get ID for port {}'.format(dut_port))
    snappi_extra_params.base_flow_config = setup_base_traffic_config(testbed_config=testbed_config,
                                                                     port_config_list=port_config_list,
                                                                     port_id=port_id)
    base_flow = snappi_extra_params.base_flow_config
    test_flow = testbed_config.flows.flow(name='IPv4 Traffic')[-1]
    test_flow.tx_rx.device.tx_names = [testbed_config.devices[0].name]
    test_flow.tx_rx.device.rx_names = [testbed_config.devices[1].name]
    test_flow.metrics.enable = True
    test_flow.metrics.loss = True
    test_flow.size.fixed = 64
    test_flow.rate.percentage = 10
    api.set_config(testbed_config)
    test_platform = TestPlatform(snappi_api._address)
    test_platform.Authenticate(snappi_api._username, snappi_api._password)
    id = test_platform.Sessions.find()[-1].Id
    session_assistant = SessionAssistant(IpAddress=snappi_api._address,
                                         RestPort=snappi_api._port,
                                         SessionId=id,
                                         UserName=snappi_api._username,
                                         Password=snappi_api._password)
    yield api, port_config_list, session_assistant


@pytest.mark.parametrize('error_type', ErrorTypes)
def test_fec_error_injection(duthosts,
                             error_type,
                             setup_config):
    """
    Test to check if packets get dropped on injecting fec errors
    """
    api, port_config_list, session_assistant = setup_config
    ixnet = api._ixnetwork
    logger.info("Wait for Arp to Resolve ...")
    wait_for_arp(api, max_attempts=30, poll_interval_sec=2)

    port1 = ixnet.Vport.find()[port_config_list[0].id]
    logger.info('|----------------------------------------|')
    logger.info('| Setting FEC Error Type to : {} |'.format(error_type))
    logger.info('|----------------------------------------|')
    port1.L1Config.FecErrorInsertion.ErrorType = error_type
    if error_type == 'codeWords':
        port1.L1Config.FecErrorInsertion.PerCodeword = 16
    port1.L1Config.FecErrorInsertion.Continuous = True

    logger.info('Starting Traffic ...')
    ts = api.control_state()
    ts.traffic.flow_transmit.state = ts.traffic.flow_transmit.START
    api.set_control_state(ts)
    wait(10, "For traffic to start")
    try:
        logger.info('Starting FEC Error Insertion')
        port1.StartFecErrorInsertion()
        wait(15, "For error insertion to start")
        logger.info('Dumping Traffic Item statistics :\n {}'.format(tabulate(get_ti_stats(ixnet), headers='keys', tablefmt='psql')))
        if error_type == 'minConsecutiveUncorrectableWithLossOfLink' or error_type == 'codeWords' or error_type == 'laneMarkers':
            pytest_assert(duthosts[0].links_status_down(port_config_list[0].peer_port) is True,
                          "FAIL: Link is still up after injecting FEC Error")
            logger.info('|----------------------------------------|')
            logger.info("PASS: Link Went down after injecting FEC Error: {}".format(error_type))
            logger.info('|----------------------------------------|')
        elif error_type == 'maxConsecutiveUncorrectableWithoutLossOfLink':
            pytest_assert(duthosts[0].links_status_down(port_config_list[0].peer_port) is False,
                          "FAIL: Link went down after injecting FEC Error")
            logger.info('|----------------------------------------|')
            logger.info("PASS: Link didn't go down after injecting FEC Error: {}".format(error_type))
            logger.info('|----------------------------------------|')

        flow_metrics = fetch_snappi_flow_metrics(api, ['IPv4 Traffic'])[0]
        pytest_assert(flow_metrics.frames_tx > 0 and int(flow_metrics.loss) > 0,
                    "FAIL: Rx Port did not stop receiving packets after starting FEC Error Insertion")
        logger.info('PASS : Rx Port stopped receiving packets after starting FEC Error Insertion')
        logger.info('Stopping FEC Error Insertion')
        port1.StopFecErrorInsertion()
        wait(15, "For error insertion to stop")
        if error_type == 'minConsecutiveUncorrectableWithLossOfLink' or error_type == 'laneMarkers' or error_type == 'codeWords':
            pytest_assert(duthosts[0].links_status_down(port_config_list[0].peer_port) is False,
                          "FAIL: Link is still down after stopping FEC Error")
            logger.info('|----------------------------------------|')
            logger.info("PASS: Link is up after stopping FEC Error injection: {}".format(error_type))
            logger.info('|----------------------------------------|')
        ixnet.ClearStats()
        wait(10, "For clear stats operation to complete")
        logger.info('Dumping Traffic Item statistics :\n {}'.
                    format(tabulate(get_ti_stats(ixnet), headers='keys', tablefmt='psql')))
        flow_metrics = fetch_snappi_flow_metrics(api, ['IPv4 Traffic'])[0]
        pytest_assert(int(flow_metrics.frames_rx_rate) > 0 and int(flow_metrics.loss) == 0,
                      "FAIL: Rx Port did not resume receiving packets after stopping FEC Error Insertion")
        logger.info('PASS : Rx Port resumed receiving packets after stopping FEC Error Insertion')
        logger.info('Stopping Traffic ...')
        ts = api.control_state()
        ts.traffic.flow_transmit.state = ts.traffic.flow_transmit.STOP
        api.set_control_state(ts)
        wait(10, "For traffic to stop")
    finally:
        logger.info('....Finally Block')
        port1.StopFecErrorInsertion()
