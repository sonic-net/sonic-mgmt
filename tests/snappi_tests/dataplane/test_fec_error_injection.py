from tests.snappi_tests.dataplane.imports import *        # noqa: F401
from tests.common.snappi_tests.traffic_generation import setup_base_traffic_config     # noqa: F401
from tests.common.snappi_tests.common_helpers import traffic_flow_mode      # noqa: F401
from tests.common.snappi_tests.snappi_helpers import wait_for_arp, fetch_snappi_flow_metrics      # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
    snappi_api, get_snappi_ports, is_snappi_multidut, \
    get_snappi_ports_single_dut, \
    get_snappi_ports_multi_dut, snappi_dut_base_config, cleanup_config, get_snappi_ports_for_rdma  # noqa: F401
from tests.common.snappi_tests.variables import dut_ip_start, snappi_ip_start, \
    prefix_length, dut_ipv6_start, snappi_ipv6_start, v6_prefix_length                # noqa: F401
from tests.snappi_tests.variables import create_ip_list                 # noqa: F401
from snappi_tests.reboot.files.reboot_helper import get_macs            # noqa: F401
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


def get_fanout_port_groups(snappi_ports, fanout_per_port):
    if fanout_per_port > 1:
        num_groups = int(len(snappi_ports)/fanout_per_port)
        group_list = []
        for i in range(fanout_per_port):
            group = []
            for j in range(num_groups):
                group.append(snappi_ports[i+j*fanout_per_port])
            pytest_assert(len(group) % 2 == 0, 'Must have Even number of front panel ports \
                          to have equal Tx and Rx ports')
            group_list.append(tuple(group))
    else:
        group_list = [snappi_ports]
    return group_list


def configure_dut_interface(duthost, fanout_port_group):
    dut_ip_list = create_ip_list(dut_ip_start, len(fanout_port_group), mask=prefix_length)
    # snappi_ip_list = create_ip_list(snappi_ip_start, len(fanout_port_group), mask=prefix_length)
    ports = [port for port in fanout_port_group if port['peer_device'] == duthost.hostname]
    for index, port in enumerate(ports):
        logger.info('Configuring port {} with IP {}/{}'.
                    format(port['peer_port'], dut_ip_list[index], prefix_length))
        duthost.command('sudo config interface ip add {} {}/{} \n'.
                        format(port['peer_port'], dut_ip_list[index], prefix_length))


def cleanup_dut_interface(duthost, fanout_port_group):  # noqa F811
    dut_ip_list = create_ip_list(dut_ip_start, len(fanout_port_group), mask=prefix_length)
    # snappi_ip_list = create_ip_list(snappi_ip_start, len(fanout_port_group), mask=prefix_length)
    ports = [port for port in fanout_port_group if port['peer_device'] == duthost.hostname]
    for index, port in enumerate(ports):
        logger.info('Removing {}/{} from port {}'.
                    format(dut_ip_list[index], prefix_length, port['peer_port']))
        duthost.command('sudo config interface ip remove {} {}/{} \n'.
                        format(port['peer_port'], dut_ip_list[index], prefix_length))


def create_snappi_config(snappi_api, fanout_port_group):  # noqa F811
    half_ports = int(len(fanout_port_group)/2)
    tx_ports = fanout_port_group[:half_ports]
    rx_ports = fanout_port_group[half_ports:]
    config = snappi_api.config()

    for index, tx_port in enumerate(tx_ports):
        config.ports.port(name='Tx_%d' %
                          index, location=tx_port['location'])
    for index, rx_port in enumerate(rx_ports):
        config.ports.port(name='Rx_%d' %
                          index, location=rx_port['location'])

    config.options.port_options.location_preemption = True
    layer1 = config.layer1.layer1()[-1]
    layer1.name = 'port settings'
    layer1.port_names = [port.name for port in config.ports]
    layer1.ieee_media_defaults = False
    layer1.auto_negotiation.rs_fec = False
    layer1.auto_negotiation.link_training = False
    layer1.speed = 'speed_'+str(int(int(fanout_port_group[0]['speed'])/1000))+'_gbps'
    layer1.auto_negotiate = False
    # Tx
    macs_tx = get_macs("101700000011", len(tx_ports))
    macs_rx = get_macs("001700000011", len(rx_ports))
    dut_ip_list = create_ip_list(dut_ip_start, len(fanout_port_group), mask=prefix_length)
    snappi_ip_list = create_ip_list(snappi_ip_start, len(fanout_port_group), mask=prefix_length)
    tx_flow_name = []
    for index, tx_port in enumerate(tx_ports):
        d1 = config.devices.device(name='Tx Topology {}'.format(index))[-1]
        eth = d1.ethernets.add()
        eth.connection.port_name = 'Tx_%d' % index
        eth.name = 'Tx_Ethernet_%d' % index
        eth.mac = macs_tx[index]
        ipv4 = eth.ipv4_addresses.add()
        ipv4.name = 'Tx_IPv4_%d' % index
        ipv4.address = snappi_ip_list[:half_ports][index]
        ipv4.gateway = dut_ip_list[:half_ports][index]
        ipv4.prefix = prefix_length
        tx_flow_name.append(d1.name)

    # Rx
    rx_flow_name = []
    for index, rx_port in enumerate(rx_ports):
        d2 = config.devices.device(name='Rx Topology {}'.format(index))[-1]
        eth = d2.ethernets.add()
        eth.connection.port_name = 'Rx_%d' % index
        eth.name = 'Rx_Ethernet_%d' % index
        eth.mac = macs_rx[index]
        ipv4 = eth.ipv4_addresses.add()
        ipv4.name = 'Rx_IPv4_%d' % index
        ipv4.address = snappi_ip_list[half_ports:][index]
        ipv4.gateway = dut_ip_list[half_ports:][index]
        ipv4.prefix = prefix_length
        rx_flow_name.append(d2.name)

    test_flow = config.flows.flow(name='IPv4 Traffic')[-1]
    test_flow.tx_rx.device.tx_names = tx_flow_name
    test_flow.tx_rx.device.rx_names = rx_flow_name
    test_flow.metrics.enable = True
    test_flow.metrics.loss = True
    test_flow.size.fixed = 512
    test_flow.rate.percentage = 100
    return config


@pytest.mark.parametrize('fanout_per_port', [2])
@pytest.mark.parametrize('error_type', ErrorTypes)
def test_fec_error_injection(duthost,
                             snappi_api,    # noqa F811 
                             get_snappi_ports,    # noqa F811
                             fanout_graph_facts_multidut,
                             fanout_per_port,
                             error_type):
    """
    Test to check if packets get dropped on injecting fec errors
    Note: fanout_per_port is the number of fanouts per fron panel port
    Example: For running the test on 400g fanout mode of a 800g port,
             fanout_per_port is 2, for 800g mode its 1, for 100g mode its 8.
    """
    snappi_ports = get_snappi_ports
    fanout_port_group_list = get_fanout_port_groups(snappi_ports, fanout_per_port)
    for iteration, fanout_port_group in enumerate(fanout_port_group_list):
        logger.info('|----------------------------------------|')
        logger.info('Iteration: {} | Using Fanout Ports :- \n'.format(iteration+1))
        for port in fanout_port_group:
            logger.info(port['peer_port'] + ' : ' + port['location'] + ' : ' + port['snappi_speed_type'])
        logger.info('|----------------------------------------|\n')
        configure_dut_interface(duthost, fanout_port_group)
        snappi_config = create_snappi_config(snappi_api, fanout_port_group)
        snappi_api.set_config(snappi_config)
        ixnet = snappi_api._ixnetwork
        logger.info("Wait for Arp to Resolve ...")
        wait_for_arp(snappi_api, max_attempts=30, poll_interval_sec=2)

        tx_ports, rx_ports = [], []
        for port in ixnet.Vport.find():
            if 'Tx' in port.Name:
                tx_ports.append(port)
            else:
                rx_ports.append(port)
        logger.info('\n\n')
        logger.info('\t Setting FEC Error Type to : {} on Snappi ports :-'.format(error_type))
        for port in tx_ports:
            port.L1Config.FecErrorInsertion.ErrorType = error_type
            logger.info(port.Name)
            if error_type == 'codeWords':
                port.L1Config.FecErrorInsertion.PerCodeword = 16
            port.L1Config.FecErrorInsertion.Continuous = True
        logger.info('|----------------------------------------|')
        logger.info('Starting Traffic ...')
        ts = snappi_api.control_state()
        ts.traffic.flow_transmit.state = ts.traffic.flow_transmit.START
        snappi_api.set_control_state(ts)
        wait(10, "For traffic to start")
        try:
            logger.info('Starting FEC Error Insertion')
            [port.StartFecErrorInsertion() for port in tx_ports]
            wait(15, "For error insertion to start")
            logger.info('Dumping Traffic Item statistics :\n {}'.
                        format(tabulate(get_ti_stats(ixnet), headers='keys', tablefmt='psql')))
            for snappi_port in tx_ports:
                for port in fanout_port_group:
                    if port['location'] == snappi_port.Location:
                        if error_type == 'minConsecutiveUncorrectableWithLossOfLink' or error_type == 'codeWords' \
                           or error_type == 'laneMarkers':
                            pytest_assert(duthost.links_status_down(port['peer_port']) is True,
                                          "FAIL: {} is still up after injecting FEC Error".format(port['peer_port']))
                            logger.info("PASS: {} Went down after injecting FEC Error: {}".
                                        format(port['peer_port'], error_type))
                        elif error_type == 'maxConsecutiveUncorrectableWithoutLossOfLink':
                            pytest_assert(duthost.links_status_down(port['peer_port']) is False,
                                          "FAIL: {} went down after injecting FEC Error".format(port['peer_port']))
                            logger.info("PASS: {} didn't go down after injecting FEC Error: {}".
                                        format(port['peer_port'], error_type))
            flow_metrics = fetch_snappi_flow_metrics(snappi_api, ['IPv4 Traffic'])[0]
            pytest_assert(flow_metrics.frames_tx > 0 and int(flow_metrics.loss) > 0,
                          "FAIL: Rx Port did not drop packets after starting FEC Error Insertion")
            logger.info('PASS : Snappi Rx Port observed packet drop after starting FEC Error Insertion')
            logger.info('Stopping FEC Error Insertion')
            [port.StopFecErrorInsertion() for port in tx_ports]
            wait(20, "For error insertion to stop")
            for snappi_port in tx_ports:
                for port in fanout_port_group:
                    if port['location'] == snappi_port.Location:
                        if error_type == 'minConsecutiveUncorrectableWithLossOfLink' or error_type == 'codeWords' \
                           or error_type == 'laneMarkers':
                            pytest_assert(duthost.links_status_down(port['peer_port']) is False,
                                          "FAIL: {} is still down after stopping FEC Error".format(port['peer_port']))
                            logger.info("PASS: {} is up after stopping FEC Error injection: {}".
                                        format(port['peer_port'], error_type))
            ixnet.ClearStats()
            wait(10, "For clear stats operation to complete")
            logger.info('Dumping Traffic Item statistics :\n {}'.
                        format(tabulate(get_ti_stats(ixnet), headers='keys', tablefmt='psql')))
            flow_metrics = fetch_snappi_flow_metrics(snappi_api, ['IPv4 Traffic'])[0]
            pytest_assert(int(flow_metrics.frames_rx_rate) > 0 and int(flow_metrics.loss) == 0,
                          "FAIL: Rx Port did not resume receiving packets after stopping FEC Error Insertion")
            logger.info('PASS : Rx Port resumed receiving packets after stopping FEC Error Insertion')
            logger.info('Stopping Traffic ...')
            ts = snappi_api.control_state()
            ts.traffic.flow_transmit.state = ts.traffic.flow_transmit.STOP
            snappi_api.set_control_state(ts)
            wait(10, "For traffic to stop")
        finally:
            logger.info('....Finally Block')
            [port.StopFecErrorInsertion() for port in tx_ports]
            cleanup_dut_interface(duthost, fanout_port_group)
