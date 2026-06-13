import random
from tests.snappi_tests.dataplane.imports import *  # noqa: F401, F403, F405
from snappi_tests.dataplane.files.helper import get_duthost_interface_details, create_snappi_config, \
    get_snappi_stats, set_primary_chassis, create_traffic_items, start_stop, \
    wait_with_message, get_stats  # noqa: F401, F403, F405, E402
from tests.common.snappi_tests.snappi_helpers import wait_for_arp
from tests.common.snappi_tests.common_helpers import config_wred, enable_ecn, \
    stop_pfcwd, disable_packet_aging, config_capture_pkt  # noqa: F401

pytestmark = [pytest.mark.topology("nut")]
logger = logging.getLogger(__name__)

ip_version = "IPv4"


@pytest.fixture(scope="module")
def port_groups(duthosts, get_snappi_ports):
    snappi_ports = get_duthost_interface_details(
        duthosts, get_snappi_ports, ip_version, protocol_type="IP"
    )
    pytest_assert(len(snappi_ports) % 3 == 0,
                  "Number of ports should be a multiple of 3 to create port groups of 3 ports each")
    pg = []
    for i in range(0, len(snappi_ports), 3):
        pg.append(snappi_ports[i:i + 3])
    return pg


@pytest.mark.parametrize("subnet_type", [ip_version])
@pytest.mark.parametrize("lossy_prio", [0, 1, 2, 5, 6])
def test_ecn_marking(
        duthosts,
        snappi_api,  # noqa: F811
        get_snappi_ports,  # noqa: F811
        set_primary_chassis,  # noqa: F811
        create_snappi_config,  # noqa: F811
        subnet_type,
        lossy_prio,
        port_groups,
        fanout_graph_facts_multidut,
):
    """
    Test to check if packets are getting ECN marked on congestion
    """
    snappi_extra_params = SnappiTestParams()
    # snappi_ports = get_duthost_interface_details(duthosts, get_snappi_ports, subnet_type, protocol_type="IP")
    for snappi_ports in port_groups:
        logger.info('\n')
        logger.info("Snappi ports used for the test:")
        for port in snappi_ports:
            logger.info('{}: {}'.format(port['peer_port'], port['location']))
        pytest_assert(len(snappi_ports) >= 3, "Not enough ports for the test, Need at least 3 ports")
        tx_ports = snappi_ports[:2]
        rx_ports = [snappi_ports[2]]
        egress_duthost = rx_ports[0]['duthost']

        config_facts = egress_duthost.config_facts(host=egress_duthost.hostname, source="running")['ansible_facts']
        if 'DSCP_TO_TC_MAP' not in config_facts:
            pytest_assert(False, "DSCP_TO_TC_MAP is not configured on the DUT")
        if str(lossy_prio) not in config_facts['DSCP_TO_TC_MAP']['AZURE'].values():
            pytest_assert(False, "Lossy priority {} is not mapped to any DSCP in DSCP_TO_TC_MAP".format(lossy_prio))

        dscp_values = [int(dscp) for dscp, tc in config_facts['DSCP_TO_TC_MAP']['AZURE'].items() if
                       int(tc) == lossy_prio]

        logger.info("Stopping PFC watchdog")
        stop_pfcwd(egress_duthost, rx_ports[0]['asic_value'])
        logger.info("Disabling packet aging if necessary")
        disable_packet_aging(egress_duthost)
        pytest_assert(enable_ecn(host_ans=egress_duthost, prio=lossy_prio), 'Unable to enable ecn')
        snappi_extra_params.protocol_config = {
            "Tx": {"protocol_type": "ip", "ports": tx_ports,
                   "subnet_type": subnet_type, 'is_rdma': True},
            "Rx": {"protocol_type": "ip",
                   "ports": rx_ports, "subnet_type": subnet_type, 'is_rdma': True},
        }
        config, snappi_obj_handles = create_snappi_config(snappi_extra_params)
        api = snappi_api
        snappi_extra_params.traffic_flow_config = [
            {
                "line_rate": 60,
                "frame_size": 1024,
                "is_rdma": True,
                "flow_name": "Traffic Flow",
                "tx_names": snappi_obj_handles["Tx"]["ip"],
                "rx_names": snappi_obj_handles["Rx"]["ip"],
                "traffic_duration_fixed_seconds": 1000,
                "lossy_prio": lossy_prio,
                "dscp_value": random.choice(dscp_values),
            },
        ]
        config = create_traffic_items(config, snappi_extra_params)
        api.set_config(config)

        logger.info("Starting All protocols")
        start_stop(snappi_api, operation="start", op_type="protocols")
        logger.info("Wait for Arp to Resolve ...")
        wait_for_arp(api, max_attempts=30, poll_interval_sec=2)
        ixnet = api._ixnetwork
        trafficItem = ixnet.Traffic.TrafficItem.find()
        trafficItem.EgressEnabled = 'True'
        eg = trafficItem.EgressTracking.find()
        eg.Encapsulation = 'Any: Use Custom Settings'
        eg.Offset = 'Custom'
        eg.CustomOffsetBits = 126
        eg.CustomWidthBits = 2
        logger.info("PASSED: Egress tracking configured successfully")
        # Start Traffic
        logger.info('Generating Traffic Item')
        trafficItem.Generate()
        logger.info('Applying Traffic')
        ixnet.Traffic.Apply()
        logger.info('Starting Traffic')
        ixnet.Traffic.StartStatelessTrafficBlocking()
        time.sleep(30)
        columns = ["frames_tx", "frames_rx", "loss", "frames_tx_rate", "frames_rx_rate"]
        get_stats(snappi_api, "Traffic Item Statistics", columns, 'print')
        TI_Statistics = StatViewAssistant(ixnet, 'Traffic Item Statistics')
        pytest_assert(int(float(TI_Statistics.Rows[0]['Loss %'])) > 0,
                      "Loss must be observed when oversubscribed traffic is running")
        # Drill Down
        tiview = ixnet.Statistics.View.find(Caption='Traffic Item Statistics')[0]
        pytest_assert(len(tiview) == 1, "No statistics rows found in Traffic Item Statistics view")
        drill_down = tiview.DrillDown.find()
        drill_down.TargetRowIndex = 0
        logger.info("Using AvailableDrillDownOptions: {}".format(drill_down.AvailableDrillDownOptions[3]))
        drill_down.TargetDrillDownOption = 'Custom: (2 bits at offset 126)'
        drill_down.DoDrillDown()
        wait_with_message("For drill down operation to complete:", 30)
        logger.info("Drill Down Finshed")
        # Stop one of the high level streams and note down its respective time stamp
        stream1 = trafficItem.HighLevelStream.find(Name="Traffic Flow-EndpointSet-1 - Flow Group 0001")
        UD_Statistics = StatViewAssistant(ixnet, 'User Defined Statistics')
        pytest_assert(int(float(UD_Statistics.Rows[2]['Rx Frame Rate'])) > 0,
                      "Flow is not receiving marked packets when traffic is running")
        logger.info("PASSED:Flow is receiving marked packets when traffic is running")
        stream1.StopStatelessTrafficBlocking()
        wait_with_message("For egress port buffer to drain:", 30)
        flow_Statistics = StatViewAssistant(ixnet, 'Flow Statistics')
        last_time_stamp_flow_1 = float(flow_Statistics.Rows[0]["Last TimeStamp"].split(':')[-1])
        # Note down the last timestamp of the ECN flow bit row 3
        UD_Statistics = StatViewAssistant(ixnet, 'User Defined Statistics')
        # When we stop the flow stream Egress tracking for Row 3 should stop receiving marked packets
        pytest_assert(int(float(UD_Statistics.Rows[2]['Rx Frame Rate'])) == 0,
                      "Flow is still receiving markedpackets after stopping one of the stream")
        logger.info("PASSED: Traffic is not receiving marked packets after stopping one of the stream")
        Egress_3 = float(UD_Statistics.Rows[2]["Last TimeStamp"].split(':')[-1])
        ECN_RESPONSE_TIME = round((Egress_3 - last_time_stamp_flow_1) * 1000, 3)
        logger.info('\n')
        logger.info("ECN Response Time is: {} milliseconds".format(ECN_RESPONSE_TIME))
        logger.info('\n')
        # Stop Traffic
        trafficItem.StopStatelessTrafficBlocking()
