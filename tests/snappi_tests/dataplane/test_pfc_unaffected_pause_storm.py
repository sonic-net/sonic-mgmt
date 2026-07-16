"""
test_pfc_unaffected_pause_storm.py

Implements test case Y01 of the PFC Lossy test plan:

    "Lossy Traffic Unaffected During PFC Storm"

A full PFC storm is generated on the lossless priorities (3, 4). While the storm
keeps the lossless queues continuously paused, all lossy priority flows
(0, 1, 2, 5, 6, 7) must keep flowing at their configured rate with zero packet
loss, and the DUT must never generate PFC on the lossy priorities.

Topology assumed: Single-Tier -- the Snappi traffic generator ports are
directly connected to the SONiC DUT.

Reference test plan:
    docs/testplan/pfc_lossy_testplan.md  (Y01)
"""
from tests.snappi_tests.dataplane.imports import *  # noqa: F401, F403, F405
from snappi_tests.dataplane.files.helper import get_duthost_interface_details, create_snappi_config, \
    set_primary_chassis, create_traffic_items, start_stop, get_stats  # noqa: F401, F403, F405, E402
from tests.common.snappi_tests.snappi_helpers import wait_for_arp
from tests.common.snappi_tests.common_helpers import (
    stop_pfcwd,
    disable_packet_aging,
    calc_pfc_pause_flow_rate,
    get_pfc_frame_count,
)  # noqa: F401

pytestmark = [pytest.mark.topology("nut")]
logger = logging.getLogger(__name__)

ip_version = "IPv4"
TIMEOUT = 30
# Per the test plan, SONiC's ``pfc_enable`` defaults to "3,4" (lossless);
# every other priority is lossy and must ignore the PFC storm.
LOSSLESS_PRIO = [3, 4]
LOSSY_PRIO = [0, 1, 2, 5, 6, 7]

# Pass/Fail thresholds from the test plan (Section: Pass/Fail Criteria).
RX_RATE_TOLERANCE = 0.02       # lossy Rx rate must stay within +/-2% of configured
MAX_LOSS_PERCENT = 0.0         # lossy priorities MUST see 0% loss

TRAFFIC_DURATION_SEC = 1000      # data flow run time
PFC_STORM_LEAD_SEC = 5         # storm starts this many seconds before data flows


@pytest.fixture(scope="module")
def port_groups(duthosts, get_snappi_ports):
    snappi_ports = get_duthost_interface_details(
        duthosts, get_snappi_ports, ip_version, protocol_type="IP"
    )
    pytest_assert(
        len(snappi_ports) >= 2,
        "Need at least 2 snappi ports for the test",
    )
    pg = []
    for i in range(0, len(snappi_ports), 2):
        pg.append(snappi_ports[i:i + 2])
    return pg


def _lossy_prio_list(config_facts):
    """Derive the lossy priority list from the DUT config, falling back to the
    test plan defaults. Lossless priorities are read from ``pfc_enable`` and the
    lossy set is the complement, restricted to priorities present in
    DSCP_TO_TC_MAP so every lossy flow can be given a valid DSCP value."""
    lossless = set(LOSSLESS_PRIO)
    try:
        for _, cable in config_facts.get("PORT_QOS_MAP", {}).items():
            if "pfc_enable" in cable:
                lossless = {int(p) for p in cable["pfc_enable"].split(",") if p != ""}
                break
    except (KeyError, ValueError, AttributeError):
        lossless = set(LOSSLESS_PRIO)

    mapped_tcs = {int(tc) for tc in config_facts["DSCP_TO_TC_MAP"]["AZURE"].values()}
    lossy = sorted(tc for tc in mapped_tcs if tc not in lossless)
    return lossy if lossy else LOSSY_PRIO


@pytest.mark.parametrize("subnet_type", [ip_version])
@pytest.mark.parametrize("speed", ["100G"])
@pytest.mark.parametrize("buffer_model", ["static"])
@pytest.mark.parametrize("asic_count", ["single"])
def test_pfc_unaffected_pause_storm(
        duthosts,
        snappi_api,  # noqa: F811
        get_snappi_ports,  # noqa: F811
        set_primary_chassis,  # noqa: F811
        create_snappi_config,  # noqa: F811
        subnet_type,
        speed,
        buffer_model,
        asic_count,
        port_groups,
        fanout_graph_facts_multidut,
):
    """
    Y01: A PFC storm on the lossless priorities (3, 4) must leave every lossy
    priority flow (0, 1, 2, 5, 6, 7) at full throughput with zero loss, and the
    DUT must not generate PFC on the lossy priorities.
    """
    snappi_extra_params = SnappiTestParams()
    for snappi_ports in port_groups:
        logger.info('\n')
        logger.info("Snappi ports used for the test:")
        for port in snappi_ports:
            logger.info('{}: {}'.format(port['peer_port'], port['location']))
        pytest_assert(len(snappi_ports) >= 2, "Not enough ports for the test, Need at least 2 ports")
        tx_ports = [snappi_ports[0]]
        rx_ports = [snappi_ports[1]]
        egress_duthost = rx_ports[0]['duthost']

        config_facts = egress_duthost.config_facts(host=egress_duthost.hostname, source="running")['ansible_facts']
        pytest_assert('DSCP_TO_TC_MAP' in config_facts, "DSCP_TO_TC_MAP is not configured on the DUT")
        lossy_prio_list = _lossy_prio_list(config_facts)
        logger.info("Lossy priorities under test: {}".format(lossy_prio_list))
        logger.info("Lossless priorities targeted by PFC storm: {}".format(LOSSLESS_PRIO))

        logger.info("Stopping PFC watchdog")
        stop_pfcwd(egress_duthost, rx_ports[0]['asic_value'])
        logger.info("Disabling packet aging if necessary")
        disable_packet_aging(egress_duthost)

        # Snappi protocol (IP) endpoints for the data flows.
        snappi_extra_params.protocol_config = {
            "Tx": {"protocol_type": "ip", "ports": tx_ports,
                   "subnet_type": subnet_type, 'is_rdma': True},
            "Rx": {"protocol_type": "ip",
                   "ports": rx_ports, "subnet_type": subnet_type, 'is_rdma': True},
        }
        config, snappi_obj_handles = create_snappi_config(snappi_extra_params)
        api = snappi_api

        # ------------------------------------------------------------------
        # Build one lossy data flow per lossy priority, each at an equal share
        # of the line rate: line_rate / number_of_lossy_priorities.
        # ------------------------------------------------------------------
        per_flow_rate = round(100.0 / len(lossy_prio_list), 3)
        traffic_flow_config = []
        for prio in lossy_prio_list:
            dscp_values = [int(dscp) for dscp, tc in config_facts['DSCP_TO_TC_MAP']['AZURE'].items()
                           if int(tc) == prio]
            pytest_assert(dscp_values,
                          "Lossy priority {} is not mapped to any DSCP in DSCP_TO_TC_MAP".format(prio))
            traffic_flow_config.append({
                "line_rate": per_flow_rate,
                "frame_size": 1024,
                "is_rdma": True,
                "flow_name": "Lossy Prio {}".format(prio),
                "tx_names": snappi_obj_handles["Tx"]["ip"],
                "rx_names": snappi_obj_handles["Rx"]["ip"],
                "traffic_duration_fixed_seconds": TRAFFIC_DURATION_SEC,
                "prio": prio,
                "dscp_value": dscp_values[0],
                # Lossy flows are non-ECN; leave the ECN field untouched.
                "ecn_value": None,
            })

        # ------------------------------------------------------------------
        # Build the PFC pause storm flow. It is transmitted from the Rx (DUT
        # egress) port back into the DUT and targets ONLY the lossless
        # priorities. Its rate is derived per link speed so the pause is
        # continuous for the whole data-flow window.
        # ------------------------------------------------------------------
        port_speed_gbps = int(int(rx_ports[0]['speed']) / 1000)
        pfc_storm_pps = calc_pfc_pause_flow_rate(port_speed_gbps)
        logger.info("PFC storm rate for {}G link: {} pps".format(port_speed_gbps, pfc_storm_pps))
        traffic_flow_config.append({
            "is_pfc": True,
            "flow_name": "PFC Storm {}".format(",".join(str(p) for p in LOSSLESS_PRIO)),
            "frame_size": 64,
            "pause_prio_list": LOSSLESS_PRIO,
            "pause_quanta": int("ffff", 16),
            "pause_flow_rate_pps": pfc_storm_pps,
            "pause_tx_port_name": "Port_{}".format(rx_ports[0]['port_id']),
            "pause_rx_port_name": "Port_{}".format(tx_ports[0]['port_id']),
            # Storm runs a little longer than the data flows so it fully covers them.
            "traffic_duration_fixed_seconds": TRAFFIC_DURATION_SEC + (2 * PFC_STORM_LEAD_SEC),
        })

        snappi_extra_params.traffic_flow_config = traffic_flow_config
        config = create_traffic_items(config, snappi_extra_params)
        api.set_config(config)
        logger.info("Starting All protocols")
        start_stop(snappi_api, operation="start", op_type="protocols")
        logger.info("Wait for Arp to Resolve ...")
        wait_for_arp(api, max_attempts=30, poll_interval_sec=2)

        # Clear DUT counters so the post-run PFC counter check is clean.
        egress_duthost.command("sonic-clear counters")
        egress_duthost.command("sonic-clear pfccounters")

        logger.info("Starting traffic (PFC storm + lossy data flows)")
        # start_stop(snappi_api, operation="start", op_type="traffic")
        logger.info('Starting Traffic')
        cs = snappi_api.control_state()
        cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.START
        snappi_api.set_control_state(cs)
        wait(TIMEOUT, "For Traffic To start")
        time.sleep(60)  # Wait for traffic to complete before stopping it
        logger.info('Stopping Traffic')
        cs = snappi_api.control_state()
        cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.STOP
        snappi_api.set_control_state(cs)
        wait(TIMEOUT, "For Traffic To stop")
        # start_stop(snappi_api, operation="stop", op_type="traffic")
        # ------------------------------------------------------------------
        # Collect and validate per-flow statistics.
        # ------------------------------------------------------------------
        columns = ["name", "frames_tx", "frames_rx", "loss", "frames_tx_rate", "frames_rx_rate"]
        get_stats(snappi_api, "Traffic Item Statistics", columns, 'print')
        flow_stats = get_stats(snappi_api, "Traffic Item Statistics")

        failures = []
        for prio in lossy_prio_list:
            flow_name = "Lossy Prio {}".format(prio)
            stat = next((s for s in flow_stats if s.name == flow_name), None)
            pytest_assert(stat is not None, "Statistics for flow {} not found".format(flow_name))

            loss_pct = float(stat.loss)
            if loss_pct > MAX_LOSS_PERCENT:
                failures.append("Lossy priority {} saw {}% loss (expected 0%)".format(prio, loss_pct))

            tx_rate = float(stat.frames_tx_rate)
            rx_rate = float(stat.frames_rx_rate)
            if tx_rate > 0:
                deviation = abs(tx_rate - rx_rate) / tx_rate
                if deviation > RX_RATE_TOLERANCE:
                    failures.append(
                        "Lossy priority {} Rx rate {} deviates {:.2%} from Tx rate {} (> 2%)".format(
                            prio, rx_rate, deviation, tx_rate))
            logger.info("Lossy priority {}: loss={}% tx_rate={} rx_rate={}".format(
                prio, loss_pct, tx_rate, rx_rate))

        # The DUT must NOT generate PFC on the lossy priorities.
        for prio in lossy_prio_list:
            tx_pfc = get_pfc_frame_count(egress_duthost, rx_ports[0]['peer_port'], prio, is_tx=True)
            if tx_pfc != 0:
                failures.append(
                    "DUT generated {} PFC frames on lossy priority {} (expected 0)".format(tx_pfc, prio))
            logger.info("DUT Tx PFC frames on lossy priority {}: {}".format(prio, tx_pfc))

        # Stop traffic before asserting so teardown is clean regardless of result.
        start_stop(snappi_api, operation="stop", op_type="traffic")
        start_stop(snappi_api, operation="stop", op_type="protocols", waittime=1)

        pytest_assert(not failures,
                      "PFC storm affected lossy traffic:\n{}".format("\n".join(failures)))
        logger.info("PASS: All lossy priority flows unaffected by the PFC storm on priorities {}".format(
            LOSSLESS_PRIO))
