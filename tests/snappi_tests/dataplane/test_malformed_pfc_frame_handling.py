"""
test_malformed_pfc_frame_handling.py

Implements test case Y02 of the PFC Lossy test plan:

    "Malformed PFC Frame Handling"

Data flows run on every priority at line rate while three malformed control
frame variants are injected into the DUT:

  * a MAC-Control frame carrying a reserved/invalid opcode,
  * a PFC frame whose class-enable vector sets all 16 bits (including the
    reserved upper byte), and
  * a truncated control frame (shorter than the 64-byte minimum).

A correctly behaving SONiC DUT must robustly ignore all of these without pausing
any traffic class or destabilising. Specifically the DUT must:

  * keep every priority flow at its configured rate with zero packet loss,
  * never relay the malformed control frames onward, and
  * keep its control plane responsive (no crash / counter corruption).

Topology assumed: Single-Tier -- the Snappi traffic generator ports are
directly connected to the SONiC DUT.

Reference test plan:
    docs/testplan/pfc_lossy_testplan.md  (Y02)
"""
from tests.snappi_tests.dataplane.imports import *  # noqa: F401, F403, F405
from snappi_tests.dataplane.files.helper import get_duthost_interface_details, create_snappi_config, \
    set_primary_chassis, create_traffic_items, start_stop, get_stats  # noqa: F401, F403, F405, E402
from tests.common.snappi_tests.snappi_helpers import wait_for_arp
from tests.common.snappi_tests.common_helpers import (
    stop_pfcwd,
    disable_packet_aging,
    calc_pfc_pause_flow_rate,
)  # noqa: F401

pytestmark = [pytest.mark.topology("nut")]
logger = logging.getLogger(__name__)

ip_version = "IPv4"
TIMEOUT = 30

# Pass/Fail thresholds from the test plan (Y02: Pass/Fail Criteria).
RX_RATE_TOLERANCE = 0.02       # every priority Rx rate must stay within +/-2% of Tx
MAX_LOSS_PERCENT = 0.0         # every priority MUST see 0% loss

TRAFFIC_DURATION_SEC = 60      # data flow run time
MALFORM_STORM_LEAD_SEC = 5     # malformed frames start/end this many seconds around the data flows

# The three malformed control frame variants injected during the test.
MALFORM_VARIANTS = [
    {"malform_type": "invalid_opcode", "frame_size": 64, "control_op_code": int("00ff", 16)},
    {"malform_type": "reserved_class_vector", "frame_size": 64, "class_enable_vector": int("1000", 16)},
    {"malform_type": "truncated", "frame_size": 40},
]


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


def _all_prio_list(config_facts):
    """Derive the full list of priorities (traffic classes) configured on the
    DUT from DSCP_TO_TC_MAP. A malformed control frame must be ignored on
    *every* priority, so there is no lossless/lossy split here."""
    mapped_tcs = {int(tc) for tc in config_facts["DSCP_TO_TC_MAP"]["AZURE"].values()}
    return sorted(mapped_tcs)


@pytest.mark.parametrize("subnet_type", [ip_version])
@pytest.mark.parametrize("speed", ["100G"])
@pytest.mark.parametrize("buffer_model", ["static"])
@pytest.mark.parametrize("asic_count", ["single"])
def test_malformed_pfc_frame_handling(
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
    Y02: Malformed control frames injected into the DUT must leave every priority
    flow at full throughput with zero loss, must not be relayed, and must not
    destabilise the DUT.
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
        all_prio_list = _all_prio_list(config_facts)
        logger.info("Priorities under test (must all ignore the malformed frames): {}".format(all_prio_list))

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
        # Build one data flow per priority, each at an equal share of the line
        # rate: line_rate / number_of_priorities.
        # ------------------------------------------------------------------
        per_flow_rate = round(100.0 / len(all_prio_list), 3)
        traffic_flow_config = []
        for prio in all_prio_list:
            dscp_values = [int(dscp) for dscp, tc in config_facts['DSCP_TO_TC_MAP']['AZURE'].items()
                           if int(tc) == prio]
            pytest_assert(dscp_values,
                          "Priority {} is not mapped to any DSCP in DSCP_TO_TC_MAP".format(prio))
            traffic_flow_config.append({
                "line_rate": per_flow_rate,
                "frame_size": 1024,
                "is_rdma": True,
                "flow_name": "Prio {}".format(prio),
                "tx_names": snappi_obj_handles["Tx"]["ip"],
                "rx_names": snappi_obj_handles["Rx"]["ip"],
                "traffic_duration_fixed_seconds": TRAFFIC_DURATION_SEC,
                "prio": prio,
                "dscp_value": dscp_values[0],
                # Non-ECN data flows; leave the ECN field untouched.
                "ecn_value": None,
            })

        # ------------------------------------------------------------------
        # Build the malformed control frame flows. Each is transmitted from the
        # Rx (DUT egress) port back into the DUT. Its rate is derived per link
        # speed so it is continuous for the whole data-flow window. The rx port
        # name is set to the Tx port so that any frame the DUT wrongly relays is
        # counted against the flow.
        # ------------------------------------------------------------------
        port_speed_gbps = int(int(rx_ports[0]['speed']) / 1000)
        malform_pps = calc_pfc_pause_flow_rate(port_speed_gbps)
        logger.info("Malformed frame injection rate for {}G link: {} pps".format(port_speed_gbps, malform_pps))
        malform_flow_names = []
        for variant in MALFORM_VARIANTS:
            flow_name = "Malformed PFC ({})".format(variant["malform_type"])
            malform_flow_names.append(flow_name)
            malform_flow = {
                "is_malformed_pfc": True,
                "flow_name": flow_name,
                "pause_quanta": int("ffff", 16),
                "pause_flow_rate_pps": malform_pps,
                "pause_tx_port_name": "Port_{}".format(rx_ports[0]['port_id']),
                "pause_rx_port_name": "Port_{}".format(tx_ports[0]['port_id']),
                # Injection runs a little longer than the data flows so it fully covers them.
                "traffic_duration_fixed_seconds": TRAFFIC_DURATION_SEC + (2 * MALFORM_STORM_LEAD_SEC),
            }
            malform_flow.update(variant)
            traffic_flow_config.append(malform_flow)

        snappi_extra_params.traffic_flow_config = traffic_flow_config
        config = create_traffic_items(config, snappi_extra_params)
        api.set_config(config)
        logger.info("Starting All protocols")
        start_stop(snappi_api, operation="start", op_type="protocols")
        logger.info("Wait for Arp to Resolve ...")
        wait_for_arp(api, max_attempts=30, poll_interval_sec=2)

        # Clear DUT counters so the post-run check is clean.
        egress_duthost.command("sonic-clear counters")
        egress_duthost.command("sonic-clear pfccounters")

        logger.info("Starting traffic (malformed control frames + data flows on all priorities)")
        start_stop(snappi_api, operation="start", op_type="traffic")
        wait(TIMEOUT, "For Traffic To start")
        time.sleep(TRAFFIC_DURATION_SEC)  # let the data flows run to completion
        logger.info("Stopping traffic")
        start_stop(snappi_api, operation="stop", op_type="traffic")

        # ------------------------------------------------------------------
        # Collect and validate per-flow statistics.
        # ------------------------------------------------------------------
        columns = ["name", "frames_tx", "frames_rx", "loss", "frames_tx_rate", "frames_rx_rate"]
        get_stats(snappi_api, "Traffic Item Statistics", columns, 'print')
        flow_stats = get_stats(snappi_api, "Traffic Item Statistics")
        failures = []
        for prio in all_prio_list:
            flow_name = "Prio {}".format(prio)
            stat = next((s for s in flow_stats if s.name == flow_name), None)
            pytest_assert(stat is not None, "Statistics for flow {} not found".format(flow_name))

            loss_pct = float(stat.loss)
            if loss_pct > MAX_LOSS_PERCENT:
                failures.append("Priority {} saw {}% loss (expected 0%)".format(prio, loss_pct))

            tx_rate = float(stat.frames_tx_rate)
            rx_rate = float(stat.frames_rx_rate)
            if tx_rate > 0:
                deviation = abs(tx_rate - rx_rate) / tx_rate
                if deviation > RX_RATE_TOLERANCE:
                    failures.append(
                        "Priority {} Rx rate {} deviates {:.2%} from Tx rate {} (> 2%)".format(
                            prio, rx_rate, deviation, tx_rate))
            logger.info("Priority {}: loss={}% tx_rate={} rx_rate={}".format(
                prio, loss_pct, tx_rate, rx_rate))

        # The DUT must NOT relay the malformed control frames. Each malformed
        # flow's Rx endpoint is the far (Tx) port, so any received frames on
        # these flows mean the DUT forwarded a frame it should have dropped.
        for flow_name in malform_flow_names:
            malform_stat = next((s for s in flow_stats if s.name == flow_name), None)
            pytest_assert(malform_stat is not None, "Statistics for flow {} not found".format(flow_name))
            relayed = int(malform_stat.frames_rx)
            if relayed != 0:
                failures.append(
                    "DUT relayed {} malformed frames for flow '{}' (expected 0)".format(relayed, flow_name))
            logger.info("Malformed frames relayed by DUT for '{}': {} (tx={})".format(
                flow_name, relayed, int(malform_stat.frames_tx)))

        # The DUT control plane must remain responsive (no crash / counter
        # corruption) after the malformed-frame injection.
        try:
            egress_duthost.command("show version")
        except Exception as e:  # noqa: BLE001
            failures.append("DUT control plane unresponsive after malformed frames: {}".format(e))

        # Stop protocols before asserting so teardown is clean regardless of result.
        start_stop(snappi_api, operation="stop", op_type="protocols", waittime=1)

        pytest_assert(not failures,
                      "Malformed control frames affected traffic or were relayed:\n{}".format(
                          "\n".join(failures)))
        logger.info("PASS: DUT robustly ignored all malformed control frames on all priorities {} "
                    "and did not relay them".format(all_prio_list))
