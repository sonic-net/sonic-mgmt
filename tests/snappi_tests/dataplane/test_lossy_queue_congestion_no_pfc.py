"""
test_lossy_queue_congestion_no_pfc.py

Implements test case Y04 of the PFC Lossy test plan:

    "Lossy Queue Congestion - No PFC Generated"

A lossy priority is oversubscribed by driving two ingress ports at line rate
into a single egress port, so the ingress rate for the lossy queue exceeds the
egress capacity. A correctly behaving SONiC DUT must drop the excess traffic
rather than generate PFC frames for the lossy priority. Specifically the DUT
must:

  * NOT generate any Tx PFC frames for the congested lossy priority, and
  * drop the excess traffic (the flows see loss).

Topology assumed: Single-Tier -- the Snappi traffic generator ports are
directly connected to the SONiC DUT. Two Tx ports and one Rx port are required
so the egress queue can be genuinely oversubscribed.

Reference test plan:
    docs/testplan/pfc_lossy_testplan.md  (Y04)
"""
from tests.snappi_tests.dataplane.imports import *  # noqa: F401, F403, F405
from snappi_tests.dataplane.files.chelper import (
    get_duthost_interface_details,
    create_snappi_config,
    set_primary_chassis,
    create_traffic_items,
    start_stop,
    get_stats,
)  # noqa: F401, F403, F405, E402
from tests.common.snappi_tests.snappi_helpers import wait_for_arp
from tests.common.snappi_tests.common_helpers import (
    stop_pfcwd,
    disable_packet_aging,
    get_pfc_frame_count,
)  # noqa: F401

pytestmark = [pytest.mark.topology("nut")]
logger = logging.getLogger(__name__)

ip_version = "IPv4"
TIMEOUT = 30
# Per the test plan, SONiC's ``pfc_enable`` defaults to "3,4" (lossless);
# every other priority is lossy.
LOSSLESS_PRIO = [3, 4]
LOSSY_PRIO = [0, 1, 2, 5, 6, 7]

# Pass/Fail thresholds from the test plan (Y04: Pass/Fail Criteria).
MAX_TX_PFC_FRAMES = 0          # DUT Tx PFC for the lossy priority MUST be 0
MIN_LOSS_PERCENT = 0.0         # excess traffic MUST be dropped (loss > 0)

TRAFFIC_DURATION_SEC = 60      # data flow run time


@pytest.fixture(scope="module")
def congestion_ports(duthosts, get_snappi_ports):
    """Oversubscription needs two ingress ports feeding one egress port, so at
    least three snappi ports are required."""
    snappi_ports = get_duthost_interface_details(
        duthosts, get_snappi_ports, ip_version, protocol_type="IP"
    )
    pytest_assert(
        len(snappi_ports) >= 3,
        "Need at least 3 snappi ports (2 Tx + 1 Rx) to oversubscribe a lossy queue",
    )
    return snappi_ports


def _lossy_prio_list(config_facts):
    """Derive the lossy priority list from the DUT config, falling back to the
    test plan defaults. Lossless priorities are read from ``pfc_enable`` and the
    lossy set is the complement, restricted to priorities present in
    DSCP_TO_TC_MAP so the lossy flow can be given a valid DSCP value."""
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
def test_lossy_queue_congestion_no_pfc(
        duthosts,
        snappi_api,  # noqa: F811
        get_snappi_ports,  # noqa: F811
        set_primary_chassis,  # noqa: F811
        create_snappi_config,  # noqa: F811
        subnet_type,
        speed,
        buffer_model,
        asic_count,
        congestion_ports,
        fanout_graph_facts_multidut,
):
    """
    Y04: Oversubscribing a lossy queue must cause the DUT to drop the excess
    traffic and must NOT cause it to generate PFC frames on the lossy priority.
    """
    snappi_extra_params = SnappiTestParams()
    # Two ingress (Tx) ports feed a single egress (Rx) port so the egress lossy
    # queue is driven at ~2x line rate.
    tx_ports = [congestion_ports[0], congestion_ports[1]]
    rx_ports = [congestion_ports[2]]
    egress_duthost = rx_ports[0]['duthost']

    logger.info("Snappi ports used for the test:")
    for port in tx_ports + rx_ports:
        logger.info('{}: {}'.format(port['peer_port'], port['location']))

    config_facts = egress_duthost.config_facts(host=egress_duthost.hostname, source="running")['ansible_facts']
    pytest_assert('DSCP_TO_TC_MAP' in config_facts, "DSCP_TO_TC_MAP is not configured on the DUT")
    lossy_prio_list = _lossy_prio_list(config_facts)
    pytest_assert(lossy_prio_list, "No lossy priority available on the DUT")
    lossy_prio = lossy_prio_list[0]
    dscp_values = [int(dscp) for dscp, tc in config_facts['DSCP_TO_TC_MAP']['AZURE'].items()
                   if int(tc) == lossy_prio]
    pytest_assert(dscp_values,
                  "Lossy priority {} is not mapped to any DSCP in DSCP_TO_TC_MAP".format(lossy_prio))
    logger.info("Oversubscribing lossy priority {} (DSCP {})".format(lossy_prio, dscp_values[0]))

    logger.info("Stopping PFC watchdog")
    stop_pfcwd(egress_duthost, rx_ports[0]['asic_value'])
    logger.info("Disabling packet aging if necessary")
    disable_packet_aging(egress_duthost)

    # Snappi protocol (IP) endpoints for the data flows: two Tx ports, one Rx.
    snappi_extra_params.protocol_config = {
        "Tx": {"protocol_type": "ip", "ports": tx_ports,
               "subnet_type": subnet_type, 'is_rdma': True},
        "Rx": {"protocol_type": "ip",
               "ports": rx_ports, "subnet_type": subnet_type, 'is_rdma': True},
    }
    config, snappi_obj_handles = create_snappi_config(snappi_extra_params)
    api = snappi_api

    # ------------------------------------------------------------------
    # Build one congestion flow from each Tx port into the single Rx port, both
    # on the same lossy priority and each at 100% line rate. Their aggregate
    # (~200%) oversubscribes the egress lossy queue.
    # ------------------------------------------------------------------
    tx_handles = snappi_obj_handles["Tx"]["ip"]
    rx_handles = snappi_obj_handles["Rx"]["ip"]
    congestion_flow_names = []
    traffic_flow_config = []
    for idx, tx_handle in enumerate(tx_handles):
        flow_name = "Congestion Flow {}".format(idx)
        congestion_flow_names.append(flow_name)
        traffic_flow_config.append({
            "line_rate": 100,
            "frame_size": 1024,
            "is_rdma": True,
            "flow_name": flow_name,
            "tx_names": [tx_handle],
            "rx_names": rx_handles,
            "traffic_duration_fixed_seconds": TRAFFIC_DURATION_SEC,
            "prio": lossy_prio,
            "dscp_value": dscp_values[0],
            # Lossy flow is non-ECN; leave the ECN field untouched.
            "ecn_value": None,
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

    logger.info("Starting traffic (oversubscribing lossy priority {})".format(lossy_prio))
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

    # The excess traffic MUST be dropped -- aggregate Tx should exceed aggregate
    # Rx (i.e. the flows see loss) since the egress queue is oversubscribed.
    total_tx = 0
    total_rx = 0
    for flow_name in congestion_flow_names:
        stat = next((s for s in flow_stats if s.name == flow_name), None)
        pytest_assert(stat is not None, "Statistics for flow {} not found".format(flow_name))
        total_tx += int(stat.frames_tx)
        total_rx += int(stat.frames_rx)
        logger.info("{}: tx={} rx={} loss={}%".format(
            flow_name, int(stat.frames_tx), int(stat.frames_rx), float(stat.loss)))
    if total_tx > 0:
        aggregate_loss_pct = (total_tx - total_rx) / total_tx * 100.0
        logger.info("Aggregate loss across congestion flows: {:.2f}%".format(aggregate_loss_pct))
        if aggregate_loss_pct <= MIN_LOSS_PERCENT:
            failures.append(
                "Expected the oversubscribed lossy queue to drop excess traffic, "
                "but aggregate loss was {:.2f}%".format(aggregate_loss_pct))

    # The DUT must NOT generate PFC on the congested lossy priority.
    tx_pfc = get_pfc_frame_count(egress_duthost, rx_ports[0]['peer_port'], lossy_prio, is_tx=True)
    logger.info("DUT Tx PFC frames on lossy priority {}: {}".format(lossy_prio, tx_pfc))
    if tx_pfc > MAX_TX_PFC_FRAMES:
        failures.append(
            "DUT generated {} PFC frames on congested lossy priority {} (expected 0)".format(
                tx_pfc, lossy_prio))

    # Stop protocols before asserting so teardown is clean regardless of result.
    start_stop(snappi_api, operation="stop", op_type="protocols", waittime=1)

    pytest_assert(not failures,
                  "Lossy queue congestion behaved incorrectly:\n{}".format("\n".join(failures)))
    logger.info("PASS: DUT dropped excess traffic on the oversubscribed lossy priority {} "
                "and generated no PFC frames".format(lossy_prio))
