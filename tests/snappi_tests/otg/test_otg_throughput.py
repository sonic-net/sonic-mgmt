"""
Phase 1e: incremental line-rate steps through a routed DUT via dpdk-tgen (OTG).

Traffic path matches phase 1c (see dpdk-tgen docs/phase1c-dut.md): generator
tx port -> DUT ingress -> DUT egress -> generator rx port.

Requires OTG testbed (ptf_image_name containing OTG), persisted L3/neighbor
config on the DUT, and conn graph links to the Snappi chassis.
"""

import logging
import os

import pytest
from tests.common.fixtures.conn_graph_facts import (  # noqa: F401
    conn_graph_facts,
    fanout_graph_facts,
)
from tests.common.helpers.assertions import pytest_assert
from tests.common.snappi_tests.otg_throughput_helpers import (
    build_otg_api_base,
    locations_from_snappi_ports,
    pick_snappi_ports_for_dut_links,
    run_one_rate_step,
)
from tests.common.snappi_tests.snappi_fixtures import (  # noqa: F401
    get_snappi_ports,
    get_snappi_ports_single_dut,
    snappi_api,
    snappi_api_serv_ip,
    snappi_api_serv_port,
)
logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("tgen"),
    pytest.mark.disable_loganalyzer,
]

# defaults (override with env vars).
DUT_INGRESS_PORT = os.environ.get("OTG_DUT_INGRESS_PORT", "Ethernet16")
DUT_EGRESS_PORT = os.environ.get("OTG_DUT_EGRESS_PORT", "Ethernet24")
SRC_IP = os.environ.get("OTG_SRC_IP", "20.1.1.0")
DST_IP = os.environ.get("OTG_DST_IP", "20.1.2.0")
SRC_MAC = os.environ.get("OTG_SRC_MAC", "94:40:c9:88:2e:24")
FRAME_SIZE = int(os.environ.get("OTG_FRAME_SIZE", "9000"))
DURATION_SEC = int(os.environ.get("OTG_DURATION_SEC", "60"))
GBPS_STEP = int(os.environ.get("OTG_GBPS_STEP", "10"))
GBPS_START = int(os.environ.get("OTG_GBPS_START", "5"))
GBPS_MAX = int(os.environ.get("OTG_GBPS_MAX", "95"))
COUNTER_TOLERANCE = int(os.environ.get("OTG_COUNTER_TOLERANCE", "0"))


@pytest.fixture(scope="module", autouse=True)
def require_otg_testbed(tbinfo):
    if "OTG" not in (tbinfo.get("ptf_image_name") or "").upper():
        pytest.skip("test_otg_throughput requires an OTG testbed (ptf_image_name contains OTG)")


@pytest.fixture(scope="module")
def otg_api_base(tbinfo, snappi_api_serv_ip, snappi_api_serv_port):     # noqa: F811
    return build_otg_api_base(tbinfo, snappi_api_serv_ip, snappi_api_serv_port)


@pytest.fixture(scope="module")
def otg_l2_l3(duthost):
    """L2/L3 header fields for the routed flow."""
    dst_mac = os.environ.get("OTG_DST_MAC")
    if not dst_mac:
        dst_mac = duthost.facts.get("router_mac")
        pytest_assert(dst_mac, "Set OTG_DST_MAC or ensure router_mac is in dut facts")
    return {
        "src_mac": SRC_MAC,
        "dst_mac": dst_mac,
        "src_ip": SRC_IP,
        "dst_ip": DST_IP,
        "src_port": int(os.environ.get("OTG_SRC_PORT", "5001")),
        "dst_port": int(os.environ.get("OTG_DST_PORT", "5002")),
    }


def _gbps_steps():
    steps = []
    gbps = GBPS_START
    while gbps <= GBPS_MAX:
        steps.append(gbps)
        gbps += GBPS_STEP
    return steps


@pytest.mark.parametrize("rate_gbps", _gbps_steps())
def test_otg_throughput_incremental(
    rate_gbps,
    duthost,
    snappi_api,     # noqa: F811
    get_snappi_ports,       # noqa: F811
    otg_api_base,
    otg_l2_l3,
):
    """
    For each target rate (default 5, 10, ... Gbps), run traffic for 60s and
    assert zero loss on the OTG flow and on DUT port counters (after clear).
    """
    tx_port, rx_port = pick_snappi_ports_for_dut_links(
        get_snappi_ports, DUT_INGRESS_PORT, DUT_EGRESS_PORT
    )
    tx_loc, rx_loc = locations_from_snappi_ports(tx_port, rx_port)

    logger.info(
        "OTG throughput step %s Gbps: %s -> DUT %s -> %s -> %s for %ds",
        rate_gbps,
        tx_loc,
        DUT_INGRESS_PORT,
        DUT_EGRESS_PORT,
        rx_loc,
        DURATION_SEC,
    )

    ok, checks, flow, port_metrics, dut_rx, dut_tx = run_one_rate_step(
        snappi_api,
        otg_api_base,
        tx_loc,
        rx_loc,
        duthost,
        DUT_INGRESS_PORT,
        DUT_EGRESS_PORT,
        rate_gbps,
        FRAME_SIZE,
        DURATION_SEC,
        otg_l2_l3,
        counter_tolerance=COUNTER_TOLERANCE,
    )

    for name, passed, detail in checks:
        logger.info("[%s] %s — %s", "PASS" if passed else "FAIL", name, detail)

    wire_gbps = (
        flow.frames_tx * (FRAME_SIZE + 24) * 8.0 / DURATION_SEC / 1e9
        if DURATION_SEC
        else 0.0
    )
    logger.info(
        "Step %s Gbps target: measured ~%.2f Gbps wire, dut RX_OK=%s TX_OK=%s",
        rate_gbps,
        wire_gbps,
        dut_rx,
        dut_tx,
    )

    pytest_assert(ok, "OTG/DUT loss at %s Gbps: %s" % (rate_gbps, checks))
