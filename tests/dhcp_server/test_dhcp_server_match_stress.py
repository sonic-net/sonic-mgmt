"""MATCH mode scale and flood tests (S01-S02 of the IPv4 match condition test plan)."""
import json
import logging
import os
import time

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.dhcp_relay_utils import enable_sonic_dhcpv4_relay_agent  # noqa: F401
from tests.common.utilities import wait_until
from dhcp_server_match_common import match_env, match_config_snapshot, match_test_isolation  # noqa: F401
from dhcp_server_match_common import VENDOR_A, VENDOR_B, DHCP_SERVER_CONTAINER, DHCP_SERVER_CONFIG_TOOL_GCU, \
    MatchConfig, DhcpClient, wait_for_kea_pools, get_dhcp_server_pids, new_client_mac

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('mx'),
    pytest.mark.parametrize("relay_agent", ["isc-relay-agent", "sonic-relay-agent"]),
]

SCALE_VENDORS = ["VendorS1", "VendorS2", "VendorS3", "VendorS4"]
SCALE_CONVERGE_SECONDS = 30
FLOOD_PORTS = 4
FLOOD_RATE = 100
FLOOD_SECONDS = 60
FLOOD_DEADLINE = 5
FLOOD_DRAIN = 5
FLOOD_MACS_PER_CATEGORY = 16
FLOOD_POOL_SIZE = 16
FLOOD_SCRIPT = "dhcp_server_match_flood.py"
PTF_FLOOD_DIR = "/tmp/dhcp_server_match_flood"


@pytest.fixture(scope="module", autouse=True)
def stress_module_setup(match_config_snapshot):  # noqa: F811
    yield


@pytest.fixture(autouse=True)
def stress_test_setup(match_test_isolation, enable_sonic_dhcpv4_relay_agent):  # noqa: F811
    yield


def _assert_services_healthy(duthost, pids):
    pytest_assert(get_dhcp_server_pids(duthost) == pids, "DHCP server processes restarted")
    status = duthost.shell("docker exec {} supervisorctl status".format(DHCP_SERVER_CONTAINER),
                           module_ignore_errors=True)["stdout_lines"]
    pytest_assert(all("RUNNING" in line for line in status if line.startswith("dhcp-server-ipv4")),
                  "dhcp_server processes are not running: {}".format(status))
    pytest_assert(duthost.is_container_running("dhcp_relay"), "dhcp_relay is not running")


def test_dhcp_server_match_scale(duthost, ptfadapter, match_env, relay_agent):  # noqa: F811
    """S01: five bindings on every VLAN member are generated in time and every combination is served."""
    env = match_env
    cfg = MatchConfig(env)
    for index, vendor in enumerate(SCALE_VENDORS):
        cfg.add_match("scale_v{}".format(index), "option60", vendor)
    expected = {}
    for port_index, port in enumerate(env.members):
        base = port_index * (len(SCALE_VENDORS) + 1)
        port_match = "scale_port_{}".format(port_index)
        cfg.add_match(port_match, "circuit_id", port.alias)
        cfg.add_binding("scale_{}_any".format(port_index), [port_match], ips=[env.ip(base)])
        expected[(port, None)] = env.ip(base)
        for index, vendor in enumerate(SCALE_VENDORS):
            ip = env.ip(base + index + 1)
            cfg.add_binding("scale_{}_v{}".format(port_index, index), [port_match, "scale_v{}".format(index)],
                            ips=[ip])
            expected[(port, vendor)] = ip
    logger.info("Scale configuration: %d ports, %d bindings", len(env.members), len(cfg.bindings))

    cfg.apply(duthost, config_tool=DHCP_SERVER_CONFIG_TOOL_GCU, wait=False)
    started = time.time()
    wait_for_kea_pools(duthost, env, cfg.expected_pools())
    converged = time.time() - started
    logger.info("Kea converged on %d pools %.1f seconds after the configuration change", len(expected), converged)
    pytest_assert(converged <= SCALE_CONVERGE_SECONDS, "Kea took {:.1f}s to apply {} bindings, limit is {}s".format(
        converged, len(cfg.bindings), SCALE_CONVERGE_SECONDS))

    for (port, vendor), ip in expected.items():
        DhcpClient(env, ptfadapter, port, vendor).dora(ip)


def _flood_clients(env, ports):
    """Clients and expected pools: VendorA and VendorB are bound per port; VendorZ and no Option 60 are not."""
    cfg = MatchConfig(env)
    cfg.add_match("vendor_a", "option60", VENDOR_A)
    cfg.add_match("vendor_b", "option60", VENDOR_B)
    clients = []
    offset = 0
    for port_index, port in enumerate(ports):
        port_match = "flood_port_{}".format(port_index)
        cfg.add_match(port_match, "circuit_id", port.alias)
        for vendor, vendor_match in ((VENDOR_A, "vendor_a"), (VENDOR_B, "vendor_b")):
            range_name = "flood_{}_{}".format(port_index, vendor_match)
            pool = env.ip_range(offset, offset + FLOOD_POOL_SIZE - 1)
            offset += FLOOD_POOL_SIZE
            cfg.add_range(range_name, pool[0], pool[-1])
            cfg.add_binding("flood_{}_{}".format(port_index, vendor_match), [port_match, vendor_match],
                            ranges=[range_name])
            clients += [{"iface": "eth{}".format(port.ptf_index), "mac": new_client_mac(), "opt60": vendor,
                         "expect": pool} for _ in range(FLOOD_MACS_PER_CATEGORY // len(ports))]
        for opt60 in ("VendorZ", None):
            clients += [{"iface": "eth{}".format(port.ptf_index), "mac": new_client_mac(), "opt60": opt60,
                         "expect": None} for _ in range(FLOOD_MACS_PER_CATEGORY // len(ports))]
    # Interleave categories and ports so that every second carries the full mix.
    clients.sort(key=lambda client: client["mac"])
    return cfg, clients


def test_dhcp_server_match_flood(duthost, ptfhost, ptfadapter, match_env, relay_agent):  # noqa: F811
    """S02: under a 100 pps DISCOVER flood every matching client is offered from its pool and no other is."""
    env = match_env
    ports = env.members[:FLOOD_PORTS]
    cfg, clients = _flood_clients(env, ports)
    cfg.apply(duthost, config_tool=DHCP_SERVER_CONFIG_TOOL_GCU)
    # Sanity check outside the flood: one client of each category on the first port.
    DhcpClient(env, ptfadapter, ports[0], VENDOR_A).expect_offer(env.ip_range(0, FLOOD_POOL_SIZE - 1))
    DhcpClient(env, ptfadapter, ports[0], "VendorZ").expect_no_offer()
    pids = get_dhcp_server_pids(duthost)

    flood_config = {"clients": clients, "rate": FLOOD_RATE, "duration": FLOOD_SECONDS,
                    "deadline": FLOOD_DEADLINE, "drain": FLOOD_DRAIN}
    ptfhost.file(path=PTF_FLOOD_DIR, state="directory")
    ptfhost.copy(src=os.path.join(os.path.dirname(__file__), FLOOD_SCRIPT), dest=PTF_FLOOD_DIR)
    ptfhost.copy(content=json.dumps(flood_config), dest="{}/config.json".format(PTF_FLOOD_DIR))
    try:
        output = ptfhost.shell("python3 {0}/{1} {0}/config.json".format(PTF_FLOOD_DIR, FLOOD_SCRIPT))["stdout"]
    finally:
        ptfhost.file(path=PTF_FLOOD_DIR, state="absent")
    result = json.loads(output.strip().splitlines()[-1])
    latencies = sorted(result.pop("latencies"))
    matching = sum(1 for index in range(result["sent"]) if clients[index % len(clients)]["expect"])
    summary = dict(result, matching=matching, offer_rate=round(result["offers"] / FLOOD_SECONDS, 1),
                   loss_pct=round(100.0 * result["missing"] / max(matching, 1), 2))
    if latencies:
        summary.update(latency_avg=round(sum(latencies) / len(latencies), 4),
                       latency_p99=latencies[int(len(latencies) * 0.99) - 1], latency_max=latencies[-1])
    logger.info("Flood result: %s", summary)

    pytest_assert(result["sent"] == FLOOD_RATE * FLOOD_SECONDS, "Sent {} DISCOVERs".format(result["sent"]))
    pytest_assert(result["offers"] > 0, "No OFFER was received during the flood")
    pytest_assert(result["missing"] == 0 and result["late"] == 0,
                  "Matching DISCOVERs without a timely OFFER: {}".format(summary))
    pytest_assert(result["wrong_pool"] == 0, "OFFERs from the wrong pool: {}".format(summary))
    pytest_assert(result["unexpected"] == 0, "OFFERs to unmatched clients: {}".format(summary))
    _assert_services_healthy(duthost, pids)
    pytest_assert(wait_until(30, 2, 0, lambda: DhcpClient(env, ptfadapter, ports[1], VENDOR_B).discover() is not None),
                  "DHCP server does not answer after the flood")
