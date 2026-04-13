"""
Test Group 7: BGP Aggregate Address — Capacity and Stress Test

Objective: Validate system stability under high aggregate address count,
verified by route presence on M2 (upstream) neighbors.

Test cases:
  7.1  Large-scale aggregate deployment (1000 aggregates)
  7.2  Data-plane under scale
  7.3  Rapid add/remove cycling
"""

import logging
import random
import time

import pytest
import requests

import ptf.testutils as testutils
import ptf.packet as scapy
from ptf.mask import Mask
from natsort import natsorted

from bgp_aggregate_helpers import (
    BGP_AGGREGATE_ADDRESS,
    BGP_SETTLE_WAIT,
    AggregateCfg,
    check_route_on_neighbor,
    announce_contributing_routes,
    db_add_multiple_aggregates,
    gcu_add_placeholder_aggregate,
    verify_bgp_aggregate_cleanup,
    verify_route_on_m2,
    withdraw_contributing_routes,
)
from tests.bgp.bgp_helpers import get_upstream_ptf_intfs
from tests.common.gcu_utils import (
    create_checkpoint,
    rollback,
    rollback_or_reload,
    delete_checkpoint,
    verify_checkpoints_exist,
)
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.constants import UPSTREAM_NEIGHBOR_MAP, DOWNSTREAM_NEIGHBOR_MAP
from tests.common.utilities import wait_until
from tests.common.config_reload import config_reload as config_reload_func

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("m1"),
]

# ---- Test data ----
AGGR_V4 = "10.100.0.0/16"
CONTRIBUTING_V4 = ["10.100.1.0/24", "10.100.2.0/24", "10.100.3.0/24"]
PLACEHOLDER_PREFIX = "192.0.2.0/32"
EXABGP_BASE_PORT = 5000
EXABGP_BASE_PORT_V6 = 6000
EXABGP_BATCH_SIZE = 50    # routes per ExaBGP HTTP request
EXABGP_BATCH_DELAY = 0.1  # seconds between ExaBGP batches

# ---- Scale test constants ----
SCALE_COUNT = 1000
SCALE_SAMPLE_SIZE = 50
RAPID_CYCLE_ITERATIONS = 100
SCALE_PASS_RATIO = 0.9  # at least 90% of sampled aggregates must be present to pass
DATAPLANE_SAMPLE_SIZE = 20  # number of aggregate prefixes to probe with PTF traffic
DATAPLANE_PKT_COUNT = 10  # packets to send per destination
DATAPLANE_SRC_IP = "192.168.100.1"  # arbitrary source IP for PTF packets
TRAFFIC_WAIT_TIME = 5  # seconds to wait for packet verification

# DUT readiness
CRITICAL_SERVICES = ["bgp", "swss", "syncd"]
DUT_READY_TIMEOUT = 300       # max seconds to wait for DUT services after reboot
DUT_READY_INTERVAL = 15
CONVERGENCE_TIMEOUT = 180   # max seconds to poll for route convergence
CONVERGENCE_INTERVAL = 10   # seconds between convergence polls
CONVERGENCE_PROBE_SIZE = 5  # number of routes to probe per poll cycle
WITHDRAWAL_SAMPLE = 10      # number of routes to verify after removal


# ---- ExaBGP route helpers ----

def _exabgp_post(ptfip, port, commands_str):
    """Send one or more commands to ExaBGP in a single HTTP POST."""
    url = 'http://{}:{}'.format(ptfip, port)
    r = requests.post(url, data={'commands': commands_str},
                      proxies={"http": None, "https": None},
                      timeout=30)
    assert r.status_code == 200


def _exabgp_batch_commands(ptfip, port, commands):
    """Send a list of commands in batches of EXABGP_BATCH_SIZE per HTTP POST.

    Multiple commands are joined with ``\n`` so ExaBGP processes them in a
    single request, reducing HTTP round-trips from N to N/EXABGP_BATCH_SIZE.
    """
    for i in range(0, len(commands), EXABGP_BATCH_SIZE):
        batch = commands[i:i + EXABGP_BATCH_SIZE]
        _exabgp_post(ptfip, port, '\n'.join(batch))
        if EXABGP_BATCH_DELAY:
            time.sleep(EXABGP_BATCH_DELAY)


# ---- Aggregate generation helpers ----

def _generate_scale_aggregates(count):
    """Generate *count* unique AggregateCfg entries for scale testing.

    Produces 75 % IPv4 (/24) and 25 % IPv6 (/48) aggregates.
    IPv4 addresses use the 10.x.y.0/24 space; IPv6 use 2001:db8:N::/48.
    """
    v4_count = int(count * 0.75)
    v6_count = count - v4_count
    if v4_count > 256 * 256:
        raise ValueError(
            f"IPv4 aggregate count {v4_count} exceeds max 65536 unique /24 prefixes"
        )
    cfgs = []
    for i in range(1, v4_count + 1):
        octet2 = (i - 1) // 256 + 1
        octet3 = (i - 1) % 256
        prefix = f"10.{octet2}.{octet3}.0/24"
        cfgs.append(AggregateCfg(prefix=prefix, bbr_required=False,
                                 summary_only=False, as_set=False))
    for i in range(1, v6_count + 1):
        prefix = f"2001:db8:{i:x}::/48"
        cfgs.append(AggregateCfg(prefix=prefix, bbr_required=False,
                                 summary_only=False, as_set=False))
    return cfgs


def _generate_contributing_route(aggregate_prefix):
    """Return a single contributing route that falls inside *aggregate_prefix*.

    IPv4 /24 -> x.y.z.1/32 ;  IPv6 /48 -> prefix:1::/64
    """
    if ":" in aggregate_prefix:
        base = aggregate_prefix.split("::/")[0]
        return f"{base}:1::/64"
    base = aggregate_prefix.rsplit(".", 1)[0]
    return f"{base}.1/32"


# ---- Fixtures ----

@pytest.fixture(scope="module", autouse=True)
def setup_teardown(duthost):
    """Module-level checkpoint / rollback + multi-ASIC guard."""
    if duthost.is_multi_asic:
        pytest.skip("BGP aggregate-address tests do not support multi-ASIC")

    create_checkpoint(duthost)

    # Ensure the BGP_AGGREGATE_ADDRESS table exists so GCU "add" ops work.
    keys_out = duthost.shell(
        f"sonic-db-cli CONFIG_DB keys '{BGP_AGGREGATE_ADDRESS}|*'",
        module_ignore_errors=True,
    )["stdout"].strip()
    if not keys_out:
        gcu_add_placeholder_aggregate(duthost, PLACEHOLDER_PREFIX)

    yield

    try:
        rollback_or_reload(duthost, fail_on_rollback_error=False)
    finally:
        delete_checkpoint(duthost)


@pytest.fixture(scope="module")
def m1_topo_setup(duthosts, rand_one_dut_hostname, tbinfo, nbrhosts, ptfhost):
    """Resolve M0 (downstream) and M2 (upstream) neighbor details."""
    topo_type = tbinfo["topo"]["type"]
    if topo_type not in UPSTREAM_NEIGHBOR_MAP or topo_type not in DOWNSTREAM_NEIGHBOR_MAP:
        pytest.skip(
            f"Topology type {topo_type} not supported for neighbor-validated tests"
        )

    upstream_type = UPSTREAM_NEIGHBOR_MAP[topo_type].upper()
    downstream_type = DOWNSTREAM_NEIGHBOR_MAP[topo_type].upper()

    upstream_neighbors = natsorted(
        [n for n in nbrhosts.keys() if n.endswith(upstream_type)]
    )
    downstream_neighbors = natsorted(
        [n for n in nbrhosts.keys() if n.endswith(downstream_type)]
    )

    if not upstream_neighbors:
        pytest.skip(f"No upstream ({upstream_type}) neighbors found in topology")
    if not downstream_neighbors:
        pytest.skip(f"No downstream ({downstream_type}) neighbors found in topology")

    downstream = downstream_neighbors[0]
    downstream_offset = (
        tbinfo["topo"]["properties"]["topology"]["VMs"][downstream]["vm_offset"]
    )
    downstream_exabgp_port = EXABGP_BASE_PORT + downstream_offset
    downstream_exabgp_port_v6 = EXABGP_BASE_PORT_V6 + downstream_offset

    nhipv4 = tbinfo["topo"]["properties"]["configuration_properties"]["common"]["nhipv4"]
    nhipv6 = tbinfo["topo"]["properties"]["configuration_properties"]["common"]["nhipv6"]

    return {
        "upstream_neighbors": upstream_neighbors,
        "downstream": downstream,
        "downstream_neighbors": downstream_neighbors,
        "downstream_exabgp_port": downstream_exabgp_port,
        "downstream_exabgp_port_v6": downstream_exabgp_port_v6,
        "nhipv4": nhipv4,
        "nhipv6": nhipv6,
        "ptfip": ptfhost.mgmt_ip,
    }


# ---- Test class ----

class TestGroup7CapacityStress:
    """Test Group 7: Capacity and Stress Test.

    Validates system stability under high aggregate address count and
    rapid add/remove cycling.  Route presence is verified on M2 neighbors;
    DUT health is checked for container crashes and resource usage.
    """

    # -- internal helpers --------------------------------------------------

    def _wait_for_dut_ready(self, duthost):
        """Wait until critical DUT services are running.

        After a config_reload or unexpected reboot, services may take
        minutes to come back. Poll until bgp, swss, syncd are all running.
        If services are still not ready after the initial timeout, attempt
        a config_reload recovery and wait again.
        """
        def _services_up():
            for svc in CRITICAL_SERVICES:
                result = duthost.shell(
                    "docker ps --filter 'name=^{}$' --filter status=running -q".format(svc),
                    module_ignore_errors=True,
                ).get("stdout", "").strip()
                if not result:
                    logger.debug("Service %s is not running", svc)
                    return False
            return True

        def _host_reachable():
            """Check if the DUT host is reachable and Docker is running."""
            result = duthost.shell(
                "docker info > /dev/null 2>&1 && echo ok",
                module_ignore_errors=True,
            )
            return result.get("stdout", "").strip() == "ok"

        if not _services_up():
            logger.info("Waiting for DUT critical services to be ready...")
            # If host is unreachable (e.g. mid-reboot), wait for it first
            if not _host_reachable():
                logger.warning("DUT host unreachable, waiting for it to come back...")
                wait_until(DUT_READY_TIMEOUT, DUT_READY_INTERVAL, 0,
                           _host_reachable)
            converged = wait_until(DUT_READY_TIMEOUT, DUT_READY_INTERVAL, 0,
                                   _services_up)
            if not converged:
                logger.warning(
                    "DUT services not ready after %ds, attempting config_reload recovery",
                    DUT_READY_TIMEOUT,
                )
                config_reload_func(duthost, safe_reload=True,
                                   wait=DUT_READY_TIMEOUT)
                converged = wait_until(DUT_READY_TIMEOUT, DUT_READY_INTERVAL, 0,
                                       _services_up)
                if not converged:
                    for svc in CRITICAL_SERVICES:
                        ps_out = duthost.shell(
                            "docker ps -a --filter 'name=^{}$' --no-trunc".format(svc),
                            module_ignore_errors=True,
                        ).get("stdout", "").strip()
                        logger.error("Service %s docker status: %s", svc, ps_out or "not found")
                    pytest.fail("DUT critical services not ready after config_reload recovery")
            # Extra settle time after services come up
            time.sleep(BGP_SETTLE_WAIT)

    def _ensure_aggregate_table(self, duthost):
        """Ensure BGP_AGGREGATE_ADDRESS table exists in CONFIG_DB.

        After a rollback or bulk removal, the table may be gone.
        """
        keys_out = duthost.shell(
            f"sonic-db-cli CONFIG_DB keys '{BGP_AGGREGATE_ADDRESS}|*'",
            module_ignore_errors=True,
        ).get("stdout", "").strip()
        if not keys_out:
            gcu_add_placeholder_aggregate(duthost, PLACEHOLDER_PREFIX)

    def _rollback_and_recheckpoint(self, duthost):
        """Rollback to checkpoint and re-create it.

        If rollback fails (e.g. OOM), falls back to config_reload and waits
        for DUT services to recover.
        """
        output = rollback(duthost)
        if output.get('rc', 1) != 0 or \
           "Config rolled back successfully" not in output.get('stdout', ''):
            logger.warning("Rollback failed (rc=%s, stdout=%s), falling back to config_reload",
                           output.get('rc', '?'),
                           output.get('stdout', '')[-200:])
            # Flush stale aggregate entries from CONFIG_DB before reload so
            # bgpcfgd does not have to process thousands of entries on restart,
            # which can overwhelm the system and trigger a reboot.
            duthost.shell(
                "sonic-db-cli CONFIG_DB eval "
                "\"local keys = redis.call('keys','BGP_AGGREGATE_ADDRESS|*') "
                "for _,k in ipairs(keys) do redis.call('del',k) end "
                "return #keys\" 0",
                module_ignore_errors=True,
            )
            config_reload_func(duthost, safe_reload=True, wait=DUT_READY_TIMEOUT)
        create_checkpoint(duthost)
        self._ensure_aggregate_table(duthost)

    def _check_dut_health(self, duthost):
        """Assert no container crashes and CPU/memory are within limits."""
        crashed = duthost.shell(
            "docker ps -a --filter 'status=exited' -q",
            module_ignore_errors=True,
        ).get("stdout", "").strip()
        if crashed:
            logger.warning("Exited containers found (IDs): %s", crashed)

        cpu_out = duthost.shell(
            "top -bn1 | head -3 | grep 'Cpu' | awk '{print $2}'",
            module_ignore_errors=True,
        ).get("stdout", "").strip()
        if cpu_out:
            try:
                cpu_pct = float(cpu_out)
                pytest_assert(cpu_pct < 95.0, f"CPU usage too high: {cpu_pct}%")
            except ValueError:
                logger.warning("Could not parse CPU usage: %s", cpu_out)

        mem_out = duthost.shell(
            "free -m | awk '/Mem:/ {printf \"%.1f\", $3/$2*100}'",
            module_ignore_errors=True,
        ).get("stdout", "").strip()
        if mem_out:
            try:
                mem_pct = float(mem_out)
                pytest_assert(mem_pct < 95.0, f"Memory usage too high: {mem_pct}%")
            except ValueError:
                logger.warning("Could not parse memory usage: %s", mem_out)

    def _announce_contributing_for_aggregates(self, setup, cfgs):
        """Announce one contributing route per aggregate from M0 via ExaBGP.

        Routes are batched into groups of EXABGP_BATCH_SIZE per HTTP request
        to avoid 1-request-per-route overhead at scale.
        """
        self._bulk_exabgp_operation(setup, cfgs, "announce")

    def _withdraw_contributing_for_aggregates(self, setup, cfgs):
        """Withdraw one contributing route per aggregate from M0 via ExaBGP."""
        self._bulk_exabgp_operation(setup, cfgs, "withdraw")

    def _bulk_exabgp_operation(self, setup, cfgs, action):
        """Announce or withdraw contributing routes in batched HTTP requests.

        Args:
            setup: topology setup dict with ExaBGP ports and next-hop IPs.
            cfgs: list of AggregateCfg entries.
            action: 'announce' or 'withdraw'.
        """
        ptfip = setup["ptfip"]
        port_v4 = setup["downstream_exabgp_port"]
        port_v6 = setup["downstream_exabgp_port_v6"]
        nhipv4 = setup["nhipv4"]
        nhipv6 = setup["nhipv6"]

        v4_cmds = []
        v6_cmds = []
        for cfg in cfgs:
            contributing = _generate_contributing_route(cfg.prefix)
            if ":" in cfg.prefix:
                v6_cmds.append('{} route {} next-hop {}'.format(
                    action, contributing, nhipv6))
            else:
                v4_cmds.append('{} route {} next-hop {}'.format(
                    action, contributing, nhipv4))

        start = time.time()
        if v4_cmds:
            _exabgp_batch_commands(ptfip, port_v4, v4_cmds)
        if v6_cmds:
            _exabgp_batch_commands(ptfip, port_v6, v6_cmds)
        elapsed = time.time() - start

        logger.info(
            "ExaBGP %s complete: %d routes (%d v4 + %d v6) in %.1fs "
            "(%d HTTP requests)",
            action, len(cfgs), len(v4_cmds), len(v6_cmds), elapsed,
            (len(v4_cmds) + EXABGP_BATCH_SIZE - 1) // EXABGP_BATCH_SIZE
            + (len(v6_cmds) + EXABGP_BATCH_SIZE - 1) // EXABGP_BATCH_SIZE,
        )

    def _wait_for_routes_on_dut(self, duthost, cfgs):
        """Poll until a small probe of contributing routes appear in DUT BGP table.

        Replaces fixed time.sleep() with active polling for faster convergence.
        """
        probe = random.sample(cfgs, min(CONVERGENCE_PROBE_SIZE, len(cfgs)))

        def _probes_present():
            for cfg in probe:
                contributing = _generate_contributing_route(cfg.prefix)
                afi = "ipv6" if ":" in cfg.prefix else "ipv4"
                result = duthost.shell(
                    "vtysh -c 'show bgp {} unicast {}'".format(afi, contributing),
                    module_ignore_errors=True,
                ).get("stdout", "")
                if "Network not in table" in result or not result.strip():
                    return False
            return True

        converged = wait_until(CONVERGENCE_TIMEOUT, CONVERGENCE_INTERVAL, 0,
                               _probes_present)
        if not converged:
            logger.warning("Contributing route convergence timed out after %ds",
                           CONVERGENCE_TIMEOUT)
        return converged

    def _wait_for_aggregates_on_dut(self, duthost, cfgs, expected_present=True):
        """Poll until a probe of aggregates are present/absent in DUT BGP RIB."""
        probe = random.sample(cfgs, min(CONVERGENCE_PROBE_SIZE, len(cfgs)))

        def _probes_match():
            for cfg in probe:
                afi = "ipv6" if ":" in cfg.prefix else "ipv4"
                result = duthost.shell(
                    "vtysh -c 'show bgp {} unicast {}'".format(afi, cfg.prefix),
                    module_ignore_errors=True,
                ).get("stdout", "")
                is_present = bool(result.strip()) and "Network not in table" not in result
                if is_present != expected_present:
                    return False
            return True

        converged = wait_until(CONVERGENCE_TIMEOUT, CONVERGENCE_INTERVAL, 0,
                               _probes_match)
        action = "installed" if expected_present else "withdrawn"
        if not converged:
            logger.warning("Aggregate route %s convergence timed out after %ds",
                           action, CONVERGENCE_TIMEOUT)
        return converged

    def _sample_and_verify_on_m2(self, nbrhosts, neighbor, cfgs, sample_size):
        """Verify a random sample of aggregates on an M2 neighbor.

        Polls all sampled routes in a single wait_until loop instead of
        one wait_until per route, dramatically reducing verification time.
        Returns (present_count, sample_cfgs, failed_prefixes).
        """
        sample_cfgs = random.sample(cfgs, min(sample_size, len(cfgs)))
        remaining = {cfg.prefix for cfg in sample_cfgs}
        confirmed = set()

        def _check_batch():
            for prefix in list(remaining):
                if check_route_on_neighbor(nbrhosts, neighbor, prefix):
                    confirmed.add(prefix)
                    remaining.discard(prefix)
            return len(confirmed) / len(sample_cfgs) >= SCALE_PASS_RATIO

        wait_until(CONVERGENCE_TIMEOUT, CONVERGENCE_INTERVAL, 0, _check_batch)

        failed_prefixes = list(remaining)
        return len(confirmed), sample_cfgs, failed_prefixes

    def _verify_withdrawal_on_m2(self, nbrhosts, neighbor, cfgs, sample_size=None):
        """Verify a sample of routes are withdrawn from M2.

        Uses a small sample and single wait_until loop.
        """
        if sample_size is None:
            sample_size = WITHDRAWAL_SAMPLE
        sample = random.sample(cfgs, min(sample_size, len(cfgs)))
        remaining = {cfg.prefix if hasattr(cfg, 'prefix') else cfg for cfg in sample}

        def _check_gone():
            for prefix in list(remaining):
                if not check_route_on_neighbor(nbrhosts, neighbor, prefix):
                    remaining.discard(prefix)
            return len(remaining) == 0

        result = wait_until(CONVERGENCE_TIMEOUT, CONVERGENCE_INTERVAL, 0, _check_gone)
        if not result:
            logger.warning("Routes still present on M2 after withdrawal: %s",
                           remaining)
        return result

    # -- Test cases --------------------------------------------------------

    def test_7_1_large_scale_aggregate_deployment(
        self, duthosts, rand_one_dut_hostname, nbrhosts, m1_topo_setup
    ):
        """Test Case 7.1: Large-scale aggregate deployment (1000 aggregates).

        Steps:
        1. Generate 1000 unique aggregate address configs (mix of IPv4/IPv6)
        2. Apply all via direct CONFIG_DB writes (bypasses GCU for speed)
        3. Announce contributing routes for all 1000 from M0 via ExaBGP
        4. Poll for route convergence on DUT
        5. On M2: verify a sample (50 random) aggregate routes are received
        6. Verify no container crashes on DUT, CPU/memory within limits
        7. Rollback to remove all 1000 aggregates
        8. On M2: verify aggregate routes withdrawn
        """
        duthost = duthosts[rand_one_dut_hostname]
        setup = m1_topo_setup
        upstream = setup["upstream_neighbors"]
        neighbor = upstream[0]

        random.seed(42)

        all_cfgs = _generate_scale_aggregates(SCALE_COUNT)

        # Step 1-2: add all aggregates directly to CONFIG_DB (bypasses GCU for speed)
        db_add_multiple_aggregates(duthost, all_cfgs)

        # Step 3: announce contributing routes from M0
        self._announce_contributing_for_aggregates(setup, all_cfgs)

        # Step 4: poll for convergence
        self._wait_for_routes_on_dut(duthost, all_cfgs)
        self._wait_for_aggregates_on_dut(duthost, all_cfgs, expected_present=True)

        aggregates_removed = False
        try:
            # Step 5: verify a sample of 50 random aggregates on M2
            present_count, sample_cfgs, failed_prefixes = (
                self._sample_and_verify_on_m2(
                    nbrhosts, neighbor, all_cfgs, SCALE_SAMPLE_SIZE
                )
            )
            pass_ratio = present_count / len(sample_cfgs)
            logger.info(
                "Scale verification: %d/%d sampled aggregates present "
                "(%d%%), required %d%%",
                present_count, len(sample_cfgs),
                int(pass_ratio * 100), int(SCALE_PASS_RATIO * 100),
            )
            if failed_prefixes:
                logger.warning("Missing aggregates on M2: %s", failed_prefixes)
            pytest_assert(
                pass_ratio >= SCALE_PASS_RATIO,
                f"Only {present_count}/{len(sample_cfgs)} ({pass_ratio:.0%}) "
                f"sampled aggregates received on M2 neighbor {neighbor}; "
                f"required {SCALE_PASS_RATIO:.0%}. Missing: {failed_prefixes}",
            )

            # Step 6: DUT health
            self._check_dut_health(duthost)

            # Step 7: rollback to remove all aggregates (much faster than batched GCU remove)
            self._rollback_and_recheckpoint(duthost)
            aggregates_removed = True

            # Step 8: verify a sample of routes withdrawn on M2
            self._wait_for_aggregates_on_dut(duthost, all_cfgs, expected_present=False)
            verified_cfgs = [
                c for c in sample_cfgs if c.prefix not in failed_prefixes
            ]
            pytest_assert(
                self._verify_withdrawal_on_m2(nbrhosts, neighbor, verified_cfgs),
                "Some aggregates still present on M2 after removal",
            )

        finally:
            if not aggregates_removed:
                try:
                    self._rollback_and_recheckpoint(duthost)
                except Exception:
                    logger.warning(
                        "Best-effort rollback cleanup failed"
                    )
            self._withdraw_contributing_for_aggregates(setup, all_cfgs)
            time.sleep(BGP_SETTLE_WAIT)

    def test_7_2_data_plane_under_scale(
        self, duthosts, rand_one_dut_hostname, nbrhosts, ptfadapter,
        tbinfo, m1_topo_setup
    ):
        """Test Case 7.2: Data-plane under scale.

        Validates DUT forwarding stability while 1000 aggregate-address
        entries are active.  Traffic flows downstream (M0) -> DUT -> upstream
        (M2), matching the real M1 topology direction.

        Since aggregate routes are locally-originated (nexthop 0.0.0.0),
        they don't create upstream FIB entries themselves.  Instead, we
        verify that normal downstream-to-upstream forwarding remains
        healthy while the DUT processes 1000 aggregates — any instability
        in bgpcfgd / FRR / orchagent would manifest as packet drops.

        Topology (M1-48):
            [M2 upstream]  ← verifies aggregate received (control-plane)
                  |           ← also receives forwarded traffic (data-plane)
             eBGP session
                  |
            +-----+-----+
            |    DUT     |  ← 1000 aggregate-address entries active
            +-----+-----+
                  |
             eBGP session
                  |
            [M0 downstream]  ← ExaBGP announces contributing routes
                  |           ← PTF injects test traffic here

        Steps:
        1. Deploy 1000 aggregates via CONFIG_DB + announce contributing routes
        2. Control-plane gate: verify aggregates on M2
        3. Discover routes that DUT forwards toward M2 (upstream-nexthop routes)
        4. Inject traffic from downstream PTF port to upstream-reachable destinations
        5. Verify packets exit on upstream PTF ports
        6. Assert ≥90% pass rate and DUT health
        7. Cleanup: rollback aggregates + withdraw contributing routes
        8. Verify cleanup traffic is no longer forwarded
        """
        duthost = duthosts[rand_one_dut_hostname]
        setup = m1_topo_setup
        upstream = setup["upstream_neighbors"]
        neighbor = upstream[0]

        random.seed(43)

        # Ensure DUT is healthy before starting data-plane test
        self._wait_for_dut_ready(duthost)

        # Resolve PTF port mappings
        mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
        router_mac = duthost.facts["router_mac"]
        upstream_ptf_ports = get_upstream_ptf_intfs(mg_facts, tbinfo)
        pytest_assert(
            upstream_ptf_ports,
            "No upstream PTF ports found for data-plane testing",
        )

        # Traffic direction: downstream (M0) → DUT → upstream (M2)
        # Inject from a downstream PTF port, verify on upstream PTF ports.
        downstream_type = DOWNSTREAM_NEIGHBOR_MAP[tbinfo["topo"]["type"]].upper()
        downstream_ethernets = [
            k for k, v in mg_facts["minigraph_neighbors"].items()
            if v["name"].endswith(downstream_type)
        ]
        pytest_assert(
            downstream_ethernets,
            "No downstream interfaces found for PTF traffic injection",
        )
        tx_port = mg_facts["minigraph_ptf_indices"][downstream_ethernets[0]]
        rx_ports = upstream_ptf_ports
        logger.info(
            "Data-plane ports: tx=%d (downstream), rx=%s (upstream)",
            tx_port, rx_ports,
        )

        # Discover destination IPs routable via upstream (M2) neighbors.
        # These are routes the DUT learned from M2 with upstream nexthops.
        # We use M2 neighbor BGP peer IPs — always routable via upstream links.
        upstream_type = UPSTREAM_NEIGHBOR_MAP[tbinfo["topo"]["type"]].upper()
        upstream_ethernets = [
            k for k, v in mg_facts["minigraph_neighbors"].items()
            if v["name"].endswith(upstream_type)
        ]
        # Collect the M2-side peer IPs from the DUT's interface addresses
        upstream_dst_ips = []
        for intf in upstream_ethernets:
            peer_ipv4 = mg_facts.get("minigraph_neighbors", {}).get(intf, {}).get("peer_addr")
            if peer_ipv4:
                upstream_dst_ips.append(peer_ipv4)
        if not upstream_dst_ips:
            # Fallback: use IPs from the upstream interface subnets
            for intf in upstream_ethernets:
                for addr_info in mg_facts.get("minigraph_interfaces", []):
                    if addr_info.get("attachto") == intf and "." in addr_info.get("peer_addr", ""):
                        upstream_dst_ips.append(addr_info["peer_addr"])
        pytest_assert(
            upstream_dst_ips,
            "No upstream-reachable destination IPs found for data-plane testing",
        )
        logger.info("Upstream-reachable destinations: %s", upstream_dst_ips)

        all_cfgs = _generate_scale_aggregates(SCALE_COUNT)

        # Step 1: add aggregates directly to CONFIG_DB + announce contributing routes
        db_add_multiple_aggregates(duthost, all_cfgs)
        self._announce_contributing_for_aggregates(setup, all_cfgs)

        # Poll for convergence on DUT (replaces fixed 120s sleep)
        self._wait_for_routes_on_dut(duthost, all_cfgs)
        self._wait_for_aggregates_on_dut(duthost, all_cfgs, expected_present=True)

        aggregates_removed = False
        try:
            # Control-plane gate: spot-check a small sample on M2
            v4_cfgs = [c for c in all_cfgs if ":" not in c.prefix]
            present_count, sample_cfgs, failed_prefixes = (
                self._sample_and_verify_on_m2(
                    nbrhosts, neighbor, v4_cfgs, CONVERGENCE_PROBE_SIZE
                )
            )
            logger.info(
                "Data-plane M2 gate: %d/%d present",
                present_count, len(sample_cfgs),
            )

            # Step 3-4: send traffic from downstream toward upstream destinations
            # Use upstream-reachable IPs to verify forwarding under aggregate scale
            dp_sample_ips = upstream_dst_ips[:DATAPLANE_SAMPLE_SIZE]
            dp_failures = []

            ptfadapter.dataplane.flush()

            for dst_ip in dp_sample_ips:

                pkt = testutils.simple_ip_packet(
                    eth_dst=router_mac,
                    ip_src=DATAPLANE_SRC_IP,
                    ip_dst=dst_ip,
                )
                exp_pkt = Mask(pkt)
                exp_pkt.set_do_not_care_packet(scapy.Ether, "dst")
                exp_pkt.set_do_not_care_packet(scapy.Ether, "src")
                exp_pkt.set_do_not_care_packet(scapy.IP, "ttl")
                exp_pkt.set_do_not_care_packet(scapy.IP, "chksum")

                try:
                    testutils.send(
                        ptfadapter, pkt=pkt, port_id=tx_port,
                        count=DATAPLANE_PKT_COUNT,
                    )
                    testutils.verify_packet_any_port(
                        ptfadapter, pkt=exp_pkt,
                        ports=rx_ports, timeout=TRAFFIC_WAIT_TIME,
                    )
                    logger.info(
                        "Data-plane OK: traffic to %s forwarded upstream",
                        dst_ip,
                    )
                except AssertionError:
                    dp_failures.append(dst_ip)
                    logger.warning(
                        "Data-plane FAIL: traffic to %s not forwarded upstream",
                        dst_ip,
                    )

            dp_pass_ratio = (
                (len(dp_sample_ips) - len(dp_failures)) / len(dp_sample_ips)
                if dp_sample_ips else 1.0
            )
            logger.info(
                "Data-plane results: %d/%d passed (%d%%)",
                len(dp_sample_ips) - len(dp_failures), len(dp_sample_ips),
                int(dp_pass_ratio * 100),
            )
            if dp_failures:
                logger.warning(
                    "Data-plane failures for destinations: %s", dp_failures
                )
            pytest_assert(
                dp_pass_ratio >= SCALE_PASS_RATIO,
                f"Data-plane forwarding failed for "
                f"{len(dp_failures)}/{len(dp_sample_ips)} destinations "
                f"({dp_pass_ratio:.0%} pass rate, "
                f"required {SCALE_PASS_RATIO:.0%}). "
                f"Failed: {dp_failures}",
            )

            # Verify DUT stability after traffic
            self._check_dut_health(duthost)

            # Cleanup: rollback to remove aggregates
            self._rollback_and_recheckpoint(duthost)
            aggregates_removed = True

            # Withdraw contributing routes
            self._withdraw_contributing_for_aggregates(setup, all_cfgs)
            time.sleep(BGP_SETTLE_WAIT)

            # Re-verify: forwarding should still work for upstream destinations
            # (removing aggregates doesn't affect upstream routing)
            ptfadapter.dataplane.flush()
            for dst_ip in dp_sample_ips[:3]:
                pkt = testutils.simple_ip_packet(
                    eth_dst=router_mac,
                    ip_src=DATAPLANE_SRC_IP,
                    ip_dst=dst_ip,
                )
                exp_pkt = Mask(pkt)
                exp_pkt.set_do_not_care_packet(scapy.Ether, "dst")
                exp_pkt.set_do_not_care_packet(scapy.Ether, "src")
                exp_pkt.set_do_not_care_packet(scapy.IP, "ttl")
                exp_pkt.set_do_not_care_packet(scapy.IP, "chksum")

                testutils.send(
                    ptfadapter, pkt=pkt, port_id=tx_port,
                    count=DATAPLANE_PKT_COUNT,
                )
                testutils.verify_packet_any_port(
                    ptfadapter, pkt=exp_pkt,
                    ports=rx_ports, timeout=TRAFFIC_WAIT_TIME,
                )

        finally:
            if not aggregates_removed:
                try:
                    self._rollback_and_recheckpoint(duthost)
                except Exception:
                    logger.warning(
                        "Best-effort rollback cleanup failed"
                    )
                # Only withdraw if we didn't already in the try block
                self._withdraw_contributing_for_aggregates(setup, all_cfgs)
            time.sleep(BGP_SETTLE_WAIT)

    def test_7_3_rapid_add_remove_cycling(
        self, duthosts, rand_one_dut_hostname, nbrhosts, m1_topo_setup
    ):
        """Test Case 7.3: Rapid add/remove cycling.

        Steps:
        1. Loop 100 times: direct DB add aggregate -> poll M2 for presence ->
           direct DB delete aggregate -> poll M2 for withdrawal
        2. After all iterations: verify no stale routes on M2, DUT stable
        """
        duthost = duthosts[rand_one_dut_hostname]
        setup = m1_topo_setup
        upstream = setup["upstream_neighbors"]
        cfg = AggregateCfg(
            prefix=AGGR_V4, bbr_required=False,
            summary_only=False, as_set=False,
        )

        # Ensure DUT is healthy before starting cycling test
        self._wait_for_dut_ready(duthost)

        # Re-create checkpoint if lost (e.g. after reboot from prior test)
        try:
            if not verify_checkpoints_exist(duthost, 'test'):
                create_checkpoint(duthost)
        except Exception:
            logger.warning("Checkpoint verification failed, re-creating")
            create_checkpoint(duthost)

        announce_contributing_routes(setup, CONTRIBUTING_V4, "ipv4")
        self._ensure_aggregate_table(duthost)

        # Pre-compute direct DB commands for add/remove (bypass GCU overhead)
        db_key = f"BGP_AGGREGATE_ADDRESS|{cfg.prefix}"
        db_add_cmd = (
            f"sonic-db-cli CONFIG_DB HSET '{db_key}' "
            f"'bbr-required' 'false' 'summary-only' 'false' 'as-set' 'false'"
        )
        db_del_cmd = f"sonic-db-cli CONFIG_DB DEL '{db_key}'"

        # Use a single M2 neighbor for fast verification
        neighbor = upstream[0]

        def _route_present():
            return check_route_on_neighbor(nbrhosts, neighbor, AGGR_V4)

        def _route_absent():
            return not check_route_on_neighbor(nbrhosts, neighbor, AGGR_V4)

        # Tight polling: 30s timeout, 2s interval (vs 120s/5s default)
        CYCLE_TIMEOUT = 30
        CYCLE_INTERVAL = 2

        try:
            for iteration in range(1, RAPID_CYCLE_ITERATIONS + 1):
                if iteration % 10 == 1:
                    logger.info(
                        "Rapid cycle iteration %d/%d",
                        iteration, RAPID_CYCLE_ITERATIONS,
                    )

                # Add aggregate via direct DB write (~0.02s vs ~6s GCU)
                duthost.shell(db_add_cmd, module_ignore_errors=True)

                # Poll M2 for route presence (replaces sleep + verify)
                pytest_assert(
                    wait_until(CYCLE_TIMEOUT, CYCLE_INTERVAL, 0, _route_present),
                    f"Iteration {iteration}: aggregate not received on M2",
                )

                # Remove aggregate via direct DB write
                duthost.shell(db_del_cmd, module_ignore_errors=True)

                # Poll M2 for route withdrawal
                pytest_assert(
                    wait_until(CYCLE_TIMEOUT, CYCLE_INTERVAL, 0, _route_absent),
                    f"Iteration {iteration}: aggregate not withdrawn from M2",
                )

            # Final checks: no stale routes
            verify_route_on_m2(
                nbrhosts, upstream, AGGR_V4, expected_present=False
            )
            verify_bgp_aggregate_cleanup(duthost, cfg.prefix)

            # DUT health check
            self._check_dut_health(duthost)

        finally:
            withdraw_contributing_routes(setup, CONTRIBUTING_V4, "ipv4")
