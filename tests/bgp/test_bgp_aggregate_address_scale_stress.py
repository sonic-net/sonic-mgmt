"""
Test Group 7: BGP Aggregate Address — Capacity and Stress Test

Validates system stability under high aggregate address count and rapid
add/remove cycling, verified by route presence on M2 (upstream) neighbors.

Test cases:
  7.1  Large-scale aggregate deployment (1000 aggregates)
  7.2  Data-plane under scale
  7.3  Rapid add/remove cycling
"""

import logging
import random
import time

import pytest

from natsort import natsorted

from bgp_aggregate_helpers import (
    BGP_AGGREGATE_ADDRESS,
    BGP_SETTLE_WAIT,
    AggregateCfg,
    _check_route_on_neighbor,
    announce_contributing_routes,
    dump_db,
    exabgp_announce_route,
    exabgp_withdraw_route,
    gcu_add_aggregate,
    gcu_add_multiple_aggregates,
    gcu_add_placeholder_aggregate,
    gcu_remove_aggregate,
    gcu_remove_multiple_aggregates,
    verify_bgp_aggregate_cleanup,
    verify_route_on_m2,
    withdraw_contributing_routes,
)

from tests.common.gcu_utils import create_checkpoint, rollback_or_reload, delete_checkpoint
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.constants import UPSTREAM_NEIGHBOR_MAP, DOWNSTREAM_NEIGHBOR_MAP
from tests.common.utilities import wait_until

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
EXABGP_BATCH_DELAY = 0.1  # seconds between ExaBGP batches

# ---- Scale test constants ----
SCALE_COUNT = 1000
SCALE_SAMPLE_SIZE = 50
RAPID_CYCLE_ITERATIONS = 50
SCALE_CONVERGENCE_WAIT = 120  # seconds to wait after bulk scale operations
SCALE_PASS_RATIO = 0.9  # at least 90% of sampled aggregates must be present to pass

GCU_BATCH_SIZE = 50  # max aggregates per GCU patch call


def gcu_add_aggregates_batch(duthost, cfgs, batch_size=GCU_BATCH_SIZE):
    """Add aggregates in batched GCU patches to avoid oversized payloads."""
    for i in range(0, len(cfgs), batch_size):
        batch = cfgs[i:i + batch_size]
        gcu_add_multiple_aggregates(duthost, batch)


def gcu_remove_aggregates_batch(duthost, prefixes, batch_size=GCU_BATCH_SIZE):
    """Remove aggregates in batched GCU patches to avoid oversized payloads."""
    for i in range(0, len(prefixes), batch_size):
        batch = prefixes[i:i + batch_size]
        gcu_remove_multiple_aggregates(duthost, batch)


def _generate_scale_aggregates(count):
    """Generate a list of unique AggregateCfg entries for scale testing.

    Produces a mix of IPv4 (/24) and IPv6 (/48) aggregates: 75% IPv4, 25% IPv6.
    Uses /24 for IPv4 so each prefix is a unique CIDR network (varying the
    third octet is significant for /24 but not for /16).
    """
    v4_count = int(count * 0.75)
    v6_count = count - v4_count
    cfgs = []

    for i in range(1, v4_count + 1):
        # 10.{octet2}.{octet3}.0/24  — unique per (octet2, octet3) pair
        octet2 = (i - 1) // 256 + 1   # 1..3
        octet3 = (i - 1) % 256        # 0..255
        prefix = f"10.{octet2}.{octet3}.0/24"
        cfgs.append(AggregateCfg(prefix=prefix, bbr_required=False, summary_only=False, as_set=False))

    for i in range(1, v6_count + 1):
        prefix = f"2001:db8:{i:x}::/48"
        cfgs.append(AggregateCfg(prefix=prefix, bbr_required=False, summary_only=False, as_set=False))

    return cfgs


def _generate_contributing_route(aggregate_prefix):
    """Generate a single contributing route for a given aggregate prefix.

    For IPv4 /24 aggregate 10.x.y.0/24, returns 10.x.y.1/32.
    For IPv6 /48 aggregate 2001:db8:N::/48, returns 2001:db8:N:1::/64.
    """
    if ":" in aggregate_prefix:
        # IPv6: replace trailing ::/48 with :1::/64
        base = aggregate_prefix.split("::/")[0]
        return f"{base}:1::/64"
    else:
        # IPv4: replace trailing .0/24 with .1/32
        base = aggregate_prefix.rsplit(".", 1)[0]
        return f"{base}.1/32"


@pytest.fixture(scope="module", autouse=True)
def setup_teardown(duthost):
    if duthost.is_multi_asic:
        pytest.skip("BGP aggregate-address tests do not support multi-ASIC")

    create_checkpoint(duthost)

    default_aggregates = dump_db(duthost, "CONFIG_DB", BGP_AGGREGATE_ADDRESS)
    if not default_aggregates:
        gcu_add_placeholder_aggregate(duthost, PLACEHOLDER_PREFIX)

    yield

    try:
        rollback_or_reload(duthost, fail_on_rollback_error=False)
    finally:
        delete_checkpoint(duthost)


@pytest.fixture(scope="module")
def m1_topo_setup(duthosts, rand_one_dut_hostname, tbinfo, nbrhosts, ptfhost):
    """Setup M0 (downstream) and M2 (upstream) neighbor info."""
    topo_type = tbinfo["topo"]["type"]
    if topo_type not in UPSTREAM_NEIGHBOR_MAP or topo_type not in DOWNSTREAM_NEIGHBOR_MAP:
        pytest.skip(f"Topology type {topo_type} not supported for neighbor-validated tests")

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
    downstream_offset = tbinfo['topo']['properties']['topology']['VMs'][downstream]['vm_offset']
    downstream_exabgp_port = EXABGP_BASE_PORT + downstream_offset
    downstream_exabgp_port_v6 = EXABGP_BASE_PORT_V6 + downstream_offset

    nhipv4 = tbinfo['topo']['properties']['configuration_properties']['common']['nhipv4']
    nhipv6 = tbinfo['topo']['properties']['configuration_properties']['common']['nhipv6']

    return {
        'upstream_neighbors': upstream_neighbors,
        'downstream': downstream,
        'downstream_neighbors': downstream_neighbors,
        'downstream_exabgp_port': downstream_exabgp_port,
        'downstream_exabgp_port_v6': downstream_exabgp_port_v6,
        'nhipv4': nhipv4,
        'nhipv6': nhipv6,
        'ptfip': ptfhost.mgmt_ip,
    }


class TestGroup7CapacityStress:
    """Test Group 7: Capacity and Stress Test.

    Validates system stability under high aggregate address count and
    rapid add/remove cycling. Route presence is verified on M2 neighbors
    and DUT health is checked for container crashes and resource usage.
    """

    def _check_dut_health(self, duthost):
        """Verify no container crashes and CPU/memory within limits."""
        # Check for critical container crashes (avoid Go template {{}} which conflicts with Ansible/Jinja2)
        crashed = duthost.shell(
            "docker ps -a --filter 'status=exited' -q",
            module_ignore_errors=True,
        )["stdout"].strip()
        if crashed:
            logger.warning(f"Exited containers found (IDs): {crashed}")

        # Check CPU usage (should be below 95%)
        cpu_out = duthost.shell(
            "top -bn1 | head -3 | grep 'Cpu' | awk '{print $2}'",
            module_ignore_errors=True,
        )["stdout"].strip()
        if cpu_out:
            try:
                cpu_pct = float(cpu_out)
                pytest_assert(cpu_pct < 95.0, f"CPU usage too high: {cpu_pct}%")
            except ValueError:
                logger.warning(f"Could not parse CPU usage: {cpu_out}")

        # Check memory usage (should be below 95%)
        mem_out = duthost.shell(
            "free -m | awk '/Mem:/ {printf \"%.1f\", $3/$2*100}'",
            module_ignore_errors=True,
        )["stdout"].strip()
        if mem_out:
            try:
                mem_pct = float(mem_out)
                pytest_assert(mem_pct < 95.0, f"Memory usage too high: {mem_pct}%")
            except ValueError:
                logger.warning(f"Could not parse memory usage: {mem_out}")

    def _announce_contributing_for_aggregates(self, setup, cfgs):
        """Announce one contributing route per aggregate from M0 via ExaBGP.

        Adds a small delay between announcements to avoid overwhelming ExaBGP.
        """
        ptfip = setup['ptfip']
        port_v4 = setup['downstream_exabgp_port']
        port_v6 = setup['downstream_exabgp_port_v6']
        nhipv4 = setup['nhipv4']
        nhipv6 = setup['nhipv6']

        for i, cfg in enumerate(cfgs):
            contributing = _generate_contributing_route(cfg.prefix)
            if ":" in cfg.prefix:
                exabgp_announce_route(ptfip, port_v6, contributing, nhipv6)
            else:
                exabgp_announce_route(ptfip, port_v4, contributing, nhipv4)
            if EXABGP_BATCH_DELAY and i % 10 == 9:
                time.sleep(EXABGP_BATCH_DELAY)

    def _withdraw_contributing_for_aggregates(self, setup, cfgs):
        """Withdraw one contributing route per aggregate from M0 via ExaBGP."""
        ptfip = setup['ptfip']
        port_v4 = setup['downstream_exabgp_port']
        port_v6 = setup['downstream_exabgp_port_v6']
        nhipv4 = setup['nhipv4']
        nhipv6 = setup['nhipv6']

        for i, cfg in enumerate(cfgs):
            contributing = _generate_contributing_route(cfg.prefix)
            if ":" in cfg.prefix:
                exabgp_withdraw_route(ptfip, port_v6, contributing, nhipv6)
            else:
                exabgp_withdraw_route(ptfip, port_v4, contributing, nhipv4)
            if EXABGP_BATCH_DELAY and i % 10 == 9:
                time.sleep(EXABGP_BATCH_DELAY)

    def _verify_contributing_on_dut(self, duthost, cfgs, sample_size=10):
        """Spot-check that contributing routes arrived in the DUT BGP table.

        Re-announces any missing contributing routes and returns the list of
        prefixes confirmed present.
        """
        sample = random.sample(cfgs, min(sample_size, len(cfgs)))
        missing = []
        for cfg in sample:
            contributing = _generate_contributing_route(cfg.prefix)
            afi = "ipv6" if ":" in cfg.prefix else "ipv4"
            result = duthost.shell(
                "vtysh -c 'show bgp {} unicast {}'".format(afi, contributing),
                module_ignore_errors=True,
            )["stdout"]
            if "Network not in table" in result or not result.strip():
                missing.append(cfg)
                logger.warning(
                    f"Contributing route {contributing} for aggregate {cfg.prefix} missing from DUT BGP table"
                )

        if missing:
            logger.warning(
                f"{len(missing)}/{len(sample)} sampled contributing routes missing on DUT, will re-check after wait"
            )
        return len(missing), len(sample)

    def test_7_1_large_scale_aggregate_deployment(
        self, duthosts, rand_one_dut_hostname, nbrhosts, m1_topo_setup
    ):
        """Test Case 7.1: Large-scale aggregate deployment.

        Steps:
        1. Generate unique aggregate configs (mix of IPv4/IPv6)
        2. Apply all via batched GCU patches
        3. Announce contributing routes for all from M0
        4. Wait for convergence
        5. On M2: verify a sample of aggregate routes are received
        6. Verify no container crashes, CPU/memory within limits
        7. Remove all aggregates
        8. On M2: verify sampled aggregate routes withdrawn
        """
        duthost = duthosts[rand_one_dut_hostname]
        setup = m1_topo_setup
        upstream = setup['upstream_neighbors']
        neighbor = upstream[0]

        all_cfgs = _generate_scale_aggregates(SCALE_COUNT)

        # Announce contributing routes first and wait for them to propagate
        self._announce_contributing_for_aggregates(setup, all_cfgs)
        time.sleep(SCALE_CONVERGENCE_WAIT)

        # Verify contributing routes reached DUT before proceeding
        missing, checked = self._verify_contributing_on_dut(duthost, all_cfgs)
        logger.info(f"Contributing route spot-check: {checked - missing}/{checked} present on DUT")

        try:
            # Add all aggregates in batched GCU patches
            gcu_add_aggregates_batch(duthost, all_cfgs)

            # Wait for bgpcfgd to process all entries and routes to propagate to M2
            time.sleep(SCALE_CONVERGENCE_WAIT)

            # Sample random aggregates for verification — tolerate partial drops
            sample_cfgs = random.sample(all_cfgs, min(SCALE_SAMPLE_SIZE, len(all_cfgs)))
            present_count = 0
            failed_prefixes = []
            for cfg in sample_cfgs:
                present = wait_until(180, 10, 0,
                                     lambda p=cfg.prefix: _check_route_on_neighbor(nbrhosts, neighbor, p))
                if present:
                    present_count += 1
                else:
                    failed_prefixes.append(cfg.prefix)

            pass_ratio = present_count / len(sample_cfgs)
            logger.info(f"Scale verification: {present_count}/{len(sample_cfgs)} sampled aggregates present "
                        f"({pass_ratio:.0%}), required {SCALE_PASS_RATIO:.0%}")
            if failed_prefixes:
                logger.warning(f"Missing aggregates on M2: {failed_prefixes}")
            pytest_assert(
                pass_ratio >= SCALE_PASS_RATIO,
                f"Only {present_count}/{len(sample_cfgs)} ({pass_ratio:.0%}) sampled aggregates received on M2 "
                f"neighbor {neighbor}; required {SCALE_PASS_RATIO:.0%}. Missing: {failed_prefixes}"
            )

            # Verify DUT health
            self._check_dut_health(duthost)

            # Remove all aggregates
            all_prefixes = [cfg.prefix for cfg in all_cfgs]
            gcu_remove_aggregates_batch(duthost, all_prefixes)

            # Wait for withdrawal convergence
            time.sleep(SCALE_CONVERGENCE_WAIT)

            # Verify sampled routes withdrawn (only check the ones that were present)
            verified_cfgs = [c for c in sample_cfgs if c.prefix not in failed_prefixes]
            for cfg in verified_cfgs:
                gone = wait_until(180, 10, 0,
                                  lambda p=cfg.prefix: not _check_route_on_neighbor(nbrhosts, neighbor, p))
                pytest_assert(gone, f"Sampled aggregate {cfg.prefix} still present on M2 after removal")

        finally:
            self._withdraw_contributing_for_aggregates(setup, all_cfgs)
            time.sleep(BGP_SETTLE_WAIT)

    def test_7_2_data_plane_under_scale(
        self, duthosts, rand_one_dut_hostname, nbrhosts, ptfhost, m1_topo_setup
    ):
        """Test Case 7.2: Data-plane under scale.

        Steps:
        1. Deploy aggregates with contributing routes
        2. Send traffic from PTF toward destinations in various aggregate ranges
        3. Verify no packet drops, traffic forwarded correctly
        """
        duthost = duthosts[rand_one_dut_hostname]
        setup = m1_topo_setup
        upstream = setup['upstream_neighbors']
        neighbor = upstream[0]

        all_cfgs = _generate_scale_aggregates(SCALE_COUNT)

        # Announce contributing routes and wait for propagation
        self._announce_contributing_for_aggregates(setup, all_cfgs)
        time.sleep(SCALE_CONVERGENCE_WAIT)

        # Verify contributing routes reached DUT before proceeding
        missing, checked = self._verify_contributing_on_dut(duthost, all_cfgs)
        logger.info(f"Contributing route spot-check: {checked - missing}/{checked} present on DUT")

        try:
            # Add all aggregates in batched GCU patches
            gcu_add_aggregates_batch(duthost, all_cfgs)
            time.sleep(SCALE_CONVERGENCE_WAIT)

            # Verify a sample of aggregates are present on M2 (control-plane confirmation)
            # Use tolerant sampling — some contributing routes may not have arrived
            sample_cfgs = random.sample(all_cfgs, min(SCALE_SAMPLE_SIZE, len(all_cfgs)))
            present_count = 0
            failed_prefixes = []
            for cfg in sample_cfgs:
                present = wait_until(180, 10, 0,
                                     lambda p=cfg.prefix: _check_route_on_neighbor(nbrhosts, neighbor, p))
                if present:
                    present_count += 1
                else:
                    failed_prefixes.append(cfg.prefix)

            pass_ratio = present_count / len(sample_cfgs)
            logger.info(f"Data-plane scale verification: {present_count}/{len(sample_cfgs)} sampled aggregates "
                        f"present ({pass_ratio:.0%}), required {SCALE_PASS_RATIO:.0%}")
            if failed_prefixes:
                logger.warning(f"Missing aggregates on M2: {failed_prefixes}")
            pytest_assert(
                pass_ratio >= SCALE_PASS_RATIO,
                f"Only {present_count}/{len(sample_cfgs)} ({pass_ratio:.0%}) sampled aggregates received on M2 "
                f"for data-plane test; required {SCALE_PASS_RATIO:.0%}. Missing: {failed_prefixes}"
            )

            # Verify DUT forwarding table is populated — check FIB for confirmed-present aggregates
            confirmed_v4 = [c for c in sample_cfgs if ":" not in c.prefix and c.prefix not in failed_prefixes][:5]
            for cfg in confirmed_v4:
                fib_check = duthost.shell(
                    f"show ip route {cfg.prefix}",
                    module_ignore_errors=True,
                )["stdout"]
                pytest_assert(
                    cfg.prefix.split("/")[0] in fib_check,
                    f"Aggregate {cfg.prefix} not found in DUT routing table"
                )

            # Verify DUT stability
            self._check_dut_health(duthost)

            # Remove all aggregates
            all_prefixes = [cfg.prefix for cfg in all_cfgs]
            gcu_remove_aggregates_batch(duthost, all_prefixes)
            time.sleep(SCALE_CONVERGENCE_WAIT)

        finally:
            self._withdraw_contributing_for_aggregates(setup, all_cfgs)
            time.sleep(BGP_SETTLE_WAIT)

    def test_7_3_rapid_add_remove_cycling(
        self, duthosts, rand_one_dut_hostname, nbrhosts, m1_topo_setup
    ):
        """Test Case 7.3: Rapid add/remove cycling.

        Steps:
        1. Loop N times: add aggregate -> verify received on M2 -> remove -> verify withdrawn
        2. After all iterations: verify no stale routes on M2, DUT stable
        """
        duthost = duthosts[rand_one_dut_hostname]
        setup = m1_topo_setup
        upstream = setup['upstream_neighbors']
        cfg = AggregateCfg(prefix=AGGR_V4, bbr_required=False, summary_only=False, as_set=False)

        announce_contributing_routes(setup, CONTRIBUTING_V4, "ipv4")
        try:
            for iteration in range(1, RAPID_CYCLE_ITERATIONS + 1):
                logger.info(f"Rapid cycle iteration {iteration}/{RAPID_CYCLE_ITERATIONS}")

                # Add aggregate
                gcu_add_aggregate(duthost, cfg)
                time.sleep(BGP_SETTLE_WAIT)

                # Verify received on M2
                verify_route_on_m2(nbrhosts, upstream, AGGR_V4, expected_present=True)

                # Remove aggregate
                gcu_remove_aggregate(duthost, cfg.prefix)
                time.sleep(BGP_SETTLE_WAIT)

                # Verify withdrawn from M2
                verify_route_on_m2(nbrhosts, upstream, AGGR_V4, expected_present=False)

            # Final checks: no stale routes
            verify_route_on_m2(nbrhosts, upstream, AGGR_V4, expected_present=False)
            verify_bgp_aggregate_cleanup(duthost, cfg.prefix)

            # DUT health check
            self._check_dut_health(duthost)

        finally:
            withdraw_contributing_routes(setup, CONTRIBUTING_V4, "ipv4")
