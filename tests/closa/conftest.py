"""Local conftest for tests/closa/.

Re-exports the 5 t1-tagging fixtures from
``tests.closa.bgp_t1_tagging_helpers_msft_internal`` so the tests in this
directory can request them by parameter name without explicit per-file
imports (mirrors the pattern previously used in tests/bgp/conftest.py).

Also provides an autouse multi-ASIC skip: every test under tests/closa/
exercises FRR templates that are only rendered on single-ASIC frontends
(msft.general / msft.mgmt / SUPPRESS_PREFIX), so on multi-ASIC platforms
they have no useful coverage and would either fail or report nonsense.
"""

import pytest

from tests.closa.bgp_t1_tagging_helpers_msft_internal import (  # noqa: F401
    aggr_cleanup,
    bgp_neighbors_not_established,
    dut_t0_peer_ips,
    dut_t2_peer_ips,
    require_t1_tagging_image,
    t0_announce_cleanup,
    t1_tagging_clean_config,
    t1_neighbors,
)


T1_TAGGING_TEST_MODULES = (
    "test_bgp_aggregate_address_t1_tagging_lifecycle_msft_internal.py",
    "test_bgp_aggregate_address_t1_tagging_t0_downstream_msft_internal.py",
    "test_bgp_aggregate_address_t1_tagging_t2_upstream_msft_internal.py",
)

LIFECYCLE_DISRUPTION_TESTS = (
    "test_lifecycle_bgp_restart_preserves_tagging",
    "test_lifecycle_config_reload_preserves_tagging",
    "test_aggregate_tag_survives_bgp_restart",
    "test_aggregate_tag_survives_config_reload",
    "test_suppress_prefix_persistence",
)

LIFECYCLE_DISRUPTION_IGNORE_LOGS = [
    # These BGP lifecycle tests do not validate SAI behavior. Match the same
    # vendor SAI query noise ignored by container autorestart tests.
    r".*ERR syncd[0-9]*#syncd.*SAI_API_UNSPECIFIED:sai_api_query.*",
    # Reloading iptables/TACACS can report different transport errors across
    # images (unreachable, disconnected, refused, or timeout). TACACS behavior
    # is outside the scope of these BGP lifecycle tests.
    r".* ERR (?:iptables|journalctl): tac_connect_single: .*",
    r".* ERR (?:iptables|journalctl): tac_author_read: reply timeout after \d+ secs.*",
    r".* ERR (?:iptables|journalctl): nss_tacplus: failed to connect TACACS\+ server .*",
    r".* ERR (?:ntpd|chronyd)\[\d+\]: nss_tacplus: .*",
    r".* ERR audisp-tacplus: tac_connect_single: connection failed with.*"
    r"(?:Interrupted system call|Transport endpoint is not connected).*",
    # Mellanox SDK releases use either device=<id> or dev_id [<id>].
    r".* ERR kernel:.*sxd_kernel: \[error\].*Health-Check: (?:device=\d+|dev_id \[\d+\]), "
    r"cause=12 \['SDK watchdog'\] - stopping further device monitoring!.*",
    r".* ERR monit.* 'chrony' process is not running.*",
    r".* ERR memory_checker: \[memory_checker\] Failed to get container ID of.*",
    r".* ERR memory_checker: \[memory_checker\] cgroup memory usage file.*",
    r".* ERR sonic-kdump-config: Failed to open kernel booter configuration file: "
    r"'/host/grub/grub\.cfg', Error is: '\[Errno 21\] Is a directory: "
    r"'/host/grub/grub\.cfg''!.*",
]


@pytest.fixture(autouse=True)
def _closa_skip_if_multi_asic(duthosts, rand_one_dut_hostname):
    """Skip every closa test on multi-ASIC testbeds.

    Equivalent to the previous conditional_mark YAML rule:
        is_multi_asic == True  ->  skip
    """
    duthost = duthosts[rand_one_dut_hostname]
    try:
        is_multi_asic = duthost.facts.get("num_asic", 1) > 1
    except Exception:
        is_multi_asic = getattr(duthost, "is_multi_asic", False)
    if is_multi_asic:
        pytest.skip("Skip for multi-ASIC testbed")


@pytest.fixture(autouse=True)
def _closa_ignore_lifecycle_disruption_logs(request, duthosts, rand_one_dut_hostname):
    """Ignore transient service errors caused by lifecycle disruptions."""
    test_name = getattr(request.node, "originalname", request.node.name)
    if test_name not in LIFECYCLE_DISRUPTION_TESTS:
        return

    loganalyzer = request.getfixturevalue("loganalyzer")
    duthost = duthosts[rand_one_dut_hostname]
    if loganalyzer and duthost.hostname in loganalyzer:
        loganalyzer[duthost.hostname].ignore_regex.extend(LIFECYCLE_DISRUPTION_IGNORE_LOGS)


@pytest.fixture(autouse=True)
def _closa_skip_if_bgp_not_established(request, duthosts, rand_one_dut_hostname,
                                       _closa_skip_if_multi_asic):
    """Skip T1-tagging tests when T0/T2 BGP sessions are not Established.

    The T1-tagging cases validate route policy and community behavior over an
    already-converged T1 testbed. Other closa modules target different
    topologies (m1 or t0) and have their own narrower preconditions.
    """
    node_path = str(getattr(request.node, "path", getattr(request.node, "fspath", "")))
    if not any(module_name in node_path for module_name in T1_TAGGING_TEST_MODULES):
        return

    duthost = duthosts[rand_one_dut_hostname]
    peer_ips = []
    for family in ("ipv4", "ipv6"):
        peer_ips.extend(dut_t0_peer_ips(duthost, family=family))
        peer_ips.extend(dut_t2_peer_ips(duthost, family=family))

    if not peer_ips:
        pytest.skip("Skip closa tests because no T0/T2 BGP peers were found on DUT")

    try:
        pending = bgp_neighbors_not_established(duthost, sorted(set(peer_ips)))
    except RuntimeError as exc:
        pytest.skip(
            "Skip closa tests because BGP summary could not be collected: {}"
            .format(exc)
        )
    if pending:
        pytest.skip(
            "Skip closa tests because DUT BGP sessions are not Established: {}"
            .format(", ".join(pending))
        )
