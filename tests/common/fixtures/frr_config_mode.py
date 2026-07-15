"""Shared fixture for exercising tests in both FRR config-programming modes.

SONiC can program FRR either through the traditional per-feature config daemons
that render FRR config from CONFIG_DB (bgpcfgd for BGP) or through the newer
"frr_mgmt_framework" / frrcfgd (native FRR mgmt framework driven directly from
CONFIG_DB, in FRR "unified" routing-config mode). Which one is active is a per-DUT
property; it governs the whole FRR stack (bgpd/ospfd/staticd/zebra), so this lives
in tests/common rather than under tests/bgp -- OSPF and other FRR-backed protocols
will reuse it.

The bgpcfgd<->frrcfgd switch is performed entirely from sonic-mgmt by
:class:`FrrConfigModeMigrator`, which translates the running BGP config into the
frrcfgd CONFIG_DB schema (see ``tests/common/helpers/frr``), persists the routing
mode so it survives ``config reload``, and reloads. No on-DUT migration tool is
required.

Fail-loud guarantee: the set of BGP config objects FRR reports (neighbors,
prefix-lists, route-maps, community-lists) is captured before the switch and
re-checked after it. If the translation drops anything, the test fails and names
the missing object, so reduced coverage in frr mode surfaces loudly instead of
silently.
"""
import json
import logging

import pytest

from tests.common.helpers.assertions import pytest_assert as pt_assert
from tests.common.helpers.frr.frr_config_mode_migrator import (
    FrrConfigModeMigrator,
    GOLDEN_CFG_FILE,
    MODE_FRR_MGMT_FRAMEWORK,
    MODE_TRADITIONAL,
)
from tests.common.helpers.frr.bgp_config_translation import FrrTranslationError
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

FRR_CONFIG_MODES = [MODE_TRADITIONAL, MODE_FRR_MGMT_FRAMEWORK]


def skip_if_frr_mgmt_framework(mode, reason):
    """Skip the frr_mgmt_framework variant of a test that exercises a feature frrcfgd
    does not (yet) implement (e.g. BGP_BBR).

    The traditional (bgpcfgd) variant still runs, so coverage is preserved; the frr
    variant is skipped with a reason (track the gap in Jira so frrcfgd can be
    extended). Call this from a test or its setup fixture, passing the yielded
    ``frr_config_mode`` value.
    """
    if mode == MODE_FRR_MGMT_FRAMEWORK:
        pytest.skip("frr_mgmt_framework mode not supported for this test: {}".format(reason))


def _bgp_established_neighbors(duthost):
    """Return the set of BGP neighbor IPs currently in the Established state."""
    out = duthost.shell('sudo vtysh -c "show bgp summary json"',
                        module_ignore_errors=True)["stdout"]
    established = set()
    try:
        data = json.loads(out)
    except ValueError:
        return established
    for af in data.values():
        if isinstance(af, dict):
            for ip, peer in af.get("peers", {}).items():
                if str(peer.get("state")) == "Established":
                    established.add(ip)
    return established


def _frr_config_fingerprint(duthost):
    """Capture the set of named BGP config objects FRR currently has, from its own
    ``show running-config``.

    These primitives (``neighbor <ip> remote-as``, ``ip[v6] prefix-list <name>``,
    ``route-map <name>``, ``bgp community-list <name>``) render identically whether
    bgpcfgd or frrcfgd generated them, so comparing the set before vs after a mode
    switch detects config the translation silently failed to carry over."""
    out = duthost.shell('sudo vtysh -c "show running-config"',
                        module_ignore_errors=True)["stdout"]
    fp = {"neighbors": set(), "prefix_lists": set(),
          "route_maps": set(), "community_lists": set()}
    for raw in out.splitlines():
        parts = raw.split()
        if len(parts) >= 3 and parts[0] == "neighbor" and parts[2] == "remote-as":
            fp["neighbors"].add(parts[1])
        elif len(parts) >= 3 and parts[0] in ("ip", "ipv6") and parts[1] == "prefix-list":
            fp["prefix_lists"].add(parts[2])
        elif len(parts) >= 2 and parts[0] == "route-map":
            fp["route_maps"].add(parts[1])
        else:
            for i, p in enumerate(parts):
                if p.endswith("community-list") and i + 1 < len(parts):
                    nxt = parts[i + 1]
                    name = (parts[i + 2] if nxt in ("standard", "expanded") and i + 2 < len(parts)
                            else nxt)
                    fp["community_lists"].add(name)
                    break
    return fp


def _assert_config_preserved(duthost, mode, baseline_fp):
    """Fail loudly if any BGP object present before the switch is missing after it."""
    after = _frr_config_fingerprint(duthost)
    dropped = {cat: sorted(objs - after[cat]) for cat, objs in baseline_fp.items()}
    dropped = {cat: v for cat, v in dropped.items() if v}
    pt_assert(not dropped,
              "Switching to '{}' mode dropped BGP config objects that were present in the "
              "original mode: {}. The bgpcfgd->frrcfgd translation did not carry them over -- "
              "extend tests/common/helpers/frr/bgp_config_translation.py (and frrcfgd) to cover "
              "them.".format(mode, dropped))


def _current_mode(duthost):
    return (MODE_FRR_MGMT_FRAMEWORK if duthost.get_frr_mgmt_framework_config()
            else MODE_TRADITIONAL)


def _is_switchless_node(duthost):
    """True for DUTs with no switchable BGP stack -- e.g. supervisor / chassis-control
    cards, which run no bgp container. A mode switch there is meaningless and the
    migrator's ``vtysh`` call would fail ("container ... is not running")."""
    try:
        return bool(duthost.is_supervisor_node())
    except Exception:
        return False


@pytest.fixture(scope="module", params=FRR_CONFIG_MODES)
def frr_config_mode(request, duthosts, rand_one_dut_hostname):
    """Run a test in BOTH the traditional (bgpcfgd) and frr_mgmt_framework (frrcfgd)
    config modes in a single pytest run.

    Tests (or their module-scoped setup fixtures) opt in by requesting this fixture;
    doing so parametrizes them over the two modes and yields the active mode string.

    Opted-in modules MUST also carry ``pytest.mark.skip_check_dut_health``: the mode
    switch rewrites BGP config_db mid-module and reloads, which the config-diff /
    YANG DUT-health checks would otherwise flag. The switch restores the DUT's
    original config on exit, leaving the testbed clean for later modules.

    The ``disable_memory_utilization`` marker is applied automatically (by
    ``pytest_collection_modifyitems`` in tests/conftest.py, keyed on this fixture) for
    the same reason: the mode-switch reload makes BGP re-learn the full route table,
    and on route-heavy DUTs that reconvergence lands inside the memory monitor's
    before/after window -- a steady-state footprint change the percent-increase
    threshold would misread as a leak.

    Switching is expensive (a config reload), so the fixture is module-scoped --
    pytest groups same-mode instances, switching at most twice per module -- and it
    skips the switch when the DUT is already in the requested mode.

    Strictness: the BGP neighbors established, and the set of BGP config objects FRR
    reports, in the DUT's original mode are captured once; after every switch the
    fixture asserts those neighbors re-establish and no config object was dropped, so
    a translation that loses config fails loudly instead of running with reduced
    coverage.

    Skips (with a clear reason, rather than running something wrong):
      * multi-ASIC DUT (per-ASIC switching not supported yet);
      * the DUT's original mode is not traditional (we only translate traditional->frr);
      * no golden_config_db.json (needed to persist the mode across config reload).
    """
    mode = request.param
    duthost = duthosts[rand_one_dut_hostname]
    mod = request.module

    # Discover the DUT's original mode once per module.
    if not hasattr(mod, "_frr_original_config_mode"):
        mod._frr_original_config_mode = _current_mode(duthost)

    # Some DUTs cannot have their BGP config-mode switched:
    #   * multi-asic DUTs use per-namespace BGP config the translator does not handle yet;
    #   * supervisor/chassis-control nodes run no bgp container at all (a mode switch there
    #     dies in the migrator's ``vtysh`` call -- "container ... is not running").
    # Rather than skip the module outright (which would turn an otherwise-passing test into
    # a skip on its native topology, e.g. a t2 chassis), run only the DUT's native mode as a
    # no-op and skip the other mode variant.
    if duthost.facts["num_asic"] > 1 or _is_switchless_node(duthost):
        if mode == mod._frr_original_config_mode:
            yield mode
            return
        pytest.skip("FRR config-mode switching is not supported on this DUT (multi-asic or "
                    "supervisor/no-bgp node); only the DUT's native '{}' mode is "
                    "exercised".format(mod._frr_original_config_mode))

    # Single-asic: set up the migrator and capture baselines once per module.
    if not hasattr(mod, "_frr_migrator"):
        mod._frr_applied_config_mode = mod._frr_original_config_mode
        mod._frr_migrator = FrrConfigModeMigrator(duthost)
        mod._frr_baseline_neighbors = _bgp_established_neighbors(duthost)
        mod._frr_baseline_fingerprint = _frr_config_fingerprint(duthost)

    if mod._frr_original_config_mode != MODE_TRADITIONAL:
        pytest.skip("dual-mode FRR switching requires a DUT that starts in traditional "
                    "(bgpcfgd) mode; this DUT is in {}".format(mod._frr_original_config_mode))
    if not duthost.is_file_existed(GOLDEN_CFG_FILE):
        pytest.skip("{} not present on DUT; cannot persist unified routing mode across "
                    "config reload".format(GOLDEN_CFG_FILE))

    if mod._frr_applied_config_mode != mode:
        _switch_mode(duthost, mod, mode)

    yield mode

    # Restore the DUT's original mode when leaving a mode we switched into.
    if mod._frr_applied_config_mode != mod._frr_original_config_mode:
        _switch_mode(duthost, mod, mod._frr_original_config_mode)
    mod._frr_migrator.cleanup()


def _switch_mode(duthost, mod, mode):
    """Switch the DUT to ``mode``, wait for BGP to recover, and assert strictness."""
    migrator = mod._frr_migrator
    logger.info("Switching FRR config mode to '%s' on %s", mode, duthost.hostname)
    try:
        if mode == MODE_FRR_MGMT_FRAMEWORK:
            migrator.to_frr_mgmt_framework()
        else:
            migrator.to_traditional()
    except FrrTranslationError as e:
        pytest.fail("Failed to switch to '{}' mode: {}".format(mode, e))
    mod._frr_applied_config_mode = mode

    pt_assert(wait_until(180, 10, 0, duthost.is_service_fully_started_per_asic_or_host, "bgp"),
              "bgp service did not come up after switching to '{}' mode".format(mode))
    baseline = mod._frr_baseline_neighbors
    pt_assert(
        wait_until(180, 10, 0, lambda: baseline <= _bgp_established_neighbors(duthost)),
        "Switching to '{}' mode did not preserve BGP: neighbors {} were not all "
        "re-established (established now: {}).".format(
            mode, sorted(baseline), sorted(_bgp_established_neighbors(duthost))))
    _assert_config_preserved(duthost, mode, mod._frr_baseline_fingerprint)
