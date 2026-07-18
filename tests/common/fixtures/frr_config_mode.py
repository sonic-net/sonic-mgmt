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
import os

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

# bgpcfgd renders these base BGP-sentinel policy objects from its Jinja templates
# (dockers/docker-fpm-frr/frr/bgpd/templates/sentinels/policies.conf.j2) on every DUT
# whose image ships that template -- FROM_BGP_SENTINEL/TO_BGP_SENTINEL unconditionally,
# and sentinel_community when the constants.bgp.sentinel_community global is set --
# regardless of whether any BGP_SENTINELS are configured. frrcfgd does not implement the
# BGP-sentinel feature at all (it drives FRR from its native schema, not those templates),
# so after switching to frr mode these objects legitimately disappear. That is a true
# frrcfgd capability gap, not a translation miss: the only test that uses sentinels
# (test_bgp_sentinel) already self-skips in frr via is_bgp_sentinel_supported(). Exempt
# them from the fail-loud fingerprint so it does not false-fail on this inert scaffolding.
FRRCFGD_UNSUPPORTED_OBJECTS = {
    "route_maps": {"FROM_BGP_SENTINEL", "TO_BGP_SENTINEL"},
    "community_lists": {"sentinel_community"},
}


def skip_if_frr_mgmt_framework(mode, reason):
    """Skip the frr_mgmt_framework variant of a test that cannot run under frrcfgd -- e.g.
    GCU add-cluster, whose patch paths assume the flat (non-VRF-keyed) BGP_NEIGHBOR schema.

    The traditional (bgpcfgd) variant still runs, so coverage is preserved. For genuine
    frrcfgd capability gaps prefer gating the skip via the ``conditional_mark`` plugin on a
    tracking issue (so it auto-lifts when the issue closes); use this helper for the simpler
    in-test case. Call it from a test or its setup fixture, passing the yielded
    ``frr_config_mode`` value.
    """
    if mode == MODE_FRR_MGMT_FRAMEWORK:
        pytest.skip("frr_mgmt_framework mode not supported for this test: {}".format(reason))


FRR_BGP_DEVICE_GLOBAL_GAP_REASON = "frrcfgd does not consume BGP_DEVICE_GLOBAL (TSA/IDF/W-ECMP)"


def skip_module_if_frr_native(duthost):
    """Skip a BGP_DEVICE_GLOBAL module (TSA/TSB, IDF isolation, W-ECMP) when the DUT
    natively runs frrcfgd. Those features are driven by the BGP_DEVICE_GLOBAL table, which
    frrcfgd does not consume by design, so the modules are not parametrized over
    frr_config_mode -- they just skip outright in native frr mode. Shared by the five such
    modules (test_traffic_shift{,_lc,_sup}, test_seq_idf_isolation, test_startup_tsa_tsb_service)
    to avoid copy-pasting the skip fixture."""
    if duthost.get_frr_mgmt_framework_config():
        pytest.skip(FRR_BGP_DEVICE_GLOBAL_GAP_REASON)


def _core_dumps(duthost):
    cmd = ("ls /var/core/ | grep -v python || true" if "20191130" in duthost.os_version
           else "ls /var/core/ || true")
    return set(duthost.shell(cmd, module_ignore_errors=True)["stdout"].split())


@pytest.fixture(scope="module", autouse=True)
def _frr_mode_core_dump_check(request, duthosts):
    """Focused core-dump (crash) detection for frr_config_mode dual-mode modules.

    Opted-in modules carry ``skip_check_dut_health`` because the mid-module mode-switch
    ``config reload`` legitimately perturbs the generic config-diff / YANG / memory checks
    (and its recovery reload races swss). That marker also disables the generic core-dump
    detection in ``core_dump_and_config_check`` -- but a process crash during a dual-mode
    BGP test must still be caught. So run a focused core-dump-only check here (no config-diff,
    no recovery reload) for modules the collection hook marked ``frr_dual_mode``. A no-op for
    every other module, so it does not touch the rest of the suite.
    """
    if request.node.get_closest_marker("frr_dual_mode") is None:
        yield
        return

    pre = {dut.hostname: _core_dumps(dut) for dut in duthosts}

    yield

    logs_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "logs")
    new_by_host = {}
    for dut in duthosts:
        new = sorted(_core_dumps(dut) - pre.get(dut.hostname, set()))
        if new:
            new_by_host[dut.hostname] = new
            for core in new:
                try:
                    dut.fetch(src="/var/core/{}".format(core), dest=logs_dir)
                except Exception as e:
                    logger.warning("Could not fetch core dump %s from %s: %s", core, dut.hostname, e)
    pt_assert(not new_by_host,
              "New core dump(s) appeared during this frr dual-mode module -- a process crashed: "
              "{}".format(new_by_host))


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
    dropped = {}
    for cat, objs in baseline_fp.items():
        missing = objs - after[cat]
        # A missing object that frrcfgd is known not to support is an expected capability
        # gap, not a translation miss -- record it visibly but do not fail on it.
        exempt = missing & FRRCFGD_UNSUPPORTED_OBJECTS.get(cat, set())
        if exempt:
            logger.info("Switching to '%s' mode dropped frrcfgd-unsupported %s %s "
                        "(bgpcfgd base-template artifacts with no frrcfgd equivalent); "
                        "ignoring -- not a translation miss.", mode, cat, sorted(exempt))
        real = sorted(missing - exempt)
        if real:
            dropped[cat] = real
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


def pytest_addoption(parser):
    parser.addoption(
        "--frr-config-mode", action="store", default="both",
        choices=["both"] + FRR_CONFIG_MODES,
        help="FRR config mode(s) to run frr_config_mode-parametrized tests in. 'both' "
             "(default) runs each opted-in test in traditional (bgpcfgd) AND "
             "frr_mgmt_framework (frrcfgd). 'traditional' or 'frr_mgmt_framework' runs only "
             "that mode -- e.g. --frr-config-mode=frr_mgmt_framework exercises frrcfgd only and "
             "bypasses the bgpcfgd variant (the DUT is switched into frr_mgmt_framework mode "
             "for the run, or run as-is if it already boots in that mode).")


def pytest_generate_tests(metafunc):
    # Parametrize frr_config_mode over the selected mode(s). Done here (rather than via
    # params= on the fixture) so --frr-config-mode can narrow it to a single mode, while
    # keeping the "[traditional]" / "[frr_mgmt_framework]" param IDs that conditional_mark
    # and -k rely on.
    if "frr_config_mode" in metafunc.fixturenames:
        selected = metafunc.config.getoption("--frr-config-mode")
        modes = FRR_CONFIG_MODES if selected == "both" else [selected]
        metafunc.parametrize("frr_config_mode", modes, indirect=True, scope="module")


@pytest.fixture(scope="module")
def frr_config_mode(request, duthosts, rand_one_dut_hostname):
    """Run a test in BOTH the traditional (bgpcfgd) and frr_mgmt_framework (frrcfgd)
    config modes in a single pytest run.

    Tests (or their module-scoped setup fixtures) opt in by requesting this fixture;
    doing so parametrizes them over the two modes and yields the active mode string.

    Use ``--frr-config-mode={both,traditional,frr_mgmt_framework}`` (default ``both``) to
    narrow the run to a single mode -- e.g. ``--frr-config-mode=frr_mgmt_framework`` exercises
    only frrcfgd and bypasses the bgpcfgd variant.

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
      * a mode that differs from the DUT's boot mode when that boot mode is not traditional
        (we only translate traditional -> frr; a same-mode native run is allowed);
      * no golden_config_db.json when a switch is required (needed to persist the mode
        across config reload).
    """
    mode = request.param
    duthost = duthosts[rand_one_dut_hostname]
    mod = request.module

    # Discover the DUT's original mode once per module.
    if not hasattr(mod, "_frr_original_config_mode"):
        mod._frr_original_config_mode = _current_mode(duthost)

    # macsec: the mode-switch config reload disrupts macsec-protected PortChannel/BGP
    # sessions, which re-negotiate slowly and flakily after a reload (so the switch-back's
    # BGP-preservation check fails even though the test bodies pass). Mode switching is
    # orthogonal to the BGP config schema, and the generic DUT-health checks already disable
    # themselves under --enable_macsec, so run only the DUT's native mode here too.
    if getattr(request.config.option, "enable_macsec", False):
        if mode == mod._frr_original_config_mode:
            yield mode
            return
        pytest.skip("FRR config-mode switching is skipped with --enable_macsec (the reload "
                    "disrupts macsec sessions); only the DUT's native '{}' mode is exercised"
                    .format(mod._frr_original_config_mode))

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

    # The translator only converts traditional -> frr (the reverse is a config_db
    # backup-restore, not a translation), so a mode other than the DUT's
    # original one is only reachable from a traditional start. A run that stays in the DUT's
    # original mode (e.g. --frr-config-mode=frr_mgmt_framework on a DUT that already boots in
    # frr_mgmt_framework) needs no switch and no translation, so allow it.
    if mode != mod._frr_original_config_mode and mod._frr_original_config_mode != MODE_TRADITIONAL:
        pytest.skip("frr_config_mode can only switch modes from a traditional (bgpcfgd) start; "
                    "this DUT boots in {}, so only that mode can be exercised".format(
                        mod._frr_original_config_mode))

    if mod._frr_applied_config_mode != mode:
        # A mode switch persists the new mode in golden config so it survives the reload; a
        # no-switch native run (mode == the DUT's boot mode) does not need it.
        if not duthost.is_file_existed(GOLDEN_CFG_FILE):
            pytest.skip("{} not present on DUT; cannot persist routing mode across config "
                        "reload".format(GOLDEN_CFG_FILE))
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
    # Capture the last-polled established set so the failure message reuses it instead of
    # firing another vtysh query -- the message string is built eagerly on every (including
    # successful) switch, so calling _bgp_established_neighbors() in .format() would run an
    # extra query per switch.
    last_established = {}

    def _neighbors_recovered():
        last_established["set"] = _bgp_established_neighbors(duthost)
        return baseline <= last_established["set"]

    pt_assert(
        wait_until(180, 10, 0, _neighbors_recovered),
        "Switching to '{}' mode did not preserve BGP: neighbors {} were not all "
        "re-established (established now: {}).".format(
            mode, sorted(baseline), sorted(last_established.get("set", set()))))
    _assert_config_preserved(duthost, mode, mod._frr_baseline_fingerprint)
