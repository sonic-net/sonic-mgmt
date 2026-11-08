"""Fixture for running tests in both FRR config modes: traditional (bgpcfgd) and
frr_mgmt_framework (frrcfgd).

:class:`FrrConfigModeMigrator` switches the DUT from sonic-mgmt. BGP config FRR reports is
captured before the switch and re-checked after it; anything dropped that is not a known
frrcfgd gap fails the test.
"""
import json
import logging
import os
import re

import pytest

from tests.common.helpers.assertions import pytest_assert as pt_assert
from tests.common.helpers.frr.frr_config_mode_migrator import (
    FrrConfigModeMigrator,
    GOLDEN_CFG_FILE,
    MODE_FRR_MGMT_FRAMEWORK,
    MODE_TRADITIONAL,
)
from tests.common.helpers.frr.bgp_config_translation import (
    FrrTranslationError,
    _ROUTE_MAP_UNSUPPORTED_CLAUSES,
)
from tests.common.helpers.frr.frr_parity_compat import (      # noqa: DELETE-WITH-FRR-PARITY
    gated_globals_missing_from_image,
    gated_route_map_clauses_missing_from_image,
)
from tests.common.platform.interface_utils import get_oper_up_ports
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

FRR_CONFIG_MODES = [MODE_TRADITIONAL, MODE_FRR_MGMT_FRAMEWORK]

FRR_GENERIC_MARKER = "frr_generic"
# Mode ``frr_generic`` modules run in (overridable by --frr-generic-mode); falls back if unreachable.
FRR_GENERIC_DEFAULT_MODE = MODE_TRADITIONAL

# Modules asserting bgpcfgd-only behaviour; their frr variant is permanently skipped by design.
FRR_BGPCFGD_ONLY_MARKER = "frr_bgpcfgd_only"

# BGP-sentinel objects bgpcfgd's templates always render; frrcfgd has no sentinel support.
FRRCFGD_UNSUPPORTED_OBJECTS = {
    "route_maps": {"FROM_BGP_SENTINEL", "TO_BGP_SENTINEL"},
    "community_lists": {"sentinel_community"},
}

# Prefixes of device-wide FRR settings (not named objects) the fingerprint also compares.
_GLOBAL_SETTING_PREFIXES = (
    "zebra ", "no zebra ",          # zebra nexthop-group keep / nexthop kernel enable
    "fpm ", "no fpm ",              # fpm address / use-next-hop-groups
    "bgp ", "no bgp ",              # router-bgp globals: graceful-restart, bestpath, listen range
    "maximum-paths ", "table-map ",  # per-address-family globals
)

# Named objects already tracked in their own categories.
_GLOBAL_SETTING_EXCLUDES = (
    "bgp community-list", "bgp extcommunity-list", "bgp large-community-list",
    "bgp as-path access-list",
)

# Globals frrcfgd cannot express yet (sonic-buildimage#28482); recorded as gaps, not failures.
FRRCFGD_UNSUPPORTED_GLOBAL_PREFIXES = (
    "bgp graceful-restart select-defer-time ",
    "bgp graceful-restart-disable",
    "bgp long-lived-graceful-restart ",
)


def _is_global_setting(line):
    """True for a running-config line that is a device-wide FRR setting we should compare."""
    if any(line.startswith(p) for p in _GLOBAL_SETTING_EXCLUDES):
        return False
    return any(line.startswith(p) for p in _GLOBAL_SETTING_PREFIXES)


# How long the config daemon gets to finish rendering after a switch.
_CONFIG_SETTLE_TIMEOUT = 120
_CONFIG_SETTLE_INTERVAL = 10


def skip_if_frr_mgmt_framework(mode, reason):
    """Skip the frr_mgmt_framework variant of a test that cannot run under frrcfgd."""
    if mode == MODE_FRR_MGMT_FRAMEWORK:
        pytest.skip("frr_mgmt_framework mode not supported for this test: {}".format(reason))


FRR_BGP_DEVICE_GLOBAL_GAP_REASON = "frrcfgd does not consume BGP_DEVICE_GLOBAL (TSA/IDF/W-ECMP)"


def switched_dut_hostname(request):
    """The hostname ``frr_config_mode`` actually switched, or None if no switch happened."""
    state = getattr(request.session, _SESSION_STATE_ATTR, None)
    if state is None or state.applied_mode == state.original_mode:
        return None
    return state.duthost.hostname


def frr_mode_switch_count(request):
    """How many FRR config-mode switches this session has performed so far (0 if none)."""
    state = getattr(request.session, _SESSION_STATE_ATTR, None)
    return state.switch_count if state is not None else 0


def frr_mode_perturbed(request, since_switch_count=None):
    """True when generic DUT-health config checks can't be trusted: the DUT is away from its
    boot mode, or (given the setup-time ``since_switch_count``) a switch ran during the module.
    """
    state = getattr(request.session, _SESSION_STATE_ATTR, None)
    if state is None:
        return False
    if state.applied_mode != state.original_mode:
        return True
    return since_switch_count is not None and state.switch_count != since_switch_count


def skip_if_dut_not_switched(request, duthost):
    """Skip when ``duthost`` is not the DUT ``frr_config_mode`` switched (no-op if no switch).

    For modules that pick their own DUTs; call from setup with the DUT the module operates on.
    """
    switched = switched_dut_hostname(request)
    if switched is None or duthost.hostname == switched:
        return
    pytest.skip(
        "frr_config_mode switched '{}', but this test operates on '{}'. Running here would "
        "report frr_mgmt_framework coverage for a DUT still in its original mode, so skip "
        "instead. Switching every DUT under test would need per-DUT migrators and baselines."
        .format(switched, duthost.hostname))

# bgpmon is superseded by BMP and out of scope for frrcfgd (sonic-buildimage#28482); by-design skip.


FRR_LEGACY_BGP_MONITORS_REASON = (
    "BGP monitors (BGP_MONITORS) is a legacy feature superseded by BMP and is intentionally "
    "unsupported in frr_mgmt_framework mode; use BMP (see tests/bmp) instead")

# BGP sentinels are a bgpcfgd macro, out of scope for frrcfgd (sonic-buildimage#28482); by-design skip.
FRR_BGPCFGD_ONLY_SENTINEL_REASON = (
    "BGP sentinels (BGP_SENTINELS) is a bgpcfgd-only macro, intentionally unsupported in "
    "frr_mgmt_framework mode (the equivalent is expressible via generic peer-group/route-map "
    "tables)")

# The aggregate-address suite asserts bgpcfgd AggregateAddressMgr behaviour frrcfgd lacks.
FRR_BGPCFGD_ONLY_AGGREGATE_REASON = (
    "the BGP aggregate-address suite asserts bgpcfgd AggregateAddressMgr behavior "
    "(BGP_AGGREGATE_ADDRESS CONFIG_DB/STATE_DB rows and bbr-required gating), which frrcfgd "
    "does not implement")


def _core_dumps(duthost):
    cmd = ("ls /var/core/ | grep -v python || true" if "20191130" in duthost.os_version
           else "ls /var/core/ || true")
    return set(duthost.shell(cmd, module_ignore_errors=True)["stdout"].split())


def expected_core_dump_patterns(node):
    """Regexes for core dumps a module expects, from its ``expected_core_dumps`` markers."""
    patterns = []
    for marker in node.iter_markers("expected_core_dumps"):
        patterns.extend(marker.args)
    return patterns


def _is_expected_core(core, patterns):
    return any(re.match(p, core) for p in patterns)


@pytest.fixture(scope="module", autouse=True)
def _frr_mode_core_dump_check(request, duthosts):
    """Core-dump check for ``frr_dual_mode`` modules that set ``skip_check_dut_health``.

    A no-op elsewhere, since the generic check already covers crashes there.
    """
    if (request.node.get_closest_marker("frr_dual_mode") is None
            or request.node.get_closest_marker("skip_check_dut_health") is None):
        yield
        return

    expected = expected_core_dump_patterns(request.node)
    pre = {dut.hostname: _core_dumps(dut) for dut in duthosts}

    yield

    logs_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "logs")
    new_by_host = {}
    for dut in duthosts:
        new = sorted(c for c in _core_dumps(dut) - pre.get(dut.hostname, set())
                     if not _is_expected_core(c, expected))
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


@pytest.fixture(scope="module", autouse=True)
def _frr_mode_restore_for_other_modules(request):
    """Put the DUT back in its boot mode before a module that does not use frr_config_mode."""
    state = getattr(request.session, _SESSION_STATE_ATTR, None)
    if (state is not None and state.applied_mode != state.original_mode
            and request.node.get_closest_marker("frr_dual_mode") is None):
        logger.info("Restoring FRR config mode to '%s' before %s", state.original_mode,
                    request.node.name)
        _switch_mode(state, state.original_mode)


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


# Content categories whose lost lines fail the switch (neighbor lines are only reported).
_FATAL_CONTENT = ("route_maps", "prefix_lists", "community_lists")
_SEQ_RE = re.compile(r" seq \d+")
# Known frrcfgd gaps accepted during this session, printed in the terminal summary.
_CONFIG_GAPS = set()


def _frr_config_fingerprint(duthost):
    """Capture the BGP config objects FRR currently has, from its own ``show running-config``."""
    out = duthost.shell('sudo vtysh -c "show running-config"',
                        module_ignore_errors=True)["stdout"]
    return _parse_fingerprint(out)


def _parse_fingerprint(out):
    """Parse running-config into named BGP objects, globals, and per-object ``content``."""
    fp = {"neighbors": set(), "prefix_lists": set(),
          "route_maps": set(), "community_lists": set(), "globals": set(), "content": {}}

    def add(cat, name, line):
        fp["content"].setdefault((cat, name), set()).add(line)

    route_map, af, neighbor_lines = None, "", []
    for raw in out.splitlines():
        stripped = raw.strip()
        if route_map and raw[:1].isspace() and stripped:
            add("route_maps", route_map[0], "{} | {}".format(route_map[1], stripped))
            continue
        route_map = None
        if _is_global_setting(stripped):
            fp["globals"].add(stripped)
        parts = raw.split()
        if not parts:
            continue
        if parts[0] == "address-family":
            af = " ".join(parts[1:])
        elif parts[0] in ("exit-address-family", "router"):
            af = ""
        if len(parts) >= 3 and parts[0] == "neighbor":
            neighbor_lines.append((parts[1], "{} | {}".format(af, " ".join(parts[2:]))))
            if parts[2] == "remote-as":
                fp["neighbors"].add(parts[1])
        elif len(parts) >= 3 and parts[0] in ("ip", "ipv6") and parts[1] == "prefix-list":
            fp["prefix_lists"].add(parts[2])
            add("prefix_lists", parts[2], _SEQ_RE.sub("", " ".join([parts[0]] + parts[3:])))
        elif len(parts) >= 2 and parts[0] == "route-map":
            fp["route_maps"].add(parts[1])
            route_map = (parts[1], " ".join(parts[2:]))
            add("route_maps", parts[1], route_map[1])
        else:
            for i, p in enumerate(parts):
                if p.endswith("community-list") and i + 1 < len(parts):
                    nxt = parts[i + 1]
                    name = (parts[i + 2] if nxt in ("standard", "expanded") and i + 2 < len(parts)
                            else nxt)
                    fp["community_lists"].add(name)
                    add("community_lists", name, _SEQ_RE.sub("", stripped))
                    break
    for ip, line in neighbor_lines:
        if ip in fp["neighbors"]:
            add("neighbors", ip, line)
    return fp


def _is_known_clause_gap(line, image_gated_clauses):
    clause = line.split(" | ", 1)[-1]
    return any(clause.startswith(prefix) for prefix, _ in _ROUTE_MAP_UNSUPPORTED_CLAUSES) or \
        any(clause.startswith(prefix) for prefix in image_gated_clauses)  # noqa: DELETE-WITH-FRR-PARITY


def _dropped_config_objects(duthost, mode, baseline_fp, image_gated_globals=frozenset(),
                            image_gated_clauses=()):
    """Return ``(dropped, gaps)``: baseline config FRR no longer renders, and accepted gaps."""
    after = _frr_config_fingerprint(duthost)
    dropped, gaps = {}, set()
    for cat, objs in baseline_fp.items():
        if cat == "content":
            continue
        missing = objs - after[cat]
        if cat == "globals":
            exempt = {o for o in missing
                      if any(o.startswith(p) for p in FRRCFGD_UNSUPPORTED_GLOBAL_PREFIXES)}
            exempt |= (missing & image_gated_globals)     # noqa: DELETE-WITH-FRR-PARITY
        else:
            exempt = missing & FRRCFGD_UNSUPPORTED_OBJECTS.get(cat, set())
        gaps.update("{} {}".format(cat, o) for o in exempt)
        real = sorted(missing - exempt)
        if real:
            dropped[cat] = real
    for (cat, name), lines in baseline_fp.get("content", {}).items():
        if (cat, name) not in after["content"]:
            continue
        lost = lines - after["content"][(cat, name)]
        exempt = {ln for ln in lost
                  if cat == "route_maps" and _is_known_clause_gap(ln, image_gated_clauses)}
        if cat not in _FATAL_CONTENT:
            exempt = lost
        gaps.update("{} {}: {}".format(cat, name, ln) for ln in exempt)
        real = sorted("{}: {}".format(name, ln) for ln in lost - exempt)
        if real:
            dropped.setdefault(cat + " content", []).extend(real)
    return dropped, gaps


def _assert_config_preserved(duthost, mode, baseline_fp):
    """Fail if baseline BGP config is still missing once the DUT has settled.

    Polls, since the config daemons render asynchronously after BGP re-establishes.
    """
    dropped, gaps = {}, set()
    # Lines this image's YANG cannot carry yet (sonic-buildimage#27192 / #28543); empty once it can.
    image_gated = gated_globals_missing_from_image(duthost)   # noqa: DELETE-WITH-FRR-PARITY
    image_gated_clauses = gated_route_map_clauses_missing_from_image(duthost)  # noqa: DELETE-WITH-FRR-PARITY
    if image_gated:
        logger.info("Image predates sonic-buildimage#28543; these globals cannot survive the "
                    "switch and are not counted as dropped: %s", sorted(image_gated))

    def _settled():
        result = _dropped_config_objects(duthost, mode, baseline_fp, image_gated,
                                         image_gated_clauses)
        dropped.clear()
        dropped.update(result[0])
        gaps.clear()
        gaps.update(result[1])
        return not dropped

    wait_until(_CONFIG_SETTLE_TIMEOUT, _CONFIG_SETTLE_INTERVAL, 0, _settled)
    if gaps:
        logger.warning("Switching to '%s' mode lost known frrcfgd gaps: %s", mode, sorted(gaps))
        _CONFIG_GAPS.update("{}: {}".format(mode, gap) for gap in gaps)
    pt_assert(not dropped,
              "Switching to '{}' mode dropped BGP config that was present in the "
              "original mode: {} (still missing after {}s). Either the bgpcfgd->frrcfgd "
              "translation did not carry it over -- extend "
              "tests/common/helpers/frr/bgp_config_translation.py (and frrcfgd) to cover it, "
              "or list a genuine frrcfgd gap in its _ROUTE_MAP_UNSUPPORTED_CLAUSES "
              "-- or this module configured it outside CONFIG_DB (vtysh, or a config file "
              "copied into the bgp container), in which case no translation can preserve it: "
              "the switch runs `config reload`, which rebuilds FRR from CONFIG_DB. Such a "
              "module belongs behind the frr_bgpcfgd_only marker."
              .format(mode, dropped, _CONFIG_SETTLE_TIMEOUT))


def pytest_terminal_summary(terminalreporter):
    if _CONFIG_GAPS:
        terminalreporter.section("FRR config-mode switch: known frrcfgd gaps accepted")
        for gap in sorted(_CONFIG_GAPS):
            terminalreporter.line(gap)


def _current_mode(duthost):
    return (MODE_FRR_MGMT_FRAMEWORK if duthost.get_frr_mgmt_framework_config()
            else MODE_TRADITIONAL)


def _mode_reachable(duthost, request, original_mode, mode):
    """Can ``mode`` actually be exercised on this DUT? Mirrors the fixture's skip conditions."""
    if mode == original_mode:
        return True
    if getattr(request.config.option, "enable_macsec", False):
        return False
    if duthost.facts["num_asic"] > 1 or _is_switchless_node(duthost):
        return False
    if original_mode != MODE_TRADITIONAL:
        return False
    return bool(duthost.is_file_existed(GOLDEN_CFG_FILE))


def _frr_generic_preference(config):
    preferred = config.getoption("--frr-generic-mode") or FRR_GENERIC_DEFAULT_MODE
    return [preferred] + [m for m in FRR_CONFIG_MODES if m != preferred]


def _generic_mode(duthost, request, original_mode):
    """The single reachable mode a ``frr_generic`` module runs in, or None if none is."""
    selected = request.config.getoption("--frr-config-mode")
    requested = FRR_CONFIG_MODES if selected == "both" else [selected]
    for mode in _frr_generic_preference(request.config):
        if mode in requested and _mode_reachable(duthost, request, original_mode, mode):
            return mode
    return None


_ENUM_DUT_FIXTURES = ("enum_upstream_dut_hostname", "enum_downstream_dut_hostname")


def _enum_dut_hostnames(request):
    """Hostnames this module's tests (in this mode variant) select via ``enum_*`` fixtures."""
    hosts = set()
    for item in request.session.items:
        callspec = getattr(item, "callspec", None)
        if (item.module is not request.module or callspec is None
                or callspec.params.get("frr_config_mode") != request.param):
            continue
        hosts.update(value for name, value in callspec.params.items()
                     if name.startswith("enum_") and name.endswith("hostname"))
        hosts.update(request.getfixturevalue(name) for name in _ENUM_DUT_FIXTURES
                     if name in item.fixturenames)
    return hosts


def _is_switchless_node(duthost):
    """True for DUTs with no bgp container (e.g. supervisor cards)."""
    try:
        return bool(duthost.is_supervisor_node())
    except Exception:
        return False


def _skip_reason(node, duthost, state, mode):
    """Why ``mode`` cannot or need not run for this module on this DUT, or None."""
    bgpcfgd_only = node.get_closest_marker(FRR_BGPCFGD_ONLY_MARKER)
    if bgpcfgd_only and mode == MODE_FRR_MGMT_FRAMEWORK:
        reason = (bgpcfgd_only.args[0] if bgpcfgd_only.args
                  else "this module asserts bgpcfgd-specific behaviour")
        return "frr_mgmt_framework mode not supported for this module: {}".format(reason)

    # Both params are kept for frr_generic modules so test IDs stay stable.
    if node.get_closest_marker(FRR_GENERIC_MARKER):
        chosen = _generic_mode(duthost, node, state.original_mode)
        if chosen is not None and mode != chosen:
            return ("Module is marked '{}' (mode-generic: it does not exercise the "
                    "bgpcfgd<->frrcfgd config translation), so it runs in one mode only; "
                    "covered here in the '{}' mode".format(FRR_GENERIC_MARKER, chosen))

    if mode == state.original_mode:
        return None
    if getattr(node.config.option, "enable_macsec", False):
        return ("FRR config-mode switching is skipped with --enable_macsec (the reload "
                "disrupts macsec sessions); only the DUT's native '{}' mode is exercised"
                .format(state.original_mode))
    if duthost.facts["num_asic"] > 1 or _is_switchless_node(duthost):
        return ("FRR config-mode switching is not supported on this DUT (multi-asic or "
                "supervisor/no-bgp node); only the DUT's native '{}' mode is "
                "exercised".format(state.original_mode))
    if state.original_mode != MODE_TRADITIONAL:
        return ("frr_config_mode can only switch modes from a traditional (bgpcfgd) start; "
                "this DUT boots in {}, so only that mode can be exercised".format(
                    state.original_mode))
    return None


class _FrrModeSessionState(object):
    """Per-session FRR config-mode state, stashed on the pytest session object.

    Session-scoped so a session switches at most once each way.
    """

    def __init__(self, duthost):
        self.duthost = duthost
        self.migrator = FrrConfigModeMigrator(duthost)
        self.original_mode = None
        self.applied_mode = None
        self.switch_count = 0
        self.early_skips = {}
        self.baseline_neighbors = None
        self.baseline_fingerprint = None


_SESSION_STATE_ATTR = "_frr_config_mode_state"


def _session_state(request, duthost):
    """Return this session's FRR mode state, initialising it on first use.

    Recovers an interrupted previous run first, so its mode is not taken as the original.
    """
    session = request.session
    state = getattr(session, _SESSION_STATE_ATTR, None)
    if state is not None:
        return state

    state = _FrrModeSessionState(duthost)
    state.migrator.recover_interrupted_run()
    state.original_mode = _current_mode(duthost)
    state.applied_mode = state.original_mode
    state.baseline_neighbors = _bgp_established_neighbors(duthost)
    state.baseline_fingerprint = _frr_config_fingerprint(duthost)
    # Back up now, before any module's fixtures change CONFIG_DB.
    state.migrator.capture_pristine_backup()
    setattr(session, _SESSION_STATE_ATTR, state)
    logger.info("FRR config-mode session state initialised; DUT boots in '%s'",
                state.original_mode)
    return state


def pytest_sessionfinish(session, exitstatus):
    """Restore the DUT's original FRR config mode once, at the end of the session.

    A failure sets ``INTERNAL_ERROR`` so a run that left the DUT switched is not read as clean.
    """
    state = getattr(session, _SESSION_STATE_ATTR, None)
    if state is None:
        return
    try:
        if state.applied_mode != state.original_mode:
            logger.info("Restoring FRR config mode to '%s' at session end", state.original_mode)
            _switch_mode(state, state.original_mode)
        # A marker still present means no restore was verified: keep the backups for recovery.
        if not state.migrator.interrupted_run_pending():
            state.migrator.cleanup()
    except (Exception, pytest.fail.Exception) as e:
        logger.error(
            "Failed to restore FRR config mode to '%s' on %s at session end: %s. The DUT may "
            "still be running %s config; the next run's recover_interrupted_run() will "
            "restore it at setup. Failing the session so CI does not read this run as clean.",
            state.original_mode, state.duthost.hostname, e, state.applied_mode)
        session.exitstatus = pytest.ExitCode.INTERNAL_ERROR


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
    parser.addoption(
        "--frr-generic-mode", action="store", default=None, choices=FRR_CONFIG_MODES,
        help="Mode frr_generic (framework-agnostic) modules prefer when --frr-config-mode is "
             "'both'. Default: FRR_GENERIC_DEFAULT_MODE ({}).".format(FRR_GENERIC_DEFAULT_MODE))


def pytest_generate_tests(metafunc):
    # Parametrized here, not via params=, so --frr-config-mode can narrow it.
    if "frr_config_mode" in metafunc.fixturenames:
        selected = metafunc.config.getoption("--frr-config-mode")
        modes = FRR_CONFIG_MODES if selected == "both" else [selected]
        metafunc.parametrize("frr_config_mode", modes, indirect=True, scope="module")


def _item_mode(item):
    callspec = getattr(item, "callspec", None)
    return callspec.params.get("frr_config_mode") if callspec is not None else None


@pytest.hookimpl(trylast=True)
def pytest_collection_modifyitems(config, items):
    """Run every frr_config_mode item as one block, all [traditional] before all
    [frr_mgmt_framework], so a session switches the DUT at most once each way."""
    modes = [_item_mode(item) for item in items]
    if MODE_FRR_MGMT_FRAMEWORK not in modes:
        return
    first = next(i for i, mode in enumerate(modes) if mode is not None)
    block = ([item for item, mode in zip(items, modes) if mode == MODE_TRADITIONAL]
             + [item for item, mode in zip(items, modes) if mode == MODE_FRR_MGMT_FRAMEWORK])
    rest = [item for item, mode in zip(items[first:], modes[first:]) if mode is None]
    items[first:] = block + rest


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_setup(item):
    """Skip a variant already known to be unreachable before any module fixture sets up."""
    mode = _item_mode(item)
    if mode is None:
        return
    state = getattr(item.session, _SESSION_STATE_ATTR, None)
    if state is None:
        if mode == MODE_FRR_MGMT_FRAMEWORK and item.get_closest_marker(FRR_BGPCFGD_ONLY_MARKER):
            pytest.skip(_skip_reason(item, None, None, mode))
        return
    key = (item.module.__name__, mode)
    if key not in state.early_skips:
        state.early_skips[key] = _skip_reason(item, state.duthost, state, mode)
    if state.early_skips[key]:
        pytest.skip(state.early_skips[key])


@pytest.fixture(scope="module")
def frr_config_mode(request, duthosts, rand_one_dut_hostname):
    """Run a module in both the traditional (bgpcfgd) and frr_mgmt_framework (frrcfgd) modes.

    Yields the active mode. Only ``rand_one_dut_hostname`` is switched; modules that drive
    other DUTs skip the frr variant (see :func:`skip_if_dut_not_switched`).
    """
    mode = request.param
    duthost = duthosts[rand_one_dut_hostname]
    state = _session_state(request, duthost)

    reason = _skip_reason(request.node, duthost, state, mode)
    if reason:
        pytest.skip(reason)

    if mode != state.original_mode:
        others = _enum_dut_hostnames(request) - {duthost.hostname}
        if others:
            pytest.skip("frr_config_mode switches only '{}', but this module also drives {}; "
                        "skip rather than report frr_mgmt_framework coverage for DUTs still in "
                        "their original mode".format(duthost.hostname, sorted(others)))

    if state.applied_mode != mode:
        if not duthost.is_file_existed(GOLDEN_CFG_FILE):
            pytest.skip("{} not present on DUT; cannot persist routing mode across config "
                        "reload".format(GOLDEN_CFG_FILE))
        _switch_mode(state, mode)

    yield mode
    # No per-module restore; pytest_sessionfinish restores the original mode once.


def _switch_mode(state, mode):
    """Switch the DUT to ``mode``, wait for BGP to recover, and assert nothing was dropped.

    A forward switch is checked against the state just before it; a restore against the
    session-start baseline.
    """
    duthost = state.duthost
    restoring = mode == state.original_mode
    if restoring:
        expected_neighbors = state.baseline_neighbors
        expected_fingerprint = state.baseline_fingerprint
    else:
        expected_neighbors = _bgp_established_neighbors(duthost)
        expected_fingerprint = _frr_config_fingerprint(duthost)
    # Oper-up, not admin-up: some testbeds keep admin-up ports deliberately unconnected.
    expected_ports = get_oper_up_ports(duthost)
    logger.info("Switching FRR config mode to '%s' on %s", mode, duthost.hostname)
    try:
        if mode == MODE_FRR_MGMT_FRAMEWORK:
            try:
                state.migrator.to_frr_mgmt_framework()
            except BaseException:
                # Past the switch marker the DUT may already be in frr; let session end restore it.
                try:
                    switched = state.migrator.interrupted_run_pending()
                except Exception:
                    switched = True
                if switched:
                    state.applied_mode = mode
                raise
        else:
            # False means the CONFIG_DB backup is gone and the DUT still runs frr config.
            if not state.migrator.to_traditional():
                pytest.fail(
                    "Failed to restore '{}' mode on {}: the pre-switch CONFIG_DB backup is "
                    "gone, so only the golden config files were restored and the DUT is "
                    "still running translated frr_mgmt_framework config. It needs manual "
                    "recovery ('config load_minigraph -y', or restore "
                    "/etc/sonic/config_db.json from a known-good copy) before further runs."
                    .format(mode, duthost.hostname))
    except FrrTranslationError as e:
        pytest.fail("Failed to switch to '{}' mode: {}".format(mode, e))
    state.applied_mode = mode
    state.switch_count += 1

    pt_assert(wait_until(180, 10, 0, duthost.is_service_fully_started_per_asic_or_host, "bgp"),
              "bgp service did not come up after switching to '{}' mode".format(mode))
    baseline = expected_neighbors
    # Reuse the last poll in the (eagerly built) failure message instead of another vtysh query.
    last_established = {}

    def _neighbors_recovered():
        last_established["set"] = _bgp_established_neighbors(duthost)
        return baseline <= last_established["set"]

    pt_assert(
        wait_until(180, 10, 0, _neighbors_recovered),
        "Switching to '{}' mode did not preserve BGP: neighbors {} were not all "
        "re-established (established now: {}).".format(
            mode, sorted(baseline), sorted(last_established.get("set", set()))))
    # Ports come up after BGP; a further reload before they do leaves a half-initialised stack.
    last_ports = {}

    def _ports_recovered():
        last_ports["set"] = get_oper_up_ports(duthost)
        return expected_ports <= last_ports["set"]

    pt_assert(
        wait_until(300, 20, 0, _ports_recovered),
        "Switching to '{}' mode left ports that were operationally up beforehand down on {}: "
        "{}. Continuing would run the module against a half-initialised stack (no LACP, "
        "connected routes 'dead linkdown', BGP stuck in Active).".format(
            mode, duthost.hostname,
            sorted(expected_ports - last_ports.get("set", set()))))
    _assert_config_preserved(duthost, mode, expected_fingerprint)
