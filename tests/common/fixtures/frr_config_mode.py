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
import re

import pytest

from tests.common.helpers.assertions import pytest_assert as pt_assert
from tests.common.helpers.frr.frr_config_mode_migrator import (
    FrrConfigModeMigrator,
    GOLDEN_CFG_FILE,
    MODE_FRR_MGMT_FRAMEWORK,
    MODE_TRADITIONAL,
)
from tests.common.helpers.frr.bgp_config_translation import FrrTranslationError
from tests.common.helpers.frr.frr_28543_compat import (      # noqa: DELETE-WITH-28543
    gated_globals_missing_from_image,
)
from tests.common.platform.interface_utils import get_oper_up_ports
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

FRR_CONFIG_MODES = [MODE_TRADITIONAL, MODE_FRR_MGMT_FRAMEWORK]

# Modules marked ``frr_generic`` are exercised in ONE config mode instead of both.
# Preference order: frr_mgmt_framework first, so the newer frrcfgd path gets the
# coverage, falling back to traditional when frr is not reachable on this DUT.
FRR_GENERIC_MARKER = "frr_generic"

# Modules marked ``frr_bgpcfgd_only`` are by design unsupported under frrcfgd: they assert
# bgpcfgd daemon behaviour, or drive a product operation frrcfgd does not consume. Their
# frr_mgmt_framework variant is skipped with the marker's reason, so the traditional variant
# still runs. A permanent, by-design skip -- deliberately NOT gated on an auto-lifting issue.
#
# The marker is the single mode-selection mechanism for these modules. It also covers the
# native-frrcfgd DUT on its own, so no extra "skip if the DUT boots frrcfgd" fixture is
# needed: the frr variant skips on the marker, and the traditional variant skips in the
# cascade below because the translator only converts traditional -> frr.
FRR_BGPCFGD_ONLY_MARKER = "frr_bgpcfgd_only"
_FRR_GENERIC_PREFERENCE = [MODE_FRR_MGMT_FRAMEWORK, MODE_TRADITIONAL]

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

# Single-line FRR *settings* (as opposed to named objects) that the fingerprint tracks.
# Named objects were never the whole story: bgpcfgd renders a set of globals from its
# templates that frrcfgd has no field for, and because those are not objects the name-based
# fingerprint below was structurally blind to them. Three were found by hand -- graceful
# restart, maximum-paths, and the zebra globals -- which is three too many, hence this.
#
# Matched by prefix at the start of a stripped running-config line. Deliberately narrow:
# only lines that are genuinely device-wide settings, so anything captured here is worth
# comparing and a disappearance is a real signal rather than noise.
_GLOBAL_SETTING_PREFIXES = (
    "zebra ", "no zebra ",          # zebra nexthop-group keep / nexthop kernel enable
    "fpm ", "no fpm ",              # fpm address / use-next-hop-groups
    "bgp ", "no bgp ",              # router-bgp globals: graceful-restart, bestpath, listen range
    "maximum-paths ", "table-map ",  # per-address-family globals
)

# ...except these, which are named objects already tracked in their own categories.
_GLOBAL_SETTING_EXCLUDES = (
    "bgp community-list", "bgp extcommunity-list", "bgp large-community-list",
    "bgp as-path access-list",
)

# Globals bgpcfgd renders that frrcfgd genuinely cannot express. Prefix-matched, since most
# carry a value. Same role as FRRCFGD_UNSUPPORTED_OBJECTS: a real frrcfgd capability gap, so
# it is recorded visibly rather than failing the switch. Each one is a behavioural difference
# in frr mode -- e.g. losing 'zebra nexthop-group keep 1' reverts zebra to FRR's 180s
# nexthop-group retention, which surfaces much later as flaky nexthop-group/CRM counts.
#
# Closing these needs new frrcfgd fields (tracked on sonic-buildimage#28482). They must be
# opt-in knobs the migrator sets, NOT changed frrcfgd defaults, so existing installations
# keep their current behaviour -- the same treatment ebgp_requires_policy gets in #28543.
FRRCFGD_UNSUPPORTED_GLOBAL_PREFIXES = (
    "zebra nexthop-group keep ",
    "zebra nexthop kernel enable",
    "no zebra nexthop kernel enable",
    # NOT listed, because frrcfgd DOES render them (templates/frr/frr.conf.j2):
    #   fpm address 127.0.0.1          -- hardcoded there, same as bgpcfgd
    #   fpm use-next-hop-groups        -- driven by DEVICE_METADATA.nexthop_group
    # If either ever goes missing across a switch that is a real regression, so let it fail.
    "bgp graceful-restart select-defer-time ",
    "bgp graceful-restart-disable",
    "bgp long-lived-graceful-restart ",
    # bgpcfgd renders this from DEVICE_METADATA.suppress-fib-pending
    # (bgpd.main.conf.j2). frrcfgd does not: grepping the whole
    # sonic-frr-mgmt-framework tree for suppress-fib finds nothing -- neither a
    # global_key_map entry nor a template line. The translator still carries the
    # DEVICE_METADATA field across (it is YANG-modeled, it is what
    # `config suppress-fib-pending` writes, and route_check.py reads it), so CONFIG_DB
    # stays consistent -- but the FRR line itself is lost in frr mode.
    "bgp suppress-fib-pending",
)


def _is_global_setting(line):
    """True for a running-config line that is a device-wide FRR setting we should compare."""
    if any(line.startswith(p) for p in _GLOBAL_SETTING_EXCLUDES):
        return False
    return any(line.startswith(p) for p in _GLOBAL_SETTING_PREFIXES)


# How long to let the config daemon finish rendering after a mode switch before
# declaring a baseline object lost. See _assert_config_preserved.
_CONFIG_SETTLE_TIMEOUT = 120
_CONFIG_SETTLE_INTERVAL = 10


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


def switched_dut_hostname(request):
    """The hostname ``frr_config_mode`` actually switched, or None if no switch happened.

    None covers every no-switch path -- a native-mode run, a multi-ASIC or supervisor DUT,
    ``--enable_macsec`` -- as well as a session where the fixture has not run yet.
    """
    state = getattr(request.session, _SESSION_STATE_ATTR, None)
    if state is None or state.applied_mode == state.original_mode:
        return None
    return state.duthost.hostname


def frr_mode_switch_count(request):
    """How many FRR config-mode switches this session has performed so far.

    0 when the fixture has not run yet. Capture it at module setup and re-read it at
    teardown to tell whether a switch (and therefore a ``config reload``) happened while the
    module was running.
    """
    state = getattr(request.session, _SESSION_STATE_ATTR, None)
    return state.switch_count if state is not None else 0


def frr_mode_perturbed(request, since_switch_count=None):
    """True when the generic DUT-health config checks cannot be trusted right now.

    Those checks compare the DUT against a testbed-wide baseline --
    ``/etc/sonic/running_golden_config.json``, written once by
    ``test_pretest.py::test_generate_running_golden_config`` and reused for the life of the
    testbed -- so they answer "does the DUT still match the pretest snapshot", not "did this
    module change anything". Two independent things make that comparison meaningless here:

    * **the DUT is not in its boot config mode.** Its CONFIG_DB then differs from the pretest
      baseline across the entire frr schema, by design rather than as drift. No amount of
      settling fixes this, so the frr_mgmt_framework variant can never pass config-diff.
    * **a mode switch ran during this module.** That is a ``config reload``, which regenerates
      telemetry/gnmi certs and re-runs db_migrator -- benign, self-restoring differences any
      reload produces, mode switch or not.

    Pass the setup-time :func:`frr_mode_switch_count` as ``since_switch_count`` to cover the
    second case; omit it to test only the first (e.g. for a pre-test check, where nothing has
    run yet). False when the fixture never ran, so non-BGP modules are unaffected.
    """
    state = getattr(request.session, _SESSION_STATE_ATTR, None)
    if state is None:
        return False
    if state.applied_mode != state.original_mode:
        return True
    return since_switch_count is not None and state.switch_count != since_switch_count


def skip_if_dut_not_switched(request, duthost):
    """Skip when ``duthost`` is not the DUT ``frr_config_mode`` switched.

    The fixture switches ``rand_one_dut_hostname``. A module that configures or asserts FRR
    behaviour on a DIFFERENT DUT -- one chosen by ``enum_rand_one_per_hwsku_frontend_hostname``,
    ``enum_frontend_dut_hostname``, or its own source/destination selection -- would otherwise
    report frr coverage while running against a DUT still in traditional mode. That is worse
    than no coverage when the module's read side normalises both schemas, because the
    ``[frr_mgmt_framework]`` variant then passes without having exercised frrcfgd at all.

    Those selections genuinely resolve to a different host on topologies that exist today: a
    dualtor testbed has two single-ASIC frontend DUTs, and a multi-DUT T2 enumerates several.

    A no-op when no switch was performed (see :func:`switched_dut_hostname`) -- there is no
    mismatch to protect against then -- and a no-op when the hostnames coincide, which they do
    on a single-DUT topology. Call it from the module's setup, passing the DUT the module
    actually operates on. Widening the fixture to switch every DUT under test instead would
    need per-DUT migrators and baselines.
    """
    switched = switched_dut_hostname(request)
    if switched is None or duthost.hostname == switched:
        return
    pytest.skip(
        "frr_config_mode switched '{}', but this test operates on '{}'. Running here would "
        "report frr_mgmt_framework coverage for a DUT still in its original mode, so skip "
        "instead. Switching every DUT under test would need per-DUT migrators and baselines."
        .format(switched, duthost.hostname))

# BGP monitors (BGP_MONITORS / bgpmon) is a legacy feature, superseded by BMP (BGP Monitoring
# Protocol, RFC 7854) which FRR now supports natively and which the tests/bmp suite covers.
# bgpmon predates BMP and was only added because FRR lacked BMP support at the time. frrcfgd
# intentionally does not implement it -- it is NOT a parity gap to close (see sonic-buildimage
# issue #28482, "Explicitly out of scope") -- so the bgpmon modules/tests are not parametrized
# over frr_config_mode: they run in traditional (bgpcfgd) mode and skip outright on a
# native-frrcfgd DUT. This is a permanent, by-design skip, deliberately NOT gated on an
# auto-lifting tracking issue.


FRR_LEGACY_BGP_MONITORS_REASON = (
    "BGP monitors (BGP_MONITORS) is a legacy feature superseded by BMP and is intentionally "
    "unsupported in frr_mgmt_framework mode; use BMP (see tests/bmp) instead")

# BGP sentinels (BGP_SENTINELS) is an opinionated bgpcfgd macro, not a routing primitive -- it
# expands to a listen-range peer-group + fixed FROM_/TO_BGP_SENTINEL route-maps + a
# sentinel_community community-list (from constants.yml), all of which are already expressible
# via the generic CONFIG_DB tables frrcfgd renders. Teaching frrcfgd a bespoke sentinel expander
# conflicts with its "render only generic primitives" design, so it stays bgpcfgd-only (see
# sonic-buildimage#28482, "Explicitly out of scope") -- a permanent, by-design skip, NOT gated on
# an auto-lifting tracking issue.
FRR_BGPCFGD_ONLY_SENTINEL_REASON = (
    "BGP sentinels (BGP_SENTINELS) is a bgpcfgd-only macro, intentionally unsupported in "
    "frr_mgmt_framework mode (the equivalent is expressible via generic peer-group/route-map "
    "tables)")

# The BGP aggregate-address suite asserts bgpcfgd's AggregateAddressMgr behavior, not just
# "FRR advertises an aggregate": it writes BGP_AGGREGATE_ADDRESS, reads that row back out of
# CONFIG_DB, and asserts the STATE_DB row AggregateAddressMgr derives from it -- including the
# bbr-required gating (an aggregate goes 'inactive' when BBR is off). frrcfgd has no
# BGP_AGGREGATE_ADDRESS handler, no STATE_DB writer, and no bbr-required concept at all; its
# native BGP_GLOBALS_AF_AGGREGATE_ADDR table expresses only the FRR-render half, so a
# mode-aware write would leave the CONFIG_DB/STATE_DB/BBR assertions -- most of the suite --
# untestable. Like test_prefix_list_suppress (PrefixListMgr), this is a bgpcfgd daemon-behavior
# suite, so its modules are not parametrized over frr_config_mode: they run in traditional mode
# and skip outright on a native-frrcfgd DUT.
FRR_BGPCFGD_ONLY_AGGREGATE_REASON = (
    "the BGP aggregate-address suite asserts bgpcfgd AggregateAddressMgr behavior "
    "(BGP_AGGREGATE_ADDRESS CONFIG_DB/STATE_DB rows and bbr-required gating), which frrcfgd "
    "does not implement")


def _core_dumps(duthost):
    cmd = ("ls /var/core/ | grep -v python || true" if "20191130" in duthost.os_version
           else "ls /var/core/ || true")
    return set(duthost.shell(cmd, module_ignore_errors=True)["stdout"].split())


def expected_core_dump_patterns(node):
    """Regexes for core dumps a module legitimately produces, from its
    ``pytest.mark.expected_core_dumps(...)`` markers.

    Some modules knowingly generate a core as part of what they exercise -- e.g. the
    traffic-shift modules and ``dplane_fpm_nl`` on certain platforms. They used to whitelist
    those by appending to ``core_dump_and_config_check``'s ``pre_core_dumps``, which only
    works while that fixture is active. Expressing it as a marker instead lets every
    core-dump checker honour the same list.
    """
    patterns = []
    for marker in node.iter_markers("expected_core_dumps"):
        patterns.extend(marker.args)
    return patterns


def _is_expected_core(core, patterns):
    return any(re.match(p, core) for p in patterns)


@pytest.fixture(scope="module", autouse=True)
def _frr_mode_core_dump_check(request, duthosts):
    """Focused core-dump (crash) detection for frr_config_mode modules whose own markers turn
    the generic check off.

    ``core_dump_and_config_check`` does crash detection for opted-in modules as usual -- it is
    only the running-config *comparison* the mode switch invalidates, and that is skipped on
    its own (see ``frr_mode_perturbed``). But a module that carries ``skip_check_dut_health``
    in its own ``pytestmark`` disables that fixture entirely, and a process crash during a
    dual-mode BGP test must still be caught. So this runs only for ``frr_dual_mode`` modules
    that are also ``skip_check_dut_health``: core dumps only, no config-diff and no recovery
    reload. A no-op everywhere else, including where the generic check is active, so a crash
    is never reported twice.

    Cores a module declares via ``expected_core_dumps`` are reported but do not fail it --
    otherwise this check would turn the traffic-shift modules' known ``dplane_fpm_nl`` core
    into a module failure, which is precisely the whitelist the generic checker honours.
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
          "route_maps": set(), "community_lists": set(), "globals": set()}
    for raw in out.splitlines():
        # Independent of the object classification below -- a line can be both a global
        # setting and (for community-lists) a named object, and the excludes handle that.
        stripped = raw.strip()
        if _is_global_setting(stripped):
            fp["globals"].add(stripped)
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


def _dropped_config_objects(duthost, mode, baseline_fp, image_gated_globals=frozenset()):
    """Return ``{category: [name, ...]}`` for baseline objects FRR is not rendering now.

    ``image_gated_globals`` are global lines this image cannot carry because the CONFIG_DB
    field behind them is not in its YANG models yet (sonic-buildimage#28543). The translator
    emits them correctly; the compat shim strips them just before they reach the DUT, so
    their absence afterwards is expected rather than a translation miss.
    """
    after = _frr_config_fingerprint(duthost)
    dropped = {}
    for cat, objs in baseline_fp.items():
        missing = objs - after[cat]
        # A missing object that frrcfgd is known not to support is an expected capability
        # gap, not a translation miss -- record it visibly but do not fail on it.
        if cat == "globals":
            # Prefix-matched: most of these carry a value (e.g. 'keep 1', 'restart-time 240').
            exempt = {o for o in missing
                      if any(o.startswith(p) for p in FRRCFGD_UNSUPPORTED_GLOBAL_PREFIXES)}
            exempt |= (missing & image_gated_globals)     # noqa: DELETE-WITH-28543
        else:
            exempt = missing & FRRCFGD_UNSUPPORTED_OBJECTS.get(cat, set())
        if exempt:
            logger.info("Switching to '%s' mode dropped frrcfgd-unsupported %s %s "
                        "(bgpcfgd base-template artifacts with no frrcfgd equivalent); "
                        "ignoring -- not a translation miss.", mode, cat, sorted(exempt))
        real = sorted(missing - exempt)
        if real:
            dropped[cat] = real
    return dropped


def _assert_config_preserved(duthost, mode, baseline_fp):
    """Fail loudly if any BGP object present before the switch is still missing once the
    DUT has settled.

    Poll rather than sample once: BGP sessions re-establishing does not mean the config
    daemon has finished rendering. bgpcfgd/frrcfgd drain their CONFIG_DB subscriptions
    asynchronously after the reload, and objects with no session to establish are the
    slowest to show up -- the bgpmon route-maps (FROM_BGPMON/TO_BGPMON), which bgpcfgd
    renders from BGP_MONITORS, routinely lag the neighbor-recovery check and made the
    switch-back to traditional mode fail spuriously.
    """
    dropped = {}
    # Probed once, not per poll: a pre-#28543 image cannot carry these, so their absence is
    # expected. Empty once the image carries #28543, tightening the check back up by itself.
    image_gated = gated_globals_missing_from_image(duthost)   # noqa: DELETE-WITH-28543
    if image_gated:
        logger.info("Image predates sonic-buildimage#28543; these globals cannot survive the "
                    "switch and are not counted as dropped: %s", sorted(image_gated))

    def _settled():
        dropped.clear()
        dropped.update(_dropped_config_objects(duthost, mode, baseline_fp, image_gated))
        return not dropped

    wait_until(_CONFIG_SETTLE_TIMEOUT, _CONFIG_SETTLE_INTERVAL, 0, _settled)
    pt_assert(not dropped,
              "Switching to '{}' mode dropped BGP config objects that were present in the "
              "original mode: {} (still missing after {}s). Either the bgpcfgd->frrcfgd "
              "translation did not carry them over -- extend "
              "tests/common/helpers/frr/bgp_config_translation.py (and frrcfgd) to cover them "
              "-- or this module configured them outside CONFIG_DB (vtysh, or a config file "
              "copied into the bgp container), in which case no translation can preserve them: "
              "the switch runs `config reload`, which rebuilds FRR from CONFIG_DB. Such a "
              "module belongs behind the frr_bgpcfgd_only marker."
              .format(mode, dropped, _CONFIG_SETTLE_TIMEOUT))


def _current_mode(duthost):
    return (MODE_FRR_MGMT_FRAMEWORK if duthost.get_frr_mgmt_framework_config()
            else MODE_TRADITIONAL)


def _mode_reachable(duthost, request, original_mode, mode):
    """Can ``mode`` actually be exercised on this DUT?

    Mirrors the skip conditions in the ``frr_config_mode`` fixture below, so a
    ``frr_generic`` module can pick a mode that will really run instead of one that
    would skip. Staying in the DUT's boot mode is always reachable (no switch needed).
    """
    if mode == original_mode:
        return True
    # macsec and multi-asic / switchless DUTs run the boot mode only (see the fixture).
    if getattr(request.config.option, "enable_macsec", False):
        return False
    if duthost.facts["num_asic"] > 1 or _is_switchless_node(duthost):
        return False
    # The translator only converts traditional -> frr.
    if original_mode != MODE_TRADITIONAL:
        return False
    # A switch persists the mode in golden config so it survives the reload.
    return bool(duthost.is_file_existed(GOLDEN_CFG_FILE))


def _generic_mode(duthost, request, original_mode):
    """For a ``frr_generic`` module, return the single mode to exercise.

    Chosen from the modes ``--frr-config-mode`` selected, in
    ``_FRR_GENERIC_PREFERENCE`` order (frrcfgd first), restricted to modes that are
    actually reachable on this DUT. Returns None when none is reachable, letting the
    fixture's normal skip cascade produce the specific reason.
    """
    selected = request.config.getoption("--frr-config-mode")
    requested = FRR_CONFIG_MODES if selected == "both" else [selected]
    for mode in _FRR_GENERIC_PREFERENCE:
        if mode in requested and _mode_reachable(duthost, request, original_mode, mode):
            return mode
    return None


def _is_switchless_node(duthost):
    """True for DUTs with no switchable BGP stack -- e.g. supervisor / chassis-control
    cards, which run no bgp container. A mode switch there is meaningless and the
    migrator's ``vtysh`` call would fail ("container ... is not running")."""
    try:
        return bool(duthost.is_supervisor_node())
    except Exception:
        return False


class _FrrModeSessionState(object):
    """Per-session FRR config-mode state.

    Deliberately session-scoped rather than per-module. The mode is a property of the DUT,
    not of a test module, so tracking it per module made every parametrized module switch
    into frr and then immediately switch back -- two `config reload`s each, even when the
    very next module wanted the same mode. pytest already groups tests by the module-scoped
    param, so consecutive same-mode modules now cost zero extra switches and the DUT is
    restored once, in pytest_sessionfinish.

    Note the DUT cannot depend on a session-scoped fixture here: rand_one_dut_hostname is
    module-scoped, so this is stashed on the session object and initialised lazily by the
    first module-scoped frr_config_mode that runs.
    """

    def __init__(self, duthost):
        self.duthost = duthost
        self.migrator = FrrConfigModeMigrator(duthost)
        self.original_mode = None
        self.applied_mode = None
        # Monotonic count of mode switches performed this session. The generic DUT-health
        # checks compare it across a module to tell "a `config reload` happened while this
        # module ran" from "the DUT was already in this mode when the module started".
        self.switch_count = 0
        self.baseline_neighbors = None
        self.baseline_fingerprint = None


_SESSION_STATE_ATTR = "_frr_config_mode_state"


def _session_state(request, duthost):
    """Return this session's FRR mode state, initialising it on first use.

    Initialisation also recovers from an interrupted previous run before reading the DUT's
    "original" mode -- otherwise a run that died mid-switch would leave the DUT in frr and we
    would record frr as the baseline to restore to, making the damage permanent.
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
    # Back the config up here, alongside the baselines it has to agree with, rather than
    # letting the migrator do it lazily at the first switch -- by then a module's own fixtures
    # may already have changed CONFIG_DB, and restoring that is not a restore.
    state.migrator.capture_pristine_backup()
    setattr(session, _SESSION_STATE_ATTR, state)
    logger.info("FRR config-mode session state initialised; DUT boots in '%s'",
                state.original_mode)
    return state


def pytest_sessionfinish(session, exitstatus):
    """Restore the DUT's original FRR config mode once, at the end of the session.

    Replaces the old per-module restore. This fires on a normal finish and on
    KeyboardInterrupt, but NOT on SIGKILL / OOM / a hard DUT crash -- nothing in pytest can.
    That residual case is covered by the migrator's setup-time
    recover_interrupted_run(), which repairs the DUT on the next run.

    A failure here is an infrastructure failure, not a test failure: the DUT may be left in
    the wrong FRR config mode, which silently mis-runs every later module on that testbed.
    So it forces a non-zero session exit status (``INTERNAL_ERROR``) rather than only logging
    -- a green run whose DUT was left switched is worse than a red one, because nothing else
    in the session reports it. The DUT is still self-repairing: the switch marker stays on
    it, so the next run's recover_interrupted_run() restores it at setup.
    """
    state = getattr(session, _SESSION_STATE_ATTR, None)
    if state is None:
        return
    try:
        if state.applied_mode != state.original_mode:
            logger.info("Restoring FRR config mode to '%s' at session end", state.original_mode)
            _switch_mode(state, state.original_mode)
        state.migrator.cleanup()
    except Exception as e:
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

    Generic DUT-health checks: the mode switch rewrites BGP config_db mid-module and
    reloads, which the config-diff and YANG checks would flag. They are NOT disabled by a
    marker -- that would suppress them for every opted-in module and both mode variants,
    including native-mode runs that reload nothing. Instead the checks themselves skip at
    runtime, via ``frr_mode_perturbed()``, exactly while the DUT is away from its boot mode
    or in a module a switch actually ran in; crash detection is never skipped. The switch
    restores the DUT's original config on exit, leaving the testbed clean for later modules.

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

    Scope caveat -- which DUT gets switched: this fixture switches the mode on
    ``rand_one_dut_hostname``. A module that acts on a different DUT
    (``enum_frontend_dut_hostname``, ``enum_rand_one_per_hwsku_frontend_hostname``,
    ``enum_downstream_dut_hostname``/``enum_upstream_dut_hostname``, or its own
    source/destination selection) is only meaningfully parametrized when those resolve to
    the same host.

    They do on a single-DUT topology, but NOT in general: a dualtor testbed has two
    single-ASIC frontend DUTs, so the multi-ASIC no-switch branch below does not save us,
    and a multi-DUT T2 enumerates several. Such a module must call
    :func:`skip_if_dut_not_switched` from its setup with the DUT it operates on, so the frr
    variant skips rather than reporting frr coverage for a DUT still in its original mode.
    That matters most where the module's read side normalises both schemas -- the variant
    would otherwise pass without exercising frrcfgd at all.

    Widening this to switch every DUT under test would need per-DUT migrators and baselines.

    Skips (with a clear reason, rather than running something wrong):
      * multi-ASIC DUT (per-ASIC switching not supported yet);
      * a mode that differs from the DUT's boot mode when that boot mode is not traditional
        (we only translate traditional -> frr; a same-mode native run is allowed);
      * no golden_config_db.json when a switch is required (needed to persist the mode
        across config reload).
    """
    mode = request.param
    duthost = duthosts[rand_one_dut_hostname]
    # Session-scoped state: the FRR config mode is a property of the DUT, not of a module.
    # Initialising it also recovers from a previous run that died mid-switch.
    state = _session_state(request, duthost)

    # frr_generic modules are mode-generic: they assert FRR / dataplane / kernel behavior
    # over config established at boot and do not exercise the bgpcfgd<->frrcfgd schema
    # translation, so running the body in both modes re-tests FRR, not the config daemon.
    # Run them in ONE mode (frrcfgd preferred) and skip the other variant.
    #
    # Both params are deliberately kept rather than collapsing to one, so test IDs stay
    # [traditional] / [frr_mgmt_framework] (conditional_mark keys and -k selection depend
    # on them), the report states which mode actually ran, and -- crucially -- a DUT that
    # cannot reach frr mode (no golden config, multi-asic, macsec, non-traditional boot)
    # still runs the module in traditional instead of skipping it entirely.
    bgpcfgd_only = request.node.get_closest_marker(FRR_BGPCFGD_ONLY_MARKER)
    if bgpcfgd_only and mode == MODE_FRR_MGMT_FRAMEWORK:
        reason = (bgpcfgd_only.args[0] if bgpcfgd_only.args
                  else "this module asserts bgpcfgd-specific behaviour")
        pytest.skip("frr_mgmt_framework mode not supported for this module: {}".format(reason))

    if request.node.get_closest_marker(FRR_GENERIC_MARKER):
        chosen = _generic_mode(duthost, request, state.original_mode)
        if chosen is not None and mode != chosen:
            pytest.skip(
                "Module is marked '{}' (mode-generic: it does not exercise the "
                "bgpcfgd<->frrcfgd config translation), so it runs in one mode only; "
                "covered here in the '{}' mode".format(FRR_GENERIC_MARKER, chosen))

    # macsec: the mode-switch config reload disrupts macsec-protected PortChannel/BGP
    # sessions, which re-negotiate slowly and flakily after a reload (so the switch-back's
    # BGP-preservation check fails even though the test bodies pass). Mode switching is
    # orthogonal to the BGP config schema, and the generic DUT-health checks already disable
    # themselves under --enable_macsec, so run only the DUT's native mode here too.
    if getattr(request.config.option, "enable_macsec", False):
        if mode == state.original_mode:
            yield mode
            return
        pytest.skip("FRR config-mode switching is skipped with --enable_macsec (the reload "
                    "disrupts macsec sessions); only the DUT's native '{}' mode is exercised"
                    .format(state.original_mode))

    # Some DUTs cannot have their BGP config-mode switched:
    #   * multi-asic DUTs use per-namespace BGP config the translator does not handle yet;
    #   * supervisor/chassis-control nodes run no bgp container at all (a mode switch there
    #     dies in the migrator's ``vtysh`` call -- "container ... is not running").
    # Rather than skip the module outright (which would turn an otherwise-passing test into
    # a skip on its native topology, e.g. a t2 chassis), run only the DUT's native mode as a
    # no-op and skip the other mode variant.
    if duthost.facts["num_asic"] > 1 or _is_switchless_node(duthost):
        if mode == state.original_mode:
            yield mode
            return
        pytest.skip("FRR config-mode switching is not supported on this DUT (multi-asic or "
                    "supervisor/no-bgp node); only the DUT's native '{}' mode is "
                    "exercised".format(state.original_mode))

    # The translator only converts traditional -> frr (the reverse is a config_db
    # backup-restore, not a translation), so a mode other than the DUT's
    # original one is only reachable from a traditional start. A run that stays in the DUT's
    # original mode (e.g. --frr-config-mode=frr_mgmt_framework on a DUT that already boots in
    # frr_mgmt_framework) needs no switch and no translation, so allow it.
    if mode != state.original_mode and state.original_mode != MODE_TRADITIONAL:
        pytest.skip("frr_config_mode can only switch modes from a traditional (bgpcfgd) start; "
                    "this DUT boots in {}, so only that mode can be exercised".format(
                        state.original_mode))

    if state.applied_mode != mode:
        # A mode switch persists the new mode in golden config so it survives the reload; a
        # no-switch native run (mode == the DUT's boot mode) does not need it.
        if not duthost.is_file_existed(GOLDEN_CFG_FILE):
            pytest.skip("{} not present on DUT; cannot persist routing mode across config "
                        "reload".format(GOLDEN_CFG_FILE))
        _switch_mode(state, mode)

    yield mode

    # No per-module restore. The DUT is left in whatever mode this module used, so the next
    # module wanting the same mode costs zero switches; pytest_sessionfinish restores the
    # original mode once at the end. A per-module restore looked safer but was not -- it
    # equally fails to run on SIGKILL / OOM / DUT crash, and only narrowed the window while
    # paying two config reloads per module. The residual case is covered idempotently at
    # setup by the migrator's recover_interrupted_run().


def _switch_mode(state, mode):
    """Switch the DUT to ``mode``, wait for BGP to recover, and assert strictness.

    What we assert against depends on the direction, because the two directions do different
    things:

    * A forward switch *translates* whatever happens to be configured right now, so it is
      compared against the state captured immediately beforehand. Comparing against the
      session-start baseline instead blames the translation for config a test changed in
      between -- observed on a t1, where a module replaces the DUT's BGP config from a template
      before the switch and the fingerprint then reported the template's missing prefix-lists
      and community-lists as a translation loss.
    * A restore reinstates the session-start backup, so the session-start baseline is exactly
      what should come back.
    """
    duthost = state.duthost
    restoring = mode == state.original_mode
    if restoring:
        expected_neighbors = state.baseline_neighbors
        expected_fingerprint = state.baseline_fingerprint
    else:
        expected_neighbors = _bgp_established_neighbors(duthost)
        expected_fingerprint = _frr_config_fingerprint(duthost)
    # Hold the switch to the ports that were actually carrying traffic beforehand, not to
    # every admin-up port: some testbeds keep admin-up ports deliberately unconnected, and
    # those must not make every mode switch fail. See the recovery check below.
    expected_ports = get_oper_up_ports(duthost)
    logger.info("Switching FRR config mode to '%s' on %s", mode, duthost.hostname)
    try:
        if mode == MODE_FRR_MGMT_FRAMEWORK:
            state.migrator.to_frr_mgmt_framework()
        else:
            # to_traditional() returns False when the CONFIG_DB backup is gone: it restored
            # the golden files only, and the DUT is still running translated frr config.
            # Recording the mode as applied there would leave the rest of the session -- and
            # the session-end restore, which no-ops when applied == original -- believing the
            # DUT had been returned to traditional. Fail instead, leaving applied_mode alone.
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
    # A mode switch is a full-stack reload ('config reload' stops sonic.target -- every
    # container). BGP being established does not mean the DUT is ready: the front-panel ports
    # come up later, and anything that reloads again before they do gets a half-initialised
    # stack. Measured on a t2: a second reload ~90s after this one left all 10 admin-up ports
    # oper-down, so LACP never formed, the peer subnets' connected routes stayed 'dead
    # linkdown', and every BGP session sat in Active with "No path to specified Neighbor" --
    # surfacing as a bogus BGP/LLDP timeout in whichever module reloaded next.
    #
    # Since continuing in that state is exactly what the comment above says must not happen,
    # this fails rather than warns. It is held to the ports that were operationally up before
    # the switch (captured above), so a testbed's intentionally-disconnected admin-up ports do
    # not turn every switch into a failure.
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
