"""Offline unit tests for the frr_config_mode fixture's mode-selection logic (no DUT)."""
import pytest

from tests.common.fixtures import frr_config_mode as fcm

pytestmark = [
    pytest.mark.topology('any')
]

TRAD, FRR = fcm.MODE_TRADITIONAL, fcm.MODE_FRR_MGMT_FRAMEWORK


class FakeConfig(object):
    def __init__(self, **options):
        self.options = {"--frr-config-mode": "both", "--frr-generic-mode": None}
        self.options.update(options)

    def getoption(self, name):
        return self.options[name]


@pytest.mark.parametrize("options,expected", [
    ({}, [TRAD, FRR]),
    ({"--frr-generic-mode": FRR}, [FRR, TRAD]),
], ids=["default", "option-override"])
def test_frr_generic_preference(options, expected):
    assert fcm.FRR_GENERIC_DEFAULT_MODE == TRAD
    assert fcm._frr_generic_preference(FakeConfig(**options)) == expected


class FakeMigrator(object):
    def __init__(self, marker=False, forward_error=None, restores=True):
        self.marker = marker
        self.forward_error = forward_error
        self.restores = restores
        self.cleaned = False

    def interrupted_run_pending(self):
        return self.marker

    def to_frr_mgmt_framework(self):
        if self.forward_error is not None:
            self.marker = True
            raise self.forward_error

    def to_traditional(self):
        return self.restores

    def cleanup(self):
        self.cleaned = True


class FakeState(object):
    def __init__(self, migrator, applied=TRAD):
        self.duthost = type("Dut", (), {"hostname": "dut1"})()
        self.migrator = migrator
        self.original_mode = TRAD
        self.applied_mode = applied
        self.switch_count = 0
        self.baseline_neighbors = set()
        self.baseline_fingerprint = {}


class FakeSession(object):
    def __init__(self, state):
        setattr(self, fcm._SESSION_STATE_ATTR, state)
        self.exitstatus = 0


@pytest.fixture
def no_ports(monkeypatch):
    for name in ("get_oper_up_ports", "_bgp_established_neighbors", "_frr_config_fingerprint"):
        monkeypatch.setattr(fcm, name, lambda dut: set())


def test_failed_forward_switch_is_recorded_as_switched(no_ports):
    state = FakeState(FakeMigrator(forward_error=RuntimeError("reload failed")))
    with pytest.raises(RuntimeError):
        fcm._switch_mode(state, FRR)
    assert state.applied_mode == FRR


def test_sessionfinish_keeps_backups_when_restore_fails(no_ports):
    """pytest.fail() from a failed restore is a BaseException; it must still fail the session."""
    migrator = FakeMigrator(marker=True, restores=False)
    session = FakeSession(FakeState(migrator, applied=FRR))
    fcm.pytest_sessionfinish(session, 0)
    assert session.exitstatus == pytest.ExitCode.INTERNAL_ERROR
    assert not migrator.cleaned


@pytest.mark.parametrize("marker", [True, False])
def test_sessionfinish_cleans_up_only_without_marker(marker):
    migrator = FakeMigrator(marker=marker)
    fcm.pytest_sessionfinish(FakeSession(FakeState(migrator)), 0)
    assert migrator.cleaned is not marker


class FakeNode(object):
    def __init__(self, markers=()):
        self.name = "test_module.py"
        self.markers = set(markers)

    def get_closest_marker(self, name):
        return name if name in self.markers else None


class FakeRequest(object):
    def __init__(self, state, markers=()):
        self.session = FakeSession(state)
        self.node = FakeNode(markers)


def _run_restore_fixture(request, monkeypatch):
    switched_to = []
    monkeypatch.setattr(fcm, "_switch_mode", lambda state, mode: switched_to.append(mode))
    fcm._frr_mode_restore_for_other_modules.__wrapped__(request)
    return switched_to


@pytest.mark.parametrize("applied,markers,expected", [
    (FRR, [], [TRAD]),
    (FRR, ["frr_dual_mode"], []),
    (TRAD, [], []),
], ids=["non-dual-mode-module-restored", "dual-mode-module-left", "already-in-boot-mode"])
def test_restore_fixture_switches_back_to_boot_mode(monkeypatch, applied, markers, expected):
    state = FakeState(FakeMigrator(), applied=applied)
    assert _run_restore_fixture(FakeRequest(state, markers), monkeypatch) == expected


class FakeItem(object):
    def __init__(self, module, params=None, fixturenames=()):
        self.module = module
        if params is not None:
            self.callspec = type("CallSpec", (), {"params": params})()
        self.fixturenames = list(fixturenames)


class FakeModuleRequest(object):
    def __init__(self, items, module="mod", param=FRR, fixtures=None):
        self.session = type("Session", (), {"items": items})()
        self.module = module
        self.param = param
        self.fixtures = fixtures or {}

    def getfixturevalue(self, name):
        return self.fixtures[name]


def test_enum_dut_hostnames_collects_this_module_and_variant_only():
    items = [
        FakeItem("mod", {"frr_config_mode": FRR, "enum_frontend_dut_hostname": "dut2"}),
        FakeItem("mod", {"frr_config_mode": TRAD, "enum_frontend_dut_hostname": "dut3"}),
        FakeItem("other", {"frr_config_mode": FRR, "enum_frontend_dut_hostname": "dut4"}),
        FakeItem("mod", {"frr_config_mode": FRR}, fixturenames=["enum_upstream_dut_hostname"]),
        FakeItem("mod"),
    ]
    request = FakeModuleRequest(items, fixtures={"enum_upstream_dut_hostname": "dut5"})
    assert fcm._enum_dut_hostnames(request) == {"dut2", "dut5"}


def _items(*spec):
    return [FakeItem(module, {"frr_config_mode": mode} if mode else None) for module, mode in spec]


def test_items_run_traditional_block_then_frr_block():
    items = _items(("pretest", None), ("a", TRAD), ("a", FRR), ("acl", None),
                   ("b", TRAD), ("b", FRR), ("posttest", None))
    fcm.pytest_collection_modifyitems(None, items)
    assert [(i.module, fcm._item_mode(i)) for i in items] == [
        ("pretest", None), ("a", TRAD), ("b", TRAD), ("a", FRR), ("b", FRR),
        ("acl", None), ("posttest", None)]


def test_item_order_untouched_without_frr_items():
    items = _items(("a", None), ("b", TRAD), ("c", None))
    before = list(items)
    fcm.pytest_collection_modifyitems(None, items)
    assert items == before


class FakeDut(object):
    hostname = "dut1"

    def __init__(self, num_asic=1):
        self.facts = {"num_asic": num_asic}

    def is_supervisor_node(self):
        return False


class SetupItem(object):
    def __init__(self, mode, markers=(), session=None, **options):
        self.callspec = type("CallSpec", (), {"params": {"frr_config_mode": mode}})()
        self.module = type("Module", (), {"__name__": "test_mod"})
        self.markers = {m: type("Mark", (), {"args": ()})() for m in markers}
        self.session = session or type("Session", (), {})()
        self.config = FakeConfig(**options)
        self.config.option = type("Option", (), {"enable_macsec": False})()

    def get_closest_marker(self, name):
        return self.markers.get(name)


def _session_with_state(dut, original=TRAD):
    state = FakeState(FakeMigrator())
    state.duthost, state.original_mode, state.early_skips = dut, original, {}
    session = type("Session", (), {})()
    setattr(session, fcm._SESSION_STATE_ATTR, state)
    return session


def test_bgpcfgd_only_frr_variant_skips_before_any_fixture_runs():
    with pytest.raises(pytest.skip.Exception):
        fcm.pytest_runtest_setup(SetupItem(FRR, [fcm.FRR_BGPCFGD_ONLY_MARKER]))


def test_frr_generic_frr_variant_skips_early_on_a_bgpcfgd_dut():
    session = _session_with_state(FakeDut())
    with pytest.raises(pytest.skip.Exception, match="covered here in the 'traditional' mode"):
        fcm.pytest_runtest_setup(SetupItem(FRR, [fcm.FRR_GENERIC_MARKER], session))
    fcm.pytest_runtest_setup(SetupItem(TRAD, [fcm.FRR_GENERIC_MARKER], session))


def test_frr_variant_skips_early_on_a_multi_asic_dut():
    with pytest.raises(pytest.skip.Exception, match="multi-asic"):
        fcm.pytest_runtest_setup(SetupItem(FRR, session=_session_with_state(FakeDut(num_asic=2))))


def test_dual_mode_frr_variant_is_left_to_the_fixture():
    fcm.pytest_runtest_setup(SetupItem(FRR, session=_session_with_state(FakeDut())))


def test_frr_generic_falls_back_to_frr_on_a_native_frrcfgd_dut():
    session = _session_with_state(FakeDut(), original=FRR)
    fcm.pytest_runtest_setup(SetupItem(FRR, [fcm.FRR_GENERIC_MARKER], session))
    with pytest.raises(pytest.skip.Exception):
        fcm.pytest_runtest_setup(SetupItem(TRAD, [fcm.FRR_GENERIC_MARKER], session))


BASELINE_RUNNING_CONFIG = """\
router bgp 65100
 neighbor 10.0.0.57 remote-as 64600
 neighbor 10.0.0.57 description ARISTA01T1
 address-family ipv4 unicast
  neighbor 10.0.0.57 activate
 exit-address-family
exit
!
ip prefix-list PL_LoopbackV4 seq 5 permit 10.1.0.32/32
ip prefix-list PL_Big seq 10 deny 0.0.0.0/0 le 17
!
bgp community-list standard allow_list_default_community seq 5 permit no-export
!
route-map FROM_BGP_PEER_V4 permit 10
 on-match next
 set tag 100
 set local-preference 200
exit
!
route-map TO_BGP_PEER_V4 permit 100
exit
"""


class RunningConfigDut(object):
    def __init__(self, running_config):
        self.running_config = running_config

    def shell(self, cmd, module_ignore_errors=False):
        return {"rc": 0, "stdout": self.running_config}


def _dropped_after(running_config, image_gated_clauses=()):
    baseline = fcm._parse_fingerprint(BASELINE_RUNNING_CONFIG)
    return fcm._dropped_config_objects(RunningConfigDut(running_config), "frr_mgmt_framework",
                                       baseline, image_gated_clauses=image_gated_clauses)


# dropped = hard failures; gaps = known/accepted losses that are only reported.
@pytest.mark.parametrize("old,new,gated,dropped,gaps", [
    ("", "", (), {}, set()),
    (" set local-preference 200\n", "", (),
     {"route_maps content": ["FROM_BGP_PEER_V4: permit 10 | set local-preference 200"]}, set()),
    (" set tag 100\n", "", (), {}, {"route_maps FROM_BGP_PEER_V4: permit 10 | set tag 100"}),
    (" on-match next\n", "", ("on-match ",), {}, {"route_maps FROM_BGP_PEER_V4: permit 10 | on-match next"}),
    (" on-match next\n", "", (), {"route_maps content": ["FROM_BGP_PEER_V4: permit 10 | on-match next"]}, set()),
    ("seq 5 permit 10.1.0.32", "seq 50 permit 10.1.0.32", (), {}, set()),
    ("deny 0.0.0.0/0 le 17", "deny 0.0.0.0/0 le 24", (), {"prefix_lists content": ["PL_Big: ip deny 0.0.0.0/0 le 17"]},
     set()),
    ("permit no-export", "permit no-advertise", (), {"community_lists content": [
        "allow_list_default_community: bgp community-list standard allow_list_default_community permit no-export"]},
     set()),
    ("  neighbor 10.0.0.57 activate\n", "", (), {}, {"neighbors 10.0.0.57: ipv4 unicast | activate"}),
], ids=["identical", "route-map-clause-lost", "route-map-frrcfgd-gap", "28543-gated-clause-on-old-image",
        "28543-gated-clause-on-new-image", "prefix-list-renumbered", "prefix-list-entry-changed",
        "community-list-entry-lost", "neighbor-line-lost"])
def test_dropped_config_objects(old, new, gated, dropped, gaps):
    running = BASELINE_RUNNING_CONFIG.replace(old, new)
    assert _dropped_after(running, image_gated_clauses=gated) == (dropped, gaps)


def test_route_map_body_is_tracked_per_stanza():
    content = fcm._parse_fingerprint(BASELINE_RUNNING_CONFIG)["content"]
    assert content[("route_maps", "FROM_BGP_PEER_V4")] == {
        "permit 10", "permit 10 | on-match next", "permit 10 | set tag 100",
        "permit 10 | set local-preference 200"}
    assert content[("route_maps", "TO_BGP_PEER_V4")] == {"permit 100"}


def test_accepted_gaps_appear_in_the_terminal_summary(monkeypatch):
    monkeypatch.setattr(fcm, "_CONFIG_GAPS", {"frr_mgmt_framework: route_maps X: permit 10 | set tag 1"})
    lines = []

    class Reporter(object):
        def section(self, title):
            lines.append(title)

        def line(self, text):
            lines.append(text)

    fcm.pytest_terminal_summary(Reporter())
    assert lines[1] == "frr_mgmt_framework: route_maps X: permit 10 | set tag 1"
