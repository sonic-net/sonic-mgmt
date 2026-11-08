"""Offline unit tests for the frr_config_mode fixture's mode-selection logic (no DUT)."""
import pytest

from tests.common.fixtures import frr_config_mode as fcm

pytestmark = [
    pytest.mark.topology('any')
]


class FakeConfig(object):
    def __init__(self, **options):
        self.options = {"--frr-config-mode": "both", "--frr-generic-mode": None}
        self.options.update(options)

    def getoption(self, name):
        return self.options[name]


def test_frr_generic_defaults_to_traditional():
    assert fcm.FRR_GENERIC_DEFAULT_MODE == fcm.MODE_TRADITIONAL
    assert fcm._frr_generic_preference(FakeConfig()) == [
        fcm.MODE_TRADITIONAL, fcm.MODE_FRR_MGMT_FRAMEWORK]


def test_frr_generic_mode_option_overrides_the_default():
    config = FakeConfig(**{"--frr-generic-mode": fcm.MODE_FRR_MGMT_FRAMEWORK})
    assert fcm._frr_generic_preference(config) == [
        fcm.MODE_FRR_MGMT_FRAMEWORK, fcm.MODE_TRADITIONAL]


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
    def __init__(self, migrator, applied=fcm.MODE_TRADITIONAL):
        self.duthost = type("Dut", (), {"hostname": "dut1"})()
        self.migrator = migrator
        self.original_mode = fcm.MODE_TRADITIONAL
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
    """A reload that fails after the marker is down must still be restored at session end."""
    state = FakeState(FakeMigrator(forward_error=RuntimeError("reload failed")))
    with pytest.raises(RuntimeError):
        fcm._switch_mode(state, fcm.MODE_FRR_MGMT_FRAMEWORK)
    assert state.applied_mode == fcm.MODE_FRR_MGMT_FRAMEWORK


def test_sessionfinish_skips_cleanup_while_marker_present():
    migrator = FakeMigrator(marker=True)
    fcm.pytest_sessionfinish(FakeSession(FakeState(migrator)), 0)
    assert not migrator.cleaned


def test_sessionfinish_cleans_up_after_a_clean_run():
    migrator = FakeMigrator()
    fcm.pytest_sessionfinish(FakeSession(FakeState(migrator)), 0)
    assert migrator.cleaned
