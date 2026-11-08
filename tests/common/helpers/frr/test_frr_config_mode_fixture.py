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
