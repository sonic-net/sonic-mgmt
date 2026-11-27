from tests.common.cisco_data import is_cisco_device


class DummyDut:
    def __init__(self, asic_type):
        self.facts = {"asic_type": asic_type}


def test_is_cisco_device_accepts_supported_asic_names():
    assert is_cisco_device(DummyDut("cisco"))
    assert is_cisco_device(DummyDut("cisco-8000"))


def test_is_cisco_device_rejects_other_asic_names():
    assert not is_cisco_device(DummyDut("broadcom"))
