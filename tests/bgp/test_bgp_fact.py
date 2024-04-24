import pytest

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]


def run_bgp_facts(duthosts, enum_frontend_dut_hostname, enum_asic_index):
    """compare the bgp facts between observed states and target state"""
    assert False


def test_bgp_facts(duthosts, enum_frontend_dut_hostname, enum_asic_index):
    run_bgp_facts(duthosts, enum_frontend_dut_hostname, enum_asic_index)
