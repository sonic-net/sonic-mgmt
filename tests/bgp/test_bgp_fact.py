import pytest
from tests.common.helpers.bgp import run_bgp_facts

pytestmark = [
    pytest.mark.topology('any', 't0-sonic'),
    pytest.mark.device_type('vs')
]


def test_bgp_facts(duthosts, enum_frontend_dut_hostname, enum_asic_index):
    run_bgp_facts(duthosts, enum_frontend_dut_hostname, enum_asic_index)
