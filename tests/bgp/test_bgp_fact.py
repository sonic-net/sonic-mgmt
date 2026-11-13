import pytest
from tests.common.helpers.bgp import run_bgp_facts

pytestmark = [
    pytest.mark.frr_generic,
    pytest.mark.topology('any', 't0-sonic', 't1-multi-asic'),
    pytest.mark.device_type('vs')
]


def test_bgp_facts(frr_config_mode, duthosts, enum_frontend_dut_hostname, enum_asic_index):
    duthost = duthosts[enum_frontend_dut_hostname]
    run_bgp_facts(duthost, enum_asic_index)
