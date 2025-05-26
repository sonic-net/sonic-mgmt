import pytest
from tests.common.helpers.bgp import run_bgp_facts
from bmp.helper import enable_bmp_feature, disable_bmp_feature

pytestmark = [
    pytest.mark.topology('any', 't0-sonic', 't1-multi-asic'),
    pytest.mark.device_type('vs')
]


def test_frr_bmp_bgp_facts(duthosts, enum_frontend_dut_hostname, enum_asic_index):
    duthost = duthosts[enum_frontend_dut_hostname]
    disable_bmp_feature(duthost)
    run_bgp_facts(duthost, enum_asic_index)
    enable_bmp_feature(duthost)
