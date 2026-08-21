import pytest
from tests.common.helpers.bgp import run_bgp_facts
from tests.common.fixtures.frr_config_mode import skip_if_dut_not_switched

pytestmark = [
    pytest.mark.frr_generic,
    pytest.mark.topology('any', 't0-sonic', 't1-multi-asic'),
    pytest.mark.device_type('vs')
]


def test_bgp_facts(request, frr_config_mode, duthosts, enum_frontend_dut_hostname, enum_asic_index):
    duthost = duthosts[enum_frontend_dut_hostname]
    # This enumerates every frontend DUT, while frr_config_mode switches only
    # rand_one_dut_hostname. The read side here normalises both schemas, so without this
    # guard the [frr_mgmt_framework] node would pass while operating on an unswitched DUT.
    skip_if_dut_not_switched(request, duthost)
    run_bgp_facts(duthost, enum_asic_index)
