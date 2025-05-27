import pytest
from tests.common.helpers.monit import check_monit_expected_container_logging
from tests.common.utilities import wait_until
from bmp.helper import enable_bmp_feature, disable_bmp_feature

pytestmark = [
    pytest.mark.topology('any', 't0-sonic', 't1-multi-asic'),
    pytest.mark.device_type('vs')
]


def test_frr_bmp_monit_log(duthosts, enum_frontend_dut_hostname, enum_asic_index):
    duthost = duthosts[enum_frontend_dut_hostname]
    disable_bmp_feature(duthost)

    wait_until(180, 60, 0, check_monit_expected_container_logging, duthost)

    enable_bmp_feature(duthost)
