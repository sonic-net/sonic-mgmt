import pytest
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer
from bmp.helper import enable_bmp_feature, disable_bmp_feature

pytestmark = [
    pytest.mark.topology('any', 't0-sonic', 't1-multi-asic'),
    pytest.mark.device_type('vs')
]


def test_frr_bmp_monit_log(duthosts, enum_frontend_dut_hostname, enum_asic_index):
    duthost = duthosts[enum_frontend_dut_hostname]
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="frr_bmp_monit_log")
    loganalyzer.match_regex = [r".*Expected containers not running.*"]

    with loganalyzer:
        disable_bmp_feature(duthost)

    enable_bmp_feature(duthost)
