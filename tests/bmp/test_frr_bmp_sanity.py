import pytest
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.monit import check_monit_expected_container_logging
from tests.common.utilities import wait_until
from bmp.helper import enable_bmp_feature, disable_bmp_feature

pytestmark = [
    pytest.mark.topology('any', 't0-sonic', 't1-multi-asic'),
    pytest.mark.device_type('vs')
]


def test_frr_bmp_monit_log(duthosts, enum_frontend_dut_hostname, enum_asic_index, loganalyzer):
    duthost = duthosts[enum_frontend_dut_hostname]
    if loganalyzer and duthost.hostname in loganalyzer:
        loganalyzer[duthost.hostname].ignore_regex.extend([
            r".* ERR memory_checker: \[memory_checker\] Failed to get container ID of 'bmp'! Exiting \.\.\.",
            r".* ERR memory_checker: \[memory_checker\] cgroup memory usage file .* of container 'bmp'.*",
        ])

    disable_bmp_feature(duthost)

    pytest_assert(wait_until(180, 60, 0, check_monit_expected_container_logging, duthost),
                  "Monit logged unexpected container-not-running messages")

    enable_bmp_feature(duthost)
