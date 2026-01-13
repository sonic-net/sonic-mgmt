import pytest
from tests.common.helpers.dut_utils import is_container_running


@pytest.fixture(scope="module")
def verify_auditd_containers_running(duthosts, enum_rand_one_per_hwsku_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    for container in ["auditd", "auditd_watchdog"]:
        if not is_container_running(duthost, container):
            pytest.skip(f"Container {container} is not running")
