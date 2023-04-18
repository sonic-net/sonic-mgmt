import pytest

from tests.common.helpers.assertions import pytest_require as py_require
from tests.common.fixtures.ptfhost_utils import change_mac_addresses        # noqa F401
from tests.common.fixtures.ptfhost_utils import run_garp_service            # noqa F401
from tests.common.utilities import get_host_visible_vars


def pytest_configure(config):

    config.addinivalue_line(
        "markers", "enable_active_active: mark test to run with 'active_active' ports"
    )

    config.addinivalue_line(
        "markers", "skip_active_standby: mark test to skip running with 'active_standby' ports"
    )


@pytest.fixture(scope="module", autouse=True)
def common_setup_teardown(rand_selected_dut, request, tbinfo, vmhost):
    # Skip dualtor test cases on unsupported platform
    supported_platforms = ['broadcom_td3_hwskus', 'broadcom_th2_hwskus', 'cisco_hwskus']
    hostvars = get_host_visible_vars(rand_selected_dut.host.options['inventory'], rand_selected_dut.hostname)
    hwsku = rand_selected_dut.facts['hwsku']
    skip = True
    for platform in supported_platforms:
        supported_skus = hostvars.get(platform, [])
        if hwsku in supported_skus:
            skip = False
            break
    py_require(not skip, "Skip on unsupported platform")

    if 'dualtor' in tbinfo['topo']['name']:
        request.getfixturevalue('run_garp_service')
