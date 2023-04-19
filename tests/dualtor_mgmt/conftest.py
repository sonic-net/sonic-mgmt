import pytest

from tests.common.helpers.assertions import pytest_require as py_require
from tests.common.fixtures.ptfhost_utils import change_mac_addresses        # noqa F401
from tests.common.fixtures.ptfhost_utils import run_garp_service            # noqa F401


def pytest_configure(config):

    config.addinivalue_line(
        "markers", "enable_active_active: mark test to run with 'active_active' ports"
    )

    config.addinivalue_line(
        "markers", "skip_active_standby: mark test to skip running with 'active_standby' ports"
    )


@pytest.fixture(scope="module", autouse=True)
def common_setup_teardown(request, tbinfo):
    # Skip dualtor-mgmt tests on non-dualtor testbed
    py_require("dualtor" in tbinfo['topo']['name'], "Skip on non-dualtor testbed")

    if 'dualtor' in tbinfo['topo']['name']:
        request.getfixturevalue('run_garp_service')
