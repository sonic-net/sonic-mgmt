import pytest

from tests.common.helpers.upgrade_helpers import xcvr_skip_list  # noqa: F401
from tests.common.fixtures.advanced_reboot import ErrorType
from tests.common.helpers.constants import CUSTOM_MSG_PREFIX


_UPGRADE_PATH_RESULT_KEY = f"{CUSTOM_MSG_PREFIX}.upgrade_path_result"


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_setup(item):
    # Seed UNKNOWN before any fixture runs so a setup-phase crash still classifies.
    item.config.cache.set(_UPGRADE_PATH_RESULT_KEY, {"error_type": ErrorType.UNKNOWN.value})


@pytest.hookimpl(trylast=True)
def pytest_runtest_teardown(item):
    # Clear the UNKNOWN seed on pass; leave the current classification on failure.
    rep_call = getattr(item, "rep_call", None)
    if rep_call and rep_call.passed:
        item.config.cache.set(_UPGRADE_PATH_RESULT_KEY, None)
        

def pytest_runtest_setup(item):
    from_list = item.config.getoption('base_image_list')
    to_list = item.config.getoption('target_image_list')
    multi_hop_upgrade_path = item.config.getoption('multi_hop_upgrade_path')
    if multi_hop_upgrade_path:
        return
    if not from_list or not to_list:
        pytest.skip("base_image_list or target_image_list is empty")


@pytest.fixture(scope="module")
def upgrade_path_lists(request):
    upgrade_type = request.config.getoption('upgrade_type')
    from_list = request.config.getoption('base_image_list')
    to_list = request.config.getoption('target_image_list')
    restore_to_image = request.config.getoption('restore_to_image')
    enable_cpa = request.config.getoption('enable_cpa')
    return upgrade_type, from_list, to_list, restore_to_image, enable_cpa
