import pytest

from tests.common.helpers.upgrade_helpers import xcvr_skip_list  # noqa: F401
from tests.common.fixtures.advanced_reboot import ErrorType
from tests.common.helpers.constants import CUSTOM_MSG_PREFIX


_UPGRADE_PATH_RESULT_KEY = f"{CUSTOM_MSG_PREFIX}.upgrade_path_result"


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_setup(item):
    multi_hop_upgrade_path = item.config.getoption('multi_hop_upgrade_path')
    if not multi_hop_upgrade_path:
        from_list = item.config.getoption('base_image_list')
        to_list = item.config.getoption('target_image_list')
        if not from_list or not to_list:
            pytest.skip("base_image_list or target_image_list is empty")
    # Seed UNKNOWN before any fixture runs so a setup-phase crash still classifies.
    # Only seed when no classification is recorded yet, so a prior test's failure
    # classification is not overwritten before it is emitted as CustomMsg.
    if item.config.cache.get(_UPGRADE_PATH_RESULT_KEY, None) is None:
        item.config.cache.set(_UPGRADE_PATH_RESULT_KEY, {"error_type": ErrorType.UNKNOWN.value})


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    rep = outcome.get_result()
    # Clear the UNKNOWN seed only once the teardown outcome is known: a test that
    # passed setup/call but failed in teardown must keep its classification.
    # Skipped tests must not leave a spurious UNKNOWN behind either.
    if rep.when == "teardown":
        rep_setup = getattr(item, "rep_setup", None)
        rep_call = getattr(item, "rep_call", None)
        skipped = ((rep_setup is not None and rep_setup.skipped)
                   or (rep_call is not None and rep_call.skipped))
        passed = (rep.passed
                  and rep_setup is not None and rep_setup.passed
                  and rep_call is not None and rep_call.passed)
        if passed or skipped:
            item.config.cache.set(_UPGRADE_PATH_RESULT_KEY, None)


@pytest.fixture(scope="module")
def upgrade_path_lists(request):
    upgrade_type = request.config.getoption('upgrade_type')
    from_list = request.config.getoption('base_image_list')
    to_list = request.config.getoption('target_image_list')
    restore_to_image = request.config.getoption('restore_to_image')
    enable_cpa = request.config.getoption('enable_cpa')
    return upgrade_type, from_list, to_list, restore_to_image, enable_cpa
