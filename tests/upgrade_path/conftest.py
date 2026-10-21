import pytest

from tests.common.helpers.upgrade_helpers import xcvr_skip_list  # noqa: F401
from tests.common.fixtures.advanced_reboot import ErrorType, get_upgrade_path_result_key
from tests.common.helpers.constants import CUSTOM_MSG_PREFIX


_UPGRADE_PATH_RESULT_PREFIX = f"{CUSTOM_MSG_PREFIX}.upgrade_path_result."


def _upgrade_path_result_cache_key(item):
    return f"{CUSTOM_MSG_PREFIX}.{get_upgrade_path_result_key(item.name)}"


def _clear_stale_results(config):
    # Drop per-test classifications left in the cache by a previous pytest run in
    # the same workdir, so they are not re-emitted by this session's CustomMsg
    # collection (same cache enumeration as log_custom_msg in tests/conftest.py).
    if getattr(config, "_upgrade_path_stale_results_cleared", False):
        return
    config._upgrade_path_stale_results_cleared = True
    cache_dir = config.cache._cachedir
    for path in cache_dir.glob('**/*'):
        if path.is_file() and path.name.startswith(_UPGRADE_PATH_RESULT_PREFIX):
            config.cache.set(path.name, None)


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_setup(item):
    multi_hop_upgrade_path = item.config.getoption('multi_hop_upgrade_path')
    if not multi_hop_upgrade_path:
        from_list = item.config.getoption('base_image_list')
        to_list = item.config.getoption('target_image_list')
        if not from_list or not to_list:
            pytest.skip("base_image_list or target_image_list is empty")
    _clear_stale_results(item.config)
    # Seed UNKNOWN under this test's own key before any fixture runs so a
    # setup-phase crash still classifies. Keys are per test, so seeding and
    # clearing never touch another test's classification.
    item.config.cache.set(_upgrade_path_result_cache_key(item), {"error_type": ErrorType.UNKNOWN.value})


@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    # Clear this test's seed before yield: the repo-level makereport hook in
    # tests/conftest.py emits CustomMsg from the cache pre-yield on the last
    # test's teardown, so clearing must happen before that emission. Teardown
    # outcome is known here via call.excinfo: a test that passed or skipped in
    # setup/call but failed in teardown keeps its classification.
    if call.when == "teardown" and call.excinfo is None:
        rep_setup = getattr(item, "rep_setup", None)
        rep_call = getattr(item, "rep_call", None)
        skipped = ((rep_setup is not None and rep_setup.skipped)
                   or (rep_call is not None and rep_call.skipped))
        passed = (rep_setup is not None and rep_setup.passed
                  and rep_call is not None and rep_call.passed)
        if passed or skipped:
            item.config.cache.set(_upgrade_path_result_cache_key(item), None)
    yield


@pytest.fixture(scope="module")
def upgrade_path_lists(request):
    upgrade_type = request.config.getoption('upgrade_type')
    from_list = request.config.getoption('base_image_list')
    to_list = request.config.getoption('target_image_list')
    restore_to_image = request.config.getoption('restore_to_image')
    enable_cpa = request.config.getoption('enable_cpa')
    return upgrade_type, from_list, to_list, restore_to_image, enable_cpa
