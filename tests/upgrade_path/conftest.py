import pytest


def pytest_runtest_setup(item):
    multi_hop_upgrade_path = item.config.getoption('multi_hop_upgrade_path')
    if multi_hop_upgrade_path:
        return


@pytest.fixture(scope="module")
def upgrade_path_lists(request):
    upgrade_type = request.config.getoption('upgrade_type')
    from_list = request.config.getoption('base_image_list')
    to_list = request.config.getoption('target_image_list')
    restore_to_image = request.config.getoption('restore_to_image')
    enable_cpa = request.config.getoption('enable_cpa')
    return upgrade_type, from_list, to_list, restore_to_image, enable_cpa
