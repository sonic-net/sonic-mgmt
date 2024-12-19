import pytest


def pytest_runtest_setup(item):
    from_list = item.config.getoption('base_image_list')
    to_list = item.config.getoption('target_image_list')
    multi_hop_upgrade_path = item.config.getoption('multi_hop_upgrade_path')
    if multi_hop_upgrade_path:
        return
    if not from_list or not to_list:
        pytest.skip("base_image_list or target_image_list is empty")
