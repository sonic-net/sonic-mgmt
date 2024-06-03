import pytest


def pytest_runtest_setup(item):
    from_image = item.config.getoption('base_image')
    to_image = item.config.getoption('target_image')
    if not from_image or not to_image:
        pytest.skip("base_image or target_image is empty")


@pytest.fixture(scope="module")
def upgrade_path_lists(request):
    upgrade_type = request.config.getoption('upgrade_type')
    from_image = request.config.getoption('base_image')
    to_image = request.config.getoption('target_image')
    restore_to_image = request.config.getoption('restore_to_image')
    return upgrade_type, from_image, to_image, restore_to_image
