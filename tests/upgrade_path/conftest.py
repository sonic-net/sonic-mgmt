import pytest


def pytest_addoption(parser):
    parser.addoption('--downgrade_type', action='store', default='sonic',
                     help='Argument related to downgrade method which should be used by test. Possible: sonic, onie')


@pytest.fixture(scope='session')
def downgrade_type(request):
    return request.config.getoption('downgrade_type')


def pytest_runtest_setup(item):
    from_list = item.config.getoption('base_image_list')
    to_list = item.config.getoption('target_image_list')
    if not from_list or not to_list:
        pytest.skip("base_image_list or target_image_list is empty")


@pytest.fixture(scope="module")
def upgrade_path_lists(request):
    upgrade_type = request.config.getoption('upgrade_type')
    from_list = request.config.getoption('base_image_list')
    to_list = request.config.getoption('target_image_list')
    restore_to_image = request.config.getoption('restore_to_image')
    return upgrade_type, from_list, to_list, restore_to_image
