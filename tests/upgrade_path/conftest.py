import pytest


# upgrade_path pytest arguments
def pytest_addoption(parser):
    options_group = parser.getgroup("Upgrade_path test suite options")

    options_group.addoption(
        "--upgrade_type",
        default="warm",
        help="Specify the type (warm/fast/cold/soft) of upgrade that is needed from source to target image",
    )

    options_group.addoption(
        "--base_image_list",
        default="",
        help="Specify the base image(s) for upgrade (comma seperated list is allowed)",
    )

    options_group.addoption(
        "--target_image_list",
        default="",
        help="Specify the target image(s) for upgrade (comma seperated list is allowed)",
    )

    options_group.addoption(
        "--restore_to_image",
        default="",
        help="Specify the target image to restore to, or stay in target image if empty",
    )


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
