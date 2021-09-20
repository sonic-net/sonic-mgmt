import pytest


def pytest_addoption(parser):
    parser.addoption(
        "--skip_vendor_specific_container",
        action="store",
        default="",
        required=False,
        help="skip vendor specific container list"
    )


@pytest.fixture(scope="module", autouse=True)
def skip_vendor_specific_container(request):
    """ This fixture is to get the skipping vendor container list and return the container information

    For example:
        pytest --skip_vendor_specific_container "container1,  container2" <other arguments>
        pytest --skip_vendor_specific_container container1,  container2 <other arguments>

    """
    skip_vendor_specific_container_opt = request.config.getoption("--skip_vendor_specific_container", default="")
    vendor_specific_container_list = []
    if skip_vendor_specific_container_opt:
        vendor_specific_container_list = [container.strip() for container in skip_vendor_specific_container_opt.split(",")]

    return vendor_specific_container_list
