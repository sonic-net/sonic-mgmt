import pytest


def pytest_addoption(parser):
    parser.addoption(
        "--vendor-specific-privileged-containers",
        action="store",
        default="",
        required=False,
        help="Comma-separated list of additional containers allowed to run "
             "in privileged mode (e.g. vendor-specific containers)"
    )


@pytest.fixture(scope="module")
def vendor_specific_privileged_containers(request):
    """
    Return a list of vendor-specific container names that are allowed to run
    in privileged mode beyond the base PRIVILEGED_CONTAINERS list.

    Pass via command line:
        pytest --vendor-specific-privileged-containers "container1,container2"
    """
    opt = request.config.getoption("--vendor-specific-privileged-containers", default="")
    if opt:
        return [c.strip() for c in opt.split(",")]
    return []
