import pytest

from tests.common.utilities import skip_release

@pytest.fixture(scope="module", autouse=True)
def check_image_version(duthost):
    """Skips this test if the SONiC image installed on DUT is older than 202106

    Args:
        duthost: Hostname of DUT.

    Returns:
        None.
    """
    skip_release(duthost, ["201811", "201911", "202012"])

