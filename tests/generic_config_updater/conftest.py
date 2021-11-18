import pytest

from tests.common.utilities import skip_version

@pytest.fixture(autouse=True, scope="module")
def check_image_version(duthost):
    """Skips this test if the SONiC image installed on DUT is older than 202106

    Args:
        duthost: Hostname of DUT.

    Returns:
        None.
    """
    skip_version(duthost, ["201811", "201911", "202012"])

