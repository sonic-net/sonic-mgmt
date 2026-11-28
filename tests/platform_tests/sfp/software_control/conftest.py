import pytest

from tests.common.utilities import skip_release
from tests.platform_tests.mellanox.software_control_constants import PLATFORM_GENERATION
from tests.platform_tests.mellanox.software_control_helper import sc_supported, sc_ms_sku, check_sc_sai_attribute_value


@pytest.fixture(autouse=True, scope="module")
def check_image_version_support(duthost):
    """
    @summary: This fixture is for skip test in SONiC release
    @param: duthost: duthost fixture
    """
    skip_release(duthost, ["201911", "202012", "202205", "202305"])


@pytest.fixture(autouse=True, scope="module")
def check_platform_support(duthost):
    """
    @summary: This fixture is for skip test if case run not in specific platform
    @param: duthost: duthost fixture
    """
    if not sc_supported(duthost):
        pytest.skip("Software Control feature supported only from spectrum 3 and above")


@pytest.fixture(autouse=True, scope="module")
def check_ms_sku(duthost):
    """
    @summary: This fixture is for skip test if case run not in specific platform
    @param: duthost: duthost fixture
    """
    if not sc_ms_sku(duthost):
        pytest.skip(f"Software Control feature supported only at Microsoft SKU {PLATFORM_GENERATION}")


@pytest.fixture(autouse=True, scope="module")
def check_sai_attribute(duthost):
    """
    @summary: This fixture is for skip test if SAI_INDEPENDENT_MODULE_MODE is not enabled
    @param: duthost: duthost fixture
    """
    if not check_sc_sai_attribute_value(duthost):
        pytest.skip("Software Control feature is not enabled in sai.profile")
