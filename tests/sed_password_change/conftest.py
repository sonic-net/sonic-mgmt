import logging
import pytest

logger = logging.getLogger(__name__)


@pytest.fixture(scope='module', autouse=True)
def set_values_for_tests(duthosts, enum_rand_one_per_hwsku_hostname, localhost, vendor_sed_class):
    """
    Fixture that resets SED password to default before and after all tests in this module.

    This fixture:
    1. Resets the SED password to default at the beginning of the script run
    2. Yields to allow all tests to run
    3. Resets the SED password to default after all tests complete
    """
    logger.info("SED password reset to default before tests")
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    vendor_sed_class.verify_sed_pass_change_feature_enabled(duthost)
    vendor_sed_class.reset_sed_pass_via_cli(duthost, localhost)

    yield

    logger.info("SED password reset to default after tests")
    vendor_sed_class.reset_sed_pass_via_cli(duthost, localhost)
