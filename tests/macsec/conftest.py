import pytest

from .macsec_helper import check_appl_db
from tests.common.utilities import wait_until


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "macsec_required: mark test as MACsec required to run")


def pytest_collection_modifyitems(config, items):
    if not config.getoption("enable_macsec"):
        skip_macsec = pytest.mark.skip(reason="macsec test cases")
        for item in items:
            if "macsec_required" in item.keywords:
                item.add_marker(skip_macsec)


@pytest.fixture(scope="session")
def profile_name(macsec_profile):
    return macsec_profile['name']


@pytest.fixture(scope="session")
def default_priority(macsec_profile):
    return macsec_profile['priority']


@pytest.fixture(scope="session")
def cipher_suite(macsec_profile):
    return macsec_profile['cipher_suite']


@pytest.fixture(scope="session")
def primary_ckn(macsec_profile):
    return macsec_profile['primary_ckn']


@pytest.fixture(scope="session")
def primary_cak(macsec_profile):
    return macsec_profile['primary_cak']


@pytest.fixture(scope="session")
def policy(macsec_profile):
    return macsec_profile['policy']


@pytest.fixture(scope="session")
def send_sci(macsec_profile):
    return macsec_profile['send_sci']


@pytest.fixture(scope="session")
def rekey_period(macsec_profile):
    return macsec_profile['rekey_period']


@pytest.fixture(scope="session")
def wait_mka_establish(duthost, ctrl_links, policy, cipher_suite, send_sci):
    assert wait_until(300, 6, 12, check_appl_db, duthost, ctrl_links, policy, cipher_suite, send_sci)
