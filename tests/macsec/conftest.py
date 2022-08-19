import pytest


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "macsec_required: mark test as MACsec required to run")


def pytest_collection_modifyitems(config, items):
    if not config.getoption("enable_macsec"):
        skip_macsec = pytest.mark.skip(reason="macsec test cases")
        for item in items:
            if "macsec_required" in item.keywords:
                item.add_marker(skip_macsec)


@pytest.fixture(scope="module")
def profile_name(macsec_profile):
    return macsec_profile['name']


@pytest.fixture(scope="module")
def default_priority(macsec_profile):
    return macsec_profile['priority']


@pytest.fixture(scope="module")
def cipher_suite(macsec_profile):
    return macsec_profile['cipher_suite']


@pytest.fixture(scope="module")
def primary_ckn(macsec_profile):
    return macsec_profile['primary_ckn']


@pytest.fixture(scope="module")
def primary_cak(macsec_profile):
    return macsec_profile['primary_cak']


@pytest.fixture(scope="module")
def policy(macsec_profile):
    return macsec_profile['policy']


@pytest.fixture(scope="module")
def send_sci(macsec_profile):
    return macsec_profile['send_sci']


@pytest.fixture(scope="module")
def rekey_period(macsec_profile):
    return macsec_profile['rekey_period']
