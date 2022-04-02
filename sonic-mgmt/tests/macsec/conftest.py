import pytest
from . import macsec_profiles


@pytest.fixture(scope="module")
def profile_name(macsec_profile):
    return macsec_profile


@pytest.fixture(scope="module")
def default_priority(macsec_profile):
    return macsec_profiles[macsec_profile]['priority']


@pytest.fixture(scope="module")
def cipher_suite(macsec_profile):
    return macsec_profiles[macsec_profile]['cipher_suite']


@pytest.fixture(scope="module")
def primary_ckn(macsec_profile):
    return macsec_profiles[macsec_profile]['primary_ckn']


@pytest.fixture(scope="module")
def primary_cak(macsec_profile):
    return macsec_profiles[macsec_profile]['primary_cak']


@pytest.fixture(scope="module")
def policy(macsec_profile):
    return macsec_profiles[macsec_profile]['policy']


@pytest.fixture(scope="module")
def send_sci(macsec_profile):
    return macsec_profiles[macsec_profile]['send_sci']
