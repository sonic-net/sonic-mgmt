import pytest

from tests.common.macsec.macsec_helper import check_appl_db
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


@pytest.fixture(scope="module")
def profile_name(macsec_profile):
    return macsec_profile['name']


@pytest.fixture(scope="module")
def get_port_profile_name(macsec_profile, port_profiles):
    """Return a callable ``f(dut_port)`` that resolves the MACsec profile
    name for a given port.  In single-profile mode this always returns the
    same name.  Tests that disable/re-enable MACsec on a port should use
    this instead of ``profile_name``.
    """
    if port_profiles:
        def _resolve(dut_port):
            return port_profiles[dut_port]['name']
    else:
        name = macsec_profile['name']
        def _resolve(dut_port):       # noqa: E306
            return name
    return _resolve


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


@pytest.fixture(scope="module")
def wait_mka_establish(duthost, ctrl_links, port_profiles, policy,
                       cipher_suite, send_sci):
    if port_profiles:
        # If per interface, verify that each port is bound to its
        # per-interface profile in CONFIG_DB.
        from tests.common.macsec.macsec_helper import getns_prefix
        for dut_port, profile in port_profiles.items():
            cmd = "sonic-db-cli {} CONFIG_DB HGET 'PORT|{}' 'macsec'".format(
                getns_prefix(duthost, dut_port), dut_port)
            bound_profile = duthost.command(cmd)['stdout'].strip()
            assert bound_profile == profile['name'], \
                "Port {} bound to '{}', expected '{}'".format(
                    dut_port, bound_profile, profile['name'])

    # Validate APPL_DB tables — works for both single-profile and
    # per-interface mode since cipher_suite/policy/send_sci are uniform.
    assert wait_until(300, 6, 12, check_appl_db, duthost, ctrl_links,
                      policy, cipher_suite, send_sci)
