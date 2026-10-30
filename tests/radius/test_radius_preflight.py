"""
RADIUS Preflight Tests — TC_RH01, TC_RH02, TC_RH03, TC_RH07, TC_RH08
Verifies RADIUS server connectivity and basic auth before running full test suite.
"""
import logging
import pytest

from tests.radius.utils import (
    start_radius_server,
    stop_radius_server,
    configure_dut_radius,
    restore_dut_aaa_config,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology("t0", "t1", "any"),
    pytest.mark.skip_check_dut_health,
]

# ---------------------------------------------------------------------------
# Module fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def radius_preflight_setup(duthosts, enum_rand_one_per_hwsku_hostname, ptfhost, radius_creds):
    """Start freeradius on PTF and configure DUT for preflight tests."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    ptf_ip = ptfhost.mgmt_ip

    users = [
        {"username": radius_creds["radius_rw_user"], "password": radius_creds["radius_rw_user_passwd"], "priv_lvl": 15},
        {"username": radius_creds["radius_ro_user"],  "password": radius_creds["radius_ro_user_passwd"],  "priv_lvl": 1},
    ]
    clients = [{"name": "sonic-dut", "ipaddr": duthost.mgmt_ip}]

    start_radius_server(ptfhost, users, clients, secret=radius_creds["passkey"])
    configure_dut_radius(duthost, ptf_ip, passkey=radius_creds["passkey"])

    yield

    restore_dut_aaa_config(duthost, ptf_ip)
    stop_radius_server(ptfhost)


# ---------------------------------------------------------------------------
# TC_RH01 — freeradius process is running on PTF
# ---------------------------------------------------------------------------
def test_rh01_freeradius_process_running(ptfhost):
    """TC_RH01: Verify freeradius daemon is running on PTF."""
    result = ptfhost.shell("pgrep freeradius")
    assert result["rc"] == 0, "freeradius is NOT running on PTF"
    logger.info("TC_RH01 PASS: freeradius PID=%s", result["stdout"].strip())


# ---------------------------------------------------------------------------
# TC_RH02 — freeradius is listening on UDP 1812
# ---------------------------------------------------------------------------
def test_rh02_freeradius_listening_udp_1812(ptfhost):
    """TC_RH02: Verify freeradius is listening on UDP port 1812."""
    result = ptfhost.shell("ss -ulnp | grep 1812")
    assert result["rc"] == 0 and "1812" in result["stdout"], \
        "freeradius is NOT listening on UDP 1812"
    logger.info("TC_RH02 PASS: port 1812 is open")


# ---------------------------------------------------------------------------
# TC_RH03 — radtest RW user returns Access-Accept
# ---------------------------------------------------------------------------
def test_rh03_radtest_rw_user_accept(ptfhost, radius_creds):
    """TC_RH03: radtest with valid RW user credentials returns Access-Accept."""
    cmd = "radtest {} {} 127.0.0.1 0 {}".format(
        radius_creds["radius_rw_user"],
        radius_creds["radius_rw_user_passwd"],
        radius_creds["passkey"],
    )
    result = ptfhost.shell(cmd)
    assert "Access-Accept" in result["stdout"], \
        "Expected Access-Accept for RW user, got:\n{}".format(result["stdout"])
    logger.info("TC_RH03 PASS: Access-Accept for %s", radius_creds["radius_rw_user"])


# ---------------------------------------------------------------------------
# TC_RH07 — DUT has RADIUS server in ConfigDB
# ---------------------------------------------------------------------------
def test_rh07_dut_radius_config_present(duthosts, enum_rand_one_per_hwsku_hostname, ptfhost):
    """TC_RH07: Verify RADIUS server entry is present in DUT ConfigDB."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    result = duthost.shell("show radius")
    assert ptfhost.mgmt_ip in result["stdout"], \
        "PTF IP {} not found in 'show radius' output:\n{}".format(
            ptfhost.mgmt_ip, result["stdout"])
    logger.info("TC_RH07 PASS: RADIUS server %s found in DUT config", ptfhost.mgmt_ip)


# ---------------------------------------------------------------------------
# TC_RH08 — DUT AAA authentication is set to radius
# ---------------------------------------------------------------------------
def test_rh08_dut_aaa_set_to_radius(duthosts, enum_rand_one_per_hwsku_hostname, radius_preflight_setup):
    """TC_RH08: Verify DUT AAA authentication includes 'radius'."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    result = duthost.shell("show aaa")
    assert "radius" in result["stdout"].lower(), \
        "AAA not set to radius:\n{}".format(result["stdout"])
    logger.info("TC_RH08 PASS: AAA includes radius")
