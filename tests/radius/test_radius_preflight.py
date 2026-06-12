"""
RADIUS Preflight Tests — TC_RH01 to TC_RH08
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
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology("any", "t1-multi-asic"),
    pytest.mark.device_type("vs"),
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
# TC_RH04 — radtest RO user returns Access-Accept
# ---------------------------------------------------------------------------
def test_rh04_radtest_ro_user_accept(ptfhost, radius_creds):
    """TC_RH04: radtest with valid RO user credentials returns Access-Accept."""
    cmd = "radtest {} {} 127.0.0.1 0 {}".format(
        radius_creds["radius_ro_user"],
        radius_creds["radius_ro_user_passwd"],
        radius_creds["passkey"],
    )
    result = ptfhost.shell(cmd)
    assert "Access-Accept" in result["stdout"], \
        "Expected Access-Accept for RO user, got:\n{}".format(result["stdout"])
    logger.info("TC_RH04 PASS: Access-Accept for %s", radius_creds["radius_ro_user"])


# ---------------------------------------------------------------------------
# TC_RH05 — wrong password returns Access-Reject
# ---------------------------------------------------------------------------
def test_rh05_radtest_wrong_password_reject(ptfhost, radius_creds):
    """TC_RH05: radtest with wrong password returns Access-Reject."""
    cmd = "radtest {} WRONGPASSWORD 127.0.0.1 0 {}".format(
        radius_creds["radius_rw_user"],
        radius_creds["passkey"],
    )
    result = ptfhost.shell(cmd, module_ignore_errors=True)
    assert "Access-Reject" in result["stdout"], \
        "Expected Access-Reject for wrong password, got:\n{}".format(result["stdout"])
    logger.info("TC_RH05 PASS: Access-Reject for wrong password")


# ---------------------------------------------------------------------------
# TC_RH06 — wrong shared secret returns no reply
# ---------------------------------------------------------------------------
def test_rh06_radtest_wrong_secret_no_reply(ptfhost, radius_creds):
    """TC_RH06: radtest with wrong shared secret gets no reply (server drops silently)."""
    cmd = "radtest {} {} 127.0.0.1 0 WRONGSECRET".format(
        radius_creds["radius_rw_user"],
        radius_creds["radius_rw_user_passwd"],
    )
    result = ptfhost.shell(cmd, module_ignore_errors=True)
    assert "Access-Accept" not in result["stdout"], \
        "Should NOT get Access-Accept with wrong secret"
    logger.info("TC_RH06 PASS: no Accept with wrong secret")


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
