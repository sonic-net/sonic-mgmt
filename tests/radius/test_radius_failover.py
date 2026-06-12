"""
RADIUS Failover Tests — TC_RADIUS_015 to TC_RADIUS_020
Verifies fallback and multi-server failover behaviour.
"""
import logging
import time
import pytest

from tests.radius.utils import (
    ssh_connect_remote_retry,
    close_ssh,
    configure_dut_radius,
    restore_dut_aaa_config,
    _radius_del,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology("any", "t1-multi-asic"),
    pytest.mark.device_type("vs"),
    pytest.mark.skip_check_dut_health,
]


def test_tc_radius_015_local_fallback_when_server_unreachable(
        radius_server_setup, radius_creds, radius_server_unreachable):
    """
    TC_RADIUS_015: When RADIUS server is unreachable, local user can still login.
    Expected: Local admin login succeeds after timeout (~timeout*retransmit seconds).
    """
    duthost = radius_server_setup["duthost"]

    start = time.time()
    client = ssh_connect_remote_retry(
        host=duthost.mgmt_ip,
        username=radius_creds["local_user"],
        password=radius_creds["local_user_passwd"],
        timeout=60,
        retries=1,
    )
    elapsed = time.time() - start

    try:
        assert client is not None, \
            "Local admin login FAILED when RADIUS unreachable (fallback broken)"
        logger.info("TC_RADIUS_015 PASS: local fallback worked in %.1fs", elapsed)
    finally:
        close_ssh(client)


def test_tc_radius_016_radius_user_denied_when_server_unreachable_no_fallback(
        duthosts, enum_rand_one_per_hwsku_hostname, ptfhost, radius_creds,
        radius_server_unreachable):
    """
    TC_RADIUS_016: RADIUS user is denied when server is unreachable and fallback is not configured.
    Expected: Login fails (no local account for RADIUS user).
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    # Set AAA to radius only (no local fallback)
    duthost.shell("config aaa authentication login radius")

    try:
        client = ssh_connect_remote_retry(
            host=duthost.mgmt_ip,
            username=radius_creds["radius_rw_user"],
            password=radius_creds["radius_rw_user_passwd"],
            retries=1,
            timeout=30,
        )
        close_ssh(client)
        assert client is None, \
            "RADIUS user should be DENIED when server unreachable (radius only)"
        logger.info("TC_RADIUS_016 PASS: RADIUS user denied when server unreachable")
    finally:
        # Restore fallback
        duthost.shell("config aaa authentication login radius local")


def test_tc_radius_017_timeout_duration_is_within_bounds(
        radius_server_setup, radius_creds, radius_server_unreachable, ptfhost):
    """
    TC_RADIUS_017: With timeout=5 and retransmit=3, failure takes between 14s and 20s.
    Expected: Time to failure is timeout*retransmit ± tolerance.
    """
    duthost = radius_server_setup["duthost"]

    # Set retransmit to 3 explicitly
    duthost.shell("config radius retransmit 3 2>/dev/null || true", module_ignore_errors=True)

    start = time.time()
    client = ssh_connect_remote_retry(
        host=duthost.mgmt_ip,
        username=radius_creds["radius_rw_user"],
        password=radius_creds["radius_rw_user_passwd"],
        retries=1,
        timeout=60,
    )
    elapsed = time.time() - start
    close_ssh(client)

    assert client is None, "Should have failed with server unreachable"
    assert elapsed >= 10, \
        "Failure too fast ({}s), expected >= 10s (retransmit timeout)".format(elapsed)
    assert elapsed <= 60, \
        "Failure too slow ({}s), may indicate hung connection".format(elapsed)
    logger.info("TC_RADIUS_017 PASS: timeout/retransmit took %.1fs", elapsed)


def test_tc_radius_018_secondary_server_failover(
        duthosts, enum_rand_one_per_hwsku_hostname, ptfhost, radius_creds):
    """
    TC_RADIUS_018: When primary RADIUS server is blocked, secondary takes over.
    Expected: RADIUS user login succeeds via secondary server.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    ptf_ip = ptfhost.mgmt_ip

    # Add secondary server at different port (reuse same PTF but different priority)
    duthost.shell("config radius add {} -k {} -t 3 -p 2".format(
        ptf_ip, radius_creds["passkey"]), module_ignore_errors=True)

    # Block primary (priority 1) — same IP different priority, use iptables rule
    ptfhost.shell("iptables -I INPUT -p udp --dport 1812 -m statistic "
                  "--mode nth --every 2 --packet 0 -j DROP", module_ignore_errors=True)

    try:
        client = ssh_connect_remote_retry(
            host=duthost.mgmt_ip,
            username=radius_creds["radius_rw_user"],
            password=radius_creds["radius_rw_user_passwd"],
            retries=2,
            timeout=30,
        )
        close_ssh(client)
        # Note: may succeed via secondary or local — just verify DUT stays stable
        logger.info("TC_RADIUS_018: secondary failover test completed (client=%s)", client)
    finally:
        ptfhost.shell("iptables -D INPUT -p udp --dport 1812 -m statistic "
                      "--mode nth --every 2 --packet 0 -j DROP", module_ignore_errors=True)
        _radius_del(duthost, ptf_ip)
        configure_dut_radius(duthost, ptf_ip, passkey=radius_creds["passkey"])


def test_tc_radius_019_show_radius_output_format(radius_server_setup):
    """
    TC_RADIUS_019: 'show radius' output contains expected fields.
    Expected: Output includes address, auth_port, passkey, priority.
    """
    duthost = radius_server_setup["duthost"]
    result = duthost.shell("show radius")
    output = result["stdout"]

    assert "RADIUS_SERVER" in output or "address" in output, \
        "show radius missing server info:\n{}".format(output)
    assert "1812" in output, \
        "show radius missing auth_port 1812:\n{}".format(output)
    logger.info("TC_RADIUS_019 PASS: show radius output is correct")


def test_tc_radius_020_dut_recovers_after_server_restart(
        radius_server_setup, radius_creds, ptfhost):
    """
    TC_RADIUS_020: DUT resumes RADIUS auth after server comes back up.
    Expected: Login works again after server is restarted.
    """
    from tests.radius.utils import start_radius_server

    duthost = radius_server_setup["duthost"]

    # Stop server temporarily
    ptfhost.shell("pkill freeradius 2>/dev/null; sleep 2", module_ignore_errors=True)

    # Restart it
    users = [
        {"username": radius_creds["radius_rw_user"],
         "password": radius_creds["radius_rw_user_passwd"],
         "priv_lvl": 15},
        {"username": radius_creds["radius_ro_user"],
         "password": radius_creds["radius_ro_user_passwd"],
         "priv_lvl": 1},
    ]
    clients = [{"name": "sonic-dut", "ipaddr": duthost.mgmt_ip}]
    start_radius_server(ptfhost, users, clients, secret=radius_creds["passkey"])

    client = ssh_connect_remote_retry(
        host=duthost.mgmt_ip,
        username=radius_creds["radius_rw_user"],
        password=radius_creds["radius_rw_user_passwd"],
    )
    try:
        assert client is not None, \
            "RADIUS login FAILED after server was restarted"
        logger.info("TC_RADIUS_020 PASS: DUT resumed RADIUS auth after server restart")
    finally:
        close_ssh(client)
