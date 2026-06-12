"""
conftest.py for tests/AAA/radius — module-scoped fixtures for the RADIUS test suite.
"""
import logging
import pytest

from tests.common.fixtures.radius import radius_creds                          # noqa: F401
from tests.aaa.radius.utils import (
    start_radius_server,
    stop_radius_server,
    configure_dut_radius,
    restore_dut_aaa_config,
    block_radius_server,
    unblock_radius_server,
    ssh_connect_remote_retry,
    close_ssh,
    delete_jit_user,
    _save_local_aaa,
    _radius_del,
)

logger = logging.getLogger(__name__)   


@pytest.fixture(scope="module")
def radius_server_setup(duthosts, enum_rand_one_per_hwsku_hostname, ptfhost, radius_creds):
    """
    Start freeradius on PTF with test users and configure DUT to use it.
    Saves local AAA config first and after — prevents DUT lockout.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    ptf_ip = ptfhost.mgmt_ip

    # Pre-cleanup: reset DUT to clean state before setup
    _save_local_aaa(duthost)
    _radius_del(duthost, ptf_ip)
    delete_jit_user(duthost, radius_creds["radius_rw_user"])
    delete_jit_user(duthost, radius_creds["radius_ro_user"])

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
    configure_dut_radius(duthost, ptf_ip, passkey=radius_creds["passkey"])

    yield {"duthost": duthost, "ptf_ip": ptf_ip}

    restore_dut_aaa_config(duthost, ptf_ip)
    delete_jit_user(duthost, radius_creds["radius_rw_user"])
    delete_jit_user(duthost, radius_creds["radius_ro_user"])
    stop_radius_server(ptfhost)


@pytest.fixture(scope="function")
def rw_user_ssh(radius_server_setup, radius_creds):
    """Open an SSH session to DUT as the RW RADIUS user."""
    duthost = radius_server_setup["duthost"]
    client = ssh_connect_remote_retry(
        duthost.mgmt_ip,
        radius_creds["radius_rw_user"],
        radius_creds["radius_rw_user_passwd"])
    yield client
    close_ssh(client)


@pytest.fixture(scope="function")
def ro_user_ssh(radius_server_setup, radius_creds):
    """Open an SSH session to DUT as the RO RADIUS user."""
    duthost = radius_server_setup["duthost"]
    client = ssh_connect_remote_retry(
        duthost.mgmt_ip,
        radius_creds["radius_ro_user"],
        radius_creds["radius_ro_user_passwd"])
    yield client
    close_ssh(client)


@pytest.fixture(scope="function")
def radius_server_unreachable(ptfhost):
    """Block UDP 1812 on PTF to simulate server unreachable. Removes block on teardown."""
    block_radius_server(ptfhost)
    yield
    unblock_radius_server(ptfhost)


@pytest.fixture(scope="module")
def combined_aaa_setup(duthosts, enum_rand_one_per_hwsku_hostname, ptfhost, radius_creds):
    """Setup for combined AAA protocol switching tests."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    ptf_ip = ptfhost.mgmt_ip

    _save_local_aaa(duthost)
    _radius_del(duthost, ptf_ip)
    delete_jit_user(duthost, radius_creds["radius_rw_user"])

    users = [
        {"username": radius_creds["radius_rw_user"],
         "password": radius_creds["radius_rw_user_passwd"],
         "priv_lvl": 15},
    ]
    clients = [{"name": "sonic-dut", "ipaddr": duthost.mgmt_ip}]
    start_radius_server(ptfhost, users, clients, secret=radius_creds["passkey"])
    configure_dut_radius(duthost, ptf_ip, passkey=radius_creds["passkey"])
    yield {"duthost": duthost, "ptf_ip": ptf_ip}
    restore_dut_aaa_config(duthost, ptf_ip)
    delete_jit_user(duthost, radius_creds["radius_rw_user"])
    stop_radius_server(ptfhost)
