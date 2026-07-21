"""Shared fixtures for the PMON daemon tests."""
import time

import pytest


def _get_daemon_duthost(request, duthosts):
    """Resolve the DUT host for a daemon test module, honoring its `daemon_dut_hostname_fixture` override."""
    hostname_fixture = getattr(request.module, "daemon_dut_hostname_fixture", "rand_one_dut_hostname")
    return duthosts[request.getfixturevalue(hostname_fixture)]


@pytest.fixture(scope="module")
def disable_pmon_container_autorestart(request, duthosts, disable_container_autorestart, enable_container_autorestart):
    """Disable pmon container autorestart so a killed daemon respawns in place instead of restarting the container."""
    duthost = _get_daemon_duthost(request, duthosts)
    daemon_name = request.module.daemon_name
    disable_container_autorestart(duthost, testcase=daemon_name, feature_list=["pmon"])
    yield
    enable_container_autorestart(duthost, testcase=daemon_name, feature_list=["pmon"])


@pytest.fixture
def check_daemon_status(request, duthosts, disable_pmon_container_autorestart):
    """Ensure the pmon daemon under test is running before the test starts."""
    duthost = _get_daemon_duthost(request, duthosts)
    daemon_name = request.module.daemon_name
    daemon_status, _ = duthost.get_pmon_daemon_status(daemon_name)
    if daemon_status != "RUNNING":
        duthost.start_pmon_daemon(daemon_name)
        time.sleep(10)
