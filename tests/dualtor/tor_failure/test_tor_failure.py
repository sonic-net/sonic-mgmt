import pytest
from tests.common.dualtor.tor_failure_utils import tor_blackhole_traffic, reboot_tor
from tests.common.dualtor.dual_tor_utils import upper_tor_host, lower_tor_host
from tests.common.dualtor.mux_simulator_control import get_active_torhost
from tests.common.dualtor.mux_simulator_control import mux_server_url
from tests.common.helpers.assertions import pytest_assert
import logging

logger = logging.getLogger(__name__)

def test_active_tor_failure_upstream(tor_blackhole_traffic, get_active_torhost):
    active_host_before = get_active_torhost()
    logger.info("Active ToR before traffic blackhole {}".format(active_host_before.hostname))

    # Blackhole all the traffic on active tor on ASIC
    tor_blackhole_traffic(active_host_before, asic=True)
    # TODO - add other checks and IO verification here

    active_host_after = get_active_torhost()
    logger.info("Active ToR after traffic blackhole {}".format(active_host_after.hostname))

    pytest_assert(active_host_before != active_host_after, "ToR switchover failed")


def test_active_tor_failure_downstream_active():
    # Out of scope, method included for completeness
    pass


def test_active_tor_failure_downstream_standby():
    pass


def test_standby_tor_failure_upstream():
    pass


def test_standby_tor_failure_downstream_active():
    pass


def test_standby_tor_failure_downstream_standby():
    # Out of scope, method included for completeness
    pass

def test_active_tor_reboot_upstream(reboot_tor, get_active_torhost):
    active_host_before = get_active_torhost()
    logger.info("Active ToR before performing reboot {}".format(active_host_before.hostname))

    # perform reboot on the active tor
    reboot_tor(active_host_before)
    # TODO - add other checks and IO verification here

    active_host_after = get_active_torhost()
    logger.info("Active ToR after performing reboot {}".format(active_host_after.hostname))

    pytest_assert(active_host_before != active_host_after, "ToR switchover failed")



def test_active_tor_reboot_downstream_active():
    # Out of scope, method included for completeness
    pass


def test_active_tor_reboot_downstream_standby():
    pass


def test_standby_tor_reboot_upstream():
    pass


def test_standby_tor_reboot_downstream_active():
    pass


def test_standby_tor_reboot_downstream_standby():
    # Out of scope, method included for completeness
    pass
