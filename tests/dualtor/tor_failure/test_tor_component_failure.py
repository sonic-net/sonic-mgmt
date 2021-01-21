import pytest
from tests.common.dualtor.tor_failure_utils import shutdown_tor_bgp
from tests.common.dualtor.dual_tor_utils import upper_tor_host, lower_tor_host # lgtm[py/unused-import]
from tests.common.dualtor.mux_simulator_control import get_active_torhost
from tests.common.dualtor.mux_simulator_control import mux_server_url # lgtm[py/unused-import]
from tests.common.helpers.assertions import pytest_assert
import logging

logger = logging.getLogger(__name__)


def test_active_tor_bgp_down_upstream(shutdown_tor_bgp, get_active_torhost):
    active_host_before = get_active_torhost()
    logger.info("Active ToR before shutting down bgp sessions {}".format(active_host_before.hostname))

    # perform bgp shutdown on active TOR
    shutdown_tor_bgp(active_host_before)
    # TODO add more verification steps here

    active_host_after = get_active_torhost()
    logger.info("Active ToR after shutting down bgp sessions {}".format(active_host_after.hostname))

    pytest_assert(active_host_before != active_host_after, "ToR switchover failed")

def test_active_tor_bgp_down_downstream_active(): # Out of scope, method included for completeness
    pass

def test_active_tor_bgp_down_downstream_standby():
    pass


def test_standby_tor_bgp_down_upstream():
    pass

def test_standby_tor_bgp_down_downstream_active():
    pass

def test_standby_tor_bgp_down_downstream_standby(): # Out of scope, method included for completeness
    pass


def test_active_tor_heartbeat_loss_upstream():
    pass

def test_active_tor_heartbeat_loss_downstream_active():
    pass

def test_active_tor_heartbeat_loss_downstream_standby():
    pass


def test_standby_tor_heartbeat_loss_upstream():
    pass

def test_standby_tor_heartbeat_loss_downstream_active():
    pass

def test_standby_tor_heartbeat_loss_downstream_standby():
    pass
