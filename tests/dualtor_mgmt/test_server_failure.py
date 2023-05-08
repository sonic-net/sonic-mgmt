import logging
import pytest
import random

from tests.common.dualtor.mux_simulator_control import toggle_simulator_port_to_upper_tor, \
                                                       simulator_flap_counter, simulator_server_down    # noqa F401
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.dualtor.dual_tor_utils import show_muxcable_status                                    # noqa: F401
from tests.common.dualtor.dual_tor_common import active_standby_ports                                   # noqa: F401
from tests.common.fixtures.ptfhost_utils import change_mac_addresses, run_garp_service, \
                                                run_icmp_responder                                      # noqa: F401
from tests.common.utilities import wait_until


pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.usefixtures('run_garp_service', 'run_icmp_responder')
]


@pytest.fixture(autouse=True, scope='module')
def skip_if_non_dualtor_topo(tbinfo):
    pytest_require('dualtor' in tbinfo['topo']['name'], "Only run on dualtor testbed")


def test_server_down(duthosts, tbinfo, active_standby_ports, simulator_flap_counter,                # noqa F811
                     simulator_server_down, toggle_simulator_port_to_upper_tor, loganalyzer):       # noqa F811
    """
    Verify that mux cable is not toggled excessively.
    """

    pytest_require(active_standby_ports, "No active-standby ports are found in the dualtor topology")
    test_iface = random.choice(active_standby_ports)
    logging.info("Selected active-standby interface %s to test", test_iface)

    if loganalyzer:
        for analyzer in list(loganalyzer.values()):
            analyzer.ignore_regex.append(
                r".*ERR swss#orchagent: :- setState: State transition from active to active is not-handled"
            )

    upper_tor = duthosts[tbinfo['duts'][0]]
    lower_tor = duthosts[tbinfo['duts'][1]]

    def upper_tor_mux_state_verification(state, health):
        mux_state_upper_tor = show_muxcable_status(upper_tor)
        return (mux_state_upper_tor[test_iface]['status'] == state and
                mux_state_upper_tor[test_iface]['health'] == health)

    def lower_tor_mux_state_verfication(state, health):
        mux_state_lower_tor = show_muxcable_status(lower_tor)
        return (mux_state_lower_tor[test_iface]['status'] == state and
                mux_state_lower_tor[test_iface]['health'] == health)

    # Set upper_tor as active
    toggle_simulator_port_to_upper_tor(test_iface)
    pytest_assert(wait_until(30, 1, 0, upper_tor_mux_state_verification, 'active', 'healthy'),
                  "mux_cable status is unexpected. Should be (active, healthy). Test can't proceed. ")
    mux_flap_counter_0 = simulator_flap_counter(test_iface)
    # Server down
    simulator_server_down(test_iface)
    # Verify mux_cable state on upper_tor is active
    pytest_assert(wait_until(20, 1, 0, upper_tor_mux_state_verification, 'active', 'unhealthy'),
                  "mux_cable status is unexpected. Should be (active, unhealthy)")
    # Verify mux_cable state on lower_tor is standby
    pytest_assert(wait_until(30, 1, 0, lower_tor_mux_state_verfication, 'standby', 'unhealthy'),
                  "mux_cable status is unexpected. Should be (standby, unhealthy)")
    # Verify that mux_cable flap_counter should be no larger than 3
    # lower_tor(standby) -> active -> standby
    # upper_tor(active) -> active
    # The toggle from both tor may be overlapped and invisible
    mux_flap_counter_1 = simulator_flap_counter(test_iface)
    pytest_assert(mux_flap_counter_1 - mux_flap_counter_0 <= 3,
                  "The mux_cable flap count should be no larger than 3 ({})"
                  .format(mux_flap_counter_1 - mux_flap_counter_0))
