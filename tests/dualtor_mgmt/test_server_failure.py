import pytest
from tests.common.dualtor.mux_simulator_control import toggle_simulator_port_to_upper_tor, \
                                                       simulator_flap_counter, simulator_server_down    # noqa F401
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.dualtor.dual_tor_utils import show_muxcable_status, rand_selected_interface           # noqa: F401
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


def test_server_down(duthosts, tbinfo, rand_selected_interface, simulator_flap_counter,             # noqa F811
                     simulator_server_down, toggle_simulator_port_to_upper_tor, loganalyzer):       # noqa F811
    """
    Verify that mux cable is not toggled excessively.
    """

    for analyzer in list(loganalyzer.values()):
        analyzer.ignore_regex.append(r".*ERR swss#orchagent: :- setState: \
                                     State transition from active to active is not-handled")

    upper_tor = duthosts[tbinfo['duts'][0]]
    lower_tor = duthosts[tbinfo['duts'][1]]

    def upper_tor_mux_state_verification(state, health):
        mux_state_upper_tor = show_muxcable_status(upper_tor)
        return mux_state_upper_tor[itfs]['status'] == state and mux_state_upper_tor[itfs]['health'] == health

    def lower_tor_mux_state_verfication(state, health):
        mux_state_lower_tor = show_muxcable_status(lower_tor)
        return mux_state_lower_tor[itfs]['status'] == state and mux_state_lower_tor[itfs]['health'] == health

    itfs, _ = rand_selected_interface
    # Set upper_tor as active
    toggle_simulator_port_to_upper_tor(itfs)
    pytest_assert(wait_until(30, 1, 0, upper_tor_mux_state_verification, 'active', 'healthy'),
                  "mux_cable status is unexpected. Should be (active, healthy). Test can't proceed. ")
    mux_flap_counter_0 = simulator_flap_counter(itfs)
    # Server down
    simulator_server_down(itfs)
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
    mux_flap_counter_1 = simulator_flap_counter(itfs)
    pytest_assert(mux_flap_counter_1 - mux_flap_counter_0 <= 3,
                  "The mux_cable flap count should be no larger than 3 ({})"
                  .format(mux_flap_counter_1 - mux_flap_counter_0))
