import pytest
import time
from tests.common.dualtor.mux_simulator_control import toggle_simulator_port_to_upper_tor, simulator_flap_counter, simulator_server_down
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.dualtor.dual_tor_utils import show_muxcable_status, rand_selected_interface
from tests.common.fixtures.ptfhost_utils import change_mac_addresses, run_garp_service, run_icmp_responder

pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.usefixtures('run_garp_service', 'run_icmp_responder')
]

@pytest.fixture(autouse=True, scope='module')
def skip_if_non_dualtor_topo(tbinfo):
    pytest_require('dualtor' in tbinfo['topo']['name'], "Only run on dualtor testbed")

def test_server_down(duthosts, tbinfo, rand_selected_interface, simulator_flap_counter, simulator_server_down, toggle_simulator_port_to_upper_tor, loganalyzer):
    """
    Verify that mux cable is not toggled excessively.
    """

    for analyzer in list(loganalyzer.values()):
        analyzer.ignore_regex.append(r".*ERR swss#orchagent: :- setState: State transition from active to active is not-handled")
        
    upper_tor = duthosts[tbinfo['duts'][0]]
    lower_tor = duthosts[tbinfo['duts'][1]]
    PAUSE_TIME = 5

    itfs, _ = rand_selected_interface
    # Set upper_tor as active
    toggle_simulator_port_to_upper_tor(itfs)
    time.sleep(PAUSE_TIME)
    mux_flap_counter_0 = simulator_flap_counter(itfs)
    # Server down
    simulator_server_down(itfs)
    time.sleep(PAUSE_TIME)
    # Verify mux_cable state on upper_tor is active
    mux_state_upper_tor = show_muxcable_status(upper_tor)
    pytest_assert(mux_state_upper_tor[itfs]['status'] == 'active' and mux_state_upper_tor[itfs]['health'] == 'unhealthy', 
                    "mux_cable status is unexpected. Should be (active, unhealthy)")
    # Verify mux_cable state on lower_tor is standby
    mux_state_lower_tor = show_muxcable_status(lower_tor)
    pytest_assert(mux_state_lower_tor[itfs]['status'] == 'standby' and mux_state_lower_tor[itfs]['health'] == 'unhealthy', 
                    "mux_cable status is unexpected. Should be (standby, unhealthy)")
    # Verify that mux_cable flap_counter should be no larger than 3
    # lower_tor(standby) -> active -> standby
    # upper_tor(active) -> active
    # The toggle from both tor may be overlapped and invisible 
    mux_flap_counter_1 = simulator_flap_counter(itfs)
    pytest_assert(mux_flap_counter_1 - mux_flap_counter_0 <= 3, 
                    "The mux_cable flap count should be no larger than 3 ({})".format(mux_flap_counter_1 - mux_flap_counter_0)) 

