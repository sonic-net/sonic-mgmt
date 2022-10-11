import logging

import pytest

from tests.common.dualtor.constants import UPPER_TOR, LOWER_TOR
from tests.common.dualtor.mux_simulator_control import check_mux_status, validate_check_result
from tests.common.utilities import wait_until


pytestmark = [
    pytest.mark.topology("t0")
]

logger = logging.getLogger(__name__)


@pytest.fixture(scope="module", autouse=True)
def check_topo(tbinfo):
    if 'dualtor' not in tbinfo['topo']['name']:
        pytest.skip('Skip on non-dualtor testbed')


@pytest.fixture
def restore_mux_auto_mode(duthosts):
    yield
    logger.info('Set all muxcable to auto mode on all ToRs')
    duthosts.shell('config muxcable mode auto all')


@pytest.mark.parametrize("active_side", [UPPER_TOR, LOWER_TOR])
def test_toggle_mux_from_simulator(duthosts, active_side, toggle_all_simulator_ports, get_mux_status, restore_mux_auto_mode):
    logger.info('Set all muxcable to manual mode on all ToRs')
    duthosts.shell('config muxcable mode manual all')

    logger.info('Toggle mux active side from mux simulator')
    toggle_all_simulator_ports(active_side)

    check_result = wait_until(60, 5, 2, check_mux_status, duthosts, active_side)

    validate_check_result(check_result, duthosts, get_mux_status)


@pytest.mark.parametrize("active_side", [UPPER_TOR, LOWER_TOR])
def test_toggle_mux_from_cli(duthosts, active_side, get_mux_status, restore_mux_auto_mode):

    logger.info('Reset muxcable mode to auto for all ports on all DUTs')
    duthosts.shell('config muxcable mode auto all')

    # Use cli to toggle muxcable active side
    if active_side == UPPER_TOR:
        mux_active_dut = duthosts[0]
    else:
        mux_active_dut = duthosts[1]
    mux_active_dut.shell('config muxcable mode active all')

    check_result = wait_until(60, 5, 2, check_mux_status, duthosts, active_side)

    validate_check_result(check_result, duthosts, get_mux_status)
