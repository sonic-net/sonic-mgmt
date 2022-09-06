import json
import logging

import pytest

from tests.common.dualtor.constants import UPPER_TOR, LOWER_TOR
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


def check_mux_status(duthosts, active_side):
    """Verify that status of muxcables are expected

    This function runs "show muxcable status --json" on both ToRs. Before call this function, active side of all
    mux cables must be toggled to one side of the ToR. Active side ToR should be indicated in argument "active_side".

    This function will ensure that on one ToR, all the mux cables are active. On the other ToR, all the mux cable
    should be standby.

    Args:
        duthosts (list): List of duthost objects
        active_side (str): Active side of all mux cables, either UPPER_TOR or LOWER_TOR

    Returns:
        bool: True if check passed. Otherwise, return False.
    """
    if active_side == UPPER_TOR:
        mux_active_dut = duthosts[0]
        mux_standby_dut = duthosts[1]
    else:
        mux_active_dut = duthosts[1]
        mux_standby_dut = duthosts[0]

    active_side_muxstatus = json.loads(mux_active_dut.shell("show muxcable status --json")['stdout'])
    standby_side_muxstatus = json.loads(mux_standby_dut.shell("show muxcable status --json")['stdout'])

    active_side_active_muxcables = [intf for intf, muxcable in active_side_muxstatus['MUX_CABLE'].items() if muxcable['STATUS'] == 'active']
    active_side_standby_muxcables = [intf for intf, muxcable in active_side_muxstatus['MUX_CABLE'].items() if muxcable['STATUS'] == 'standby']

    standby_side_active_muxcables = [intf for intf, muxcable in standby_side_muxstatus['MUX_CABLE'].items() if muxcable['STATUS'] == 'active']
    standby_side_standby_muxcables = [intf for intf, muxcable in standby_side_muxstatus['MUX_CABLE'].items() if muxcable['STATUS'] == 'standby']

    if len(active_side_active_muxcables) > 0 and \
        len(active_side_standby_muxcables) == 0 and \
        len(standby_side_active_muxcables) == 0 and \
        len(standby_side_standby_muxcables) > 0 and \
        set(active_side_active_muxcables) == set(standby_side_standby_muxcables):
        logger.info('Check mux status on DUTs passed')
        return True
    else:
        logger.info('Unexpected mux status. active_side={}'.format(active_side))
        logger.info('Active side active muxcables: {}'.format(active_side_active_muxcables))
        logger.info('Active side standby muxcables: {}'.format(active_side_standby_muxcables))
        logger.info('Standby side active muxcables: {}'.format(standby_side_active_muxcables))
        logger.info('Standby side standby muxcables: {}'.format(standby_side_standby_muxcables))
        logger.info('Check mux status on DUTs failed')
        return False


def validate_check_result(check_result, duthosts, get_mux_status):
    """If check_result is False, collect some log and fail the test.

    Args:
        check_result (bool): Check result
        duthosts (list): List of duthost objects.
    """
    if not check_result:
        duthosts.shell('show muxcable config')
        duthosts.shell('show muxcable status')
        simulator_muxstatus = get_mux_status()
        if simulator_muxstatus is not None:
            logger.info('Mux status from mux simulator: {}'.format(json.dumps(simulator_muxstatus)))
        else:
            logger.error('Failed to get mux status from mux simulator')
        pytest.fail('Toggle mux from simulator test failed')


@pytest.mark.parametrize("active_side", [UPPER_TOR, LOWER_TOR])
def test_toggle_mux_from_simulator(duthosts, active_side, toggle_all_simulator_ports, get_mux_status, restore_mux_auto_mode):
    logger.info('Set all muxcable to manual mode on all ToRs')
    duthosts.shell('config muxcable mode manual all')

    logger.info('Toggle mux active side from mux simulator')
    toggle_all_simulator_ports(active_side)

    check_result = wait_until(10, 2, 2, check_mux_status, duthosts, active_side)

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

    check_result = wait_until(10, 2, 2, check_mux_status, duthosts, active_side)

    validate_check_result(check_result, duthosts, get_mux_status)
