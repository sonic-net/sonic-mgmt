import logging
import json
import pytest

from tests.common.dualtor.constants import UPPER_TOR, LOWER_TOR
from tests.common.dualtor.mux_simulator_control import check_mux_status, validate_check_result
from tests.common.dualtor.dual_tor_utils import update_linkmgrd_probe_interval
from tests.common.utilities import wait_until


pytestmark = [
    pytest.mark.topology("t0")
]

logger = logging.getLogger(__name__)

DEFAUL_INTERVAL_V4 = 100


@pytest.fixture(scope="module", autouse=True)
def check_topo(tbinfo):
    if 'dualtor' not in tbinfo['topo']['name']:
        pytest.skip('Skip on non-dualtor testbed')


@pytest.fixture
def restore_mux_auto_mode(duthosts):
    yield
    logger.info('Set all muxcable to auto mode on all ToRs')
    duthosts.shell('config muxcable mode auto all')


@pytest.fixture(scope="module")
def get_interval_v4(duthosts):
    mux_linkmgr_output = duthosts.shell('sonic-cfggen -d --var-json MUX_LINKMGR')
    mux_linkmgr = list(mux_linkmgr_output.values())[0]['stdout']
    if len(mux_linkmgr) != 0:
        cur_interval_v4 = json.loads(mux_linkmgr)['LINK_PROBER']['interval_v4']
        return cur_interval_v4
    else:
        return None


@pytest.mark.parametrize("active_side", [UPPER_TOR, LOWER_TOR])
def test_toggle_mux_from_simulator(duthosts, tbinfo, active_side, toggle_all_simulator_ports,
                                   get_mux_status, get_interval_v4, restore_mux_auto_mode):
    logger.info('Set all muxcable to manual mode on all ToRs')
    duthosts.shell('config muxcable mode manual all')

    cur_interval_v4 = get_interval_v4
    if cur_interval_v4 is not None:
        update_linkmgrd_probe_interval(duthosts, tbinfo, DEFAUL_INTERVAL_V4)

    logger.info('Toggle mux active side from mux simulator')
    toggle_all_simulator_ports(active_side)

    check_result = wait_until(60, 5, 2, check_mux_status, duthosts, active_side)

    if cur_interval_v4 is not None:
        update_linkmgrd_probe_interval(duthosts, tbinfo, cur_interval_v4)

    validate_check_result(check_result, duthosts, get_mux_status)


@pytest.mark.parametrize("active_side", [UPPER_TOR, LOWER_TOR])
def test_toggle_mux_from_cli(duthosts, tbinfo, active_side, get_mux_status, get_interval_v4, restore_mux_auto_mode):
    logger.info('Reset muxcable mode to auto for all ports on all DUTs')
    duthosts.shell('config muxcable mode auto all')

    cur_interval_v4 = get_interval_v4
    if cur_interval_v4 is not None:
        update_linkmgrd_probe_interval(duthosts, tbinfo, DEFAUL_INTERVAL_V4)

    # Use cli to toggle muxcable active side
    if active_side == UPPER_TOR:
        mux_active_dut = duthosts[0]
    else:
        mux_active_dut = duthosts[1]
    mux_active_dut.shell('config muxcable mode active all')

    check_result = wait_until(60, 5, 2, check_mux_status, duthosts, active_side)

    if cur_interval_v4 is not None:
        update_linkmgrd_probe_interval(duthosts, tbinfo, cur_interval_v4)

    validate_check_result(check_result, duthosts, get_mux_status)
