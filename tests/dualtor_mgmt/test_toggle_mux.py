import logging
import json
import pytest

from tests.common.dualtor.constants import UPPER_TOR, LOWER_TOR
from tests.common.dualtor.dual_tor_common import active_standby_ports                                   # noqa: F401
from tests.common.dualtor.mux_simulator_control import check_mux_status, validate_check_result
from tests.common.dualtor.dual_tor_utils import recover_linkmgrd_probe_interval, update_linkmgrd_probe_interval
from tests.common.utilities import wait_until


pytestmark = [
    pytest.mark.topology("dualtor")
]

logger = logging.getLogger(__name__)


@pytest.fixture(scope="module", autouse=True)
def check_topo(active_standby_ports, tbinfo):                                                           # noqa: F811
    if 'dualtor' not in tbinfo['topo']['name']:
        pytest.skip('Skip on non-dualtor testbed')

    if not active_standby_ports:
        pytest.skip("Skip as no 'active-standby' mux ports available")


@pytest.fixture
def restore_mux_auto_mode(duthosts):
    yield
    logger.info('Set all muxcable to auto mode on all ToRs')
    duthosts.shell('config muxcable mode auto all')


@pytest.fixture(scope="module")
def get_interval_v4(duthosts):
    mux_linkmgr_output = duthosts.shell('sonic-cfggen -d --var-json MUX_LINKMGR')
    mux_linkmgr = list(mux_linkmgr_output.values())[0]['stdout']
    mux_linkmgr_json = json.loads(mux_linkmgr)
    if len(mux_linkmgr) != 0 and 'LINK_PROBER' in mux_linkmgr_json:
        cur_interval_v4 = mux_linkmgr_json['LINK_PROBER']['interval_v4']
        return cur_interval_v4
    else:
        return None


@pytest.fixture(scope="module")
def reset_link_prober_interval_v4(duthosts, get_interval_v4, tbinfo):
    cur_interval_v4 = get_interval_v4
    if cur_interval_v4 is not None:
        recover_linkmgrd_probe_interval(duthosts, tbinfo)

    # NOTE: as there is no icmp_responder running, the device is stucked in consistently probing
    # the mux status. If there is a previous case that has fixture run_icmp_responder called, the
    # link prober interval is changed into 1000ms, the mux probing interval could be 384s at most.
    # So after a hardware mux change, SONiC is only able to learn the change after 384s in worst case.
    # To accelerate this, let's restarting linkmgrd to break out from the probing loop firstly and
    # change the the probing interval back to 100ms to reduce the future probing interval maximum
    # down to 38.4s.
    duthosts.shell("docker exec mux supervisorctl restart linkmgrd")

    yield

    if cur_interval_v4 is not None:
        update_linkmgrd_probe_interval(duthosts, tbinfo, cur_interval_v4)


@pytest.mark.parametrize("active_side", [UPPER_TOR, LOWER_TOR])
def test_toggle_mux_from_simulator(duthosts, active_side, toggle_all_simulator_ports,
                                   get_mux_status, reset_link_prober_interval_v4, restore_mux_auto_mode):
    logger.info('Set all muxcable to manual mode on all ToRs')
    duthosts.shell('config muxcable mode manual all')

    logger.info('Toggle mux active side from mux simulator')
    toggle_all_simulator_ports(active_side)

    check_result = wait_until(60, 5, 2, check_mux_status, duthosts, active_side)
    validate_check_result(check_result, duthosts, get_mux_status)


@pytest.mark.parametrize("active_side", [UPPER_TOR, LOWER_TOR])
def test_toggle_mux_from_cli(duthosts, active_side, get_mux_status,
                             reset_link_prober_interval_v4, restore_mux_auto_mode):
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
