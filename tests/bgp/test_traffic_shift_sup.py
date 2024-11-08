import logging
import pytest
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.multi_thread_utils import SafeThreadPoolExecutor
from tests.common import config_reload
from tests.bgp.constants import TS_NORMAL, TS_MAINTENANCE
from tests.bgp.traffic_checker import get_traffic_shift_state
from tests.bgp.bgp_helpers import force_tsb_before_and_after_test # noqa F401

pytestmark = [
    pytest.mark.topology('t2')
]

logger = logging.getLogger(__name__)

"""
This test file is specific to T2 chassis topology
It tests TSA/B functionality from supervisor
"""


@pytest.fixture(scope="module")
def check_support(duthosts, enum_supervisor_dut_hostname):
    duthost = duthosts[enum_supervisor_dut_hostname]
    rcli_path = duthost.shell("python3 -c \"import pkgutil ; print(pkgutil.find_loader('rcli'))\"")['stdout']
    if str(rcli_path) == "None":
        pytest.skip("rcli package not installed. TSA/B/C from supervisor is not supported in this image")


def config_save_all_lcs(duthosts):
    for linecard in duthosts.frontend_nodes:
        linecard.shell('sudo config save -y')


def config_reload_all_lcs(duthosts):
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for linecard in duthosts.frontend_nodes:
            executor.submit(config_reload, linecard, safe_reload=True, check_intf_up_ports=True)


def verify_traffic_shift_state_all_lcs(duthosts, ts_state, state):
    for linecard in duthosts.frontend_nodes:
        pytest_assert(ts_state == get_traffic_shift_state(linecard, "TSC no-stats"),
                      "Linecard {} is not in {} state".format(linecard, state))


def test_TSA(duthosts, enum_supervisor_dut_hostname):
    """
    Test TSA
    Verify all linecards transition to maintenance state after TSA on supervisor
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    try:
        # Make sure LCs are in normal mode before tests starts
        verify_traffic_shift_state_all_lcs(duthosts, TS_NORMAL, "normal")

        # Issue TSA on DUT
        suphost.shell("TSA")
        # Verify DUT is in maintenance state.
        verify_traffic_shift_state_all_lcs(duthosts, TS_MAINTENANCE, "maintenance")
    except Exception as e:
        # Log exception
        logger.error("Exception caught in TSB test. Error message: {}".format(e))
    finally:
        # Issue TSB on DUT to recover the chassis
        suphost.shell("TSB")


def test_TSB(duthosts, enum_supervisor_dut_hostname):
    """
    Test TSB
    Verify all linecards transition back to normal state from maintenance after TSB on supervisor
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    try:
        # Make sure LCs are in normal mode before tests starts
        verify_traffic_shift_state_all_lcs(duthosts, TS_NORMAL, "normal")

        # Issue TSA on DUT to move chassis to maintenance
        suphost.shell("TSA")
        verify_traffic_shift_state_all_lcs(duthosts, TS_MAINTENANCE, "maintenance")

        # Recover to Normal state
        suphost.shell("TSB")
        # Verify DUT is in normal state
        verify_traffic_shift_state_all_lcs(duthosts, TS_NORMAL, "normal")
    except Exception as e:
        # Log exception
        logger.error("Exception caught in TSB test. Error message: {}".format(e))


@pytest.mark.disable_loganalyzer
def test_TSA_TSB_chassis_with_config_reload(duthosts, enum_supervisor_dut_hostname):
    """
    Test TSA/TSB with config reload
    Verify all linecards remain in Maintenance state after TSA and config reload on supervisor
    Verify all linecards remain in Normal state after TSB and config reload on supervisor
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    try:
        # Make sure LCs are in normal mode before tests starts
        verify_traffic_shift_state_all_lcs(duthosts, TS_NORMAL, "normal")

        # Issue TSA on DUT to move chassis to maintenance
        suphost.shell("TSA")
        verify_traffic_shift_state_all_lcs(duthosts, TS_MAINTENANCE, "maintenance")

        # Save config and perform config reload on all LCs
        config_save_all_lcs(duthosts)
        config_reload_all_lcs(duthosts)

        # Verify DUT is still in maintenance state.
        verify_traffic_shift_state_all_lcs(duthosts, TS_MAINTENANCE, "maintenance")
    finally:
        # Recover to Normal state
        suphost.shell("TSB")
        # Verify DUT is in normal state.
        verify_traffic_shift_state_all_lcs(duthosts, TS_NORMAL, "normal")

        # Save config and perform config reload on all LCs
        config_save_all_lcs(duthosts)
        config_reload_all_lcs(duthosts)

        # Verify DUT is in normal state.
        verify_traffic_shift_state_all_lcs(duthosts, TS_NORMAL, "normal")
