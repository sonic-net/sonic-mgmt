"""
Reliable TSA / chassis_tsa_supported (CONFIG_DB) vs CHASSIS_APP_DB tsa_enabled behavior.

These tests manipulate CONFIG_DB chassis_tsa_supported explicitly.
"""
import logging

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.multi_thread_utils import SafeThreadPoolExecutor
from tests.common.utilities import wait_until
from tests.bgp.constants import TS_MAINTENANCE, TS_NORMAL
from tests.bgp.traffic_checker import get_traffic_shift_state
from tests.bgp.bgp_helpers import (
    get_chassis_app_db_tsa_enabled_raw,
    get_configdb_chassis_tsa_supported,
    get_configdb_tsa_enabled_raw,
    get_tsa_chassisdb_config,
    initial_tsa_check_before_and_after_test,
    restore_configdb_chassis_tsa_supported,
    run_supervisor_rexec_path_traffic_shift,
    set_configdb_chassis_tsa_supported,
)

pytestmark = [
    pytest.mark.topology('t2'),
]

logger = logging.getLogger(__name__)

APP_DB_SYNC_TIMEOUT_SEC = 120
APP_DB_SYNC_INTERVAL_SEC = 5
TSA_TSB_TIMEOUT_SEC = 90
TSA_TSB_INTERVAL_SEC = 5


def verify_traffic_shift_state_all_lcs(duthosts, ts_state, state_label):
    def _verify(lc):
        pytest_assert(
            wait_until(
                TSA_TSB_TIMEOUT_SEC, TSA_TSB_INTERVAL_SEC, 0,
                lambda: get_traffic_shift_state(lc, "TSC no-stats") == ts_state),
            "Linecard {} is not in {} ({})".format(lc.hostname, state_label, ts_state))

    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for lc in duthosts.frontend_nodes:
            executor.submit(_verify, lc)


def chassis_app_db_tsa_false_or_absent(raw):
    """
    Valid CHASSIS_APP_DB tsa_enabled value when chassis_tsa_supported is absent or false in CONFIG_DB:
    field may be missing / empty or explicitly false.
    """
    return raw in ('', 'false')


def restore_sup_flag_and_tsb(duthosts, enum_supervisor_dut_hostname, prior_flag, creds=None):
    suphost = duthosts[enum_supervisor_dut_hostname]
    try:
        if creds is not None:
            try:
                run_supervisor_rexec_path_traffic_shift(suphost, "TSB", creds=creds)
            except Exception as err:
                logger.warning("interactive TSB cleanup failed, trying shell TSB: %s", err)
                suphost.shell("TSB", module_ignore_errors=True)
        else:
            suphost.shell("TSB", module_ignore_errors=True)
        suphost.shell("sudo config save -y", module_ignore_errors=True)
    except Exception as err:
        logger.error("cleanup TSB failed: %s", err)

    restore_configdb_chassis_tsa_supported(suphost, prior_flag)


@pytest.mark.disable_loganalyzer
def test_chassis_tsa_supported_config_app_db_and_supervisor_tsa_tsb(
        duthosts, enum_supervisor_dut_hostname):
    """
    With chassis_tsa_supported true (APP_DB path):
      1) Baseline TSB / LCs normal.
      2) CONFIG_DB tsa_enabled false; CHASSIS_APP_DB tsa_enabled absent or explicit false.
      3) TSA: APP_DB true, CONFIG_DB tsa_enabled true, chassis_tsa_supported still true, LCs maintenance.
      4) TSB: APP_DB tsa_enabled false, CONFIG_DB tsa_enabled false, LCs normal.
      5) Set chassis_tsa_supported false; CONFIG_DB tsa_enabled false; CHASSIS_APP_DB tsa_enabled false.
      6) Restore chassis_tsa_supported to pre-test value (finally).
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    prior_flag = get_configdb_chassis_tsa_supported(suphost)

    try:
        set_configdb_chassis_tsa_supported(suphost, "true")
        initial_tsa_check_before_and_after_test(duthosts)
        verify_traffic_shift_state_all_lcs(duthosts, TS_NORMAL, "normal")

        pytest_assert(
            get_configdb_chassis_tsa_supported(suphost) == 'true',
            "chassis_tsa_supported must be true for APP_DB path in this test")
        pytest_assert(
            get_configdb_tsa_enabled_raw(suphost) == 'false',
            "Step 2: CONFIG_DB tsa_enabled must be false when idle")
        pytest_assert(
            wait_until(
                APP_DB_SYNC_TIMEOUT_SEC, APP_DB_SYNC_INTERVAL_SEC, 0,
                lambda: chassis_app_db_tsa_false_or_absent(get_chassis_app_db_tsa_enabled_raw(suphost))),
            "Step 2: CHASSIS_APP_DB tsa_enabled must be absent or false when idle")

        suphost.shell("TSA")
        pytest_assert(
            wait_until(
                TSA_TSB_TIMEOUT_SEC, TSA_TSB_INTERVAL_SEC, 0,
                lambda: get_chassis_app_db_tsa_enabled_raw(suphost) == 'true'),
            "Step 3: CHASSIS_APP_DB tsa_enabled must be true after TSA")
        pytest_assert(
            wait_until(
                TSA_TSB_TIMEOUT_SEC, TSA_TSB_INTERVAL_SEC, 0,
                lambda: get_configdb_tsa_enabled_raw(suphost) == 'true'),
            "Step 3: CONFIG_DB tsa_enabled must be true after TSA")
        pytest_assert(
            get_configdb_chassis_tsa_supported(suphost) == 'true',
            "Step 3: chassis_tsa_supported must remain true after TSA")
        verify_traffic_shift_state_all_lcs(duthosts, TS_MAINTENANCE, "maintenance")

        suphost.shell("TSB")
        pytest_assert(
            wait_until(
                TSA_TSB_TIMEOUT_SEC, TSA_TSB_INTERVAL_SEC, 0,
                lambda: chassis_app_db_tsa_false_or_absent(get_chassis_app_db_tsa_enabled_raw(suphost))),
            "Step 4: CHASSIS_APP_DB tsa_enabled must be false after TSB")
        pytest_assert(
            wait_until(
                TSA_TSB_TIMEOUT_SEC, TSA_TSB_INTERVAL_SEC, 0,
                lambda: get_configdb_tsa_enabled_raw(suphost) == 'false'),
            "Step 4: CONFIG_DB tsa_enabled must be false after TSB")
        verify_traffic_shift_state_all_lcs(duthosts, TS_NORMAL, "normal")

        set_configdb_chassis_tsa_supported(suphost, "false")
        pytest_assert(get_configdb_chassis_tsa_supported(suphost) == 'false')
        pytest_assert(
            wait_until(
                APP_DB_SYNC_TIMEOUT_SEC, APP_DB_SYNC_INTERVAL_SEC, 0,
                lambda: get_configdb_tsa_enabled_raw(suphost) == 'false'),
            "Step 5: CONFIG_DB tsa_enabled is expected to be false")
        pytest_assert(
            wait_until(
                APP_DB_SYNC_TIMEOUT_SEC, APP_DB_SYNC_INTERVAL_SEC, 0,
                lambda: chassis_app_db_tsa_false_or_absent(get_chassis_app_db_tsa_enabled_raw(suphost))),
            "Step 5: CHASSIS_APP_DB tsa_enabled must remain false with chassis_tsa_supported false")

    finally:
        restore_sup_flag_and_tsb(duthosts, enum_supervisor_dut_hostname, prior_flag)


@pytest.mark.disable_loganalyzer
def test_chassis_tsa_rexec_path_then_app_db_path(
        duthosts, enum_supervisor_dut_hostname, creds_all_duts):
    """
    Rexec traffic-shift path when `chassis_tsa_supported` is absent, then APP_DB path via `shell`.

      1) Baseline TSB / LCs normal.
      2) `TSA` via `rexec' path. Verify LCs maintenance and make sure tsa_enabled flags are 'false' and 'true'
          in CHASSIS_APP_DB and CONFIG_DB respectively.
      3) TSB` via `rexec' path. Verify LCs normal and make sure tsa_enabled flags are 'false'
         in both CHASSIS_APP_DB and CONFIG_DB.
      4) Set `chassis_tsa_supported` true (APP_DB path); wait idle CHASSIS_APP_DB false; verify LCs normal.
      5) `TSA` via 'shell'; CHASSIS_APP_DB true; verify LCs maintenance.
      6) `TSB` via `shell`; CHASSIS_APP_DB false; verify LCs normal.
      7) Restore `chassis_tsa_supported` and TSB cleanup in `finally` (`restore_sup_flag_and_tsb` with creds).
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    creds = creds_all_duts[suphost.hostname]
    prior_flag = get_configdb_chassis_tsa_supported(suphost)
    try:
        set_configdb_chassis_tsa_supported(suphost, "true")
        initial_tsa_check_before_and_after_test(duthosts)

        restore_configdb_chassis_tsa_supported(suphost, "")
        pytest_assert(
            wait_until(
                APP_DB_SYNC_TIMEOUT_SEC, APP_DB_SYNC_INTERVAL_SEC, 0,
                lambda: chassis_app_db_tsa_false_or_absent(get_chassis_app_db_tsa_enabled_raw(suphost))),
            "Step 1: CHASSIS_APP_DB tsa_enabled absent or false when chassis_tsa_supported absent")

        verify_traffic_shift_state_all_lcs(duthosts, TS_NORMAL, "normal")
        # rexec TSA: CHASSIS_APP_DB tsa_enabled stays false/absent; CONFIG_DB returns to true.
        run_supervisor_rexec_path_traffic_shift(suphost, "TSA", creds=creds)
        pytest_assert(
            wait_until(
                TSA_TSB_TIMEOUT_SEC, TSA_TSB_INTERVAL_SEC, 0,
                lambda: (
                    (
                        chassis_app_db_tsa_false_or_absent(get_chassis_app_db_tsa_enabled_raw(suphost))
                        and get_configdb_tsa_enabled_raw(suphost) == 'true'
                    )
                    or all(
                        get_traffic_shift_state(lc, "TSC no-stats") == TS_MAINTENANCE
                        for lc in duthosts.frontend_nodes))),
            "Step 2: rexec TSA: need (CHASSIS_APP_DB tsa_enabled false/absent and CONFIG_DB tsa_enabled true), "
            "or all LCs maintenance; APP_DB={} CONFIG_DB={}".format(
                get_chassis_app_db_tsa_enabled_raw(suphost),
                get_configdb_tsa_enabled_raw(suphost)))
        verify_traffic_shift_state_all_lcs(duthosts, TS_MAINTENANCE, "maintenance")
        run_supervisor_rexec_path_traffic_shift(suphost, "TSB", creds=creds)
        # rexec TSB: CHASSIS_APP_DB tsa_enabled stays false/absent; CONFIG_DB returns to false.
        pytest_assert(
            wait_until(
                TSA_TSB_TIMEOUT_SEC, TSA_TSB_INTERVAL_SEC, 0,
                lambda: (
                    (
                        chassis_app_db_tsa_false_or_absent(get_chassis_app_db_tsa_enabled_raw(suphost))
                        and get_configdb_tsa_enabled_raw(suphost) == 'false'
                    )
                    or all(
                        get_traffic_shift_state(lc, "TSC no-stats") == TS_NORMAL
                        for lc in duthosts.frontend_nodes))),
            "Step 3: rexec TSB: need (CHASSIS_APP_DB tsa_enabled false/absent and CONFIG_DB tsa_enabled false), "
            "or all LCs normal; APP_DB={} CONFIG_DB={}".format(
                get_chassis_app_db_tsa_enabled_raw(suphost),
                get_configdb_tsa_enabled_raw(suphost)))
        verify_traffic_shift_state_all_lcs(duthosts, TS_NORMAL, "normal")

        set_configdb_chassis_tsa_supported(suphost, "true")
        pytest_assert(
            wait_until(
                APP_DB_SYNC_TIMEOUT_SEC, APP_DB_SYNC_INTERVAL_SEC, 0,
                lambda: get_chassis_app_db_tsa_enabled_raw(suphost) == 'false'),
            "Step 4: Idle APP_DB tsa_enabled should be false when chassis_tsa_supported true")

        verify_traffic_shift_state_all_lcs(duthosts, TS_NORMAL, "normal")
        suphost.shell("TSA")
        pytest_assert(
            wait_until(
                TSA_TSB_TIMEOUT_SEC, TSA_TSB_INTERVAL_SEC, 0,
                lambda: get_tsa_chassisdb_config(suphost) == 'true'),
            "Step 5: CHASSIS_APP_DB tsa_enabled true after TSA")
        verify_traffic_shift_state_all_lcs(duthosts, TS_MAINTENANCE, "maintenance")

        suphost.shell("TSB")
        pytest_assert(
            wait_until(
                TSA_TSB_TIMEOUT_SEC, TSA_TSB_INTERVAL_SEC, 0,
                lambda: get_tsa_chassisdb_config(suphost) == 'false'),
            "Step 6: CHASSIS_APP_DB tsa_enabled false after TSB")
        verify_traffic_shift_state_all_lcs(duthosts, TS_NORMAL, "normal")

    finally:
        restore_sup_flag_and_tsb(duthosts, enum_supervisor_dut_hostname, prior_flag, creds)
