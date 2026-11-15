'''
Persistence of the mirror session label across config reload, cold / fast reboot and swss restart.

Test plan: docs/testplan/Mirror-session-label-test-plan.md (test_label_persistence)

The sessions, the ACL rule and the checks are defined in mirror_label_scenario.py. Warm reboot is
tested separately (test_mirror_session_label_warm_reboot.py).
'''

import logging

import pytest

from tests.common.config_reload import config_reload
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.reboot import reboot
from mirror_label_helpers import (
    ACL_TABLE,
    acl_table_exists,
    apply_mirror_acl_rule,
    direct_hset_field,
    remove_mirror_acl_rules,
)
from mirror_label_scenario import (
    ACL_NUMBER,
    PORT_MIRROR_NUMBER,
    assert_state,
    create_sessions,
    initial_labels,
    session,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.disable_memory_utilization,
    pytest.mark.disable_loganalyzer,    # reloads and reboots produce expected errors in the logs
]

LABEL_NEW = "P01_NEW"

RESTART_TYPES = ["config_reload", "cold", "fast", "swss_restart"]


def _restart(duthost, localhost, ptfadapter, restart_type):
    '''Perform the restart type and wait until the critical processes are back.'''
    logger.info("Restart type: %s", restart_type)
    if restart_type == "config_reload":
        config_reload(duthost, safe_reload=True, wait=120)
    elif restart_type == "swss_restart":
        duthost.shell("sudo systemctl reset-failed swss; sudo systemctl restart swss")
    else:
        reboot(duthost, localhost, reboot_type=restart_type, wait_for_ssh=True)
    wait_critical_processes(duthost)
    ptfadapter.reinit()


@pytest.mark.parametrize("restart_type", RESTART_TYPES)
def test_label_persistence(duthosts, rand_one_dut_hostname, localhost, label_config_backup, label_erspan_route,
                           label_asic, label_ports, ptfadapter, restart_type):
    '''
    Labels, sessions and the ACL <-> session binding survive config reload, cold / fast reboot and
    swss restart, and mirrored traffic is delivered again afterwards. Warm reboot is not covered here.

    Three sessions are created from the highest number to the lowest, which is the reverse of the order
    they are replayed in, so a label can not be restored "by luck" through the order of re-creation.
    swss_restart row: a label changed straight in CONFIG_DB is applied by the restart (CONFIG_DB is the
    source of truth).
    '''
    duthost = duthosts[rand_one_dut_hostname]
    if not acl_table_exists(label_asic):
        pytest.skip("ACL table {} does not exist on the DUT".format(ACL_TABLE))

    expected = initial_labels()

    try:
        create_sessions(duthost, label_ports["src"]["name"])
        apply_mirror_acl_rule(duthost, session(ACL_NUMBER)[0])

        # baseline before any restart
        assert_state(duthost, label_asic, expected, ptfadapter, label_ports, label_erspan_route)

        duthost.command("config save -y")
        _restart(duthost, localhost, ptfadapter, restart_type)

        assert_state(duthost, label_asic, expected, ptfadapter, label_ports, label_erspan_route)

        if restart_type == "swss_restart":
            direct_hset_field(label_asic, session(PORT_MIRROR_NUMBER)[0], "label", LABEL_NEW)
            _restart(duthost, localhost, ptfadapter, restart_type)
            expected[PORT_MIRROR_NUMBER] = LABEL_NEW
            assert_state(duthost, label_asic, expected, ptfadapter, label_ports, label_erspan_route)
    finally:
        remove_mirror_acl_rules(duthost)
