'''
Mirror session label across a warm reboot, with mirrored traffic running during the reboot.

Test plan: docs/testplan/Mirror-session-label-test-plan.md
'''

import logging

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.reboot import REBOOT_TYPE_WARM, reboot
from mirror_label_helpers import (
    ACL_RULE_SRC_IP,
    ACL_TABLE,
    ContinuousMirrorTraffic,
    acl_table_exists,
    apply_mirror_acl_rule,
    remove_mirror_acl_rules,
)
from mirror_label_scenario import (
    ACL_NUMBER,
    assert_state,
    create_sessions,
    initial_labels,
    make_packet,
    mirrored_destinations,
    session,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.disable_memory_utilization,
    pytest.mark.disable_loganalyzer,    # a reboot produces expected errors in the logs
]

TRAFFIC_INTERVAL = 0.01     # one test packet every 10 ms during the reboot
MAX_LOSS = 0                # mirrored packets each stream may lose during the reboot: none are expected


def test_label_warm_reboot(duthosts, rand_one_dut_hostname, localhost, label_config_backup, label_erspan_route,
                           label_asic, label_ports, ptfadapter):
    '''
    Labels, sessions and the ACL <-> session binding survive a warm reboot, and the mirrored traffic is not
    interrupted while the DUT reboots: a test packet is sent every 10 ms the whole time and each of the two
    mirrored streams (ACL, port mirror) must not lose a packet. The longest pause between two mirrored
    frames is logged.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    if not acl_table_exists(label_asic):
        pytest.skip("ACL table {} does not exist on the DUT".format(ACL_TABLE))

    expected = initial_labels()
    dst_acl, dst_port, others = mirrored_destinations()
    src = label_ports["src"]

    try:
        create_sessions(duthost, src["name"])
        apply_mirror_acl_rule(duthost, session(ACL_NUMBER)[0])

        # baseline before the reboot
        assert_state(duthost, label_asic, expected, ptfadapter, label_ports, label_erspan_route)

        duthost.command("config save -y")
        traffic = ContinuousMirrorTraffic(ptfadapter, src["index"], make_packet(duthost, ptfadapter, src["index"]),
                                          label_erspan_route["ptf_index"], ACL_RULE_SRC_IP,
                                          interval=TRAFFIC_INTERVAL)
        traffic.start()
        try:
            reboot(duthost, localhost, reboot_type=REBOOT_TYPE_WARM, wait_for_ssh=True,
                   wait_warmboot_finalizer=True)
            wait_critical_processes(duthost)
        finally:
            counts = traffic.finish()

        logger.info("Warm reboot: sent %d packets (%d send errors); mirrored frames %s; longest pause between "
                    "frames %s s", traffic.sent, traffic.send_errors, counts,
                    {d: round(g, 3) for d, g in traffic.max_gap.items()})
        pytest_assert(traffic.sent > 0, "No test packet was sent during the reboot")
        for dst in (dst_acl, dst_port):
            received = counts.get(dst, 0)
            pytest_assert(traffic.sent - MAX_LOSS <= received <= traffic.sent,
                          "Stream to {} got {} of {} packets during the warm reboot (allowed loss {}, duplicates "
                          "not allowed); longest pause {} s".format(dst, received, traffic.sent, MAX_LOSS,
                                                                    round(traffic.max_gap.get(dst, 0), 3)))
        pytest_assert(not any(dst in counts for dst in others),
                      "Other sessions must mirror nothing, got {}".format(counts))

        ptfadapter.reinit()
        assert_state(duthost, label_asic, expected, ptfadapter, label_ports, label_erspan_route)
    finally:
        remove_mirror_acl_rules(duthost)
