"""
Verify that a warm reboot is hitless for SRv6 traffic.

A warm reboot is expected to keep forwarding the data plane while the control
plane restarts. Checking the SRv6 state before and after the reboot is not
enough to prove it: the SID entries could be removed and reprogrammed during the
boot and the final state would still look correct.

These tests therefore send a continuous SRv6 flow through the DUT for the whole
duration of the warm reboot, and fail when that flow is disrupted. The state
which makes the forwarding possible is checked afterwards, so that a failure
points at the component which did not preserve it.
"""

import logging

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.srv6_helper import is_bgp_route_synced
from tests.common.helpers.srv6_io import run_srv6_io_test, format_flow_result, SRV6_FLOW
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.common.reboot import reboot
from tests.common.utilities import wait_until
from tests.srv6.srv6_utils import UN_SID_APPL_DB_KEY, UN_SID_TRAFFIC_DST, UN_EGRESS_DST, \
    UN_EGRESS_ROUTE, SRV6_BLACKHOLE_ROUTE, CRM_FAST_POLL_INTERVAL, verify_appl_db_sid_entry_exist, \
    verify_asic_db_sid_entry_exist, get_asic_db_mysid_entries, verify_static_route_installed, \
    verify_reboot_cause_warm, collect_warmboot_diagnostics, get_neighbor_mac, \
    get_srv6_mysid_entry_usage, get_crm_polling_interval, set_crm_polling_interval, \
    run_srv6_traffic_test, run_srv6_no_sid_blackhole_test

logger = logging.getLogger(__name__)

# SRv6 is only expected to survive a warm reboot on Mellanox/NVIDIA Spectrum-5 and
# newer platforms. The setups which do not support it are skipped through the
# conditional mark of srv6/test_srv6_warmboot.py in tests_mark_conditions.yaml.
pytestmark = [
    pytest.mark.asic("mellanox"),
    pytest.mark.topology("t0", "t1"),
    # A warm reboot generates expected log noise, the SRv6 state is verified explicitly instead
    pytest.mark.disable_loganalyzer,
]


@pytest.fixture(autouse=True)
def fast_crm_polling(setup_uN):
    """
    Speed up the CRM polling for the duration of the test, and restore it after.

    CRM refreshes its resource counters on a polling interval which defaults to
    300s, while setup_uN configures the SID immediately before the test runs. The
    MY_SID counter read as the reference would therefore still be stale, and the
    first poll happening during the reboot would show up as a change caused by
    it. The interval is lowered so that the counter reflects the configured entry
    before it is snapshotted.
    """
    duthost = setup_uN['duthost']
    previous_interval = get_crm_polling_interval(duthost)
    set_crm_polling_interval(duthost, CRM_FAST_POLL_INTERVAL)

    # Wait for CRM to account for the SID configured by setup_uN, so that the
    # reference taken by the test is the settled value
    if not wait_until(CRM_FAST_POLL_INTERVAL * 6, CRM_FAST_POLL_INTERVAL, CRM_FAST_POLL_INTERVAL,
                      lambda: (get_srv6_mysid_entry_usage(duthost) or {}).get('used_count', 0) > 0):
        logger.warning("CRM still does not account for any MY_SID entry, the counter check may be "
                       "comparing a stale reference")
    try:
        yield
    finally:
        set_crm_polling_interval(duthost, previous_interval)


def warm_reboot_params(request):
    """Collect the tunables of the warm reboot I/O test."""
    return {
        'send_interval': request.config.getoption("--srv6_warmboot_send_interval"),
        'max_duration': request.config.getoption("--srv6_warmboot_max_duration"),
        'settle_time': request.config.getoption("--srv6_warmboot_settle_time"),
        'allowed_disruption': request.config.getoption("--srv6_warmboot_allowed_disruption"),
        'allowed_duplication': request.config.getoption("--srv6_warmboot_allowed_duplication"),
    }


def do_warm_reboot(duthost, localhost):
    """Save the configuration and warm reboot the DUT, waiting for the finalizer."""
    duthost.shell('config save -y')
    reboot(duthost, localhost, reboot_type='warm', wait_warmboot_finalizer=True,
           safe_reboot=True, check_intf_up_ports=True, wait_for_bgp=True)


def validate_srv6_state_after_warmboot(setup_uN, sonic_db_cli, asic_sid_entries, crm_usage):
    """Verify that the SRv6 forwarding state survived the warm reboot."""
    duthost = setup_uN['duthost']

    pytest_assert(verify_reboot_cause_warm(duthost),
                  "The last reboot was not a warm reboot, the hitless expectation does not apply")

    pytest_assert(wait_until(180, 5, 0, verify_appl_db_sid_entry_exist, duthost, sonic_db_cli,
                             UN_SID_APPL_DB_KEY, True),
                  "SID entry is missing in APPL_DB after the warm reboot")
    pytest_assert(wait_until(60, 5, 0, verify_asic_db_sid_entry_exist, duthost, sonic_db_cli),
                  "ASIC_STATE:SAI_OBJECT_TYPE_MY_SID_ENTRY entries are missing in ASIC_DB "
                  "after the warm reboot")

    entries_after = get_asic_db_mysid_entries(duthost, sonic_db_cli)
    pytest_assert(set(entries_after.keys()) == set(asic_sid_entries.keys()),
                  "The MY_SID entries programmed in ASIC_DB changed over the warm reboot. "
                  "Before: {}, after: {}".format(sorted(asic_sid_entries.keys()),
                                                 sorted(entries_after.keys())))
    for key, attributes in asic_sid_entries.items():
        if entries_after[key] != attributes:
            # The entry is still there but has been reprogrammed differently. This
            # does not necessarily break the forwarding, so it is reported and not
            # asserted, the hitless check is the authoritative verdict.
            logger.warning("Attributes of the MY_SID entry {} changed over the warm reboot. "
                           "Before: {}, after: {}".format(key, attributes, entries_after[key]))

    # CRM restarts with the rest of the control plane and needs one poll cycle
    # before its counters are current again, so give it a bounded chance to
    # settle on the expected value instead of reading it straight away
    if crm_usage:
        wait_until(CRM_FAST_POLL_INTERVAL * 6, CRM_FAST_POLL_INTERVAL, 0,
                   lambda: (get_srv6_mysid_entry_usage(duthost) or {}).get('used_count')
                   == crm_usage['used_count'])
    crm_usage_after = get_srv6_mysid_entry_usage(duthost)
    if crm_usage and crm_usage_after:
        pytest_assert(crm_usage_after['used_count'] == crm_usage['used_count'],
                      "The number of MY_SID entries accounted by CRM changed over the warm reboot. "
                      "Before: {}, after: {}".format(crm_usage['used_count'],
                                                     crm_usage_after['used_count']))

    # The static routes used for SRv6 forwarding are not redistributed into BGP,
    # so they are verified on the box instead of from a BGP neighbor.
    pytest_assert(wait_until(120, 5, 0, verify_static_route_installed, duthost, UN_EGRESS_ROUTE,
                             setup_uN['neighbor_ip'], setup_uN['dut_port'], False, sonic_db_cli,
                             setup_uN['cli_options']),
                  "The static route {} is not installed after the warm reboot".format(UN_EGRESS_ROUTE))
    pytest_assert(wait_until(120, 5, 0, verify_static_route_installed, duthost, SRV6_BLACKHOLE_ROUTE,
                             None, None, True, sonic_db_cli, setup_uN['cli_options']),
                  "The blackhole route {} is not installed after the warm reboot".format(SRV6_BLACKHOLE_ROUTE))

    pytest_assert(wait_until(120, 5, 0, is_bgp_route_synced, duthost), "BGP route is not synced")
    pytest_assert(wait_until(60, 5, 0, get_neighbor_mac, duthost, setup_uN['neighbor_ip']),
                  "The neighbor table was not updated with the MAC of the neighbor")


def validate_hitless(results, allowed_disruption, allowed_duplication, is_kvm):
    """Assert that the SRv6 flow was not disrupted by the warm reboot."""
    for flow, result in results.items():
        logger.info("I/O results of the %s flow:\n%s", flow, format_flow_result(result))

    srv6_result = results[SRV6_FLOW]

    # A sniffer which captured nothing would make every other check pass silently
    pytest_assert(srv6_result['received_packets'] > 0,
                  "No SRv6 traffic was captured, the traffic test did not run properly")

    # Traffic which stopped before the reboot completed would not have covered the
    # outage, and the absence of disruption would not mean anything
    pytest_assert(srv6_result['covers_action'] is not False,
                  "The SRv6 traffic did not span the whole warm reboot, so it cannot tell whether "
                  "the reboot was hitless. Increase --srv6_warmboot_max_duration or "
                  "--srv6_warmboot_send_interval.")

    if is_kvm:
        logger.warning("Running on a virtual switch, the data plane is not preserved over a warm "
                       "reboot: the disruption of the SRv6 flow is reported but not asserted")
        return

    pytest_assert(srv6_result['mis_forwarded_packets'] == 0,
                  "{} SRv6 packets were forwarded without the uN behavior being applied."
                  .format(srv6_result['mis_forwarded_packets']))
    pytest_assert(srv6_result['total_disruption'] <= allowed_disruption,
                  "The SRv6 flow was disrupted for {:.4f}s over the warm reboot, which is more than "
                  "the allowed {}s. {} packet(s) lost in {} disruption(s), the longest one lasted "
                  "{:.4f}s.".format(srv6_result['total_disruption'], allowed_disruption,
                                    srv6_result['lost_packets'], srv6_result['disruption_count'],
                                    srv6_result['longest_disruption']))
    pytest_assert(srv6_result['duplicated_packets'] <= allowed_duplication,
                  "{} SRv6 packets were duplicated over the warm reboot, which is more than the "
                  "allowed {}".format(srv6_result['duplicated_packets'], allowed_duplication))


@pytest.mark.parametrize("with_srh", [True, False])
def test_srv6_uN_hitless_warmboot(setup_uN, ptfadapter, ptfhost, localhost, request, with_srh):
    """
    Verify that a warm reboot does not disrupt the SRv6 uN traffic.

    A continuous SRv6 flow is injected through the DUT while it is warm rebooted.
    The flow keeps running until after the warm boot finalizer completed, because
    the SID entries are reconciled by bgpcfgd, fpmsyncd and orchagent once the
    device is already reachable again.
    """
    params = warm_reboot_params(request)
    duthost = setup_uN['duthost']
    dut_mac = setup_uN['dut_mac']
    ptf_src_ports = setup_uN['ptf_src_ports']
    neighbor_ip = setup_uN['neighbor_ip']
    sonic_db_cli = "sonic-db-cli" + setup_uN['cli_options']
    ptf_src_port = ptf_src_ports[0] if isinstance(ptf_src_ports, list) else ptf_src_ports

    with allure.step('Validate the SRv6 forwarding state before the warm reboot'):
        pytest_assert(wait_until(60, 5, 0, verify_appl_db_sid_entry_exist, duthost, sonic_db_cli,
                                 UN_SID_APPL_DB_KEY, True),
                      "SID entry is missing in APPL_DB before the warm reboot")
        pytest_assert(wait_until(60, 5, 0, verify_asic_db_sid_entry_exist, duthost, sonic_db_cli),
                      "ASIC_STATE:SAI_OBJECT_TYPE_MY_SID_ENTRY entries are missing in ASIC_DB "
                      "before the warm reboot")
        pytest_assert(wait_until(60, 5, 0, verify_static_route_installed, duthost, UN_EGRESS_ROUTE,
                                 neighbor_ip, setup_uN['dut_port'], False, sonic_db_cli,
                                 setup_uN['cli_options']),
                      "The static route {} is not installed before the warm reboot".format(UN_EGRESS_ROUTE))
        pytest_assert(wait_until(60, 5, 0, verify_static_route_installed, duthost, SRV6_BLACKHOLE_ROUTE,
                                 None, None, True, sonic_db_cli, setup_uN['cli_options']),
                      "The blackhole route {} is not installed before the warm reboot"
                      .format(SRV6_BLACKHOLE_ROUTE))

        asic_sid_entries = get_asic_db_mysid_entries(duthost, sonic_db_cli)
        crm_usage = get_srv6_mysid_entry_usage(duthost)

    with allure.step('Validate the SRv6 forwarding before the warm reboot'):
        run_srv6_traffic_test(duthost, dut_mac, ptf_src_ports, neighbor_ip, ptfadapter, ptfhost, with_srh)

    with allure.step('Warm reboot the DUT while SRv6 traffic is running'):
        srv6_io = run_srv6_io_test(
            duthost, ptfhost, ptfadapter,
            action=lambda: do_warm_reboot(duthost, localhost),
            ptf_src_port=ptf_src_port,
            router_mac=dut_mac,
            sid_dst=UN_SID_TRAFFIC_DST,
            egress_dst=UN_EGRESS_DST,
            with_srh=with_srh,
            send_interval=params['send_interval'],
            max_duration=params['max_duration'],
            settle_time=params['settle_time'])

    try:
        with allure.step('Validate that the warm reboot was hitless for the SRv6 traffic'):
            validate_hitless(srv6_io.get_test_results(), params['allowed_disruption'],
                             params['allowed_duplication'], duthost.facts["asic_type"] == "vs")

        with allure.step('Validate the SRv6 forwarding state after the warm reboot'):
            validate_srv6_state_after_warmboot(setup_uN, sonic_db_cli, asic_sid_entries, crm_usage)

        with allure.step('Validate the SRv6 forwarding after the warm reboot'):
            run_srv6_traffic_test(duthost, dut_mac, ptf_src_ports, neighbor_ip, ptfadapter, ptfhost, with_srh)
    except (Exception, pytest.fail.Exception):
        # pytest.fail.Exception is listed explicitly because it derives from
        # BaseException, not Exception, so that test outcomes are not swallowed
        # by a bare except. The checks above all report through pytest_assert, so
        # catching Exception alone would skip the diagnostics for exactly the
        # assertion failures they are meant to explain. KeyboardInterrupt and
        # Skipped are deliberately left out. The re-raise keeps the outcome.
        collect_warmboot_diagnostics(duthost, sonic_db_cli)
        raise


def test_srv6_no_sid_blackhole_after_warmboot(setup_uN, ptfadapter, ptfhost, localhost):
    """
    Verify that packets sent to an unprogrammed SID are still dropped after a warm reboot.

    The drop relies on the fcbb:bbbb::/32 blackhole static route. That route is
    configured in CONFIG_DB and is not redistributed into BGP, so it does not
    benefit from the BGP graceful restart and its reinstallation has to be
    verified explicitly.
    """
    duthost = setup_uN['duthost']
    sonic_db_cli = "sonic-db-cli" + setup_uN['cli_options']

    with allure.step('Validate that the unprogrammed SID is blackholed before the warm reboot'):
        run_srv6_no_sid_blackhole_test(setup_uN, ptfadapter, ptfhost, with_srh=False)

    with allure.step('Warm reboot the DUT'):
        do_warm_reboot(duthost, localhost)

    try:
        with allure.step('Validate that the blackhole route was reinstalled'):
            pytest_assert(verify_reboot_cause_warm(duthost), "The last reboot was not a warm reboot")
            pytest_assert(wait_until(120, 5, 0, verify_static_route_installed, duthost,
                                     SRV6_BLACKHOLE_ROUTE, None, None, True, sonic_db_cli,
                                     setup_uN['cli_options']),
                          "The blackhole route {} is not installed after the warm reboot"
                          .format(SRV6_BLACKHOLE_ROUTE))

        with allure.step('Validate that the unprogrammed SID is blackholed after the warm reboot'):
            run_srv6_no_sid_blackhole_test(setup_uN, ptfadapter, ptfhost, with_srh=False)
    except (Exception, pytest.fail.Exception):
        # See the note in test_srv6_uN_hitless_warmboot: pytest_assert raises
        # pytest.fail.Exception, which does not derive from Exception
        collect_warmboot_diagnostics(duthost, sonic_db_cli)
        raise
