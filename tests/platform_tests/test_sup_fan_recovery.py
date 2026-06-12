"""
Sup fan-status test for T2 chassis.

Targets a thermalctld / psu-service bug seen after a chassis sup reload
+ cold reboot, where the sup came back with fans incorrectly reported
as ``Not present`` and thermalctld throwing ``UnboundLocalError``
tracebacks.

Sequence on every sup:

    1. Snapshot existing core dumps across all cards.
    2. Arm a sup-scoped LogAnalyzer for the bug's syslog signature
       (Traceback / UnboundLocalError / Fan removed warning /
       Insufficient number of working fans).
    3. Reload the sup's config from minigraph with override:
           sudo config load_minigraph --override_config -y
    4. Require ``show platform fan`` to report **every** fan in OK state
       on the sup AFTER the minigraph load (before reboot).  This isolates
       a load_minigraph-only regression from a reboot-only one.
    5. Cold-reboot the sup and wait for the chassis to come back.
    6. Verify interfaces and critical services post-reboot.
    7. Require ``show platform fan`` to report **every** fan in OK state
       on the sup AFTER the cold reboot.
    8. Analyze the sup's syslog between the markers.
    9. Verify no new core dumps appeared on any card.
"""
import datetime
import logging

import pytest

from tests.common import config_reload
from tests.common.helpers.assertions import pytest_assert
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer
from tests.common.reboot import REBOOT_TYPE_COLD
from tests.common.utilities import wait_until, file_exists_on_dut
from tests.platform_tests import test_reboot
from tests.platform_tests.cli.test_show_platform import verify_show_platform_fan_output

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t2')
]


SUP_SYSLOG_MATCH_REGEX = [
    r".*Traceback \(most recent call last\).*",
    r".*UnboundLocalError.*",
    r".*Fan removed warning.*",
    r".*Insufficient number of working fans.*",
]


def _snapshot_cores(duthosts):
    """Return {hostname: [core file names]} for every dut."""
    snap = {}
    for d in duthosts:
        try:
            out = d.shell('ls /var/core/ 2>/dev/null || true')['stdout']
        except Exception as err:
            logger.warning("Could not list /var/core on %s: %s", d.hostname, err)
            out = ''
        snap[d.hostname] = out.split()
    return snap


def _all_fans_ok(duthost, cmd="show platform fan"):
    """Return True iff every fan row reported by ``cmd`` is in OK state.

    Skips devices where fan reporting isn't applicable (virtual switch /
    DPU).  This is intentionally stricter than the upstream
    ``check_fan_status`` helper (which accepts >=1 OK fan) -- we want
    a single non-OK fan to fail the test, because that is exactly how
    the bug manifested.
    """
    if duthost.facts.get("asic_type") == "vs":
        return True

    raw = duthost.command(cmd)["stdout_lines"]
    fans = verify_show_platform_fan_output(duthost, raw)

    if not fans:
        cfg = duthost.config_facts(host=duthost.hostname, source="running")["ansible_facts"]
        if cfg.get("DEVICE_METADATA", {}).get("localhost", {}).get("switch_type", "") == "dpu":
            return True
        logger.info("No fan rows reported by '%s' on %s yet", cmd, duthost.hostname)
        return False

    not_ok = {name: row.get("Status") for name, row in fans.items()
              if row.get("Status") != "OK"}
    if not_ok:
        logger.info("Non-OK fans on %s: %s", duthost.hostname, not_ok)
        return False
    return True


def _assert_no_new_cores(duthosts, before):
    new_per_host = {}
    for d in duthosts:
        try:
            after = d.shell('ls /var/core/ 2>/dev/null || true')['stdout'].split()
        except Exception as err:
            logger.warning("Could not list /var/core on %s: %s", d.hostname, err)
            after = []
        new = sorted(set(after) - set(before.get(d.hostname, [])))
        if new:
            new_per_host[d.hostname] = new
    assert not new_per_host, \
        "New core dumps appeared during sup reload+reboot: {}".format(new_per_host)


def test_sup_fan_status_after_reload_reboot(duthosts, localhost, conn_graph_facts, xcvr_skip_list):
    if not duthosts.supervisor_nodes:
        pytest.skip("test_sup_fan_status_after_reload_reboot requires a chassis with supervisor_nodes")

    # The bug this test targets is a hardware-only thermalctld / psu-service
    # regression.  On a virtual / KVM chassis (asic_type == "vs") pmon's
    # sub-daemons don't fully come back after a sup cold reboot, so
    # reboot_and_check would fail with "Not all pmon daemons running"
    # before we ever reach the fan-status assertion -- and syslog on the
    # simulated sup is full of KVM-only errors (dummy-sup switch type,
    # bmc_base watchdog, system-health.service, RETBleed, shpchp PCI
    # hotplug, etc.) that the autouse loganalyzer flags as failures.
    # Skip cleanly so this test only runs on real T2 chassis where the
    # bug actually exists.
    if any(d.facts.get("asic_type") == "vs" for d in duthosts):
        pytest.skip("test_sup_fan_status_after_reload_reboot is hardware-only "
                    "(skipped on virtual / KVM chassis)")

    core_before = _snapshot_cores(duthosts)

    for sup in duthosts.supervisor_nodes:
        # `config load_minigraph` is meaningless without /etc/sonic/minigraph.xml
        # on the sup -- skip cleanly instead of letting config_reload crash.
        if not file_exists_on_dut(sup, "/etc/sonic/minigraph.xml"):
            pytest.skip(
                "No /etc/sonic/minigraph.xml on sup {} -- cannot run "
                "load_minigraph".format(sup.hostname)
            )

        logger.info("Start of test_sup_fan_status_after_reload_reboot on %s at %s",
                    sup.hostname, datetime.datetime.now())

        # Scope the LogAnalyzer to the sup only.  The start marker is
        # written into /var/log/syslog before the reboot and survives
        # the cold reboot because /var/log/syslog is on the host fs.
        sup_la = LogAnalyzer(ansible_host=sup, marker_prefix="test_sup_fan_status_after_reload_reboot")
        sup_la.match_regex = list(SUP_SYSLOG_MATCH_REGEX)
        sup_la.expect_regex = []
        sup_la.ignore_regex = []
        sup_la_marker = sup_la.init()

        # Apply minigraph with override -- equivalent to:
        #     sudo config load_minigraph --override_config -y
        config_reload(sup, config_source='minigraph', override_config=True, wait=420)

        # Stage 1 assertion: fans must already be OK after the minigraph
        # load alone, before we trigger the cold reboot.  Splitting the
        # check here from the post-reboot check below tells us whether a
        # regression is in load_minigraph, in the reboot path, or only in
        # the combined sequence.  thermalctld can take a few seconds to
        # repopulate state-db, so poll.
        pytest_assert(
            wait_until(90, 5, 0, _all_fans_ok, sup),
            "Not all fans reported OK by 'show platform fan' on sup "
            "{} after 'config load_minigraph --override_config' "
            "(before cold reboot)".format(sup.hostname),
        )

        # reboot_and_check already runs check_interfaces_and_services
        # for the sup and every frontend linecard internally.  Called
        # directly because the test_cold_reboot wrapper now requires
        # invocation_type / ptf_gnoi fixtures that cannot be injected
        # from a plain function call.
        test_reboot.reboot_and_check(
            localhost, sup,
            conn_graph_facts.get("device_conn", {}).get(sup.hostname, {}),
            xcvr_skip_list,
            reboot_type=REBOOT_TYPE_COLD,
            duthosts=duthosts,
        )

        # Stage 2 assertion: every fan reported by `show platform fan`
        # on the sup must be in OK state after the cold reboot too.
        # thermalctld can take a few seconds to repopulate state-db after
        # reboot, so poll.
        pytest_assert(
            wait_until(90, 5, 0, _all_fans_ok, sup),
            "Not all fans reported OK by 'show platform fan' on sup "
            "{} after reload + cold reboot".format(sup.hostname),
        )

        sup_la.analyze(sup_la_marker)

    _assert_no_new_cores(duthosts, core_before)
