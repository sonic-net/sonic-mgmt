"""Cold-reboot recovery-time measurement.

Measures how long the DUT takes, after a cold reboot, to restore the management,
control, data and traffic planes, and compares the total against an SLA.
See the cold reboot recovery timing test plan for the method and rationale.

Usage:
    pytest tests/platform_tests/cold_reboot_timing/test_cold_reboot_timing.py

    Optional env overrides:
        COLD_REBOOT_SLA=320       pass/fail threshold in seconds
        COLD_REBOOT_LOG_DIR=...   where to write the run artifacts
"""

import logging
import os
import json
import re
import subprocess
import sys
import time
from datetime import datetime

import pytest

from tests.common.fixtures.conn_graph_facts import conn_graph_facts   # noqa: F401
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.reboot import reboot
from tests.platform_tests.cold_reboot_timing import cold_reboot_timing_helper as helper

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('t1'),
]

logger = logging.getLogger(__name__)

HERE = os.path.dirname(os.path.realpath(__file__))
PTF_SCRIPT_SRC = os.path.join(HERE, 'files', 'ptf_traffic_test.py')
PARSER = os.path.join(HERE, 'reboot_timing_parser.py')

# Measured master-image totals sit at ~287-296s, so a flat 300s would flag normal
# jitter as a failure. Override with COLD_REBOOT_SLA.
DEFAULT_SLA = 320               # seconds
ROUTE_RECOVERY_TIMEOUT = 900    # cap on the post-reboot traffic poll
# reboot() defaults to a 300s SSH wait, but this platform takes ~350-450s to boot
# and would abort early. It returns as soon as SSH is up.
BOOT_TIMEOUT = 900


@pytest.fixture(scope='module')
def results_dir():
    base = os.environ.get('COLD_REBOOT_LOG_DIR', os.path.join(HERE, 'logs'))
    path = os.path.join(base, 'run_{}'.format(time.strftime('%Y%m%d_%H%M%S')))
    os.makedirs(path)
    logger.info("Run artifacts: %s", path)
    return path


def _fetch(duthost, remote, local, required=True):
    """Stage a root-owned file to /var/tmp and fetch it to the test host."""
    name = os.path.basename(remote)
    staged = '/var/tmp/{}'.format(name)
    res = duthost.shell(
        "if [ -f {r} ]; then sudo cp {r} {s} && sudo chmod 644 {s}; else exit 42; fi".format(
            r=remote, s=staged), module_ignore_errors=True)
    if res['rc'] != 0:
        if required:
            pytest_assert(False, "Could not stage {} on DUT".format(remote))
        logger.info("%s not present on DUT - skipping", remote)
        return False
    duthost.fetch(src=staged, dest=local, flat=True)
    logger.info("Copied %s", remote)
    return True


def _total_from_report(output):
    """Total recovery seconds from the parser report, or None if absent."""
    match = re.search(r'Total recovery time\s*:.*?\(\s*([\d.]+)s\)', output)
    return float(match.group(1)) if match else None


def test_cold_reboot_recovery_time(duthost, ptfhost, localhost, tbinfo,
                                   conn_graph_facts, results_dir):     # noqa: F811
    # Fixed-form (single-asic) only: on multi-asic the route injection would have
    # to target each ASIC namespace, so skip cleanly rather than fail obscurely.
    pytest_require(not duthost.is_multi_asic,
                   "Cold reboot timing is supported on fixed-form "
                   "(single-asic) platforms only")

    sla = int(os.environ.get('COLD_REBOOT_SLA', DEFAULT_SLA))

    console_log = os.path.join(results_dir, 'console.log')
    syslog_dst = os.path.join(results_dir, 'syslog')
    cfgdb_dst = os.path.join(results_dir, 'config_db.json')
    ptf_log_dst = os.path.join(results_dir, 'ptf_rx.log')
    dut_info_dst = os.path.join(results_dir, 'dut_info.json')
    result_file = os.path.join(results_dir, 'result.log')

    params = helper.get_traffic_params(duthost, tbinfo)
    recorder = None
    routes_added = False
    have_cfgdb = False
    have_syslog = False
    recovered = 0
    elapsed = 0.0
    rx_mark = 0
    clock_offset = 0.0
    reboot_start_dt = None
    oper_up = {'portchannels': set(), 'ports': set()}
    dut_info = {}

    try:
        # Expectations must come from real oper state, not config_db admin_status:
        # a link with no peer stays admin-up but never comes up.
        oper_up = helper.get_oper_up_interfaces(duthost)

        # Recorded with the timings so two runs can be compared. Must be read
        # before the reboot: the containers are what we are about to restart.
        dut_info = helper.get_dut_info(duthost, tbinfo)

        if not oper_up['portchannels']:
            # Empty means APPL_DB could not be read, not that the links are down.
            # Fall back to the parser's config_db behaviour and say so loudly.
            logger.warning("Could not read pre-reboot oper state; parser will "
                           "fall back to config_db admin_status expectations")
        else:
            pytest_assert(params['rx_pc'] in oper_up['portchannels'],
                          "RX PortChannel {} is not operationally up before the "
                          "reboot - cannot measure traffic recovery"
                          .format(params['rx_pc']))

        # --- Inject the test routes -------------------------------------
        helper.add_test_routes(duthost, params['nexthop'])
        routes_added = True

        # --- Start the PTF probe and take a pre-reboot baseline ----------
        helper.start_ptf_probe(ptfhost, PTF_SCRIPT_SRC, params)
        time.sleep(5)   # a few full sweeps
        baseline = helper.ptf_distinct_routes(ptfhost)
        logger.info("Baseline: %d/%d routes forwarding before reboot",
                    baseline, helper.NUM_ROUTES)
        pytest_assert(baseline > 0,
                      "No routes forwarding before reboot - routes not programmed "
                      "or PTF wiring issue")

        # Best-effort: without it we lose only the BIOS/GRUB/shutdown markers.
        recorder = helper.ConsoleRecorder.from_conn_graph(
            conn_graph_facts, duthost.hostname, console_log)
        if recorder and not recorder.start(duthost=duthost):
            recorder = None
        if recorder:
            time.sleep(2)

        # syslog uses the DUT clock, the PTF log this host's; capture the
        # difference so the parser can put both on one timeline.
        clock_offset = helper.get_clock_offset(duthost)

        logger.info("Performing cold reboot")
        reboot_start = time.time()
        reboot_start_dt = datetime.utcnow()
        reboot(duthost, localhost, reboot_type='cold', timeout=BOOT_TIMEOUT)
        wait_critical_processes(duthost)

        # Mark the RX log only once the DUT is back: the DUT keeps forwarding a
        # few seconds into the shutdown, which already covers every route.
        rx_mark = helper.ptf_rx_log_lines(ptfhost)

        # reboot() only proves the control plane is back; the last static route
        # returns ~60s later.
        recovered, _ = helper.wait_all_routes_recovered(
            ptfhost, ROUTE_RECOVERY_TIMEOUT, from_line=rx_mark)
        elapsed = time.time() - reboot_start
        logger.info("Traffic plane: %d/%d routes recovered within %.0fs of reboot trigger",
                    recovered, helper.NUM_ROUTES, elapsed)

    finally:
        # Collect artifacts unconditionally: a failed run is exactly when the
        # logs matter most, so this must not live on the success path.
        if recorder:
            try:
                recorder.stop()
            except Exception as err:
                logger.warning("Console recorder stop failed: %s", err)
        try:
            helper.stop_ptf_probe(ptfhost)
            ptfhost.fetch(src=helper.PTF_RX_LOG, dest=ptf_log_dst, flat=True)
            # The poll only samples every few seconds, so refine the SLA number
            # using the exact RX timestamp of the last route to come back.
            if reboot_start_dt and os.path.exists(ptf_log_dst):
                exact = helper.recovery_time_from_ptf_log(ptf_log_dst, reboot_start_dt)
                if exact is not None:
                    logger.info("Recovery time from PTF log: %.1fs (poll reported %.0fs)",
                                exact, elapsed)
                    elapsed = exact
        except Exception as err:
            logger.warning("Could not retrieve PTF RX log: %s", err)

        have_syslog = _fetch(duthost, '/var/log/syslog', syslog_dst, required=False)
        # logrotate may fire between the reboot and now, moving the reboot
        # marker into syslog.1; the parser falls back to it automatically.
        _fetch(duthost, '/var/log/syslog.1', syslog_dst + '.1', required=False)
        have_cfgdb = _fetch(duthost, '/etc/sonic/config_db.json', cfgdb_dst, required=False)

        if routes_added:
            try:
                helper.del_test_routes(duthost)
            except Exception as err:
                logger.warning("Route cleanup failed - remove 172.16.x routes manually: %s", err)

        # Analyse whatever we managed to collect, so even an aborted run leaves
        # a readable timing report behind.
        if have_syslog:
            if dut_info:
                try:
                    with open(dut_info_dst, 'w') as fh:
                        json.dump(dut_info, fh, indent=2, sort_keys=True)
                except Exception as err:
                    logger.warning("Could not write DUT info: %s", err)
            cmd = [sys.executable, PARSER, '--syslog', syslog_dst,
                   '--sla', str(sla)]
            if os.path.exists(dut_info_dst):
                cmd += ['--dut-info', dut_info_dst]
            # Expect back exactly the interfaces that were up beforehand.
            if oper_up['portchannels']:
                cmd += ['--portchannels', ','.join(sorted(oper_up['portchannels']))]
                if oper_up['ports']:
                    cmd += ['--pc-members', ','.join(sorted(oper_up['ports']))]
            if os.path.exists(ptf_log_dst):
                cmd += ['--ptf-log', ptf_log_dst,
                        '--ptf-num-routes', str(helper.NUM_ROUTES),
                        '--console-offset', '{:.3f}'.format(clock_offset)]
            if have_cfgdb:
                cmd += ['--config-db', cfgdb_dst]
            if os.path.exists(console_log):
                cmd += ['--console-log', console_log]
            try:
                proc = subprocess.run(cmd, stdout=subprocess.PIPE,
                                      stderr=subprocess.STDOUT, timeout=300)
                output = proc.stdout.decode('utf-8', errors='replace')
            except Exception as err:
                output = "Timing analysis failed: {}".format(err)
            logger.info("Timing analysis:\n%s", output)
            with open(result_file, 'w') as fh:
                fh.write(output)
            # The SLA verdict must match the report, so take the total from the
            # parser: it measures from the syslog reboot marker, while a local
            # timestamp also counts the SSH/Ansible delay before the DUT sees it.
            total = _total_from_report(output)
            if total is not None:
                logger.info("Recovery time from syslog markers: %.1fs "
                            "(PTF-log measurement was %.1fs)", total, elapsed)
                elapsed = total
            else:
                logger.warning("No total in the timing report - keeping the "
                               "PTF-log measurement of %.1fs", elapsed)
        else:
            logger.warning("No syslog collected - skipping timing analysis")

        logger.info("Run artifacts saved in: %s", results_dir)

    pytest_assert(recovered >= helper.NUM_ROUTES,
                  "Only {}/{} static routes recovered within {}s".format(
                      recovered, helper.NUM_ROUTES, ROUTE_RECOVERY_TIMEOUT))
    pytest_assert(elapsed <= sla,
                  "Cold reboot recovery took {:.0f}s, exceeding the {}s SLA. "
                  "See {}".format(elapsed, sla, result_file))
