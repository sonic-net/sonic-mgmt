import os
import re
import csv
import sys
import pdb
import time
import glob
import copy
import subprocess
from collections import OrderedDict
from collections import Counter
import random
import traceback
import threading
import textwrap
import tempfile
import logging
import socket
import signal
import atexit
import pytest

from apis.common.init import apis_register
from apis.common.init import apis_trace_register
from apis.common.init import apis_instrument

import utilities.common as utils
import utilities.parallel as putil
from spytest.net import Net
from spytest.logger import Logger
from spytest.logger import LEVEL_NOTICE
from spytest.logger import LEVEL_TOPO
from spytest.result import Result
from spytest.result import ReportType
from spytest.testbed import Testbed
from spytest.rps import RPS
from spytest.termserv import TermServ
from spytest.dicts import SpyTestDict
from spytest.tgen import tg as tgapi
from spytest.version import get_git_ver
from spytest.datamap import DataMap
from spytest import batch
from spytest.st_time import get_timenow
from spytest.st_time import get_elapsed
from spytest.st_time import get_timestamp
from spytest.ftrace import ftrace, print_ftrace
from spytest.suite import parse as parse_suites
from spytest import tcmap
from spytest import paths
from spytest import cmdargs
from spytest import env
from spytest import syslog
from spytest import generate
from spytest import item_utils

root_path = os.path.join(os.path.dirname(__file__), '..')
root_path = os.path.abspath(root_path)

g_lock = threading.Lock()
bg_results = putil.ExecuteBackgroud()
min_time = 0
missing_test_names_msg = ""
selected_test_results = OrderedDict()
reused_test_results = OrderedDict()
current_test = SpyTestDict()
current_module = SpyTestDict()
gWorkArea = None

exec_phases = ['always', 'onfail', "none", "onerror", "session",
               "onfail-epilog", "module-always", "module-onfail", "module-onerror"]
ui_types = ['click', 'klish', 'click-fallback', 'klish-fallback',
            'rest-put', 'rest-patch', 'rest', 'rest-post',
            'gnmi', 'gnmi-update', 'gnmi-replace',
            'random', 'custom'
            ]
random_ui_types = ['click', 'klish', 'rest-patch']
load_image_types = ['installer', 'onie1', 'onie', "installer-without-migration"]

mail_build = "UNKNOWN"


def set_mail_build(val):
    global mail_build
    mail_build = val


dtrace_dbg, dtrace_log = False, False


def dtrace(*args):
    if dtrace_log:
        ftrace(*args)
    if not dtrace_dbg:
        return
    worker_id = batch.get_worker_id()
    wa = get_work_area()
    if wa:
        wa.log(args)
    elif not worker_id:
        print(args)
    elif not dtrace_log:
        ftrace(*args)


def _get_logs_path(master=False):
    user_root = env.get("SPYTEST_USER_ROOT", os.getcwd())
    logs_path = env.get("SPYTEST_LOGS_PATH", user_root)
    worker_id = batch.get_worker_id()
    if worker_id and not master:
        logs_path = os.path.join(logs_path, worker_id)
    if not os.path.isabs(logs_path):
        logs_path = os.path.join(user_root, logs_path)
    if not os.path.exists(logs_path):
        os.makedirs(logs_path)
    return [user_root, logs_path, worker_id]


def create_pid_file():
    logs_path = _get_logs_path()[1]
    pid_file = paths.get_pid_log(logs_path)
    utils.write_file(pid_file, "{}".format(os.getpid()))


def build_module_logname(nodeid):
    if env.get("SPYTEST_REPEAT_MODULE_SUPPORT") == "0":
        return paths.get_mlog_name(nodeid)
    try:
        cur_test = env.get("PYTEST_CURRENT_TEST", "").split(" ")[0]
        modid, _ = cur_test.split("::")
    except Exception:
        modid = nodeid
    return paths.get_mlog_name(modid)


def dump_connections(msg):
    for line in utils.dump_connections(msg):
        ftrace(line)


def global_abort_run(val, reason):
    if reason is not None:
        print_ftrace(reason)
        logs_path = _get_logs_path()[1]
        file_path = os.path.join(logs_path, "node_dead_reason")
        utils.write_file(file_path, "{}".format(reason))
    utils.dump_connections("Connections@Abort")
    utils.abort_run(val)


def append_email_body(body, filename, prefix="", suffix=""):
    if not os.path.exists(filename):
        return body
    lines = []
    lines.append(prefix)
    for line in utils.read_lines(filename):
        lines.append(re.sub('<a.*?>|</a> ', '', line))
    lines.append(suffix)
    return body + "\n".join(lines) + "\n<br>\n"


class Context(object):

    def __init__(self, wa, cfg):
        self.wa = wa
        self.cfg = cfg
        self.tc_results = dict()
        self.all_tc_executed = 0
        self.shutting_down = False
        self.sent_first_progress = False
        self.last_report_line = None
        self.file_prefix = None
        self.cleanup_calls = []
        self.skip_tgen = cfg.skip_tgen
        self.topo_str = ""
        self.root_path = "ROOT_PATH: {}".format(root_path)
        self.version_msg = "VERSION: {}".format(get_git_ver())
        self.hostname = "HOST: {} {}".format(socket.gethostname(),
                                             utils.get_meminfo())
        self.pyver = "{}.{}.{}".format(sys.version_info.major,
                                       sys.version_info.minor, sys.version_info.micro)
        self.cmdline_args = env.get("SPYTEST_CMDLINE_ARGS", "")
        self.cmdline_args = "ARGS: {}".format(self.cmdline_args)
        self.net = None
        self.execution_start_time = get_timenow()
        self.execution_end_time = None
        self.session_start_time = get_timenow()
        self.session_init_time_taken = None
        self.total_tc_start_time = None

        # bail out if the threads are not sane
        if putil.get_thread_name().startswith("Dummy"):
            global_abort_run(2, "Threads are corrupted")

        # bail out early
        self.user_root, self.logs_path, self.worker_id = _get_logs_path()
        if not self.user_root:
            msg = "SPYTEST_USER_ROOT env not found"
            global_abort_run(1, msg)

        # init logger
        self._log_init()

        # log the worker node info
        if self.worker_id:
            self.log.notice("WORKER = {}".format(self.worker_id))
            gwtestbed = "SPYTEST_TESTBED_FILE_{}".format(self.worker_id)
            gwtestbed = env.get(gwtestbed)
            self.log.notice("using testbed file {}".format(gwtestbed))
            if gwtestbed:
                cfg.testbed = gwtestbed

        # log the start time and logs path
        self.log.notice("Execution Start Time: {}".format(self.execution_start_time))
        self.log.notice("LOGS PATH: {}".format(self.logs_path))
        if os.path.exists(os.path.join(self.logs_path, "node_used")):
            self.cfg.load_image = "none"
            if env.get("SPYTEST_SKIP_USED_NODE_BREAKOUT", "1") == "1":
                self.cfg.breakout_mode = "none"
                self.cfg.speed_mode = "none"

        # parse testbed file
        tb_errors = self.read_testbed_file()

        # log the version information
        self.log_verion_info()

        # log the environment variables
        for name, value in cfg.env.items():
            self.log.warning("setting environment {} = {}".format(name, value))
            os.environ[name] = value

        # log the reused test results
        if reused_test_results:
            self.log.info("Reusing previous test results:")
            for tc in reused_test_results.keys():
                self.log.info("   {}".format(tc))

        # set the needed log level
        if cfg.log_lvl:
            self.log.set_lvl(cfg.log_lvl)

        # bail out if testbed is not valid
        if tb_errors:
            self.log.error("\n".join(tb_errors), split_lines=True)
            msg = "Error: testbed file is not found or contains errors"
            global_abort_run(2, msg)

        # init features
        self.wa._context = self
        self.wa._init_features()

        # load known issues
        self.known_issues = self.load_known_issues()

        # set callback for parallel calls
        putil.set_post_parallel(self._parallel_callback)

        # register for signal handlers
        self._handle_signals()

        # dump default arguments
        if not batch.is_worker():
            generate.defaults_report(self.logs_path)
            generate.devfeats_report(self.logs_path, self.wa.feature)

        # register context with batch
        batch.set_workarea(self)

        # nothing to do in batch master
        if batch.is_master():
            self.result = Result(self.file_prefix, False)
            return

        # handle need to just reboot all devices
        if cfg.rps_reboot:
            return

        # register worker with batch
        batch.worker_register(self)

        # create Result object
        self.result = Result(self.file_prefix)

        # load the topology
        has_non_scapy = self._load_topo()
        if self.cfg.filemode and has_non_scapy and self.cfg.dryrun != 2:
            self.skip_tgen = True
        tgapi.init_tgen(self.wa, self.log, self.skip_tgen)

        # create net module and register devices
        self.net = Net(self.cfg, self.file_prefix, self.log, self._tb)
        self.net.set_workarea(self.wa)
        self.log.warning("Registering Topology")
        self.net.register_devices(self.topo)

        # move the connect to session init
        wa._context = self
        wa.net = self.net
        set_work_area(wa)
        self._connect()

        # verify the build url
        for dut in self.topo.duts:
            if self.cfg.filemode:
                continue
            if self.wa.get_cfg_load_image(dut) == "none":
                continue
            errmsg = self.wa._verify_build_url_dut(dut)[0]
            if errmsg:
                global_abort_run(2, errmsg)

        # simulate node dead and excluded in session init
        batch.simulate_deadnode(0)
        for dut in self.topo.duts:
            batch.simulate_deadnode(3, dut=dut)

        # copy testbed files
        testbed_info = "{0}_{1}".format(self.file_prefix, "testbed_info.txt")
        with open(os.path.join(self.logs_path, testbed_info), "w") as ofh:
            for filepath in self._tb.get_all_files():
                ofh.write("########## {} ##########".format(filepath))
                with open(filepath) as ifh:
                    for line in ifh:
                        ofh.write(line)
                ofh.write("###################################")

        # report missing test cases
        missing_tests = "{0}_{1}".format(self.file_prefix, "missing_tests.txt")
        with open(os.path.join(self.logs_path, missing_tests), "w") as ofh:
            ofh.write(missing_test_names_msg)

        stats_csv = paths.get_stats_csv(self.logs_path)
        Result.write_report_csv(stats_csv, [], ReportType.STATS, is_batch=False)
        msysinfo_csv = paths.get_msysinfo_csv(self.logs_path)
        Result.write_report_csv(msysinfo_csv, [], ReportType.MSYSINFO, is_batch=False)
        fsysinfo_csv = paths.get_fsysinfo_csv(self.logs_path)
        Result.write_report_csv(fsysinfo_csv, [], ReportType.FSYSINFO, is_batch=False)
        dsysinfo_csv = paths.get_dsysinfo_csv(self.logs_path)
        Result.write_report_csv(dsysinfo_csv, [], ReportType.DSYSINFO, is_batch=False)
        coverage_csv = paths.get_coverage_csv(self.logs_path)
        Result.write_report_csv(coverage_csv, [], ReportType.COVERAGE, is_batch=False)
        scale_csv = paths.get_scale_csv(self.logs_path)
        Result.write_report_csv(scale_csv, [], ReportType.SCALE, is_batch=False)
        featcov_csv = paths.get_featcov_csv(self.logs_path)
        Result.write_report_csv(featcov_csv, [], ReportType.FEATCOV, is_batch=False)
        utils.delete_file(paths.get_stats_txt(self.logs_path))
        utils.delete_file(os.path.join(self.logs_path, "node_dead"))

    def read_testbed_file(self):
        try:
            self._tb = Testbed(self.cfg.testbed, self.log, self.cfg)
            self.topo_str = "Topology {}: {}".format(self._tb.get_name(), self._tb.get_topo())
            return None
        except Exception:
            return utils.stack_trace(None, True)

    def load_known_issues(self):
        known_issues = []
        for fpath in self.cfg.known_issues:
            if not os.path.exists(fpath):
                msg = "Error: know issues file {} is not found".format(fpath)
                self.log.error(msg)
                global_abort_run(2, msg)
            with open(fpath, 'r') as fd:
                for row in csv.reader(fd):
                    if not row or row[0].startswith("#"):
                        continue
                    issue, tc = row[0], row[1]
                    desc = ",".join(row[2:])
                    known_issues.append([tc, desc, issue])
                fd.close()
        return known_issues

    def get_known_issue(self, func, tcid, desc):
        for row in self.known_issues:
            if tcid == row[0] and desc == row[1]:
                return row[2]
        for row in self.known_issues:
            if func == row[0] and desc == row[1]:
                return row[2]
        return ""

    def log_verion_info(self, dst=None):
        self.log.notice(self.version_msg, dst=dst)
        self.log.notice(self.hostname, dst=dst)
        self.log.notice(self.root_path, dst=dst)
        self.log.notice("Python: {}".format(self.pyver), dst=dst)
        if self.topo_str:
            self.log.notice(self.topo_str, dst=dst)
        if self.wa and self.wa.swver:
            ver_dut_map = utils.invert_dict(self.wa.swver)
            for ver, dut in ver_dut_map.items():
                self.log.notice("SOFTWARE Version {} = {}".format(dut, ver), dst=dst)
            ver_dut_map = utils.invert_dict(self.wa.hwsku)
            for ver, dut in ver_dut_map.items():
                self.log.notice("HARDWARE SKU {} = {}".format(dut, ver), dst=dst)
        suite_args = env.get("SPYTEST_SUITE_ARGS", "")
        if suite_args:
            self.log.debug("\nSUITE ARGS: {}\n".format(suite_args), dst=dst)
        self.log.notice(self.cmdline_args, dst=dst)

    def register_cleanup(self, func, *args, **kwargs):
        self.cleanup_calls.append([func, copy.copy(args), copy.copy(kwargs)])

    def _cleanup_gracefully(self):
        self._cleanup_registered()
        if not self.shutting_down:
            self.shutting_down = True
            atexit._run_exitfuncs()
            putil.set_shutting_down()
            self._disconnect()
            self._tgen_close()
            batch.shutdown()

    def _cleanup_registered(self):
        for func, args, kwargs in self.cleanup_calls:
            try:
                func(*args, **kwargs)
            except Exception:
                pass

    def _exit_gracefully(self, signum, frame):
        if self.cfg.graceful_exit:
            ident = self.worker_id or ""
            msg = "{} shutting down - signal {}".format(ident, signum)
            self.log.warning(msg)
            self._cleanup_gracefully()
            time.sleep(2)
            global_abort_run(0, msg)
        else:
            self._cleanup_registered()

    def _handle_signals(self):
        signal.signal(signal.SIGINT, self._exit_gracefully)
        signal.signal(signal.SIGTERM, self._exit_gracefully)

    def log_time(self, name, mode="a"):
        filepath = "{}_time.log".format(self.file_prefix)
        msg = "{} = {}\n".format(get_timenow(), name)
        utils.write_file(filepath, msg, mode)

    def _init_log_path(self, prefix="results"):
        self.file_prefix = env.get("SPYTEST_FILE_PREFIX")
        if not self.file_prefix:
            if self.cfg.filemode:
                # for file mode overwrite the existing log file
                self.file_prefix = "{0}".format(prefix)
            else:
                self.file_prefix = "{0}_{1}".format(
                    prefix, time.strftime("%H_%M_%m_%d_%Y"))
        if batch.is_master():
            self.file_prefix = os.path.join(self.logs_path, "master", self.file_prefix)
        else:
            self.file_prefix = os.path.join(self.logs_path, self.file_prefix)
        self.wa.file_prefix = self.file_prefix

    def _log_init(self):
        self._init_log_path()
        lvl_name = env.get("SPYTEST_LOGS_LEVEL", "info").lower()
        if lvl_name == "debug":
            lvl = logging.DEBUG
        elif lvl_name == "warn":
            lvl = logging.WARN
        elif lvl_name == "error":
            lvl = logging.ERROR
        elif lvl_name == "notice":
            lvl = LEVEL_NOTICE
        else:
            lvl = logging.INFO
        session_log_name = paths.get_session_log_name()
        self.log = Logger(self.file_prefix, session_log_name, level=lvl)
        self.log_time("START", "w")

    def _load_topo(self):
        duts = OrderedDict()
        links = OrderedDict()
        for dut in self._tb.get_device_names("DUT"):
            duts[dut] = self._tb.get_dut_access(dut)
        tgens = OrderedDict()
        has_non_scapy = False
        for tgen_name in self._tb.get_device_names("TG"):
            tgen_dict = self._tb.get_tg_info(tgen_name)
            if not tgen_dict:
                continue
            tgen_ports = list()
            tgen_links = self._tb.get_links(tgen_name)
            for linkElem in tgen_links:
                port = linkElem[0]
                tgen_ports.append(port)
            tgen_dict['ports'] = tgen_ports
            tgens[tgen_name] = tgen_dict
            if tgen_dict["type"] != "scapy":
                has_non_scapy = True
                continue
            filepath = os.path.join(self.logs_path, "tgen.txt")
            utils.write_file(filepath, str(tgen_dict['ip']))
            self.log.info("TGEN-IP {}".format(str(tgen_dict['ip'])))
        self.topo = SpyTestDict()
        self.topo.duts = duts
        self.topo.links = links
        self.topo.tgens = tgens
        return has_non_scapy

    def _tgen_close(self):
        failures = tgapi.close_tgen()
        return False if failures and not self.skip_tgen else True

    # phase 0: session create 1: session init 2: reinit
    def _tgen_init(self, phase):
        failures = False
        for tgen_dict in self.topo.tgens.values():
            if not tgapi.load_tgen(tgen_dict, phase):
                failures = True
        return False if failures and not self.skip_tgen else True

    def _tgen_instrument(self, phase, data):
        if not batch.is_infra_test(data):
            tgapi.instrument_tgen(phase, data)

    def _parallel_callback(self, **kwargs):
        # self.wa.log("Parallel Operation Complete")
        pass

    def abort_run(self, code, reason, hang, line=None):
        if self.cfg.gcov == 1:
            phase = "session"
        elif self.cfg.gcov == 2:
            phase = "module"
        else:
            phase = None
        if self.wa.session_init_completed and not hang and phase:
            if not putil.wait_for_parallel():
                self.wa.error("Timed out waiting for threads to complete")
                self.wa.error(" TRY GCOV data collection anyway")
            self.wa._fetch_gcov_files(None, phase)
        line = line or utils.get_line_number(1)
        self.wa.log("--FINISH--RUN--{} @{}".format(code, line))
        global_abort_run(code, reason)

    def ensure_tgen(self, tg_ret, tg_exp, logger, ignore=False):
        if tg_ret and tg_exp is None:
            return
        if tg_exp is not None:
            for msg in utils.stack_trace(tg_exp):
                if "DeprecationWarning" in msg:
                    ignore = True
                    logger.warning(msg, split_lines=True)
                else:
                    logger.error(msg, split_lines=True)
        msg = "Failed to connect TGEN devices in topology"
        if not ignore:
            logger.error(msg)
            self.abort_run(5, msg, False)
        logger.warning(msg)

    def _connect(self):
        self.log.info("Connecting all devices")
        funcs = [
            [self._tgen_init, 0],
            [self.net.connect_all_devices, self.cfg.faster_init, "trace"]
        ]
        self.log_time("device connections start")
        [rv1, rv2], [e1, e2] = putil.exec_all2(self.cfg.faster_init, "trace",
                                               funcs, True)[:2]
        self.log_time("device connections finish")
        if rv2 or e2 is not None:
            if rv2:
                msg2 = "Failed to connect ({})".format(rv2)
            else:
                msg2 = "Failed to connect one or more devices in topology"
            self.log.error(msg2)
            if e2 is not None:
                for msg in utils.stack_trace(e2):
                    self.log.error(msg, split_lines=True)
            self.abort_run(4, msg2, False)
        self.ensure_tgen(rv1, e1, self.log)

    def _disconnect(self):
        if not self.net:
            return
        self.log.warning("Unregistering Topology")
        try:
            self.net.unregister_devices()
        except Exception:
            pass

    def email(self, subject=None):
        filepath = os.path.join(self.logs_path, "build.txt")
        daily_run = env.getint("SPYTEST_DAILY_RUN", "0")
        test_suite = env.get("SPYTEST_SUITE_NAME_ARG", "")
        daily_run = 1 if bool(daily_run or test_suite) else 0
        gcov_run = 0 if not self.cfg.gcov else 1
        end_time = get_timenow()
        start_time = self.execution_start_time
        time_taken = get_elapsed(start_time, True, end=end_time)
        combinedReport = env.get("SPYTEST_GENERATE_COMBINED_REPORT", "0")
        image_build_path = env.get("SPYTEST_IMAGE_BUILD_PATH", "")
        if image_build_path:
            try:
                image_build_path = os.path.realpath(image_build_path)
            except Exception:
                pass

        date = self.execution_start_time.strftime('%b-%d')

        jobid = env.get("SPYTEST_JENKINS_JOB", "").upper()
        chip = env.get("SPYTEST_JENKINS_CHIP", "").upper()
        phase = env.get("SPYTEST_JENKINS_PHASE", "").upper()
        executed = env.get("SPYTEST_CURRENT_TOTAL_EXECUTED", "")
        pass_cnt = env.get("SPYTEST_CURRENT_TOTAL_PASS_CNT", "")
        passrate = env.get("SPYTEST_CURRENT_TOTAL_PASSRATE", "")

        bldver = mail_build
        bldver = bldver.replace("SONiC-OS-", "")
        bldver = bldver.replace("-Enterprise_Base", "")
        bldver = bldver.replace("_daily", "")

        tgen = env.get("SPYTEST_JENKINS_TGEN", "").upper()
        mail_subject = subject or self.cfg.email_subject
        mail_subject = utils.j2_apply(mail_subject, job=jobid, chip=chip,
                                      phase=phase, build=mail_build, date=date, uitype=self.cfg.ui_type,
                                      executed=executed, pass_cnt=pass_cnt, passrate=passrate, tgen=tgen,
                                      pyver=self.pyver, bldver=bldver, ifname_type=self.cfg.ifname_type)

        uncovered_platforms = env.get("SPYTEST_UNCOVERED_PLATFORMS", "")
        uncovered_chips = env.get("SPYTEST_UNCOVERED_CHIPS", "")
        build_info = textwrap.dedent("""\
            build: {0}
            uitype: {1}
            Execution Started: {2}
            Execution Completed: {3}
            Execution Time: {4}
            DailyRun: {5}
            Python: {6}
            Combined Report: {7}
            GCOV Run: {8}
            Image Build Path: {9}
            EMail: {10}
            EMailSubject: {11}
            Dry Run: {12}
            GCOV_POST_RUN_KPI_UPDATE: {13}
            GCOV_MERGE_HTML: {14}
            Pass Rate: {15}
            Suite: {16}
            Platforms Not Covered: {17}
            Chips Not Covered: {18}
        """.format(mail_build, self.cfg.ui_type, start_time, end_time,
                   time_taken, daily_run, self.pyver, combinedReport,
                   gcov_run, image_build_path, self.cfg.email_csv,
                   mail_subject, (1 if self.cfg.filemode else 0),
                   env.get("SPYTEST_GCOV_POST_RUN_KPI_UPDATE", "0"),
                   env.get("SPYTEST_GCOV_MERGE_HTML", "0"), passrate,
                   test_suite, uncovered_platforms, uncovered_chips
                   ))
        utils.write_file(filepath, build_info)

        if not self.cfg.email_csv or env.get("SPYTEST_EMAIL_SUPPORT", "1") == "0":
            return

        is_master, is_html, add_png, dead = batch.is_master(), True, False, 0
        if is_master:
            dead = batch.get_dead_member_count()

        body_lines = [self.version_msg, self.root_path, self.hostname]
        body_lines.append("Python: {}".format(self.pyver))
        body_lines.append("Build: {}".format(mail_build))
        body_lines.append("Run Time: {}".format(time_taken))
        body_lines.append("UI: {}".format(self.cfg.ui_type))
        body_lines.append("Suite: {}".format(test_suite))
        body_lines.append("Platforms Not Covered: {}".format(uncovered_platforms))
        body_lines.append("Chips Not Covered: {}".format(uncovered_chips))
        prefix = env.get("SPYTEST_EMAIL_BODY_PREFIX", "")
        if prefix:
            body_lines.insert(0, prefix)
        if combinedReport and combinedReport != "0":
            body_lines.append("Combined Report: {}".format(combinedReport))
        if dead:
            body_lines.append("Dead: {}".format(dead))
        if is_html:
            body_lines = ["<br/>{}".format(line) for line in body_lines]
        body = "\n".join(body_lines)

        attchments = []
        if self.cfg.email_attachments:
            tc_results_csv = paths.get_tc_results_csv(self.logs_path, is_master)
            if os.path.exists(tc_results_csv):
                attchments.append(tc_results_csv)
                tc_results_htm = paths.get_tc_results_htm(self.logs_path, is_master)
                if os.path.exists(tc_results_htm):
                    attchments.append(tc_results_htm)
                tc_results_png = paths.get_tc_results_png(self.logs_path, is_master)
                if add_png and os.path.exists(tc_results_png):
                    attchments.append(tc_results_png)
            results_csv = paths.get_results_csv(self.logs_path, is_master)
            if os.path.exists(results_csv):
                attchments.append(results_csv)
                results_htm = paths.get_results_htm(self.logs_path, is_master)
                if os.path.exists(results_htm):
                    attchments.append(results_htm)
                results_png = paths.get_results_png(self.logs_path, is_master)
                if add_png and os.path.exists(results_png):
                    attchments.append(results_png)
                modules_htm = paths.get_modules_htm(self.logs_path, is_master)
                if os.path.exists(modules_htm):
                    attchments.append(modules_htm)

        ###################################################
        # build mail body from report files
        ###################################################
        features_htmls = []
        features_htmls.append(paths.get_features_summary_htm(self.logs_path, is_master))
        features_htmls.append(paths.get_features_htm(self.logs_path, is_master))
        if tcmap.get_current_releases() is not None:
            features_htmls.append(paths.get_new_features_htm(self.logs_path, is_master))
            features_htmls.append(paths.get_regression_features_htm(self.logs_path, is_master))
        for name in self.cfg.sub_report.keys():
            features_htm = paths.get_features_htm(batch.sub_report_path(self.logs_path, name), is_master)
            features_htmls.append(features_htm)

        # add feature reports
        for features_htm in features_htmls:
            body = append_email_body(body, features_htm)

        # add summary report
        if env.get("SPYTEST_EMAIL_RUN_SUMMARY", "0") != "0":
            reports_htm = paths.get_summary_htm(self.logs_path, is_master)
            body = append_email_body(body, reports_htm)

        # add module report
        reports_htm = paths.get_modules_htm(self.logs_path, is_master)
        mini_reports_htm = reports_htm.replace(".html", "-mini.html")
        body = append_email_body(body, mini_reports_htm)

        # get the services for first DUT for SMTP details
        first_dut = None
        for dut in self._tb.get_device_names("DUT"):
            first_dut = dut
            break
        # ftrace("mail body '{}'".format(body))
        server = self._tb.get_service(first_dut, "smtp")
        mailcfg = SpyTestDict({
            "recipients": self.cfg.email_csv,
            "subject": mail_subject,
            "body": body,
            "server": server
        })

        self.result.email(mailcfg, attchments, is_html)

    def set_default_error(self, res, msgid, *args):
        self.result.set_default_error(res, msgid, *args)

    def report_tc(self, tcid, res, msgid, *args):
        try:
            desc = self.result.build_msg(msgid, *args)
        except Exception as e:
            desc = "Invalid error code {} : {}".format(msgid, e)
            res = "Fail"
        self.tc_results[tcid] = (res, desc)
        return res, desc

    def _report(self, res, msgid, *args):
        if item_utils.has_marker(current_test.nodeid, "must_fail"):
            res = "Fail" if res in ["Pass"] else "Pass"
        retval = self.result.set(res, msgid, *args)
        msg = "Report({}):{}: {}".format(res, get_current_nodeid(), retval)
        if self.last_report_line is not None:
            msg = "{} @{}".format(msg, self.last_report_line)
        self.log.info("========= {} =========".format(msg))
        set_current_result(res, retval)
        return retval

    def publish2(self, nodeid, func, tcid, time_taken, comp=None,
                 result=None, desc=None, rtype="Executed"):
        if batch.is_infra_test(nodeid):
            return False
        if not comp and func and func in selected_test_results:
            if selected_test_results[func] is not None:
                return False

        syslogs = self.net.get_syslogs()
        fcli = self.net.get_fcli()
        tryssh = self.net.get_tryssh()
        dut_list = self._tb.get_device_names("DUT")
        models = self._tb.get_device_models("DUT")
        chips = self._tb.get_device_chips("DUT")
        _, desc_def = self.result.get()
        knownIssue = self.get_known_issue(func, tcid, desc or desc_def)
        try:
            doc = utils.get_doc_string(item_utils.find(func).function)[1]
        except Exception:
            doc = ""
        res = self.result.publish(nodeid, func, tcid, time_taken, comp, result,
                                  desc, rtype, syslogs, fcli, tryssh, dut_list,
                                  models, chips, knownIssue, doc)
        if not comp and func:
            selected_test_results[func] = res["Result"]
            self.all_tc_executed = self.all_tc_executed + 1
        # item = item_utils.find(func)
        # if item:
            # if "TimeTaken" not in res:
            # res["TimeTaken"] = "0:00:00"
            # row = ["", res["Module"], func, res["Result"], res["TimeTaken"],
            # res["ExecutedOn"], res["Description"]]
            # item.user_properties.append(row)
        if not self.worker_id:
            self.run_progress_report(self.all_tc_executed)
        return True

    def publish(self, nodeid, func, time_taken):
        if not self.publish2(nodeid, func, None, time_taken):
            return
        tclist = tcmap.get_tclist(func)
        # self.log.info("publish {} FUNC={} TCLIST={} RES={}".format(nodeid, func, tclist, self.tc_results))
        if not tclist:
            self.publish2(nodeid, func, func, "0:00:00",
                          "==UNKNOWN==", None, None, "NotMapped")

        for tcid in tclist:
            if env.get("SPYTEST_REPEAT_MODULE_SUPPORT") == "0":
                tcid1 = tcid
            else:
                try:
                    tcid1 = tcid.split("[")[0]
                except Exception:
                    tcid1 = tcid
            if tcid1 not in self.tc_results:
                comp = tcmap.get_comp(tcid)
                self.publish2(nodeid, func, tcid, "0:00:00",
                              comp, None, None, "Mapped")
        for tcid in self.tc_results.keys():
            res, desc = self.tc_results[tcid]
            if env.get("SPYTEST_REPEAT_MODULE_SUPPORT") != "0":
                try:
                    tcid = "{}[{}]".format(tcid, re.split(r"\[|\]", func)[1])
                except Exception:
                    pass
            comp = tcmap.get_comp(tcid) or tcmap.get_comp(func)
            if not comp:
                continue
            self.publish2(nodeid, func, tcid, "0:00:00", comp,
                          res, desc, "SubTest")

    def run_progress_report(self, executed):
        if executed < 1 or self.cfg.run_progress_report < 1:
            return
        if not self.sent_first_progress:
            subject = "Progress(First) - "
        else:
            subject = "Progress({}) - ".format(executed)
        subject = subject + self.cfg.email_subject
        if self.cfg.run_progress_report == 1 or not self.sent_first_progress:
            self.email(subject)
            self.sent_first_progress = True
        elif (executed % self.cfg.run_progress_report) == 0:
            self.email(subject)

    def is_feature_supported(self, name, dut=None):
        return self.wa.feature.is_supported(name, dut)


class WorkArea(object):

    def __init__(self, cfg):
        """
        Construction of WorkArea object
        :param cfg:
        :type cfg:
        """
        self.cli_records = OrderedDict()
        self.modules_completed = []
        if env.get("SPYTEST_APPLY_BASE_CONFIG_AFTER_MODULE", "0") != "0":
            self.apply_base_config_after_module = True
        else:
            self.apply_base_config_after_module = False
        self.sysinfo = OrderedDict()
        self.sysinfo_logs = dict()
        self.dmaps = dict()
        self.app_vars = dict()
        self.cache = dict()
        self.cli_type_cache = OrderedDict()
        self.module_info = dict()
        self.module_vars = dict()
        self.dut_ui_type = dict()
        self._context = None
        self.file_prefix = None
        self.all_ports = OrderedDict()
        self.alt_port_names = OrderedDict()
        self.native_port_names = OrderedDict()
        self.connected_ports = OrderedDict()
        self.reserved_ports = OrderedDict()
        self.free_ports = OrderedDict()
        self.pending_image_load = dict()
        self.swver = OrderedDict()
        self.hwsku = OrderedDict()
        self.cfg = cfg
        self.dut_cfg = {}
        self.hooks = apis_register()
        self.session_init_completed = False
        self.current_tc_start_time = None
        self.abort_module_msg = None
        self.abort_module_res = None
        self.abort_function_msg = None
        self.ignore_post_function_epilog = False
        self.module_log_mode = {}
        self.skips = {}
        self.module_tc_executed = 0
        self.verify_csv_min_topo = env.getint("SPYTEST_VERIFY_CSV_MIN_TOPOLOGY", "0")
        self.data_lock = threading.Lock()
        set_work_area(self)
        self._context = Context(self, cfg)
        self.net = self._context.net
        self.last_error = None
        if env.get("SPYTEST_TRACE_API_CALLS", "0") != "0":
            apis_trace_register(self.api_trace_func, None)

        # RPS REBOOT
        if cfg.rps_reboot:
            if cfg.rps_reboot == "__all__":
                devices = self.get_dut_names()
            else:
                devices = utils.split_byall(cfg.rps_reboot, True)
            devlist = []
            for d in self.get_dut_names():
                dinfo = self._context._tb.get_device_info(d)
                if d in devices or dinfo.alias in devices:
                    devlist.append(d)

            _, exps, threads = self._foreach(devlist, self.do_rps, "reset", recon=False)
            msg = "exception doing RPS reboot"
            self._check_exceptions(devlist, msg, exps, threads, False)
            global_abort_run(1, msg)

        self.base_config_verified = False
        self.module_tc_fails = 0
        self.module_get_tech_support = False
        self.module_fetch_core_files = False
        self.module_tscount = {}
        self.min_topo_called = False
        self.tgen_reconnect = False

    def __del__(self, name=None):
        if self._context:
            self._context._disconnect()
            self._context._tgen_close()

    def _init_features(self):
        self.feature = self.hooks.init_features(self.cfg.feature_group,
                                                self.cfg.feature_enable,
                                                self.cfg.feature_disable)
        self.support = self.hooks.init_support(self.cfg)

    def api_trace_func(self, event, data, fpath, func, *args, **kwargs):
        self.data_lock.acquire()
        self.debug(">>> {}::{}".format(fpath, utils.logcall(func, *args, **kwargs)))
        self.data_lock.release()

    def abort_run(self, code, reason, hang=False, line=None):
        line = line or utils.get_line_number(1)
        self._context.abort_run(code, reason, hang, line)

    def abort_module(self, msgid, *args, **kwargs):
        self.last_error = kwargs.get("type", "fail")
        self.clear_last_report_line()
        support = kwargs.get("support", True)
        desc = self._report("", self.last_error, msgid, *args, support=support)
        self.report_pdb()
        self.abort_module_msg = desc
        self.abort_module_res = self.last_error
        self.pytest_skip(desc)

    def set_node_dead(self, dut, reason, hang):
        # removed as requested by regression team on 23-Feb-21 1.13AM IST
        # logs_path = _get_logs_path()[1]
        # file_path = os.path.join(logs_path, "node_dead")
        # utils.write_file(file_path, " " + dut, "a")
        if hang:
            if dut:
                msg = "Console hang ({}): {}".format(dut, reason)
            else:
                msg = "Console hang: {}".format(reason)
            self.abort_run(15, msg, hang)
        else:
            self.abort_run(15, reason, hang)

    def _foreach(self, items, func, *args, **kwargs):
        return putil.exec_foreach2(self.cfg.faster_init, "trace", items,
                                   func, *args, **kwargs)

    def _foreach_dev(self, func, *args, **kwargs):
        return self._foreach(self.get_dut_names(), func, *args, **kwargs)

    def is_dry_run(self):
        return self.cfg.filemode

    def is_batch_run(self):
        return batch.is_batch()

    def get_run_arg(self, name, default=None):
        return self.cfg.get(name, default)

    def _is_save_cli_types(self):
        return bool(env.get("SPYTEST_SAVE_CLI_TYPE", "1") != "0")

    def _is_save_cli_cmds(self):
        return bool(env.get("SPYTEST_SAVE_CLI_CMDS", "1") != "0")

    def is_supported_device(self, dut):
        if self.is_sonic_device(dut):
            return True
        if self.is_any_fastpath_device(dut):
            return True
        if self.is_linux_device(dut):
            return True
        return False

    def is_sonic_device(self, dut):
        return self.net.is_sonic_device(dut)

    def is_any_fastpath_device(self, dut):
        return self.net.is_any_fastpath_device(dut)

    def is_linux_device(self, dut):
        return self.net.is_linux_device(dut)

    def is_sonicvs(self, dut=None):
        if not dut:
            dut = self.get_dut_names()[0]
        return self.net.is_sonicvs_device(dut)

    def is_vsonic(self, dut=None):
        if not dut:
            dut = self.get_dut_names()[0]
        return self.net.is_vsonic_device(dut) or \
            self.get_dut_var(dut, "is_vsonic", False)

    def is_soft_tgen(self, vars=None):
        return tgapi.is_soft_tgen(vars)

    def is_valid_base_config(self):
        return bool(self.cfg.skip_load_config not in ["base"])

    def get_logs_path(self, for_file=None, subdir=None):
        logs_path = _get_logs_path()[1]
        if subdir:
            logs_path = os.path.join(logs_path, subdir)
        if for_file:
            for_file = "{0}_{1}".format(self.file_prefix, for_file)
        return os.path.join(logs_path, for_file) if for_file else logs_path

    def profiling_start(self, msg, max_time, skip_report=False):
        return self.net.profiling_start(msg, max_time, skip_report)

    def profiling_stop(self, pid):
        return self.net.profiling_stop(pid)

    def _no_print(self, msg):
        pass

    def banner(self, msg, width=80, delimiter="#", wrap=True, tnl=True, lnl=True, dut=None):
        content = utils.banner(msg, width, delimiter, wrap, self._no_print, tnl, lnl)
        self.log(content, dut=dut, split_lines=True)
        return content

    def debug(self, msg, dut=None, split_lines=False, dst=None):
        self.log_lvl(logging.DEBUG, msg, dut, split_lines, dst)

    def event(self, *args):
        msg = ""
        for arg in args:
            msg = msg + " " + str(arg)
            msg = msg.strip()
        msg = "\n================== {} ==================".format(msg)
        msg2 = self.hooks.audit("event", None, msg, dst="audit")
        if not msg2:
            self.log(msg)

    def log_time(self, name):
        self._context.log_time(name)

    def log_lvl(self, lvl, msg, dut=None, split_lines=False, dst=None):
        if dut:
            self.dut_log(dut, msg, lvl, dst=dst, split_lines=split_lines)
        elif self._context:
            self._context.log.log(lvl, msg, dut, dst=dst, split_lines=split_lines)

    def log(self, msg, dut=None, split_lines=False, dst=None, lvl=None):
        self.log_lvl(lvl or logging.INFO, msg, dut, split_lines, dst)

    def verbose(self, msg, dut=None, split_lines=True, dst=None):
        msg_list = msg.splitlines() if split_lines else [msg]
        for line in msg_list:
            line = "[{}] : {}".format(dut, line) if dut else line
            ftrace(line)

    def exception(self, msg, dut=None, split_lines=True):
        self._context.log.exception(msg, dut, split_lines)

    def warn(self, msg, dut=None, split_lines=False, dst=None):
        self.log_lvl(logging.WARNING, msg, dut, split_lines, dst)

    def error(self, msg, dut=None, split_lines=False, dst=None):
        self.log_lvl(logging.ERROR, msg, dut, split_lines, dst)

    def notice(self, msg, dut=None, split_lines=False, dst=None):
        self.log_lvl(LEVEL_NOTICE, msg, dut, split_lines, dst)

    def topo_debug(self, msg, dut=None, split_lines=False, dst=None):
        self.log_lvl(LEVEL_TOPO, msg, dut, split_lines, dst)

    def topo_error(self, msg, dut=None, split_lines=False, dst=None):
        self.log_lvl(LEVEL_TOPO, msg, dut, split_lines, dst)

    def audit(self, msg, split_lines=False, audit_only=False):
        dst = ["audit"] if audit_only else None
        return self._context.log.audit(msg, split_lines, dst=dst) if msg else ""

    def dut_log(self, dut, msg, lvl=logging.INFO, cond=True,
                dst=["all", "dut"], split_lines=True):
        if not self.net:
            return self._context.log.log(lvl, msg, split_lines=split_lines, dst=dst)
        for d in utils.make_list(dut):
            try:
                self.net.dut_log(d, msg, lvl, cond, dst, split_lines=split_lines)
            except Exception:
                self._context.log.log(lvl, "{}:{}".format(d, msg),
                                      split_lines=split_lines, dst=dst)

    def alert(self, msg, type="", lvl=logging.ERROR, skip_log=True):
        worker_id = batch.get_worker_id() or ""
        m = "#### {} {} {}".format(worker_id, type, get_current_nodeid())
        list2 = utils.make_list(m, msg)
        self._context.log.alert(list2, lvl=lvl)
        if not skip_log:
            for this_msg in utils.make_list(msg):
                self.error(this_msg)

    def wait(self, val, msg=None, dut=None):
        line = utils.get_line_number(2)
        if msg:
            self.log("Sleep for {} sec(s)...{} @{}".format(val, msg, line), dut=dut)
        else:
            self.log("Sleep for {} sec(s)... @{}".format(val, line), dut=dut)
        self.net.wait(val)

    def tg_wait(self, val, msg=None):
        if self.is_soft_tgen():
            multiplier = env.get("SPYTEST_SOFT_TGEN_WAIT_MULTIPLIER", "2")
            multiplier = utils.integer_parse(multiplier, 2)
            val = val * multiplier
        if msg:
            self.log("TG Sleep for {} sec(s)...{}".format(val, msg))
        else:
            self.log("TG Sleep for {} sec(s)...".format(val))
        self._context.net.tg_wait(val)

    def get_ts_count(self, name):
        try:
            return self.module_tscount.get(name, 0)
        except Exception:
            return 0

    def fetch_support(self, dut, scope, res, desc, name):
        if dut is not None:
            msg = " ".join(["support", scope, name, res, "'{}'".format(desc)])
            if res.strip() in ["Pass", ""]:
                self.alert(msg, lvl=logging.INFO)
            else:
                self.alert(msg, lvl=logging.WARNING)
            module = paths.parse_nodeid(get_current_nodeid())[0]
            ts = tcmap.get_module_info(module).ts
            apis_instrument("fetch-support-start", dut=dut)
            self.support.fetch(dut, scope, res, desc, name, ts=ts)
            apis_instrument("fetch-support-end", dut=dut)
        else:
            apis_instrument(scope, res=res, desc=desc, name=name)
            self._foreach_dev(self.fetch_support, scope, res, desc, name)
            self._context._tgen_instrument(scope, name)

    def _report_tc(self, tcid, res, msgid, *args, **kwargs):
        abort = kwargs.get("abort", False)
        support = kwargs.get("support", True)
        res, desc = self._context.report_tc(tcid, res, msgid, *args)
        if support:
            self.fetch_support(None, "testcase", res, desc, tcid)
        if abort:
            self.pytest_xfail(desc)
        return desc

    def report_tc_pass(self, tcid, msgid, *args):
        self.set_last_report_line(None, 2)
        return self.report(msgid, *args, type="pass", tcid=tcid)

    def report_tc_fail(self, tcid, msgid, *args):
        self.set_last_report_line(None, 2)
        return self.report(msgid, *args, type="fail", tcid=tcid)

    def report_tc_unsupported(self, tcid, msgid, *args):
        self.set_last_report_line(None, 2)
        return self.report(msgid, *args, type="unsupported", tcid=tcid)

    def report_msg(self, msgid, *args):
        self.set_last_report_line(None, 2)
        msg, _ = self._context.result.msg(msgid, *args)
        line = utils.get_line_number(2)
        self._context.log.info("RMSG: {} @line {}".format(msg, line))
        return msg

    def _report(self, dut, res, msgid, *args, **kwargs):
        # for msg in utils.stack_trace(None, True): print_ftrace(msg)
        abort = kwargs.get("abort", False)
        support = kwargs.get("support", True)
        desc = self._context._report(res, msgid, *args)
        _, func = paths.parse_nodeid(current_test.nodeid)
        if dut and "result already set to" not in desc and support:
            self.fetch_support(dut, "function", res, desc, func)
        if abort:
            self.report_pdb()
            self.pytest_xfail(desc)
        return desc

    def report(self, msgid, *args, **kwargs):
        dut = kwargs.get("dut", None)
        rtype = kwargs.get("type", "fail")
        tcid = kwargs.get("tcid", None)
        support = kwargs.get("support", True)
        abort = bool(rtype not in ["pass"] and not tcid)
        abort = kwargs.get("abort", abort)

        if tcid:
            if rtype == "pass":
                return self._report_tc(tcid, "Pass", msgid, *args, abort=abort, support=support)

            if rtype == "unsupported":
                return self._report_tc(tcid, "Unsupported", msgid, *args, abort=abort, support=support)

            return self._report_tc(tcid, "Fail", msgid, *args, abort=abort, support=support)

        if rtype == "pass":
            self.last_error = None
            return self._report("", "Pass", msgid, *args, abort=abort, support=support)

        # collect the support data again
        self.ignore_post_function_epilog = False

        if rtype == "unsupported":
            self.last_error = "Unsupported"
            return self._report("", self.last_error, msgid, *args, abort=abort, support=support)

        if rtype == "env":
            self.last_error = "EnvFail"
            return self._report(dut, self.last_error, msgid, *args, abort=abort, support=support)

        if rtype == "topo":
            self.last_error = "TopoFail"
            return self._report("", self.last_error, msgid, *args, abort=abort, support=support)

        if rtype == "tgen":
            self.last_error = "TGenFail"
            return self._report(dut, self.last_error, msgid, *args, abort=abort, support=support)

        if rtype == "config":
            self.last_error = "ConfigFail"
            return self._report(dut, self.last_error, msgid, *args, abort=abort, support=support)

        if rtype == "timeout":
            self.last_error = "Timeout"
            return self._report("", self.last_error, msgid, *args, abort=abort, support=support)

        if rtype == "dutfail":
            self.last_error = "DUTFail"
            return self._report("", self.last_error, msgid, *args, abort=abort, support=support)

        if rtype == "script" or rtype == "scripterror":
            self.last_error = "ScriptError"
            return self._report("", self.last_error, msgid, *args, abort=abort, support=support)

        if rtype == "cmdfail":
            self.last_error = "CmdFail"
            return self._report("", self.last_error, msgid, *args, abort=abort, support=support)

        self.last_error = "Fail"
        return self._report("", self.last_error, msgid, *args, abort=abort, support=support)

    def report_pass(self, msgid, *args):
        self.set_last_report_line(None, 2)
        return self.report(msgid, *args, type="pass")

    def report_pdb(self):
        if self.cfg.pdb_on_error:
            pdb.set_trace()  # pylint: disable=forgotten-debug-statement
            HELP = " NOTE: execute 'up' command thrice to go to the failure line ==== "
            utils.unused(HELP)

    def report_env_fail_int(self, dut, abort, msgid, *args):
        return self.report(msgid, *args, type="env", dut=dut, abort=abort)

    def report_env_fail(self, msgid, *args):
        self.set_last_report_line(None, 2)
        return self.report_env_fail_int(None, True, msgid, *args)

    def report_timeout(self, msgid, *args):
        self.set_last_report_line(None, 2)
        return self.report(msgid, *args, type="timeout")

    def report_topo_fail(self, msgid, *args, **kwargs):
        lvl = kwargs.get("lvl", 2)
        self.set_last_report_line(None, lvl)
        return self.report(msgid, *args, type="topo")

    def tgen_ftrace(self, *args):
        ftrace("TGEN:", get_current_nodeid(), *args)

    def _ftrace(self, *args):
        ftrace(*args)

    def report_tgen_exception(self, ex):
        ignore = False
        for msg in utils.stack_trace(ex):
            if "DeprecationWarning" in msg:
                self.warn(msg, split_lines=True)
                ignore = True
            else:
                self.error(msg, split_lines=True)
        if not ignore:
            self.last_error = "TGenFail"
            self.clear_last_report_line()
            desc = self._report("", self.last_error, "tgen_exception", "{}".format(ex))
            self.report_pdb()
            self.pytest_skip(desc)

    def report_tgen_fail_int(self, dut, abort, msgid, *args):
        return self.report(msgid, *args, type="tgen", dut=dut, abort=abort)

    def report_tgen_fail(self, msgid, *args):
        return self.report_tgen_fail_int(None, True, msgid, *args)

    def report_tgen_abort(self, msgid, *args):
        self.last_error = "TGenFail"
        self.clear_last_report_line()
        desc = self._report("", self.last_error, msgid, *args)
        self.report_pdb()
        self.abort_module_msg = "TGen connection aborted"
        self.abort_module_res = self.last_error
        self.tgen_reconnect = True
        self.pytest_skip(desc)

    def set_thread_skip(self, value):
        try:
            self.skips[putil.get_thread_name()] = value
        except Exception as exp:
            print_ftrace(exp)

    def pytest_xfail(self, msg):
        abort_method = env.getint("SPYTEST_TEST_ABORT_METHOD", "4")
        if abort_method == 0:
            pytest.xfail(msg)
        elif abort_method == 1:
            pytest.exit(msg, returncode=1)
        elif abort_method == 2:
            try:
                pytest.xfail(msg)
            finally:
                raise ValueError(msg)
        elif abort_method == 3:
            try:
                pytest.xfail(msg)
            finally:
                pytest.exit(msg, returncode=1)
        elif abort_method == 4:
            self.set_thread_skip(1)
            pytest.xfail(msg)

    def pytest_skip(self, msg):
        abort_method = env.getint("SPYTEST_TEST_ABORT_METHOD", "4")
        if abort_method == 0:
            pytest.skip(msg)
        elif abort_method == 1:
            pytest.exit(msg, returncode=1)
        elif abort_method == 2:
            try:
                pytest.skip(msg)
            finally:
                raise ValueError(msg)
        elif abort_method == 3:
            try:
                pytest.skip(msg)
            finally:
                pytest.exit(msg, returncode=1)
        elif abort_method == 4:
            self.set_thread_skip(2)
            pytest.skip(msg)

    def report_fail_int(self, dut, abort, msgid, *args):
        return self.report(msgid, *args, type="fail", dut=dut, abort=abort)

    def report_fail(self, msgid, *args):
        self.set_last_report_line(None, 2)
        return self.report_fail_int(None, True, msgid, *args)

    def report_dut_fail_int(self, dut, abort, msgid, *args):
        return self.report(msgid, *args, type="dutfail", dut=dut, abort=abort)

    def report_dut_fail(self, msgid, *args):
        self.set_last_report_line(None, 2)
        return self.report_dut_fail_int(None, True, msgid, *args)

    def report_unsupported(self, msgid, *args):
        self.set_last_report_line(None, 2)
        return self.report(msgid, *args, type="unsupported")

    def report_scripterror(self, msgid, *args):
        self.set_last_report_line(None, 2)
        return self.report(msgid, *args, type="script", dut="", abort=True)

    def get_last_report_line(self):
        return self._context.last_report_line

    def clear_last_report_line(self):
        self._context.last_report_line = None

    def set_last_report_line(self, line, lvl=0):
        if line is None:
            self._context.last_report_line = utils.get_line_number(lvl + 1)
        else:
            self._context.last_report_line = line

    def report_cmd_fail_int(self, dut, abort, msgid, *args):
        return self.report(msgid, *args, type="cmdfail", dut=dut, abort=abort)

    def report_config_fail_int(self, dut, abort, msgid, *args):
        return self.report(msgid, *args, type="config", dut=dut, abort=abort)

    def report_config_fail(self, msgid, *args):
        self.set_last_report_line(None, 2)
        return self.report_config_fail_int(None, True, msgid, *args)

    def report_sysinfo(self, dut, scope, mem, cpu, output):
        self.sysinfo[dut][scope] = [mem, cpu]
        self.dut_log(dut, "sysinfo: {}".format(self.sysinfo[dut]))

        # save the output
        if dut in self.sysinfo_logs:
            file_path = self.sysinfo_logs[dut]
            utils.write_file(file_path, output, "w")
        else:
            file_path = self.net.make_local_file_path(dut, "", "all.log", "sysinfo")
            self.sysinfo_logs[dut] = file_path
            utils.write_file(file_path, output, "a")

    def report_scale(self, dut, name, value, platform=None, chip=None, module=None, func=None):
        scale_csv = paths.get_scale_csv(self._context.logs_path)
        platform = platform or self.app_vars.get(dut, {}).get("platform", "")
        chip = chip or self.app_vars.get(dut, {}).get("chip", "")
        version = self.app_vars.get(dut, {}).get("version", "")
        module0, func0 = paths.parse_nodeid(get_current_nodeid())
        module = module or module0 or ""
        func = func or func0 or ""
        row = ["", dut, name, value, platform, chip, version, module, func]
        Result.write_report_csv(scale_csv, [row], ReportType.SCALE, is_batch=False, append=True)

    def report_featcov(self, dut, name, value, platform=None, chip=None, module=None, func=None):
        featcov_csv = paths.get_featcov_csv(self._context.logs_path)
        platform = platform or self.app_vars.get(dut, {}).get("platform", "")
        chip = chip or self.app_vars.get(dut, {}).get("chip", "")
        version = self.app_vars.get(dut, {}).get("version", "")
        module0, func0 = paths.parse_nodeid(get_current_nodeid())
        module = module or module0 or ""
        func = func or func0 or ""
        row = ["", dut, name, value, platform, chip, version, module, func]
        Result.write_report_csv(featcov_csv, [row], ReportType.FEATCOV, is_batch=False, append=True)

    def set_default_error(self, res, msgid, *args):
        self._context.set_default_error(res, msgid, *args)

    def apply_script(self, dut, cmdlist):
        return self.net.apply_script(dut, cmdlist)

    def apply_json(self, dut, json, **kwargs):
        return self.net.apply_json(dut, json, **kwargs)

    def apply_json2(self, dut, json, **kwargs):
        return self.net.apply_json2(dut, json, **kwargs)

    def apply_files(self, dut, file_list, method="incremental"):
        return self.net.apply_files(dut, file_list, method)

    def run_script(self, dut, timeout, script_path, *args):
        return self.net.run_script(dut, timeout, script_path, *args)

    def clear_config(self, dut):
        retval_1 = self.hooks.clear_config(dut)
        if retval_1 is None:
            retval_1 = self.net.clear_config(dut)

        # wait for system ready
        retval_2 = self.wait_system_status(dut)

        if retval_1 and retval_2:
            return True
        return False

    def erase_config(self, dut, erase=True, reboot=True):
        return self.net.erase_config(dut, erase, reboot)

    def config_db_reload(self, dut, save=False, max_time=0):
        retval_1 = self.net.config_db_reload(dut, save, max_time=max_time)

        # wait for system ready
        retval_2 = self.wait_system_status(dut)

        if isinstance(retval_1, bool):
            if retval_1 and retval_2:
                return True
            return False
        return [retval_1, retval_2]

    def get_cfg_load_image(self, dut):
        if self.cfg.load_image == "testbed":
            load_image = self.get_device_param(dut, "load_image", "onie")
        else:
            load_image = self.cfg.load_image
        if load_image == "random":
            load_image = random.choice(load_image_types)
        return load_image

    def get_ifname_type(self, dut, oper=False):
        if oper:
            return self.hooks.get_ifname_type(dut)
        if self.cfg.ifname_type == "testbed":
            ifname_type = self.get_device_param(dut, "ifname_type", "native")
        else:
            ifname_type = self.cfg.ifname_type
        if ifname_type == "random":
            random_ifname_type = random.choice(["native", "alias", "std-ext"])
            dut_cfg = self.dut_cfg.setdefault(dut, {})
            if "ifname_type" not in dut_cfg:
                dut_cfg["ifname_type"] = random_ifname_type
                self.warn("Using ifname type = {}".format(random_ifname_type), dut=dut)
            ifname_type = self.dut_cfg[dut]["ifname_type"]
        if not self.is_feature_supported("intf-alias", dut) or not self.is_feature_supported("std-ext", dut):
            ifname_type = "native"
        if not self.is_feature_supported("ifname-type", dut):
            ifname_type = "native"
        return ifname_type

    def get_cfg_breakout_mode(self, dut):
        if self.cfg.breakout_mode == "testbed":
            breakout_mode = self.get_device_param(dut, "breakout_mode", "static")
        else:
            breakout_mode = self.cfg.breakout_mode
        if not self.is_feature_supported("dpb", dut):
            if breakout_mode == "native":
                breakout_mode = "static"
        return breakout_mode

    def upgrade_image(self, dut, url, skip_reboot=False, port_break=True,
                      port_speed=True, max_ready_wait=0, max_attempts=1,
                      method=None):
        ug_retval, pb_retval = False, True
        method = method or self.get_cfg_load_image(dut)
        if method in ["onie1", "onie2"]:
            ug_retval = self.net.upgrade_onie_image1(dut, url, max_ready_wait=max_ready_wait)
        elif method == "onie":
            ug_retval = self.net.upgrade_onie_image(dut, url, max_ready_wait=max_ready_wait)
        else:
            migrate = bool(method != "installer-without-migration")
            ug_retval = self.net.upgrade_image(dut, url, skip_reboot, migrate,
                                               max_ready_wait, max_attempts)
        if port_break or port_speed:
            pb_retval = self.set_port_defaults(dut, port_break, port_speed)

        # read app vars again
        self._read_vars(dut, "post image upgrade")

        return bool(ug_retval and (pb_retval or port_speed))

    def upgrade_libsai(self, dut):
        if self.cfg.libsai_url:
            self.hooks.upgrade_libsai(dut, self.cfg.libsai_url)
            self._read_vars(dut, "post libsai upgrade")
        return True

    def _read_vars(self, dut, phase):
        self.dmaps[dut] = dict()
        self.app_vars[dut] = self.hooks.get_vars(dut, phase)

    def reboot(self, dut, method=None, skip_port_wait=False,
               skip_exception=False, skip_fallback=False,
               ret_logs=False, abort_on_fail=False, **kwargs):

        kwargs.pop("internal", False)
        if dut is None:
            self.log("reboot all {}".format(self.cfg.faster_init))
            self._foreach_dev(self.reboot, method=method, skip_port_wait=skip_port_wait,
                              skip_exception=skip_exception, skip_fallback=skip_fallback,
                              ret_logs=ret_logs, internal=False, abort_on_fail=abort_on_fail, **kwargs)
        elif isinstance(dut, list):
            self.log("reboot: {}".format(",".join(dut)))
            self._foreach(dut, self.reboot, method=method, skip_port_wait=skip_port_wait,
                          skip_exception=skip_exception, skip_fallback=skip_fallback,
                          ret_logs=ret_logs, internal=False, abort_on_fail=abort_on_fail, **kwargs)
        else:
            self.report_featcov(dut, "reboot", method or "normal")
            output = self.net.reboot(dut, method=method, skip_port_wait=skip_port_wait,
                                     skip_exception=skip_exception, skip_fallback=skip_fallback,
                                     ret_logs=ret_logs, internal=False, abort_on_fail=abort_on_fail, **kwargs)
            return output

    def _apply_config_file_list(self, dut, files):
        for filename in utils.make_list(files):
            if not isinstance(filename, list):
                if filename == "__reboot__":
                    self.apply_files(dut, [filename])
                    continue
                file_path = self._context._tb.get_config_file_path(filename)
                if not file_path:
                    self.warn("failed to locate {}".format(filename))
                else:
                    self.apply_files(dut, [file_path], "full")
                continue
            # create new list with full paths
            inner_list = []
            for inner_list_file in filename:
                file_path = self._context._tb.get_config_file_path(inner_list_file)
                if not file_path:
                    self.warn("failed to locate {}".format(filename))
                else:
                    inner_list.append(file_path)
            if inner_list:
                self.apply_files(dut, inner_list, "full")

    def is_shutting_down(self):
        return self._context.shutting_down

    def wait_system_reboot(self, dut):
        return self._context.net.wait_system_reboot(dut)

    def _wait_post_system_ready(self):
        wait_post_system_ready = env.getint("SPYTEST_POST_SYSTEM_READY_WAIT", 0)
        if wait_post_system_ready > 0 and not self.is_dry_run():
            self.wait(wait_post_system_ready, "wait_post_system_ready")
        return True

    def _wait_for_ports(self, dut, max_time=0):
        if self.is_dry_run():
            return True
        if dut in self.all_ports:
            last_port = self.all_ports[dut][-1]
            t = time.time() + max_time
            self.dut_log(dut, "wait for last port {} creation".format(last_port))
            while 1:
                status = self.hooks.get_interface_status(dut, last_port)
                if status is not None:
                    return self._wait_post_system_ready()
                time.sleep(3)
                if time.time() > t:
                    break
            return False
        return self.net.apply_remote(dut, "wait-for-ports", [max_time])

    def wait_system_status(self, dut, max_time=0, lvl=0):
        if self.cfg.pde:
            return True

        line = utils.get_line_number(lvl + 1)
        msg = "Wait for system ready Ref: {}".format(line)
        self.dut_log(dut, msg, logging.DEBUG)

        max_time = max_time or self.cfg.port_init_wait
        if not self.is_feature_supported("system-status", dut):
            return self._wait_for_ports(dut, max_time)

        endtime = time.time() + max_time
        force_console = False
        while True:
            pending_image_load = self.pending_image_load.get(dut, False)
            kwargs = {"skip_error_check": True, "on_cr_recover": "ignore",
                      "expect_ipchange": force_console,
                      "pending_image_load": pending_image_load}
            kwargs.pop("pending_image_load")  # TODO
            rv = self.hooks.get_system_status(dut, **kwargs)
            if rv or self.is_dry_run():
                return self._wait_post_system_ready()
            if rv is None:
                # wait for ports when build has not support system-status
                return self._wait_for_ports(dut, max_time)
            if time.time() > endtime:
                break
            force_console = env.get("SPYTEST_SLOW_SYSTEM_STATUS_ON_CONSOLE", False)
            time.sleep(3)
        msg = "system is not online - waited for {} sec Ref: {}".format(max_time, line)
        self.dut_log(dut, msg, logging.WARNING)
        return False

    def is_tech_support_onerror(self, which):
        default = "system,port_list,port_status,console_hang,on_cr_recover"
        support = env.get("SPYTEST_TECH_SUPPORT_ONERROR", default)
        return bool(which in support.split(","))

    def _ensure_system_ready(self, dut, name):

        # handle request for all devices
        if dut is None:
            self._foreach_dev(self._ensure_system_ready, name)
            return

        # nothing to be ensured for non supported devices
        if not self.is_supported_device(dut):
            return

        # wait for system status
        if self.wait_system_status(dut, lvl=1):
            self.hooks.show_dut_time(dut)
            return

        # system not ready - collect debug information
        log_file = self.net.make_local_file_path(dut, prefix="debug-system-status", ext=".log")
        self.hooks.debug_system_status(dut, log_file)

        # system not ready - aborting current module
        self.abort_module_msg = " system status is not ready in time."
        msg = self.abort_module_msg + " Trying to recover the DUT with reboot."
        self.dut_log(dut, msg, logging.WARNING)

        # bailing out - collect the tech-support
        self.fetch_support(dut, "system-not-ready", "fail", msg, name)

        # recover the system by reboot - for next module
        recovery_methods = env.get("SPYTEST_SYSTEM_NREADY_RECOVERY_METHODS", "normal")
        for method in recovery_methods.split(","):
            msg = "Trying to recover using {} reboot".format(method)
            self.dut_log(dut, msg)

            # issue reboot
            rv = self.net.reboot(dut, method, skip_exception=True)
            if not rv:
                msg = "Failed to recover using {} reboot".format(method)
                self.dut_log(dut, msg, logging.ERROR)
                continue

            # reboot is successful - check system status
            msg = "Successfully {}-rebooted the DUT to recover.".format(method)
            msg = msg + " verifying if system status also ready."
            self.dut_log(dut, msg, logging.WARNING)
            rv = self.wait_system_status(dut, 10)
            if not rv:
                msg = "system status is not ready even after recovery using {} reboot".format(method)
                self.dut_log(dut, msg, logging.ERROR)
                continue

            # system is back online after recovery
            if self.session_init_completed:
                msg = "system status is ready after recovery."
                msg = msg + " abort current module and continue with next module"
                self.dut_log(dut, msg, logging.WARNING)
                self.report_dut_fail_int(dut, True, "system_status_not_ready")
            return self.hooks.show_dut_time(dut)

        # failed to recover devices - bailout the run
        msg = "system status is not ready in {} even after recovery - bailout run".format(dut)
        self.dut_log(dut, msg, logging.ERROR)
        self.abort_run(6, msg, False)

    def _fill_hooks_data(self, dut, phase):
        self._read_vars(dut, phase)
        self.swver[dut] = self.app_vars[dut].get("version", "unknown")
        self.hwsku[dut] = self.app_vars[dut].get("hwsku", "unknown")
        set_mail_build(self.swver[dut])

    def _noshutdown_connected(self, dut):
        if dut in self.connected_ports and self.connected_ports[dut]:
            msg = "noshutdown connected ports:{}".format(self.connected_ports[dut])
            self.dut_log(dut, msg, logging.INFO)
            self.hooks.noshutdown(dut, self.connected_ports[dut])

    def _shutdown_reserved_and_free(self, dut):
        ports = []
        if dut in self.reserved_ports and self.reserved_ports[dut]:
            msg = "shutdown reserved ports:{}".format(self.reserved_ports[dut])
            self.dut_log(dut, msg, logging.WARNING)
            ports.extend(self.reserved_ports[dut])

        if env.get("SPYTEST_SHUTDOWN_FREE_PORTS", "0") == "0":
            # not shutting down free ports
            pass
        elif dut in self.free_ports and self.free_ports[dut]:
            msg = "shutdown free ports:{}".format(self.free_ports[dut])
            self.dut_log(dut, msg, logging.WARNING)
            ports.extend(self.free_ports[dut])

        if ports:
            self.hooks.shutdown(dut, ports)
            if env.match("SPYTEST_UPDATE_RESERVED_PORTS", "1", "1"):
                if env.match("SPYTEST_BASE_CONFIG_METHOD", "legacy", "legacy"):
                    self.net.apply_remote(dut, "update-reserved-ports", [ports])

    def _save_base_config_dut(self, dut):

        if not self.is_supported_device(dut):
            return

        # no-shut connected ports so that they get saved as up in config
        self._noshutdown_connected(dut)

        # shut reserved ports so that they get saved as down in config
        self._shutdown_reserved_and_free(dut)

        if not self.cfg.skip_init_config:
            # save the configuration as TA default configuration
            self.hooks.save_config(dut, "base")

    def _verify_build_url_dut(self, dut, scope="current"):
        if self.cfg.build_url is not None and not self.cfg.build_url.strip():
            msg = "Given build url is not valid..."
            self.dut_log(dut, msg, logging.ERROR)
            return msg, None

        if self.cfg.build_url and scope == "current":
            build = self.cfg.build_url
        else:
            build = self.get_build(dut, scope)

        if not build:
            msg = "testbed file does not contain {} build".format(scope)
            self.dut_log(dut, msg, logging.WARNING)
            return None, None

        status, exp = utils.urlcheck(build)
        if not status:
            msg = "May be Invalid Build URL '{}'".format(build)
            self.dut_log(dut, msg, logging.ERROR)
            self.dut_log(dut, str(exp), logging.ERROR)
            # return msg, None

        return None, build

    def _load_image_dut(self, dut, scope):
        errmsg, build = self._verify_build_url_dut(dut, scope)
        if not build:
            if errmsg:
                raise ValueError(errmsg)
            return False

        if self.get_cfg_breakout_mode(dut) != "none" or self.cfg.speed_mode != "none":
            if env.get("SPYTEST_SYSTEM_READY_AFTER_PORT_SETTINGS", "0") == "1":
                self.upgrade_image(dut, build, False, False, False, 1, 3)
            else:
                self.upgrade_image(dut, build, False, False, False, 0, 3)
        else:
            self.upgrade_image(dut, build, False, False, False, 0, 3)
        return self.upgrade_libsai(dut)

    def _load_testbed_config_dut(self, dut, scope):
        if self.cfg.pde:
            return
        if self.cfg.skip_init_config:
            return

        # apply configs as given in template
        files = self.get_config(dut, scope)
        if not files:
            msg = "testbed file does not contain {} specific configs section".format(scope)
            self.dut_log(dut, msg, logging.DEBUG)
            files = []

        # apply all the config groups given in the template for current scope
        self._apply_config_file_list(dut, files)

    def has_get_tech_support(self, *args):
        runopt = utils.csv2list(self.cfg.get_tech_support)
        for m in args:
            if m in runopt:
                return True
        return False

    def has_fetch_core_files(self, *args):
        runopt = utils.csv2list(self.cfg.fetch_core_files)
        for m in args:
            if m in runopt:
                return True
        return False

    def _init_base_config_db(self, dut):
        # no need for skip and default profile
        profile = self.get_config_profile()

        any_fetch_core_files = bool(self.cfg.fetch_core_files != "none")
        any_get_tech_support = bool(self.cfg.get_tech_support != "none")
        if self.cfg.skip_init_config and profile in ["na"]:
            self.net.init_clean(dut, any_fetch_core_files, any_get_tech_support, True)

        # no need for PDE
        if self.cfg.pde:
            return

        if self.cfg.skip_init_config and profile in ["na"]:
            return

        # create init config file
        largs_list = [any_fetch_core_files, any_get_tech_support,
                      self.cfg.clear_tech_support, True, profile]
        self.net.apply_remote(dut, "init-ta-config", largs_list)

        # apply the init config file
        self.net.apply_remote(dut, "apply-init-config")
        self._ensure_system_ready(dut, "apply-init-config")

    def _filemode_ports(self, count=200, prefix="Ethernet"):
        retval = []
        for port in range(0, count):
            retval.append("{}{}".format(prefix, port))
        return retval

    def _get_physical_ifname_map(self, dut):
        if self.is_dry_run():
            all_ports = self._filemode_ports()
            alias_ports = self._filemode_ports(prefix="Eth1/")
        else:
            d = self.hooks.get_physical_ifname_map(dut)
            if d is not None:
                all_ports, alias_ports = [list(d.keys()), list(d.values())]
            else:
                all_ports = self._get_device_links_local(dut, native=True)
                reserved_ports = self._context._tb.get_rerved_links(dut)
                all_ports.extend(reserved_ports)
                alias_ports = all_ports
        alt_port_names, native_port_names = OrderedDict(), OrderedDict()
        for alias, native in zip(alias_ports, all_ports):
            alt_port_names[native] = alias
            native_port_names[alias] = native

        return all_ports, alt_port_names, native_port_names

    def map_port_name(self, dut, port):
        if dut not in self.alt_port_names:
            return port
        if port not in self.alt_port_names[dut]:
            return port
        return self.alt_port_names[dut][port]

    def get_other_name(self, dut, port):
        if dut in self.alt_port_names:
            if port in self.alt_port_names[dut]:
                return self.alt_port_names[dut][port]
        if dut in self.native_port_names:
            if port in self.native_port_names[dut]:
                return self.native_port_names[dut][port]
        return port

    def get_other_names(self, dut, port_list):
        retval = []
        for port in utils.make_list(port_list):
            retval.append(self.get_other_name(dut, port))
        return retval

    def _build_port_list(self, dut, retry):

        alias = self.get_device_alias(dut)
        errs = []
        self.all_ports[dut] = []
        self.free_ports[dut] = []

        all_ports, alt_port_names, native_port_names = self._get_physical_ifname_map(dut)
        self.alt_port_names[dut] = alt_port_names
        self.native_port_names[dut] = native_port_names
        self.connected_ports[dut] = self._get_device_links_local(dut, native=True)
        self.reserved_ports[dut] = self._context._tb.get_rerved_links(dut)

        err_msg = "Failed to display interfaces in {}".format(dut)
        if all_ports:
            for port in self.connected_ports[dut]:
                if port not in all_ports:
                    errs.append("invalid connected port {}/{}".format(alias, port))
                    errs.append("        should be one of {}".format(all_ports))
            ignore_invalid_reserved, valid_reserved_ports = True, []
            for port in self.reserved_ports[dut]:
                if port in all_ports:
                    valid_reserved_ports.append(port)
                elif not ignore_invalid_reserved:
                    errs.append("invalid reserved port {}/{}".format(alias, port))
                    errs.append("        should be one of {}".format(all_ports))
            if ignore_invalid_reserved:
                self.reserved_ports[dut] = valid_reserved_ports
            for port in all_ports:
                if port not in self.reserved_ports[dut]:
                    self.all_ports[dut].append(port)
                    if port not in self.connected_ports[dut]:
                        self.free_ports[dut].append(port)
        else:
            errs.append(err_msg)

        if errs and retry > 0:
            retry = retry - 1
            msg = "{} - retry {}".format(err_msg, retry)
            self.dut_log(dut, msg, logging.WARNING)
            errs = self._build_port_list(dut, retry)

        return errs

    def _session_breakout_speed(self, dut):
        if not self.set_port_defaults(dut, check_only=True):
            return

        if self.is_sonic_device(dut) and self.get_cfg_breakout_mode(dut) != "none":
            if self.get_cfg_load_image(dut) not in ["onie", "onie1", "onie2"]:
                self.dut_log(dut, "save configuration as TA configuration - 1")
                self._save_base_config_dut(dut)
                # DPB does not work when there is some configuration,
                # which is the case when we skip load image
                self.hooks.apply_config(dut, 0)

            # load any breakout specific configuration specified
            self._load_testbed_config_dut(dut, "breakout")

        # configure breakout and speed
        self.set_port_defaults(dut)

    # the sequence is init, transfer and save
    # init triggers init-ta-config
    # transfer triggers apply-files
    # save triggers save-base-config
    # Note: init and transfer can't be completed because
    # we support config.cmds which need to be executed from framework
    def _session_init_dut(self, dut):

        if self.cfg.skip_init_checks or not self.net:
            return True

        if not self.is_supported_device(dut):
            return True

        # pre load image config
        self.hooks.pre_load_image(dut)

        # load image
        if self.get_cfg_load_image(dut) == "none":
            msg = "SKIP loading {} image".format("current")
            self.dut_log(dut, msg, logging.WARNING)
            apply_port_defaults = True
        else:
            apply_port_defaults = self._load_image_dut(dut, "current")

        # create TA default configuration
        self.pending_image_load[dut] = False
        apis_instrument("init-config-start", dut=dut)
        hwsku = self.get_device_param(dut, "hwsku", None)
        profile = self.get_config_profile()
        self.hooks.init_config(dut, "base", hwsku, profile)
        apis_instrument("init-config-end", dut=dut)

        # apply port speed and breakout
        if apply_port_defaults:
            self._session_breakout_speed(dut)

        # load user configuration if any specified in testbed
        self._load_testbed_config_dut(dut, "current")

        # save configuration as TA configuration
        self.dut_log(dut, "save configuration as TA configuration - 2")
        self._save_base_config_dut(dut)

        # perform extended base config verification
        if not self.hooks.verify_config(dut, "base"):
            msg = "Failed perform extended base config verification..."
            self.dut_log(dut, msg, logging.ERROR)
            raise ValueError(msg)

        # configure ASAN
        asan_config = bool("config" in env.get("SPYTEST_ASAN_OPTIONS", ""))
        if asan_config:
            self.net.apply_remote(dut, "asan-config")
            self.net.reboot(dut, "fast", skip_exception=True)

        # per device session init is completed
        return True

    def _session_build_ports_dut(self, dut, recover=True):
        errs = []

        if self.cfg.skip_init_checks:
            return

        # read the port list
        if not self.cfg.pde:
            errs.extend(self._build_port_list(dut, 25))

        # check if there are any issues reported if not all is well
        if not errs:
            if self.get_cfg_load_image(dut) != "none":
                self._fill_hooks_data(dut, "post image load")
            self._save_base_config_dut(dut)
            return True

        # generate tech-support on breakout issues
        self.fetch_support(dut, "portlist-not-ready", "fail", "", "breakout")

        # bail out on testbed issues
        if self.all_ports[dut]:
            self._trace_errors(dut, "invalid ports in testbed file", errs)
            return False

        # nothing to do if we are not recovering
        if not recover:
            msg = "ports are not created - bailout run"
            self.dut_log(dut, msg, logging.ERROR)
            return False

        # recover the DUT with reboot
        msg = " ports are not created - trying to recover the DUT with reboot."
        self.dut_log(dut, msg, logging.WARNING)
        rv = self.net.reboot(dut, "fast", skip_exception=True)
        if not rv:
            msg = "Failed to reboot the DUT to recover - bailout run"
            self.dut_log(dut, msg, logging.ERROR)
            return False

        # reboot is OK, check ports again
        msg = "Successfully rebooted the DUT to recover - verify testbed ports"
        self.dut_log(dut, msg, logging.WARNING)
        if not self._session_build_ports_dut(dut, False):
            msg = "ports are not ready even after recovery - bailout run"
            self.dut_log(dut, msg, logging.ERROR)
            return False

        # all is well at least now
        msg = "Successfully verified testbed ports after recovery"
        self.dut_log(dut, msg, logging.INFO)
        return True

    def _trace_errors(self, dut, msg, errs):
        if msg:
            self.dut_log(dut, msg, lvl=logging.ERROR)
        for err in errs:
            self.dut_log(dut, err, lvl=logging.ERROR)
        return False

    def _check_exceptions(self, dut_list, msg, exceptions, threads, abort=True):
        dut_list = dut_list or self.get_dut_names()
        errs, failed_devices = [], []
        for dut_index, ex in enumerate(exceptions):
            if not ex:
                continue
            self.dut_log(dut_list[dut_index], str(ex), logging.ERROR)
            errs.extend(ex)
            failed_devices.append(dut_list[dut_index])
        if threads and self.check_skips(threads):
            errs.append("Exception in Threads")
        if errs:
            self.error(msg)
            if abort:
                if failed_devices:
                    msg = "{} ({})".format(msg, failed_devices)
                self.abort_run(6, msg, False)
            return msg
        return None

    def extend_config(self, dut, phase):
        if self.cfg.ifname_type not in ["none"]:
            ifname_type = self.get_ifname_type(dut)
        else:
            ifname_type = "none"
        self.hooks.extend_config(dut, phase, ifname_type=ifname_type)

    def _get_swver_map(self, dut_list=None):
        dut_list = dut_list or self.get_dut_names()
        version_dut_map = dict()
        for dut in dut_list:
            version = self.swver.get(dut, "Unknown")
            if version not in version_dut_map:
                version_dut_map[version] = [dut]
            else:
                version_dut_map[version].append(dut)
        return version_dut_map

    def _session_init(self):
        self.log_time("session init start")
        apis_instrument("session-init-start")

        # save initial inventory
        self._save_inventory()

        # skip cheks for faster init
        if self.cfg.skip_init_checks:
            retvals, exceptions, threads = self._foreach_dev(self._fill_hooks_data, "read version")
            msg = "exception while reading version"
            self._check_exceptions(None, msg, exceptions, threads)
            return

        # init software versions, data maps etc
        for dut in self.get_dut_names():
            self.swver[dut] = ""
            self.hwsku[dut] = ""
            self.dmaps[dut] = dict()

        # load current image, config and perform
        funcs = [[self._context._tgen_init, 1]]
        for dut in self.get_dut_names():
            funcs.append([self._session_init_dut, dut])
        wait_on_first = env.getint("SPYTEST_TGEN_P1_THREAD_WAIT", 0)
        retvals, exceptions, threads = putil.exec_all2(self.cfg.faster_init, "trace",
                                                       funcs, True, wait_on_first)
        tg_ret, tg_exp, _ = retvals.pop(0), exceptions.pop(0), threads.pop(0)
        self._context.ensure_tgen(tg_ret, tg_exp, self._context.log)
        msg = "exception loading image or init config"
        self._check_exceptions(None, msg, exceptions, threads)

        # save inventory after image loading
        self._save_inventory()

        # identify invalid port names given in testbed file
        self.log("building port list and save base config")
        recover = env.match("SPYTEST_RECOVER_INITIAL_SYSTEM_NOT_READY", "1", "1")
        retvals, exceptions, threads = self._foreach_dev(self._session_build_ports_dut, recover)
        msg = "exception saving base config"
        self._check_exceptions(None, msg, exceptions, threads)

        # bail out if there are errors detected in topology
        if not all(retvals):
            msg = "invalid ports in topology - please check testbed file"
            failed_duts = []
            for dut, retval in zip(self.get_dut_names(), retvals):
                if retval:
                    continue
                failed_duts.append(dut)
                self.dut_log(dut, msg, lvl=logging.ERROR)
            if not self.is_dry_run():
                msg = "{} ({})".format(msg, failed_duts)
                self.abort_run(6, msg, False)

        # get application vars
        self._module_init_cache()
        for dut in self.get_dut_names():
            self.module_vars[dut] = dict()
            # self._fill_hooks_data(dut, "before version check")
        retvals, exceptions, threads = self._foreach_dev(self._fill_hooks_data, "before version check")
        msg = "exception while version check"
        self._check_exceptions(None, msg, exceptions, threads)

        # save the DUT build names for email
        version_dut_map = self._get_swver_map()
        if version_dut_map:
            set_mail_build(",".join(list(version_dut_map.keys())))

        # bail out if there is any difference in software version
        version_check = env.get("SPYTEST_ABORT_ON_VERSION_MISMATCH", "2")
        if version_check != "0":
            dut_list = self.get_dut_names()
            if version_check == "1":
                if len(dut_list) > 1:
                    if len(version_dut_map.keys()) > 1:
                        msg2 = "Software Version Mismatch identified..."
                        failed_duts = []
                        for dut in dut_list:
                            self.dut_log(dut, msg2, logging.ERROR)
                            for tmp_version in version_dut_map.keys():
                                msg = "DUT's with Software Version '{}': '{}'."
                                msg = msg.format(tmp_version, ",".join(version_dut_map[tmp_version]))
                                failed_duts.append(dut)
                                self.dut_log(dut, msg, logging.ERROR)
                        msg2 = "{} ({})".format(msg2, failed_duts)
                        self.abort_run(6, msg2, False)
                    else:
                        for dut in dut_list:
                            for tmp_version in version_dut_map.keys():
                                msg = "DUT's with Software Version '{}': '{}'."
                                msg = msg.format(tmp_version, ",".join(version_dut_map[tmp_version]))
                                self.dut_log(dut, msg, logging.INFO)
            elif version_check != "2":
                if len(dut_list) > 1:
                    duts_missed = []
                    for dut in dut_list:
                        if version_check != self.swver[dut]:
                            duts_missed.append(dut)
                    if duts_missed:
                        msg = "Software Version mismatch on DUT's '{}'. Didn't matched with given version: '{}'"
                        msg = msg.format(",".join(duts_missed), version_check)
                        for dut in dut_list:
                            self.dut_log(dut, msg, logging.ERROR)
                        msg = "{} ({})".format(msg, duts_missed)
                        self.abort_run(6, msg, False)

        # extend base config
        self._foreach_dev(self.extend_config, "base")

        # save the base config
        if not self.cfg.skip_init_config:
            _, exceptions, threads = self._foreach_dev(self.hooks.save_config, "base")
            msg = "exception saving base config"
            self._check_exceptions(None, msg, exceptions, threads)

        # perform topology check
        if self.is_topology_check(["report", "abort"]):
            retval, header, rows, seen_exp, _ = self.hooks_verify_topology("report")
            topo_status = utils.sprint_vtable(header, rows)
            if not retval or seen_exp:
                msg = "Topology verification failed"
                self.error(msg)
                self.topo_error(topo_status, split_lines=True)
                if self.is_topology_check(["abort"]):
                    self.abort_run(7, msg, False)
            else:
                self.log("Topology verification successful")
                self.topo_debug(topo_status, split_lines=True)
        elif self.is_topology_check(["module", "function"]):
            # no need if we are doing same in module/function
            pass
        else:
            self.warn("SKIP Topology verification")

        # apply base configuration for first module
        if self.apply_base_config_after_module:
            self._module_apply_base_config(None)

        # flag to run module init
        self.base_config_verified = True
        self._context.session_init_time_taken = get_elapsed(self._context.session_start_time, True)
        self._context.total_tc_start_time = get_timenow()

        if batch.is_member():
            self._report_file_generation()

        self.fetch_support(None, "post-session-prolog", "pass", "", "session")

        apis_instrument("session-init-end")
        self.log_time("session init end")

    def _fetch_gcov_files(self, dut, phase):

        # check if we need this for all devices
        if dut is None:
            self._foreach_dev(self._fetch_gcov_files, phase)
            return

        self.debug("fetch_gcov_files({})".format(phase), dut=dut)
        self.net.fetch_gcov_files(dut, phase)

    def _session_clean_dut(self, dut):

        if not self.net or not self.is_supported_device(dut):
            return

        # perform unbreakout if specified in testbed file
        self.set_port_defaults(dut, section="unbreakout", speed=False)

        # Load Image
        if self.get_cfg_load_image(dut) == "none":
            msg = "SKIP loading {} image".format("restore")
            self.dut_log(dut, msg, logging.WARNING)
            apply_port_defaults = False
        else:
            apply_port_defaults = self._load_image_dut(dut, "restore")

        # port speed and breakout
        if apply_port_defaults:
            self._session_breakout_speed(dut)

        # load user configuration if any specified in testbed
        self._load_testbed_config_dut(dut, "restore")

        # CHECK: do we need to apply base config at session clean?
        self.hooks.apply_config(dut, 2)

    def _session_clean(self):
        self.log_time("session clean start")
        apis_instrument("session-clean-start")

        if batch.is_member():
            self.fetch_support(None, "session-epilog", "pass", "", "session")

        # collect the GCOV data
        if self.cfg.gcov == 1:
            self._fetch_gcov_files(None, "session")

        # cleanup TGEN and Devices
        funcs, clean_tgen = [], env.match("SPYTEST_SESSION_TGEN_CLEAN", "1", "1")
        if clean_tgen:
            funcs.append([self._module_init_tgen])
        for dut in self.get_dut_names():
            funcs.append([self._session_clean_dut, dut])
        rvs, exceptions, threads = putil.exec_all2(self.cfg.faster_init, "trace", funcs, True)
        if clean_tgen:
            tg_ret, tg_exp, _ = rvs.pop(0), exceptions.pop(0), threads.pop(0)
            self._context.ensure_tgen(tg_ret, tg_exp, self._context.log, True)
        fail_msg = "Failed in session cleanup"
        self._check_exceptions(None, fail_msg, exceptions, threads, False)

        if batch.is_member():
            data = self._report_file_generation()

        apis_instrument("session-clean-end")
        if self.net:
            self.net.session_close()
        if batch.is_member():
            self.notice("=================== Final Report =========================")
            self.notice(data, split_lines=True)
            self._log_version_info()
            rlist = selected_test_results.values()
            self.notice("============ Results : {}".format(list(Counter(rlist).items())))
            self.notice("==========================================================")
        self.log_time("session clean end")

    def _log_version_info(self, dst=["all"]):
        self._log_software_info(dst)
        self._log_hardware_info(dst)

    def _log_software_info(self, dst=["all"]):
        self.notice(" ================== Software Version ====================", dst=dst)
        ver_dut_map = utils.invert_dict(self.swver)
        for ver, dut in ver_dut_map.items():
            self.notice(" ============ {} = {}".format(dut, ver), dst=dst)
        self.notice(" ==========================================================", dst=dst)

    def _log_hardware_info(self, dst=["all"]):
        self.notice(" ================== Hardware SKU ====================", dst=dst)
        ver_dut_map = utils.invert_dict(self.hwsku)
        for ver, dut in ver_dut_map.items():
            self.notice(" ============ {} = {}".format(dut, ver), dst=dst)
        self.notice(" ==========================================================", dst=dst)

    def _module_init_dut(self, dut, filepath):

        if self.cfg.skip_init_checks:
            return

        self.clear_module_vars(dut)

        # no need to apply base config for first module
        if not self.modules_completed:
            self.dut_log(dut, "no need to apply base config for first module")
        else:
            self.hooks.apply_config(dut, 1)

        # ensure system is ready
        if filepath:
            module_str = "module_{}".format(filepath.split('.')[0])
        else:
            module_str = "session_start"
        self._ensure_system_ready(dut, module_str)

    def _module_apply_base_config(self, filepath):

        if self.tgen_reconnect:
            self.warn("Reconnecting to TGen")
            self._context._tgen_close()
            if not self._context._tgen_init(2):
                msg = "Failed to reconnect to TGEN"
                self.error(msg)
                self.abort_run(6, msg, False)
            self.warn("Reconnected to TGen")
            self.tgen_reconnect = False

        self.log("Applying base configuration {}".format(self.abort_module_msg or ""))
        fail_msg = "Failed to module init one or more devices in topology"
        self.last_error = None
        funcs = [[self._module_init_tgen]]
        for dut in self.get_dut_names():
            funcs.append([self._module_init_dut, dut, filepath])
        putil.exec_foreach(True, self.get_dut_names(), self.hooks.gnmi_cert_config_ensure)
        retvals, exceptions, threads = putil.exec_all2(self.cfg.faster_init, "trace", funcs, True)
        tg_ret, tg_exp, _ = retvals.pop(0), exceptions.pop(0), threads.pop(0)
        self._context.ensure_tgen(tg_ret, tg_exp, self._context.log, True)
        errmsg = self._check_exceptions(None, fail_msg, exceptions, threads, False)
        if errmsg and env.get("SPYTEST_ABORT_ON_APPLY_BASE_CONFIG_FAIL", "1") != "0":
            self.abort_run(6, errmsg, False)

        # abort the module if not able to apply base config
        if errmsg or self.last_error or self.check_skips(threads):
            self.last_error = None  # reset last error
            self.abort_module_msg = errmsg
            self.error("Failed to apply base configuration: {}".format(self.abort_module_msg))
        else:
            self.log("Successfully applied base configuration")

    def _function_init_sysinfo(self):
        for dut in self.get_dut_names():
            self.sysinfo[dut] = OrderedDict()
            for scope in ["pre-module-prolog", "pre-function-prolog",
                          "post-function-epilog", "post-module-epilog"]:
                self.sysinfo[dut][scope] = ["NE", "NE"]

    def _module_init_cache(self):
        self.dut_ui_type.clear()
        self.cli_records.clear()
        self.cli_type_cache.clear()
        for dut in self.get_dut_names():
            self.cli_records[dut] = []
            self.cli_type_cache[dut] = OrderedDict()
        self.sysinfo.clear()
        self._function_init_sysinfo()

    def _module_init_tgen(self):
        if self.cfg.tgen_module_init:
            if self.modules_completed:
                tgapi.module_init()
        return True

    def _module_init(self, nodeid, filepath):
        retval = self._module_init_int(nodeid, filepath)
        if retval is not None:
            module, _ = paths.parse_nodeid(nodeid)
            self.fetch_support(None, "post-module-prolog", "Fail", "", module)
        return retval

    def _module_init_int(self, nodeid, filepath):
        self.log_time("module {} init start".format(filepath))

        self._context._tb.reset_derived()
        self.clear_tc_results()

        # per module faster-cli
        if self.cfg.faster_cli == 1:
            fcli = 1
        elif self.cfg.faster_cli == 2:
            fcli = tcmap.get_module_info(filepath).fcli
        else:
            fcli = 0

        # per module tryssh
        if self.cfg.tryssh == 1:
            tryssh = 1
        elif self.cfg.tryssh == 2:
            tryssh = tcmap.get_module_info(filepath).tryssh
        else:
            tryssh = 0

        # adjust Module MAX Timeout using data from tcmap
        if self.cfg.module_max_timeout > 0:
            module_max_timeout = tcmap.get_module_info(filepath).maxtime
        else:
            module_max_timeout = 0
        if module_max_timeout > 0 and module_max_timeout > self.cfg.module_max_timeout:
            self.net.module_init_start(module_max_timeout, fcli, tryssh)
        else:
            self.net.module_init_start(self.cfg.module_max_timeout, fcli, tryssh)

        if self.cfg.skip_init_checks:
            self.base_config_verified = True

        if not self.base_config_verified:
            self.warn("base config verification already failed - no need to run any modules")
            return "SKIP"

        self._context.result.clear()
        self._module_init_cache()

        self.min_topo_called = False
        self.module_tc_executed = 0
        self.module_tc_fails = 0
        self.module_get_tech_support = False
        self.module_fetch_core_files = False
        self.abort_module_msg = None
        self.abort_module_res = None

        # simulate node dead in module init
        batch.simulate_deadnode(1)

        # check min topology in modules csv
        if self.verify_csv_min_topo > 0 and self.verify_csv_min_topo < 100:
            mname = item_utils.map_nodeid(nodeid)
            csv_topo = self._get_csv_topo(mname)
            self._ensure_min_topology(csv_topo)

        # apply base configuration
        if not self.apply_base_config_after_module:
            self._module_apply_base_config(filepath)

        # verify topology before module start
        if not self.abort_module_msg:
            if self.is_topology_check(["module"]):
                msg = "verify/show port status before module {}"
                self.log(msg.format(",".join(self.get_dut_names())))
                name = build_module_logname(nodeid)
                self.verify_topology("module", name)

        # ensure system is ready to proceed further
        if self.abort_module_msg:
            self.error(self.abort_module_msg)
            return "SKIP"

        self._pre_module_prolog(nodeid)

        self.log_time("module {} init end".format(filepath))

        return None

    def _clear_devices_usage_list(self):
        self.net.clear_devices_usage_list()

    def _get_devices_usage_list(self):
        return self.net.get_devices_usage_list()

    def _set_device_usage_collection(self, collect_flag):
        self.net.set_device_usage_collection(collect_flag)

    def _pre_module_prolog(self, name):
        if not batch.is_infra_test(name):
            self.fetch_support(None, "pre-module-prolog", "", "", name)

    def _pre_module_epilog(self, name):
        self._scope_module_epilog(name, "pre-module-epilog")

    def _post_module_prolog(self, name, res, desc):
        self.debug_check_min_topology_abort()
        self._trace_missing_parallel_operations(name)
        if not batch.is_infra_test(name):
            self.fetch_support(None, "post-module-prolog", res, desc, name)
        if self.cfg.skip_load_config not in ["base"]:
            self._foreach_dev(self._save_module_config)

    def _scope_module_epilog(self, name, scope):
        scopes = [scope]
        if self.module_get_tech_support:
            result = "fail"
        elif self.module_tc_fails > 0:
            result = "fail"
        elif self.module_tc_executed <= 0:
            # no test case is executed - fire post function prolog
            if scope == "pre-module-epilog":
                scopes.insert(0, "post-function-prolog")
            result = "fail"
        else:
            result = "pass"

        for scope in scopes:
            if not batch.is_infra_test(name):
                self.fetch_support(None, scope, result, "", name)

    def _post_function_prolog(self, name, res, desc):
        if not batch.is_infra_test(name):
            self.fetch_support(None, "post-function-prolog", res, desc, name)

    def _pre_function_epilog(self, name):
        if not batch.is_infra_test(name):
            res, desc = self._context.result.get(False)
            if not desc or "result already set to" in desc:
                return
            self.fetch_support(None, "pre-function-epilog", res, desc, name)
            self.ignore_post_function_epilog = True

    def _post_class_prolog(self, name, res, desc):
        if not batch.is_infra_test(name):
            self.fetch_support(None, "post-class-prolog", res, desc, name)

    def _post_class_epilog(self, name):
        if not batch.is_infra_test(name):
            self.fetch_support(None, "post-class-epilog", "pass", "", name)

    def _save_module_config(self, dut=None):
        # we MUST save the module config even though we don;t need to call
        # apply-module-config, because if reboot happens the device should
        # start with module config
        # save the module configuration before executing any test cases in the module
        msg = "save the module config - needed if device reboots "
        if self.cfg.skip_load_config not in ["module"]:
            msg = " and for restore across test cases"
        self.dut_log(dut, msg)
        self.hooks.save_config(dut, "module")

    def set_module_lvl_action_flags(self, action):
        if action == "core-dump":
            self.module_fetch_core_files = True
        elif action == "tech-support":
            self.module_get_tech_support = True

    def _module_complete_dut(self, dut, filepath):

        # check if we need to proceed further
        if env.get("SPYTEST_MODULE_EPILOG_ENSURE_SYSTEM_READY", "1") != "1":
            return

        # check if we need this for all devices
        if dut is None:
            self._foreach_dev(self._module_complete_dut, filepath)
            return

        # ensure that system is ready at the end of module
        module_str = "module_{}".format(filepath.split('.')[0])
        self._ensure_system_ready(dut, module_str)

    def _module_complete(self, nodeid, filepath):
        self._scope_module_epilog(nodeid, "post-module-epilog")
        self._save_cli(nodeid)
        self._module_complete_dut(None, filepath)

        # save the module to completed list
        if not batch.is_infra_test(filepath):
            self.modules_completed.append(current_module.name or filepath)

    def _init_sysinfo(self, row, module, func, extra):
        row.append(module)
        if func:
            row.append(func)
        row.append(extra)
        off = len(row)
        row.extend([0, 0, 0])                   # Memory usage
        if Result.has_cpu_cols():
            row.extend([0.0, 0.0, 0.0])             # CPU Usage
        return off

    def _fill_sysinfo_data(self, row, off, index, entry, key, isint=1):
        err, ne = "ERROR", "NE"
        data = entry.get(key, [err, err])
        value = data[index] if len(data) > index else err
        if value == err:
            row[off] = err
        elif value == ne:
            row[off] = ne
        elif row[off] in [err, ne]:
            pass
        elif isint:
            row[off] = row[off] + int(value)
        else:
            row[off] = row[off] + float(value)

    def _fill_sysinfo_diff0(self, row, off):
        for i in range(2):
            if row[off + i] in ["ERROR", "NE"]:
                return
        row[off + 2] = row[off + 1] - row[off + 0]

    def _fill_sysinfo_diff(self, row, off):
        if row[off + 2] in ["ERROR", "NE"]:
            pass
        elif row[off + 0] in ["ERROR", "NE"]:
            row[off + 2] = row[off + 0]
        elif row[off + 1] in ["ERROR", "NE"]:
            row[off + 2] = row[off + 1]
        else:
            row[off + 2] = row[off + 1] - row[off + 0]

    def _fill_sysinfo(self, row, off, entry, dtype):
        self._fill_sysinfo_data(row, off + 0, 0, entry, "pre-{}-prolog".format(dtype))
        self._fill_sysinfo_data(row, off + 1, 0, entry, "post-{}-epilog".format(dtype))
        self._fill_sysinfo_diff(row, off)
        if not Result.has_cpu_cols():
            return
        self._fill_sysinfo_data(row, off + 3, 1, entry, "pre-{}-prolog".format(dtype))
        self._fill_sysinfo_data(row, off + 4, 1, entry, "post-{}-epilog".format(dtype))
        self._fill_sysinfo_diff(row, off + 3)

    def _build_msysinfo(self, nodeid):
        name = paths.get_mlog_basename(nodeid)
        row = [len(self.modules_completed)]     # s.no
        off = self._init_sysinfo(row, name, None, len(self.sysinfo))
        for entry in self.sysinfo.values():
            self._fill_sysinfo(row, off, entry, "module")
        return row

    def _save_msysinfo(self, nodeid, this_row=None):
        row = this_row or self._build_msysinfo(nodeid)
        msysinfo_csv = paths.get_msysinfo_csv(self._context.logs_path)
        Result.write_report_csv(msysinfo_csv, [row], ReportType.MSYSINFO, False, True)
        if not this_row:
            if not row[1]:
                self._dbg_sysinfo(nodeid, "MSYSINFO", "module")
            if not row[3] or not row[4]:
                self._dbg_sysinfo(nodeid, "MSYSINFO", "values", row)
        row.insert(2, " --Module--")
        self._save_fsysinfo(nodeid, row)
        nodeid = "{}::--Module--".format(nodeid)
        self._save_dsysinfo(nodeid, dtype="module")

    def _module_save_coverage(self):
        mname = paths.get_mlog_basename(current_module.name)
        row = [len(self.modules_completed)]     # s.no
        row.append(mname)                       # module name
        dut_list = self._context._tb.get_device_names("DUT")
        models = self._context._tb.get_device_models("DUT")
        chips = self._context._tb.get_device_chips("DUT")
        tgens = self._context._tb.get_tgen_types()
        row.append(", ".join(dut_list))
        row.append(", ".join(models))
        row.append(", ".join(chips))
        row.append(", ".join(tgens))
        row.extend(["", "", "", ""])
        coverage_csv = paths.get_coverage_csv(self._context.logs_path)
        Result.write_report_csv(coverage_csv, [row], ReportType.COVERAGE, False, True)

    def _save_inventory(self):
        dut_list = self._context._tb.get_device_names("DUT")
        models = self._context._tb.get_device_models("DUT")
        chips = self._context._tb.get_device_chips("DUT")
        rows, versions = [], list(self.swver.values())
        for dut, model, chip, version in zip(dut_list, models, chips, versions):
            rows.append([dut, model, chip, version])
        inventory_csv = paths.get_device_inventory_csv(self._context.logs_path)
        Result.write_report_csv(inventory_csv, rows, ReportType.DEVICE_INVENTORY, False)

    def _module_clean(self, nodeid, filepath):
        if not self.min_topo_called:
            self.warn("Module {} Minimum Topology is not specified".format(filepath))
        self.log_time("module {} clean start".format(filepath))

        self._module_complete(nodeid, filepath)

        # apply base configuration
        if self.apply_base_config_after_module:
            self._module_apply_base_config(filepath)
        elif self.cfg.gcov != 0 and not batch.is_infra_test(nodeid):
            self.log("Apply the base config so that GCOV data is saved")
            self._module_apply_base_config(filepath)

        # collect the GCOV data
        if self.cfg.gcov == 2 and not batch.is_infra_test(nodeid):
            self._fetch_gcov_files(None, "module")

        # create sysinfo report
        if not batch.is_infra_test(filepath):
            self._save_msysinfo(nodeid)
            self._module_save_coverage()

        # update the node report files for every module
        # if we are not reporting run progress
        if self.cfg.run_progress_report == 0:
            self._report_file_generation()

        utils.dump_connections("Connections@ModuleComplete")
        self.log_time("module {} clean end".format(filepath))

    def tc_log_init(self, func_name):
        self._context.log.tc_log_init(func_name)

    def module_log_init(self, module_name):
        if not module_name:
            self._log_version_info(["module"])

        # close the current module to see start message in session log
        self._context.log.module_log_init(None)

        # start new module log
        if module_name:
            self.banner("Executing Module {}".format(module_name))
            append = self.module_log_mode.get(module_name, False)
            self._context.log.module_log_init(module_name, append=append)
            self.module_log_mode[module_name] = True
            self._context.log_verion_info(dst=["module"])
            if self.modules_completed:
                self.log("Previous Module: {}".format(self.modules_completed[-1]))

    def _test_log_init(self, nodeid, func_name, show_trace=False):
        if not self._context or not self._context.result:
            for msg in utils.stack_trace(None, True):
                print_ftrace(msg)
            global_abort_run(0, None)
        self._context.result.clear()
        msg = "\n================== {} ==================\n".format(nodeid)
        if show_trace:
            self.log(msg)
        for dut in self.get_dut_names():
            self.dut_log(dut, msg, dst=["dut"])

    def is_topology_check(self, value):
        if self.cfg.filemode:
            return False
        value_list = utils.make_list(value)
        if "skip" in self.cfg.topology_check:
            return False
        for check in self.cfg.topology_check:
            if check in value_list:
                return True
        return False

    def hooks_verify_topology(self, check_type):
        apis_instrument("pre-verify-topology", phase=check_type)
        retval = self.hooks.verify_topology(check_type, self.cfg.faster_init,
                                            self._context.skip_tgen)
        apis_instrument("post-verify-topology", phase=check_type)
        return retval

    def verify_topology(self, check_type, name):
        topo_status = False
        max_wait = env.get("SPYTEST_TOPOLOGY_STATUS_MAX_WAIT", "60")
        max_wait = utils.integer_parse(max_wait, 0)
        max_iter = int(max_wait / 5)
        failed_rows = []

        if self.cfg.skip_init_checks:
            return True

        for retry in range(max_iter + 1):
            failed_rows = []
            retval = self.hooks_verify_topology(check_type)
            if retval:
                header, rows, seen_exp, show_alias = retval[1:]
                if seen_exp:
                    self.abort_function_msg = "Observed exception during the topology verification"
                    return False
                topo_status = utils.sprint_vtable(header, rows)
                self.topo_debug(topo_status, split_lines=True)
                if max_wait > 0:
                    for row in rows:
                        indexes = [4, 9] if show_alias else [3, 7]
                        for index in indexes:
                            if row[index] not in ["Enable/Up", "up/up", "oper-up/up", "NA"]:
                                failed_rows.append(row)
                                break
            if not failed_rows:
                self.log("Port Status Check ({}): PASS".format(check_type))
                return True
            if retry < max_iter:
                msg = "Retry Port Status Check ({}) Iteration {} of Max {}".format(check_type, retry, max_iter)
                self.wait(5, msg)
        # some/all the ports are down
        self.warn("Port Status Check ({}): FAIL".format(check_type))

        # fetch tech-support
        scope = "port-status"
        if check_type in ["module", "function"]:
            scope = "{}-{}".format(scope, check_type)
        if self.is_tech_support_onerror("port_status"):
            self.fetch_support(None, scope, "fail", "", name)

        abort_msgs = []
        for row in failed_rows:
            abort_msgs.append("{}({})/{}".format(row[0], row[1], row[2]))
            if check_type == "module":
                self._context._tb.set_port_down(row[0], row[2])
        abort_msgs.insert(0, "Port(s) not ready before {}: ".format(check_type))
        abort_msg = " \n".join(abort_msgs)
        status_abort = env.get("SPYTEST_TOPOLOGY_STATUS_ONFAIL_ABORT", "module")
        if check_type in status_abort.split(",") and check_type in ["module", "function"]:
            self.abort_module_msg = abort_msg
        elif batch.is_infra_test(name):
            self.abort_module_msg = abort_msg
        else:
            self.warn(abort_msg)

        return False

    def _function_init(self, nodeid, func_name):

        # post-user-module-prolog right before start of first function
        if self.module_tc_executed == 0:
            module, _ = paths.parse_nodeid(nodeid)
            res, desc = get_current_result("module")
            self._post_module_prolog(module, res, desc)

        # clear the function scope sysinfo
        for dut in list(self.sysinfo.keys()):
            self.sysinfo[dut].pop("pre-function-prolog", "")
            # self.sysinfo[dut].pop("post-function-prolog", "")
            # self.sysinfo[dut].pop("pre-function-epilog", "")
            self.sysinfo[dut].pop("post-function-epilog", "")

        self.clear_tc_results()
        self.abort_function_msg = None
        self.log_time("function {} init start".format(nodeid))

        self.current_tc_start_time = get_timenow()

        # adjust TC MAX Timeout using data from tcmap
        if self.cfg.tc_max_timeout > 0:
            tc_max_timeout = tcmap.get_function_info(func_name).maxtime
        else:
            tc_max_timeout = 0
        if tc_max_timeout > 0 and tc_max_timeout > self.cfg.tc_max_timeout:
            self.net.function_init_start(tc_max_timeout)
        else:
            self.net.function_init_start(self.cfg.tc_max_timeout)

        self._test_log_init(nodeid, func_name)

        # if self.is_community_build() and item_utils.has_marker(nodeid, "community_unsupported"):
        # desc = self._report("", "Unsupported", "test_case_unsupported")
        # self._function_clean(nodeid, func_name, min_time)
        # self.pytest_skip(desc)

        if self.abort_module_msg:
            self.set_last_report_line(None)
            desc = self._report("", "SKIPPED", "test_execution_skipped", self.abort_module_msg)
            self._function_clean(nodeid, func_name, min_time)
            self.pytest_skip(desc)

        if self.cfg.first_test_only and self.module_tc_executed > 0 and not batch.is_infra_test(func_name):
            self.set_last_report_line(None)
            desc = self._report("", "SKIPPED", "test_execution_skipped", "as the ask is to run first test only")
            self._function_clean(nodeid, func_name, min_time)
            self.pytest_skip(desc)

        if self.cfg.max_functions_per_module > 0 and self.module_tc_executed >= self.cfg.max_functions_per_module:
            desc = "as the ask is to execute only {} functions".format(self.cfg.max_functions_per_module)
            desc = self.report("", "SKIPPED", "test_execution_skipped", desc)
            self._function_clean(nodeid, func_name, min_time)
            self.pytest_skip(desc)

        # report as failure if the base config is not verified
        if not self.base_config_verified:
            self.error("base config verification failed - no need to run {}".format(func_name))
            self.set_last_report_line(None)
            desc = self._report("", "ConfigFail", "base_config_verification_failed")
            self._function_clean(nodeid, func_name, min_time)
            self.pytest_skip(desc)

        # check if the dependent test case is failed
        if batch.is_infra_test(func_name):
            pass  # no need to check on the infra tests
        elif not self.cfg.ignore_dep_check:
            errs = check_dependency(func_name)
            if errs:
                self.error("dependent test case failed - no need to run {}".format(func_name))
                self.clear_last_report_line()
                desc = self._report("", "DepFail", "depedent_test_failed", errs)
                self._function_clean(nodeid, func_name, min_time)
                self.pytest_skip(desc)

        # simulate node dead in function init
        batch.simulate_deadnode(2)

        if not self.abort_module_msg:
            if self.is_topology_check(["function"]):
                msg = "verify/show port status before function {}"
                self.log(msg.format(",".join(self.get_dut_names())))
                self.verify_topology("function", func_name)

        if self.abort_module_msg:
            self.set_last_report_line(None)
            desc = self._report("", "SKIPPED", "test_execution_skipped", self.abort_module_msg)
            self._function_clean(nodeid, func_name, min_time)
            self.pytest_skip(desc)

        if self.abort_function_msg:
            self.set_last_report_line(None)
            desc = self._report("", "SKIPPED", "test_execution_skipped", self.abort_function_msg)
            self._function_clean(nodeid, func_name, min_time)
            self.pytest_skip(desc)

        # ensure system is ready before executing test function
        self._ensure_system_ready(None, func_name)
        if self.abort_module_msg:
            self.error(self.abort_module_msg)
            return "SKIP"

        # init net variables for test function
        self.net.tc_start(self.current_tc_start_time)

        # collect support data
        if not batch.is_infra_test(func_name):
            self.fetch_support(None, "pre-function-prolog", "", "", func_name)

        self.log_time("function {} init end".format(nodeid))

    def _function_clean(self, nodeid, func_name, time_taken=None):

        self.log_time("function {} clean start".format(nodeid))

        self._context.net.set_prev_tc(func_name)

        # Get result and description to print in log files.
        res, desc = self._context.result.get()

        # collect support data
        if not self.abort_module_msg:
            if not batch.is_infra_test(func_name):
                if res and res.lower() != "pass" and self.ignore_post_function_epilog:
                    res = "ignore"
                self.fetch_support(None, "post-function-epilog", res, desc, func_name)
                self.ignore_post_function_epilog = False
                res, desc = self._context.result.get()  # read-again

        # apply module config if needed
        if self.cfg.skip_load_config not in ["base", "module"]:
            self._foreach_dev(self.net.apply_remote, "apply-module-config")
            self._ensure_system_ready(None, func_name)

        # create sysinfo report
        if not batch.is_infra_test(nodeid):
            self._save_fsysinfo(nodeid)

        if time_taken is None:
            time_taken = get_elapsed(self.current_tc_start_time, True, min_time)
        elif isinstance(time_taken, int):
            time_taken = utils.time_format(time_taken)

        self._test_log_finish(nodeid, func_name, res, desc, time_taken)
        self.module_tc_executed = self.module_tc_executed + 1
        if self.cfg.run_progress_report > 1:
            self._report_file_generation()
        if res.lower() != "pass":
            self.module_tc_fails = self.module_tc_fails + 1
            if self.cfg.maxfail and self.module_tc_fails >= self.cfg.maxfail:
                self.abort_run(0, None, False)

        utils.dump_connections("Connections@FunctionComplete")
        self.log_time("function {} clean end".format(nodeid))

    def _build_fsysinfo(self, nodeid):
        module, name = paths.parse_nodeid(nodeid)
        row = [self.module_tc_executed]     # s.no
        off = self._init_sysinfo(row, module, name, len(self.sysinfo))
        for entry in self.sysinfo.values():
            self._fill_sysinfo(row, off, entry, "function")
        return row

    def _save_fsysinfo(self, nodeid, this_row=None):
        row = this_row or self._build_fsysinfo(nodeid)
        fsysinfo_csv = paths.get_fsysinfo_csv(self._context.logs_path)
        Result.write_report_csv(fsysinfo_csv, [row], ReportType.FSYSINFO, False, True)
        if not this_row:
            self._save_dsysinfo(nodeid)
            if not row[1]:
                self._dbg_sysinfo(nodeid, "FSYSINFO", "module")
            if not row[2]:
                self._dbg_sysinfo(nodeid, "FSYSINFO", "function")
            if not row[4] or not row[5]:
                self._dbg_sysinfo(nodeid, "FSYSINFO", "values", row)

    def _build_dsysinfo(self, nodeid, dtype="function"):
        module, func = paths.parse_nodeid(nodeid)
        rows = []
        for dut, entry in self.sysinfo.items():
            row = [self.module_tc_executed]     # s.no
            off = self._init_sysinfo(row, module, func, dut)
            self._fill_sysinfo(row, off, entry, dtype)
            rows.append(row)
        return rows

    def _save_dsysinfo(self, nodeid, this_rows=None, dtype="function"):
        rows = this_rows or self._build_dsysinfo(nodeid, dtype)
        dsysinfo_csv = paths.get_dsysinfo_csv(self._context.logs_path)
        Result.write_report_csv(dsysinfo_csv, rows, ReportType.DSYSINFO, False, True)
        if not this_rows:
            for row in rows:
                if not row[1]:
                    self._dbg_sysinfo(nodeid, "DSYSINFO", "module")
                if not row[2]:
                    self._dbg_sysinfo(nodeid, "DSYSINFO", "function")
                if not row[4] or not row[5]:
                    self._dbg_sysinfo(nodeid, "DSYSINFO", "values", row)

    def _dbg_sysinfo(self, nodeid, itype, dtype, row=""):
        # self.error("{}: invalid {} {} {}".format(itype, dtype, nodeid, row))
        # self.log("sysinfo-debug: {}".format(self.sysinfo))
        pass

    def _report_file_generation(self):
        self.log_time("report file generation start")

        self._context.execution_end_time = get_timenow()
        total_tc_time_taken = get_elapsed(self._context.total_tc_start_time, True)

        data = generate.update_reports(self._context.execution_start_time,
                                       self._context.execution_end_time,
                                       self._context.session_init_time_taken,
                                       total_tc_time_taken, len(self.swver))
        logs_path = _get_logs_path()[1]
        report_txt = paths.get_summary_txt(logs_path)
        with open(report_txt, "w") as ofh:
            ofh.write(data)
            last_dut_version = ""
            duts_sw_versions = []
            ver_dut_map = utils.invert_dict(self.swver)
            for swver, dut in ver_dut_map.items():
                duts_sw_versions.append("{} : {}".format(dut, swver))
                last_dut_version = swver
            ofh.write("\nSoftware Versions = {}".format(",".join(duts_sw_versions)))
            ofh.write("\nSoftware Version = {}".format(last_dut_version))

        self.log_time("report file generation end")
        return data

    def _trace_missing_parallel_operations(self, nodeid):
        stats = self._context.net.get_stats()
        if stats.canbe_parallel:
            msg = "yet to be parallized: {}".format(nodeid)
            utils.banner(msg, func=ftrace)
            for [start_time, msg, dut1, dut2] in stats.canbe_parallel:
                ftrace(start_time, msg, dut1, dut2)
            utils.banner(None, func=ftrace)

    def _test_log_finish(self, nodeid, func_name, res, desc, time_taken):

        if isinstance(time_taken, int):
            time_taken = utils.time_format(time_taken)

        self._trace_missing_parallel_operations(nodeid)

        # Construct the final result log message to print in all log files.
        msg = "Report({}):{} {} {}".format(res, nodeid, time_taken, desc)
        last_report_line = self.get_last_report_line()
        if last_report_line is not None:
            msg = "{} @{}".format(msg, last_report_line)
        self.log("--------- {} ---------".format(msg))

        self._write_stats(nodeid, res, desc, time_taken)
        self._context.net.tc_start()
        for dut in self.get_dut_names():
            self.dut_log(dut, msg, dst=["dut"])
        self._context.publish(nodeid, func_name, time_taken)
        self.log_time("Test Time ({} - {}) Published".format(self.current_tc_start_time, get_timenow()))

        # bailout the node if the infra test failed
        if res != "Pass" and batch.is_batch() and batch.is_infra_test(nodeid):
            desc = "{} in {}".format(desc, func_name)
            self.set_node_dead(None, desc, False)

    def _write_stats(self, nodeid, res, desc, time_taken):
        module, func = paths.parse_nodeid(nodeid)
        if batch.is_infra_test(func):
            return
        logs_path = _get_logs_path()[1]
        stats_csv = paths.get_stats_csv(logs_path)
        stats_txt = paths.get_stats_txt(logs_path)
        with open(stats_txt, "a") as ofh:
            ofh.write("\n======================= STATS: {} ===========================".format(nodeid))
            stats = self._context.net.get_stats()
            stats.tc_total_wait = utils.time_format(stats.tc_total_wait)
            stats.tg_total_wait = utils.time_format(stats.tg_total_wait)
            stats.tc_cmd_time = utils.time_format(stats.tc_cmd_time, True)
            stats.helper_cmd_time = utils.time_format(stats.helper_cmd_time, True)
            stats.tg_cmd_time = utils.time_format(stats.tg_cmd_time, True)
            ofh.write("\nRESULT = {}".format(res))
            ofh.write("\nDESCRIPTION = {}".format(desc))
            ofh.write("\nTOTAL Test Time = {}".format(time_taken))
            ofh.write("\nTOTAL Sleep Time = {}".format(stats.tc_total_wait))
            ofh.write("\nTOTAL TG Sleep = {}".format(stats.tg_total_wait))
            ofh.write("\nTOTAL CMD Time = {}".format(stats.tc_cmd_time))
            ofh.write("\nTOTAL HELPER Time = {}".format(stats.helper_cmd_time))
            ofh.write("\nTOTAL TG Time = {}".format(stats.tg_cmd_time))
            ofh.write("\nTOTAL PROMPT NFOUND = {}".format(stats.pnfound))
            ofh.write("\nTOTAL TECH SUPPORT = {}".format(stats.ts_files))
            for [start_time, thid, ctype, dut, cmd, ctime] in stats.cmds:
                start_msg = "\n{} {}".format(get_timestamp(this=start_time), thid)
                if ctype == "CMD":
                    ofh.write("{}CMD TIME: {} {} = {}".format(start_msg, ctime, dut, cmd))
                elif ctype == "HELPER":
                    ofh.write("{}HELPER TIME: {} {} = {}".format(start_msg, ctime, dut, cmd))
                elif ctype == "TG":
                    ofh.write("{}TG TIME: {} = {}".format(start_msg, ctime, cmd))
                elif ctype == "WAIT":
                    ofh.write("{}WAIT TIME: {} = {}".format(start_msg, ctime, cmd))
                elif ctype == "TGWAIT":
                    ofh.write("{}TGWAIT TIME: {} = {}".format(start_msg, ctime, cmd))
                elif ctype == "PROMPT_NFOUND":
                    ofh.write("{}PROMPT NFOUND: {}".format(start_msg, cmd))
                elif ctype == "TECH_SUPPORT":
                    ofh.write("{}TECH SUPPORT: {}".format(start_msg, cmd))
            ofh.write("\n=========================================================\n")
        try:
            self.stats_count = self.stats_count + 1
        except Exception:
            self.stats_count = 1
        row = [self.stats_count, module, func, res, time_taken, stats.helper_cmd_time,
               stats.tc_cmd_time, stats.tg_cmd_time, stats.tc_total_wait,
               stats.tg_total_wait, stats.pnfound, stats.ts_files, desc.replace(",", " ")]
        Result.write_report_csv(stats_csv, [row], ReportType.STATS, False, True)

    def get_device_names(self, dtype):
        """
        This method is used to get all device names of given type

        :return: all device names or device names of given type
        :rtype: list
        """
        return self._context._tb.get_device_names(dtype)

    def get_dut_names(self):
        """
        This method is used to get all the DUT names

        :return: names of all the duts
        :rtype: list
        """
        return self.get_device_names("DUT")

    def get_tg_names(self):
        """
        This method is used to get all the TG names

        :return: names of all the TG
        :rtype: list
        """
        return self.get_device_names("TG")

    def get_tg_type(self, name=None):
        return tgapi.get_tg_type(name)

    def _build_native_map(self, native):
        native_map = dict()
        for dut in self.get_dut_names():
            native_map[dut] = self._is_ifname_native(dut, native)
        return native_map

    def _is_ifname_native(self, dut, native):
        if native is not None:
            return native
        ifname_type = self.get_ifname_type(dut)
        return bool(ifname_type in ["native", "none"])

    def map_ports(self, dut, ports, native=None):
        retval = []
        native = self._is_ifname_native(dut, native)
        for port in ports:
            if not native:
                port = self.map_port_name(dut, port)
            retval.append(port)
        return retval

    def get_connected_ports(self, dut, native=None):
        if dut in self.connected_ports:
            return self.map_ports(dut, self.connected_ports[dut], native)
        return []

    def get_reserved_ports(self, dut, native=None):
        if dut in self.reserved_ports:
            return self.map_ports(dut, self.reserved_ports[dut], native)
        return []

    def get_free_ports(self, dut, native=None):
        """
        This method gets all the ports that are not connected to either
        partner DUT or Traffic Generator

        :param dut: device under test
        :type dut:
        :return: all the free ports
        :rtype: list
        """
        if dut in self.free_ports:
            return self.map_ports(dut, self.free_ports[dut], native)
        return []

    def get_all_ports(self, dut, native=None):
        """
        This method gets all the ports that are not connected to either
        partner DUT or Traffic Generator

        :param dut: device under test
        :type dut:
        :return: all the free ports
        :rtype: list
        """
        if dut in self.all_ports:
            return self.map_ports(dut, self.all_ports[dut], native)
        return []

    def get_service_info(self, dut, name):
        return self._context._tb.get_service(dut, name)

    def get_links(self, dut, peer=None, native=None):
        return self._get_device_links(dut, peer, None, native)

    def _get_device_links_local(self, dut, peer=None, dtype=None, index=None, native=None):
        retval = []
        native = self._is_ifname_native(dut, native)
        for local, _, _ in self._get_device_links(dut, peer, dtype, native):
            retval.append(local)
        if index is None:
            return retval
        try:
            return [retval[int(index)]]
        except Exception:
            return []

    def get_dut_links_local(self, dut, peer=None, index=None, native=None):
        return self._get_device_links_local(dut, peer, "DUT", index, native)

    def _get_device_links(self, dut, peer=None, dtype=None, native=None):
        native_map = self._build_native_map(native)
        native = self._is_ifname_native(dut, native)
        ifmap = {} if native else self.alt_port_names
        return self._context._tb.get_links(dut, peer, dtype, False, ifmap, native_map)

    def get_dut_links(self, dut, peer=None, native=None):
        native = self._is_ifname_native(dut, native)
        return self._get_device_links(dut, peer, "DUT", native)

    def get_tg_links(self, dut, peer=None, native=None):
        native = self._is_ifname_native(dut, native)
        return self._get_device_links(dut, peer, "TG", native)

    def get_tg_info(self, tg=None):
        return self._context._tb.get_tg_info(tg)

    def get_device_alias(self, name, only=False, retid=False):
        return self._context._tb.get_device_alias(name, only, retid)

    def set_device_alias(self, dut, name):
        return self.net.set_device_alias(dut, name)

    def _rps_error(self, dut, msgid, report=True):
        if report:
            self.report_env_fail_int(dut, True, msgid)
        return []

    def get_rps(self, dut, report=True):
        rinfo_list = self._context._tb.get_rps(dut)
        if not rinfo_list:
            return self._rps_error(dut, "testbed_no_rps_info", report)
        for rinfo in rinfo_list:
            if "model" not in rinfo or not rinfo.model or rinfo.model in ["None", "none"]:
                return self._rps_error(dut, "testbed_no_rps_model", report)
            elif "ip" not in rinfo or not rinfo.ip:
                return self._rps_error(dut, "testbed_no_rps_ip", report)
            elif "outlet" not in rinfo or not rinfo.outlet:
                return self._rps_error(dut, "testbed_no_rps_outlet", report)
            elif "username" not in rinfo or rinfo.username is None:
                return self._rps_error(dut, "testbed_no_rps_username", report)
        return rinfo_list

    def moveto_grub_mode(self, dut):
        retval, rinfo_list = self.do_rps_int(dut, "reset", 1, recon=False)
        if self.is_dry_run():
            return True
        if retval:
            dinfo = self._context._tb.get_dut_access(dut)
            retval = rinfo_list[0].obj.grub_wait(dinfo["ip"], dinfo["port"])
        return retval

    def do_rps_int(self, dut, op, on_delay=None, off_delay=None, recon=True,
                   dead=False, log_file=None):
        """
        This method performs the RPS operations such as on/off/reset.
        RPS models supported are Raritan, ServerTech, Avocent
        and all are through telnet.
        The RPS information is obtained from the testbed file.
        :param dut: DUT identifier
        :type dut: basestring
        :param op: operation i.e. on/off/reset
        :return: True if the operation is successful else False
        """
        retval, rinfo_list = False, self.get_rps(dut)
        if self.is_dry_run():
            return True, None

        # build list of RPS operations
        if op == "reset" and len(rinfo_list) > 1:
            oplist = ["off", "on"]
            lastop = oplist[1]
        else:
            oplist = [op]
            lastop = op

        # create RPS object
        for rinfo in rinfo_list:
            if "port" not in rinfo:
                rinfo.port = 23
            rps = RPS(rinfo.model, rinfo.ip, rinfo.port, rinfo.outlet,
                      rinfo.username, rinfo.password, dut=str(dut), logger=self.get_logger())
            if "pdu_id" in rinfo:
                rps.set_pdu_id(rinfo.pdu_id)
            rinfo.obj = rps

        # perform operations
        for curop in oplist:
            for rinfo in rinfo_list:
                disc = bool(curop == lastop)
                if recon and disc:
                    self.net.do_pre_rps(dut, curop.lower())
                self.log("Performing RPS {} Device {}".format(curop, dut))
                try:
                    retval = bool(rinfo.obj.do_op(curop, on_delay, off_delay,
                                                  disc=disc, log_file=log_file))
                    if not retval:
                        self.error("Failed to perform RPS {}".format(curop))
                except Exception:
                    self.error(utils.stack_trace(None, True), dut=dut)
                    retval = False

        # perform post operations
        if recon:
            retval = self.net.do_post_rps(dut, op.lower(), dead)
            if not retval:
                self.error("Failed to reconnect post RPS")

        # done
        return retval, rinfo_list

    def do_rps(self, dut, op, on_delay=None, off_delay=None, recon=True, dead=False, log_file=None):
        retval, _ = self.do_rps_int(dut, op, on_delay, off_delay, recon, dead, log_file)
        return retval

    def do_ts(self, dut, op):
        """
        This method performs the terminal server operations such as show/kill.
        Terminal Server models supported are Digi, Avocent
        and all are through ssh.
        The terminal server information is obtained from the testbed file.
        :param dut: DUT identifier
        :type dut: basestring
        :param op: operation i.e. show/kill
        :return: True if the operation is successful else False
        """
        rinfo = self._context._tb.get_ts(dut)
        retval = False
        if not rinfo:
            self.report_env_fail_int(dut, True, "testbed_no_ts_info")
        elif "model" not in rinfo or not rinfo.model or rinfo.model in ["None", "none"]:
            self.report_env_fail_int(dut, True, "testbed_no_ts_model")
        elif "ip" not in rinfo or not rinfo.ip:
            self.report_env_fail_int(dut, True, "testbed_no_ts_ip")
        elif "cid" not in rinfo or not rinfo.cid:
            self.report_env_fail_int(dut, True, "testbed_no_ts_cid")
        elif "username" not in rinfo or rinfo.username is None:
            self.report_env_fail_int(dut, True, "testbed_no_ts_username")
        elif not self.is_dry_run():
            self.log("Performing Terminal Server Operation {}".format(op), dut=dut)
            ts = TermServ(rinfo.model, rinfo.ip, rinfo.cid,
                          rinfo.username, rinfo.password, desc=str(dut))
            if not ts.do_op(op):
                self.error("Failed to perform Terminal Server Operation {}".format(op), dut=dut)
            retval = True
        else:
            retval = True
        return retval

    def lock_topology(self, spec):
        """
        locks the topology to specified specification though
        current testbed topology has more than specified
        :param spec: needed topology specification
        :type spec: basestring
        :return: True if the operation is successful else False
        :rtype: bool
        """
        pass

    def _process_testbed_properties(self, tbvars, properties):
        if not properties:
            return
        if None in properties and "CONSOLE_ONLY" in properties[None]:
            self.net.set_console_only(True)
        for dut in tbvars.dut_list:
            did = tbvars.dut_ids[dut]
            ui_type = None
            if did in properties and "UI" in properties[did]:
                ui_type = properties[did]["UI"]
            elif None in properties and "UI" in properties[None]:
                ui_type = properties[None]["UI"]
            if ui_type:
                if ui_type in ui_types:
                    self.dut_ui_type[dut] = ui_type
                else:
                    self.error("Invalid UI Type {}".format(ui_type))

    def _get_csv_topo(self, mname=None, ignore=[]):
        if not self.module_info:
            for row in tcmap.read_module_csv()[1]:
                self.module_info[row[2]] = Testbed.preparse_topo(ignore, row[3])
        return self.module_info.get(mname, None)

    def debug_check_min_topology_abort(self):
        if self.verify_csv_min_topo > 101:
            desc = self._report("", "SKIPPED", "test_execution_skipped", "as we are asked to verify only min topology")
            self.pytest_skip(desc)

    def debug_check_min_topology(self, mname, *args, **kwargs):
        ignore = ["MODEL1", "MODEL2", "MODEL3", "MODEL4"]
        ignore.extend(["TGEN", "TGCARD", "TGSPEED"])
        ignore.extend(["CHIP", "CHIP_REV"])
        ignore.append("MODEL")
        prefix = "debug_check_min_topology: "
        mname = os.path.relpath(get_current_nodeid())
        call_topo = Testbed.preparse_topo(ignore, *args)
        csv_topo = self._get_csv_topo(mname, ignore)
        if csv_topo and csv_topo != call_topo:
            print_ftrace("{}{} mismatch CALL: {}".format(
                prefix, mname, call_topo or "D1"))
            print_ftrace("{}{} mismatch CSV : {}".format(
                prefix, mname, csv_topo or "D1"))
        elif call_topo and not csv_topo:
            print_ftrace("{}{} not found CALL: {}".format(
                prefix, mname, call_topo))

    def ensure_min_topology(self, *args, **kwargs):
        force = kwargs.get('force', False)
        if not force and self.verify_csv_min_topo > 0 and self.verify_csv_min_topo < 100:
            return self.get_testbed_vars(**kwargs)

        return self._ensure_min_topology(*args, **kwargs)

    def _ensure_min_topology(self, *args, **kwargs):
        """
        verifies if the current testbed topology satisfies the
        minimum topology required by test script
        :param spec: needed topology specification
        :type spec: basestring
        :return: True if current topology is good enough else False
        :rtype: bool
        """
        mname = get_current_nodeid().replace(".py", "")
        mname = os.path.basename(mname.replace("-", "_"))
        topo = env.get("SPYTEST_REPEAT_TOPO_{}".format(mname), "")
        if topo:
            new_args = list(args)
            new_args.append(topo)
            args = new_args
        fail = kwargs.get('fail', True)
        native = kwargs.get('native', None)
        self.log("Requested ensure_min_topology: {}".format(args))
        self.min_topo_called = True
        ftrace("ensure_min_topology", get_current_nodeid(), *args)

        # check min topology in modules csv
        if self.verify_csv_min_topo > 100:
            self.debug_check_min_topology(mname, *args, **kwargs)
            self.debug_check_min_topology_abort()

        errs, properties = self._context._tb.ensure_min_topology(*args, **kwargs)
        if not errs:
            topo_1 = self._context._tb.get_topo(True)
            topo_2 = self._context._tb.get_topo(False)
            self.log("Assigned topology: {}".format(topo_1))
            self.log("Assigned devices: {}".format(topo_2))
            tbvars = self.get_testbed_vars(native)
            self._process_testbed_properties(tbvars, properties)
            self.log("Assigned device List: {}".format(tbvars.dut_list))
            return tbvars

        if fail:
            self.report_topo_fail("min_topology_fail", errs, lvl=3)

        return None

    def get_testbed_vars(self, native=None):
        """
        returns the testbed variables in a dictionary
        :return: testbed variables dictionary
        :rtype: dict
        """
        ifmap = {} if native else self.alt_port_names
        native_map = self._build_native_map(native)
        rv = self._context._tb.get_testbed_vars(ifmap, native_map)
        for dut in self.get_dut_names():
            if dut in self.app_vars:
                for name in self.app_vars[dut]:
                    if name not in rv:
                        rv[name] = dict()
                    rv[name][dut] = self.app_vars[dut][name]
            if dut in self.module_vars:
                for name in self.module_vars[dut]:
                    if name not in rv:
                        rv[name] = dict()
                    rv[name][dut] = self.module_vars[dut][name]
        rv["config"] = self.cfg
        return rv

    def get_dut_var(self, dut, name, default=None):
        if dut not in self.app_vars:
            return default
        if name is None:
            rv = SpyTestDict()
            if dut in self.app_vars:
                for key, value in self.app_vars[dut]:
                    rv[key] = value
            if dut in self.module_vars:
                for key, value in self.module_vars[dut]:
                    rv[key] = value
            return rv
        if dut in self.app_vars:
            if name in self.app_vars[dut]:
                return self.app_vars[dut][name]
        if dut in self.module_vars:
            if name in self.module_vars[dut]:
                return self.module_vars[dut][name]
        return default

    def clear_tc_results(self):
        self._context.tc_results.clear()

    def clear_module_vars(self, dut):
        self.module_vars[dut].clear()

    def add_module_vars(self, dut, name, value):
        dut_list = [dut] if dut else self.get_dut_names()
        for d in dut_list:
            self.module_vars[d][name] = value

    def set_module_params(self, dut, **kwargs):
        return self._context.net.set_module_params(dut, **kwargs)

    def set_function_params(self, dut, **kwargs):
        return self._context.net.set_function_params(dut, **kwargs)

    def get_mgmt_ifname(self, dut):
        return self._context.net.get_mgmt_ifname(dut)

    def get_mgmt_ip(self, dut):
        return self._context.net.get_mgmt_ip(dut)

    def get_config(self, dut, scope="current"):
        return self._context._tb.get_config(dut, scope)

    def get_build(self, dut, scope="current"):
        return self._context._tb.get_build(dut, scope)

    def get_breakout(self, dut, port_list=None):
        return self._context._tb.get_breakout(dut, port_list)

    def get_param(self, name, default):
        return self._context._tb.get_param(name, default)

    def get_device_param(self, dut, name, default):
        return self._context._tb.get_device_param(dut, name, default)

    def get_link_param(self, dut, local, name, default):
        native = self._is_ifname_native(dut, None)
        local = local if native else self.get_other_name(dut, local)
        return self._context._tb.get_link_param(dut, local, name, default)

    def get_tgen(self, name, port=None, tg=None):
        tbvars = self.get_testbed_vars()
        if name is not None:
            if name not in tbvars.tgen_ports:
                return (None, None)
            tg, _, port = tbvars.tgen_ports[name]
            return tgapi.get_tgen(port, tbvars[tg])
        if port is not None:
            return tgapi.get_tgen(port, tg)
        return (None, None)

    def get_tgen_handles(self, max_ports=0, name=None, tg=None, port=None):
        rv = SpyTestDict()
        tbvars = self.get_testbed_vars()
        if tg is None and port is not None:
            return (None, None)
        if tg is not None and port is None:
            return (None, None)
        if tg is not None and port is not None:
            return tgapi.get_tgen(port, tg)
        count = 0
        for name1, value in tbvars.tgen_ports.items():
            tg, _, port = value
            rv[name1] = tgapi.get_tgen(port, tbvars[tg])
            if max_ports != 0:
                count = count + 1
                if count >= max_ports:
                    break
        if name is None:
            return rv
        if name in rv:
            return rv[name]
        return (None, None)

    def get_run_config(self):
        return self.cfg

    def get_args(self, arg):
        if arg in self.cfg:
            return self.cfg[arg]
        return None

    def refresh_files(self):
        self.net.register_templates()

    def _record_cli_type(self, dut, rv):
        if self._is_save_cli_types():
            key = self.hooks.get_cli_type_record(dut, rv)
            if dut in self.cli_type_cache:
                self.cli_type_cache[dut][key] = 1
        return rv

    def _save_cli_type(self, nodeid):
        if batch.is_infra_test(nodeid):
            return
        if self._is_save_cli_types():
            logs_path = _get_logs_path()[1]
            fpath = paths.get_cli_type_log(nodeid, logs_path)
            utils.write_file(fpath, "")
            lines = []
            for dut in self.cli_type_cache:
                for name in self.cli_type_cache[dut]:
                    line = "{}\n".format(name)
                    if line not in lines:
                        utils.write_file(fpath, "{}\n".format(name), "a")
                        lines.append(line)

    def get_ui_type(self, dut=None, **kwargs):
        _, ui_type = generate._get_module_ui(current_module.name, self.cfg)
        dut = utils.make_list(dut)[0]
        cli_type = kwargs.get('cli_type', '')
        if cli_type:
            cli_type = cli_type.strip()
        if not cli_type:
            dut_ui_type = self.dut_ui_type.get(dut, '')
            if not dut_ui_type:
                if ui_type != "random":
                    cli_type = ui_type
                else:
                    cli_type = random.choice(random_ui_types)
            else:
                cli_type = dut_ui_type
                msg = "CLI-TYPE Forced to {} From Topology".format(cli_type)
                if dut:
                    self.dut_log(dut, msg, logging.DEBUG)
                else:
                    self.debug(msg)
        elif cli_type != ui_type:
            msg = "CLI-TYPE Forced to {} From caller".format(cli_type)
            if dut:
                self.dut_log(dut, msg, logging.DEBUG)
            else:
                self.debug(msg)
        if cli_type == "custom":
            cli_type = self.hooks.get_custom_ui(dut)
        return self._record_cli_type(dut, cli_type)

    def record_ui_type(self, dut=None, **kwargs):
        cli_type = kwargs.get('cli_type', '')
        return self._record_cli_type(dut, cli_type)

    def get_datastore(self, dut, name, scope):
        self.data_lock.acquire()
        if dut not in self.dmaps:
            self.dmaps[dut] = dict()
        if scope not in self.dmaps[dut]:
            self.dmaps[dut][scope] = dict()
        dmaps = self.dmaps[dut][scope]
        if name not in dmaps:
            dmaps[name] = DataMap(name)
        self.data_lock.release()
        return dmaps[name].get(scope)

    def exec_ssh(self, dut, username=None, password=None, cmdlist=[]):
        return self._context.net.exec_ssh(dut, username, password, cmdlist)

    def exec_remote(self, ipaddress, username, password, scriptpath, wait_factor=2):
        return self._context.net.exec_remote(ipaddress, username, password, scriptpath, wait_factor)

    def change_passwd(self, dut, username, password):
        return self._context.net.change_passwd(dut, username, password)

    def upload_file_to_dut(self, dut, src_file, dst_file, cft):
        return self._context.net.upload_file_to_dut(dut, src_file, dst_file, cft)

    def download_file_from_dut(self, dut, src_file, dst_file=None):
        return self._context.net.download_file_from_dut(dut, src_file, dst_file)

    def ansible_dut(self, dut, playbook, **kwargs):
        return self._context.net.ansible_dut(dut, playbook, **kwargs)

    def ansible_service(self, service, playbook, **kwargs):
        tbvars = self.get_testbed_vars()
        service_data = self.get_service_info(tbvars.D1, service)
        service_data["filemode"] = self.get_args("filemode")
        return self._context.net.ansible_service(service_data, playbook, **kwargs)

    def add_addl_auth(self, dut, username, password):
        self._context.net.add_addl_auth(dut, username, password)

    def set_port_defaults(self, dut, breakout=True, speed=True, section=None,
                          check_only=False):

        # init applicable ports and arguments
        all_ports, apply_args = [], [[], []]

        breakout_mode = self.get_cfg_breakout_mode(dut)

        # fill breakout settings arguments
        if breakout_mode != "none" and breakout:

            # get the breakout info from testbed file
            breakout_info = self._context._tb.get_breakout(dut, section=section)
            if not breakout_info:
                breakout_info = []

            for [l_port, l_breakout] in breakout_info:
                all_ports.append(l_port)
                apply_args[0].append(l_port)
                apply_args[0].append(l_breakout)

        # fill speed settings arguments
        if self.cfg.speed_mode != "none" and speed:

            # get the speed info from testbed file
            speed_info = self._context._tb.get_speed(dut)
            if not speed_info:
                speed_info = dict()

            for l_port, l_speed in speed_info.items():
                all_ports.append(l_port)
                apply_args[1].append(l_port)
                apply_args[1].append(l_speed)

        if check_only:
            return bool(all_ports)

        if not apply_args[0] and not apply_args[1]:
            return True

        # wait for system status before breakout
        self._ensure_system_ready(dut, "breakout_speed")

        if breakout_mode in ["static", "script"]:
            if all_ports:
                # trace interfaces to debug settings before port breakout
                self.dut_log(dut, "dump interface status before breakout", logging.DEBUG)
                self.hooks.get_interface_status(dut, ",".join(all_ports))
            return self.net.apply_remote(dut, "port-defaults", apply_args)

        if env.match("SPYTEST_BREAKOUT_USING_SSH", "1", "0"):
            change_in_tryssh = self.net.tryssh_switch(dut, True)
            retval_1 = self.hooks.set_port_defaults(dut, apply_args[0], apply_args[1])
            if change_in_tryssh:
                self.net.tryssh_switch(dut)
        else:
            retval_1 = self.hooks.set_port_defaults(dut, apply_args[0], apply_args[1])

        return retval_1

    def add_prevent(self, what):
        return self._context.net.add_prevent(what)

    def instrument(self, dut, scope):
        dut_list = [dut] if dut else self.get_dut_names()
        for d in dut_list:
            inst = self._context._tb.get_instrument(d, scope)
            if not inst:
                continue
            op = inst[0]
            rem_args = inst[1:]
            if op == "info":
                self.log(" ".join(rem_args))
            elif op == "warn":
                self.warn(" ".join(rem_args))
            elif op == "sh" or op == "cmds":
                self._apply_config_file_list(dut, rem_args)
            else:
                self.log("INSTRUMENT: {} = {}".format(scope, rem_args))

    def change_prompt(self, dut, mode, **kwargs):
        return self.net.change_prompt(dut, mode, **kwargs)

    def cli_config(self, dut, cmd, mode=None, skip_error_check=False, delay_factor=0, **kwargs):
        return self.net.cli_config(dut, cmd, mode, skip_error_check, delay_factor, **kwargs)

    def cli_show(self, dut, cmd, mode=None, skip_tmpl=False, skip_error_check=False, **kwargs):
        return self.net.cli_show(dut, cmd, mode, skip_tmpl, skip_error_check, **kwargs)

    def get_config_profile(self):
        profile = self._context._tb.get_config_profile()
        profile = profile or self.cfg.config_profile
        profile = profile or "na"
        return profile.lower()

    def get_device_type(self, dut):
        return self._context._tb.get_device_type(dut)

    def open_config(self, dut, template, var=None, **kwargs):
        return self.net.open_config(dut, template, var=var, **kwargs)

    def rest_init(self, dut, username, password, altpassword, cached=False, ip_changed=False):
        return self.net.rest_init(dut, username, password, altpassword, cached=cached, ip_changed=ip_changed)

    def rest_create(self, dut, path, data, *args, **kwargs):
        return self.net.rest_create(dut, path, data, *args, **kwargs)

    def rest_update(self, dut, path, data, *args, **kwargs):
        return self.net.rest_update(dut, path, data, *args, **kwargs)

    def rest_modify(self, dut, path, data, *args, **kwargs):
        return self.net.rest_modify(dut, path, data, *args, **kwargs)

    def rest_read(self, dut, path, *args, **kwargs):
        return self.net.rest_read(dut, path, *args, **kwargs)

    def rest_delete(self, dut, path, *args, **kwargs):
        return self.net.rest_delete(dut, path, *args, **kwargs)

    def rest_parse(self, dut, filepath=None, all_sections=False, paths=[], **kwargs):
        return self.net.rest_parse(dut, filepath, all_sections, paths, **kwargs)

    def rest_apply(self, dut, data):
        return self.net.rest_apply(dut, data)

    def rest_send(self, dut, api='', method='get', params=None, data=None, verify=False, retAs='json', **kwargs):
        """
        Sending REST request to DUT
        :param dut: targeted DUT device name
        :type dut: string
        :param api: REST API (path or complete url)
        :type api: string
        :param method: REST request method can be one of [get, post, patch, delete]; default is 'get'
        :type method: string
        :param params: URL parameters to append to the URL
        :type params: dict or list of tuples [(key, value)]
        :param data: attached body (for post, patch)
        :type data: dict, list of tuples [(key, value)], bytes, or file-like object
        :param verify: Enforce to verify TLS certificate; default is False
        :type verify: boolean
        :param retAs: return data format, can be one of [json, text, asis]; default is 'json'
        :type retAs: string
        :return: according to retAs; json object, plain text, or respond object
        :rtype: any
        """
        return self.net.rest_send(dut, api=api, method=method, params=params, data=data, verify=verify, retAs=retAs, **kwargs)

    def parse_show(self, dut, cmd, output, tmpl=None):
        return self.net.parse_show(dut, cmd, output, tmpl=tmpl)

    def remove_prompt(self, dut, output):
        return self.net.remove_prompt(dut, output)

    def show(self, dut, cmd, **kwargs):
        if self.is_vsonic(dut):
            self.wait(5, "before show command")
        instrument = kwargs.pop("instrument", True)
        if instrument:
            apis_instrument("pre-st.show", dut, cmd, **kwargs)
        retval = self.net.show(dut, cmd, **kwargs)
        if instrument:
            apis_instrument("post-st.show", dut, cmd, _output_=retval, **kwargs)
        return retval

    def config(self, dut, cmd, **kwargs):
        instrument = kwargs.pop("instrument", True)
        if instrument:
            apis_instrument("pre-st.config", dut, cmd, **kwargs)
        retval = self.net.config(dut, cmd, **kwargs)
        if instrument:
            apis_instrument("post-st.config", dut, cmd, _output_=retval, **kwargs)
        return retval

    def exec_ssh_remote_dut(self, dut, ipaddress, username, password, command=None, timeout=30, **kwargs):
        return self.net.exec_ssh_remote_dut(dut, ipaddress, username, password, command, timeout, **kwargs)

    def generate_tech_support_2(self, dut, name, force=False):
        if not force and self.has_get_tech_support("none"):
            self.debug("generate_tech_support({}): disabled".format(name), dut=dut)
            return

        # generate on single DUT
        if dut is not None and not isinstance(dut, list):
            self.debug("generate_tech_support({})".format(name), dut=dut)
            self.gen_net_tech_support([dut], name)
            return

        # prepare list of devices to execute
        if dut is None:
            dut_list = self.get_dut_names()
            self.debug("generate_tech_support({}): all".format(name))
        else:
            dut_list = utils.make_list(dut)
            self.debug("generate_tech_support({}): {}".format(name, dut_list))

        # use parallel calls when called from main
        if putil.is_main_thread():
            self.gen_net_tech_support(dut_list, name)
            return

        # use serial calls when called from thread
        self.warn("generate_tech_support -- serial {}".format(putil.get_thread_name()))
        for d in self.get_dut_names():
            self.gen_net_tech_support([d], name)

    def collect_core_files_2(self, dut, name, force=False):
        if not force and self.has_fetch_core_files("none"):
            self.debug("collect_core_files({}): disabled".format(name), dut=dut)
            return

        # generate on single DUT
        if dut is not None and not isinstance(dut, list):
            self.debug("collect_core_files({})".format(name), dut=dut)
            self.net.collect_core_files(dut, name)
            return

        # prepare list of devices to execute
        if dut is None:
            dut_list = self.get_dut_names()
            self.debug("collect_core_files({}): all".format(name))
        else:
            dut_list = utils.make_list(dut)
            self.debug("collect_core_files({}): {}".format(name, dut_list))

        # use parallel calls when called from main
        if putil.is_main_thread():
            self._foreach(dut_list, self.net.collect_core_files, name)
            return

        # use serial calls when called from thread
        self.warn("collect_core_files -- serial {}".format(putil.get_thread_name()))
        for d in self.get_dut_names():
            self.net.collect_core_files(d, name)

    def gen_net_tech_support(self, dut_list, name):
        self._foreach(dut_list, self.net.generate_tech_support, name)
        mname = current_module.name
        try:
            self.module_tscount[mname] = self.get_ts_count(mname) + len(dut_list)
        except Exception:
            pass

    def generate_tech_support_1(self, dut, name, force=False):
        if not force and self.has_get_tech_support("none"):
            self.debug("generate_tech_support({}): disabled".format(name), dut=dut)
        elif dut is None:
            self.debug("generate_tech_support({}): all".format(name), dut=dut)
            self.gen_net_tech_support(self.get_dut_names(), name)
        elif isinstance(dut, list):
            self.debug("generate_tech_support({})".format(name), dut=dut)
            self.gen_net_tech_support(dut, name)
        else:
            self.gen_net_tech_support([dut], name)

    def collect_core_files_1(self, dut, name, force=False):
        if not force and self.has_fetch_core_files("none"):
            self.debug("collect_core_files({}): disabled".format(name), dut=dut)
        elif dut is None:
            self.debug("collect_core_files({}): all".format(name), dut=dut)
            self._foreach_dev(self.net.collect_core_files, name)
        elif isinstance(dut, list):
            self.debug("collect_core_files({})".format(name), dut=dut)
            self._foreach(dut, self.net.collect_core_files, name)
        else:
            self.net.collect_core_files(dut, name)

    def gen_rps_debug_info(self, dut):
        if not env.match("SPYTEST_RPS_DEBUG", "1", "1"):
            return
        dut = utils.make_list(dut or self.get_dut_names())[0]
        if not self.is_sonicvs(dut) and not self.is_vsonic(dut):
            # no need to fetch for non VS runs
            return
        if not self.get_rps(dut, False):
            # no rps info
            return
        try:
            log_file = self.net.make_local_file_path(dut, prefix="debug-vsh", ext=".log")
            self.do_rps(dut, "debug", recon=False, log_file=log_file)
            self.dut_log(dut, "VSH DEBUG file {}".format(log_file))
        except Exception:
            self.dut_log(dut, "Exception performing RPS debug", lvl=logging.ERROR)

    def generate_tech_support(self, dut, name, force=False):
        detect = env.get("SPYTEST_DETECT_CONCURRENT_ACCESS")
        if detect != "0":
            self.generate_tech_support_1(dut, name, force)
        else:
            self.generate_tech_support_2(dut, name, force)

        # collect the RPS debug info
        self.gen_rps_debug_info(dut)

    def collect_core_files(self, dut, name, force=False):
        detect = env.get("SPYTEST_DETECT_CONCURRENT_ACCESS")
        if detect != "0":
            self.collect_core_files_1(dut, name, force)
        else:
            self.collect_core_files_2(dut, name, force)

    def save_sairedis(self, dut, name, clear=False):
        op = "clear" if clear else "read"
        self.net.apply_remote(dut, "sairedis", [op, name])

    def syslog_check(self, dut, scope, lvl, name):
        return self.net.syslog_check(dut, scope, lvl, name)

    def get_credentials(self, dut):
        return self.net.get_credentials(dut)

    def _trace_cli(self, dut, mode, cmd):
        if self._is_save_cli_cmds():
            if dut not in self.cli_records:
                self.cli_records[dut] = []
            cmd = cmd.replace("\r\n", "\\r\\n")
            cmd = cmd.replace("\n", "\\n")
            cmd = cmd.replace("\r", "\\r")
            module, func = paths.parse_nodeid(current_test.nodeid)
            module = current_module.name
            if current_test.phase == "test_module_begin":
                phase = "module-prolog"
            elif current_test.phase == "test_class_begin":
                phase = "class-prolog"
            elif current_test.phase == "test_function_begin":
                phase = "function-prolog"
            elif current_test.phase == "test_function_end":
                phase = "function-or-epilog"
            elif current_test.phase == "global_function_finish":
                phase = "module-or-class-epilog"
            elif current_test.phase == "test_class_finish":
                phase = "module-epilog"
            else:
                phase = "framework"
            entry = [phase, module, func, dut, mode, cmd]
            self.cli_records[dut].append(entry)

    def _save_cli(self, nodeid):
        self._save_cli_type(nodeid)
        if self._is_save_cli_cmds():
            logs_path = _get_logs_path()[1]
            fpath = paths.get_cli_log(nodeid, logs_path)
            utils.write_file(fpath, "")
            for _, mode_cmd_list in self.cli_records.items():
                for entry in mode_cmd_list:
                    line = ",".join(entry) + "\n"
                    utils.write_file(fpath, line, "a")

    def dump_all_commands(self, dut, type='click'):
        return self.net.dump_all_commands(dut, type)

    def poll_wait(self, delay, timeout, method, *args, **kwargs):

        rv = bool(method(*args, **kwargs))
        if rv or self.is_dry_run():
            return rv

        # retry after sleep
        t = time.time() + timeout
        while True:
            time.sleep(delay)
            if time.time() > t:
                break
            if method(*args, **kwargs):
                return True
        return False

    def check_skips(self, threads):
        for thread in threads:
            skip = self.skips.get(putil.get_thread_name(thread))
            if skip:
                return True
        return False

    def handle_skips(self, result):
        retvals, exceptions, threads = result
        for thread in threads:
            if not thread:
                continue
            skip = self.skips.get(putil.get_thread_name(thread))
            if not skip:
                continue
            if skip == 1:
                pytest.xfail("xfail")
            if skip == 2:
                pytest.skip("skip")
            break
        return [retvals, exceptions]

    def exec_all(self, entries, first_on_main=False):
        rv = putil.exec_all2(self.cfg.faster_init, "abort", entries,
                             first_on_main)
        return self.handle_skips(rv)

    def exec_each(self, items, func, *args, **kwargs):
        rv = putil.exec_foreach2(self.cfg.faster_init, "abort", items, func,
                                 *args, **kwargs)
        return self.handle_skips(rv)

    def exec_each2(self, items, func, kwarg_list, *args):
        rv = putil.exec_parallel2(self.cfg.faster_init, "abort", items, func,
                                  kwarg_list, *args)
        return self.handle_skips(rv)

    def is_feature_supported(self, name, dut=None):
        return self.feature.is_supported(name, dut)

    def getenv(self, name, default=None):
        return env.get(name, default)

    def infra_debug(self, msg):
        self.banner(msg)
        self.log(current_test)

    def init_base_config_db(self, dut):

        # recover the system by reboot - for next module
        recovery_methods = env.get("SPYTEST_SYSTEM_NREADY_RECOVERY_METHODS", "normal")
        for method in recovery_methods.split(","):
            try:
                self._init_base_config_db(dut)
                return
            except Exception:
                msg = "Failed to init config DB - trying to recover using {} reboot".format(method)
                self.dut_log(dut, msg, lvl=logging.ERROR)
                rv = self.net.reboot(dut, method, skip_exception=True)
                if rv:
                    return
                msg = "Failed to init config DB - failed to recover using {} reboot".format(method)
                self.dut_log(dut, msg, logging.ERROR)
                raise ValueError(msg)

    def apply_base_config_db(self, dut):
        if self.cfg.skip_load_config in ["base"]:
            return False
        apis_instrument("apply-base-config-dut-start", dut=dut)
        self.net.apply_remote(dut, "apply-base-config")
        apis_instrument("apply-base-config-dut-end", dut=dut)
        return True

    def save_config_db(self, dut, type="base"):
        if type == "base":
            self.net.apply_remote(dut, "save-base-config", on_cr_recover="retry3")
        else:
            self.net.apply_remote(dut, "save-module-config", on_cr_recover="retry3")

    def mktemp(self, dir=None):
        dir = dir or _get_logs_path()[1]
        return tempfile.mkstemp(dir=dir)[1]

    def unsupported_cli(self, cli_type, ret=False, lvl=1):
        line = utils.get_line_number(lvl)
        self.error("[{}]: UNSUPPORTED CLI TYPE -- {}".format(line, cli_type))
        return ret

    def get_result(self):
        return self._context.result.get(False)[0]

    def set_hostname(self, dut, hname=None):
        self.net.set_hostname(dut, hname)

    def do_ssh(self, ipaddress, username, password, **kwargs):
        return self.net.do_ssh(ipaddress, username, password, **kwargs)

    def do_ssh_disconnect(self, dut, conn_index):
        return self.net.do_ssh_disconnect(dut, conn_index)

    def get_current_testid(self):
        return get_current_nodeid()

    def get_cache(self, name, dut=None, default=None):
        self.data_lock.acquire()
        self.cache.setdefault(dut, dict())
        retval = self.cache[dut].get(name, default)
        self.data_lock.release()
        return retval

    def set_cache(self, name, value, dut=None):
        self.data_lock.acquire()
        self.cache.setdefault(dut, dict())
        self.cache[dut][name] = value
        self.data_lock.release()

    def del_cache(self, name, dut=None):
        self.data_lock.acquire()
        self.cache.setdefault(dut, dict())
        if name in self.cache[dut]:
            del (self.cache[dut][name])
        self.data_lock.release()

    def get_logger(self):
        return self._context.log

    def run_cmd(self, cmd, **kwargs):
        kwargs.setdefault("shell", True)
        kwargs.setdefault("stdout", subprocess.PIPE)
        kwargs.setdefault("stderr", subprocess.PIPE)
        kwargs.setdefault("universal_newlines", None)
        self.log("Executing: {}".format(cmd))
        proc = subprocess.Popen(cmd, **kwargs)
        outs, errs = proc.communicate()
        proc.wait()
        outs, errs = outs.decode('utf-8'), errs.decode('utf-8')
        rv = SpyTestDict()
        rv.returncode = proc.returncode
        rv.stdout, rv.stderr = outs, errs
        rv.command, rv.proc, rv.pid = cmd, proc, proc.pid
        return rv

    def get_login_password(self, dut):
        return self._context.net.get_login_password(dut)

    def register_cleanup(self, func, *args, **kwargs):
        return self._context.register_cleanup(func, *args, **kwargs)

    def tryssh_switch(self, dut, *args, **kwargs):
        return self.net.tryssh_switch(dut, *args, **kwargs)

    def fetch_and_get_mgmt_ip(self, dut, try_again=3, wait_for_ip=0, wait_for_ready=None):
        if wait_for_ready is not None:
            self.wait_system_status(dut, wait_for_ready)
        return self.net.fetch_and_get_mgmt_ip(dut, try_again=try_again, wait_for_ip=wait_for_ip)


def add_option(group, name, **kwargs):
    default = kwargs.pop("default", None)
    default = cmdargs.get_default_1(name, default)
    help = kwargs.pop("help", "")
    if default not in [None, ""]:
        if help:
            help = help + " -- "
        help = help + " default: {}".format(default)
    group.addoption(name, default=default, help=help, **kwargs)


def add_options(parser):
    group = parser.getgroup("SPyTest")
    add_option(group, "--testbed-file", action="store",
               metavar="<testbed file path>",
               help="testbed file path -- default: ./testbed.yaml")
    add_option(group, "--ignore-tcmap-errors", action="store", type=int,
               choices=[0, 1], help="Ignore errors in tcmap")
    add_option(group, "--test-suite", action="append", default=[], help="test suites")
    if env.match("SPYTEST_INCLUDE_MODULE_OPTION", "1", "0"):
        add_option(group, "--include-module", action="append", default=[], help="include given module")
    add_option(group, "--test-suite-exclude", action="append",
               default=[], help="tests that need to be excluded")
    add_option(group, "--tclist-bucket", action="append", help="use test cases from buckets")
    add_option(group, "--tclist-file", action="append", metavar="<test case list file path>",
               help="file contaning test function names to include")
    add_option(group, "--tclist-file-exclude", action="append",
               metavar="<exclude test case list file path>",
               help="file contaning test function names to exclude")
    add_option(group, "--tclist-csv", action="append", metavar="<test case list csv>",
               help="test case list csv")
    add_option(group, "--tclist-csv-exclude", action="append",
               metavar="<exclude test case list csv>",
               help="exclude test case list csv")
    add_option(group, "--logs-path", action="store", metavar="<logs folder path>",
               help="logs folder -- default: .")
    add_option(group, "--file-mode", action="store_true", help="Execute in file mode - deprecated use --dryrun <value>")
    add_option(group, "--dryrun", action="store", type=int, choices=[0, 1, 2],
               help="Dry Run <1> for dryrun DUT and TG, <2> for dryrun DUT only")
    add_option(group, "--quick-test", action="store_true",
               help="Disable options for a quick test")
    add_option(group, "--ut-mode", action="store_true",
               help="Disable options for unit tests")
    add_option(group, "--email", action="append", help="Email address(es) to send report to.")
    add_option(group, "--email-subject", action="store",
               help="Email subject to be used to send report")
    add_option(group, "--email-subject-nargs", action="store",
               nargs='+', metavar=("<email subject>"), default=[],
               help="Email subject to be used to send report. use --noop to terminate.")
    add_option(group, "--email-attachments", action="store", type=int, choices=[0, 1],
               help="Enable email attachments")
    add_option(group, "--skip-tgen", action="store_true",
               help="Skip connecting to traffic generator(s)")
    add_option(group, "--tgen-module-init", action="store", type=int,
               choices=[0, 1], help="Call TGEN module init")
    help_msg = """
        check port connection status in the topology
            <skip>     don't perform any check
            <abort>    perform shut/noshut to check correctness of connection details
                       while starting the run and abort run when any port is not up.
            <report>   same as 'abort' but without aborting the run
            <module>   check port status of all connection while starting test module and report it (default)
            <function> check port status of all connection while starting test function and report it
    """
    add_option(group, "--topology-check", action="append", help=help_msg,
               choices=['abort', 'report', 'skip', 'session', 'module', 'function'])
    add_option(group, "--skip-init-checks", action="store_true", default=False,
               help="Skip misc device checks before and after execution -- default: false")
    help_msg = """
        method used while applying configuration
            <none>     use built-in default (reload when routing-mode=split else force-reload (default)
            <reload>   config-reload when there is change in the current configuration
            <replace>  config-replace when there is change in the current configuration
            <reboot>   device reboot when there is change in the current configuration
            <rps-reboot>   device reboot using RPS when there is change in the current configuration
            <force-reload> config-reload even when there is no change in the current configuration
            <force-replace> config-replace even when there is no change in the current configuration
            <force-reboot> device reboot even when there is no change in the current configuration
            <force-rps-reboot> device reboot using RPS even when there is no change in the current configuration
    """
    add_option(group, "--load-config-method", action="store",
               choices=['none', 'reload', 'replace', 'reboot', 'rps-reboot',
                        'force-reload', 'force-replace', 'force-reboot', 'force-rps-reboot'], help=help_msg)
    add_option(group, "--skip-init-config", action="store_true",
               help="Skip loading initial configuration before and after execution")
    add_option(group, "--skip-load-config", action="store", choices=['base', 'module', 'none'],
               help="Skip loading configuration before and after test case execution")
    load_image_choice = utils.list_insert(load_image_types, "onie2", "none", "testbed", "random")
    add_option(group, "--load-image", action="store", choices=load_image_choice,
               help="Loading image before and after execution using specified method")
    add_option(group, "--ignore-dep-check", action="store", type=int,
               choices=[0, 1], help="Ignore depends mark in test cases")
    add_option(group, "--memory-check", action="store", choices=['test', 'module', 'none'],
               help="read memory usage - deprecated use --sysinfo-check", default=None)
    add_option(group, "--sysinfo-check", action=cmdargs.validate_exec_scope(True),
               help="read sysinfo check")
    add_option(group, "--syslog-check", action="store", choices=syslog.levels,
               help="read syslog messages of given level and clear all syslog messages")
    save_help = "save data of given type {} at given scope {}".format(cmdargs.save_types, cmdargs.save_scopes)
    add_option(group, "--save", action=cmdargs.validate_save(), metavar=("<type> <scope>"),
               help=save_help, nargs=2, default={})
    add_option(group, "--save-sairedis", action=cmdargs.validate_exec_scope(False),
               help="save sairedis messages - deprecated use --save sairedis function/module/function,module")
    add_option(group, "--save-warmboot", action="store", type=int,
               choices=[0, 1], help="save warmboot state")
    add_option(group, "--faster-init", action="store", type=int,
               choices=[0, 1], help="Enable speeding up initialization")
    help_msg = """
        Faster CLI.
            <0> disable (default)
            <1> enable for all modules
            <2> use the value from module info
    """
    add_option(group, "--faster-cli", action="store", type=int,
               choices=[0, 1, 2], help=help_msg)
    add_option(group, "--port-init-wait", action="store", type=int,
               help="Wait time in seconds for ports to come up - deprecated use --max-time port <value>")
    add_option(group, "--reboot-wait", action="store", type=int,
               help="Wait time in seconds for ports to come up after reboot - deprecated use --max-time reboot <value>")
    add_option(group, "--fetch-core-files", action=cmdargs.validate_exec_phase(exec_phases),
               help="Fetch the core files from DUT to logs location")
    add_option(group, "--get-tech-support", action=cmdargs.validate_exec_phase(exec_phases),
               help="Get the tech-support information from DUT to logs location")
    add_option(group, "--tc-max-timeout", action="store", type=int,
               help="Max time that a testcase can take to execute - deprecated use --max-time function <value>")
    add_option(group, "--module-init-max-timeout", action="store", type=int,
               help="Max time that a module initialization can take to execute - deprecated use --max-time module <value>")
    add_option(group, "--max-time", action=cmdargs.validate_max_time(),
               nargs='+', metavar=("<type> <value>"),
               help=cmdargs.max_time_help_msg, default={})

    add_option(group, "--results-prefix", action="store",
               help="Prefix to be used for results")
    add_option(group, "--results-compare", action="store",
               help="Compare the results with that are in given path")
    add_option(group, "--exclude-devices", action="store",
               help="exclude given duts from testbed")
    add_option(group, "--exclude-module", action="append", default=[],
               help="exclude given module from run")
    add_option(group, "--include-devices", action="store",
               help="include given duts from testbed")
    add_option(group, "--run-progress-report", action="store",
               type=int, help="send run progress report at given frequency")
    add_option(group, "--env", action=cmdargs.validate_env(), default={}, nargs='+',
               help="set environment variables", metavar=("<name>=<value>"))
    add_option(group, "--random-order", action="store", type=int,
               choices=[0, 1, 2, 3], help=cmdargs.random_order_help_msg)
    add_option(group, "--repeat-test", action=cmdargs.validate_repeat(),
               metavar=("<type>", "<times>"), nargs=2,
               help="repeat each test function given number of times")
    add_option(group, "--rps-reboot", action="store",
               metavar="<device names csv>",
               help="Reboot given devices using RPS")
    add_option(group, "--pde", action="store_true",
               help="PDE image support")
    add_option(group, "--tryssh", action="store", type=int,
               choices=[0, 1, 2], help=cmdargs.tryssh_help_msg)
    add_option(group, "--first-test-only", action="store_true",
               help="Execute only first test in each module - default: false - deprecated use --max-functions-per-module 1")
    add_option(group, "--max-functions-per-module", action="store", type=int, default=0,
               help="Execute only given number of functions in each module")
    add_option(group, "--config-profile", action="store",
               choices=['l2', 'l3', 'NA'], help="Profile to load - default: None")
    add_option(group, "--build-url", action="store",
               help="URL to load the build from - default: None")
    add_option(group, "--libsai-url", action="store",
               help="URL to load libsail.so - default: None")
    add_option(group, "--clear-tech-support", action="store", type=int,
               choices=[0, 1], help="Clears tech support data on the dut")
    add_option(group, "--module-epilog-tgen-cleanup", action="store", type=int,
               choices=[0, 1], help="Enable TGEN cleanup in module epilog")
    add_option(group, "--module-epilog", action="store", type=int,
               choices=[0, 1], help="Enable module epilog")
    add_option(group, "--graceful-exit", action="store", type=int,
               choices=[0, 1], help="Graceful exit on control+c")
    add_option(group, "--reuse-results", action="store",
               choices=['none', 'all', 'pass', 'allpass'],
               help="Reuse results from previous execution")
    help_msg = """
        Override link parameters in the testbed.
        Use __all__ for all DUTs and __all__ for all ports
    """
    add_option(group, "--link-param", action="append", nargs=4,
               metavar=("<DUT>", "<port>", "<param>", "<value>"), help=help_msg)
    help_msg = """
        Override device property in the testbed.
        Use __all__ for all DUTs
    """
    add_option(group, "--dev-prop", action="append", nargs=3,
               metavar=("<DUT>", "<property>", "<value>"), help=help_msg)
    help_msg = """
        Override device parameter in the testbed.
        Use __all__ for all DUTs
    """
    add_option(group, "--dev-param", action="append", nargs=3,
               metavar=("<DUT>", "<param>", "<value>"), help=help_msg)
    help_msg = "Override section names in the testbed."
    add_option(group, "--change-section", action="append", nargs=2,
               metavar=("<from>", "<to>"), help=help_msg)
    help_msg = """
        Override section values in the testbed. For example:
            --change-section-value builds/default/current http://NEW_URL
    """
    add_option(group, "--change-section-value", action="append", nargs=2,
               metavar=("<from>", "<to>"), help=help_msg)
    add_option(group, "--ixserver", action="append", help="override ixnetwork server")
    add_option(group, "--ui-type", action="store", choices=ui_types,
               help="CLI type needed in scripts execution")
    help_msg = """
        Port breakout configuration mode.
            <testbed> use breakout_mode from testbed file which can be [static, script, native, none]
            <static>  use static breakout utility in DUT (default).
            <script>  use spytest static breakout script.
            <native>  use CLI command for dynamic port breakout.
            <none>    do not perform any breakout
    """
    add_option(group, "--breakout-mode", action="store",
               choices=['static', 'script', 'native', 'testbed', 'none'], help=help_msg)
    help_msg = """
        Port speed configuration mode.
            <configured> apply speed settings as specified in testbed file (default)
            <connected>  apply speed settings as specified in testbed file ONLY for connected ports.
                         This will be supported in the future and current this is equivalent to <configured>.
            <none>       do not apply any speed settings
    """
    add_option(group, "--speed-mode", action="store",
               choices=['connected', 'configured', 'none'], help=help_msg)
    help_msg = """
        Interface name type.
            <testbed> use ifname-type from testbed file which can be [native, alias, none, std-ext, random]
            <native>  interfaces appear like Ethernet0, Ethernet1 etc
            <alias>   interfaces appear like Eth1/0, Eth1/1 etc. in klish
            <std-ext> interfaces appear like Eth1/0, Eth1/1 etc. in klish and click
            <none>    use current ifname-type
            <random>  randomly select among [native, alias, std-ext]
    """
    add_option(group, "--ifname-type", action="store",
               choices=['native', 'alias', 'none', 'testbed', "std-ext", "random"], help=help_msg)
    help_msg = """
        Enable/Disable manamgement vrf.
            <0>  Do nothing
            <1>  Enable management vrf
            <2>  Disable management vrf
    """
    add_option(group, "--mgmt-vrf", action="store", type=int, choices=[0, 1, 2], help=help_msg)
    add_option(group, "--device-feature-enable", default=[], action="append", help="Enable device feature - deprecated use --feature-enable <name>")
    add_option(group, "--device-feature-disable", default=[], action="append", help="Disable device feature - deprecated use --feature-disable <name>")
    add_option(group, "--device-feature-group", default=None, action="store", help="Choose feature group - deprecated use --feature-enable <name>")
    add_option(group, "--feature-enable", default=[], action="append", help="Enable feature")
    add_option(group, "--feature-disable", default=[], action="append", help="Disable feature")
    add_option(group, "--feature-group", default=None, action="store", help="Choose feature group")
    add_option(group, "--known-issues", action="append", metavar="<known issues file path>",
               help="known issues file path", default=[])

    add_option(group, "--routed-sub-intf", action="store_true", default=False,
               help="Enable support for routed sub interfaces - default: false")

    help_msg = """
        GCOV Support
            <0>  Disable GCOV data collection
            <1>  Enable GCOV data collection once per session
            <2>  Enable GCOV data collection once per module
    """
    add_option(group, "--gcov", action="store", type=int, choices=[0, 1, 2], help=help_msg)

    add_option(group, "--augment-modules-csv", action="append", default=[], nargs="*",
               help="Add additional lines to modules.csv")
    add_option(group, "--append-modules-csv", action="append", default=[], nargs="*",
               help="Add additional lines to modules.csv")
    add_option(group, "--change-modules-csv", action="append", default=[], nargs="*",
               help="change lines in modules.csv")

    add_option(group, "--sub-report", action=cmdargs.validate_sub_report(), default={}, nargs=4,
               help="Additional Sub Reports", metavar=("<name> <action> <type> <data>"))


def get_work_area():
    return gWorkArea


def set_work_area(val):
    global gWorkArea
    gWorkArea = val


def read_cfg_dict(config, group, name, default):
    value = config.getoption(group)
    if name in value:
        return value[name], False
    return default[name], True


def _create_work_area2(config):
    missing, missing_msg = [], ""
    for arg in config.args:
        if os.path.isfile(arg):
            continue
        if os.path.isdir(arg):
            continue
        missing.append(arg)
    if missing:
        missing_msg = utils.banner("Missing Paths: {}".format(",".join(missing)))
    cfg = SpyTestDict()
    cfg.filemode = config.getoption("--file-mode")
    cfg.dryrun = config.getoption("--dryrun", 0)
    if cfg.dryrun:
        cfg.filemode = True
    cfg.testbed = config.getoption("--testbed-file")
    cfg.logs_path = config.getoption("--logs-path")
    cfg.log_lvl = config.getoption("--log-level")
    cfg.test_suite = config.getoption("--test-suite")
    cfg.tclist_bucket = config.getoption("--tclist-bucket", None)
    cfg.email_csv = config.getoption("--email")
    if cfg.email_csv:
        cfg.email_csv = ",".join(cfg.email_csv)
    email_subject_args = " ".join(config.getoption("--email-subject-nargs", []))
    cfg.email_subject = email_subject_args or config.getoption("--email-subject", "Run Report")
    cfg.email_attachments = bool(config.getoption("--email-attachments", 0))
    cfg.skip_tgen = config.getoption("--skip-tgen")
    cfg.tgen_module_init = bool(config.getoption("--tgen-module-init", 1))
    cfg.load_config_method = config.getoption("--load-config-method")
    cfg.topology_check = config.getoption("--topology-check", ["module"])
    cfg.skip_init_config = config.getoption("--skip-init-config")
    cfg.skip_init_checks = config.getoption("--skip-init-checks")
    cfg.skip_load_config = config.getoption("--skip-load-config")
    cfg.load_image = config.getoption("--load-image", "onie")
    cfg.ignore_dep_check = bool(config.getoption("--ignore-dep-check"))
    mcheck = config.getoption("--memory-check")
    if mcheck is not None:
        cfg.sysinfo_check = "function" if mcheck == "test" else mcheck
    else:
        cfg.sysinfo_check = config.getoption("--sysinfo-check") or "none"
    cfg.syslog_check = config.getoption("--syslog-check")
    cfg.save = config.getoption("--save")
    val, isdef = read_cfg_dict(config, "--save", "sairedis", cmdargs.save_default)
    cfg.save_sairedis = config.getoption("--save-sairedis") if isdef else val
    cfg.save_config_db_json = read_cfg_dict(config, "--save", "config-db", cmdargs.save_default)[0]
    cfg.save_running_config = read_cfg_dict(config, "--save", "running-config", cmdargs.save_default)[0]
    cfg.save_warmboot = config.getoption("--save-warmboot")
    cfg.faster_init = bool(config.getoption("--faster-init", 1))
    cfg.fetch_core_files = config.getoption("--fetch-core-files")
    if cfg.fetch_core_files is None:
        cfg.fetch_core_files = cmdargs.get_default_2("--fetch-core-files", "session")
    cfg.get_tech_support = config.getoption("--get-tech-support")
    if cfg.get_tech_support is None:
        cfg.get_tech_support = cmdargs.get_default_2("--get-tech-support", "onfail-epilog")
    cfg.results_prefix = config.getoption("--results-prefix")
    cfg.results_compare = config.getoption("--results-compare")
    cfg.sub_report = {}
    for name, action, typ, data in config.getoption("--sub-report").values():
        cfg.sub_report.setdefault(name, {})
        cfg.sub_report[name].setdefault(action, {})
        cfg.sub_report[name][action].setdefault(typ, [])
        cfg.sub_report[name][action][typ].extend(data)
    cfg.exclude_devices = config.getoption("--exclude-devices")
    cfg.include_devices = config.getoption("--include-devices")
    cfg.run_progress_report = config.getoption("--run-progress-report", 0)
    cfg.rps_reboot = config.getoption("--rps-reboot", None)
    cfg.pde = config.getoption("--pde", False)
    cfg.quick_test = config.getoption("--quick-test", False)
    cfg.ut_mode = config.getoption("--ut-mode", False)
    cfg.first_test_only = bool(env.get("SPYTEST_FIRST_TEST_ONLY", "0") == "1")
    cfg.first_test_only = config.getoption("--first-test-only", cfg.first_test_only)
    cfg.max_functions_per_module = config.getoption("--max-functions-per-module", 0)
    cfg.tryssh = config.getoption("--tryssh", 0)
    cfg.random_order = config.getoption("--random-order", 1)
    cfg.env = config.getoption("--env", {})
    cfg.pdb_on_error = config.getoption("--pdb", False)
    x_flag = config.getoption("-x", False)
    exitfirst_flag = config.getoption("--exitfirst", False)
    cfg.exit_on_firstfail = True if x_flag or exitfirst_flag else False
    cfg.maxfail = config.getoption("--maxfail", 0)
    cfg.faster_cli = config.getoption("--faster-cli", 0)
    cfg.config_profile = config.getoption("--config-profile")
    cfg.build_url = config.getoption("--build-url")
    cfg.libsai_url = config.getoption("--libsai-url")
    cfg.clear_tech_support = bool(config.getoption("--clear-tech-support", 0))
    cfg.module_epilog_tgen_cleanup = config.getoption("--module-epilog-tgen-cleanup")
    cfg.module_epilog = config.getoption("--module-epilog")
    cfg.graceful_exit = config.getoption("--graceful-exit")
    cfg.reuse_results = config.getoption("--reuse-results")
    cfg.dev_prop = config.getoption("--dev-prop", [])
    cfg.dev_param = config.getoption("--dev-param", [])
    cfg.link_param = config.getoption("--link-param", [])
    cfg.change_section = config.getoption("--change-section", [])
    cfg.change_section_value = config.getoption("--change-section-value", [])
    cfg.ixserver = config.getoption("--ixserver", [])
    cfg.ui_type = config.getoption("--ui-type", "click")
    cfg.breakout_mode = config.getoption("--breakout-mode", "static")
    cfg.speed_mode = config.getoption("--speed-mode", "configured")
    cfg.ifname_type = config.getoption("--ifname-type", "native")
    cfg.mgmt_vrf = config.getoption("--mgmt-vrf", 0)
    cfg.feature_enable = config.getoption("--feature-enable", []) or config.getoption("--device-feature-enable", [])
    cfg.feature_disable = config.getoption("--feature-disable", []) or config.getoption("--device-feature-disable", [])
    cfg.feature_group = config.getoption("--feature-group") or config.getoption("--device-feature-group")
    cfg.routed_sub_intf = config.getoption("--routed-sub-intf", False)
    cfg.known_issues = config.getoption("--known-issues", [])
    cfg.gcov = config.getoption("--gcov", 0)

    val, _ = read_cfg_dict(config, "--max-time", "session", cmdargs.max_time_default)
    cfg.session_max_timeout = val
    val, isdef = read_cfg_dict(config, "--max-time", "reboot", cmdargs.max_time_default)
    cfg.reboot_wait = config.getoption("--reboot-wait") if isdef else val
    val, isdef = read_cfg_dict(config, "--max-time", "port", cmdargs.max_time_default)
    cfg.port_init_wait = config.getoption("--port-init-wait") if isdef else val
    val, isdef = read_cfg_dict(config, "--max-time", "module", cmdargs.max_time_default)
    cfg.module_max_timeout = config.getoption("--module-init-max-timeout") if isdef else val
    val, isdef = read_cfg_dict(config, "--max-time", "function", cmdargs.max_time_default)
    cfg.tc_max_timeout = config.getoption("--tc-max-timeout") if isdef else val

    if cfg.pde:
        cfg.skip_init_config = True
        cfg.skip_load_config = "base"

    if cfg.quick_test or cfg.ut_mode:
        cfg.load_image = "none"
        cfg.fetch_core_files = "none"
        cfg.get_tech_support = "none"
        cfg.syslog_check = "none"
        cfg.sysinfo_check = "none"
        cfg.topology_check = config.getoption("--topology-check", "skip")
        cfg.save_sairedis = "none"
        cfg.save_config_db_json = "none"
        cfg.ifname_type = "none"

    if cfg.quick_test:
        cfg.skip_load_config = "base"
        cfg.skip_init_config = True
        cfg.breakout_mode = "none"
        cfg.speed_mode = "none"
        os.environ["SPYTEST_TECH_SUPPORT_ONERROR"] = ""

    if cfg.ut_mode:
        env_defaults = {
            "SPYTEST_DATE_SYNC": "0", "SPYTEST_HOOKS_MGMT_IP_FORCE_IFCONFIG": "1",
            "SPYTEST_USE_NO_MORE": "0", "SPYTEST_REDIS_DB_USE_DEFAULT_PORTMAP": "1",
            "SPYTEST_ACCESS_DRIVER": "paramiko", "SPYTEST_BASE_CONFIG_METHOD": "current",
            "SPYTEST_SAVE_CLI_TYPE": "0", "SPYTEST_SAVE_CLI_CMDS": "0",
            "SPYTEST_LOGS_PER_DUT_SUPPORT": "0",
            "SPYTEST_LOGS_PER_MODULE_SUPPORT": "2",
            "SPYTEST_TECH_SUPPORT_ONERROR": "",
            "SPYTEST_SESSION_TGEN_CLEAN": "0",
            "SPYTEST_TGEN_DELAYED_CONNECT": "2",
            "SPYTEST_LOGS_TIME_FMT_ELAPSED": "1",
            "SPYTEST_UPDATE_RESERVED_PORTS": "0",
            "SPYTEST_REDO_BREAKOUT": "0",
            "SPYTEST_TGEN_P1_THREAD_WAIT": "5",
            "SPYTEST_MODULE_EPILOG_ENSURE_SYSTEM_READY": "0",
            "SPYTEST_PRESERVE_GNMI_CERT": "1",
            "SPYTEST_MESSAGE_STATS": "1",
        }
        for name, value in env_defaults.items():
            os.environ[name] = os.getenv(name, value)

    if cfg.filemode:
        os.environ["SPYTEST_TOPOLOGY_STATUS_ONFAIL_ABORT"] = ""

    wa = get_work_area()
    if not wa:
        try:
            wa = WorkArea(cfg)
        except Exception:
            for msg in utils.stack_trace(None, True):
                print_ftrace(msg)
            global_abort_run(2, None)
        set_work_area(wa)

    if missing_msg:
        print_ftrace(missing_msg)
        try:
            wa.warn(missing_msg)
        except Exception:
            pass

    return wa


def _create_work_area(request):
    wa = _create_work_area2(request.config)
    start = get_timenow()
    wa._session_init()
    wa.session_init_completed = True
    end = get_timenow()
    wa.log("session started in {} seconds".format(end - start))


def _delete_work_area():
    wa = get_work_area()
    if not wa:
        return

    wa._session_clean()

    if batch.is_master():
        consolidate_results(add_nes=True, ident="master")
    elif not batch.is_member():
        consolidate_results(ident="standalone")
    else:  # stand alone
        generate.sub_reports(_get_logs_path()[1], False)

    if not batch.is_worker():  # master/standalone
        generate.email_report()
        wa._context.email()

    if not batch.is_master():
        wa._context._cleanup_gracefully()

    set_work_area(None)

    try:
        bg_results.stop()
    except Exception:
        pass


def log_test_exception(excinfo, hook='test_function'):
    dtrace("log_test_exception", excinfo)
    wa = get_work_area()
    if not wa or not wa._context.log:
        return
    root = os.path.join(os.path.dirname(__file__), '..')
    root = os.path.abspath(root)
    dicts = os.path.join(root, "dicts.py")
    ex_msg = "{} {}".format(excinfo.typename, excinfo.value)
    msg = "Exception: {}".format(ex_msg)
    wa._context.log.error(msg)
    entries = traceback.extract_tb(excinfo.tb)
    index, has_exp, desc, msg_list = 0, False, "", []
    for item in reversed(entries):
        fname, line, func, text = item
        if not fname.startswith(root):
            continue
        fname = fname.replace(root, "")
        if not has_exp:
            if fname != dicts:
                desc = wa._context._report("ScriptError", "exception_name_file_line", ex_msg, fname, line)
                msg_list.append(desc)
                has_exp = True
        msg = "[{}] {}:{} {} {}".format(index, fname, line, func, text)
        index = index + 1
        msg_list.append(msg)
    wa.alert(msg_list, "Exception", skip_log=False)
    return desc


def _build_tclist_file(config, option="--tclist-file"):
    file_names = config.getoption(option, [])
    if not file_names and option == "--tclist-file":
        file_name = env.get("SPYTEST_TCLIST_FILE")
        if file_name:
            file_names = file_name.split(",")
    if not file_names:
        return None

    test_names = []
    for file_name in file_names:
        user_root = _get_logs_path()[1]
        if os.path.isfile(file_name):
            file_path = file_name
        else:
            file_path = os.path.join(user_root, file_name)
            if not os.path.isfile(file_path):
                msg = "Failed to locate test case list file {}".format(file_name)
                global_abort_run(8, msg)

        with utils.open_file(file_path) as fh:
            for test_name in fh:
                test_name = test_name.strip()
                if test_name and not test_name.startswith("#"):
                    test_names.append(test_name)
            if len(test_names) <= 0:
                msg = "no test cases are specified in test case list file"
                msg = "{} {}".format(msg, file_name)
                global_abort_run(9, msg)

    return test_names


def _build_tclist_csv(config, option="--tclist-csv"):
    tclist_csv_list = config.getoption(option, None)
    if not tclist_csv_list:
        return None
    test_names_list = []
    for tclist_csv in tclist_csv_list:
        test_names = tclist_csv.replace(",", ' ').split()
        if not test_names:
            msg = " ERROR: Must have at least one name in {}".format(option)
            global_abort_run(10, msg)
        test_names_list.extend(test_names)
    return test_names_list


def parse_suite_files(sin, sex, section=None, ume=False):
    return parse_suites(sin, sex, section, ume)


def _show_tcmap_errors():
    if batch.is_master():
        return
    tcm = tcmap.get()
    if tcm.errors:
        print_ftrace("===== TCMAP Errors ======")
        print_ftrace("\n".join(tcm.errors))
        print_ftrace("========================")


def _check_include_module(config, item):
    if env.match("SPYTEST_INCLUDE_MODULE_OPTION", "1", "0"):
        include_modules = config.getoption("--include-module")
        for module in include_modules:
            if item.location[0].endswith(module):
                return True
        if include_modules and os.path.relpath(item.location[0]) in include_modules:
            return True
    return False


def _build_selected_tests(config, items, test_names, exclude_test_names):
    global missing_test_names_msg
    seen_test_names = []
    selected_items = []
    deselected_items = []
    for item in items:
        alt_item_name = item.location[2][5:]
        if item.location[2] in exclude_test_names or item.nodeid in exclude_test_names:
            deselected_items.append(item)
        elif alt_item_name in exclude_test_names:
            deselected_items.append(item)
        elif test_names is None:
            selected_items.append(item)
        elif item.location[2] in test_names or item.nodeid in test_names:
            selected_items.append(item)
        elif alt_item_name in test_names:
            selected_items.append(item)
            seen_test_names.append(alt_item_name)
        elif _check_include_module(config, item):
            selected_items.append(item)
        else:
            deselected_items.append(item)
        seen_test_names.append(item.location[2])
        seen_test_names.append(item.nodeid)

    # trace missing tests
    if test_names is not None:
        missing_test_names = []
        for i in test_names:
            if i not in seen_test_names:
                if not batch.is_infra_test(i):
                    missing_test_names.append(i)
        if missing_test_names:
            m1 = "Ignoring below missing functions: Available {}\n  - "
            m2 = m1.format(len(items)) + "\n  - ".join(missing_test_names)
            print_ftrace(m2)
            missing_test_names_msg = m2
    return selected_items, deselected_items


def get_item_module_file(item):
    module = getattr(item, "module", None)
    if not module:
        module = item
    return module.__file__


def order_items(items, test_names):
    new_items, missing = [], []
    for item in items:
        for test_name in test_names:
            alt_item_name = item.location[2][5:]
            if test_name in [item.location[2], item.nodeid, alt_item_name]:
                new_items.append(item)
                break
        if item not in new_items:
            missing.append(item)
    new_items.extend(missing)
    items[:] = new_items


def shuffle_items(items, order=1):
    modules = OrderedDict()
    for item in items:
        mfile = get_item_module_file(item)
        if mfile not in modules:
            modules[mfile] = []
        modules[mfile].append(item)
    module_names = list(modules.keys())
    if order:
        seed = utils.get_random_seed()
        random.Random(seed).shuffle(module_names)
    new_items = []
    for module_name in module_names:
        module_items = modules[module_name]
        if order == 3:
            order = 2 if tcmap.get_module_info(module_name).random else 0
        if order == 2:
            random.Random(seed).shuffle(module_items)
        new_items.extend(module_items)
    items[:] = new_items


def batch_infra_tests_remove(items):
    prefix_items, new_items, suffix_items = [], [], []
    for item in items:
        rv = batch.is_infra_test(item.nodeid)
        if rv == 1:
            prefix_items.insert(0, item)
        elif rv == 2:
            prefix_items.insert(1, item)
        elif rv == 3:
            suffix_items.insert(0, item)
        else:
            new_items.append(item)
    items[:] = new_items
    return prefix_items, suffix_items


def batch_infra_tests_add(items, prefix_items, suffix_items):
    if batch.is_infra_test(None):
        new_items = []
        new_items.extend(prefix_items)
        new_items.extend(items)
        new_items.extend(suffix_items)
        items[:] = new_items


def generate_tests(config, metafunc):
    ordered_names = []
    addme = None
    for name in metafunc.fixturenames:
        if name == "global_module_hook_addl":
            addme = name
            continue
        if name == "global_function_hook":
            if addme:
                ordered_names.append(addme)
                addme = None
        ordered_names.append(name)
    metafunc.fixturenames[:] = ordered_names

    mfile = get_item_module_file(metafunc)
    repeat = env.get("SPYTEST_REPEAT_NAME_{}".format(mfile))
    if repeat:
        def repeat_ids(a):
            return '{0} '.format(a).strip()
        metafunc.parametrize('global_repeat_request', [repeat],
                             indirect=True, ids=repeat_ids, scope="module")
    scope, count = config.option.repeat_test
    if count <= 1:
        return

    def range_ids(a):
        return '{0}.{1}'.format(a + 1, count)
    metafunc.parametrize('global_repeat_request', range(count),
                         indirect=True, ids=range_ids, scope=scope)


def global_repeat_request(request):
    _, count = request.config.option.repeat_test
    if count <= 1:
        return None
    return request.param


def _add_repeat_tests(test_names, items):
    if not test_names:
        return
    test_names_list = []
    for testname in test_names:
        regex = r"^{}\[\D\S+\]".format(testname)
        for item in items:
            if re.match(regex, item.name):
                test_names_list.append(item.name)
    test_names.extend(test_names_list)
    return test_names


def _remove_excluded_modules(config, items):
    excluded_modules = config.getoption("--exclude-module", None)
    if not excluded_modules:
        return None
    new_items = []
    for item in items:
        module = item.location[0].split(':')[0]
        module = os.path.basename(module)
        if module not in excluded_modules:
            new_items.append(item)
    items[:] = new_items


def _remove_repeat_renamed(items):
    new_items = []
    for item in items:
        if not batch.is_renamed(item.nodeid):
            new_items.append(item)
        else:
            ftrace("remove renamed: {}".format(item.nodeid))
    items[:] = new_items


def _remove_parameterized(items):
    func_list = [item.location[2] for item in items]
    env_parameterized = env.get("SPYTEST_EXCLUDE_PARAMETERIZED", "0")
    new_items_check_1 = []
    if env_parameterized in ["0", "1"]:
        new_items_check_1 = []
        for item in items:
            func = item.location[2]
            parts = func.split("[")
            if parts[0] == func or parts[0] in func_list:
                new_items_check_1.append(item)
            else:
                ftrace("remove unused repeated: {} {}".format(item.nodeid, parts[0]))
        items[:] = new_items_check_1

    if env_parameterized in ["1"]:
        new_items_check_2 = []
        for item in items:
            func = item.location[2]
            if "[" in func and item not in new_items_check_1:
                ftrace("remove parameterized: {}".format(item.nodeid))
            else:
                new_items_check_2.append(item)
        items[:] = new_items_check_2


def modify_tests(config, items):

    orig_count = len(items)
    test_names = []

    # create PID file
    create_pid_file()

    # set the process name
    worker_id = _get_logs_path()[2]
    if worker_id:
        jobid = env.get("SPYTEST_JENKINS_JOB", "").upper()
        ps_name = "{}-{}".format(jobid, worker_id) if jobid else worker_id
        if not utils.set_ps_name(ps_name):
            ftrace("Failed to set the process name to {}".format(ps_name))

    # load the tcmap - verify later
    tcm = tcmap.load(False)
    for msg in tcm.warnings:
        ftrace(msg)

    # extract infra tests
    prefix_items, suffix_items = batch_infra_tests_remove(items)

    # get the test names from CSV if specified
    tclist_method = "csv"
    test_names = _build_tclist_csv(config)
    _add_repeat_tests(test_names, items)

    # --tclist-csv supersedes --tclist-file
    if not test_names:
        tclist_method = "file"
        test_names = _build_tclist_file(config)
        _add_repeat_tests(test_names, items)

    # prepare exclude list
    exclude_test_names = _build_tclist_file(config, "--tclist-file-exclude") or []
    exclude_test_names.extend(_build_tclist_csv(config, "--tclist-csv-exclude") or [])
    _add_repeat_tests(exclude_test_names, items)

    ############################################################################
    # exclude the test function is not present in TEST PATHS
    ############################################################################
    testpaths = []
    for testpath in env.get("SPYTEST_TEST_PATHS", "").split(","):
        if testpath:
            testpaths.append(os.path.abspath(testpath) + "/")
    if testpaths:
        for item in items:
            exclude, fspath = False, str(item.fspath)
            for testpath in testpaths:
                if fspath.startswith(testpath):
                    exclude = True
                    break
            if not exclude:
                exclude_test_names.append(item.name)
    ############################################################################

    if test_names or exclude_test_names:
        selected, deselected = _build_selected_tests(config, items, test_names, exclude_test_names)
        items[:] = selected
        config.hook.pytest_deselected(items=deselected)
        if tclist_method == "map":
            utils.banner("deselected tests cases", func=ftrace)
            for item in deselected:
                ftrace(item.nodeid)
            utils.banner(None, func=ftrace)
            utils.banner("selected tests cases", func=ftrace)
            for item in selected:
                ftrace(item.nodeid)
            utils.banner(None, func=ftrace)

    # remove from --exclude-module arg
    _remove_excluded_modules(config, items)

    # add infra only items
    batch_infra_tests_add(items, prefix_items, suffix_items)

    # remove parameterized and unused repeated
    _remove_parameterized(items)

    # remove the repeat renamed
    _remove_repeat_renamed(items)

    # order the items based on test names list
    if test_names:
        start_time = get_timenow()
        order_items(items, test_names)
        time_taken = get_elapsed(start_time, True)
        print_ftrace("ordering items took {}".format(time_taken))

    # verify the tcmap
    start_time = get_timenow()
    tcmap.verify(items)
    time_taken = get_elapsed(start_time, True)
    ftrace("tcmap verify took {}".format(time_taken))

    # ignore the test cases that are already completed
    exclude_executed_tests(config, items)

    # check for known markers
    item_utils.read_known_markers(items)

    # add the dependency
    if not config.getoption("--ignore-dep-check", 0):
        build_dependency(config, items)

    # shuffle the items for random order
    order = config.getoption("--random-order", 1)
    shuffle_items(items, order)

    # get the logs path
    logs_path = _get_logs_path()[1]

    # save the function names in file
    func_list = [item.location[2] for item in items]
    func_list.sort()
    out_file = paths.get_functions_txt(logs_path)
    utils.write_file(out_file, "\n".join(func_list))

    # save non-mapped function names
    if not batch.is_master():
        tcm = tcmap.get()
        out_file = paths.get_file_path("tcmap_add_functions", "txt", logs_path)
        utils.write_file(out_file, "\n".join(tcm.non_mapped))
        out_file = paths.get_file_path("tcmap_remove_functions", "txt", logs_path)
        utils.write_file(out_file, "\n".join(missing_test_names_msg))

    # save the test cases in file
    lines = []
    for item in items:
        func = item.location[2]
        module = item.location[0]
        tclist = tcmap.get_tclist(func)
        for tcid in tclist:
            comp = tcmap.get_comp(tcid) or ""
            lines.append(",".join([tcid, func, module, comp]))
    lines.sort()
    out_file = paths.get_testcases_txt(logs_path)
    utils.write_file(out_file, "\n".join(lines))

    # print counts
    final_count = len(items)
    print_ftrace("Tests considered {} and ignored {}".format(final_count, orig_count - final_count))

    # print items
    if batch.is_debug_collection():
        for item in items:
            print_ftrace(item.nodeid)

    # save effective tcmap
    if not batch.is_master():
        tcmap.save(filepath=os.path.join(logs_path, "tcmap.csv"), printerr=ftrace)


def get_result_files(logs_path):
    csv_files, retval = [], []
    if batch.is_worker():
        name = paths.get_results_name(True)
        csv_files.extend(glob.glob("{}/../*_{}.csv".format(logs_path, name)))
        tc_index = 2
    else:
        name = paths.get_results_name()
        csv_files.extend(glob.glob("{}/*_{}.csv".format(logs_path, name)))
        tc_index = 1
    for csv_file in csv_files:
        abs_path = os.path.abspath(csv_file)
        if abs_path not in retval:
            retval.append(abs_path)
    return [tc_index, retval]


def exclude_executed_tests(config, items):

    if batch.is_master():
        return

    reuse_results = config.getoption("--reuse-results", None)
    if reuse_results in ["none"]:
        return

    logs_path = _get_logs_path()[1]
    tc_index, csv_files = get_result_files(logs_path)

    # prepare reused test case list
    reused_results = OrderedDict()
    for csv_file in csv_files:
        for row in Result.read_report_csv(csv_file):
            if reuse_results in ["all"]:
                reused_results[row[tc_index]] = 1
            elif reuse_results in ["pass", "allpass"] and \
                    row[tc_index + 1] in ["Pass"]:
                reused_results[row[tc_index]] = 1

    # prepare reused module list
    selected_modules = dict()
    for item in items:
        if item.location[2] not in reused_results:
            selected_modules[item.location[0]] = 1

    # prepare selected items based on reused module list
    reused_test_results.clear()
    new_selected = OrderedDict()
    for item in items:
        if item.location[0] in selected_modules:
            if reuse_results in ["allpass"]:
                # current test is in selected tests and
                # we are excluding only all pass
                new_selected[item.location[2]] = item
                continue
        if item.location[2] not in reused_results:
            new_selected[item.location[2]] = item
        else:
            reused_test_results[item.location[2]] = 1
    items[:] = new_selected.values()


def collect_fail(fail):
    print_ftrace("Failed to collect {}".format(fail))


def collect_test(item):
    dtrace("collect_test", item)
    item_utils.collect(item)


def build_dependency(config, items):
    item_utils.build_dependency(items, ftrace)
    for item in items:
        selected_test_results[item.location[2]] = None


def check_dependency(name):
    errs = []
    item = item_utils.find(name)
    if not item:
        errs.append("some thing is wrong - failed to find test item")
        return errs
    marker = item.get_closest_marker("depends")
    if not marker:
        return None
    parts = name.split("[")
    if len(parts) > 1:
        suffix = "[{}".format(parts[1])
    else:
        suffix = ""
    for dep_name in marker.args:
        if selected_test_results[dep_name + suffix] != "Pass":
            errs.append(dep_name + suffix)
    return errs


current_test.excinfo = None
current_test.hook = ""
current_test.phase = ""
current_test.nodeid = ""
current_test.result = ""
current_test.result_desc = ""
current_module.start_time = None
current_module.end_time = None
current_module.time_taken = None
current_module.epilog_start = None
current_module.global_module_finished = True
current_module.global_module_finalized = True
current_module.user_module_finished = True
current_module.user_module_finalized = True
current_module.user_class_finished = True
current_module.name = ""
current_module.result = ""
current_module.result_desc = ""


def get_current_nodeid():
    return current_test.nodeid or current_module.name


def set_current_result(res=None, desc="", scope=""):
    if not desc or not res:
        if scope in ["", "module"]:
            current_module.result_desc = ""
            current_module.result = "Pass"
        if scope in ["", "test"]:
            current_test.result_desc = ""
            current_test.result = "Pass"
    elif current_test.hook in ["global_module", "test_module", "test_class"]:
        if not current_module.result_desc:
            current_module.result_desc = desc
            current_module.result = res
    elif current_test.hook in ["global_function", "test_function"]:
        if not current_test.result_desc:
            current_test.result_desc = desc
            current_test.result = res


def get_current_result(which):
    if which in ["module", "class"]:
        return current_module.result, current_module.result_desc
    return current_test.result, current_test.result_desc


def log_module_time_start():
    time_now = get_timenow()
    current_module.start_time = time_now
    current_module.time_taken = None
    wa = get_work_area()
    wa._context.net.tc_start(time_now)


def log_module_time_finish(nodeid=None, func_name=None):
    dtrace("log_module_time_finish", nodeid, func_name,
           current_module.start_time, current_module.time_taken)

    if not current_module.time_taken and current_module.start_time:
        current_module.end_time = get_timenow()
        current_module.time_taken = get_elapsed(current_module.start_time, True, min_time)

    wa = get_work_area()

    if nodeid and not func_name and current_module.time_taken:
        wa._write_stats(nodeid, "", "Module Configuration", current_module.time_taken)

    if nodeid and func_name and current_module.time_taken:
        wa._context.publish2(nodeid, None, None, current_module.time_taken, None, "", "Module Prolog")
        wa.log_time("Module Config Time ({} - {}) Published".format(current_module.start_time, current_module.end_time))
        current_module.time_taken = None
        current_module.start_time = None


def make_report(item, call):
    dtrace("make_report", item, call, call.excinfo)
    if call.excinfo and call.excinfo.typename not in ["XFailed", "Skipped"]:
        current_test.excinfo = call.excinfo
    else:
        current_test.excinfo = None


def log_report(report):
    wa = get_work_area()
    worker_id = getattr(report, "worker_id", None)
    if worker_id:
        log_report_master(report, wa)
    else:
        log_report_worker(report, wa)


def log_report_worker(report, wa):
    nodeid = item_utils.map_nodeid(report.nodeid)
    func_name = item_utils.get_func_name(report.nodeid)

    # record module finish time
    dtrace("log_report", report, func_name, current_test)
    if report.when == "setup" and func_name and wa:
        log_module_time_finish(nodeid, func_name)

    # fail tests when  the module config is failed
    if report.when == "setup" and report.outcome != "passed" and wa and func_name:
        if not current_test.excinfo:
            wa._test_log_init(nodeid, func_name)
            if current_test.hook == "global_function" and current_test.result == "Unsupported":
                # to avoid showing confusing ConfigFail when marker identifies as unsupported
                pass
            elif current_test.hook == "test_function":
                res, desc = get_current_result("function")
                if res not in ["TopoFail", "ScriptError"]:
                    res = "ConfigFail"
                desc = "{} @{}".format(desc, utils.get_line_number())
                wa._context.set_default_error(res, "pretest_config_failed", desc)
            elif wa.abort_module_msg:
                res, desc = wa.abort_module_res or 'SKIPPED', wa.abort_module_msg
                desc = "{} @{}".format(desc, utils.get_line_number())
                desc = wa._context._report(res, "msg", desc)
                wa._test_log_finish(nodeid, func_name, res, desc, min_time)
            elif wa.abort_function_msg:
                res, desc = 'SKIPPED', wa.abort_function_msg
                desc = "{} @{}".format(desc, utils.get_line_number())
                desc = wa._context._report(res, "msg", desc)
                wa._test_log_finish(nodeid, func_name, res, desc, min_time)
            else:
                res, desc = get_current_result("module")
                if res == "Pass":
                    res = "ConfigFail"
                desc = "{} @{}".format(desc, utils.get_line_number())
                desc = wa._context._report(res, "module_config_failed", desc)
                wa._save_fsysinfo(nodeid)
                wa._test_log_finish(nodeid, func_name, res, desc, min_time)
        else:
            if current_test.hook != "test_function":
                wa._test_log_init(nodeid, func_name)
                desc = log_test_exception(current_test.excinfo, current_test.hook)
                wa._test_log_finish(nodeid, func_name, "ConfigFail", desc, min_time)

    if report.when == "setup" and report.outcome == "passed" and wa:
        wa.event("Test Execution:", format_nodeid(nodeid))


def log_report_master(report, wa):
    batch.log_report_master(report)
    if report.when == "teardown":
        consolidate_results(wa.cfg.run_progress_report, True, ident="teardown")


def session_start(session):
    if env.get("SPYTEST_LIVE_RESULTS", "1") == "1":
        if not batch.is_worker():
            bg_results.start(consolidate_results, ident="background")


def consolidate_results(progress=None, thread=False, count=None, add_nes=False, ident=None):

    ident = ident or ""
    try:
        msg = "{} {}".format(ident, threading.get_native_id())
    except Exception:
        msg = ident

    ftrace("{} comparison report".format(msg))
    generate.compare_report()

    ftrace("{} generate email report {}".format(msg, count))
    generate.email_report(count)

    count = batch.get_member_count() if count is None else count
    if count < 1 or batch.get_worker_id() or not batch.is_batch():
        return

    # if threaded set event
    if thread and bg_results.is_valid():
        bg_results.run()
        return

    # check if we really need to do this
    if progress is not None and progress <= 0:
        return

    # generate progress reports
    ftrace("{} progress report {}".format(msg, add_nes))
    generate.consolidated_results(_get_logs_path()[1], add_nes=add_nes)


def compare_results(dir1, dir2, show_all=True):
    file1 = glob.glob(dir1 + "/*_result*.csv")
    file2 = glob.glob(dir2 + "/*_result*.csv")
    if not file1 or not file2:
        return
    rows1 = Result.read_report_csv(file1[0])
    rows2 = Result.read_report_csv(file2[0])
    results = SpyTestDict()
    for row in rows1:
        if not row[3]:
            continue
        key = "{}::{}".format(row[1], row[2])
        results[key] = [row[1], row[2], row[3], row[4]]
    for row in rows2:
        if not row[3]:
            continue
        key = "{}::{}".format(row[1], row[2])
        if key in results:
            results[key].extend([row[3], row[4]])
    for res in results:
        row = results[res]
        if show_all or row[2] != row[4]:
            print(row)


def session_finish(session, exitstatus):

    # stop the result thread if started
    if bg_results.is_valid():
        bg_results.stop()

    if not batch.finish():
        return

    consolidate_results(ident="finish")


def configure(config):

    config.addinivalue_line("markers", "inventory: this one is for specifying sub-tests.")

    logs_path = _get_logs_path()[1]
    root_logs_path = _get_logs_path(True)[1]

    if batch.configure(config, logs_path, root_logs_path):
        # create pseudo work area for the master
        wa = _create_work_area2(config)
        tcm = tcmap.load()
        batch.set_tcmap(tcm)
        batch.set_logger(wa._context.log)
    batch.set_abort_run(global_abort_run)


def unconfigure(config):

    if not batch.unconfigure(config):
        return

    # delete pseudo work area for the master
    _delete_work_area()


def parse_batch_args(numprocesses, buckets_csv, append_modules_csv, change_modules_csv):
    logs_path = _get_logs_path()[1]
    if env.match("SPYTEST_DEBUG_FTRACE_LOG", "1", "0"):
        global dtrace_log
        dtrace_log = True
    return batch.parse_args(numprocesses, buckets_csv, logs_path, append_modules_csv, change_modules_csv)


def make_scheduler(config, log):
    return batch.make_scheduler(config, log)


def configure_nodes(config, specs):
    return batch.configure_nodes(config, specs)


def configure_node(node):
    return batch.configure_node(node)


def begin_node(gateway):
    return batch.begin_node(gateway)


def finish_node(node, err):
    return batch.finish_node(node, err, Result.read_report_csv)


def log_devices_used_until_now(wa, fixturedef):
    # dbg_msg = "Devices used in the entire module till now {} {}:".format(fixturedef.scope, fixturedef.argname)
    # wa.event(dbg_msg, wa._get_devices_usage_list())
    pass


def format_nodeid(nodeid):
    module, func = paths.parse_nodeid(nodeid)
    return "{}::{}".format(module, func) if module else func


def get_request_id(request):
    rid = request.node.nodeid
    if not rid:
        rid = request.node.name
    retval = format_nodeid(rid)
    return item_utils.map_nodeid(retval)


def get_request_module_id(request):
    return get_request_id(request)


def get_request_function_id(request):
    return get_request_id(request)


def get_request_function_name(request):
    nodeid = get_request_function_id(request)
    return paths.parse_nodeid(nodeid)[1]


def hook_event(wa, name, fixturedef, request):
    if env.match("SPYTEST_USE_FULL_NODEID", "1", "0"):
        rid = get_request_id(request)
    else:
        rid = format_nodeid(fixturedef.baseid)
    wa.event(name, rid, fixturedef.argname)


def fixture_post_finalizer(fixturedef, request):
    dtrace("fixture_post_finalizer", fixturedef, request, current_test)

    wa = get_work_area()
    if not wa:
        return None

    if fixturedef.argname == "global_session_request":
        pass
    elif fixturedef.argname == "global_module_hook_addl":
        if not current_module.user_module_finalized:
            mid = get_request_module_id(request)
            wa._pre_module_epilog(mid)
    elif fixturedef.argname == "global_module_hook":
        current_test.phase = "global_module_finish"
        if not current_module.global_module_finalized:
            mid = get_request_module_id(request)
            result = "Pass: {}/{}".format(wa.module_tc_executed - wa.module_tc_fails, wa.module_tc_executed)
            wa.event("Framework Module Hook Finalize:", mid, result)
            current_module.global_module_finalized = True
            wa.log_time("Framework Module Hook Finalize")
            wa.module_log_init(None)
            used_devices = wa._get_devices_usage_list()
            wa.event("Devices used:", mid, len(used_devices), wa._get_devices_usage_list())
            batch.verify_bucket(mid, len(used_devices), wa.module_tc_fails)
            wa._set_device_usage_collection(False)
    elif fixturedef.argname == "global_function_hook":
        current_test.phase = "global_function_finish"
        fid = get_request_function_id(request)
        wa.event("Framework Function Hook Finalize:", fid)
        wa.log_time("Framework Function Hook Finalize")
        current_module.epilog_start = get_timenow()
        wa.tc_log_init(None)
        log_devices_used_until_now(wa, fixturedef)
        wa._set_device_usage_collection(True)
    elif fixturedef.argname == "__pytest_repeat_step_number":
        pass
    elif fixturedef.argname == "global_repeat_request":
        pass
    elif fixturedef.scope == "module":
        current_test.phase = "test_module_finish"
        if not current_module.user_module_finalized:
            mid = get_request_module_id(request)
            current_module.user_module_finalized = True
            hook_event(wa, "Module Hook Finalize:", fixturedef, request)
            set_current_result()
            time_taken = get_elapsed(current_module.epilog_start, True, min_time)
            if env.match("SPYTEST_USE_FULL_NODEID", "1", "0"):
                wa._context.publish2(mid, None, None, time_taken, None, "", "Module Epilog")
            else:
                wa._context.publish2(fixturedef.baseid, None, None, time_taken, None, "", "Module Epilog")
            current_module.epilog_start = None
            wa.log_time("User Module {} Hook Finalize".format(mid))
            log_devices_used_until_now(wa, fixturedef)
            wa._set_device_usage_collection(False)
    elif fixturedef.scope == "function":
        fid = get_request_function_id(request)
        current_test.phase = "test_function_finish"
        current_test.nodeid = fid  # CHECK THIS
        hook_event(wa, "Function Hook Finalize:", fixturedef, request)
        wa.log_time("User Function {} Hook Finalize".format(fid))
        log_devices_used_until_now(wa, fixturedef)
        wa._set_device_usage_collection(False)
    elif fixturedef.scope == "class":
        current_test.phase = "test_class_finish"
        hook_event(wa, "Class Hook Finalize:", fixturedef, request)
        wa._post_class_epilog(fixturedef.baseid)
        wa.log_time("User Class {} Hook Finalize".format(fixturedef.baseid))
    else:
        current_test.phase = "misc_finish"
        hook_event(wa, "Misc Hook Finalize:", fixturedef, request)
        wa.log_time("Misc {} Hook scope {} Finalize".format(fixturedef.baseid, fixturedef.scope))


def fixture_setup(fixturedef, request):
    dtrace("fixture_setup", fixturedef, request, current_test)

    wa = get_work_area()
    if not wa:
        return None

    if fixturedef.argname == "global_module_hook":
        mid = get_request_module_id(request)
        module_name = build_module_logname(mid)
        wa.module_log_init(module_name)
        wa.log_time("Framework Module Hook Start")
        log_module_time_start()
        current_test.hook = "global_module"
        current_test.phase = "global_module_begin"
        wa.event("Framework Module Hook:", mid)
        current_module.global_module_finished = False
        current_module.global_module_finalized = False
        current_module.name = ""
        current_test.nodeid = ""
        set_current_result()
        wa._set_device_usage_collection(False)
        log_devices_used_until_now(wa, fixturedef)
    elif fixturedef.argname == "global_module_hook_addl":
        pass
    elif fixturedef.argname == "global_function_hook":
        wa.tc_log_init(request.node.location[2])
        wa.log_time("Framework Function Hook Start")
        fid = get_request_function_id(request)
        log_module_time_finish(fid)
        current_test.hook = "global_function"
        current_test.phase = "global_function_begin"
        current_test.nodeid = ""
        wa.instrument(None, "pre-infra-module")
        wa.event("Framework Function Hook:", fid)
        wa._set_device_usage_collection(False)
        log_devices_used_until_now(wa, fixturedef)
    elif fixturedef.argname == "__pytest_repeat_step_number":
        pass
    elif fixturedef.argname == "global_repeat_request":
        pass
    elif fixturedef.scope == "module":
        mid = get_request_module_id(request)
        if wa.abort_module_msg:
            hook_event(wa, "SKIP Module Hook:", fixturedef, request)
            wa.pytest_skip(wa.abort_module_msg)
        wa.log_time("User Module {} Hook Start".format(mid))
        current_test.hook = "test_module"
        current_test.phase = "test_module_begin"
        set_current_result()
        hook_event(wa, "Module Hook:", fixturedef, request)
        wa.instrument(None, "pre-user-module")
        current_module.name = mid
        current_test.nodeid = ""
        current_module.user_module_finished = False
        current_module.user_module_finalized = False
        log_devices_used_until_now(wa, fixturedef)
    elif fixturedef.scope == "function":
        fid = get_request_function_id(request)
        res, desc = get_current_result("module")
        if res != "Pass" or desc:
            desc = desc or res
            desc = "{} @{}".format(desc, utils.get_line_number())
            desc = wa._context._report("ConfigFail", "module_config_failed", desc)
            wa.pytest_skip(desc)
        if wa.abort_module_msg:
            hook_event(wa, "SKIP Function Hook:", fixturedef, request)
            wa.pytest_skip(wa.abort_module_msg)
        wa.log_time("User Function {} Hook Start".format(fid))
        current_test.hook = "test_function"
        current_test.phase = "test_function_begin"
        current_test.nodeid = fid
        hook_event(wa, "Function Hook:", fixturedef, request)
        wa.instrument(None, "pre-user-func")
        log_devices_used_until_now(wa, fixturedef)
        set_current_result(scope="test")
    elif fixturedef.scope == "class":
        wa.log_time("User Class {} Hook Start".format(fixturedef.baseid))
        current_test.hook = "test_class"
        current_test.phase = "test_class_begin"
        hook_event(wa, "Class Hook:", fixturedef, request)
        current_module.user_class_finished = False
    else:
        wa.log_time("Misc {} Hook scope {} Start".format(fixturedef.baseid, fixturedef.scope))
        current_test.hook = "misc"
        current_test.phase = "misc_begin"
        hook_event(wa, "Misc Hook:", fixturedef, request)

    if not wa.base_config_verified:
        setattr(fixturedef, "cached_result", ["SKIP", None, None])
        return "SKIP"

    return None


def fixture_setup_finish(fixturedef, request):
    dtrace("fixture_setup_finish", fixturedef, request, current_test)

    wa = get_work_area()
    if not wa:
        return None

    if fixturedef.argname == "global_session_request":
        pass
    elif fixturedef.argname == "global_module_hook_addl":
        pass
    elif fixturedef.argname == "global_module_hook":
        current_test.phase = "global_module_end"
        mid = get_request_module_id(request)
        if not current_module.global_module_finished:
            current_module.global_module_finished = True
            wa.event("Framework Module Hook Finish:", mid)
            wa.log_time("Framework Module Hook end")
            wa._clear_devices_usage_list()
            wa._set_device_usage_collection(True)
            log_devices_used_until_now(wa, fixturedef)
    elif fixturedef.argname == "global_function_hook":
        fid = get_request_function_id(request)
        current_test.phase = "global_function_end"
        current_test.nodeid = fid  # CHECK THIS
        wa.instrument(None, "post-infra-module")
        wa.event("Framework Function Hook Finish:", fid)
        wa.log_time("Framework Function Hook end")
        wa._set_device_usage_collection(True)
        log_devices_used_until_now(wa, fixturedef)
    elif fixturedef.argname == "__pytest_repeat_step_number":
        pass
    elif fixturedef.argname == "global_repeat_request":
        pass
    elif fixturedef.scope == "module":
        mid = get_request_module_id(request)
        current_test.phase = "test_module_end"
        wa._set_device_usage_collection(False)
        log_devices_used_until_now(wa, fixturedef)
        if not wa.cfg.module_epilog:
            fixturedef._finalizers = []
        if not current_module.user_module_finished:
            current_module.user_module_finished = True
            wa.instrument(None, "post-user-module")
            hook_event(wa, "Module Hook Finish:", fixturedef, request)
            wa.log_time("User Module {} Hook end".format(mid))
    elif fixturedef.scope == "function":
        fid = get_request_function_id(request)
        current_test.phase = "test_function_end"
        log_devices_used_until_now(wa, fixturedef)
        wa.instrument(None, "post-user-func")
        fname = get_request_function_name(request)
        res, desc = get_current_result("test")
        wa._post_function_prolog(fname, res, desc)
        # set_current_result(scope="test")
        hook_event(wa, "Function Hook Finish:", fixturedef, request)
        wa.log_time("User Function {} Hook end".format(fid))
    elif fixturedef.scope == "class":
        current_test.phase = "test_class_end"
        wa._set_device_usage_collection(False)
        if not wa.cfg.module_epilog:
            fixturedef._finalizers = []
        if not current_module.user_class_finished:
            current_module.user_class_finished = True
            res, desc = get_current_result("module")
            wa._post_class_prolog(fixturedef.baseid, res, desc)
        hook_event(wa, "Class Hook Finish:", fixturedef, request)
        wa.log_time("User Class {} Hook end".format(fixturedef.baseid))
    else:
        current_test.phase = "misc_end"
        hook_event(wa, "Misc Hook Finish:", fixturedef, request)
        wa.log_time("Misc {} Hook scope {} end".format(fixturedef.baseid, fixturedef.scope))


def pyfunc_call(pyfuncitem, after):
    wa = get_work_area()
    if not wa:
        return None
    func_name = pyfuncitem.location[2]
    if after:
        wa._pre_function_epilog(func_name)
    elif wa.abort_module_msg:
        return wa.abort_module_msg


def fixture_callback(request, scope, isend):
    if scope == "session":
        if isend:
            return _delete_work_area()
        _create_work_area(request)
        return None

    wa = get_work_area()
    if not wa:
        return None

    filepath = request.fspath.basename
    if scope == "module":
        func = wa._module_clean if isend else wa._module_init
        return func(get_request_module_id(request), filepath)

    func_name = request.node.location[2]
    if scope == "function":
        func = wa._function_clean if isend else wa._function_init
        return func(get_request_function_id(request), func_name)

    return None
