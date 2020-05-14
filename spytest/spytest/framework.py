import os
import sys
import pdb
import csv
import time
import copy
import glob
from inspect import currentframe
from collections import OrderedDict
from operator import itemgetter
import traceback
import textwrap
import logging
import socket
import signal
import pytest

from apis.common.init import apis_register
from apis.common.init import apis_common_init
from apis.common.init import apis_common_clean

import utilities.common as utils
import utilities.parallel as putil
from spytest.net import Net
from spytest.logger import Logger
from spytest.result import Result
from spytest.testbed import Testbed
from spytest.rps import RPS
from spytest.dicts import SpyTestDict
from spytest.tgen import tg as tgapi
from spytest.version import get_git_ver
from spytest.datamap import DataMap
from spytest import batch
from spytest.st_time import get_timenow
from spytest.st_time import get_elapsed
from spytest.st_time import get_timestamp

bg_results = putil.ExecuteBackgroud()
min_time = 0
tcmap = SpyTestDict()
missing_test_names_msg = ""
collected_items = dict()
selected_test_items = OrderedDict()
must_fail_items = OrderedDict()
nodeid_test_names = dict()
selected_test_results = OrderedDict()
reused_test_results = OrderedDict()
current_test = SpyTestDict()
current_module = SpyTestDict()
gWorkArea = None
result_vals = ["PASS", "FAIL", "ENVFAIL", "SCRIPTERROR", "DEPFAIL", \
               "CONFIGFAIL", "SKIPPED", "TIMEOUT", "TOPOFAIL", \
               "TGENFAIL", "DUTFAIL", "UNSUPPORTED"]
report_cols = ["Execution Started", "Execution Completed", "Execution Time", \
               "Session Init Time", "Tests Time"]
report_cols.extend(["Module Count", "Function Count", "Test Count", \
     "SysLog Count", "Pass Count", "Pass Rate", "Software Versions"])
report_cols.extend(sorted(result_vals))
syslog_levels = ['emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug', 'none']
mail_build = "UNKNOWN Build"
def set_mail_build(val):
    global mail_build
    mail_build = val

ftrace_file = None
def ftrace(*args):
    global ftrace_file
    if not ftrace_file:
        [user_root, logs_path, slave_id] = _get_logs_path()
        ftrace_file = get_file_path("ftrace", "txt", logs_path)
        utils.write_file(ftrace_file, "")
    l_args = []
    for arg in args:
        l_args.append(str(arg))
    utils.write_file(ftrace_file, " ".join(l_args) + "\n", "a")

def dtrace(*args):
    dbg = False
    if not dbg:
        return
    wa = get_work_area()
    if wa:
        wa.log(args)
    else:
        print(args)

def _get_logs_path():
    user_root = os.getenv("SPYTEST_USER_ROOT", os.getcwd())
    logs_path = os.getenv("SPYTEST_LOGS_PATH", user_root)
    slave_id = batch.get_slave_id()
    if slave_id:
        logs_path = os.path.join(logs_path, slave_id)
    if not os.path.isabs(logs_path):
        logs_path = os.path.join(user_root, logs_path)
    if not os.path.exists(logs_path):
        os.makedirs(logs_path)
    return [user_root, logs_path, slave_id]

def get_file_path(suffix, extn, prefix=None, consolidated=False):
    file_prefix = os.getenv("SPYTEST_FILE_PREFIX", "results")
    results_prefix = os.getenv("SPYTEST_RESULTS_PREFIX", file_prefix)
    if not consolidated:
        filename = "{}_{}.{}".format(results_prefix, suffix, extn)
    else:
        filename = "{}_{}_all.{}".format(results_prefix, suffix, extn)
    if prefix:
        filename = os.path.join(prefix, filename)
    return filename

def get_results_csv(prefix=None, consolidated=False):
    return get_file_path("result", "csv", prefix, consolidated)

def get_tc_results_csv(prefix=None, consolidated=False):
    return get_file_path("tcresult", "csv", prefix, consolidated)

def get_syslog_csv(prefix=None, consolidated=False):
    return get_file_path("syslog", "csv", prefix, consolidated)

def get_report_txt(prefix=None, consolidated=False):
    return get_file_path("report", "txt", prefix, consolidated)

def create_pid_file():
    [user_root, logs_path, slave_id] = _get_logs_path()
    pid_file = get_file_path("pid", "txt", logs_path)
    utils.write_file(pid_file, "{}".format(os.getpid()))

class Context(object):

    def __init__(self, wa, cfg):
        self.stats_txt = None
        self.stats_csv = None
        self.wa = wa
        self.cfg = cfg
        self.tc_results = dict()
        self.all_tc_executed = 0
        self.shutting_down = False
        self.sent_first_progress = False
        self.file_prefix = None
        self.skip_tgen = cfg.skip_tgen
        self.version_msg = "VERSION: {}".format(get_git_ver())
        self.hostname = "HOSTNAME: {}".format(socket.gethostname())
        self.cmdline_args = os.getenv("SPYTEST_CMDLINE_ARGS", "")
        self.cmdline_args = "ARGS: {}".format(self.cmdline_args)
        [self.user_root, self.logs_path, self.slave_id] = _get_logs_path()
        if not self.user_root:
            print("SPYTEST_USER_ROOT env not found")
            os._exit(1)
        self.net = None
        self._log_init()
        if self.slave_id:
            self.log.info("SPYTEST_SLAVE_ID = {}".format(self.slave_id))
            gwtestbed = "SPYTEST_TESTBED_FILE_{}".format(self.slave_id)
            gwtestbed = os.getenv(gwtestbed)
            self.log.info("using testbed file {}".format(gwtestbed))
            if gwtestbed:
                cfg.testbed = gwtestbed
        self.execution_start_time = get_timenow()
        self.log.info("")
        self.log.info("Execution Start Time: {}".format(self.execution_start_time))
        self.log.info(self.version_msg)
        self.log.info(self.hostname)
        self.log.info("Python: {}.{}.{}".format(sys.version_info.major,
                      sys.version_info.minor, sys.version_info.micro))
        self.log.info(self.cmdline_args)
        self.log.info("LOGS PATH: {}".format(self.logs_path))
        if os.path.exists(os.path.join(self.logs_path, "slave_used")):
            self.cfg.skip_load_image = True
        self.execution_end_time = None
        self.session_start_time = get_timenow()
        self.session_init_time_taken = None
        self.total_tc_start_time = None
        for name, value in cfg.env:
            self.log.warning("setting environment {} = {}".format(name, value))
            os.environ[name] = value

        # log the reused test results
        if reused_test_results:
            self.log.info("Reusing previous test results:")
            for tc in reused_test_results.keys():
                self.log.info("   {}".format(tc))

        if cfg.log_lvl:
            self.log.set_lvl(cfg.log_lvl)

        self._tb = Testbed(cfg.testbed, self.log, self.cfg)
        if not self._tb.is_valid():
            print("Error: testbed file is not found or contains errors")
            os._exit(2)

        topo_str = self._tb.get_topo()
        self.log.info("Topology: {}".format(topo_str))

        # register for signal handlers
        if self.cfg.graceful_exit:
            self._handle_signals()

        # nothing to do in batch master
        if batch.is_master():
            self.report_txt = get_report_txt(self.logs_path, True)
            self.results_csv = get_results_csv(self.logs_path, True)
            self.tc_results_csv = get_tc_results_csv(self.logs_path, True)
            self.result = Result(self.file_prefix, False)
            return

        if cfg.rps_reboot:
            # nothing further when we are just rebooting devices
            return

        self.result = Result(self.file_prefix)

        has_non_scapy = self._load_topo()
        if self.cfg.filemode and has_non_scapy:
            self.skip_tgen = True
        tgapi.init_tgen(self.wa, self.log, self.skip_tgen)

        # create net module and register devices
        self.net = Net(self.cfg, self.file_prefix, self.log, self._tb)
        self.net.set_workarea(self.wa)
        if self._tb.is_valid():
            self.net.register_devices(self.topo)

        # move the connect to session init
        wa._context = self
        wa.net = self.net
        set_work_area(wa)
        self._connect()

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

        self.results_csv = get_results_csv(self.logs_path)
        self.tc_results_csv = get_tc_results_csv(self.logs_path)
        self.report_txt = get_report_txt(self.logs_path)
        self.stats_txt = get_file_path("stats", "txt", self.logs_path, False)
        self.stats_csv = get_file_path("stats", "csv", self.logs_path, False)
        Result.write_report_csv(self.stats_csv, [], 3, is_batch=False)
        utils.delete_file(self.stats_txt)

    def _cleanup_gracefully(self):
        if not self.shutting_down:
            self.shutting_down = True
            putil.set_shutting_down()
            self._disconnect()
            self._tgen_close()
            batch.shutdown()

    def _exit_gracefully(self, signum, frame):
        self.log.warning("shutting down - signal {}".format(signum))
        self._cleanup_gracefully()
        time.sleep(2)
        os._exit(0)

    def _handle_signals(self):
        signal.signal(signal.SIGINT, self._exit_gracefully)
        signal.signal(signal.SIGTERM, self._exit_gracefully)

    def log_time(self, name, mode="a"):
        filepath = "{}_time.log".format(self.file_prefix)
        msg = "{} = {}\n".format(get_timenow(), name)
        utils.write_file(filepath, msg, mode)

    def _init_log_path(self, prefix="results"):
        self.file_prefix = os.getenv("SPYTEST_FILE_PREFIX", None)
        if not self.file_prefix:
            if self.cfg.filemode:
                # for filemode overwrite the existing log file
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
        lvl_name = os.getenv("SPYTEST_LOGS_LEVEL", "info").lower()
        if lvl_name == "debug":
            lvl = logging.DEBUG
        elif lvl_name == "warn":
            lvl = logging.WARN
        else:
            lvl = logging.INFO
        self.log = Logger(self.file_prefix, "logs.log", level=lvl, tlog=self.cfg.tc_log_support)
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
            if tgen_dict:
                tgen_ports = list()
                tgen_links = self._tb.get_links(tgen_name)
                for linkElem in tgen_links:
                    port = linkElem[0]
                    tgen_ports.append(port)
                tgen_dict['ports'] = tgen_ports
                tgens[tgen_name] = tgen_dict
                if tgen_dict["type"] != "scapy":
                    has_non_scapy = True
        self.topo = {"duts": duts, "links": links, "tgens": tgens}
        return has_non_scapy

    def _tgen_close(self):
        failures = False
        try:
            for tgen_dict in self.topo["tgens"].values():
                if not tgapi.close_tgen(tgen_dict):
                    failures = True
        except:
            pass
        return False if failures and not self.skip_tgen else True

    def _tgen_init(self):
        failures = False
        for tgen_dict in self.topo["tgens"].values():
            if not tgapi.load_tgen(tgen_dict):
                failures = True
        return False if failures and not self.skip_tgen else True

    def _tgen_instrument(self, phase, data):
        for tgen_dict in self.topo["tgens"].values():
            try:
                tgapi.instrument_tgen(tgen_dict, phase, data)
            except Exception as exp:
                self.log.debug("TGEN instrument {} {} failed: {}".format(phase, data, exp))

    def _connect(self):
        self.log.debug("\nconnect().....\n")
        funcs = [
            [self._tgen_init],
            [self.net.connect_all_devices, self.cfg.faster_init]
        ]
        self.log_time("device connections start")
        [[rv1, rv2], [e1, e2]] = putil.exec_all(self.cfg.faster_init, funcs, True)
        self.log_time("device connections finish")
        if rv2 is False or e2 is not None:
            self.log.error("Failed to connect one or more devices in topology")
            if e2 is not None:
                for msg in utils.stack_trace(e2):
                    self.log.error(msg, split_lines=True)
            os._exit(4)
        if rv1 is False or e1 is not None:
            ignore = False
            if e1 is not None:
                for msg in utils.stack_trace(e1):
                    if "DeprecationWarning" in msg:
                        ignore = True
                        self.log.warning(msg, split_lines=True)
                    else:
                        self.log.error(msg, split_lines=True)
            msg = "Failed to connect one or more TGEN devices in topology"
            if not ignore:
                self.log.error(msg)
                os._exit(5)
            self.log.warning(msg)

    def _disconnect(self):
        try:
            if self.net:
                self.net.unregister_devices()
        except:
            pass

    def email(self, subject=None):
        filepath = os.path.join(self.logs_path, "build.txt")
        build_info = 'build:{0}\nuitype:{1}\nExecution Started:{2}\nExecution Completed:{3}'.format(mail_build,
                                self.cfg.ui_type, self.execution_start_time, get_timenow())
        utils.write_file(filepath, build_info)

        if not self.cfg.email_csv:
            return

        (report_file, is_html, add_png) = (None, True, False)
        html_file = os.path.splitext(self.report_txt)[0]+'.html'
        if os.path.exists(html_file):
            report_file = html_file

        # get the first DUT name to read the services info
        first_dut = None
        for dut in self._tb.get_device_names("DUT"):
            first_dut = dut
            break

        body = os.getenv("SPYTEST_EMAIL_BODY_PREFIX", "")
        body = body + textwrap.dedent("""\
        {3}VERSION : {0}
        {3}{1}
        {3}{2}
        """.format(get_git_ver(), self.hostname, self.cmdline_args,
                  "<p>" if is_html else ""))

        attchments = []
        if self.cfg.email_attachments:
            if self.tc_results_csv and os.path.exists(self.tc_results_csv):
                attchments.append(self.tc_results_csv)
                html_file = os.path.splitext(self.tc_results_csv)[0]+'.html'
                if os.path.exists(html_file):
                    attchments.append(html_file)
                png_file = os.path.splitext(self.tc_results_csv)[0]+'.png'
                if add_png and os.path.exists(png_file):
                    attchments.append(png_file)
            if self.results_csv and os.path.exists(self.results_csv):
                attchments.append(self.results_csv)
                html_file = os.path.splitext(self.results_csv)[0]+'.html'
                if os.path.exists(html_file):
                    attchments.append(html_file)
                png_file = os.path.splitext(self.results_csv)[0]+'.png'
                if add_png and os.path.exists(png_file):
                    attchments.append(png_file)
                html_file = os.path.splitext(self.results_csv)[0]+'_modules.html'
                if os.path.exists(html_file):
                    attchments.append(html_file)

        html_file = os.path.splitext(self.tc_results_csv)[0]+'_components.html'
        if os.path.exists(html_file):
            lines = utils.read_lines(html_file)
            body = body + "\n".join(lines)
            body = body + "\n<br>\n"

        # build mail body from report file
        if report_file:
            lines = utils.read_lines(report_file)
            body = body + "\n".join(lines)

        # get the servics for first DUT for SMTP details
        server = self._tb.get_service(first_dut, "smtp")
        mailcfg = SpyTestDict({
            "recipients": self.cfg.email_csv,
            "subject": subject or self.cfg.email_subject,
            "body": body,
            "server": server
        })

        date=self.execution_start_time.strftime('%b-%d')

        mailcfg.subject = utils.j2_apply(mailcfg.subject,
                build=mail_build, date=date, uitype=self.cfg.ui_type)

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

    def report(self, res, msgid, *args):
        """
        todo: Update Documentation
        :param res: pass/fail/envfail/depfail
        :param msgid: message identifier from /messages/*.yaml files
        :param args: arguments required in message identifier specification
        :return:
        """
        if current_test.name in must_fail_items:
            res = "Fail" if res in ["Pass"] else "Pass"
        retval = self.result.set(res, msgid, *args)
        self.log.info("========= Report({}): {} =========".format(res, retval))
        set_current_result(res, retval)
        return retval

    def publish2(self, nodeid, func, tcid, time_taken, comp=None,
                 result=None, desc=None, rtype="Executed"):
        if not comp and func and func in selected_test_results:
            if selected_test_results[func] != None:
                return False

        syslogs = self.net.get_syslogs()
        fcli = self.net.get_fcli()
        tryssh = self.net.get_tryssh()
        dut_list = self._tb.get_device_names("DUT")
        res = self.result.publish(nodeid, func, tcid, time_taken, comp,
                                  result, desc, rtype, syslogs,
                                  fcli, tryssh, dut_list)
        if not comp and func:
            selected_test_results[func] = res["Result"]
            self.all_tc_executed = self.all_tc_executed + 1
        if func in selected_test_items:
            item = selected_test_items[func]
            if "TimeTaken" not in res:
                res["TimeTaken"] = "0:00:00"
            row = ["", res["Module"], func, res["Result"], res["TimeTaken"],
                   res["ExecutedOn"], res["Description"]]
            item.user_properties.append(row)
        if not self.slave_id:
            self.run_progress_report(self.all_tc_executed)
        return True

    def publish(self, nodeid, func, time_taken):
        if not self.publish2(nodeid, func, None, time_taken):
            return
        if func in tcmap.tclist:
            for tcid in tcmap.tclist[func]:
                if tcid not in self.tc_results:
                    comp = tcmap.comp[tcid]
                    self.publish2(nodeid, func, tcid, "0:00:00",
                                  comp, None, None, "Mapped")
        for tcid in self.tc_results.keys():
            (res, desc) = self.tc_results[tcid]
            if tcid in tcmap.comp:
                comp = tcmap.comp[tcid]
            elif func in tcmap.comp:
                comp = tcmap.comp[func]
            else:
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

class WorkArea(object):
    """
    todo: Update Documentation
    """

    def __init__(self, cfg):
        """
        Construction of WorkArea object
        :param cfg:
        :type cfg:
        """
        self.cli_file = None
        self.cli_records = OrderedDict()
        self.syslog_levels = syslog_levels
        self.dmaps = dict()
        self.vsonic_map = dict()
        self.app_vars = dict()
        self.module_vars = dict()
        self._context = None
        self.file_prefix = None
        self.all_ports = OrderedDict()
        self.connected_ports = OrderedDict()
        self.reserved_ports = OrderedDict()
        self.free_ports = OrderedDict()
        self.hooks = dict()
        self.swver = OrderedDict()
        self.cfg = cfg
        self.hooks = apis_register()
        self.session_init_completed = False
        self.current_tc_start_time = None
        self._context = Context(self, cfg)
        self.net = self._context.net

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

            [rvs, exps] = self._foreach(devlist, self.do_rps, "reset", recon=False)
            self._trace_exceptions(devlist, "exception doing RPS reboot", exps)
            os._exit(1)

            try: self.do_rps_new(devlist, "reset", recon=False)
            finally: os._exit(1)

        self.base_config_verified = False
        self.module_config_verified = False
        self.current_module_verifier = None
        self.module_tc_fails = 0
        self.module_get_tech_support = False
        self.module_fetch_core_files = False
        self.stats_count = 0
        self.module_tc_executed = 0
        self.min_topo_called = False
        self.abort_module_msg = None
        self.tgen_reconnect = False

    def __del__(self, name=None):
        """
        todo: Update Documentation
        :param name:
        :type name:
        :return:
        :rtype:
        """
        if self._context:
            self._context._disconnect()
            self._context._tgen_close()

    def _foreach (self, items, func, *args, **kwargs):
        return putil.exec_foreach(self.cfg.faster_init, items, func, *args, **kwargs)

    def _foreach_dev (self, func, *args, **kwargs):
        return self._foreach(self.get_dut_names(), func, *args, **kwargs)

    def is_dry_run(self):
        return self.cfg.filemode

    def is_community_build(self, dut=None):
        if os.getenv("SPYTEST_COMMUNITY_BUILD_FEATURES", "0") != "0":
            return True
        return self.cfg.community_build

    def is_vsonic(self, dut=None):
        if not dut:
            dut = self.get_dut_names()[0]
        if dut not in self.vsonic_map:
            self.vsonic_map[dut] = self.net.is_vsonic(dut)
        return self.vsonic_map[dut]

    def is_valid_base_config(self):
        return bool(self.cfg.skip_load_config not in ["base"])

    def get_logs_path(self, for_file=None):
        [user_root, logs_path, slave_id] = _get_logs_path()
        if for_file:
            file_path = "{0}_{1}".format(self.file_prefix, for_file)
            return os.path.join(logs_path, file_path)
        return logs_path

    def profiling_start(self, msg, max_time):
        return self.net.profiling_start(msg, max_time)

    def profiling_stop(self, pid):
        return self.net.profiling_stop(pid)

    def banner(self, msg, width=80, delimiter="#", wrap=True, tnl=True, lnl=True):
        utils.banner(msg, width, delimiter, wrap, self.log, tnl, lnl)

    def debug(self, msg, dut=None, split_lines=False):
        self._context.log.debug(msg, dut, split_lines)

    def event(self, *args):
        msg = ""
        for arg in args:
            msg = msg + " " + str(arg)
            msg = msg.strip()
        self.log("\n================== {} ==================".format(msg))

    def log_time(self, name):
        self._context.log_time(name)

    def log(self, msg, dut=None, split_lines=False):
        self._context.log.info(msg, dut, split_lines)

    def exception(self, msg, dut=None, split_lines=True):
        self._context.log.exception(msg, dut, split_lines)

    def warn(self, msg, dut=None, split_lines=False):
        self._context.log.warning(msg, dut, split_lines)

    def error(self, msg, dut=None, split_lines=False):
        self._context.log.error(msg, dut, split_lines)

    def dut_log(self, dut, msg, skip_general=False, lvl=logging.INFO, cond=True):
        self._context.net.dut_log(dut, msg, skip_general, lvl, cond)

    def wait(self, val, msg=None):
        if msg:
            self.log("Sleep for {} sec(s)...{}".format(val, msg))
        else:
            self.log("Sleep for {} sec(s)...".format(val))
        self._context.net.wait(val)

    def tg_wait(self, val, msg=None):
        if msg:
            self.log("TG Sleep for {} sec(s)...{}".format(val, msg))
        else:
            self.log("TG Sleep for {} sec(s)...".format(val))
        self._context.net.tg_wait(val)

    def report_tc_pass(self, tcid, msgid, *args):
        self._context.report_tc(tcid, "Pass", msgid, *args)

    def onfail_debug_dump(self):
        if os.getenv("SPYTEST_ONFAIL_TGEN_STATS", "0") != "0":
            self.tgen_debug_show()

    def report_tc_fail(self, tcid, msgid, *args):
        self.onfail_debug_dump()
        self._context.report_tc(tcid, "Fail", msgid, *args)

    def report_tc_unsupported(self, tcid, msgid, *args):
        self._context.report_tc(tcid, "Unsupported", msgid, *args)

    def report_pass(self, msgid, *args):
        """
        Infrastructure API used by test scripts to report pass
        :param msgid: message identifier from /messages/*.yaml files
        :param args: arguments required in message identifier specification
        :return:
        """
        self._context.report("Pass", msgid, *args)

    def report_pdb(self):
        if self.cfg.pdb_on_error:
            pdb.set_trace()
            HELP = " NOTE: execute 'up' command thrice to go to the failure line ==== "

    def report_env_fail(self, msgid, *args):
        desc = self._context.report("EnvFail", msgid, *args)
        self.report_pdb()
        pytest.skip(desc)

    def report_timeout(self, msgid, *args):
        desc = self._context.report("Timeout", msgid, *args)
        self.report_pdb()
        pytest.skip(desc)

    def report_topo_fail(self, msgid, *args):
        desc = self._context.report("TopoFail", msgid, *args)
        self.report_pdb()
        pytest.skip(desc)

    def tgen_ftrace(self, *args):
        ftrace("TGEN:", args, current_module.name, current_test.name)

    def report_tgen_exception(self, ex):
        ignore = False
        for msg in utils.stack_trace(ex):
            if "DeprecationWarning" in msg:
                self.warn(msg, split_lines=True)
                ignore = True
            else:
                self.error(msg, split_lines=True)
        if not ignore:
            desc = self._context.report("TGenFail", "tgen_exception", "{}".format(ex))
            self.report_pdb()
            pytest.skip(desc)

    def report_tgen_fail(self, msgid, *args):
        desc = self._context.report("TGenFail", msgid, *args)
        self.report_pdb()
        pytest.skip(desc)

    def report_tgen_abort(self, msgid, *args):
        desc = self._context.report("TGenFail", msgid, *args)
        self.report_pdb()
        self.abort_module_msg = "TGen connection aborted"
        self.tgen_reconnect = True
        pytest.skip(desc)

    def report_fail(self, msgid, *args):
        msg = self._context.report("Fail", msgid, *args)
        self.report_pdb()
        self.onfail_debug_dump()
        pytest.xfail(msg)

    def report_dut_fail(self, msgid, *args):
        msg = self._context.report("DUTFail", msgid, *args)
        self.report_pdb()
        self.onfail_debug_dump()
        pytest.xfail(msg)

    def report_unsupported(self, msgid, *args):
        msg = self._context.report("Unsupported", msgid, *args)
        self.report_pdb()
        pytest.xfail(msg)

    def report_scripterror(self, msgid, *args):
        msg = self._context.report("ScriptError", msgid, *args)
        self.report_pdb()
        pytest.xfail(msg)

    def report_config_fail(self, msgid, *args):
        msg = self._context.report("ConfigFail", msgid, *args)
        self.report_pdb()
        self.onfail_debug_dump()
        pytest.xfail(msg)

    def set_default_error(self, res, msgid, *args):
        self._context.set_default_error(res, msgid, *args)

    def apply_script(self, dut, cmdlist):
        """
        todo: Update Documentation
        :param cmdlist:
        :type cmdlist:
        :param dut:
        :type dut:
        :return:
        :rtype:
        """
        return self._context.net.apply_script(dut, cmdlist)

    def apply_json(self, dut, json):
        """
        todo: Update Documentation
        :param json:
        :type json:
        :param dut:
        :type dut:
        :return:
        :rtype:
        """
        return self._context.net.apply_json(dut, json)

    def apply_json2(self, dut, json):
        """
        todo: Update Documentation
        :param json:
        :type json:
        :param dut:
        :type dut:
        :return:
        :rtype:
        """
        return self._context.net.apply_json2(dut, json)

    def apply_files(self, dut, file_list, method="incremental"):
        """
        todo: Update Documentation
        :param dut:
        :type dut:
        :param file_list:
        :type file_list:
        :return:
        :rtype:
        """
        return self._context.net.apply_files(dut, file_list, method)

    def run_script(self, dut, timeout, script_path, *args):
        """
        todo: Update Documentation
        :param dut:
        :type dut:
        :param timeout: in secs
        :type timeout:
        :param script_path:
        :type script_path:
        :return:
        :rtype:
        """
        return self._context.net.run_script(dut, timeout, script_path, *args)

    def enable_disable_console_debug_msgs(self, dut, flag):
        """
        todo: Update Documentation
        :param dut:
        :type dut:
        :return:
        :rtype:
        """
        return self._context.net.enable_disable_console_debug_msgs(dut, flag)

    def clear_config(self, dut):
        """
        todo: Update Documentation
        :param dut:
        :type dut:
        :return:
        :rtype:
        """
        retval_1 = self._context.net.clear_config(dut)

        # wait for system ready
        retval_2 = self.wait_system_status(dut)

        if retval_1 and retval_2:
            return True
        return False

    def config_db_reload(self, dut, save=False):
        """
        todo: Update Documentation
        :param dut:
        :type dut:
        :param save:
        :type save:
        :return:
        :rtype:
        """
        retval_1 = self._context.net.config_db_reload(dut, save)

        # wait for system ready
        retval_2 = self.wait_system_status(dut)

        if isinstance(retval_1, bool):
            if retval_1 and retval_2:
                return True
            return False
        return [retval_1, retval_2]

    def upgrade_image(self, dut, url, skip_reboot=False, port_break=True, port_speed=True, max_ready_wait=0):
        """
        Upgrade the software in the given DUT from given URL
        :param dut:
        :type dut:
        :param url: URL string used to upgrade
        :type url: String
        :param skip_reboot: Flag to avoid rebooting device after upgrade
        :type url: boolean (default False)
        :return:
        :rtype:
        """
        upgrd_retval = False
        pb_retval = True
        if self.cfg.load_image == "onie1":
            upgrd_retval = self.net.upgrade_onie_image1(dut, url,max_ready_wait=max_ready_wait)
        elif self.cfg.load_image == "onie":
            upgrd_retval = self.net.upgrade_onie_image2(dut, url,max_ready_wait=max_ready_wait)
        elif self.cfg.load_image == "installer-without-migration":
            upgrd_retval = self.net.upgrade_image(dut, url, skip_reboot, False,max_ready_wait=max_ready_wait)
        else:
            upgrd_retval = self.net.upgrade_image(dut, url, skip_reboot,max_ready_wait=max_ready_wait)
        if port_break or port_speed:
            pb_retval = self.set_port_defaults(dut, port_break, port_speed)

        # read app vars again
        self.app_vars[dut] = self.hooks.get_vars(dut)

        return bool(upgrd_retval and (pb_retval or port_speed))

    def reboot(self, dut, method="normal", skip_port_wait=False, skip_exception=False, skip_fallback=False):
        if not dut:
            self.log("reboot all {}".format(self.cfg.faster_init))
            self._foreach_dev(self._context.net.reboot, method, skip_port_wait,
                               skip_exception, skip_fallback)
        else:
            self._context.net.reboot(dut, method, skip_port_wait, skip_exception, skip_fallback)

    def _apply_config_file_list(self, dut, files):
        for filename in utils.make_list(files):
            if not isinstance(filename, list):
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

    def wait_system_status(self, dut, max_time=0):
        if self.cfg.pde: return True
        max_time = self.cfg.port_init_wait if max_time == 0 else max_time
        apply_args = [max_time, self.cfg.poll_for_ports]
        if self.cfg.community_build:
            apply_args.append(True)
            return self._context.net._apply_remote(dut, "wait-for-ports", apply_args)

        line = currentframe().f_back.f_lineno
        t = time.time() + max_time
        msg = "system is not online - waited for {} sec Ref: {}".format(max_time, line)
        while not self.cfg.pde:
            if "get_system_status" not in self.hooks:
                msg = "get_system_status API not found"
                break
            rv = self.hooks.get_system_status(dut, skip_error_check=True)
            if rv or self.cfg.filemode: return True
            if rv == None:
                # run without --community-build when device has community build
                apply_args.append(True)
                return self._context.net._apply_remote(dut, "wait-for-ports", apply_args)
            time.sleep(3)
            if time.time() > t:
                break
        self.dut_log(dut, msg, False, logging.WARNING)
        return False

    def ensure_system_ready(self, dut, scope="", name=""):

        # un-comment to simulate system not ready
        #if scope in ["pre-test", "module"]:
            #self.abort_module_msg = " show system status is not ready in time."
            #return

        if self.wait_system_status(dut):
            return self.net.show_dut_time(dut)

        # recover the system by config reload
        # this is not working as getting messages while saving
        #msg = "Trying to recover the DUT with save and reload"
        #self.dut_log(dut, msg, False, logging.WARNING)
        #if self.config_db_reload(dut):
            #return

        # system not ready - aborting current module
        self.abort_module_msg = " show system status is not ready in time."
        msg = self.abort_module_msg + " Trying to recover the DUT with reboot."
        self.dut_log(dut, msg, False, logging.WARNING)

        # the module is bailing out - collect the syslog and tech-support
        if scope in ["pre-test", "module"] and name:
            self.net.do_memory_checks(dut, "post-module-epilog", name)
            self.net.do_syslog_checks(dut, "post-module-epilog", name)
            self.net.generate_tech_support(dut, name)

        # recover the system by reboot - for next module
        rv = self.net.reboot(dut, "fast", skip_exception=True)
        if rv:
            msg = "Successfully rebooted the DUT to recover."
            msg = msg + " Final verification if show system status also ready."
            self.dut_log(dut, msg, False, logging.WARNING)
            rv = self.wait_system_status(dut, 10)
        if rv:
            if self.session_init_completed:
                msg = "show system status is ready after recovery."
                msg = msg + " abort current module and continue with next module"
                self.dut_log(dut, msg, False, logging.WARNING)
                self.report_dut_fail("show_system_status_not_ready")
            return self.net.show_dut_time(dut)

        # failed to recover devices - bailout the run
        msg = "show systemn status is not ready even after recovery - bailout run"
        self.dut_log(dut, msg, False, logging.ERROR)
        os._exit(6)

    def _fill_hooks_data(self, dut):
        try:
            self.swver[dut] = self.hooks.get_swver(dut)
        except:
            self.swver[dut] = "UNKNOWN"
            msg = "Failed to get the software version"
            self.dut_log(dut, msg, False, logging.WARNING)
        self.app_vars[dut] = self.hooks.get_vars(dut)
        set_mail_build(self.swver[dut])

    def _noshutdown_connected(self, dut):
        if dut in self.connected_ports and self.connected_ports[dut]:
            msg = "noshutdown connected ports:{}".format(self.connected_ports[dut])
            self.dut_log(dut, msg, False, logging.INFO)
            self.hooks.port_noshutdown(dut, self.connected_ports[dut])

    def _shutdown_reserved(self, dut):
        if dut in self.reserved_ports and self.reserved_ports[dut]:
            msg = "shutdown reserved ports:{}".format(self.reserved_ports[dut])
            self.dut_log(dut, msg, False, logging.WARNING)
            self.hooks.port_shutdown(dut, self.reserved_ports[dut])
            self._context.net._apply_remote(dut, "update-reserved-ports", [self.reserved_ports[dut]])

    def _save_base_config_dut(self, dut):

        # noshut connected ports so that they get saved as up in config
        self._noshutdown_connected(dut)

        # shut reserved ports so that they get saved as down in config
        self._shutdown_reserved(dut)

        if not self.cfg.skip_init_config:
            # save the configuration as TA default configuration
            self._context.net._apply_remote(dut, "save-base-config")

    def _apply_config_profile_dut(self, dut):
        # Apply the profile configuration
        profile_name = self._context._tb.get_config_profile()
        if self.cfg.config_profile:
            profile_name = self.cfg.config_profile
        largs_list = [profile_name]
        self._context.net._apply_remote(dut, "config-profile", largs_list)

    def _load_image_dut(self, dut, scope):
        build = self.get_build(dut, scope)
        if self.cfg.build_url != None and self.cfg.build_url.strip() == "":
            msg = "Given build url is not valid..."
            self.dut_log(dut, msg, False, logging.ERROR)
            raise ValueError(msg)
        if self.cfg.build_url and scope == "current":
            build = self.cfg.build_url
        if build:
            if self.cfg.port_breakout or self.cfg.port_speed:
                if os.getenv("SPYTEST_SYSTEM_READY_AFTER_PORT_SETTINGS", "0") == "1":
                    self.upgrade_image(dut, build, False, False, False, 1)
                else:
                    self.upgrade_image(dut, build, False, False, False, 0)
            else:
                self.upgrade_image(dut, build, False, False, False, 0)
            return True
        msg = "testbed file does not contain {} build".format(scope)
        self.dut_log(dut, msg, False, logging.WARNING)
        return False

    def _load_config_dut(self, dut, scope, pertest=False):
        if not pertest:
            # create TA default configuration
            self._create_init_ta_config(dut)

        # apply configs as given in template
        files = self.get_config(dut, scope)
        if not files:
            if not pertest:
                msg = "testbed file does not contain {} configs".format(scope)
                self.dut_log(dut, msg, False, logging.WARNING)
            files = []

        # apply all the config groups given in the template for current scope
        self._apply_config_file_list(dut, files)

    def _create_init_ta_config(self, dut):
        profile_name = self._context._tb.get_config_profile()
        if self.cfg.config_profile:
            profile_name = self.cfg.config_profile
        largs_list = [self.cfg.fetch_core_files, self.cfg.get_tech_support, profile_name]
        self._context.net._apply_remote(dut, "init-ta-config", largs_list)

    def _get_interfaces_all(self, dut):
        if not self.cfg.filemode:
            return self.hooks.get_interfaces_all(dut)
        retval = []
        for port in range(0,200):
            retval.append("Ethernet{}".format(port))
        return retval

    def _build_port_list(self, dut, retry):
        alias = self._context._tb.get_device_alias(dut)
        self.free_ports[dut] = []
        self.all_ports[dut] = []
        self.connected_ports[dut] = []
        self.reserved_ports[dut] = self._context._tb.get_rerved_links(dut)
        for local, partner, remote in self._get_device_links(dut, None, None):
            self.connected_ports[dut].append(local)
        all_ports = self._get_interfaces_all(dut)
        errs = []
        err_msg = "Failed to display interfaces in show command in {}".format(dut)
        if all_ports:
            for port in self.connected_ports[dut]:
                if port not in all_ports:
                    errs.append("invalid connected port {}/{}".format(alias, port))
                    errs.append("        should be one of {}".format(all_ports))
            for port in self.reserved_ports[dut]:
                if port not in all_ports:
                    errs.append("invalid reserved port {}/{}".format(alias, port))
                    errs.append("        should be one of {}".format(all_ports))
            for port in all_ports:
                if port not in self.reserved_ports[dut]:
                    self.all_ports[dut].append(port)
                    if port not in self.connected_ports[dut]:
                        if "Ethernet" in port:
                            self.free_ports[dut].append(port)
        elif retry > 0:
            retry = retry - 1
            msg = "{} - retry {}".format(err_msg, retry)
            self.dut_log(dut, msg, False, logging.WARNING)
            errs = self._build_port_list(dut, retry)
        else:
            errs.append(err_msg)
        return errs

    # the sequence is init, transfer and save
    # init triggers init-ta-config
    # transfer triggers apply-files
    # save triggers save-base-config
    # Note: init and transfer can't be compibed because
    # we support config.cmds which need to be executed from framework
    def _session_common_dut(self, dut, scope):

        if not self.net.is_sonic_device(dut):
            return

        if scope == "restore":
            if self.cfg.get_tech_support not in ["none"]:
                self.net.generate_tech_support(dut, "session")
            if self.cfg.fetch_core_files not in ["none"]:
                self.net._apply_remote(dut, "fetch-core-files", ["session"])

        # Load Image
        if self.cfg.skip_load_image:
            msg = "SKIP loading {} image".format(scope)
            self.dut_log(dut, msg, False, logging.WARNING)
            apply_port_defaults = True
        else:
            apply_port_defaults = self._load_image_dut(dut, scope)

        # Apply Profile
        if scope == "current":
            self._apply_config_profile_dut(dut)

        # load user configuration
        if os.getenv("SPYTEST_PORT_DEFAULTS_CONFIG"):
            self._load_config_dut2(dut, scope)

        # port speed and breakout
        if scope == "current" or apply_port_defaults:
            if os.getenv("SPYTEST_SKIP_RESERVED_PORT_SPEED"):
                self.set_port_defaults(dut, speed=False)
            else:
                self.set_port_defaults(dut)

        # load user configuration
        if not os.getenv("SPYTEST_PORT_DEFAULTS_CONFIG"):
            self._load_config_dut2(dut, scope)

        # save configuration as TA configuration
        self._save_base_config_dut(dut)

    def _load_config_dut2(self, dut, scope):
        if self.cfg.pde:
            msg = "SKIP loading configuration"
            self.dut_log(dut, msg, False, logging.WARNING)
        elif self.cfg.skip_init_config:
            msg = "SKIP loading configuration"
            self.dut_log(dut, msg, False, logging.WARNING)
            largs = [self.cfg.fetch_core_files, self.cfg.get_tech_support, self.cfg.clear_tech_support]
            self.net._apply_remote(dut, "init-clean", largs)
            if self.cfg.config_profile:
                self._create_init_ta_config(dut)
        else:
            self._load_config_dut(dut, scope, False)

    def _session_common_dut2(self, dut, no_recovery=True):
        errs = []

        # read the port list
        if not self.cfg.pde:
            errs.extend(self._build_port_list(dut, 3))

        # check if there are any issues reported if not all is well
        if not errs:
            if os.getenv("SPYTEST_SKIP_RESERVED_PORT_SPEED"):
                # set the port speeed after building port list
                self.set_port_defaults(dut, breakout=False)
            self._fill_hooks_data(dut)
            self._save_base_config_dut(dut)
            return True

        # bail out on testbed issues
        if self.all_ports[dut]:
            self._trace_errors("invalid ports in testbed file", errs)
            return False

        # nothing to do if we are not recovering
        if no_recovery:
            msg = "ports are not created - bailout run"
            self.dut_log(dut, msg, False, logging.ERROR)
            return False

        # recover the DUT with reboot
        msg = " ports are not created - trying to recover the DUT with reboot."
        self.dut_log(dut, msg, False, logging.WARNING)
        rv = self.net.reboot(dut, "fast", skip_exception=True)
        if not rv:
            msg = "Failed to reboot the DUT to recover - bailout run"
            self.dut_log(dut, msg, False, logging.ERROR)
            return False

        # reboot is OK, check ports again
        msg = "Successfully rebooted the DUT to recover - verify testbed ports"
        self.dut_log(dut, msg, False, logging.WARNING)
        if not self._session_common_dut2(dut, True):
            msg = "ports are not ready even after recovery - bailout run"
            self.dut_log(dut, msg, False, logging.ERROR)
            return False

        # all is well atleast now
        msg = "Successfully verified testbed ports after recovery"
        self.dut_log(dut, msg, False, logging.INFO)
        return True

    def _trace_errors(self, msg, errs):
        if msg: self.error(msg)
        for err in errs: self.error(err)
        return False

    def _trace_exceptions(self, dut_list, msg, exceptions):
        errs = []
        for dut_index, ex in enumerate(exceptions):
            if not ex: continue
            self.dut_log(dut_list[dut_index], str(ex), False, logging.ERROR)
            errs.extend(ex)
        if errs:
            self.error("exception loading image or init config")
        return errs

    def _session_init(self):
        self.log("session init start")
        self.log_time("session init start")

        dut_list = self.get_dut_names()

        # init software versions
        for dut in dut_list:
            self.swver[dut] = ""

        # load current image, config and perform
        [retvals, exceptions] = self._foreach(dut_list, self._session_common_dut, "current")
        if self._trace_exceptions(dut_list, "exception loading image or init config", exceptions):
            os._exit(6)

        apis_common_init("session", None)

        # identify invalid port names given in testbed file
        self.log("building port list and save base config")
        no_recovery = bool(os.getenv("SPYTEST_RECOVER_INITIAL_SYSTEM_NOT_READY", "0") == "1")
        [retvals, exceptions] = self._foreach(dut_list, self._session_common_dut2, no_recovery)
        if self._trace_exceptions(dut_list, "exception saving base config", exceptions):
            os._exit(6)

        # bail out if there are erros detected in topology
        if not all(retvals):
            self.error("invalid ports in topology - please check testbed file")
            if not self.cfg.filemode: os._exit(6)

        # get application vars
        for dut in self.get_dut_names():
            self.app_vars[dut] = self.hooks.get_vars(dut)
            self.module_vars[dut] = dict()

        # perform topology check
        if self.cfg.topology_check not in ["skip", "status2", "status3", "status4"]:
            [retval, header, rows] = self.hooks.verify_topology(self.cfg.topology_check)
            topo_status = utils.sprint_vtable(header, rows)
            if not retval:
                self.error("Topology verification failed")
                self.error(topo_status, split_lines=True)
                if self.cfg.topology_check in ["abort"]:
                    os._exit(7)
            else:
                self.log("Topology verification successful")
                self.log(topo_status, split_lines=True)
        else:
            self.warn("SKIP Topology verification")

        # flag to run module init
        self.base_config_verified = True
        self._context.session_init_time_taken = get_elapsed(self._context.session_start_time, True)
        self._context.total_tc_start_time = get_timenow()

        if batch.is_member():
            self._report_file_generation()

        self.log_time("session init end")

    def _session_clean(self):
        self.log_time("session clean start")

        #self.log("session clean {}".format(self.cfg.faster_init))
        if batch.is_member():
            data = self._report_file_generation()

        if self.cfg.tgen_module_init:
            funcs = [
                [self._module_init_tgen],
                [self._foreach_dev, self._session_common_dut, "restore"]
            ]
            putil.exec_all(self.cfg.faster_init, funcs, True)
        else:
            self._foreach_dev(self._session_common_dut, "restore")

        apis_common_clean("session", None)
        if self.net:
            self.net.session_close()
        if batch.is_member():
            self.log("=================== Final Report =========================")
            self.log(data, split_lines=True)
            self.log(" ================== Software Versions ====================")
            ver_dut_map = utils.invert_dict(self.swver)
            for swver, dut in ver_dut_map.items():
                self.log(" ============ {} = {}".format(dut, swver))
            self.log("==========================================================")
            rlist = [i for i in selected_test_results.values()]
            from collections import Counter
            self.log("============ Results : {}".format(list(Counter(rlist).items())))
            self.log("==========================================================")
        self.log_time("session clean end")

    def _module_init_dut(self, dut, filepath):
        self.clear_module_vars(dut)
        if self.cfg.skip_load_config not in ["base"]:
            largs = [self.cfg.load_config_method]
            self._context.net._apply_remote(dut, "apply-base-config", largs)
        else:
            msg = "SKIP appying base configuration"
            self.dut_log(dut, msg, False, logging.WARNING)

        # ensure system is ready
        module_str = "module_{}".format(filepath.split('.')[0])
        self.ensure_system_ready(dut, "module", module_str)

    def _module_init_tgen(self):
        for tgen in self._context.topo["tgens"]:
            tgapi.module_init(self._context.topo["tgens"][tgen])

    def _module_init(self, filepath):
        base_filename = os.path.basename(filepath)
        #self.log("module init start")
        self.log_time("module {} init start".format(filepath))
        self._context._tb.reset_derived_devices()
        self.clear_tc_results()

        # per module faster-cli
        if self.cfg.faster_cli == 1:
            fcli = 1
        elif self.cfg.faster_cli == 2:
            fcli = tcmap.faster_cli.get(base_filename, 0)
        elif self.cfg.faster_cli == 3:
            fcli = tcmap.faster_cli.get(base_filename, 1)
        else:
            fcli = 0

        # per module tryssh
        if self.cfg.tryssh == 1:
            tryssh = 1
        elif self.cfg.tryssh == 2:
            tryssh = tcmap.tryssh.get(base_filename, 0)
        elif self.cfg.tryssh == 3:
            tryssh = tcmap.tryssh.get(base_filename, 1)
        else:
            tryssh = 0

        # ajdust Module MAX Timeout using data from tcmap
        try: module_max_timeout = tcmap.module_max_timeout.get(base_filename, 0)
        except: module_max_timeout = 0
        if module_max_timeout > 0 and module_max_timeout > self.cfg.module_max_timeout:
            self.net.module_init_start(module_max_timeout, fcli, tryssh)
        else:
            self.net.module_init_start(self.cfg.module_max_timeout, fcli, tryssh)

        if not self.base_config_verified:
            self.warn("base config verification already failed - no need to run any modules")
            self.module_config_verified = False
            return "SKIP"

        apis_common_init("module", filepath)
        self._context.result.clear()
        self.cli_records.clear()

        self.min_topo_called = False
        self.module_tc_executed = 0
        self.module_tc_fails = 0
        self.module_get_tech_support = False
        self.module_fetch_core_files = False
        self.current_module_verifier = "NA"
        self.abort_module_msg = None

        if self.tgen_reconnect:
            self.warn("Reconnecting to TGen")
            self._context._tgen_close()
            if not self._context._tgen_init():
                self.error("Failed to reconnect to tgen")
                os._exit(6)
            self.warn("Reconnected to TGen")
            self.tgen_reconnect = False

        self.log("applying base configuration: {}".format(self.abort_module_msg))
        if self.cfg.tgen_module_init:
            funcs = [
                [self._module_init_tgen],
                [self._foreach_dev, self._module_init_dut, filepath]
            ]
            [[rv1, rv2], [e1, e2]] = putil.exec_all(self.cfg.faster_init, funcs, True)
            if e2 is not None:
                self.error("Failed to module init one or more devices in topology")
                for msg in utils.stack_trace(e2):
                    self.error(msg, split_lines=True)
            if e1 is not None:
                ignore = False
                for msg in utils.stack_trace(e1):
                    if "DeprecationWarning" in msg:
                        ignore = True
                        self.warn(msg, split_lines=True)
                    else:
                        self.error(msg, split_lines=True)
                msg = "Failed to module init one or more TGEN devices in topology"
                if not ignore:
                    self.error(msg)
                self.warn(msg)
        else:
            [rvs, exps] = self._foreach_dev(self._module_init_dut, filepath)
            self.log("RVs: {} EXPs: {} CHK: {}".format(rvs, exps, self.abort_module_msg))

        self.log("base configuration applied: {}".format(self.abort_module_msg))

        # ensure system is ready to proceed further
        if self.abort_module_msg:
            self.error(self.abort_module_msg)
            self.module_config_verified = False
            return "SKIP"

        if self.cfg.topology_check in ["status2", "status3", "status4"]:
            self.log("verify/show port status before module")
            [retval, header, rows] = self.hooks.verify_topology(self.cfg.topology_check)
            topo_status = utils.sprint_vtable(header, rows)
            self.log(topo_status, split_lines=True)
            # TODO: Swap ports if they are down

        if self.cfg.skip_load_config not in ["base"] and \
           self.cfg.skip_verify_config not in ["base", "both"]:
            verifier = self._context._tb.get_verifier()
            self.log("base config verification - {}".format(verifier))
            verifiers = self.hooks.verifiers()
            if verifier in verifiers:
                self.base_config_verified = verifiers[verifier]()
                if not self.base_config_verified:
                    self.error("base config verification failed - no need to run any modules")
                    self.module_config_verified = False
                    return "SKIP"
                else:
                    self.log("base config verification successful")
            else:
                self.base_config_verified = False
                self.log("base config verifier '{}' not found".format(verifier))
        else:
            self.warn("base config verification is skipped")

        self.module_config_verified = self.base_config_verified
        self.log_time("module {} init end".format(filepath))

    def _clear_devices_usage_list(self):
        self.net.clear_devices_usage_list()

    def _get_devices_usage_list(self):
        return self.net.get_devices_usage_list()

    def _set_device_usage_collection(self, collect_flag):
        self.net.set_device_usage_collection(collect_flag)

    def save_sairedis(self, phase, name):
        if self.cfg.save_sairedis not in [None]:
            self._foreach_dev(self.net.save_sairedis, phase, name)

    def _do_memory_checks(self, phase, name):
        if self.cfg.memory_check not in ["none"]:
            self._foreach_dev(self.net.do_memory_checks, phase, name)

    def _do_syslog_checks(self, phase, name):
        if self.cfg.syslog_check not in ["none"]:
            self._foreach_dev(self.net.do_syslog_checks, phase, name)

    def _pre_module_prolog(self, name):
        self._do_memory_checks("pre-module-prolog", name)
        self._do_syslog_checks("pre-module-prolog", name)
        self.save_sairedis("pre-module-prolog", name)
        self._context._tgen_instrument("pre-module-prolog", name)

    def _post_module_prolog(self, name, success_status):

        # fetch debug info when module config failed
        if not success_status:
            if self.cfg.get_tech_support in ["onfail", "onfail-epilog"]:
                self._foreach_dev(self.net.generate_tech_support, name)
            if self.cfg.fetch_core_files in ["onfail", "onfail-epilog"]:
                self._foreach_dev(self.net._apply_remote, "fetch-core-files", [name])

        self._do_memory_checks("post-module-prolog", name)
        self._do_syslog_checks("post-module-prolog", name)
        self.save_sairedis("post-module-prolog", name)
        self._context._tgen_instrument("post-module-prolog", name)

        if success_status and self.cfg.skip_load_config not in ["base"]:
            self._foreach_dev(self._save_module_config)

    def _post_module_epilog(self, name, success_status):
        if not self.abort_module_msg:
            self._do_memory_checks("post-module-epilog", name)
            self._do_syslog_checks("post-module-epilog", name)
            self.save_sairedis("post-module-epilog", name)
            self._context._tgen_instrument("post-module-epilog", name)

    def _pre_function_prolog(self, name):
        pass

    def _post_function_prolog(self, name):
        pass

    def _pre_function_epilog(self, name):
        (res, desc) = self._context.result.get()
        if res.lower() not in ["fail", "xfail", "dutfail"]:
            return
        if self.cfg.get_tech_support in ["onfail-epilog"]:
            self._foreach_dev(self.net.generate_tech_support, name)
        if self.cfg.fetch_core_files in ["onfail-epilog"]:
            self._foreach_dev(self.net._apply_remote, "fetch-core-files", [name])

    def _post_function_epilog(self, name):
        pass

    def _save_module_config(self, dut=None):
        # we MUST save the module config even though we don;t need to call
        # apply-module-config, because if reboot happens the device should
        # start with module config
        # save the module configuration before executing any test cases in the module
        msg = "save the module config - needed if device reboots "
        if self.cfg.skip_load_config not in ["module"]:
            msg = " and for restore across test cases"
        self.dut_log(dut, msg)
        self._context.net._apply_remote(dut, "save-module-config")

    def set_module_lvl_action_flags(self, action):
        if action == "core-dump":
            self.module_fetch_core_files = True
        elif action == "tech-support":
            self.module_get_tech_support = True

    def _module_complete_dut(self, dut, filepath):
        module_str = "module_{}".format(filepath.split('.')[0])

        if self.module_get_tech_support and self.cfg.get_tech_support in ["module-onerror"]:
            self.net.generate_tech_support(dut, module_str)
            self.net._apply_remote(dut, "init-clean", ["none", self.cfg.get_tech_support, self.cfg.clear_tech_support])
        elif self.cfg.get_tech_support in ["module-onfail"] and self.module_tc_fails > 0:
            self.net.generate_tech_support(dut, module_str)
            self.net._apply_remote(dut, "init-clean", ["none", self.cfg.get_tech_support, self.cfg.clear_tech_support])
        elif self.cfg.get_tech_support in ["module-always"]:
            self.net.generate_tech_support(dut, module_str)
            self.net._apply_remote(dut, "init-clean", ["none", self.cfg.get_tech_support, self.cfg.clear_tech_support])

        if self.module_fetch_core_files and self.cfg.fetch_core_files in ["module-onerror"]:
            self.net._apply_remote(dut, "fetch-core-files", [module_str])
            self.net._apply_remote(dut, "init-clean", [self.cfg.fetch_core_files, "none", self.cfg.clear_tech_support])
        elif self.cfg.fetch_core_files in ["module-onfail"] and self.module_tc_fails > 0:
            self.net._apply_remote(dut, "fetch-core-files", [module_str])
            self.net._apply_remote(dut, "init-clean", [self.cfg.fetch_core_files, "none", self.cfg.clear_tech_support])
        elif self.cfg.fetch_core_files in ["module-always"]:
            self.net._apply_remote(dut, "fetch-core-files", [module_str])
            self.net._apply_remote(dut, "init-clean", [self.cfg.fetch_core_files, "none", self.cfg.clear_tech_support])

    def _module_complete(self, filepath):
        self._save_cli()
        dut_list = self.get_dut_names()
        [retvals, exceptions] = self._foreach(dut_list, self._module_complete_dut, filepath)
        errs = []
        dut_index = 0
        for ex in exceptions:
            if ex:
                self.dut_log(dut_list[dut_index], str(ex), False, logging.ERROR)
                errs.extend(ex)
            dut_index = dut_index + 1
        if errs:
            self.error("exception collecting module level core and dump files")
            os._exit(6)

    def _module_clean(self, filepath):
        #self.log("module clean start")
        if not self.min_topo_called:
            self.error("Module {} Minimum Topology is not specified".format(filepath))
        self.log_time("module {} clean start".format(filepath))
        apis_common_clean("module", filepath)
        self._module_complete(filepath)
        self.log_time("module {} clean end".format(filepath))
        # update the node report files for every module
        # if we are not reporting run progress
        if self.cfg.run_progress_report == 0:
            self._report_file_generation()

    def _check_dut_state(self, dut):
        self.dut_log(dut, "Check DUT state")
        return self._context.net._check_dut_state(dut)

    def _check_dut_port_state(self, dut):
        self.dut_log(dut, "Check DUT port state connected to TG/DUT")
        return_states = []
        for port in self.connected_ports[dut]:
            status = self.hooks.get_interface_status(dut, port)
            return_states.append(status)
        return return_states

    def _function_common_dut(self, dut, scope, res=None, func_name=None):

        if scope != "post-test":
            self.ensure_system_ready(dut, "pre-test", func_name)
            self.net.do_memory_checks(dut, "pre-test", func_name)
            self.net.do_syslog_checks(dut, "pre-test", func_name)
            self.net.save_sairedis(dut, "pre-test", func_name)
            return

        if not self.abort_module_msg:
            self.net.do_memory_checks(dut, "post-test", func_name)
            self.net.do_syslog_checks(dut, "post-test", func_name)
            self.net.save_sairedis(dut, "post-test", func_name)
            self.net.do_audit("post-test", dut, func_name, res)

        if self.cfg.skip_load_config in ["base", "module"]:
            return

        # check for any configuration cleanup not done as part of testcase
        # if found any difference apply the module configuration at the end of every test case
        largs = [self.cfg.load_config_method]
        self.net._apply_remote(dut, "apply-module-config", largs)
        self.ensure_system_ready(dut)

    def tc_log_init(self, func_name):
        self._context.log.tc_log_init(func_name)
        if self.cfg.tc_log_support and func_name:
            self.log(self._context.version_msg)
            self.log(self._context.cmdline_args)
            self.log("Topology: {}".format(self._context._tb.get_topo()))

    def module_log_init(self, func_name):
        self._context.log.module_log_init(func_name)
        if func_name:
            #self.log("Execution Start Time: {}".format(self._context.execution_start_time))
            self.log(self._context.version_msg)
            self.log(self._context.cmdline_args)
            self.log("Topology: {}".format(self._context._tb.get_topo()))

    def _test_log_init(self, nodeid, func_name, show_trace=False):
        self._context.result.clear()
        msg = "\n================== {} ==================\n".format(nodeid)
        if show_trace:
            self.log(msg)
        for dut in self.get_dut_names():
            self.dut_log(dut, msg, True)

    def _function_init(self, nodeid, func_name):

        self.clear_tc_results()
        #self.log("function init start")
        self.log_time("function {} init start".format(nodeid))
        self.current_tc_start_time = get_timenow()

        # ajdust TC MAX Timeout using data from tcmap
        try: tc_max_timeout = tcmap.tc_max_timeout.get(func_name, 0)
        except: tc_max_timeout = 0

        if tc_max_timeout > 0 and tc_max_timeout > self.cfg.tc_max_timeout:
            self.net.function_init_start(tc_max_timeout)
        else:
            self.net.function_init_start(self.cfg.tc_max_timeout)

        self._test_log_init(nodeid, func_name)

        if self.abort_module_msg:
            desc = self._context.report("SKIPPED", "test_execution_skipped", self.abort_module_msg)
            self._function_clean(nodeid, func_name, min_time)
            pytest.skip(desc)

        if self.cfg.first_test_only and self.module_tc_executed > 0:
            desc = self._context.report("SKIPPED", "test_execution_skipped", "as the ask for to run first test only")
            self._function_clean(nodeid, func_name, min_time)
            pytest.skip(desc)

        # report as failure if the base config is not verified
        if not self.base_config_verified:
            self.error("base config verification failed - no need to run {}".format(func_name))
            desc = self._context.report("ConfigFail", "base_config_verification_failed")
            self._function_clean(nodeid, func_name, min_time)
            pytest.skip(desc)

        # report as failure if the module config is not verified
        if not self.module_config_verified:
            self.error("module config verification failed - no need to run {}".format(func_name))
            desc = self._context.report("ConfigFail", "module_config_verification_failed")
            self._function_clean(nodeid, func_name, min_time)
            pytest.skip(desc)

        # check if the dependent test case is failed
        if not self.cfg.ignore_dep_check:
            errs = check_dependency(func_name)
            if errs:
                self.error("dependent test case failed - no need to run {}".format(func_name))
                desc = self._context.report("DepFail", "depedent_test_failed", errs)
                self._function_clean(nodeid, func_name, min_time)
                pytest.skip(desc)

        #if self.cfg.topology_check in ["status4"] and not self.cfg.filemode:
        if self.cfg.topology_check in ["status4"]:
            self.log("verify/show port status before function")
            [retval, header, rows] = self.hooks.verify_topology(self.cfg.topology_check)
            topo_status = utils.sprint_vtable(header, rows)
            self.log(topo_status, split_lines=True)

        # per-testcase topology checking
        if self.cfg.pertest_topo_check:
            self.log("perform topology check per test case")
            self._context._tb.pertest_topo_checking = True

            # get the dut states
            [retvals, exceptions] = self._foreach_dev(self._check_dut_state)
            for dut in self.get_dut_names():
                self._context._tb.devices_state[dut] = retvals.pop(0)

            # get the dut-port-ixia states
            [retvals, exceptions] = self._foreach_dev(self._check_dut_port_state)
            for dut in self.get_dut_names():
                dut_port_states = retvals.pop(0)
                for port in self.connected_ports[dut]:
                    self._context._tb.devices_port_state["{}:{}".format(dut,port)] = dut_port_states.pop(0)

        #self.log("save/apply module config if not skipped")
        self._foreach_dev(self._function_common_dut, "pre-test", func_name=func_name)

        # ensure system is ready to proceed further
        if self.abort_module_msg:
            self.error(self.abort_module_msg)
            return "SKIP"

        self._context._tgen_instrument("pre-test", func_name)

        apis_common_init("function", func_name)
        if self.cfg.skip_load_config not in ["base", "module"] and \
           self.cfg.skip_verify_config not in ["module", "both"]:
            verifier = self.current_module_verifier
            self.log("performing module config verification - {}".format(verifier))
            verifiers = self.hooks.verifiers()
            if verifier in verifiers:
                self.module_config_verified = verifiers[verifier]()
                if not self.module_config_verified:
                    self.error("module config verification failed - no need to run {}".format(func_name))
                else:
                    self.log("module config verification successful")
            else:
                self.module_config_verified = False
                self.log("module module config verifier '{}' not found".format(verifier))

            if not self.module_config_verified:
                # bail out current test
                desc = self._context.report("ConfigFail", "module_config_verification_failed")
                self._function_clean(nodeid, func_name, min_time)
                pytest.skip(desc)
                return
        else:
            self.warn("module config verification is skipped")
        self._context.net.tc_start(self.current_tc_start_time)
        self.log_time("function {} init end".format(nodeid))

    def _function_clean(self, nodeid, func_name, time_taken=None):

        #self.log("function clean start")
        self.log_time("function {} clean start".format(nodeid))
        self._context.net.set_prev_tc(func_name)
        apis_common_clean("function", func_name)

        # Get result and description to print in log files.
        (res, desc) = self._context.result.get()

        self._foreach_dev(self._function_common_dut, "post-test", res, func_name)
        self._context._tgen_instrument("post-test", func_name)

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
                os._exit(0)
        self.log_time("function {} clean end".format(nodeid))

    def _report_file_generation(self):
        self.log_time("report file generation start")

        self._context.execution_end_time = get_timenow()
        total_tc_time_taken = get_elapsed(self._context.total_tc_start_time, True)
        tcresults_csv = get_tc_results_csv(self._context.logs_path)
        results_csv = get_results_csv(self._context.logs_path)
        syslog_csv = get_syslog_csv(self._context.logs_path)

        data = _report_data_generation(self._context.execution_start_time,
                                       self._context.execution_end_time,
                                       self._context.session_init_time_taken,
                                       total_tc_time_taken,
                                       results_csv, tcresults_csv, syslog_csv)
        with open(self._context.report_txt, "w") as ofh:
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

    def _test_log_finish(self, nodeid, func_name, res, desc, time_taken):

        if isinstance(time_taken, int):
            time_taken = utils.time_format(time_taken)

        # trace missing parallel operations
        stats = self._context.net.get_stats()
        if stats.canbe_parallel:
            msg = "yet to be parallized: {}".format(nodeid)
            utils.banner(msg, func=ftrace)
            for [start_time, msg, dut1, dut2] in stats.canbe_parallel:
                ftrace(start_time, msg, dut1, dut2)
            utils.banner(None, func=ftrace)

        #Construct the final result log message to print in all log files.
        msg = "\n================== Report: {} : {} : {} : {} =========\n"
        msg = msg.format(nodeid, res, time_taken, desc)
        self.log(msg)

        self._write_stats(nodeid, res, desc, time_taken)
        self._context.net.tc_start()
        for dut in self.get_dut_names():
            self.dut_log(dut, msg, True)
        self._context.publish(nodeid, func_name, time_taken)
        self.log_time("Test Time ({} - {}) Published".format(self.current_tc_start_time, get_timenow()))

    def _write_stats(self, nodeid, res, desc, time_taken):
        if not self._context.stats_txt:
            return
        with open(self._context.stats_txt, "a") as ofh:
            ofh.write("\n======================= STATS: {} ===========================".format(nodeid))
            stats = self._context.net.get_stats()
            ofh.write("\nRESULT = {}".format(res))
            ofh.write("\nDESCRIPTION = {}".format(desc))
            ofh.write("\nTOTAL Test Time = {}".format(time_taken))
            ofh.write("\nTOTAL Sleep Time = {} sec".format(stats.tc_total_wait))
            ofh.write("\nTOTAL TG Sleep = {} sec".format(stats.tg_total_wait))
            ofh.write("\nTOTAL CMD Time = {}".format(stats.tc_cmd_time))
            ofh.write("\nTOTAL INFRA Time = {}".format(stats.infra_cmd_time))
            ofh.write("\nTOTAL TG Time = {}".format(stats.tg_cmd_time))
            ofh.write("\nTOTAL PROMPT NFOUND = {}".format(stats.pnfound))
            for [start_time, thid, ctype, dut, cmd, ctime] in stats.cmds:
                start_msg = "\n{} {}".format(get_timestamp(this=start_time), thid)
                if ctype == "CMD":
                    ofh.write("{}CMD TIME: {} {} = {}".format(start_msg, ctime, dut, cmd))
                elif ctype == "INFRA":
                    ofh.write("{}INFRA TIME: {} {} = {}".format(start_msg, ctime, dut, cmd))
                elif ctype == "TG":
                    ofh.write("{}TG TIME: {} = {}".format(start_msg, ctime, cmd))
                elif ctype == "WAIT":
                    ofh.write("{}WAIT TIME: {} = {}".format(start_msg, ctime, cmd))
                elif ctype == "TGWAIT":
                    ofh.write("{}TGWAIT TIME: {} = {}".format(start_msg, ctime, cmd))
                elif ctype == "PROMPT_NFOUND":
                    ofh.write("{}PROMPT NFOUND: {}".format(start_msg, cmd))
            ofh.write("\n=========================================================\n")
        self.stats_count = self.stats_count + 1
        row = [self.stats_count, nodeid, res, time_taken, stats.infra_cmd_time,
               stats.tc_cmd_time, stats.tg_cmd_time, stats.tc_total_wait,
               stats.tg_total_wait, stats.pnfound, desc.replace(",", " ")]
        Result.write_report_csv(self._context.stats_csv, [row], 3, False, True)

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

        :return: names of all the tg
        :rtype: list
        """
        return self.get_device_names("TG")

    def get_free_ports(self, dut):
        """
        This method gets all the ports that are not connected to either
        partner DUT or Traffic Generator

        :param dut: device under test
        :type dut:
        :return: all the free ports
        :rtype: list
        """
        return self.free_ports[dut]

    def get_all_ports(self, dut):
        """
        This method gets all the ports that are not connected to either
        partner DUT or Traffic Generator

        :param dut: device under test
        :type dut:
        :return: all the free ports
        :rtype: list
        """
        return self.all_ports[dut]

    def get_service_info(self, dut, name):
        """
        todo: Update Documentation
        :param name:
        :type name:
        :param dut:
        :type dut:
        :return:
        :rtype:
        """
        return self._context._tb.get_service(dut, name)

    def get_links(self, dut, peer=None):
        return self._context._tb.get_links(dut, peer, None)

    def get_dut_links_local(self, dut, peer=None, index=None):
        retval = []
        for local, partner, remote in self.get_dut_links(dut, peer):
            retval.append(local)
        if index is None:
            return retval
        try:
            return [retval[int(index)]]
        except:
            return []

    def _get_device_links(self, dut, peer=None, dtype="DUT"):
        return self._context._tb.get_links(dut, peer, dtype)

    def get_dut_links(self, dut, peer=None):
        return self._get_device_links(dut, peer, "DUT")

    def get_tg_links(self, tg, peer=None):
        return self._get_device_links(tg, peer, "TG")

    def get_tg_info(self, tg):
        return self._context._tb.get_tg_info(tg)

    def get_device_alias(self, dut):
        return self._context._tb.get_device_alias(dut)

    def set_device_alias(self, dut, name):
        return self.net.set_device_alias(dut, name)

    def do_rps(self, dut, op, on_delay=None, off_delay=None, recon=True):
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
        rinfo = self._context._tb.get_rps(dut)
        retval = False
        if not rinfo:
            self.report_env_fail("testbed_no_rps_info")
        elif "model" not in rinfo or not rinfo.model or rinfo.model in ["None"]:
            self.report_env_fail("testbed_no_rps_model")
        elif "ip" not in rinfo or not rinfo.ip:
            self.report_env_fail("testbed_no_rps_ip")
        elif "outlet" not in rinfo or not rinfo.outlet:
            self.report_env_fail("testbed_no_rps_outlet")
        elif "username" not in rinfo or rinfo.username is None:
            self.report_env_fail("testbed_no_rps_username")
        elif not self.cfg.filemode:
            if "port" not in rinfo: rinfo.port = 23
            rps = RPS(rinfo.model, rinfo.ip, rinfo.port, rinfo.outlet,
                      rinfo.username, rinfo.password, desc=str(dut))
            if "pdu_id" in rinfo: rps.set_pdu_id(rinfo.pdu_id)
            if recon: self.net.do_pre_rps(dut, op.lower())
            if not rps.do_op(op, on_delay, off_delay):
                self.error("Failed to perform RPS {}".format(op))
            retval = True
            if recon: self.net.do_post_rps(dut, op.lower())
        else:
            retval = True
        return retval

    def do_rps_new(self, dut, op, on_delay=None, off_delay=None, recon=True):
        dut_list = utils.make_list(dut)
        dut_mrinfo = OrderedDict()
        for d in dut_list:
            rinfo = self._context._tb.get_rps(d)
            if not rinfo:
                self.report_env_fail("testbed_no_rps_info")
            if "model" not in rinfo or not rinfo.model or rinfo.model in ["None"]:
                self.report_env_fail("testbed_no_rps_model")
            elif "ip" not in rinfo or not rinfo.ip:
                self.report_env_fail("testbed_no_rps_ip")
            elif "outlet" not in rinfo or not rinfo.outlet:
                self.report_env_fail("testbed_no_rps_outlet")
            elif "username" not in rinfo or rinfo.username is None:
                self.report_env_fail("testbed_no_rps_username")

            if "port" not in rinfo: rinfo.port = 23
            rps = RPS(rinfo.model, rinfo.ip, rinfo.port, rinfo.outlet,
                      rinfo.username, rinfo.password, desc=str(d))
            if "pdu_id" in rinfo: rps.set_pdu_id(rinfo.pdu_id)
            if rps.has_multi_support():
                key = "_".join(map(str,[rinfo.model, rinfo.ip, rinfo.port]))
            else:
                key = "_".join(map(str,[rinfo.model, rinfo.ip, rinfo.port, d]))
            if key not in dut_mrinfo:
                dut_mrinfo[key] = [rps, [rinfo.outlet]]
            else:
                dut_mrinfo[key][1].append(rinfo.outlet)

        if self.cfg.filemode:
            return True

        # perform pre-rps operations
        if recon:
            self._foreach(dut_list, self.net.do_pre_rps, op.lower())

        def f(key):
            [rps, outlets] = dut_mrinfo[key]
            if not rps.do_op(op.lower(), on_delay, off_delay, outlets):
                self.error("Failed to perform RPS {}".format(op))
                return False
            return True
        (rvs, exps) = self._foreach(dut_mrinfo.keys(), f)
        retval = all(rvs)

        # perform post-rps operations
        if recon:
            self._foreach(dut_list, self.net.do_post_rps, op.lower())

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

    def ensure_min_topology(self, *args):
        """
        verifies if the current testbed topology satifies the
        minimum topology required by test script
        :param spec: needed topology specification
        :type spec: basestring
        :return: True if current topology is good enough else False
        :rtype: bool
        """
        self.log("ensure_min_topology: {}".format(args))
        self.min_topo_called = True
        ftrace("ensure_min_topology", args, current_module.name, current_test.name)
        [errs, properties] = self._context._tb.ensure_min_topology(*args)
        if not errs:
            if None in properties and "CONSOLE_ONLY" in properties[None]:
                self.net.set_console_only(True)
            return self.get_testbed_vars()

        if self.cfg.pertest_topo_check:
            if "dut_down" in errs or "link_down" in errs:
                self.report_env_fail("pertest_topology_fail", errs)

        self.report_topo_fail("min_topology_fail", errs)

    def get_testbed_vars(self):
        """
        returns the testbed variables in a dictionary
        :return: testbed variables dictionary
        :rtype: dict
        """
        rv = self._context._tb.get_testbed_vars()
        for dut in self.get_dut_names():
            for name in self.app_vars[dut]:
                if name not in rv:
                    rv[name] = dict()
                rv[name][dut] = self.app_vars[dut][name]
            for name in self.module_vars[dut]:
                if name not in rv:
                    rv[name] = dict()
                rv[name][dut] = self.module_vars[dut][name]
        rv["config"] = self.cfg
        return rv

    def clear_tc_results(self):
        self._context.tc_results.clear()

    def clear_module_vars(self, dut):
        self.module_vars[dut].clear()

    def add_module_vars(self, dut, name, value):
        dut_list = [dut] if dut else self.get_dut_names()
        for d in dut_list:
            self.module_vars[d][name] = value

    def get_mgmt_ip(self, dut):
        return self._context.net.get_mgmt_ip(dut)

    def get_config(self, dut, scope="current"):
        return self._context._tb.get_config(dut, scope)

    def get_build(self, dut, scope="current"):
        return self._context._tb.get_build(dut, scope)

    def get_param(self, name, default):
        return self._context._tb.get_param(name, default)

    def get_device_param(self, dut, name, default):
        return self._context._tb.get_device_param(dut, name, default)

    def get_link_param(self, dut, local, name, default):
        return self._context._tb.get_link_param(dut, local, name, default)

    def tgen_debug_show(self, name=None, tg=None, port=None, msg=""):
        for (c, p) in self.get_tgen_handles(name=name, tg=tg, port=port).values():
            if c and p:
                c.debug_show(p, msg)

    def get_tgen(self, name, port=None, tg=None):
        tbvars = self.get_testbed_vars()
        if name is not None:
            if name not in tbvars.tgen_ports:
                return (None, None)
            [tg, ctype, port] = tbvars.tgen_ports[name]
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
            [tg, ctype, port] = value
            rv[name1] = tgapi.get_tgen(port, tbvars[tg])
            if max_ports != 0:
                count = count + 1
                if count >= max_ports:
                    break
        if name is None: return rv
        if name in rv: return rv[name]
        return (None, None)

    def get_run_config(self):
        return self.cfg

    def get_args(self, arg):
        if arg in self.cfg:
            return self.cfg[arg]
        return None

    def get_ui_type(self, dut=None):
        if dut and dut in self.app_vars:
            vervars = self.app_vars[dut].get("vervars")
            if vervars:
                val = vervars.get("UI_TYPE")
                if val and self.cfg["ui_type"] != val:
                    self.dut_log(dut, "UI-TYPE Forced to {}".format(val), logging.DEBUG)
                    return val
        return self.cfg["ui_type"]

    def get_datastore(self, dut, name, scope):
        if dut not in self.dmaps:
            self.dmaps[dut] = dict()
        dmaps = self.dmaps[dut]
        if name not in dmaps:
            dmaps[name] = DataMap(name)
        return dmaps[name].get(scope)

    def exec_ssh(self, dut, username=None, password=None, cmdlist=[]):
        return self._context.net.exec_ssh(dut, username, password, cmdlist)

    def exec_remote(self, ipaddress, username, password, scriptpath, wait_factor=2):
        return self._context.net.exec_remote(ipaddress, username, password, scriptpath, wait_factor)

    def change_passwd(self, dut, username, password):
        return self._context.net.change_passwd(dut, username, password)

    def upload_file_to_dut(self, dut, src_file, dst_file):
        return self._context.net.upload_file_to_dut(dut, src_file, dst_file)

    def download_file_from_dut(self, dut, src_file, dst_file):
        return self._context.net.download_file_from_dut(dut, src_file, dst_file)

    def set_module_verifier (self, verifier):
        verifiers = self.hooks.verifiers()
        if verifier not in verifiers:
            self.warn("Verifier '{}' is not registered".format(verifier))
        self.current_module_verifier = verifier

    def ansible_dut(self, dut, playbook):
        return self._context.net.ansible_dut(dut, playbook)

    def ansible_service(self, service, playbook):
        tbvars = self.get_testbed_vars()
        service_data = self.get_service_info(tbvars.D1, service)
        service_data["filemode"] = self.get_args("filemode")
        return self._context.net.ansible_service(service_data, playbook)

    def add_addl_auth(self, dut, username, password):
        self._context.net.add_addl_auth(dut, username, password)

    def set_port_defaults(self, dut, breakout=True, speed=True):

        # init applicable ports and arguments
        (all_ports, apply_args) = ([], [[],[]])

        # fill breakout settings arguments
        if self.cfg.port_breakout and breakout:

            # get the breakout infor from testbed file
            breakout_info = self._context._tb.get_breakout(dut)
            if not breakout_info: breakout_info = []

            for [l_port, l_breakout] in breakout_info:
                all_ports.append(l_port)
                apply_args[0].append(l_port)
                apply_args[0].append(l_breakout)

        # fill speed settings arguments
        if self.cfg.port_speed and speed:

            # get the spped infor from testbed file
            speed_info = self._context._tb.get_speed(dut)
            if not speed_info: speed_info = dict()

            ######################################################
            # remove the speed info for reserved ports
            if os.getenv("SPYTEST_SKIP_RESERVED_PORT_SPEED"):
                speed_info = copy.copy(speed_info)
                for l_port in self.reserved_ports[dut]:
                    if l_port in speed_info:
                        msg = "skip speed setting for reserved port {}"
                        self.dut_log(dut, msg.format(l_port), False, logging.DEBUG)
                        del speed_info[l_port]
                    else:
                        msg = "no speed setting for reserved port {}"
                        self.dut_log(dut, msg.format(l_port), False)
                for l_port in self.connected_ports[dut]:
                    if l_port in speed_info:
                        msg = "speed setting for connected port {} = {}"
                        msg = msg.format(l_port, speed_info[l_port])
                        self.dut_log(dut, msg, False, logging.DEBUG)
                    else:
                        msg = "no speed setting for connected port {}"
                        self.dut_log(dut, msg.format(l_port), False, logging.DEBUG)
                for l_port in self.free_ports[dut]:
                    if l_port in speed_info:
                        msg = "speed setting for free port {} = {}"
                        self.dut_log(dut, msg.format(l_port, speed_info[l_port]), False)
                        #msg = "skip speed setting for unconnected port {}"
                        #self.dut_log(dut, msg.format(l_port), False, logging.DEBUG)
                        #del speed_info[l_port]
                    else:
                        msg = "no speed setting for unconnected port {}"
                        self.dut_log(dut, msg.format(l_port), False, logging.DEBUG)
            ######################################################

            apply_args[1] = []
            for l_port, l_speed in speed_info.items():
                all_ports.append(l_port)
                apply_args[1].append(l_port)
                apply_args[1].append(l_speed)

        if all_ports:
            # trace interfaces to debug settings before port breakout
            self.hooks.get_interface_status(dut, ",".join(all_ports))

        if apply_args[0] or apply_args[1]:
            retval_1 = self.net._apply_remote(dut, "port-defaults", apply_args)
            retval_2 = self.ensure_system_ready(dut)
            if not retval_1 or not retval_2:
                return False

        return True

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
        return self._context.net.change_prompt(dut, mode, **kwargs)

    def cli_config(self, dut, cmd, mode=None, skip_error_check=False, delay_factor=0, **kwargs):
        return self._context.net.cli_config(dut, cmd, mode, skip_error_check, delay_factor, **kwargs)

    def cli_show(self, dut, cmd, mode=None, skip_tmpl=False, skip_error_check=False, **kwargs):
        return self._context.net.cli_show(dut, cmd, mode, skip_tmpl, skip_error_check, **kwargs)

    def get_config_profile(self):
        return self._context._tb.get_config_profile()

    def get_device_type(self, dut):
        return self._context._tb.get_device_type(dut)

    def rest_init(self, dut, username, password, altpassword):
        return self.net.rest_init(dut, username, password, altpassword)

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

    def parse_show(self, dut, cmd, output):
        return self.net.parse_show(dut, cmd, output)

    def show_new(self, dut, cmd, **kwargs):
        return self.net.show_new(dut, cmd, **kwargs)

    def config_new(self, dut, cmd, **kwargs):
        return self.net.config_new(dut, cmd, **kwargs)

    def exec_ssh_remote_dut(self, dut, ipaddress, username, password, command=None, timeout=30):
        return self.net.exec_ssh_remote_dut(dut, ipaddress, username, password, command, timeout)

    def run_uicli_script(self, dut, scriptname):
        return self.net.run_uicli_script(dut, scriptname)

    def run_uirest_script(self, dut, scriptname):
        return self.net.run_uirest_script(dut, scriptname)

    def run_uignmi_script(self, dut, scriptname, **kwargs):
        return self.net.run_uignmi_script(dut, scriptname, **kwargs)

    def generate_tech_support(self, dut, name):
        self.net.generate_tech_support(dut, name)

    def get_credentials(self, dut):
        return self.net.get_credentials(dut)

    def _trace_cli(self, dut, mode, cmd):
        if dut not in self.cli_records:
            self.cli_records[dut] = []
        self.cli_records[dut].append([mode, cmd])

    def _save_cli(self):
        if not self.cli_file:
            [user_root, logs_path, slave_id] = _get_logs_path()
            self.cli_file = get_file_path("cli", "txt", logs_path)
            utils.write_file(self.cli_file, "")
        for dut, mode_cmd_list in self.cli_records.items():
            for entry in mode_cmd_list:
                [mode, cmd] = entry
                utils.write_file(self.cli_file, "{},{}\n".format(mode, cmd), "a")

    def dump_all_commands(self, dut, type='click'):
        return self.net.dump_all_commands(dut, type)

def add_options(parser):
    group = parser.getgroup("SpyTest")
    group.addoption("--testbed-file", action="store", default=None,
                    metavar="<testbed file path>",
                    help="testbed file path -- default: ./testbed.yaml")
    group.addoption("--ignore-tcmap-errors", action="store", default=0, type=int,
                    choices=[0, 1], help="Ignore errors in tcmap -- default: 0")
    group.addoption("--tclist-map", action="store",
                    default=None, help="use test case map file")
    group.addoption("--tclist-bucket", action="append",
                    default=None, help="use test cases from buckets")
    group.addoption("--tclist-file", action="store",
                    metavar="<test case list file path>",
                    default=None, help="test case list file path")
    group.addoption("--tclist-csv", action="store",
                    metavar="<test case list csv>",
                    default=None, help="test case list csv")
    group.addoption("--logs-path", action="store", default=None,
                    metavar="<logs folder path>",
                    help="logs folder -- default: .")
    group.addoption("--file-mode", action="store_true", default=False,
                    help="Execute in file mode -- default: false")
    group.addoption("--quick-test", action="store_true", default=False,
                    help="Disable options for a quick test -- default: false")
    group.addoption("--email", action="append", default=None,
                    help="Email address(es) to send report to.")
    group.addoption("--email-subject", action="store", default="Run Report",
                    help="Email subject to be used to send report")
    group.addoption("--email-attachments", action="store", default=0, type=int,
                    choices=[0, 1], help="Enable email attachments -- default: 0")
    group.addoption("--skip-tgen", action="store_true", default=False,
                    help="Skip connecting to traffic generator(s) -- default: false")
    group.addoption("--tgen-module-init", action="store", default=1, type=int,
                    choices=[0, 1], help="Call TGEN module init -- default: 1")
    group.addoption("--native-port-breakout", action="store", default=1, type=int,
                    choices=[0, 1], help="Use port breakout script from device -- default: 1")
    group.addoption("--port-defaults", action="store", default="both",
                    choices=['breakout', 'speed', 'both', 'none'],
                    help="set port defaults -- default: none")
    group.addoption("--topology-check", action="store", default="status3",
                    choices=['abort', 'report', 'skip', 'status', 'status2', 'status3', 'status4'],
                    help="Topology Check -- default: status3")
    group.addoption("--load-config-method", action="store", default="reload",
                    choices=['reload', 'replace', 'reboot', 'force_reload', 'force_reboot'],
                    help="Method to be used to load config -- default: reload.")
    group.addoption("--skip-init-config", action="store_true", default=False,
                    help="Skip loading initial configuration before and after execution -- default: false")
    group.addoption("--skip-load-config", action="store", default="module",
                    choices=['base', 'module', 'none'],
                    help="Skip loading configuration before and after test case execution -- default: false")
    group.addoption("--load-image", action="store", default="onie",
                    choices=['installer', 'onie', "none", "installer-without-migration"],
                    help="Loading image before and after execution using specified method -- default: onie")
    group.addoption("--skip-verify-config", action="store", default="none", choices=['base', 'module', "both", "none"],
                    help="Skip verifying base and/or module configuration")
    group.addoption("--ignore-dep-check", action="store", default=0, type=int,
                    choices=[0, 1], help="Ignore depends mark in test cases -- default: 0")
    group.addoption("--memory-check", action="store", default="none",
                    choices=['test', 'module', 'none'],
                    help="read memory usage default: none")
    group.addoption("--syslog-check", action="store", default="err",
                    choices=syslog_levels,
                    help="read syslog messages of given level and clear all syslog messages default: err")
    group.addoption("--save-sairedis", action="store", default="none",
                    choices=["none", "test", "module"], help="read sairedis messages")
    group.addoption("--faster-init", action="store", default=1, type=int,
                    choices=[0, 1], help="Enable speeding up initialization -- default: 1")
    group.addoption("--faster-cli", action="store", default=0, type=int,
                    choices=[0, 1, 2, 3], help="Enable speeding up CLI -- default: 0")
    group.addoption("--port-init-wait", action="store", type=int, default=300,
                    help="Wait time in seconds for ports to come up -- default: 300")
    group.addoption("--reboot-wait", action="store", type=int, default=0,
                    help="Wait time in seconds for ports to come up -- default: 0")
    group.addoption("--fetch-core-files", action="store", default="session",
                    choices=['always', 'onfail', "none", "onerror", "session", \
                             "onfail-epilog",
                             "module-always", "module-onfail", "module-onerror"],
                    help="Fetch the core files from DUT to logs location -- default: session")
    group.addoption("--get-tech-support", action="store", default="onfail-epilog",
                    choices=['always', 'onfail', "none", "onerror", "session", \
                             "onfail-epilog",
                             "module-always", "module-onfail", "module-onerror"],
                    help="Get the tech-support information from DUT to logs location -- default: session")
    group.addoption("--pertest-topo-check",  action="store", default=0, type=int,
                    choices=[0, 1], help="Topology check per testcase -- default: 0")
    group.addoption("--tc-max-timeout", action="store", type=int, default=600,
                    help="Max time that a testcase can take to execute -- default: 600")
    group.addoption("--module-init-max-timeout", action="store", type=int, default=1200,
                    help="Max time that a module initialization can take to execute -- default: 1200")
    group.addoption("--results-prefix", action="store", default=None,
                    help="Prefix to be used for results")
    group.addoption("--exclude-devices", action="store", default=None,
                    help="exclude given duts from testbed")
    group.addoption("--include-devices", action="store", default=None,
                    help="include given duts from testbed")
    group.addoption("--run-progress-report", action="store", default=0,
                    type=int, help="send run progress report at given frequency")
    group.addoption("--env", action="append", default=[],
                    nargs=2, help="environment variables")
    group.addoption("--random-order", action="store", default=1, type=int,
                    choices=[0, 1], help="Enable executing tests in random order -- default: 1")
    group.addoption("--rps-reboot", action="store", default=None,
                    metavar="<device names csv>",
                    help="Reboot given devices using RPS")
    group.addoption("--pde", action="store_true", default=False,
                    help="PDE image support -- default: false")
    group.addoption("--community-build", action="store", default=0, type=int,
                    choices=[0, 1], help="Community build support -- default: 0")
    group.addoption("--tryssh", action="store", default=0, type=int,
                    choices=[0, 1, 2, 3], help="Try executing through SSH -- default: 0")
    group.addoption("--flex-dut", action="store", default=1, type=int,
                    choices=[0, 1], help="Rearrange DUT based on min topology - default: 1")
    group.addoption("--first-test-only", action="store_true", default=False,
                    help="Execute only first test in each module - default: false")
    group.addoption("--config-profile", action="store", default=None,
                    choices=['l2', 'l3', 'NA'], help="Profile to load - default: None")
    group.addoption("--build-url", action="store", default=None,
                    help="Profile to load - default: None")
    group.addoption("--clear-tech-support", action="store", default=0, type=int,
                    choices=[0, 1], help="Clears tech support data on the dut -- default: 0")
    group.addoption("--module-epilog-tgen-cleanup", action="store", default=1, type=int,
                    choices=[0, 1], help="Enable TGEN cleanup in module epilog")
    group.addoption("--module-epilog", action="store", default=1, type=int,
                    choices=[0, 1], help="Enable module epilog")
    group.addoption("--graceful-exit", action="store", default=1, type=int,
                    choices=[0, 1], help="Graceful exit on control+c")
    group.addoption("--reuse-results", action="store", default="none",
                    choices=['none', 'all', 'pass', 'allpass'],
                    help="Reuse results from previous execution")
    group.addoption("--dev-prop", action="append", default=[], nargs=2,
                    help="override device property in the testbed")
    group.addoption("--ixserver", action="append", default=[],
                    help="override ixnetwork server")
    group.addoption("--ui-type", action="store", default="click",
                    choices=['click', 'klish', 'klishplus'],
                    help="CLI type needed in scripts execution")

def get_tgen_utils():
    from spytest.tgen import tgen_utils
    return tgen_utils

def get_work_area():
    return gWorkArea

def set_work_area(val):
    global gWorkArea
    gWorkArea = val

def _create_work_area2(config):
    cfg = SpyTestDict()
    cfg.filemode = config.getoption("--file-mode")
    cfg.testbed = config.getoption("--testbed-file")
    cfg.logs_path = config.getoption("--logs-path")
    cfg.log_lvl = config.getoption("--log-level")
    cfg.tclist_file = config.getoption("--tclist-file")
    cfg.tclist_map = config.getoption("--tclist-map")
    cfg.tclist_bucket = config.getoption("--tclist-bucket", None)
    cfg.tclist_csv = config.getoption("--tclist-csv", None)
    cfg.email_csv = config.getoption("--email")
    if cfg.email_csv:
        cfg.email_csv = ",".join(cfg.email_csv)
    cfg.email_subject = config.getoption("--email-subject", "Run Report")
    cfg.email_attachments = bool(config.getoption("--email-attachments", 0))
    cfg.skip_tgen = config.getoption("--skip-tgen")
    cfg.tgen_module_init = bool(config.getoption("--tgen-module-init", 1))
    cfg.load_config_method = config.getoption("--load-config-method")
    cfg.topology_check = config.getoption("--topology-check", "skip")
    cfg.port_defaults = config.getoption("--port-defaults")
    cfg.native_port_breakout = config.getoption("--native-port-breakout")
    cfg.port_breakout = bool(cfg.port_defaults in ["breakout", "both"])
    cfg.port_speed = bool(cfg.port_defaults in ["speed", "both"])
    cfg.skip_init_config = config.getoption("--skip-init-config")
    cfg.skip_load_config = config.getoption("--skip-load-config")
    cfg.load_image = config.getoption("--load-image", "onie")
    cfg.ignore_dep_check = bool(config.getoption("--ignore-dep-check"))
    cfg.memory_check = config.getoption("--memory-check")
    cfg.syslog_check = config.getoption("--syslog-check")
    cfg.save_sairedis = config.getoption("--save-sairedis")
    cfg.faster_init = bool(config.getoption("--faster-init", 1))
    cfg.port_init_wait = config.getoption("--port-init-wait")
    cfg.reboot_wait = config.getoption("--reboot-wait")
    cfg.poll_for_ports = bool(config.getoption("--poll-for-ports", 1))
    cfg.fetch_core_files = config.getoption("--fetch-core-files")
    cfg.get_tech_support = config.getoption("--get-tech-support")
    cfg.skip_verify_config = config.getoption("--skip-verify-config")
    cfg.pertest_topo_check = bool(config.getoption("--pertest-topo-check", 0))
    cfg.tc_max_timeout = config.getoption("--tc-max-timeout")
    cfg.module_max_timeout = config.getoption("--module-init-max-timeout")
    cfg.results_prefix = config.getoption("--results-prefix")
    cfg.exclude_devices = config.getoption("--exclude-devices")
    cfg.include_devices = config.getoption("--include-devices")
    cfg.run_progress_report = config.getoption("--run-progress-report", 0)
    cfg.rps_reboot = config.getoption("--rps-reboot", None)
    cfg.pde = config.getoption("--pde", False)
    cfg.community_build = config.getoption("--community-build", False)
    cfg.flex_dut = bool(config.getoption("--flex-dut", 1))
    cfg.first_test_only = config.getoption("--first-test-only", False)
    cfg.tryssh = config.getoption("--tryssh", 0)
    cfg.env = config.getoption("--env", [])
    cfg.pdb_on_error = config.getoption("--pdb", False)
    x_flag = config.getoption("-x", False)
    exitfirst_flag = config.getoption("--exitfirst", False)
    cfg.exit_on_firstfail = True if x_flag or exitfirst_flag else False
    cfg.maxfail = config.getoption("--maxfail", 0)
    cfg.faster_cli = config.getoption("--faster-cli", 0)
    cfg.tc_log_support = config.getoption("--tc-log", False)
    cfg.config_profile = config.getoption("--config-profile")
    cfg.build_url = config.getoption("--build-url")
    cfg.clear_tech_support = bool(config.getoption("--clear-tech-support", 0))
    cfg.module_epilog_tgen_cleanup = config.getoption("--module-epilog-tgen-cleanup")
    cfg.module_epilog = config.getoption("--module-epilog")
    cfg.graceful_exit = config.getoption("--graceful-exit")
    cfg.reuse_results = config.getoption("--reuse-results")
    cfg.dev_prop = config.getoption("--dev-prop", [])
    cfg.ixserver = config.getoption("--ixserver", [])
    cfg.ui_type = config.getoption("--ui-type", "click")

    cfg.skip_load_image = bool(cfg.load_image == "none")

    if cfg.pde:
        cfg.skip_init_config = True
        cfg.skip_load_config = "base"
        os.environ["SPYTEST_SKIP_INIT_COMMANDS"] = "1"

    if config.getoption("--quick-test", False):
        cfg.skip_load_image = True
        cfg.fetch_core_files = "none"
        cfg.get_tech_support = "none"
        cfg.syslog_check = "none"
        cfg.memory_check = "none"
        cfg.save_sairedis = "none"
        cfg.skip_load_config = "base"
        cfg.skip_init_config = True
        cfg.port_breakout = False
        cfg.port_speed = False
        os.environ["SPYTEST_SKIP_INIT_COMMANDS"] = "1"
        os.environ["SPYTEST_KDUMP_ENABLE"] = "0"

    if cfg.community_build:
        cfg.port_init_wait = 240
        os.environ["SPYTEST_KDUMP_ENABLE"] = "0"

    wa = get_work_area()
    if not wa:
        wa = WorkArea(cfg)
        set_work_area(wa)
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
    [user_root, logs_path, slave_id] = _get_logs_path()
    if not batch.is_member():
        # master or standalone
        consolidate_results()
    if not batch.is_slave():
        # NOTE: standalone is handled somewhere else
        wa._context.email()
    else:
        wa._context._cleanup_gracefully()
    set_work_area(None)
    bg_results.stop()

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
    index = 0
    has_exp = False
    desc = ""
    for item in reversed(entries):
        fname, line, func, text = item
        if not fname.startswith(root):
            continue
        if not has_exp:
            if fname != dicts:
                if hook == 'test_module':
                    exp_msg = wa._context.result.build_msg("exception_name_file_line", ex_msg, fname, line)
                    desc = wa._context.report("ConfigFail", "module_config_failed", exp_msg)
                else:
                    desc = wa._context.report("ScriptError", "exception_name_file_line", ex_msg, fname, line)
                has_exp = True
        msg = "[{}] {}:{} {} {}".format(index, fname, line, func, text)
        index = index + 1
        wa._context.log.error(msg)
        for dut in wa.get_dut_names():
            wa._context.net.dut_log(dut, msg, True, logging.ERROR)
    return desc

def _build_tclist_file(config):
    file_name = config.getoption("--tclist-file")
    if not file_name:
        file_name = os.getenv("SPYTEST_TCLIST_FILE", None)
    if not file_name:
        return None

    [user_root, logs_path, slave_id] = _get_logs_path()
    if os.path.isfile(file_name):
        file_path = file_name
    else:
        file_path = os.path.join(user_root, file_name)
        if not os.path.isfile(file_path):
            print("Failed to locate test case list file {}".format(file_name))
            os._exit(8)

    with utils.open_file(file_path) as fh:
        test_names = []
        for test_name in fh:
            test_name = test_name.strip()
            if test_name and not test_name.startswith("#"):
                test_names.append(test_name)
        if len(test_names) <= 0:
            msg = "no test cases are specified in test case list file"
            print("{} {}".format(msg, file_name))
            os._exit(9)

    return set(test_names)

def _add_tcmap_entry(age, cadence, comp, tcid, func):
    if tcid in tcmap.cadence:
        msg = "duplicate test case id {}"
        tcmap.errors.append(msg.format(tcid))
    if func not in tcmap.tclist:
        tcmap.tclist[func] = []
    if tcid not in tcmap.tclist[func]:
        tcmap.tclist[func].append(tcid)
    else:
        msg = "duplicate test case id {}"
        tcmap.errors.append(msg.format(tcid))
    tcmap.comp[tcid] = comp
    tcmap.cadence[tcid] = cadence
    tcmap.func[tcid] = func

def _load_csv(csv_file, path):
    path = os.path.join(os.path.dirname(__file__), '..', path)
    csv_file = os.path.join(os.path.abspath(path), csv_file)

    if os.path.exists(csv_file):
        filepath = csv_file
    else:
        return []
    rows = []
    with open(filepath, 'r') as fd:
        for row in csv.reader(fd):
            rows.append(row)
        fd.close()
    return rows

def _load_tcmap(verify=True, items=None):
    tcmap.tclist = OrderedDict()
    tcmap.comp = OrderedDict()
    tcmap.cadence = OrderedDict()
    tcmap.func = OrderedDict()
    tcmap.modules = OrderedDict()
    tcmap.module_max_timeout = OrderedDict()
    tcmap.faster_cli = OrderedDict()
    tcmap.tryssh = OrderedDict()
    tcmap.tc_max_timeout = OrderedDict()
    tcmap.errors = []

    for row in _load_csv("faster_cli.csv", "reporting"):
        if len(row) < 2: continue
        fcli, name = [str(i).strip() for i in row[:2]]
        if fcli.strip().startswith("#"): continue
        name = os.path.basename(name)
        tcmap.faster_cli[name] = utils.integer_parse(fcli, 0)

    for row in _load_csv("tryssh.csv", "reporting"):
        if len(row) < 2: continue
        tryssh, name = [str(i).strip() for i in row[:2]]
        if tryssh.strip().startswith("#"): continue
        name = os.path.basename(name)
        tcmap.tryssh[name] = utils.integer_parse(tryssh, 0)

    for row in _load_csv("module_max_time.csv", "reporting"):
        if len(row) < 2: continue
        time, name = [str(i).strip() for i in row[:2]]
        if time.strip().startswith("#"): continue
        name = os.path.basename(name)
        tcmap.module_max_timeout[name] = utils.integer_parse(time, 0)

    for row in _load_csv("test_max_time.csv", "reporting"):
        if len(row) < 2: continue
        time, name = [str(i).strip() for i in row[:2]]
        if time.strip().startswith("#"): continue
        tcmap.tc_max_timeout[name] = utils.integer_parse(time, 0)

    tcmap_csv = os.getenv("SPYTEST_TCMAP_CSV_FILENAME", "tcmap.csv")
    for row in _load_csv(tcmap_csv, "reporting"):
        if len(row) == 4:
            #  TODO treat the data as module
            (age, cadence, comp, name) = (row[0], row[1], row[2], row[3])
            if name in tcmap.modules:
                msg = "duplicate module {}"
                tcmap.errors.append(msg.format(name))
                continue
            module = SpyTestDict()
            module.age = age
            module.cadence = cadence
            module.comp = comp
            module.name = name
            tcmap.modules[name] = module
            continue
        if len(row) < 5:
            print("Invalid line", row)
            continue
        (age, cadence, comp, tcid, func) = (row[0], row[1], row[2], row[3], row[4])
        if age.strip().startswith("#"):
            continue
        _add_tcmap_entry(age, cadence, comp, tcid, func)

    # verify the tcmap if required
    if verify: _verify_tcmap(items)

def _verify_tcmap(items=None):

    # expand the modules
    for name, module in tcmap.modules.items():
        if not items: continue
        for item in items:
            if item.location[0] != name:
                if item.location[0] != os.path.basename(name):
                    continue
            tc = item.location[2]
            # use function name for TC
            _add_tcmap_entry(module.age, module.cadence, module.comp, tc, tc)

    # check if any function mapped in multiple cadences
    for func, tcid_list in tcmap.tclist.items():
        cadences = dict()
        for tcid in tcid_list:
            cadences[tcmap.cadence[tcid]] = 1
        if len(cadences) > 1:
            msg = "function {} is mapped to {} testcases in multiple cadences {}"
            tcmap.errors.append(msg.format(func, len(tcid_list), cadences))

    # check if any function mapped in multiple components
    for func, tcid_list in tcmap.tclist.items():
        components = dict()
        for tcid in tcid_list:
            components[tcmap.comp[tcid]] = 1
        if len(components) > 1:
            msg = "function {} is mapped to {} testcases in multiple components {}"
            #TODO: enable this once the issues are fixed in tcmap.csv
            #tcmap.errors.append(msg.format(func, len(tcid_list), components.keys()))
            print(msg.format(func, len(tcid_list), components.keys()))

    _show_tcmap_errors()

def _show_tcmap_errors():
    if tcmap.errors:
        print("===== TCMAP Errors ======")
        print("\n".join(tcmap.errors))
        print("========================")

def _build_tclist_map(config, items):
    use_cadence = config.getoption("--tclist-map", None)
    if not use_cadence: return None
    use_cadences = use_cadence.replace(",", ' ').split()
    if not use_cadences: return None
    test_names = []
    for use_cadence in use_cadences:
        for name, module in tcmap.modules.items():
            if use_cadence == "all" or module.cadence == use_cadence:
                for item in items:
                    if item.location[0] == name:
                        func = item.location[2]
                        if func not in test_names:
                            test_names.append(func)
        for tcid, cadence in tcmap.cadence.items():
            if use_cadence == "all" or cadence == use_cadence:
                func = tcmap.func[tcid]
                if func not in test_names:
                    test_names.append(func)

    if len(test_names) <= 0:
        msg = " no '{}' test cases found in test case map file"
        print(msg.format(use_cadence))
        os._exit(9)

    if tcmap.errors:
        _show_tcmap_errors()
        if not config.getoption("--ignore-tcmap-errors", 0):
            os._exit(9)

    return set(test_names)

def _build_selected_tests(items, test_names):
    global missing_test_names_msg
    seen_test_names = set()
    selected_items = []
    deselected_items = []
    for item in items:
        alt_item_name = item.location[2][5:]
        if item.location[2] in test_names or item.nodeid in test_names:
            selected_items.append(item)
        elif alt_item_name in test_names:
            selected_items.append(item)
            seen_test_names.add(alt_item_name)
        else:
            deselected_items.append(item)
        seen_test_names.add(item.location[2])
        seen_test_names.add(item.nodeid)

    # trace missing tests
    missing_test_names = test_names - seen_test_names
    if missing_test_names:
        message = ("Ignoring below missing test list:\n  - ")
        message += "\n  - ".join(missing_test_names)
        print(message)
        missing_test_names_msg = message
    return selected_items, deselected_items

def shuffle_items(items):
    files = OrderedDict()
    for item in items:
        module = getattr(item, "module", None)
        if module.__file__ not in files:
            files[module.__file__] = []
        files[module.__file__].append(item)
    names = list(files.keys())
    seed = int(os.getenv("SPYTEST_RAMDOM_SEED", "100"))
    from random import Random
    Random(seed).shuffle(names)
    new_items = []
    for name in names:
        new_items.extend(files[name])
    items[:] = new_items

def modify_tests(config, items):
    test_names = []

    # create PID file
    create_pid_file()

    # load the tcmap - verify later
    _load_tcmap(False)

    # get the test names from CSV if specified
    tclist_method = "csv"
    tclist_csv = config.getoption("--tclist-csv", None)
    if tclist_csv:
        test_names = tclist_csv.replace(",", ' ').split()
        if not test_names:
            print("no test cases are specified in test case csv {}".format(tclist_csv))
            os._exit(10)
        test_names = set(test_names)

    # --tclist-csv superceeds --tclist-file
    if not test_names:
        tclist_method = "file"
        test_names = _build_tclist_file(config)

    # --tclist-file superceeds --tclist-map
    if not test_names:
        tclist_method = "map"
        test_names = _build_tclist_map(config, items)

    if test_names:
        selected, deselected = _build_selected_tests(items, test_names)
        items[:] = selected
        config.hook.pytest_deselected(items=deselected)
        if tclist_method == "map":
            utils.banner("deselected tests cases", func=ftrace)
            for item in deselected:
                ftrace(item.nodeid)
            utils.banner(None, func=ftrace)

    # verify the tcmap
    _verify_tcmap(items)

    # ignore the test cases that are already completed
    exclude_executed_tests(config, items)

    # check for known markers
    if not config.getoption("--ignore-known-markers", 0):
        read_known_markers(config, items)

    # add the dependency
    if not config.getoption("--ignore-dep-check", 0):
        build_dependency(config, items)

    # shuffile ine items for random order
    if config.getoption("--random-order", 1):
        shuffle_items(items)

def get_result_files(logs_path):
    (csv_files, retval) = ([], [])
    if batch.is_slave():
        csv_files.extend(glob.glob("{}/../*_result_all.csv".format(logs_path)))
        tc_index = 2
    else:
        csv_files.extend(glob.glob("{}/*_result.csv".format(logs_path)))
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

    [user_root, logs_path, slave_id] = _get_logs_path()
    [tc_index, csv_files] = get_result_files(logs_path)

    # prepare reused test case list
    reused_results = OrderedDict()
    for csv_file in csv_files:
        for row in Result.read_report_csv(csv_file):
            if reuse_results in ["all"]:
                reused_results[row[tc_index]] = 1
            elif reuse_results in ["pass", "allpass"] and \
                 row[tc_index+1] in ["Pass"]:
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

def collect_test(item):
    dtrace("collect_test", item)
    collected_items[item.location[2]] = item
    nodeid_test_names[item.nodeid] = item.location[2]

def add_dep_item(item, items):
    marker = item.get_closest_marker("depends")
    if marker:
        for dep_name in marker.args:
            if dep_name not in items:
                if dep_name not in collected_items:
                    # this is the case of using --count option
                    msg = "item {} dependency {} not found in collected".format(item, dep_name)
                    if not item.originalname or not item.name:
                        print(msg)
                        continue
                    repeat = item.name.replace(item.originalname,"")
                    dep_name = "{}{}".format(dep_name, repeat)
                    if dep_name not in collected_items:
                        print(msg)
                        continue
                add_item = collected_items[dep_name]
                add_dep_item(add_item, items)
                if add_item not in items.values():
                    items[dep_name] = add_item
    if item not in items.values():
        items[item.location[2]] = item

def build_dependency(config, items):
    selected_test_items.clear()
    for item in items:
        add_dep_item(item, selected_test_items)
    items[:] = selected_test_items.values()
    for item in items:
        selected_test_results[item.location[2]] = None

def check_dependency(name):
    errs = []
    if name not in selected_test_items:
        errs.append("some thing is wrong - failed to find test item")
        return errs
    item = selected_test_items[name]
    marker = item.get_closest_marker("depends")
    if not marker:
        return None
    for dep_name in marker.args:
        if selected_test_results[dep_name] != "Pass":
            errs.append(dep_name)
    return errs

def read_known_markers(config, items):
    must_fail_items.clear()
    for item in items:
        marker = item.get_closest_marker("must_fail")
        if marker:
            must_fail_items[item.location[2]] = None

current_test.excinfo = None
current_test.hook = ""
current_test.name = ""
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
current_module.name = ""
current_module.result = ""
current_module.result_desc = ""
def set_current_result(res=None, desc=""):
    if not desc or not res:
        current_module.result_desc = ""
        current_module.result = "ConfigFail"
        current_test.result_desc = ""
        current_test.result = "ConfigFail"
    elif current_test.hook == "test_module":
        if not current_module.result_desc:
            current_module.result_desc = desc
            current_module.result = res
    elif current_test.hook == "test_function":
        if not current_test.result_desc:
            current_test.result_desc = desc
            current_test.result = res

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
    if call.excinfo and call.excinfo.typename not in [ "XFailed", "Skipped"]:
        current_test.excinfo = call.excinfo
    else:
        current_test.excinfo = None

def log_report(report):
    wa = get_work_area()
    worker_id = getattr(report, "worker_id", None)
    if worker_id:
        log_report_master(report, wa)
    else:
        log_report_slave(report, wa)

def log_report_slave(report, wa):
    [user_root, logs_path, slave_id] = _get_logs_path()

    if report.nodeid in nodeid_test_names:
        func_name = nodeid_test_names[report.nodeid]
    else:
        func_name = None

    # record module finish time
    dtrace("log_report", report, func_name, current_test)
    if report.when == "setup" and func_name and wa:
        log_module_time_finish(report.nodeid, func_name)

    # fail tests when  the module config is failed
    if report.when == "setup" and report.outcome != "passed" and wa and func_name:
        if not current_test.excinfo:
            wa._test_log_init(report.nodeid, func_name)
            if current_test.hook == "test_function":
                desc = wa._context.set_default_error("ConfigFail", "pretest_config_failed")
            elif wa.abort_module_msg:
                [res, desc] = ['SKIPPED', wa.abort_module_msg]
                desc = wa._context.report(res, "msg", desc)
                wa._test_log_finish(report.nodeid, func_name, res, desc, min_time)
            else:
                [res, desc] = [current_module.result, current_module.result_desc]
                desc = wa._context.report(res, "module_config_failed", desc)
                wa._test_log_finish(report.nodeid, func_name, res, desc, min_time)
        else:
            if current_test.hook != "test_function":
                wa._test_log_init(report.nodeid, func_name)
                desc = log_test_exception(current_test.excinfo, current_test.hook)
                wa._test_log_finish(report.nodeid, func_name, "ConfigFail", desc, min_time)

    if report.when == "setup" and report.outcome == "passed" and wa:
        wa.event("Test Execution:", report.nodeid)

def log_report_master(report, wa):
    if report.when == "teardown":
        consolidate_results(wa.cfg.run_progress_report, True)

def session_start(session):
    if os.getenv("SPYTEST_LIVE_RESULTS", "1") == "1":
        bg_results.start(consolidate_results)

def get_rate(val, total):
    if total:
        return '{:.2%}'.format(val*1.0/total)
    return "0.00%"

def read_all_results(logs_path, suffix, offset):

    def csv_base_file(val):
        val = os.path.basename(val)
        return val

    # get all the result file paths
    csv_files = glob.glob("{}/gw*/*_{}.csv".format(logs_path, suffix))
    csv_files.sort(key=csv_base_file)

    # prepare the map for module result and result file
    module_result = OrderedDict()
    rows_dict = dict()
    for csv_file in csv_files:
        rows = Result.read_report_csv(csv_file)
        rows_dict[csv_file] = rows
        for row in rows:
            module_result[row[offset]] = csv_file

    # Results
    [results, links] = ([], [])
    for csv_file in csv_files:
        rows = rows_dict[csv_file]
        gw_name = os.path.basename(os.path.dirname(csv_file))
        for row in rows:
            if module_result[row[offset]] == csv_file:
                gw_logs = find_log_path(row[offset], csv_file, gw_name)
                new_row = [gw_name]
                new_row.extend(row)
                results.append(new_row)
                links.append(gw_logs)

    return [results, links]

def consolidate_results(progress=None, thread=False, count=None):

    # generate email report
    generate_email_report(count)

    [user_root, logs_path, slave_id] = _get_logs_path()
    count = batch.get_member_count() if count is None else count
    if slave_id or count < 1 or not batch.is_batch():
        return

    # if threaded set event
    if thread and bg_results.is_valid():
        bg_results.run()
        return

    # check if we really need to do this
    if progress is not None and progress <= 0:
        return

    # Func Results
    [results, links] = read_all_results(logs_path, "result", 0)
    if links:
        for i,row in enumerate(results): row.append(links[i])
    consolidated = sorted(results, key=itemgetter(5))
    if links:
        for i,row in enumerate(consolidated): links[i] = row.pop()
    results_csv = get_results_csv(logs_path, True)
    Result.write_report_csv(results_csv, consolidated, 0)
    generate_module_report(results_csv, 1, links)
    html_file = os.path.splitext(results_csv)[0]+'.html'
    Result.write_report_html(html_file, consolidated, 0, True, 4)
    wa = get_work_area()
    if wa and wa._context:
        wa._context.run_progress_report(len(consolidated))

    # TC Results
    [results, links] = read_all_results(logs_path, "tcresult", 7)
    if links:
        for i,row in enumerate(results): row.append(links[i])
    consolidated = sorted(results, key=itemgetter(5))
    if links:
        for i,row in enumerate(consolidated): links[i] = row.pop()
    tcresults_csv = get_tc_results_csv(logs_path, True)
    Result.write_report_csv(tcresults_csv, consolidated, 1)
    generate_component_report(results_csv, tcresults_csv, 1)
    html_file = os.path.splitext(tcresults_csv)[0]+'.html'
    Result.write_report_html(html_file, consolidated, 1, True, 4)

    # syslog Results
    [results, links] = read_all_results(logs_path, "syslog", 1)
    if links:
        for i,row in enumerate(results): row.append(links[i])
    consolidated = sorted(results, key=itemgetter(5))
    if links:
        for i,row in enumerate(consolidated): links[i] = row.pop()
    syslog_csv = get_syslog_csv(logs_path, True)
    Result.write_report_csv(syslog_csv, consolidated, 2)
    html_file = os.path.splitext(syslog_csv)[0]+'.html'
    Result.write_report_html(html_file, consolidated, 2, True)

    # Stats
    [consolidated, links] = read_all_results(logs_path, "stats", 0)
    csv_file = get_file_path("stats", "csv", logs_path, True)
    Result.write_report_csv(csv_file, consolidated, 3)
    html_file = os.path.splitext(csv_file)[0]+'.html'
    Result.write_report_html(html_file, consolidated, 3, True)

def generate_email_report_files(files, nodes, report_html):

    count = len(files)
    reports_header = ["Stat"]
    if not nodes:
        reports_header.append("Value")
    else:
        for node in nodes:
            reports_header.append(node)

    if count > 1:
        reports_header.append("Consolidated")

    report_data = OrderedDict()
    for key in report_cols:
        row = [key] # stat name
        for index in range(0, count):
            row.append("0") # node stat
        if count > 1:
            row.append("0") #total
        report_data[key] = row

    all_reports = []

    # fill the stat values
    for index in range(0, count):
        report_file = files[index]
        if os.path.exists(report_file):
            lines = utils.read_lines(report_file)
            rows = [i for i in lines if i]
            for row in rows:
                (key, val) = row.split('=')
                key = key.strip()
                val = val.strip()
                if key == "Software Version":
                    set_mail_build(val)
                if key in report_data:
                    report_data[key][index+1] = val

    # compute totals
    (pass_count, tc_count) = (0, 0)
    for key in report_cols:
        if count <= 1:
            pass
        elif "Execution Started" in key:
            first_started = "NA"
            for ele in report_data[key][1:]:
                date_time_obj = utils.date_parse(ele)
                if date_time_obj is None:
                    continue
                if first_started == "NA" or date_time_obj < first_started:
                    first_started = date_time_obj
            report_data[key][count+1] = str(first_started)
        elif "Execution Completed" in key:
            last_completed = "NA"
            for ele in report_data[key][1:]:
                date_time_obj = utils.date_parse(ele)
                if date_time_obj is None:
                    continue
                if last_completed == "NA" or date_time_obj > last_completed:
                    last_completed = date_time_obj
            report_data[key][count+1] = str(last_completed)
        elif "Execution Time" in key:
            first_started = report_data["Execution Started"][count+1]
            last_completed = report_data["Execution Completed"][count+1]
            try:
                first_started = utils.date_parse(first_started)
                last_completed = utils.date_parse(last_completed)
                exec_time = utils.time_diff(first_started, last_completed, True)
                report_data[key][count+1] = str(exec_time)
            except:
                report_data[key][count+1] = "NA"
        elif "Session Init Time" in key:
            max_init_time = 0
            for ele in report_data[key][1:]:
                if ele != "0" and ele != "":
                    (h,m,s) = ele.split(':')
                    tmp_secs = int(h) * 3600 + int(m) * 60 + int(s)
                    if tmp_secs > max_init_time:
                        max_init_time = tmp_secs
            report_data[key][count+1] = utils.time_format(max_init_time)
        elif "Tests Time" in key:
            total_secs = 0
            for ele in report_data[key][1:]:
                if ele != "0" and ele != "":
                    (h,m,s) = ele.split(':')
                    total_secs += int(h) * 3600 + int(m) * 60 + int(s)
            report_data[key][count+1] = utils.time_format(total_secs)
        elif key in result_vals or key == "Module Count":
            total = sum([int(i) for i in report_data[key][1:]])
            report_data[key][count+1] = total
        elif key in result_vals or key == "Function Count":
            total = sum([int(i) for i in report_data[key][1:]])
            report_data[key][count+1] = total
        elif key in result_vals or key == "Test Count":
            tc_count = sum([int(i) for i in report_data[key][1:]])
            report_data[key][count+1] = tc_count
        elif key in result_vals or key == "Pass Count":
            pass_count = sum([int(i) for i in report_data[key][1:]])
            report_data[key][count+1] = pass_count
        elif key in result_vals or key == "Pass Rate":
            report_data[key][count+1] = get_rate(pass_count, tc_count)
        elif key in result_vals or key == "SysLog Count":
            total = sum([int(i) for i in report_data[key][1:]])
            report_data[key][count+1] = total
        else:
            report_data[key][count+1] = "NA"

    for key in report_cols:
        all_reports.append(report_data[key])

    if len(all_reports) < len(reports_header):
        (rows, cols) = ([], [""])
        for row in all_reports: cols.append(row[0])
        for col_index in range(1, len(reports_header)):
            new_row = [reports_header[col_index]]
            for row in all_reports:
                new_row.append(row[col_index])
            rows.append(new_row)
        report_status = utils.write_html_table2(cols, rows)
    else:
        report_status = utils.write_html_table2(reports_header, all_reports)
    with open(report_html, "w") as ofh:
        ofh.write("\n\n{}\n".format(report_status))

def generate_email_report(count=None):
    [user_root, logs_path, slave_id] = _get_logs_path()
    if slave_id:
        return

    count = batch.get_member_count() if count is None else count
    if count <= 1 and not batch.is_batch():
        report_txt = get_report_txt(logs_path)
        report_html = os.path.splitext(report_txt)[0]+'.html'
        return generate_email_report_files([report_txt], [], report_html)

    report_txt = get_report_txt(logs_path, True)
    report_html = os.path.splitext(report_txt)[0]+'.html'
    (files, nodes, report_txt) = ([],[], get_report_txt())
    for index in range(0, count):
        node = "gw{}".format(index)
        report_file = os.path.join(logs_path, node, report_txt)
        files.append(report_file)
        nodes.append(node)

    return generate_email_report_files(files, nodes, report_html)

def find_log_path(name, csv_file, node):
    replace = "_tests_{}".format(name.replace(".py", ".log"))
    replace = replace.replace("/", "_")
    suffix = os.path.basename(csv_file)
    suffix = suffix.replace("_result_all.csv", replace)
    suffix = suffix.replace("_result.csv", replace)
    return suffix if not node else "{}/{}".format(node, suffix)

def generate_module_report(csv_file, offset=0, links=None):
    html_file = os.path.splitext(csv_file)[0]+'_modules.html'
    rows = Result.read_report_csv(csv_file)
    module_logs = OrderedDict()
    modules = OrderedDict()

    for i, row in enumerate(rows):
        name = row[offset]
        if name not in modules:
            if offset == 0:
                module_logs[name] = find_log_path(name, csv_file, None)
            elif links is not None:
                module_logs[name] = links[i]
            else:
                module_logs[name] = find_log_path(name, csv_file, row[0])
            modules[name] = OrderedDict()
            module = modules[name]
            module["PassRate"]  = 0
            module["SysLogs"]  = 0
            module["CDT"]  = 0
            module["FCLI"]  = 0
            module["TSSH"]  = 0
            module["DCNT"]  = 0
            module["Functions"]  = 0
            module["PrologTime"]  = 0
            module["EpilogTime"]  = 0
            module["FuncTime"]  = 0
            module["ExecTime"]  = 0
            for res in result_vals:
                module[res] = 0
        else:
            module = modules[name]
        res = row[offset+2].upper()
        secs = utils.time_parse(row[offset+3])
        syslogs = utils.integer_parse(row[offset+5])
        syslogs = syslogs if syslogs else 0
        fcli = utils.integer_parse(row[offset+6])
        tryssh = utils.integer_parse(row[offset+7])
        num_duts = utils.integer_parse(row[offset+8])
        desc = row[offset+9]
        if res in module:
            module[res] = module[res] + 1
            module["SysLogs"] = module["SysLogs"] + syslogs
            module["FuncTime"] = module["FuncTime"] + secs
            module["Functions"] = module["Functions"] + 1
            module["PassRate"] = get_rate(module["PASS"], module["Functions"])
        else:
            if "Prolog" in desc:
                module["PrologTime"] = module["PrologTime"] + secs
                module["FCLI"] = fcli
                module["TSSH"] = tryssh
                module["DCNT"] = num_duts
            else:
                module["EpilogTime"] = module["EpilogTime"] + secs
            module["SysLogs"] = module["SysLogs"] + syslogs

    total = OrderedDict()
    for module in modules.values():
        module["ExecTime"] = module["FuncTime"] + module["PrologTime"] + module["EpilogTime"]
        module["CDT"] = module["ExecTime"] * module["DCNT"]
        for col in module:
            try:
                if col not in total: total[col] =  module[col]
                else: total[col] = total[col] + module[col]
            except: pass
        total["PassRate"]  = get_rate(total["PASS"], total["Functions"])

    if modules:
        modules["==== TOTAL ===="] = total
        module_logs["==== TOTAL ===="] = None

    def sort_func(y):
        try:
            #return y[1]['ExecTime']
            return y[1]['CDT']
        except:
            return 0

    # sort the modules on total execution time
    sorted_modules = sorted(modules.items(), key=sort_func)

    (rows, cols, links) = ([],[],[])
    for name, module in sorted_modules:
        for col in ["PrologTime", "EpilogTime", "FuncTime", "ExecTime", "CDT"]:
            module[col] = utils.time_format(int(module[col]))
        links.append(module_logs[name])
        row = [name]
        row.extend(module.values())
        rows.append(row)
        cols = list(module.keys())
        cols.insert(0, "")
    utils.write_html_table2(cols, rows, html_file, links)
    csv_file = os.path.splitext(html_file)[0]+'.csv'
    utils.write_csv_file(cols, rows, csv_file)

def generate_component_report(results_csv, tcresults_csv, offset=0):
    modules = OrderedDict()
    func_time = dict()
    func_syslogs = dict()
    tcmodmap = dict()
    tc_rows = Result.read_report_csv(tcresults_csv)
    func_rows = Result.read_report_csv(results_csv)
    for row in func_rows:
        name = row[offset]
        func = row[offset+1]
        res = row[offset+2]
        secs = utils.time_parse(row[offset+3])
        syslogs = utils.integer_parse(row[offset+5])
        syslogs = syslogs if syslogs else 0
        num_duts = utils.integer_parse(row[offset+8])
        desc = row[offset+9]
        if name not in modules:
            modules[name] = OrderedDict()
            module = modules[name]
            module["PrologTime"] = 0
            module["EpilogTime"] = 0
            module["SysLogs"] = 0
            module["DCNT"] = num_duts
        else:
            module = modules[name]

        if not func:
            if "Prolog" in desc:
                module["PrologTime"] = module["PrologTime"] + secs
            else:
                module["EpilogTime"] = module["EpilogTime"] + secs
            module["SysLogs"] = module["SysLogs"] + syslogs
        else:
            tcmodmap[func] = name
            func_time[func] = secs
            func_syslogs[func] = syslogs

    components = OrderedDict()
    total_executed = 0
    total_pass_count = 0
    total_pass_rate = 0.00
    total_envfail_count = 0
    total_envfail_rate = 0.00
    total_skipped_count = 0
    total_skipped_rate = 0.00
    total_time_taken = 0
    total_dut_time = 0
    total_syslog_count = 0
    for row in tc_rows:
        tc = row[offset+1]
        res = row[offset+2].upper()
        if tc not in tcmap.comp:
            # use the value from tcresults
            name = row[offset]
        else:
            name = tcmap.comp[tc]

        if tc not in tcmap.func:
            # use the value from tcresults
            func = row[offset+6]
        else:
            func = tcmap.func[tc]

        if name not in components:
            components[name] = OrderedDict()
            component = components[name]
            component["PassRate"]  = 0.00
            component["Executed"]  = 0
            component["PassCount"]  = 0
            component["TimeTaken"]  = 0
            component["SysLogs"]  = 0
            component["EnvFailCount"]  = 0
            component["EnvFailRate"]  = 0.00
            component["SkippedCount"]  = 0
            component["SkippedRate"]  = 0.00
            component["CDT"]  = 0
        else:
            component = components[name]
        if res == "PASS":
            component["PassCount"] = component["PassCount"]  + 1
            total_pass_count = total_pass_count + 1
        elif res in ["SKIPPED"]:
            component["SkippedCount"] = component["SkippedCount"]  + 1
            total_skipped_count = total_skipped_count + 1
        elif res in ["ENVFAIL", "TOPOFAIL", "TGENFAIL"]:
            component["EnvFailCount"] = component["EnvFailCount"]  + 1
            total_envfail_count = total_envfail_count + 1
        try:
            func_secs = func_time[func]
            syslogs = func_syslogs[func]
        except:
            #print("=========== Failed to find function {} time -- ignore".format(func))
            func_secs = 0
            syslogs = 0
        try:
            module = modules[tcmodmap[func]]
            prolog_secs = module["PrologTime"]
            epilog_secs = module["EpilogTime"]
            module_syslogs = module["SysLogs"]
            num_duts = module["DCNT"]
        except:
            #print("=========== Failed to find module {} time -- ignore".format(func))
            prolog_secs = 0
            epilog_secs = 0
            module_syslogs = 0
            num_duts = 1
        all_secs = func_secs + prolog_secs + epilog_secs
        component["Executed"] = component["Executed"]  + 1
        component["PassRate"]  = get_rate(component["PassCount"], component["Executed"])
        component["TimeTaken"] = component["TimeTaken"] + all_secs
        component["SysLogs"] = component["SysLogs"] + syslogs + module_syslogs
        component["EnvFailRate"]  = get_rate(component["EnvFailCount"], component["Executed"])
        component["SkippedRate"]  = get_rate(component["SkippedCount"], component["Executed"])
        component["CDT"] = component["CDT"] + all_secs * num_duts
        total_executed = total_executed + 1
        total_pass_rate = get_rate(total_pass_count, total_executed)
        total_time_taken = total_time_taken + all_secs
        total_dut_time = total_dut_time + all_secs * num_duts
        total_syslog_count = total_syslog_count + syslogs + module_syslogs
        total_envfail_rate = get_rate(total_envfail_count, total_executed)
        total_skipped_rate = get_rate(total_skipped_count, total_executed)
        if func_secs:
            func_time[func] = 0
        if syslogs:
            func_syslogs[func] = 0
        if prolog_secs:
            module["PrologTime"] = 0
        if epilog_secs:
            module["EpilogTime"] = 0
        module["SysLogs"] = 0

    components = OrderedDict(sorted(components.items()))

    name = "==== TOTAL ===="
    components[name] = OrderedDict()
    component = components[name]
    component["PassRate"]  = total_pass_rate
    component["Executed"] = total_executed
    component["PassCount"] = total_pass_count
    component["TimeTaken"]  = total_time_taken
    component["SysLogs"]  = total_syslog_count
    component["EnvFailCount"] = total_envfail_count
    component["EnvFailRate"]  = total_envfail_rate
    component["SkippedCount"] = total_skipped_count
    component["SkippedRate"]  = total_skipped_rate
    component["CDT"]  = total_dut_time

    # remove the columns that are not needed
    for name, component in components.items():
        del component["EnvFailCount"]
        del component["SkippedCount"]

    (rows, cols) = ([], [])
    for name, component in components.items():
        component["TimeTaken"] = utils.time_format(int(component["TimeTaken"]))
        component["CDT"] = utils.time_format(int(component["CDT"]))
        row = [name]
        row.extend(component.values())
        rows.append(row)
        cols = list(component.keys())
        cols.insert(0, "")
    html_file = os.path.splitext(tcresults_csv)[0]+'_components.html'
    utils.write_html_table2(cols, rows, html_file)
    csv_file = os.path.splitext(html_file)[0]+'.csv'
    utils.write_csv_file(cols, rows, csv_file)

def _report_data_generation(execution_start, execution_end,
                            session_init_time, total_tc_time,
                            results_csv, tcresults_csv, syslog_csv):

    generate_component_report(results_csv, tcresults_csv)
    tc_rows = Result.read_report_csv(tcresults_csv)
    html_file = os.path.splitext(tcresults_csv)[0]+'.html'
    Result.write_report_html(html_file, tc_rows, 1, False)

    generate_module_report(results_csv)
    func_rows = Result.read_report_csv(results_csv)
    html_file = os.path.splitext(results_csv)[0]+'.html'
    Result.write_report_html(html_file, func_rows, 0, False)

    syslog_rows = Result.read_report_csv(syslog_csv)
    html_file = os.path.splitext(syslog_csv)[0]+'.html'
    Result.write_report_html(html_file, syslog_rows, 2, False)

    tc_result_dict = {}
    for key in result_vals:
        tc_result_dict[key] = 0
    total_tcs = 0
    for row in tc_rows:
        col_result = str(row[2])
        if col_result != "" and col_result is not None:
            col_result = col_result.upper()
            if col_result in tc_result_dict:
                tc_result_dict[col_result] += 1
                total_tcs += 1
            else:
                print(col_result, " is not found in tc results ")

    func_result_dict = {}
    for key in result_vals:
        func_result_dict[key] = 0
    modules = dict()
    total_funcs = 0
    total_syslogs = 0
    for row in func_rows:
        modules[row[0]] = 1
        col_result = str(row[2])
        syslogs = utils.integer_parse(row[5])
        syslogs = syslogs if syslogs else 0
        total_syslogs = total_syslogs + syslogs
        if col_result != "" and col_result is not None:
            col_result = col_result.upper()
            if col_result in func_result_dict:
                func_result_dict[col_result] += 1
                total_funcs += 1
            else:
                print(col_result, " is not found in results ")

    data = ""
    start_time = execution_start.replace(microsecond=0)
    end_time = execution_end.replace(microsecond=0)
    data = "{}\nExecution Started = {}".format(data, start_time)
    data = "{}\nExecution Completed = {}".format(data, end_time)
    exec_time = utils.time_diff(execution_start, execution_end, True)
    data = "{}\nExecution Time = {}".format(data, exec_time)
    data = "{}\nSession Init Time = {}".format(data, session_init_time)
    data = "{}\nTests Time = {}".format(data, total_tc_time)

    for item, value in func_result_dict.items():
        data = "{}\n{} = {}".format(data, item, value)
    data = "{}\nFunction Count = {}".format(data, total_funcs)
    data = "{}\nModule Count = {}".format(data, len(modules))
    data = "{}\nTest Count = {}".format(data, total_tcs)
    data = "{}\nPass Count = {}".format(data, tc_result_dict["PASS"])
    data = "{}\nPass Rate = {}".format(data, get_rate(tc_result_dict["PASS"], total_tcs))
    data = "{}\nSysLog Count = {}".format(data, total_syslogs)

    return data

def compare_results(dir1, dir2, show_all=True):
    file1=glob.glob(dir1+"/*_result*.csv")
    file2=glob.glob(dir2+"/*_result*.csv")
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

    consolidate_results()

def configure(config):

    [user_root, logs_path, slave_id] = _get_logs_path()

    if batch.configure(config, logs_path):
        # create psuedo workarea for the master
        wa = _create_work_area2(config)
        _load_tcmap()
        batch.set_tcmap(tcmap)
        batch.set_logger(wa._context.log)

def unconfigure(config):

    if not batch.unconfigure(config):
        return

    # delete psuedo workarea for the master
    _delete_work_area()

def parse_batch_args(numprocesses, buckets):
    [user_root, logs_path, slave_id] = _get_logs_path()
    return batch.parse_args(numprocesses, buckets, logs_path)

def make_scheduler(config, log):
    return batch.make_scheduler(config, log)

def configure_nodes(config):
    return batch.configure_nodes(config)

def configure_node(node):
    return batch.configure_node(node)

def begin_node(gateway):
    return batch.begin_node(gateway)

def finish_node(node, err):
    return batch.finish_node(node, err)

def fixture_post_finalizer(fixturedef, request):
    dtrace("fixture_post_finalizer", fixturedef, request, current_test)

    wa = get_work_area()
    if not wa:
        return None

    if fixturedef.argname == "global_module_hook":
        if not current_module.global_module_finalized:
            result = "Pass: {}/{}".format(wa.module_tc_executed-wa.module_tc_fails, wa.module_tc_executed)
            wa.event("Framework Module Hook Finalize:", request.node.nodeid, result)
            current_module.global_module_finalized = True
            wa.log_time("Framework Module Hook Finilize")
            wa.module_log_init(None)
            used_devices = wa._get_devices_usage_list()
            wa.event("Devices used:", request.node.nodeid, len(used_devices), wa._get_devices_usage_list())
            batch.verify_bucket(request.node.nodeid, len(used_devices), wa.module_tc_fails)
            wa._set_device_usage_collection(False)
    elif fixturedef.argname == "global_function_hook":
        wa.event("Framework Function Hook Finalize:", request.node.nodeid)
        wa.log_time("Framework Function Hook Finilize")
        current_module.epilog_start = get_timenow()
        wa.tc_log_init(None)
        #dbg_msg = "Devices used in the entire module till now {} {}:".format(fixturedef.scope, fixturedef.argname)
        #wa.event(dbg_msg, wa._get_devices_usage_list())
        wa._set_device_usage_collection(True)
    elif fixturedef.argname == "__pytest_repeat_step_number":
        pass
    elif fixturedef.scope == "module":
        if not current_module.user_module_finalized:
            current_module.user_module_finalized = True
            wa.event("Module Hook Finalize:", fixturedef.baseid, fixturedef.argname)
            wa._post_module_epilog(fixturedef.baseid, True)
            set_current_result()
            time_taken = get_elapsed(current_module.epilog_start, True, min_time)
            wa._context.publish2(fixturedef.baseid, None, None, time_taken, None, "", "Module Epilog")
            current_module.epilog_start = None
            wa.log_time("User Module {} Hook Finilize".format(fixturedef.baseid))
            #dbg_msg = "Devices used in the entire module till now {} {}:".format(fixturedef.scope, fixturedef.argname)
            #wa.event(dbg_msg, wa._get_devices_usage_list())
            wa._set_device_usage_collection(False)
    elif fixturedef.scope == "function":
        wa.event("Function Hook Finalize:", fixturedef.baseid, fixturedef.argname)
        wa._post_function_epilog(fixturedef.baseid)
        wa.log_time("User Function {} Hook Finilize".format(fixturedef.baseid))
        #dbg_msg = "Devices used in the entire module till now {} {}:".format(fixturedef.scope, fixturedef.argname)
        #wa.event(dbg_msg, wa._get_devices_usage_list())
        wa._set_device_usage_collection(False)
    elif fixturedef.scope == "class":
        wa.event("Class Hook Finalize:", fixturedef.baseid, fixturedef.argname)
        wa.log_time("User Class {} Hook Finilize".format(fixturedef.baseid))
    else:
        wa.event("Misc Hook Finalize:", fixturedef.baseid, fixturedef.argname)
        wa.log_time("Misc {} Hook scope {} Finilize".format(fixturedef.baseid, fixturedef.scope))

def fixture_setup(fixturedef, request):

    dtrace("fixture_setup", fixturedef, request, current_test)

    wa = get_work_area()
    if not wa:
        return None

    if fixturedef.argname == "global_module_hook":
        module_name = "tests/{}".format(request.node.nodeid.replace(".py", ""))
        module_name = module_name.replace("/", "_")
        wa.module_log_init(module_name)
        wa.log_time("Framework Module Hook Start")
        log_module_time_start()
        current_test.hook = "global_module"
        wa.event("Framework Module Hook:", request.node.nodeid)
        current_module.global_module_finished = False
        current_module.global_module_finalized = False
        current_module.name = ""
        current_test.name = ""
        set_current_result()
        wa._set_device_usage_collection(False)
        #dbg_msg = "Devices used in the entire module till now {} {}:".format(fixturedef.scope, fixturedef.argname)
        #wa.event(dbg_msg, wa._get_devices_usage_list())
    elif fixturedef.argname == "global_function_hook":
        wa.tc_log_init(request.node.location[2])
        wa.log_time("Framework Function Hook Start")
        log_module_time_finish(request.node.nodeid)
        current_test.hook = "global_function"
        current_test.name = ""
        wa.instrument(None, "pre-infra-module")
        wa.event("Framework Function Hook:", request.node.nodeid)
        wa._set_device_usage_collection(False)
        #dbg_msg = "Devices used in the entire module till now {} {}:".format(fixturedef.scope, fixturedef.argname)
        #wa.event(dbg_msg, wa._get_devices_usage_list())
    elif fixturedef.argname == "__pytest_repeat_step_number":
        pass
    elif fixturedef.scope == "module":
        if wa.abort_module_msg:
            wa.event("SKIP Module Hook:", fixturedef.baseid, fixturedef.argname)
            pytest.skip(wa.abort_module_msg)
        wa.log_time("User Module {} Hook Start".format(fixturedef.baseid))
        wa._pre_module_prolog(fixturedef.baseid)
        current_test.hook = "test_module"
        set_current_result()
        wa.event("Module Hook:", fixturedef.baseid, fixturedef.argname)
        wa.instrument(None, "pre-user-module")
        current_module.name = fixturedef.baseid
        current_test.name = ""
        current_module.user_module_finished = False
        current_module.user_module_finalized = False
        #dbg_msg = "Devices used in the entire module till now {} {}:".format(fixturedef.scope, fixturedef.argname)
        #wa.event(dbg_msg, wa._get_devices_usage_list())
    elif fixturedef.scope == "function":
        if wa.abort_module_msg:
            wa.event("SKIP Function Hook:", fixturedef.baseid, fixturedef.argname)
            pytest.skip(wa.abort_module_msg)
        wa.log_time("User Function {} Hook Start".format(fixturedef.baseid))
        current_test.hook = "test_function"
        try: current_test.name = request.function.func_name
        except: current_test.name = request.function.__name__
        wa._pre_function_prolog(current_test.name)
        wa.event("Function Hook:", fixturedef.baseid, fixturedef.argname)
        wa.instrument(None, "pre-user-func")
        #dbg_msg = "Devices used in the entire module till now {} {}:".format(fixturedef.scope, fixturedef.argname)
        #wa.event(dbg_msg, wa._get_devices_usage_list())
    elif fixturedef.scope == "class":
        wa.log_time("User Class {} Hook Start".format(fixturedef.baseid))
        current_test.hook = "test_class"
        wa.event("Class Hook:", fixturedef.baseid, fixturedef.argname)
    else:
        wa.log_time("Misc {} Hook scope {} Start".format(fixturedef.baseid, fixturedef.scope))
        current_test.hook = "misc"
        wa.event("Misc Hook:", fixturedef.baseid, fixturedef.argname)

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
    elif fixturedef.argname == "global_module_hook":
        if not current_module.global_module_finished:
            current_module.global_module_finished = True
            wa.event("Framework Module Hook Finish:", request.node.nodeid)
            wa.log_time("Framework Module Hook end")
            wa._clear_devices_usage_list()
            wa._set_device_usage_collection(True)
            #dbg_msg = "Devices used in the entire module till now {} {}:".format(fixturedef.scope, fixturedef.argname)
            #wa.event(dbg_msg, wa._get_devices_usage_list())
    elif fixturedef.argname == "global_function_hook":
        wa.instrument(None, "post-infra-module")
        wa.event("Framework Function Hook Finish:", request.node.nodeid)
        wa.log_time("Framework Function Hook end")
        wa._set_device_usage_collection(True)
        #dbg_msg = "Devices used in the entire module till now {} {}:".format(fixturedef.scope, fixturedef.argname)
        #wa.event(dbg_msg, wa._get_devices_usage_list())
    elif fixturedef.argname == "__pytest_repeat_step_number":
        pass
    elif fixturedef.scope == "module":
        wa._set_device_usage_collection(False)
        #dbg_msg = "Devices used in the entire module till now {} {}:".format(fixturedef.scope, fixturedef.argname)
        #wa.event(dbg_msg, wa._get_devices_usage_list())
        if not wa.cfg.module_epilog:
            fixturedef._finalizers = []
        if not current_module.user_module_finished:
            current_module.user_module_finished = True
            # current_module.result can't be used as its value is ConfigFail
            # hence using current_module.result_desc
            if not current_module.result_desc:
                wa._post_module_prolog(fixturedef.baseid, True)
            else:
                wa._post_module_prolog(fixturedef.baseid, False)
            wa.instrument(None, "post-user-module")
            wa.event("Module Hook Finish:", fixturedef.baseid, fixturedef.argname)
            wa.log_time("User Module {} Hook end".format(fixturedef.baseid))
    elif fixturedef.scope == "function":
        #dbg_msg = "Devices used in the entire module till now {} {}:".format(fixturedef.scope, fixturedef.argname)
        #wa.event(dbg_msg, wa._get_devices_usage_list())
        wa.instrument(None, "post-user-func")
        wa._post_function_prolog(fixturedef.baseid)
        wa.event("Function Hook Finish:", fixturedef.baseid, fixturedef.argname)
        wa.log_time("User Function {} Hook end".format(fixturedef.baseid))
    elif fixturedef.scope == "class":
        wa.event("Class Hook Finish:", fixturedef.baseid, fixturedef.argname)
        wa.log_time("User Class {} Hook end".format(fixturedef.baseid))
    else:
        wa.event("Misc Hook Finish:", fixturedef.baseid, fixturedef.argname)
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
    if scope == "session" and not isend:
        return _create_work_area(request)
    if scope == "session" and isend:
        return _delete_work_area()

    wa = get_work_area()
    if not wa:
        return None

    filepath = request.fspath.basename
    if scope == "module" and not isend:
        return wa._module_init(filepath)
    if scope == "module" and isend:
        return wa._module_clean(filepath)

    func_name = request.node.location[2]
    if scope == "function" and not isend:
        return wa._function_init(request.node.nodeid, func_name)
    if scope == "function" and isend:
        return wa._function_clean(request.node.nodeid, func_name)

    return None

