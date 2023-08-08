import os
import re
import sys
import pdb
import time
import glob
import argparse
from inspect import currentframe
from collections import OrderedDict
from operator import itemgetter
from random import Random
import traceback
import threading
import textwrap
import tempfile
import logging
import socket
import signal
import pytest
import shutil

from apis.common.init import apis_register
from apis.common.init import apis_instrument

import utilities.common as utils
import utilities.parallel as putil
from spytest.net import Net
from spytest.logger import Logger
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
import spytest.compare as compare
import spytest.tcmap as tcmap
import spytest.paths as paths
import spytest.cmdargs as cmdargs
import spytest.env as env
import spytest.syslog as syslog
from spytest.feature import Feature

root_path = os.path.join(os.path.dirname(__file__), '..')
root_path = os.path.abspath(root_path)

g_lock = threading.Lock()
bg_results = putil.ExecuteBackgroud()
min_time = 0
missing_test_names_msg = ""
collected_items = dict()
selected_test_items = OrderedDict()
must_fail_items = OrderedDict()
community_unsupported = OrderedDict()
nodeid_test_names = dict()
selected_test_results = OrderedDict()
reused_test_results = OrderedDict()
current_test = SpyTestDict()
current_module = SpyTestDict()
gWorkArea = None

results_map = OrderedDict([
    ("", ""),
    ("PASS", "Pass"),
    ("FAIL", "Fail"),
    ("DUTFAIL", "Dut Fail"),
    ("TGENFAIL", "TGen Fail"),
    ("SCRIPTERROR", "Script Error"),
    ("UNSUPPORTED", "Not Supported"),
    ("CONFIGFAIL", "Config Fail"),
    ("ENVFAIL", "Env Fail"),
    ("DEPFAIL", "Dep Fail"),
    ("SKIPPED", "Skipped"),
    ("TIMEOUT", "Timeout"),
    ("TOPOFAIL", "Topo Fail"),
])

report_cols = ["Execution Started", "Execution Completed", "Execution Time", \
               "Session Init Time", "Tests Time"]
report_cols.extend(["Module Count", "Function Count", "Test Count", \
     "SysLog Count", "Pass Count", "Pass Rate", "Software Versions"])
report_cols.extend(sorted(results_map.keys()))
report_total_col = "====TOTAL===="

exec_phases=['always', 'onfail', "none", "onerror", "session", \
             "onfail-epilog", "module-always", "module-onfail", "module-onerror"]

mail_build = "UNKNOWN Build"
def set_mail_build(val):
    global mail_build
    mail_build = val

ftrace_files = {}
def ftrace_prefix(prefix, *args):
    if g_lock: g_lock.acquire()
    if prefix not in ftrace_files:
        [_, logs_path, _] = _get_logs_path()
        ftrace_files[prefix] = paths.get_file_path(prefix, "txt", logs_path)
        utils.write_file(ftrace_files[prefix], "")
    l_args = []
    for arg in args:
        l_args.append(str(arg))
    utils.write_file(ftrace_files[prefix], " ".join(l_args) + "\n", "a")
    if g_lock: g_lock.release()

def ftrace(*args):
    ftrace_prefix("ftrace", *args)

dtrace_dbg = False
def dtrace(*args):
    if not dtrace_dbg: return
    slave_id = batch.get_slave_id()
    wa = get_work_area()
    if wa: wa.log(args)
    elif not slave_id: print(args)
    else: ftrace(*args)

def _get_logs_path(master=False):
    user_root = env.get("SPYTEST_USER_ROOT", os.getcwd())
    logs_path = env.get("SPYTEST_LOGS_PATH", user_root)
    slave_id = batch.get_slave_id()
    if slave_id and not master:
        logs_path = os.path.join(logs_path, slave_id)
    if not os.path.isabs(logs_path):
        logs_path = os.path.join(user_root, logs_path)
    if not os.path.exists(logs_path):
        os.makedirs(logs_path)
    return [user_root, logs_path, slave_id]

def create_pid_file():
    [_, logs_path, _] = _get_logs_path()
    pid_file = paths.get_pid_log(logs_path)
    utils.write_file(pid_file, "{}".format(os.getpid()))

def build_module_logname(nodeid):
    if env.get("SPYTEST_REPEAT_MODULE_SUPPORT", "0") == "0":
        return paths.get_mlog_name(nodeid)
    try:
        cur_test = env.get("PYTEST_CURRENT_TEST", "").split(" ")[0]
        modid, _ = cur_test.split("::")
    except Exception:
        modid = nodeid
    return paths.get_mlog_name(modid)

def _get_module_ui(name, cfg=None):
    if not cfg:
        wa = get_work_area()
        if not wa: return ""
        cfg = wa.cfg

    # per-module UI type takes precedence over
    ui_type = cfg["ui_type"].strip().lower()
    if ui_type in ["click-fallback", "klish-fallback"]:
        fallback = True
        module_ui = tcmap.get_module_info(name).uitype if name else ""
        if not module_ui:
            ui_type = ui_type.replace("-fallback", "")
        else:
            ui_type = module_ui
    else:
        fallback = False

    return fallback,ui_type

def _get_module_random(name, cfg=None):
    if not cfg:
        wa = get_work_area()
        if not wa: return ""
        cfg = wa.cfg

    global_ro = cfg["random_order"]
    if global_ro != 3:
        return global_ro, global_ro
    ro_module = tcmap.get_module_info(name).random
    return global_ro, ro_module

class Context(object):

    def __init__(self, wa, cfg):
        self.wa = wa
        self.cfg = cfg
        self.tc_results = dict()
        self.all_tc_executed = 0
        self.shutting_down = False
        self.sent_first_progress = False
        self.file_prefix = None
        self.skip_tgen = cfg.skip_tgen
        self.topo_str = ""
        self.root_path = "ROOT_PATH: {}".format(root_path)
        self.version_msg = "VERSION: {}".format(get_git_ver())
        self.hostname = "HOSTNAME: {}".format(socket.gethostname())
        self.cmdline_args = env.get("SPYTEST_CMDLINE_ARGS", "")
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
            gwtestbed = env.get(gwtestbed)
            self.log.info("using testbed file {}".format(gwtestbed))
            if gwtestbed:
                cfg.testbed = gwtestbed
        self.execution_start_time = get_timenow()
        self.log.info("")
        self.log.info("Execution Start Time: {}".format(self.execution_start_time))
        self.log_verion_info()
        self.log.info("LOGS PATH: {}".format(self.logs_path))
        if os.path.exists(os.path.join(self.logs_path, "node_used")):
            self.cfg.load_image = "none"
            self.cfg.breakout_mode = "none"
            self.cfg.speed_mode = "none"
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

        self.topo_str = "Topology: {}".format(self._tb.get_topo())
        self.log.info(self.topo_str)

        # register for signal handlers
        if self.cfg.graceful_exit:
            self._handle_signals()

        # dump default arguments
        if not batch.is_slave():
            self.generate_defaults_report()
            self.generate_devfeat_report()

        # nothing to do in batch master
        if batch.is_master():
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

        # simulate node dead and excluded
        batch.simulate_deadnode(0)
        for dut in self.topo["duts"]:
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
        sysinfo_csv = paths.get_sysinfo_csv(self.logs_path)
        Result.write_report_csv(sysinfo_csv, [], ReportType.SYSINFO, is_batch=False)
        utils.delete_file(paths.get_stats_txt(self.logs_path))
        utils.delete_file(os.path.join(self.logs_path, "node_dead"))

    def log_verion_info(self):
        self.log.info(self.version_msg)
        self.log.info(self.hostname)
        self.log.info(self.root_path)
        self.log.info("Python: {}.{}.{}".format(sys.version_info.major,
                      sys.version_info.minor, sys.version_info.micro))
        self.log.info(self.cmdline_args)
        suite_args = env.get("SPYTEST_SUITE_ARGS", "")
        if suite_args:
            self.log.info("SUITE ARGS: {}".format(suite_args))
        if self.topo_str:
            self.log.info(self.topo_str)

    def generate_defaults_report(self):
        rows = []
        for name, value in cmdargs.get_default_all():
            rows.append([name, value])
        for name, value in env.get_default_all():
            rows.append([name, value])
        defaults_htm = paths.get_defaults_htm(self.logs_path)
        align = {col: True for col in ["Name", "Value"]}
        Result.write_report_html(defaults_htm, rows, ReportType.DEFAULTS, False, align=align)

    def generate_devfeat_report(self):
        rows = []
        for name, value in self.wa.feature.get_all():
            rows.append([name, value])
        devfeat_htm = paths.get_devfeat_htm(self.logs_path)
        align = {col: True for col in ["Name", "Value"]}
        Result.write_report_html(devfeat_htm, rows, ReportType.DEFAULTS, False, align=align)

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
        self.file_prefix = env.get("SPYTEST_FILE_PREFIX")
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
        lvl_name = env.get("SPYTEST_LOGS_LEVEL", "info").lower()
        if lvl_name == "debug":
            lvl = logging.DEBUG
        elif lvl_name == "warn":
            lvl = logging.WARN
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
        failures = tgapi.close_tgen()
        return False if failures and not self.skip_tgen else True

    def _tgen_init(self):
        failures = False
        for tgen_dict in self.topo["tgens"].values():
            if not tgapi.load_tgen(tgen_dict):
                failures = True
        return False if failures and not self.skip_tgen else True

    def _tgen_instrument(self, phase, data):
        tgapi.instrument_tgen(phase, data)

    def _connect(self):
        self.log.debug("\nconnect().....\n")
        funcs = [
            [self._tgen_init],
            [self.net.connect_all_devices, self.cfg.faster_init]
        ]
        self.log_time("device connections start")
        [[rv1, rv2], [e1, e2]] = putil.exec_all2(self.cfg.faster_init, "trace",
                                                 funcs, True)
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
        except Exception:
            pass

    def email(self, subject=None):
        filepath = os.path.join(self.logs_path, "build.txt")
        build_info = 'build:{0}\nuitype:{1}\nExecution Started:{2}\nExecution Completed:{3}'.format(mail_build,
                                self.cfg.ui_type, self.execution_start_time, get_timenow())
        utils.write_file(filepath, build_info)

        if not self.cfg.email_csv:
            return

        is_master, is_html, add_png = batch.is_master(), True, False

        # get the first DUT name to read the services info
        first_dut = None
        for dut in self._tb.get_device_names("DUT"):
            first_dut = dut
            break

        body = env.get("SPYTEST_EMAIL_BODY_PREFIX", "")
        body = body + textwrap.dedent("""\
        {3}VERSION : {0}
        {3}{1}
        {3}{2}
        """.format(get_git_ver(), self.hostname, self.cmdline_args,
                  "<p>" if is_html else ""))

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

        features_htm = paths.get_features_htm(self.logs_path, is_master)
        if os.path.exists(features_htm):
            lines = utils.read_lines(features_htm)
            body = body + "\n".join(lines)
            body = body + "\n<br>\n"

        # build mail body from report file
        reports_htm = paths.get_report_htm(self.logs_path, is_master)
        if os.path.exists(reports_htm):
            lines = utils.read_lines(reports_htm)
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
        if current_test.nodeid in must_fail_items:
            res = "Fail" if res in ["Pass"] else "Pass"
        retval = self.result.set(res, msgid, *args)
        self.log.info("========= Report({}): {} =========".format(res, retval))
        set_current_result(res, retval)
        return retval

    def publish2(self, nodeid, func, tcid, time_taken, comp=None,
                 result=None, desc=None, rtype="Executed"):
        if batch.is_infra_test(nodeid):
            return False
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
        #if func in selected_test_items:
            #if "TimeTaken" not in res:
                #res["TimeTaken"] = "0:00:00"
            #row = ["", res["Module"], func, res["Result"], res["TimeTaken"],
                   #res["ExecutedOn"], res["Description"]]
            #item = selected_test_items[func]
            #item.user_properties.append(row)
        if not self.slave_id:
            self.run_progress_report(self.all_tc_executed)
        return True

    def publish(self, nodeid, func, time_taken):
        if not self.publish2(nodeid, func, None, time_taken):
            return
        tclist = tcmap.get_tclist(func)
        if not tclist:
            self.publish2(nodeid, func, func, "0:00:00",
                          "==UNKNOWN==", None, None, "NotMapped")
        for tcid in tclist:
            if tcid not in self.tc_results:
                comp = tcmap.get_comp(tcid)
                self.publish2(nodeid, func, tcid, "0:00:00",
                              comp, None, None, "Mapped")
        for tcid in self.tc_results.keys():
            (res, desc) = self.tc_results[tcid]
            comp = tcmap.get_comp(tcid) or tcmap.get_comp(func)
            if not comp: continue
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
        self.cli_records = OrderedDict()
        self.modules_completed = []
        if env.get("SPYTEST_APPLY_BASE_CONFIG_AFTER_MODULE", "0") != "0":
            self.apply_base_config_after_module = True
        else:
            self.apply_base_config_after_module = False
        self.module_sysinfo = OrderedDict()
        self.dmaps = dict()
        self.app_vars = dict()
        self.cli_type_cache = OrderedDict()
        self.module_vars = dict()
        self._context = None
        self.file_prefix = None
        self.chat = None
        self.all_ports = OrderedDict()
        self.alt_port_names = OrderedDict()
        self.native_port_names = OrderedDict()
        self.connected_ports = OrderedDict()
        self.reserved_ports = OrderedDict()
        self.free_ports = OrderedDict()
        self.swver = OrderedDict()
        self.cfg = cfg
        self.hooks = apis_register()
        self.session_init_completed = False
        self.current_tc_start_time = None
        self.abort_module_msg = None
        self.abort_function_msg = None
        self.feature = Feature(self.cfg.device_feature_group)
        for fname in self.cfg.device_feature_enable:
            self.feature.set_supported(fname)
        for fname in self.cfg.device_feature_disable:
            self.feature.set_unsupported(fname)
        self._context = Context(self, cfg)
        self.net = self._context.net
        self.data_lock = threading.Lock()
        self.last_error = None

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

            [_, exps] = self._foreach(devlist, self.do_rps, "reset", recon=False)
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
        self.tgen_reconnect = False

    def __del__(self, name=None):
        if self._context:
            self._context._disconnect()
            self._context._tgen_close()

    def set_node_dead(self, dut):
        [_, logs_path, _] = _get_logs_path()
        file_path = os.path.join(logs_path, "node_dead")
        utils.write_file(file_path, " " + dut, "a")
        os._exit(15)

    def _foreach (self, items, func, *args, **kwargs):
        return putil.exec_foreach2(self.cfg.faster_init, "trace", items,
                                   func, *args, **kwargs)

    def _foreach_dev (self, func, *args, **kwargs):
        return self._foreach(self.get_dut_names(), func, *args, **kwargs)

    def is_dry_run(self):
        return self.cfg.filemode

    def _is_save_cli_types(self):
        return bool(env.get("SPYTEST_SAVE_CLI_TYPE", "1") != "0")

    def _is_save_cli_cmds(self):
        return bool(env.get("SPYTEST_SAVE_CLI_CMDS", "1") != "0")

    def is_vsonic(self, dut=None):
        if not dut: dut = self.get_dut_names()[0]
        return self.get_dut_var(dut, "is_vsonic", False)

    def is_soft_tgen(self):
        return tgapi.is_soft_tgen()

    def is_valid_base_config(self):
        return bool(self.cfg.skip_load_config not in ["base"])

    def get_logs_path(self, for_file=None):
        [_, logs_path, _] = _get_logs_path()
        if for_file:
            file_path = "{0}_{1}".format(self.file_prefix, for_file)
            return os.path.join(logs_path, file_path)
        return logs_path

    def profiling_start(self, msg, max_time):
        return self.net.profiling_start(msg, max_time)

    def profiling_stop(self, pid):
        return self.net.profiling_stop(pid)

    def _no_print(self, msg):
        pass

    def banner(self, msg, width=80, delimiter="#", wrap=True, tnl=True, lnl=True, dut=None):
        content = utils.banner(msg, width, delimiter, wrap, self._no_print, tnl, lnl)
        self.log(content, dut=dut, split_lines=True)

    def debug(self, msg, dut=None, split_lines=False):
        self._context.log.debug(msg, dut, split_lines)

    def event(self, *args):
        msg = ""
        for arg in args:
            msg = msg + " " + str(arg)
            msg = msg.strip()
        self.log("\n================== {} ==================".format(msg))

    def log_time(self, name):
        #self._context.log.debug(name)
        self._context.log_time(name)

    def log(self, msg, dut=None, split_lines=False, dst=None):
        if dut: self.net.dut_log(dut, msg, logging.INFO, True, dst)
        else: self._context.log.info(msg, dut, split_lines, dst=dst)

    def exception(self, msg, dut=None, split_lines=True):
        self._context.log.exception(msg, dut, split_lines)

    def warn(self, msg, dut=None, split_lines=False, dst=None):
        if dut: self.net.dut_log(dut, msg, logging.WARNING, True, dst)
        else: self._context.log.warning(msg, dut, split_lines)

    def error(self, msg, dut=None, split_lines=False, dst=None):
        if dut: self.net.dut_log(dut, msg, logging.ERROR, True, dst)
        else: self._context.log.error(msg, dut, split_lines)

    def dut_log(self, dut, msg, lvl=logging.INFO, cond=True, dst=["all", "dut"]):
        self.net.dut_log(dut, msg, lvl, cond, dst)

    def alert(self, msg, type="", lvl=logging.ERROR):
        slave_id = batch.get_slave_id() or ""
        m = "#### {} {} {}".format(slave_id, type, get_current_nodeid())
        list2 = utils.make_list(m, msg)
        self._context.log.alert(list2, lvl=lvl)
        for this_msg in utils.make_list(msg):
            self.error(this_msg)
            if self.chat: self.chat.send(this_msg)
            for dut in self.get_dut_names():
                self.dut_log(dut, this_msg, logging.ERROR, dst=["dut"])

    def wait(self, val, msg=None):
        if msg:
            self.log("Sleep for {} sec(s)...{}".format(val, msg))
        else:
            self.log("Sleep for {} sec(s)...".format(val))
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

    def report_tc_pass(self, tcid, msgid, *args):
        self._context.report_tc(tcid, "Pass", msgid, *args)

    def onfail_debug_dump(self):
        if env.get("SPYTEST_ONFAIL_TGEN_STATS", "0") != "0":
            self.tgen_debug_show()

    def report_tc_fail(self, tcid, msgid, *args):
        self.onfail_debug_dump()
        self._context.report_tc(tcid, "Fail", msgid, *args)

    def report_tc_unsupported(self, tcid, msgid, *args):
        self._context.report_tc(tcid, "Unsupported", msgid, *args)

    def report_msg(self, msgid, *args):
        msg, _ = self._context.result.msg(msgid, *args)
        line = utils.get_line_number(2)
        self._context.log.info("RMSG: {} @line {}".format(msg, line))
        return msg

    def report_pass(self, msgid, *args):
        """
        Infrastructure API used by test scripts to report pass
        :param msgid: message identifier from /messages/*.yaml files
        :param args: arguments required in message identifier specification
        :return:
        """
        self.last_error = None
        self._context.report("Pass", msgid, *args)

    def report_pdb(self):
        if self.cfg.pdb_on_error:
            pdb.set_trace()
            HELP = " NOTE: execute 'up' command thrice to go to the failure line ==== "
            utils.unused(HELP)

    def report_env_fail2(self, msgid, *args):
        self.last_error = "EnvFail"
        self._context.report(self.last_error, msgid, *args)
        self.report_pdb()

    def report_env_fail(self, msgid, *args):
        self.last_error = "EnvFail"
        desc = self._context.report(self.last_error, msgid, *args)
        self.report_pdb()
        pytest.skip(desc)

    def report_timeout(self, msgid, *args):
        self.last_error = "Timeout"
        desc = self._context.report(self.last_error, msgid, *args)
        self.report_pdb()
        pytest.skip(desc)

    def report_topo_fail(self, msgid, *args):
        self.last_error = "TopoFail"
        desc = self._context.report(self.last_error, msgid, *args)
        self.report_pdb()
        pytest.skip(desc)

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
            desc = self._context.report(self.last_error, "tgen_exception", "{}".format(ex))
            self.report_pdb()
            pytest.skip(desc)

    def report_tgen_fail(self, msgid, *args):
        self.last_error = "TGenFail"
        desc = self._context.report(self.last_error, msgid, *args)
        self.report_pdb()
        pytest.skip(desc)

    def report_tgen_abort(self, msgid, *args):
        self.last_error = "TGenFail"
        desc = self._context.report(self.last_error, msgid, *args)
        self.report_pdb()
        self.abort_module_msg = "TGen connection aborted"
        self.tgen_reconnect = True
        pytest.skip(desc)

    def report_fail(self, msgid, *args):
        self.last_error = "Fail"
        msg = self._context.report(self.last_error, msgid, *args)
        self.report_pdb()
        self.onfail_debug_dump()
        pytest.xfail(msg)

    def report_dut_fail(self, msgid, *args):
        self.last_error = "DUTFail"
        msg = self._context.report(self.last_error, msgid, *args)
        self.report_pdb()
        self.onfail_debug_dump()
        pytest.xfail(msg)

    def report_unsupported(self, msgid, *args):
        self.last_error = "Unsupported"
        msg = self._context.report(self.last_error, msgid, *args)
        self.report_pdb()
        pytest.xfail(msg)

    def report_scripterror(self, msgid, *args):
        self.last_error = "ScriptError"
        msg = self._context.report(self.last_error, msgid, *args)
        self.report_pdb()
        pytest.xfail(msg)

    def report_config_fail(self, msgid, *args):
        self.last_error = "ConfigFail"
        msg = self._context.report(self.last_error, msgid, *args)
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
        return self.net.apply_script(dut, cmdlist)

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
        return self.net.apply_json(dut, json)

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
        return self.net.apply_json2(dut, json)

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
        return self.net.apply_files(dut, file_list, method)

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
        return self.net.run_script(dut, timeout, script_path, *args)

    def enable_disable_console_debug_msgs(self, dut, flag):
        """
        todo: Update Documentation
        :param dut:
        :type dut:
        :return:
        :rtype:
        """
        return self.net.enable_disable_console_debug_msgs(dut, flag)

    def clear_config(self, dut):
        """
        todo: Update Documentation
        :param dut:
        :type dut:
        :return:
        :rtype:
        """
        retval_1 = self.net.clear_config(dut)

        # wait for system ready
        retval_2 = self.wait_system_status(dut)

        if retval_1 and retval_2:
            return True
        return False

    def config_db_reload(self, dut, save=False, max_time=0):
        """
        todo: Update Documentation
        :param dut:
        :type dut:
        :param save:
        :type save:
        :return:
        :rtype:
        """
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
        return load_image

    def get_cfg_ifname_type(self, dut):
        if self.cfg.ifname_type == "testbed":
            ifname_type = self.get_device_param(dut, "ifname_type", "native")
        else:
            ifname_type = self.cfg.ifname_type
        if not self.is_feature_supported("intf-alias", dut):
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
        load_image = self.get_cfg_load_image(dut)
        if load_image == "onie1":
            upgrd_retval = self.net.upgrade_onie_image1(dut, url,max_ready_wait=max_ready_wait)
        elif load_image == "onie":
            upgrd_retval = self.net.upgrade_onie_image2(dut, url,max_ready_wait=max_ready_wait)
        elif load_image == "installer-without-migration":
            upgrd_retval = self.net.upgrade_image(dut, url, skip_reboot, False,max_ready_wait=max_ready_wait)
        else:
            upgrd_retval = self.net.upgrade_image(dut, url, skip_reboot,max_ready_wait=max_ready_wait)
        if port_break or port_speed:
            pb_retval = self.set_port_defaults(dut, port_break, port_speed)

        # read app vars again
        self._read_vars(dut)

        return bool(upgrd_retval and (pb_retval or port_speed))

    def upgrade_libsai(self, dut):
        if self.cfg.libsai_url:
            self.hooks.upgrade_libsai(dut, self.cfg.libsai_url)
            self._read_vars(dut)
        return True

    def _read_vars(self, dut):
        self.dmaps[dut] = dict()
        self.app_vars[dut] = self.hooks.get_vars(dut)

    def reboot(self, dut, method="normal", skip_port_wait=False,
               skip_exception=False, skip_fallback=False, ret_logs=False):

        if dut is None:
            self.log("reboot all {}".format(self.cfg.faster_init))
            self._foreach_dev(self.net.reboot, method=method, skip_port_wait=skip_port_wait,
                              skip_exception=skip_exception, skip_fallback=skip_fallback,
                              ret_logs=ret_logs, internal=False)
        elif isinstance(dut, list):
            self.log("reboot: {}".format(",".join(dut)))
            self._foreach(dut, self.net.reboot, method=method, skip_port_wait=skip_port_wait,
                          skip_exception=skip_exception, skip_fallback=skip_fallback,
                          ret_logs=ret_logs, internal=False)
        else:
            output = self.net.reboot(dut, method=method, skip_port_wait=skip_port_wait,
                            skip_exception=skip_exception, skip_fallback=skip_fallback,
                            ret_logs=ret_logs, internal=False)
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

    def _wait_for_ports(self, dut, max_time=0):
        if dut in self.all_ports:
            last_port = self.all_ports[dut][-1]
            t = time.time() + max_time
            self.dut_log(dut, "wait for last port {} creation".format(last_port))
            while 1:
                status = self.hooks.get_interface_status(dut, last_port)
                if status is not None:
                    return True
                time.sleep(3)
                if time.time() > t:
                    break
            return False
        return self.net._apply_remote(dut, "wait-for-ports", [max_time])

    def wait_system_status(self, dut, max_time=0):
        if self.cfg.pde: return True

        max_time = max_time or self.cfg.port_init_wait
        if not self.is_feature_supported("system-status", dut):
            return self._wait_for_ports(dut, max_time)

        line = currentframe().f_back.f_lineno
        t = time.time() + max_time
        msg = "system is not online - waited for {} sec Ref: {}".format(max_time, line)
        while not self.cfg.pde:
            rv = self.hooks.get_system_status(dut, skip_error_check=True)
            if rv or self.cfg.filemode: return True
            if rv is None:
                # run with system-status feature when device build has not support for it
                return self._wait_for_ports(dut)
            time.sleep(3)
            if time.time() > t:
                break
        self.dut_log(dut, msg, logging.WARNING)
        return False

    def is_tech_support_onerror(self, which):
        default = "system,port_list,port_status,console_hang"
        support = env.get("SPYTEST_TECH_SUPPORT_ONERROR", default)
        return bool(which in support.split(","))

    def _ensure_system_ready(self, dut, name):

        if self.wait_system_status(dut):
            return self.net.show_dut_time(dut)

        # recover the system by config reload
        # this is not working as getting messages while saving
        #msg = "Trying to recover the DUT with save and reload"
        #self.dut_log(dut, msg, logging.WARNING)
        #if self.config_db_reload(dut):
            #return

        # system not ready - collect debug information
        self.hooks.debug_system_status(dut)

        # system not ready - aborting current module
        self.abort_module_msg = " show system status is not ready in time."
        msg = self.abort_module_msg + " Trying to recover the DUT with reboot."
        self.dut_log(dut, msg, logging.WARNING)

        # bailing out - collect the tech-support
        if self.is_tech_support_onerror("system"):
            self.net.generate_tech_support(dut, name)

        # recover the system by reboot - for next module
        rv = self.net.reboot(dut, "fast", skip_exception=True)
        if rv:
            msg = "Successfully rebooted the DUT to recover."
            msg = msg + " Final verification if show system status also ready."
            self.dut_log(dut, msg, logging.WARNING)
            rv = self.wait_system_status(dut, 10)
        if rv:
            if self.session_init_completed:
                msg = "show system status is ready after recovery."
                msg = msg + " abort current module and continue with next module"
                self.dut_log(dut, msg, logging.WARNING)
                self.report_dut_fail("show_system_status_not_ready")
            return self.net.show_dut_time(dut)

        # failed to recover devices - bailout the run
        msg = "show systemn status is not ready even after recovery - bailout run"
        self.dut_log(dut, msg, logging.ERROR)
        os._exit(6)

    def _fill_hooks_data(self, dut):
        self._read_vars(dut)
        self.swver[dut] = self.app_vars[dut]["version"]
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
            self.net._apply_remote(dut, "update-reserved-ports", [ports])

    def _save_base_config_dut(self, dut):

        # noshut connected ports so that they get saved as up in config
        self._noshutdown_connected(dut)

        # shut reserved ports so that they get saved as down in config
        self._shutdown_reserved_and_free(dut)

        if not self.cfg.skip_init_config:
            # save the configuration as TA default configuration
            self.net._apply_remote(dut, "save-base-config")

    def _apply_config_profile_dut(self, dut):
        # Apply the profile configuration
        profile_name = self._context._tb.get_config_profile()
        if self.cfg.config_profile:
            profile_name = self.cfg.config_profile
        largs_list = [profile_name]
        self.net._apply_remote(dut, "config-profile", largs_list)
        max_time = 240
        apply_args = [max_time]

        apply_args.append(True)
        self._context.net._apply_remote(dut, "wait-for-ports", apply_args)

    def _load_image_dut(self, dut, scope):
        build = self.get_build(dut, scope)
        if self.cfg.build_url != None and self.cfg.build_url.strip() == "":
            msg = "Given build url is not valid..."
            self.dut_log(dut, msg, logging.ERROR)
            raise ValueError(msg)
        if self.cfg.build_url and scope == "current":
            build = self.cfg.build_url
        if build:
            if self.get_cfg_breakout_mode(dut) != "none" or self.cfg.speed_mode != "none":
                if env.get("SPYTEST_SYSTEM_READY_AFTER_PORT_SETTINGS", "0") == "1":
                    self.upgrade_image(dut, build, False, False, False, 1)
                else:
                    self.upgrade_image(dut, build, False, False, False, 0)
            else:
                self.upgrade_image(dut, build, False, False, False, 0)
            return self.upgrade_libsai(dut)
        msg = "testbed file does not contain {} build".format(scope)
        self.dut_log(dut, msg, logging.DEBUG)
        return False

    def _load_testbed_config_dut(self, dut, scope):
        if self.cfg.pde: return
        if self.cfg.skip_init_config: return

        # apply configs as given in template
        files = self.get_config(dut, scope)
        if not files:
            msg = "testbed file does not contain {} specific configs section".format(scope)
            self.dut_log(dut, msg, logging.DEBUG)
            files = []

        # apply all the config groups given in the template for current scope
        self._apply_config_file_list(dut, files)

    def has_get_tech_support(self, *args):
        runopt = utils.make_list2(self.cfg.get_tech_support)
        for m in args:
            if m in runopt: return True
        return False

    def has_fetch_core_files(self, *args):
        runopt = utils.make_list2(self.cfg.fetch_core_files)
        for m in args:
            if m in runopt: return True
        return False

    def _create_init_config_db(self, dut):
        any_fetch_core_files = bool(self.cfg.fetch_core_files != "none")
        any_get_tech_support = bool(self.cfg.get_tech_support != "none")
        self.net._init_clean(dut, any_fetch_core_files, any_get_tech_support, True)

        if self.cfg.skip_init_config and not self.cfg.config_profile: return
        if self.cfg.pde: return

        profile_name = self._context._tb.get_config_profile()
        if self.cfg.config_profile:
            profile_name = self.cfg.config_profile

        # create init config file
        largs_list = [any_fetch_core_files, any_get_tech_support, \
                      self.cfg.clear_tech_support, True, profile_name]
        self.net._apply_remote(dut, "init-ta-config", largs_list)

        # apply the init config file
        self.net._apply_remote(dut, "apply-init-config")

    def _filemode_ports(self, count=200, prefix="Ethernet"):
        retval = []
        for port in range(0,count):
            retval.append("{}{}".format(prefix, port))
        return retval

    def _get_physical_ifname_map(self, dut):
        if self.cfg.filemode:
            all_ports = self._filemode_ports()
            alias_ports = self._filemode_ports(prefix="Eth1/")
        else:
            d = self.hooks.get_physical_ifname_map(dut)
            all_ports, alias_ports = [d.keys(), d.values()]
        alt_port_names = OrderedDict()
        native_port_names = OrderedDict()
        for alias, native in zip(alias_ports, all_ports):
            alt_port_names[native] = alias
            native_port_names[alias] = native
        return [all_ports, alt_port_names, native_port_names]

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
        for port in port_list:
            retval.append(self.get_other_name(dut, port))
        return retval

    def _config_ifname_type(self, dut, ifname_type=None):
        if self.cfg.ifname_type in ["none"]:
            return # support is not enabled
        ifname_type = ifname_type or self.get_cfg_ifname_type(dut)
        if ifname_type not in ["none"]:
            self.hooks.config_ifname_type(dut, ifname_type)

    def _build_port_list(self, dut, retry):

        alias = self.get_device_alias(dut)
        errs = []
        self.all_ports[dut] = []
        self.free_ports[dut] = []

        [all_ports, alt_port_names, native_port_names] = self._get_physical_ifname_map(dut)
        self.alt_port_names[dut] = alt_port_names
        self.native_port_names[dut] = native_port_names
        self.connected_ports[dut] = self._get_device_links_local(dut, native=True)
        self.reserved_ports[dut] = self._context._tb.get_rerved_links(dut)

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
                        self.free_ports[dut].append(port)
        else:
            errs.append(err_msg)

        if errs and retry > 0:
            retry = retry - 1
            msg = "{} - retry {}".format(err_msg, retry)
            self.dut_log(dut, msg, logging.WARNING)
            errs = self._build_port_list(dut, retry)

        return errs

    def _apply_base_config_dut(self, dut):
        if self.cfg.skip_load_config in ["base"]:
            return False
        apis_instrument("apply-base-config-dut-start", dut)
        self.net._apply_remote(dut, "apply-base-config")
        apis_instrument("apply-base-config-dut-end", dut)
        return True

    def _session_breakout_speed(self, dut):
        if self.get_cfg_breakout_mode(dut) != "none":
            if self.get_cfg_load_image(dut) not in ["onie", "onie1"]:
                self.dut_log(dut, "save configuration as TA configuration - 1")
                self._save_base_config_dut(dut)
                # DPB does not work when there is some configuration,
                # which is the case when we skip load image
                self._apply_base_config_dut(dut)

            # load any breakout specific configuration specified
            self._load_testbed_config_dut(dut, "breakout")

        # configure breakout and speed
        self.set_port_defaults(dut)

    # the sequence is init, transfer and save
    # init triggers init-ta-config
    # transfer triggers apply-files
    # save triggers save-base-config
    # Note: init and transfer can't be compibed because
    # we support config.cmds which need to be executed from framework
    def _session_init_dut(self, dut):

        if not self.net or not self.net.is_sonic_device(dut):
            return

        # Load Image
        if self.get_cfg_load_image(dut) == "none":
            msg = "SKIP loading {} image".format("current")
            self.dut_log(dut, msg, logging.WARNING)
            apply_port_defaults = True
        else:
            apply_port_defaults = self._load_image_dut(dut, "current")

        # create TA default configuration
        apis_instrument("init-config-start", dut)
        self.hooks.init_base_config(dut)
        apis_instrument("init-config-end", dut)

        # Apply Profile
        hwsku = self.get_device_param(dut, "hwsku", None)
        if hwsku: self.hooks.set_hwsku(dut, hwsku)
        self._apply_config_profile_dut(dut)

        # load user configuration
        if env.get("SPYTEST_APPLY_CONFIG_BEFORE_BREAKOUT", "0") != "0":
            self._load_testbed_config_dut(dut, "current")

        # port speed and breakout
        if apply_port_defaults:
            self._session_breakout_speed(dut)

        # load user configuration
        if env.get("SPYTEST_APPLY_CONFIG_BEFORE_BREAKOUT", "0") == "0":
            self._load_testbed_config_dut(dut, "current")

        # save configuration as TA configuration
        self.dut_log(dut, "save configuration as TA configuration - 2")
        self._save_base_config_dut(dut)

        # configure ASAN
        asan_config = bool("config" in env.get("SPYTEST_ASAN_OPTIONS", ""))
        if asan_config:
            self.net._apply_remote(dut, "asan-config")
            self.net.reboot(dut, "fast", skip_exception=True)

    def _session_build_ports_dut(self, dut, no_recovery=True):
        errs = []
        self._read_vars(dut)

        if 'rp' in self.app_vars[dut]['hwsku'].lower():
            print('interfacce validation skipping on RP')

        # read the port list
        elif not self.cfg.pde:
            errs.extend(self._build_port_list(dut, 3))

        # check if there are any issues reported if not all is well
        if not errs:
            self._fill_hooks_data(dut)
            self._save_base_config_dut(dut)
            return True

        # generate tech-support on breakout issues
        if self.is_tech_support_onerror("port_list"):
            self.generate_tech_support(dut, "breakout")

        # bail out on testbed issues
        if self.all_ports[dut]:
            self._trace_errors(dut, "invalid ports in testbed file", errs)
            return False

        # nothing to do if we are not recovering
        if no_recovery:
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
        if not self._session_build_ports_dut(dut, True):
            msg = "ports are not ready even after recovery - bailout run"
            self.dut_log(dut, msg, logging.ERROR)
            return False

        # all is well atleast now
        msg = "Successfully verified testbed ports after recovery"
        self.dut_log(dut, msg, logging.INFO)
        return True

    def _trace_errors(self, dut, msg, errs):
        if msg:
            self.dut_log(dut, msg, lvl=logging.ERROR)
        for err in errs:
            self.dut_log(dut, err, lvl=logging.ERROR)
        return False

    def _trace_exceptions(self, dut_list, msg, exceptions):
        dut_list = dut_list or self.get_dut_names()
        errs = []
        for dut_index, ex in enumerate(exceptions):
            if not ex: continue
            self.dut_log(dut_list[dut_index], str(ex), logging.ERROR)
            errs.extend(ex)
        if errs:
            self.error(msg)
        return errs

    def _session_mgmt_vrf_init(self):
        if self.cfg.mgmt_vrf:
            [_, exceptions] = self._foreach_dev(self.hooks.set_mgmt_vrf, self.cfg.mgmt_vrf)
            if self._trace_exceptions(None, "exception setting interface alias mode to native", exceptions):
                os._exit(6)

    def _session_ifname_type_set(self, ifname_type=None):
        [_, exceptions] = self._foreach_dev(self._config_ifname_type, ifname_type)
        ifname_type_msg = "configured" if not ifname_type else ifname_type
        msg = "exception setting interface alias mode to {}".format(ifname_type_msg)
        if self._trace_exceptions(None, msg, exceptions):
            os._exit(6)

    def _session_init(self):
        self.log_time("session init start")
        apis_instrument("session-init-start", None)

        # init software versions, data maps etc
        for dut in self.get_dut_names():
            self.swver[dut] = ""
            self.dmaps[dut] = dict()

        # Enable or disable managemenr vrf
        self._session_mgmt_vrf_init()

        # set interface alias mode to native
        self._session_ifname_type_set("native")

        # load current image, config and perform
        [retvals, exceptions] = self._foreach_dev(self._session_init_dut)
        if self._trace_exceptions(None, "exception loading image or init config", exceptions):
            os._exit(6)

        # identify invalid port names given in testbed file
        self.log("building port list and save base config")
        no_recovery = bool(env.get("SPYTEST_RECOVER_INITIAL_SYSTEM_NOT_READY", "0") == "1")
        [retvals, exceptions] = self._foreach_dev(self._session_build_ports_dut, no_recovery)
        if self._trace_exceptions(None, "exception saving base config", exceptions):
            os._exit(6)

        # bail out if there are erros detected in topology
        if not all(retvals):
            for dut, retval in zip(self.get_dut_names(), retvals):
                if retval: continue
                msg = "invalid ports in topology - please check testbed file"
                self.dut_log(dut, msg, lvl=logging.ERROR)
            if not self.cfg.filemode: os._exit(6)

        # get application vars
        self._module_init_cli_cache()
        for dut in self.get_dut_names():
            self.module_vars[dut] = dict()
            self._read_vars(dut)

        # bail out if there is any difference in software version
        version_check = env.get("SPYTEST_ABORT_ON_VERSION_MISMATCH", "2")
        if version_check != "0":
            dut_list = self.get_dut_names()
            if version_check == "1":
                if len(dut_list) > 1:
                    version_dut_map = dict()
                    for dut in dut_list:
                        tmp_version = self.swver[dut]
                        if tmp_version not in version_dut_map:
                            version_dut_map[tmp_version] = [dut]
                        else:
                            version_dut_map[tmp_version].append(dut)
                    if len(version_dut_map.keys()) > 1:
                        for dut in dut_list:
                            self.dut_log(dut, "Software Version Mismatch identified...", logging.ERROR)
                            for tmp_version in version_dut_map.keys():
                                msg = "DUT's with Software Version '{}': '{}'."
                                msg = msg.format(tmp_version, ",".join(version_dut_map[tmp_version]))
                                self.dut_log(dut, msg, logging.ERROR)
                        os._exit(6)
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
                        os._exit(6)

        # perform topology check
        if self.is_topology_check(["report", "abort"]):
            [retval, header, rows, seen_exp, _] = self.hooks.verify_topology("report")
            topo_status = utils.sprint_vtable(header, rows)
            if not retval or seen_exp:
                self.error("Topology verification failed")
                self.error(topo_status, split_lines=True)
                if self.is_topology_check(["abort"]):
                    os._exit(7)
            else:
                self.log("Topology verification successful")
                self.log(topo_status, split_lines=True)
        elif self.is_topology_check(["module", "function"]):
            #no need if we are doing same in module/function
            pass
        else:
            self.warn("SKIP Topology verification")

        # Enable or disable managemenr vrf
        self._session_mgmt_vrf_init()

        # set interface alias mode to configured
        self._session_ifname_type_set(None)

        # extend base config
        self._foreach_dev(self.hooks.extend_base_config)

        # save the current running configuration as TA default configuration
        if not self.cfg.skip_init_config:
            [retvals, exceptions] = self._foreach_dev(self.net._apply_remote, "rewrite-ta-config")
            if self._trace_exceptions(None, "exception rewriting running configuration to default ta configuration", exceptions):
                os._exit(6)

        # save the TA default configuration as base configuration
        if not self.cfg.skip_init_config:
            [retvals, exceptions] = self._foreach_dev(self.net._apply_remote, "save-base-config")
            if self._trace_exceptions(None, "exception saving base configuration", exceptions):
                os._exit(6)

        # apply base configuration for first module
        if self.apply_base_config_after_module:
            self._module_apply_base_config(None)

        # flag to run module init
        self.base_config_verified = True
        self._context.session_init_time_taken = get_elapsed(self._context.session_start_time, True)
        self._context.total_tc_start_time = get_timenow()

        if batch.is_member():
            self._report_file_generation()

        apis_instrument("session-init-end", None)
        self.log_time("session init end")

    def _session_clean_dut(self, dut):

        if not self.net or not self.net.is_sonic_device(dut):
            return

        # fetch session tech support
        if self.has_get_tech_support("session"):
            self.net.generate_tech_support(dut, "session")

        # fetch session core files
        if self.has_fetch_core_files("session"):
            self.net._apply_remote(dut, "fetch-core-files", ["session"])

        # perform unbreakout if specified in testbed file
        self.set_port_defaults(dut, section="unbreakout", speed=False)

        # Load Image
        if self.get_cfg_load_image(dut) == "none":
            msg = "SKIP loading {} image".format("restore")
            self.dut_log(dut, msg, logging.WARNING)
            apply_port_defaults = False
        else:
            apply_port_defaults = self._load_image_dut(dut, "restore")

        # load user configuration
        if env.get("SPYTEST_APPLY_CONFIG_BEFORE_BREAKOUT", "0") != "0":
            self._load_testbed_config_dut(dut, "restore")

        # port speed and breakout
        if apply_port_defaults:
            self._session_breakout_speed(dut)

        # load user configuration
        if env.get("SPYTEST_APPLY_CONFIG_BEFORE_BREAKOUT", "0") == "0":
            self._load_testbed_config_dut(dut, "restore")

        self._apply_base_config_dut(dut)

    def _session_clean(self):
        self.log_time("session clean start")
        apis_instrument("session-clean-start", None)

        if batch.is_member():
            data = self._report_file_generation()

        if self.cfg.tgen_module_init:
            funcs = [
                [self._module_init_tgen],
                [self._foreach_dev, self._session_clean_dut]
            ]
            putil.exec_all2(self.cfg.faster_init, "trace", funcs, True)
        else:
            self._foreach_dev(self._session_clean_dut)

        apis_instrument("session-clean-end", None)
        if self.net:
            self.net.session_close()
        if batch.is_member():
            self.log("=================== Final Report =========================")
            self.log(data, split_lines=True)
            self._log_software_versions()
            rlist = selected_test_results.values()
            from collections import Counter
            self.log("============ Results : {}".format(list(Counter(rlist).items())))
            self.log("==========================================================")
        self.log_time("session clean end")

    def _log_software_versions(self, dst=["all"]):
        self.log(" ================== Software Versions ====================", dst=dst)
        ver_dut_map = utils.invert_dict(self.swver)
        for swver, dut in ver_dut_map.items():
            self.log(" ============ {} = {}".format(dut, swver), dst=dst)
        self.log("==========================================================", dst=dst)

    def _module_init_dut(self, dut, filepath):
        self.clear_module_vars(dut)
        self._module_apply_base_config_dut(dut, filepath)

    def _module_apply_base_config_dut(self, dut, filepath):
        if not self._apply_base_config_dut(dut):
            msg = "SKIP appying base configuration"
            self.dut_log(dut, msg, logging.WARNING)

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
            if not self._context._tgen_init():
                self.error("Failed to reconnect to tgen")
                os._exit(6)
            self.warn("Reconnected to TGen")
            self.tgen_reconnect = False

        self.log("applying base configuration: {}".format(self.abort_module_msg))
        self.last_error = None
        fail_msg = "Failed to module init one or more devices in topology"
        if self.cfg.tgen_module_init:
            funcs = [
                [self._module_init_tgen],
                [self._foreach_dev, self._module_init_dut, filepath]
            ]
            [[_, _], [e1, e2]] = putil.exec_all2(self.cfg.faster_init, "trace",
                                                 funcs, True)
            if e2 is not None:
                self.error(fail_msg)
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

        # abort the module if not able to apply base config
        if self.last_error:
            self.last_error = None # reset last error
            self.abort_module_msg = fail_msg
            self.log("failed to apply base configuration: {}".format(self.abort_module_msg))
        else:
            self.log("successfully to apply base configuration: {}".format(self.abort_module_msg))

    def _module_init_cli_cache(self):
        self.module_sysinfo.clear()
        self.cli_records.clear()
        self.cli_type_cache.clear()
        for dut in self.get_dut_names():
            self.module_sysinfo[dut] = {}
            self.cli_records[dut] = []
            self.cli_type_cache[dut] = OrderedDict()

    def _module_init_tgen(self):
        tgapi.module_init()

    def _module_init(self, nodeid, filepath):
        self.log_time("module {} init start".format(filepath))
        apis_instrument("module-init-start", filepath)

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

        # ajdust Module MAX Timeout using data from tcmap
        if self.cfg.module_max_timeout > 0:
            module_max_timeout = tcmap.get_module_info(filepath).maxtime
        else:
            module_max_timeout = 0
        if module_max_timeout > 0 and module_max_timeout > self.cfg.module_max_timeout:
            self.net.module_init_start(module_max_timeout, fcli, tryssh)
        else:
            self.net.module_init_start(self.cfg.module_max_timeout, fcli, tryssh)

        if not self.base_config_verified:
            self.warn("base config verification already failed - no need to run any modules")
            self.module_config_verified = False
            return "SKIP"

        self._context.result.clear()
        self._module_init_cli_cache()

        self.min_topo_called = False
        self.module_tc_executed = 0
        self.module_tc_fails = 0
        self.module_get_tech_support = False
        self.module_fetch_core_files = False
        self.current_module_verifier = "NA"
        self.abort_module_msg = None

        # simulate node dead
        batch.simulate_deadnode(1)

        # apply base configuration
        if not self.apply_base_config_after_module:
            self._module_apply_base_config(filepath)
        elif not batch.is_infra_test(filepath):
            self._pre_module_init(filepath)

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
            self.module_config_verified = False
            return "SKIP"

        # verify base configuration
        if self.cfg.skip_load_config not in ["base"] and \
           self.cfg.skip_verify_config not in ["base", "both"]:
            verifier = self._context._tb.get_verifier()
            self.log("base config verification - {}".format(verifier))
            verifiers = self.hooks.get_verifiers()
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

        apis_instrument("module-init-end", filepath)
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

    def _do_memory_checks_dut(self, dut, phase, name):
        metrics = self.net.do_memory_checks(dut, phase, name)
        self.module_sysinfo[dut][phase] = metrics
        self.dut_log(dut, "sysinfo: {}".format(self.module_sysinfo[dut]))

    def _do_memory_checks(self, phase, name):
        for dut in self.get_dut_names():
            if dut not in self.module_sysinfo:
                self.module_sysinfo[dut] = {}
        if self.cfg.memory_check not in ["none"]:
            self._foreach_dev(self._do_memory_checks_dut, phase, name)
            self.log("sysinfo: {}".format(self.module_sysinfo))

    def _do_syslog_checks(self, phase, name):
        if self.cfg.syslog_check not in ["none"]:
            self._foreach_dev(self.net.do_syslog_checks, phase, name)

    def _create_module_logs(self, phase, name):
        self._do_memory_checks(phase, name)
        self._do_syslog_checks(phase, name)
        self.save_sairedis(phase, name)
        self._context._tgen_instrument(phase, name)

    def _pre_module_prolog(self, name):
        self._create_module_logs("pre-module-prolog", name)

    def _apis_instrument_dut(self, dut, name):
        apis_instrument(name, dut)

    def _post_module_prolog(self, name, success_status):

        # fetch debug info when module config failed
        if not success_status:
            if self.has_get_tech_support("onfail", "onfail-epilog"):
                self._foreach_dev(self.net.generate_tech_support, name)
            if self.has_fetch_core_files("onfail", "onfail-epilog"):
                self._foreach_dev(self.net._apply_remote, "fetch-core-files", [name])

        self._create_module_logs("post-module-prolog", name)

        if success_status and self.cfg.skip_load_config not in ["base"]:
            self._foreach_dev(self._save_module_config)

        self._foreach_dev(self._apis_instrument_dut, "post-module-prolog")

    def _post_module_epilog(self, name, success_status):
        #if self.abort_module_msg: return
        self._create_module_logs("post-module-epilog", name)

    def _pre_module_init(self, name):
        if not self.abort_module_msg:
            self._create_module_logs("pre-module", name)

    def _post_module_cleanup(self, name):
        if not self.abort_module_msg:
            self._create_module_logs("post-module", name)

    def _pre_function_prolog(self, name):
        pass

    def _post_function_prolog(self, name):
        pass

    def _pre_function_epilog(self, name):
        (res, _) = self._context.result.get()
        if res.lower() not in ["fail", "xfail", "dutfail"]:
            return
        if self.has_get_tech_support("onfail-epilog"):
            self._foreach_dev(self.net.generate_tech_support, name)
        if self.has_fetch_core_files("onfail-epilog"):
            self._foreach_dev(self.net._apply_remote, "fetch-core-files", [name])

    def _post_function_epilog(self, name):
        pass

    def _post_class_prolog(self, name, success_status):

        # fetch debug info when class config failed
        if not success_status:
            if self.has_get_tech_support("onfail", "onfail-epilog"):
                self._foreach_dev(self.net.generate_tech_support, name)
            if self.has_fetch_core_files("onfail", "onfail-epilog"):
                self._foreach_dev(self.net._apply_remote, "fetch-core-files", [name])

        self._foreach_dev(self._apis_instrument_dut, "post-class-prolog")

    def _save_module_config(self, dut=None):
        # we MUST save the module config even though we don;t need to call
        # apply-module-config, because if reboot happens the device should
        # start with module config
        # save the module configuration before executing any test cases in the module
        msg = "save the module config - needed if device reboots "
        if self.cfg.skip_load_config not in ["module"]:
            msg = " and for restore across test cases"
        self.dut_log(dut, msg)
        self.net._apply_remote(dut, "save-module-config")

    def set_module_lvl_action_flags(self, action):
        if action == "core-dump":
            self.module_fetch_core_files = True
        elif action == "tech-support":
            self.module_get_tech_support = True

    def _module_complete_dut(self, dut, filepath):
        module_str = "module_{}".format(filepath.split('.')[0])

        if self.module_get_tech_support and self.has_get_tech_support("module-onerror"):
            self.net.generate_tech_support(dut, module_str)
            self.net._init_clean(dut, False, True)
        elif self.has_get_tech_support("module-onfail") and self.module_tc_fails > 0:
            self.net.generate_tech_support(dut, module_str)
            self.net._init_clean(dut, False, True)
        elif self.has_get_tech_support("module-always"):
            self.net.generate_tech_support(dut, module_str)
            self.net._init_clean(dut, False, True)

        if self.module_fetch_core_files and self.has_fetch_core_files("module-onerror"):
            self.net._apply_remote(dut, "fetch-core-files", [module_str])
            self.net._init_clean(dut, True, False)
        elif self.has_fetch_core_files("module-onfail") and self.module_tc_fails > 0:
            self.net._apply_remote(dut, "fetch-core-files", [module_str])
            self.net._init_clean(dut, True, False)
        elif self.has_fetch_core_files("module-always"):
            self.net._apply_remote(dut, "fetch-core-files", [module_str])
            self.net._init_clean(dut, True, False)

    def _module_complete(self, nodeid, filepath):
        self._save_cli(nodeid)
        dut_list = self.get_dut_names()
        [_, exceptions] = self._foreach(dut_list, self._module_complete_dut, filepath)
        errs = []
        for dut_index, ex in enumerate(exceptions):
            if not ex: continue
            self.dut_log(dut_list[dut_index], str(ex), logging.ERROR)
            errs.extend(ex)
        if errs:
            self.error("exception collecting module level core and dump files")
            os._exit(6)

        # save the module to completed list
        if not batch.is_infra_test(filepath):
            self.modules_completed.append(current_module.name or filepath)

    def _module_save_sysinfo(self):
        mname = paths.get_mlog_basename(current_module.name)
        row = [len(self.modules_completed)]     # s.no
        row.append(mname)                       # module name
        row.append(len(self.module_sysinfo))    # number of DUTs
        off = len(row)
        row.extend([0, 0, 0])                   # Memory usage
        row.extend([0.0, 0.0, 0.0])             # CPU Usage
        for entry in self.module_sysinfo.values():
            prolog_data = entry.get("pre-module", [])
            epilog_data = entry.get("post-module", [])
            if len(prolog_data) > 0: row[off+0] = row[off+0] + int(prolog_data[0])
            if len(epilog_data) > 0: row[off+1] = row[off+1] + int(epilog_data[0])
            row[off+2] = row[off+1] - row[off+0]
            if len(prolog_data) > 1: row[off+3] = row[off+3] + float(prolog_data[1])
            if len(epilog_data) > 1: row[off+4] = row[off+4] + float(epilog_data[1])
            row[off+5] = row[off+4] - row[off+3]
        sysinfo_csv = paths.get_sysinfo_csv(self._context.logs_path)
        Result.write_report_csv(sysinfo_csv, [row], ReportType.SYSINFO, False, True)

    def _module_clean(self, nodeid, filepath):
        if not self.min_topo_called:
            self.error("Module {} Minimum Topology is not specified".format(filepath))
        self.log_time("module {} clean start".format(filepath))
        apis_instrument("module-clean-start", filepath)

        self._module_complete(nodeid, filepath)

        # apply base configuration
        if self.apply_base_config_after_module:
            self._module_apply_base_config(filepath)

        # create sysinfo report
        if not batch.is_infra_test(filepath):
            self._post_module_cleanup(filepath)
            self._module_save_sysinfo()

        # update the node report files for every module
        # if we are not reporting run progress
        if self.cfg.run_progress_report == 0:
            self._report_file_generation()

        apis_instrument("module-clean-end", filepath)
        self.log_time("module {} clean end".format(filepath))

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

        # pre test data collection
        if scope == "pre-test":
            self._ensure_system_ready(dut, func_name)
            self.net.do_memory_checks(dut, "pre-test", func_name)
            self.net.do_syslog_checks(dut, "pre-test", func_name)
            self.net.save_sairedis(dut, "pre-test", func_name)
            return

        # post test data collection - skip when aborting
        if not self.abort_module_msg:
            self.net.do_memory_checks(dut, "post-test", func_name)
            self.net.do_syslog_checks(dut, "post-test", func_name)
            self.net.save_sairedis(dut, "post-test", func_name)
            self.net.do_audit("post-test", dut, func_name, res)

        if self.cfg.skip_load_config in ["base", "module"]:
            return

        # check for any configuration cleanup not done as part of testcase
        # if found any difference apply the module configuration at the end of every test case
        self.net._apply_remote(dut, "apply-module-config")
        self._ensure_system_ready(dut, func_name)

    def tc_log_init(self, func_name):
        self._context.log.tc_log_init(func_name)

    def module_log_init(self, module_name):
        if not module_name:
            self._log_software_versions(["module"])
        self._context.log.module_log_init(module_name)
        if module_name:
            #self.log("Execution Start Time: {}".format(self._context.execution_start_time))
            self._context.log_verion_info()
            if self.modules_completed:
                self.log("Previous Module: {}".format(self.modules_completed[-1]))

    def _test_log_init(self, nodeid, func_name, show_trace=False):
        self._context.result.clear()
        msg = "\n================== {} ==================\n".format(nodeid)
        if show_trace:
            self.log(msg)
        for dut in self.get_dut_names():
            self.dut_log(dut, msg, dst=["dut"])

    def is_topology_check(self, value):
        value_list = utils.make_list(value)
        for check in self.cfg.topology_check:
            if check in value_list:
                return True
        return False

    def verify_topology(self, check_type, name):
        topo_status = False
        max_wait = env.get("SPYTEST_TOPOLOGY_STATUS_MAX_WAIT", "60")
        max_wait = utils.integer_parse(max_wait, 0)
        max_iter = int(max_wait/5)
        failed_rows = []
        for retry in range(max_iter+1):
            [_, header, rows, seen_exp, show_alias] = self.hooks.verify_topology(check_type)
            if seen_exp:
                self.abort_function_msg  = "Observed exception during the topology verification"
                return False
            topo_status = utils.sprint_vtable(header, rows)
            self.log(topo_status, split_lines=True)
            failed_rows = []
            if max_wait > 0:
                for row in rows:
                    if row[4 if show_alias else 3] == "up/up": continue
                    if row[9 if show_alias else 7] == "NA" and self.cfg.skip_tgen: continue
                    failed_rows.append(row)
            if not failed_rows:
                self.log("Port Status Check ({}): PASS".format(check_type))
                return True
            if retry < max_iter:
                msg = "Retry Port Status Check ({}) Iteration {} of Max {}".format(check_type, retry, max_iter)
                self.wait(5, msg)
        # some/all the ports are down
        self.warn("Port Status Check ({}): FAIL".format(check_type))
        if name:
            prefix = "{}_topology_check_{}".format(check_type, name)
        else:
            prefix = "{}_topology_check".format(check_type)
        if self.is_tech_support_onerror("port_status"):
            self._foreach_dev(self.net.do_syslog_checks, prefix, "")
            self.generate_tech_support(None, prefix)

        abort_msgs = []
        for row in failed_rows:
            msg = "Port {}({})/{} is not ready in time before {}"
            msg = msg.format(row[0], row[1], row[2], check_type)
            abort_msgs.append(msg)
            if check_type == "module":
                self._context._tb.set_port_down(row[0], row[2])
        abort_msg = "\n".join(abort_msgs)
        status_abort = env.get("SPYTEST_TOPOLOGY_STATUS_ONFAIL_ABORT", "module")
        if check_type in status_abort.split(",") and check_type in ["module", "function"]:
            self.abort_module_msg = abort_msg
        else:
            self.warn(abort_msg)

        return False

    def _function_init(self, nodeid, func_name):

        self.clear_tc_results()
        self.abort_function_msg = None
        self.log_time("function {} init start".format(nodeid))

        apis_instrument("function-init-start", func_name)
        self.current_tc_start_time = get_timenow()

        # ajdust TC MAX Timeout using data from tcmap
        if self.cfg.tc_max_timeout > 0:
            tc_max_timeout = tcmap.get_function_info(func_name).maxtime
        else:
            tc_max_timeout = 0
        if tc_max_timeout > 0 and tc_max_timeout > self.cfg.tc_max_timeout:
            self.net.function_init_start(tc_max_timeout)
        else:
            self.net.function_init_start(self.cfg.tc_max_timeout)

        self._test_log_init(nodeid, func_name)

        #if self.is_community_build() and nodeid in community_unsupported:
            #desc = self._context.report("Unsupported", "test_case_unsupported")
            #self._function_clean(nodeid, func_name, min_time)
            #pytest.skip(desc)

        if self.abort_module_msg:
            desc = self._context.report("SKIPPED", "test_execution_skipped", self.abort_module_msg)
            self._function_clean(nodeid, func_name, min_time)
            pytest.skip(desc)

        if self.cfg.first_test_only and self.module_tc_executed > 0:
            desc = self._context.report("SKIPPED", "test_execution_skipped", "as the ask is to run first test only")
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
        if batch.is_infra_test(func_name):
            pass # no need to check on the infra tests
        elif not self.cfg.ignore_dep_check:
            errs = check_dependency(func_name)
            if errs:
                self.error("dependent test case failed - no need to run {}".format(func_name))
                desc = self._context.report("DepFail", "depedent_test_failed", errs)
                self._function_clean(nodeid, func_name, min_time)
                pytest.skip(desc)

        # simulate node dead
        batch.simulate_deadnode(2)

        if not self.abort_module_msg:
            if self.is_topology_check(["function"]):
                msg = "verify/show port status before function {}"
                self.log(msg.format(",".join(self.get_dut_names())))
                self.verify_topology("function", func_name)

        if self.abort_module_msg:
            desc = self._context.report("SKIPPED", "test_execution_skipped", self.abort_module_msg)
            self._function_clean(nodeid, func_name, min_time)
            pytest.skip(desc)

        if self.abort_function_msg:
            desc = self._context.report("SKIPPED", "test_execution_skipped", self.abort_function_msg)
            self._function_clean(nodeid, func_name, min_time)
            pytest.skip(desc)

        #self.log("save/apply module config if not skipped")
        self._foreach_dev(self._function_common_dut, "pre-test", func_name=func_name)

        # ensure system is ready to proceed further
        if self.abort_module_msg:
            self.error(self.abort_module_msg)
            return "SKIP"

        self._context._tgen_instrument("pre-test", func_name)

        if self.cfg.skip_load_config not in ["base", "module"] and \
           self.cfg.skip_verify_config not in ["module", "both"]:
            verifier = self.current_module_verifier
            self.log("performing module config verification - {}".format(verifier))
            verifiers = self.hooks.get_verifiers()
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

        apis_instrument("function-init-end", func_name)
        self.log_time("function {} init end".format(nodeid))

    def _function_clean(self, nodeid, func_name, time_taken=None):

        self.log_time("function {} clean start".format(nodeid))
        apis_instrument("function-clean-start", func_name)

        self._context.net.set_prev_tc(func_name)

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

        apis_instrument("function-clean-end", func_name)
        self.log_time("function {} clean end".format(nodeid))

    def _report_file_generation(self):
        self.log_time("report file generation start")

        self._context.execution_end_time = get_timenow()
        total_tc_time_taken = get_elapsed(self._context.total_tc_start_time, True)

        data = _report_data_generation(self._context.execution_start_time,
                                       self._context.execution_end_time,
                                       self._context.session_init_time_taken,
                                       total_tc_time_taken)
        [_, logs_path, _] = _get_logs_path()
        report_txt = paths.get_report_txt(logs_path)
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
            self.dut_log(dut, msg, dst=["dut"])
        self._context.publish(nodeid, func_name, time_taken)
        self.log_time("Test Time ({} - {}) Published".format(self.current_tc_start_time, get_timenow()))

    def _write_stats(self, nodeid, res, desc, time_taken):
        module, func = paths.parse_nodeid(nodeid)
        if batch.is_infra_test(func):
            return
        [_, logs_path, _] = _get_logs_path()
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
            ofh.write("\n=========================================================\n")
        self.stats_count = self.stats_count + 1
        row = [self.stats_count, module, func, res, time_taken, stats.helper_cmd_time,
               stats.tc_cmd_time, stats.tg_cmd_time, stats.tc_total_wait,
               stats.tg_total_wait, stats.pnfound, desc.replace(",", " ")]
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

        :return: names of all the tg
        :rtype: list
        """
        return self.get_device_names("TG")

    def _build_native_map(self, native):
        native_map = dict()
        for dut in self.get_dut_names():
            native_map[dut] = self._is_ifname_native(dut, native)
        return native_map

    def _is_ifname_native(self, dut, native):
        if native is not None:
            return native
        ifname_type = self.get_cfg_ifname_type(dut)
        if ifname_type in ["alias"]:
            return False
        return True

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
        for local, _, _, _, _ in self._get_device_links(dut, peer, dtype, native):
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

    def get_tg_info(self, tg):
        return self._context._tb.get_tg_info(tg)

    def get_device_alias(self, name, only=False, retid=False):
        return self._context._tb.get_device_alias(name, only, retid)

    def set_device_alias(self, dut, name):
        return self.net.set_device_alias(dut, name)

    def moveto_grub_mode(self, dut):
        tb_dut_details = self._context._tb.get_dut_access(dut)
        rinfo = self._context._tb.get_rps(dut)
        retval = False
        if not rinfo:
            self.report_env_fail("testbed_no_rps_info")
        elif "model" not in rinfo or not rinfo.model or rinfo.model in ["None", "none"]:
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
                      rinfo.username, rinfo.password, dut=str(dut))
            if "pdu_id" in rinfo: rps.set_pdu_id(rinfo.pdu_id)
            self.dut_log(dut, "Performing RPS {} Device {}".format("reset", dut))
            if not rps.do_op("reset", 1):
                self.error("Failed to perform RPS {}".format("reset"))
            retval = True
            if retval:
                retval = rps.grub_wait(tb_dut_details["ip"], tb_dut_details["port"])
        else:
            retval = True
        return retval

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
        elif "model" not in rinfo or not rinfo.model or rinfo.model in ["None", "none"]:
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
                      rinfo.username, rinfo.password, dut=str(dut))
            if "pdu_id" in rinfo: rps.set_pdu_id(rinfo.pdu_id)
            if recon: self.net.do_pre_rps(dut, op.lower())
            self.log("Performing RPS {} Device {}".format(op, dut))
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
            if "model" not in rinfo or not rinfo.model or rinfo.model in ["None", "none"]:
                self.report_env_fail("testbed_no_rps_model")
            elif "ip" not in rinfo or not rinfo.ip:
                self.report_env_fail("testbed_no_rps_ip")
            elif "outlet" not in rinfo or not rinfo.outlet:
                self.report_env_fail("testbed_no_rps_outlet")
            elif "username" not in rinfo or rinfo.username is None:
                self.report_env_fail("testbed_no_rps_username")

            if "port" not in rinfo: rinfo.port = 23
            rps = RPS(rinfo.model, rinfo.ip, rinfo.port, rinfo.outlet,
                      rinfo.username, rinfo.password, dut=str(d))
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
        (rvs, _) = self._foreach(dut_mrinfo.keys(), f)
        retval = all(rvs)

        # perform post-rps operations
        if recon:
            self._foreach(dut_list, self.net.do_post_rps, op.lower())

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
            self.report_env_fail("testbed_no_ts_info")
        elif "model" not in rinfo or not rinfo.model or rinfo.model in ["None", "none"]:
            self.report_env_fail("testbed_no_ts_model")
        elif "ip" not in rinfo or not rinfo.ip:
            self.report_env_fail("testbed_no_ts_ip")
        elif "cid" not in rinfo or not rinfo.cid:
            self.report_env_fail("testbed_no_ts_cid")
        elif "username" not in rinfo or rinfo.username is None:
            self.report_env_fail("testbed_no_ts_username")
        elif not self.cfg.filemode:
            self.log("Performing Terminal Server Operation {} Device: {}".format(op, dut))
            ts = TermServ(rinfo.model, rinfo.ip, rinfo.cid,
                          rinfo.username, rinfo.password, desc=str(dut))
            if not ts.do_op(op):
                self.error("Failed to perform Terminal Server Operation {}".format(op))
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

    def ensure_min_topology(self, *args, **kwargs):
        """
        verifies if the current testbed topology satifies the
        minimum topology required by test script
        :param spec: needed topology specification
        :type spec: basestring
        :return: True if current topology is good enough else False
        :rtype: bool
        """
        native = kwargs.get('native', None)
        self.log("Requested ensure_min_topology: {}".format(args))
        self.min_topo_called = True
        ftrace("ensure_min_topology", get_current_nodeid(), *args)

        [errs, properties] = self._context._tb.ensure_min_topology(*args)
        if not errs:
            if properties and None in properties:
                if "CONSOLE_ONLY" in properties[None]:
                    self.net.set_console_only(True)
            topo_1 = self._context._tb.get_topo(True)
            topo_2 = self._context._tb.get_topo(False)
            self.log("Assigned topology: {}".format(topo_1))
            self.log("Assigned devices: {}".format(topo_2))
            return self.get_testbed_vars(native)

        self.report_topo_fail("min_topology_fail", errs)

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
            for key, value in self.app_vars[dut]:
                rv[key] = value
            for key, value in self.module_vars[dut]:
                rv[key] = value
            return rv
        if name in self.app_vars[dut]:
            return self.app_vars[dut][name]
        if name in self.module_vars[dut]:
            return self.module_vars[dut][name]
        return default

    def get_platform_type(self, dut):
        """
        returns the platform type as a string
        :return: platform type string 
        :rtype: str
        """
        return self._context._tb.get_platform_type(dut)
    
    def get_rp_ip_address(self, dut):
        """
        returns the platform type as a string
        :return: platform type string
        :rtype: str
        """
        return self._context._tb.get_rp_ip_address(dut)

    def get_build_commit_hash(self, dut):
        """
        returns the build commit hash as a string
        :return: commit hash string 
        :rtype: str
        """
        return self._context._tb.get_build_commit_hash(dut)

    def get_build_time(self, dut):
        """
        returns the build time as a string
        :return: image build time  string 
        :rtype: str
        """
        return self._context._tb.get_build_time(dut)

    def get_sdk_version(self, dut):
        """
        returns the build sdk version as a string
        :return: sdk version string 
        :rtype: str
        """
        return self._context._tb.get_sdk_version(dut)

    def get_username(self, dut):
        """
        returns the username as a string
        :return: user name string 
        :rtype: str
        """
        return self._context._tb.get_username(dut)

    def get_password(self, dut):
        """
        returns the password as a string
        :return: password string 
        :rtype: str
        """
        return self._context._tb.get_password(dut)

    def clear_tc_results(self):
        self._context.tc_results.clear()

    def clear_module_vars(self, dut):
        self.module_vars[dut].clear()

    def add_module_vars(self, dut, name, value):
        dut_list = [dut] if dut else self.get_dut_names()
        for d in dut_list:
            self.module_vars[d][name] = value

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
        # TODO check alias
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
            [tg, _, port] = tbvars.tgen_ports[name]
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
            [tg, _, port] = value
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

    def refresh_files(self):
        self.net.register_templates()

    def _record_cli_type(self, dut, rv):
        if self._is_save_cli_types():
            file_name = sys._getframe(3).f_code.co_filename
            file_name = os.path.basename(file_name)
            func_name = sys._getframe(3).f_code.co_name
            key = "{}::{},{}".format(file_name, func_name, rv)
            if dut in self.cli_type_cache:
                self.cli_type_cache[dut][key] = 1
        return rv

    def _save_cli_type(self, nodeid):
        if batch.is_infra_test(nodeid):
            return
        if self._is_save_cli_types():
            [_, logs_path, _] = _get_logs_path()
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
        _, ui_type = _get_module_ui(current_module.name, self.cfg)
        dut = utils.make_list(dut)[0]
        cli_type = kwargs.get('cli_type', '')
        if cli_type: cli_type = cli_type.strip()
        if not cli_type: cli_type = ui_type
        elif cli_type != ui_type:
            msg = "CLI-TYPE Forced to {} From caller".format(cli_type)
            if dut: self.dut_log(dut, msg, logging.DEBUG)
            else: self.debug(msg)
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

    def upload_file_to_dut(self, dut, src_file, dst_file):
        return self._context.net.upload_file_to_dut(dut, src_file, dst_file)

    def download_file_from_dut(self, dut, src_file, dst_file):
        return self._context.net.download_file_from_dut(dut, src_file, dst_file)

    def set_module_verifier (self, verifier):
        verifiers = self.hooks.get_verifiers()
        if verifier not in verifiers:
            self.warn("Verifier '{}' is not registered".format(verifier))
        self.current_module_verifier = verifier

    def ansible_dut(self, dut, playbook, **kwargs):
        return self._context.net.ansible_dut(dut, playbook, **kwargs)

    def ansible_service(self, service, playbook, **kwargs):
        tbvars = self.get_testbed_vars()
        service_data = self.get_service_info(tbvars.D1, service)
        service_data["filemode"] = self.get_args("filemode")
        return self._context.net.ansible_service(service_data, playbook, **kwargs)

    def add_addl_auth(self, dut, username, password):
        self._context.net.add_addl_auth(dut, username, password)

    def set_port_defaults(self, dut, breakout=True, speed=True, section=None):

        # init applicable ports and arguments
        (all_ports, apply_args) = ([], [[],[]])

        breakout_mode = self.get_cfg_breakout_mode(dut)

        # fill breakout settings arguments
        if breakout_mode != "none" and breakout:

            # get the breakout info from testbed file
            breakout_info = self._context._tb.get_breakout(dut, section=section)
            if not breakout_info: breakout_info = []

            for [l_port, l_breakout] in breakout_info:
                all_ports.append(l_port)
                apply_args[0].append(l_port)
                apply_args[0].append(l_breakout)

        # fill speed settings arguments
        if self.cfg.speed_mode != "none" and speed:

            # get the speed info from testbed file
            speed_info = self._context._tb.get_speed(dut)
            if not speed_info: speed_info = dict()

            apply_args[1] = []
            for l_port, l_speed in speed_info.items():
                all_ports.append(l_port)
                apply_args[1].append(l_port)
                apply_args[1].append(l_speed)

        if all_ports:
            # trace interfaces to debug settings before port breakout
            self.dut_log(dut, "dump interface status before breakout", logging.DEBUG)
            self.hooks.get_interface_status(dut, ",".join(all_ports))

        if not apply_args[0] and not apply_args[1]:
            return True

        if breakout_mode in ["static", "script"]:
            retval_1 = self.net._apply_remote(dut, "port-defaults", apply_args)
        else:
            retval_1 = self.hooks.set_port_defaults(dut, apply_args[0], apply_args[1])

        retval_2 = self._ensure_system_ready(dut, "session")
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
        return self.net.change_prompt(dut, mode, **kwargs)

    def cli_config(self, dut, cmd, mode=None, skip_error_check=False, delay_factor=0, **kwargs):
        return self.net.cli_config(dut, cmd, mode, skip_error_check, delay_factor, **kwargs)

    def cli_show(self, dut, cmd, mode=None, skip_tmpl=False, skip_error_check=False, **kwargs):
        return self.net.cli_show(dut, cmd, mode, skip_tmpl, skip_error_check, **kwargs)

    def get_config_profile(self):
        return self._context._tb.get_config_profile()

    def get_device_type(self, dut):
        return self._context._tb.get_device_type(dut)

    def open_config(self, dut, template, var=None, **kwargs):
        return self.net.open_config(dut, template, var=var, **kwargs)

    def gnmi_init(self, dut):
        return self.net.gnmi_init(dut)

    def gnmi_create(self, dut, path, data, *args, **kwargs):
        return self.net.gnmi_create(dut, path, data, *args, **kwargs)

    def gnmi_update(self, dut, path, data, *args, **kwargs):
        return self.net.gnmi_update(dut, path, data, *args, **kwargs)

    def gnmi_replace(self, dut, path, data, *args, **kwargs):
        return self.net.gnmi_replace(dut, path, data, *args, **kwargs)

    def gnmi_delete(self, dut, path, *args, **kwargs):
        return self.net.gnmi_delete(dut, path, *args, **kwargs)

    def gnmi_get(self, dut, path, *args, **kwargs):
        return self.net.gnmi_get(dut, path, *args, **kwargs)

    def gnmi_send(self, dut, path, *args, **kwargs):
        return self.net.gnmi_send(dut, path, *args, **kwargs)

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

    def parse_show(self, dut, cmd, output):
        return self.net.parse_show(dut, cmd, output)

    def show(self, dut, cmd, **kwargs):
        return self.net.show(dut, cmd, **kwargs)

    def config(self, dut, cmd, **kwargs):
        return self.net.config(dut, cmd, **kwargs)

    def exec_ssh_remote_dut(self, dut, ipaddress, username, password, command=None, timeout=30):
        return self.net.exec_ssh_remote_dut(dut, ipaddress, username, password, command, timeout)

    def run_uicli_script(self, dut, scriptname):
        return self.net.run_uicli_script(dut, scriptname)

    def run_uirest_script(self, dut, scriptname):
        return self.net.run_uirest_script(dut, scriptname)

    def run_uignmi_script(self, dut, scriptname, **kwargs):
        return self.net.run_uignmi_script(dut, scriptname, **kwargs)

    def generate_tech_support(self, dut, name):
        if dut is None:
            self.log("generate_tech_support: all")
            self._foreach_dev(self.net.generate_tech_support, name)
        elif isinstance(dut, list):
            self.log("generate_tech_support: {}".format(",".join(dut)))
            self._foreach(dut, self.net.generate_tech_support, name)
        else:
            self.net.generate_tech_support(dut, name)

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
            if current_test.phase == "test_module_begin": phase = "module-prolog"
            elif current_test.phase == "test_class_begin": phase = "class-prolog"
            elif current_test.phase == "test_function_begin": phase = "function-prolog"
            elif current_test.phase == "test_function_end": phase = "function-or-epilog"
            elif current_test.phase == "global_function_finish": phase = "module-or-class-epilog"
            elif current_test.phase == "test_class_finish": phase = "module-epilog"
            else: phase = "framework"
            entry = [phase, module, func, dut, mode, cmd]
            self.cli_records[dut].append(entry)

    def _save_cli(self, nodeid):
        self._save_cli_type(nodeid)
        if self._is_save_cli_cmds():
            [_, logs_path, _] = _get_logs_path()
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

    def exec_all(self, entries, first_on_main=False):
        return putil.exec_all2(self.cfg.faster_init, "abort", entries,
                               first_on_main)

    def exec_each(self, items, func, *args, **kwargs):
        return putil.exec_foreach2(self.cfg.faster_init, "abort", items, func,
                                   *args, **kwargs)

    def exec_each2(self, items, func, kwarg_list, *args):
        return putil.exec_parallel2(self.cfg.faster_init, "abort", items, func,
                                    kwarg_list, *args)

    def is_feature_supported(self, name, dut=None):
        return self.feature.is_supported(name)

    def getenv(self, name, default=None):
        return env.get(name, default)

    def infra_debug(self, msg):
        self.banner(msg)
        self.log(current_test)

    def create_init_config_db(self, dut):
        self._create_init_config_db(dut)

    def mktemp(self, dir=None):
        dir = dir or _get_logs_path()[1]
        return tempfile.mkstemp(dir=dir)[1]


def arg_validate_repeat():
    class ArgValidateRepeat(argparse.Action):
        def __call__(self, parser, namespace, values, option_string=None):
            message = ''
            types_supported = ["function", "module"]
            if len(values) != 2:
                message = "requires both <type> and <times>"
            elif values[0] not in types_supported:
                message = "<type> should be one of {}".format(types_supported)
            else:
                try:
                    values[1] = int(values[1])
                except ValueError:
                    message = "<times> should be integer"
            if message:
                raise argparse.ArgumentError(self, message)
            setattr(namespace, self.dest, values)
    return ArgValidateRepeat

def arg_validate_exec_phase():
    class ArgValidateExecPhase(argparse.Action):
        def __call__(self, parser, namespace, values, option_string=None):
            for value in values.split(","):
                if value not in exec_phases:
                    message = "unknown sub-option {}".format(value)
                    raise argparse.ArgumentError(self, message)
            setattr(namespace, self.dest, values)
    return ArgValidateExecPhase

def add_option(group, name, **kwargs):
    default = kwargs.pop("default", None)
    default = cmdargs.get_default(name, default)
    help = kwargs.pop("help", "")
    if default not in [None, ""]:
        if help: help = help + " -- "
        help = help + " default: {}".format(default)
    group.addoption(name, default=default, help=help, **kwargs)

def add_options(parser):
    group = parser.getgroup("SpyTest")
    add_option(group, "--testbed-file", action="store",
               metavar="<testbed file path>",
               help="testbed file path -- default: ./testbed.yaml")
    add_option(group, "--ignore-tcmap-errors", action="store", type=int,
               choices=[0, 1], help="Ignore errors in tcmap")
    add_option(group, "--tclist-map", action="store", help="use test case map file")
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
    add_option(group, "--file-mode", action="store_true", help="Execute in file mode")
    add_option(group, "--quick-test", action="store_true",
               help="Disable options for a quick test")
    add_option(group, "--email", action="append", help="Email address(es) to send report to.")
    add_option(group, "--email-subject", action="store",
               help="Email subject to be used to send report")
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
    help_msg = """
        method used while applying configuration
            <none>     use built-in default (reload when routing-mode=split else force-reload (default)
            <reload>   config-reload when there is change in the current configuration
            <replace>  config-replace when there is change in the current configuration
            <reboot>   device reboot when there is change in the current configuration
            <force-reload> config-reload even when there is no change in the current configuration
            <force-replace> config-replace even when there is no change in the current configuration
            <force-reboot> device reboot even when there is no change in the current configuration
    """
    add_option(group, "--load-config-method", action="store",
               choices=['none', 'reload', 'replace', 'reboot',
               'force-reload', 'force-replace', 'force-reboot'], help=help_msg)
    add_option(group, "--skip-init-config", action="store_true",
               help="Skip loading initial configuration before and after execution")
    add_option(group, "--skip-load-config", action="store", choices=['base', 'module', 'none'],
               help="Skip loading configuration before and after test case execution")
    add_option(group, "--load-image", action="store",
               choices=['installer', 'onie1', 'onie', "none", "installer-without-migration", "testbed"],
               help="Loading image before and after execution using specified method")
    add_option(group, "--skip-verify-config", action="store", choices=['base', 'module', "both", "none"],
               help="Skip verifying base and/or module configuration")
    add_option(group, "--ignore-dep-check", action="store", type=int,
               choices=[0, 1], help="Ignore depends mark in test cases")
    add_option(group, "--memory-check", action="store", choices=['test', 'module', 'none'],
               help="read memory usage")
    add_option(group, "--syslog-check", action="store", choices=syslog.levels,
               help="read syslog messages of given level and clear all syslog messages")
    add_option(group, "--save-sairedis", action="store",
               choices=["none", "test", "module"], help="read sairedis messages")
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
               help="Wait time in seconds for ports to come up")
    add_option(group, "--reboot-wait", action="store", type=int,
               help="Wait time in seconds for ports to come up")
    add_option(group, "--fetch-core-files", action=arg_validate_exec_phase(),
               help="Fetch the core files from DUT to logs location")
    add_option(group, "--get-tech-support", action=arg_validate_exec_phase(),
               help="Get the tech-support information from DUT to logs location")
    add_option(group, "--tc-max-timeout", action="store", type=int,
               help="Max time that a testcase can take to execute")
    add_option(group, "--module-init-max-timeout", action="store", type=int,
               help="Max time that a module initialization can take to execute")
    add_option(group, "--results-prefix", action="store",
               help="Prefix to be used for results")
    add_option(group, "--results-compare", action="store",
               help="Compare the results with that are in given path")
    add_option(group, "--exclude-devices", action="store",
               help="exclude given duts from testbed")
    add_option(group, "--include-devices", action="store",
               help="include given duts from testbed")
    add_option(group, "--run-progress-report", action="store",
               type=int, help="send run progress report at given frequency")
    add_option(group, "--env", action="append",
               metavar=("<name>", "<value>"),
               nargs=2, help="environment variables")
    help_msg = """
        Enable executing tests in random order.
            <0> disable random order execution
            <1> execute the modules in random order (default).
            <2> execute the test cases in random order
            <3> use the random order from module info
    """
    add_option(group, "--random-order", action="store", type=int,
               choices=[0, 1, 2, 3], help=help_msg)
    add_option(group, "--repeat-test", action=arg_validate_repeat(),
               metavar=("<type>", "<times>"), nargs=2,
               help="repeat each test function given number of times")
    add_option(group, "--rps-reboot", action="store",
               metavar="<device names csv>",
               help="Reboot given devices using RPS")
    add_option(group, "--pde", action="store_true",
               help="PDE image support")
    help_msg = """
        Try executing through SSH
            <0> disable (default)
            <1> enable for all modules
            <2> use the value from module info
    """
    add_option(group, "--tryssh", action="store", type=int,
               choices=[0, 1, 2], help=help_msg)
    add_option(group, "--first-test-only", action="store_true",
               help="Execute only first test in each module - default: false")
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
               metavar=("<DUT>", "<port>" , "<param>", "<value>"), help=help_msg)
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
    add_option(group, "--ixserver", action="append", help="override ixnetwork server")
    add_option(group, "--ui-type", action="store",
               choices=['click', 'klish', 'click-fallback', 'klish-fallback', 'rest-put', 'rest-patch'],
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
            <testbed> use ifname-type from testbed file which can be [native, alias, none]
            <native>  interfaces appear like Ethernet0, Ethernet1 etc
            <alias>   interfaces appear like Eth1/0, Eth1/1 etc
            <none>    no support for interface name, assume native
    """
    add_option(group, "--ifname-type", action="store",
               choices=['native', 'alias', 'none', 'testbed'], help=help_msg)
    help_msg = """
        Enable/Disable manamgement vrf.
            <0>  Do nothing
            <1>  Enable management vrf
            <2>  Disable management vrf
    """
    add_option(group, "--mgmt-vrf", action="store", type=int, choices=[0, 1, 2], help=help_msg)
    add_option(group, "--device-feature-enable", default=[], action="append", help="Enable device feature")
    add_option(group, "--device-feature-disable", default=[], action="append", help="Disable device feature")
    add_option(group, "--device-feature-group", default="broadcom", action="store", help="choose feature group")


def get_work_area():
    return gWorkArea

def set_work_area(val):
    global gWorkArea
    gWorkArea = val

def _create_work_area2(config):
    missing = []
    for arg in config.args:
        if os.path.isfile(arg): continue
        if os.path.isdir(arg): continue
        missing.append(arg)
    if missing:
        utils.banner("Missing Paths: {}".format(",".join(missing)))
    cfg = SpyTestDict()
    cfg.filemode = config.getoption("--file-mode")
    cfg.testbed = config.getoption("--testbed-file")
    cfg.logs_path = config.getoption("--logs-path")
    cfg.log_lvl = config.getoption("--log-level")
    cfg.tclist_map = config.getoption("--tclist-map")
    cfg.tclist_bucket = config.getoption("--tclist-bucket", None)
    cfg.email_csv = config.getoption("--email")
    if cfg.email_csv: cfg.email_csv = ",".join(cfg.email_csv)
    cfg.email_subject = config.getoption("--email-subject", "Run Report")
    cfg.email_attachments = bool(config.getoption("--email-attachments", 0))
    cfg.skip_tgen = config.getoption("--skip-tgen")
    cfg.tgen_module_init = bool(config.getoption("--tgen-module-init", 1))
    cfg.load_config_method = config.getoption("--load-config-method")
    cfg.topology_check = config.getoption("--topology-check", ["module"])
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
    cfg.fetch_core_files = config.getoption("--fetch-core-files")
    cfg.get_tech_support = config.getoption("--get-tech-support")
    cfg.skip_verify_config = config.getoption("--skip-verify-config")
    cfg.tc_max_timeout = config.getoption("--tc-max-timeout")
    cfg.module_max_timeout = config.getoption("--module-init-max-timeout")
    cfg.results_prefix = config.getoption("--results-prefix")
    cfg.results_compare = config.getoption("--results-compare")
    cfg.exclude_devices = config.getoption("--exclude-devices")
    cfg.include_devices = config.getoption("--include-devices")
    cfg.run_progress_report = config.getoption("--run-progress-report", 0)
    cfg.rps_reboot = config.getoption("--rps-reboot", None)
    cfg.pde = config.getoption("--pde", False)
    cfg.first_test_only = config.getoption("--first-test-only", False)
    cfg.tryssh = config.getoption("--tryssh", 0)
    cfg.random_order = config.getoption("--random-order", 1)
    cfg.env = config.getoption("--env", [])
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
    cfg.ixserver = config.getoption("--ixserver", [])
    cfg.ui_type = config.getoption("--ui-type", "click")
    cfg.breakout_mode = config.getoption("--breakout-mode", "static")
    cfg.speed_mode = config.getoption("--speed-mode", "configured")
    cfg.ifname_type = config.getoption("--ifname-type", "native")
    cfg.mgmt_vrf = config.getoption("--mgmt-vrf", 0)
    cfg.device_feature_enable = config.getoption("--device-feature-enable", [])
    cfg.device_feature_disable = config.getoption("--device-feature-disable", [])
    cfg.device_feature_group = config.getoption("--device-feature-group", "broadcom")

    if cfg.pde:
        cfg.skip_init_config = True
        cfg.skip_load_config = "base"

    if config.getoption("--quick-test", False):
        cfg.load_image = "none"
        cfg.fetch_core_files = "none"
        cfg.get_tech_support = "none"
        cfg.syslog_check = "none"
        cfg.memory_check = "none"
        cfg.save_sairedis = "none"
        cfg.skip_load_config = "base"
        cfg.skip_init_config = True
        cfg.breakout_mode = "none"
        cfg.speed_mode = "none"
        os.environ["SPYTEST_TECH_SUPPORT_ONERROR"] = ""

    if cfg.filemode:
        os.environ["SPYTEST_TOPOLOGY_STATUS_ONFAIL_ABORT"] = ""

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
    if not batch.is_member():
        # master or standalone
        consolidate_results()
    if not batch.is_slave():
        # NOTE: standalone is handled somewhere else
        generate_email_report()
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
    index, has_exp, desc, msg_list = 0, False, "", []
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
                msg_list.append(desc)
                has_exp = True
        msg = "[{}] {}:{} {} {}".format(index, fname, line, func, text)
        index = index + 1
        msg_list.append(msg)
    wa.alert(msg_list, "Exception")
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
        [user_root, _, _] = _get_logs_path()
        if os.path.isfile(file_name):
            file_path = file_name
        else:
            file_path = os.path.join(user_root, file_name)
            if not os.path.isfile(file_path):
                print("Failed to locate test case list file {}".format(file_name))
                os._exit(8)

        with utils.open_file(file_path) as fh:
            for test_name in fh:
                test_name = test_name.strip()
                if test_name and not test_name.startswith("#"):
                    test_names.append(test_name)
            if len(test_names) <= 0:
                msg = "no test cases are specified in test case list file"
                print("{} {}".format(msg, file_name))
                os._exit(9)

    return test_names

def _build_tclist_csv(config, option="--tclist-csv"):
    tclist_csv_list = config.getoption(option, None)
    if not tclist_csv_list: return None
    test_names_list = []
    for tclist_csv in tclist_csv_list:
        test_names = tclist_csv.replace(",", ' ').split()
        if not test_names:
            print(" ERROR: Must have at least one name in {}".format(option))
            os._exit(10)
        test_names_list.extend(test_names)
    return test_names_list

def _parse_suite_files(suites, fin, fex, tin, tex):
    path = os.path.dirname(__file__)
    path = os.path.join(path, '..', "reporting", "suites")

    errs, lines, csuites, args = [], [], [], []
    for suite in suites:
        fname = os.path.join(os.path.abspath(path), suite)
        if not os.path.exists(fname):
            errs.append("Suite File {} is not found".format(fname))
            continue
        lines.extend(utils.read_lines(fname))
    if errs:
        print("Failed to find suite files")
        print("\n".join(errs))
        os._exit(9)

    for line in lines:
        if not line or line.startswith("#"): continue
        if line.startswith("+suite:"):
            csuites.append(line[7:].strip())
        elif line.startswith("+file:"):
            fin.append(line[6:].strip())
        elif line.startswith("-file:"):
            fex.append(line[6:].strip())
        elif line.startswith("-test:"):
            tex.append(line[6:].strip())
        elif line.startswith("+test:"):
            tin.append(line[6:].strip())
        elif line.startswith("+args:"):
            args.extend(line[6:].strip().split())
    if csuites:
        _parse_suite_files(csuites, fin, fex, tin, tex)
    return fin, fex, tin, tex, args

def parse_suite_files(suites):
    fin, fex, tin, tex, opts = _parse_suite_files(suites, [], [], [], [])
    for f in fex:
        opts.extend(["--ignore", f])
    for t in tin:
        if t not in tex:
            if fin:
                # This is applicable only when files are not specified
                continue
            opts.extend(["--tclist-csv", t])
    for t in tex:
        opts.extend(["--tclist-csv-exclude", t])
    for f in fin:
        if f not in fex:
            opts.append(f)
    return opts

def _show_tcmap_errors():
    if batch.is_master():
        return
    tcm = tcmap.get()
    if tcm.errors:
        print("===== TCMAP Errors ======")
        print("\n".join(tcm.errors))
        print("========================")

def _build_tclist_map(config, items):
    use_cadence = config.getoption("--tclist-map", None)
    ignore_errs = config.getoption("--ignore-tcmap-errors", 0)
    if not use_cadence: return None
    use_cadences = use_cadence.replace(",", ' ').split()
    if not use_cadences: return None
    test_names = []
    tcm = tcmap.get()
    for use_cadence in use_cadences:
        for name, module in tcm.modules.items():
            if use_cadence == "all" or module.cadence == use_cadence:
                for item in items:
                    if item.location[0] == name:
                        func = item.location[2]
                        if func not in test_names:
                            test_names.append(func)
        for tcid, cadence in tcm.cadence.items():
            if use_cadence == "all" or cadence == use_cadence:
                func = tcmap.get_func(tcid)
                if func not in test_names:
                    test_names.append(func)

    if len(test_names) <= 0:
        msg = " no '{}' test cases found in test case map file"
        print(msg.format(use_cadence))
        os._exit(9)

    if tcm.errors:
        _show_tcmap_errors()
        if not ignore_errs:
            os._exit(9)

    return test_names

def _build_selected_tests(items, test_names, exclude_test_names):
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
        else:
            deselected_items.append(item)
        seen_test_names.append(item.location[2])
        seen_test_names.append(item.nodeid)

    # trace missing tests
    if test_names is not None:
        missing_test_names = [i for i in test_names if i not in seen_test_names]
        if missing_test_names:
            m1 = "Ignoring below missing functions: Available {}\n  - "
            m2 = m1.format(len(items)) + "\n  - ".join(missing_test_names)
            print(m2)
            missing_test_names_msg = m2
    return selected_items, deselected_items

def get_item_module_file(item):
    module = getattr(item, "module", None)
    if not module:
        module = item
    return module.__file__

def order_items(items, test_names):
    new_items = []
    for test_name in test_names:
        for item in items:
            alt_item_name = item.location[2][5:]
            if test_name in [item.location[2], item.nodeid, alt_item_name]:
                new_items.append(item)
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
        Random(seed).shuffle(module_names)
    new_items = []
    for module_name in module_names:
        module_items = modules[module_name]
        if order == 3:
            order = 2 if tcmap.get_module_info(module_name).random else 0
        if order == 2:
            Random(seed).shuffle(module_items)
        new_items.extend(module_items)
    items[:] = new_items

def batch_infra_tests_remove(items):
    prefix_items, new_items, suffix_items = [],[],[]
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
    mfile = get_item_module_file(metafunc)
    repeat = env.get("SPYTEST_REPEAT_NAME_{}".format(mfile))
    if repeat:
        ids = lambda a : '{0}'.format(a)
        metafunc.parametrize('global_repeat_request', [repeat],
                             indirect=True, ids=ids, scope="module")
    scope, count = config.option.repeat_test
    if count <= 1: return
    ids = lambda a : '{0}.{1}'.format(a + 1, count)
    metafunc.parametrize('global_repeat_request', range(count),
                         indirect=True, ids=ids, scope=scope)

def global_repeat_request(request):
    _, count = request.config.option.repeat_test
    if count <= 1: return None
    return request.param

def _add_repeat_tests(test_names, items):
    if not test_names: return
    test_names_list = []
    for testname in test_names:
        regex = r"^{}\[\D\S+\]".format(testname)
        for item in items:
            if re.match(regex, item.name):
                test_names_list.append(item.name)
    test_names.extend(test_names_list)
    return test_names

def modify_tests(config, items):
    test_names = []

    # create PID file
    create_pid_file()

    # load the tcmap - verify later
    tcm = tcmap.load(False)
    for warn in tcm.warnings:
        ftrace(warn)

    # extract infra tests
    prefix_items, suffix_items = batch_infra_tests_remove(items)

    # get the test names from CSV if specified
    tclist_method = "csv"
    test_names = _build_tclist_csv(config)
    _add_repeat_tests(test_names, items)

    # --tclist-csv superceeds --tclist-file
    if not test_names:
        tclist_method = "file"
        test_names = _build_tclist_file(config)
        _add_repeat_tests(test_names, items)

    # --tclist-file superceeds --tclist-map
    if not test_names:
        tclist_method = "map"
        test_names = _build_tclist_map(config, items)
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
        selected, deselected = _build_selected_tests(items, test_names, exclude_test_names)
        items[:] = selected
        config.hook.pytest_deselected(items=deselected)
        if tclist_method == "map":
            utils.banner("deselected tests cases", func=ftrace)
            for item in deselected:
                ftrace(item.nodeid)
            utils.banner(None, func=ftrace)

    # order the items based on test names list
    if test_names: order_items(items, test_names)

    # verify the tcmap
    tcmap.verify(items)

    # ignore the test cases that are already completed
    exclude_executed_tests(config, items)

    # check for known markers
    if not config.getoption("--ignore-known-markers", 0):
        read_known_markers(config, items)

    # add the dependency
    if not config.getoption("--ignore-dep-check", 0):
        build_dependency(config, items)

    # shuffile ine items for random order
    order = config.getoption("--random-order", 1)
    shuffle_items(items, order)

    # get the logs path
    [_, logs_path, _] = _get_logs_path()

    # save the function names in file
    func_list = []
    for item in items:
        func_list.append(item.location[2])
    out_file = paths.get_results_txt(logs_path)
    utils.write_file(out_file, "\n".join(func_list))

    # save non-mapped function names
    if not batch.is_master():
        tcm = tcmap.get()
        out_file = paths.get_file_path("tcmap_add_functions", "txt", logs_path)
        utils.write_file(out_file, "\n".join(tcm.non_mapped))
        out_file = paths.get_file_path("tcmap_remove_functions", "txt", logs_path)
        utils.write_file(out_file, "\n".join(missing_test_names_msg))

    # add infra only items
    batch_infra_tests_add(items, prefix_items, suffix_items)

def get_result_files(logs_path):
    (csv_files, retval) = ([], [])
    if batch.is_slave():
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

    [_, logs_path, _] = _get_logs_path()
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
    parts = name.split("[")
    if len(parts) > 1:
        suffix = "[{}".format(parts[1])
    else:
        suffix = ""
    for dep_name in marker.args:
        if selected_test_results[dep_name+suffix] != "Pass":
            errs.append(dep_name+suffix)
    return errs

def read_known_markers(config, items):
    must_fail_items.clear()
    for item in items:
        marker = item.get_closest_marker("must_fail")
        if marker:
            must_fail_items[item.nodeid] = None
    community_unsupported.clear()
    for item in items:
        marker = item.get_closest_marker("community_unsupported")
        if marker:
            community_unsupported[item.nodeid] = None
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
def set_current_result(res=None, desc=""):
    if not desc or not res:
        current_module.result_desc = ""
        current_module.result = "ConfigFail"
        current_test.result_desc = ""
        current_test.result = "ConfigFail"
    elif current_test.hook in ["test_module", "test_class"]:
        if not current_module.result_desc:
            current_module.result_desc = desc
            current_module.result = res
    elif current_test.hook in ["global_function", "test_function"]:
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
            if current_test.hook == "global_function" and current_test.result == "Unsupported":
                # to avoid showing confusing ConfigFail when marker identifies as unsupported
                pass
            elif current_test.hook == "test_function":
                wa._context.set_default_error("ConfigFail", "pretest_config_failed")
            elif wa.abort_module_msg:
                [res, desc] = ['SKIPPED', wa.abort_module_msg]
                desc = wa._context.report(res, "msg", desc)
                wa._test_log_finish(report.nodeid, func_name, res, desc, min_time)
            elif wa.abort_function_msg:
                [res, desc] = ['SKIPPED', wa.abort_function_msg]
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
        wa.event("Test Execution:", format_nodeid(report.nodeid))

def log_report_master(report, wa):
    batch.log_report_master(report)
    if report.when == "teardown":
        consolidate_results(wa.cfg.run_progress_report, True)

def session_start(session):
    if env.get("SPYTEST_LIVE_RESULTS", "1") == "1":
        bg_results.start(consolidate_results)

def get_rate(val, total):
    if total:
        return '{:.2%}'.format(val*1.0/total)
    return "0.00%"

def get_pass_rate(passed, notsupported, total):
    if env.get("SPYTEST_PASSRATE_EXCLUDING_UNSUPPORTED", "0") == "0":
        return get_rate(passed, total)
    return get_rate(passed, total-notsupported)

def get_non_pass_count(passed, notsupported, total):
    if env.get("SPYTEST_PASSRATE_EXCLUDING_UNSUPPORTED", "0") == "0":
        return total - passed
    return total - notsupported - passed

def read_all_result_names(logs_path, suffix, extn, dot="."):

    def result_base_file(val):
        val = os.path.basename(val)
        return val

    # get all the result file paths
    prefix = batch.get_node_prefix()
    suffix = "_{}".format(suffix) if suffix else ""
    fmt = "{}/{}*/*{}{}{}".format(logs_path, prefix, suffix, dot, extn)
    files = glob.glob(fmt)

    files.sort(key=result_base_file)

    return files

def read_all_results(logs_path, suffix):

    csv_files = read_all_result_names(logs_path, suffix, "csv")
    results = []
    for csv_file in csv_files:
        gw_name = os.path.basename(os.path.dirname(csv_file))
        for row in Result.read_report_csv(csv_file):
            row.insert(0, gw_name)
            results.append(row)

    return results

def concat_files(target, files, add_prefix=True):
    utils.write_file(target, "")
    for fp in files:
        for line in utils.read_lines(fp):
            prefix = "{},".format(os.path.basename(fp)) if add_prefix else ""
            utils.write_file(target, "{}{}\n".format(prefix, line), "a")

def get_header_info(index, cols, is_batch=True):
    links, indexes = {}, {}
    hdr = Result.get_header(index, is_batch)
    for col in cols: links[col] = []
    for col in cols: indexes[col] = hdr.index(col) - 1
    return links, indexes

def consolidate_results(progress=None, thread=False, count=None):

    # generate email report
    generate_email_report(count)

    # generate comparision report
    generate_compare_report()

    [_, logs_path, slave_id] = _get_logs_path()
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

    # functions
    results = read_all_results(logs_path, "functions")
    consolidated = sorted(results, key=itemgetter(5))
    results_csv = paths.get_results_csv(logs_path, True)
    Result.write_report_csv(results_csv, consolidated, ReportType.FUNCTIONS)
    ############## REMOVE ME ##########################
    results_csv2 = paths.get_file_path("result", "csv", logs_path, True)
    #Result.write_report_csv(results_csv2, consolidated, ReportType.FUNCTIONS)
    shutil.copy2(results_csv, results_csv2)
    ###################################################
    links, indexes = get_header_info(ReportType.FUNCTIONS, ["Node", "Module", "Result", "Syslogs"])
    for row in consolidated:
        node_name = row[indexes["Node"]]
        results_htm = paths.get_results_htm(node_name)
        syslog_htm = paths.get_syslog_htm(node_name)
        mlog = paths.get_mlog_path(row[indexes["Module"]], node_name)
        links["Node"].append(results_htm)
        links["Module"].append(mlog)
        links["Result"].append(mlog)
        links["Syslogs"].append(syslog_htm)
    results_htm = paths.get_results_htm(logs_path, True)
    align = {col: True for col in ["Module", "TestFunction", "Description", "Devices"]}
    Result.write_report_html(results_htm, consolidated, ReportType.FUNCTIONS, True, 4, links=links, align=align)
    save_failed_function_list(results_csv, 1)
    wa = get_work_area()
    if wa and wa._context:
        wa._context.run_progress_report(len(consolidated))
    tcresults_csv = paths.get_tc_results_csv(logs_path, True)
    generate_module_report(results_csv, tcresults_csv, 1)

    # testcases
    results = read_all_results(logs_path, "testcases")
    consolidated = sorted(results, key=itemgetter(5))
    tcresults_csv = paths.get_tc_results_csv(logs_path, True)
    Result.write_report_csv(tcresults_csv, consolidated, ReportType.TESTCASES)
    ############## REMOVE ME ##########################
    tcresults_csv2 = paths.get_file_path("tcresult", "csv", logs_path, True)
    #Result.write_report_csv(tcresults_csv2, consolidated, ReportType.TESTCASES)
    shutil.copy2(tcresults_csv, tcresults_csv2)
    ###################################################
    links, indexes = get_header_info(ReportType.TESTCASES, ["Node", "Result", "Module", "ResultType", "ExecutedOn"])
    for row in consolidated:
        node_name = row[indexes["Node"]]
        results_htm = paths.get_tc_results_htm(node_name)
        mlog = paths.get_mlog_path(row[indexes["Module"]], node_name)
        links["Node"].append(results_htm)
        links["Module"].append(mlog)
        links["Result"].append(mlog)
    results_htm = paths.get_tc_results_htm(logs_path, True)
    align = {col: True for col in ["Feature", "TestCase", "Description", "Function", "Module", "Devices"]}
    Result.write_report_html(results_htm, consolidated, ReportType.TESTCASES, True, 4, links=links, align=align)
    generate_features_report(results_csv, tcresults_csv, 1)

    # analisys - reuse from testcases report
    try:
        analisys_csv = paths.get_analisys_csv(logs_path, True)
        for rindex, row in enumerate(consolidated):
            engineer = "=vlookup($F{},Owner!$A:$X,4,False)".format(rindex+2)
            result_url_base = "http://10.59.137.5:9008/scheduler/jobs/11199"
            result_url_base = "<MODIFY-THIS>"
            log_url = "{}/{}".format(result_url_base, links["Module"][rindex])
            row[indexes["Module"]] = '=HYPERLINK("{}", "{}")'.format(log_url, row[indexes["Module"]])
            row.pop(indexes["ExecutedOn"])
            row.pop(indexes["ResultType"])
            row.pop(indexes["Node"])
            row.append("") # Analisis
            row.append("") # DUT Defect ID
            row.append("") # SQA Defect ID
            row.append(engineer)
        Result.write_report_csv(analisys_csv, consolidated, ReportType.ANALISYS, row_index=False)
    except Exception:
        if wa: wa.error("Failed to analisys report")
        else: print("Failed to analisys report")

    # syslogs
    results = read_all_results(logs_path, "syslog")
    consolidated = sorted(results, key=itemgetter(5))
    links, indexes = get_header_info(ReportType.SYSLOGS, ["Node", "Device", "Module"])
    for row in consolidated:
        node_name = row[indexes["Node"]]
        syslog_htm = paths.get_syslog_htm(node_name)
        dlog = paths.get_dlog_path(row[indexes["Device"]], node_name)
        mlog = paths.get_mlog_path(row[indexes["Module"]], node_name)
        links["Node"].append(syslog_htm)
        links["Device"].append(dlog)
        links["Module"].append(mlog)
    syslog_csv = paths.get_syslog_csv(logs_path, True)
    Result.write_report_csv(syslog_csv, consolidated, ReportType.SYSLOGS)
    syslog_htm = paths.get_syslog_htm(logs_path, True)
    align = {col: True for col in ["Module", "TestFunction", "LogMessage"]}
    Result.write_report_html(syslog_htm, consolidated, ReportType.SYSLOGS, True, links=links, align=align)

    # stats
    consolidated = read_all_results(logs_path, "stats")
    stats_csv = paths.get_stats_csv(logs_path, True)
    Result.write_report_csv(stats_csv, consolidated, ReportType.STATS)
    links, indexes = get_header_info(ReportType.STATS, ["Node", "Module"])
    for row in consolidated:
        node_name = row[indexes["Node"]]
        stats_htm = paths.get_stats_htm(node_name)
        links["Node"].append(stats_htm)
        mlog = paths.get_mlog_path(row[indexes["Module"]], node_name)
        links["Module"].append(mlog)
    stats_htm = paths.get_stats_htm(logs_path, True)
    align = {col: True for col in ["Module", "Function", "Description"]}
    Result.write_report_html(stats_htm, consolidated, ReportType.STATS, True, links=links, align=align)

    # sysinfo
    consolidated = read_all_results(logs_path, "sysinfo")
    sysinfo_csv = paths.get_sysinfo_csv(logs_path, True)
    Result.write_report_csv(sysinfo_csv, consolidated, ReportType.SYSINFO)
    links, indexes = get_header_info(ReportType.SYSINFO, ["Node", "Module"])
    for row in consolidated:
        node_name = row[indexes["Node"]]
        sysinfo_htm = paths.get_sysinfo_htm(node_name)
        links["Node"].append(sysinfo_htm)
        mlog = paths.get_mlog_path(row[indexes["Module"]], node_name)
        links["Module"].append(mlog)
    sysinfo_htm = paths.get_sysinfo_htm(logs_path, True)
    align = {col: True for col in ["Module"]}
    Result.write_report_html(sysinfo_htm, consolidated, ReportType.SYSINFO, True, links=links, align=align)

    # CLI files
    all_file = paths.get_cli_log("", logs_path, True)
    files = read_all_result_names(logs_path, "", "cli")
    concat_files(all_file, files, False)

    # CLI type files
    all_file = paths.get_cli_type_log("", logs_path, True)
    files = read_all_result_names(logs_path, "", "cli_type")
    concat_files(all_file, files)

    # alert files
    all_file = paths.get_alerts_log(logs_path, True)
    files = read_all_result_names(logs_path, "alerts", "log")
    concat_files(all_file, files, False)

def generate_compare_report():
    wa = get_work_area()
    [_, logs_path, slave_id] = _get_logs_path()
    if slave_id or not wa or not wa.cfg.results_compare:
        return

    cmp_csv = paths.get_file_path("result-compare", "csv", logs_path)
    err, cols, rows = compare.folders(wa.cfg.results_compare, logs_path)
    if not err:
        utils.write_csv_file(cols, rows, cmp_csv)
        html_file = os.path.splitext(cmp_csv)[0]+'.html'
        utils.write_html_table3(cols, rows, html_file, total=False)
    else:
        wa.error("Failed to create results comparison")
        wa.error(err)

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
        if key:
            report_data[key] = row

    all_reports = []

    # fill the stat values
    for index in range(0, count):
        report_file = files[index]
        if os.path.exists(report_file):
            lines = utils.read_lines(report_file)
            for line in lines:
                if "=" not in line: continue
                (key, val) = line.split('=')
                key = key.strip()
                val = val.strip()
                if key == "Software Version":
                    set_mail_build(val)
                if key in report_data:
                    report_data[key][index+1] = val

    # compute totals
    (pass_count, tc_count) = (0, 0)
    for key in report_cols:
        if count <= 1 or key not in report_data:
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
            except Exception:
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
        elif key in results_map or key == "Module Count":
            total = sum([int(i) for i in report_data[key][1:]])
            report_data[key][count+1] = total
        elif key in results_map or key == "Function Count":
            total = sum([int(i) for i in report_data[key][1:]])
            report_data[key][count+1] = total
        elif key in results_map or key == "Test Count":
            tc_count = sum([int(i) for i in report_data[key][1:]])
            report_data[key][count+1] = tc_count
        elif key in results_map or key == "Pass Count":
            pass_count = sum([int(i) for i in report_data[key][1:]])
            report_data[key][count+1] = pass_count
        elif key in results_map or key == "Pass Rate":
            report_data[key][count+1] = get_rate(pass_count, tc_count)
        elif key in results_map or key == "SysLog Count":
            total = sum([int(i) for i in report_data[key][1:]])
            report_data[key][count+1] = total
        else:
            report_data[key][count+1] = "NA"

    for key in report_cols:
        if key in report_data:
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
    [_, logs_path, slave_id] = _get_logs_path()
    if slave_id:
        return

    count = batch.get_member_count() if count is None else count
    if count <= 1 and not batch.is_batch():
        report_txt = paths.get_report_txt(logs_path)
        report_htm = paths.get_report_htm(logs_path)
        generate_email_report_files([report_txt], [], report_htm)
        return

    (files, nodes, report_txt) = ([],[], paths.get_report_txt())
    for index in range(0, count):
        node = batch.build_node_name(index)
        report_file = os.path.join(logs_path, node, report_txt)
        files.append(report_file)
        nodes.append(node)

    report_htm = paths.get_report_htm(logs_path, True)
    generate_email_report_files(files, nodes, report_htm)

def generate_module_report(results_csv, tcresults_csv, offset=0):
    [_, logs_path, _] = _get_logs_path()
    report_csv = paths.get_modules_csv(logs_path, bool(offset))
    report_htm = paths.get_modules_htm(logs_path, bool(offset))
    syslog_htm = paths.get_syslog_htm(None, bool(offset))
    rows = Result.read_report_csv(results_csv)
    module_logs = OrderedDict()
    sys_logs = OrderedDict()
    modules = OrderedDict()

    tc_all, tc_pass = OrderedDict(), OrderedDict()
    tc_rows = Result.read_report_csv(tcresults_csv)
    for row in tc_rows:
        module = row[offset+7]
        res = row[offset+2]
        tc_all[module] = tc_all.get(module, 0) + 1
        pass_incr = 1 if res == "Pass" else 0
        tc_pass[module] = tc_pass.get(module, 0) + pass_incr

    def init_module(name, fallback, ro_global):
        module = OrderedDict()
        module["Pass Rate"] = 0
        module["TC Count"] = tc_all.get(name, 0)
        module["TC Pass"] = tc_pass.get(name, 0)
        module["Sys Logs"] = 0
        module["CDT"] = 0
        module["FCLI"] = 0
        module["TSSH"] = 0
        module["DCNT"] = 0
        if ro_global == 3:
            module["RO"] = 1
        if fallback:
            module["UI"] = ""
        module["Func Count"] = 0
        module["Prolog Time"] = 0
        module["Epilog Time"] = 0
        module["Func Time"] = 0
        module["Exec Time"] = 0
        for res in results_map.values():
            if res: module[res] = 0
        if offset:
            module["Node"] = ""
        return module

    for row in rows:
        name = row[offset]
        fallback, ui_type = _get_module_ui(name)
        ro_global, ro_module = _get_module_random(name)
        if name not in modules:
            if offset == 0:
                module_logs[name] = paths.get_mlog_path(name)
                sys_logs[name] = paths.get_syslog_htm()
            else:
                module_logs[name] = paths.get_mlog_path(name, row[0])
                sys_logs[name] = paths.get_syslog_htm(row[0])
            modules[name] = init_module(name, fallback, ro_global)
        res = row[offset+2].upper()
        res = results_map.get(res, "")
        secs = utils.time_parse(row[offset+3])
        syslogs = utils.integer_parse(row[offset+5])
        syslogs = syslogs if syslogs else 0
        fcli = utils.integer_parse(row[offset+6])
        tryssh = utils.integer_parse(row[offset+7])
        num_duts = utils.integer_parse(row[offset+8])
        desc = row[offset+9]
        module = modules[name]
        if offset:
            module["Node"] = row[0].replace(batch.get_node_prefix(), "")
        if res in module:
            module[res] = module[res] + 1
            module["Sys Logs"] = module["Sys Logs"] + syslogs
            module["Func Time"] = module["Func Time"] + secs
            module["Func Count"] = module["Func Count"] + 1
            module["Pass Rate"] = get_pass_rate(module["Pass"], module["Not Supported"], module["Func Count"])
        else:
            if "Prolog" in desc:
                module["Prolog Time"] = module["Prolog Time"] + secs
                module["FCLI"] = fcli
                module["TSSH"] = tryssh
                module["DCNT"] = num_duts
                if ro_global == 3:
                    module["RO"] = ro_module
                if fallback:
                    module["UI"] = ui_type
            else:
                module["Epilog Time"] = module["Epilog Time"] + secs
            module["Sys Logs"] = module["Sys Logs"] + syslogs

    total = OrderedDict()
    for module in modules.values():
        module["Exec Time"] = module["Func Time"] + module["Prolog Time"] + module["Epilog Time"]
        module["CDT"] = module["Exec Time"] * module["DCNT"]
        for col in module:
            try:
                if col not in total: total[col] = module[col]
                elif col in ["UI", "RO", "Node"]: total[col] = ""
                else: total[col] = total[col] + module[col]
            except Exception: pass
        total["Pass Rate"] = get_pass_rate(total["Pass"], total["Not Supported"], total["Func Count"])

    def sort_func(y):
        try:
            col = env.get("SPYTEST_MODULE_REPORT_SORTER", "CDT")
            if col not in y[1]: col = "CDT"
            return float(str(y[1][col]).replace("%",""))
        except Exception:
            return 0

    # sort the modules on total execution time
    sorted_modules = sorted(modules.items(), key=sort_func)

    total_col = report_total_col
    if not total: total = init_module(total_col, False, False)
    modules[total_col] = total
    module_logs[total_col] = None
    sys_logs[total_col] = syslog_htm
    sorted_modules.append((total_col, total))

    (rows, cols, links) = ([],[],{"Module Name":[],"Sys Logs":[],"Node":[]})
    colors = {"Pass Rate":[], "Script Error":[], "Not Supported":[], "Env Fail":[], "Topo Fail":[], "TGen Fail":[]}
    align = {col: True for col in ["Module Name"]}
    for name, module in sorted_modules:
        for col in ["Prolog Time", "Epilog Time", "Func Time", "Exec Time", "CDT"]:
            module[col] = utils.time_format(int(module[col]))
        links["Sys Logs"].append(sys_logs[name] if module["Sys Logs"] else None)
        links["Module Name"].append(module_logs[name])
        links["Node"].append(os.path.dirname(module_logs[name]) if module_logs[name] else None)
        row = [name]
        row.extend(module.values())
        rows.append(row)
        cols = list(module.keys())
        cols.insert(0, "Module Name")
        colors["Pass Rate"].append(Result.get_color(module["Pass Rate"]))
        colors["Script Error"].append(Result.get_color_red(module["Script Error"]))
        colors["Not Supported"].append(Result.get_color_red(module["Not Supported"]))
        colors["Env Fail"].append(Result.get_color_red(module["Env Fail"]))
        colors["Topo Fail"].append(Result.get_color_red(module["Topo Fail"]))
        colors["TGen Fail"].append(Result.get_color_red(module["TGen Fail"]))
    utils.write_html_table3(cols, rows, report_htm, links=links, colors=colors, align=align)
    utils.write_csv_file(cols, rows, report_csv)

save_function_list_supported = False
def save_function_list(items, logs_path):
    if not save_function_list_supported:
        return
    func_list = []
    for item in items:
        func_list.append(item.location[2])
    out_file = paths.get_results_txt(logs_path)
    utils.write_file(out_file, "\n".join(func_list))

save_failed_function_list_supported = False
def save_failed_function_list(csv_file, offset=0):
    if not save_failed_function_list_supported:
        return
    func_list = []
    for row in Result.read_report_csv(csv_file):
        res = row[offset+2].upper()
        if not res in ["", "PASS"]:
            func_list.append(row[offset+1])
    out_file = os.path.splitext(csv_file)[0]+'_fails.txt'
    utils.write_file(out_file, "\n".join(func_list))

def generate_features_report(results_csv, tcresults_csv, offset=0):
    modules = OrderedDict()
    func_time = dict()
    func_syslogs = dict()
    tcmodmap = dict()
    tc_rows = Result.read_report_csv(tcresults_csv)
    func_rows = Result.read_report_csv(results_csv)
    for row in func_rows:
        name = row[offset]
        func = row[offset+1]
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
    total_script_error_count = 0
    total_script_error_rate = 0.00
    total_unsupported_count = 0
    total_unsupported_rate = 0.00
    total_time_taken = 0
    total_dut_time = 0
    total_syslog_count = 0
    for row in tc_rows:
        tc = row[offset+1]
        res = row[offset+2].upper()
        name = tcmap.get_comp(tc, row[offset])
        func = tcmap.get_func(tc, row[offset+6])

        if name not in components:
            components[name] = OrderedDict()
            component = components[name]
            component["PassRate"]  = 0.00
            component["Executed"]  = 0
            component["Pass"]  = 0
            component["Fail"]  = 0
            component["TimeTaken"]  = 0
            component["SysLogs"]  = 0
            component["EnvFail"]  = 0
            component["EnvFailRate"]  = 0.00
            component["Skipped"]  = 0
            component["SkippedRate"]  = 0.00
            component["ScriptError"]  = 0
            component["ScriptErrorRate"]  = 0.00
            component["Unsupported"]  = 0
            component["UnsupportedRate"]  = 0.00
            component["CDT"]  = 0
        else:
            component = components[name]
        if res == "PASS":
            component["Pass"] = component["Pass"]  + 1
            total_pass_count = total_pass_count + 1
        elif res == "UNSUPPORTED":
            component["Unsupported"] = component["Unsupported"]  + 1
            total_unsupported_count = total_unsupported_count + 1
        elif res in ["SKIPPED"]:
            component["Skipped"] = component["Skipped"]  + 1
            total_skipped_count = total_skipped_count + 1
        elif res in ["SCRIPT ERROR"]:
            component["ScriptError"] = component["ScriptError"]  + 1
            total_script_error_count = total_script_error_count + 1
        elif res in ["ENVFAIL", "TOPOFAIL", "TGENFAIL"]:
            component["EnvFail"] = component["EnvFail"]  + 1
            total_envfail_count = total_envfail_count + 1
        try:
            func_secs = func_time[func]
            syslogs = func_syslogs[func]
        except Exception:
            #print("=========== Failed to find function {} time -- ignore".format(func))
            func_secs = 0
            syslogs = 0
        try:
            module = modules[tcmodmap[func]]
            prolog_secs = module["PrologTime"]
            epilog_secs = module["EpilogTime"]
            module_syslogs = module["SysLogs"]
            num_duts = module["DCNT"]
        except Exception:
            #print("=========== Failed to find module {} time -- ignore".format(func))
            prolog_secs = 0
            epilog_secs = 0
            module_syslogs = 0
            num_duts = 1
        all_secs = func_secs + prolog_secs + epilog_secs
        component["Executed"] = component["Executed"] + 1
        component["Fail"] = get_non_pass_count(component["Pass"], component["Unsupported"], component["Executed"])
        component["PassRate"]  = get_pass_rate(component["Pass"], component["Unsupported"], component["Executed"])
        component["TimeTaken"] = component["TimeTaken"] + all_secs
        component["SysLogs"] = component["SysLogs"] + syslogs + module_syslogs
        component["EnvFailRate"]  = get_rate(component["EnvFail"], component["Executed"])
        component["SkippedRate"]  = get_rate(component["Skipped"], component["Executed"])
        component["ScriptErrorRate"]  = get_rate(component["ScriptError"], component["Executed"])
        component["UnsupportedRate"]  = get_rate(component["Unsupported"], component["Executed"])
        component["CDT"] = component["CDT"] + all_secs * num_duts
        total_executed = total_executed + 1
        total_pass_rate = get_pass_rate(total_pass_count, total_unsupported_count, total_executed)
        total_time_taken = total_time_taken + all_secs
        total_dut_time = total_dut_time + all_secs * num_duts
        total_syslog_count = total_syslog_count + syslogs + module_syslogs
        total_envfail_rate = get_rate(total_envfail_count, total_executed)
        total_skipped_rate = get_rate(total_skipped_count, total_executed)
        total_script_error_rate = get_rate(total_script_error_count, total_executed)
        total_unsupported_rate = get_rate(total_unsupported_count, total_executed)
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

    name = report_total_col
    components[name] = OrderedDict()
    component = components[name]
    component["PassRate"]  = total_pass_rate
    component["Executed"] = total_executed
    component["Pass"] = total_pass_count
    component["Fail"] = get_non_pass_count(total_pass_count, total_unsupported_count, total_executed)
    component["TimeTaken"]  = total_time_taken
    component["SysLogs"]  = total_syslog_count
    component["EnvFail"] = total_envfail_count
    component["EnvFailRate"]  = total_envfail_rate
    component["Skipped"] = total_skipped_count
    component["SkippedRate"]  = total_skipped_rate
    component["ScriptError"] = total_script_error_count
    component["ScriptErrorRate"]  = total_script_error_rate
    component["Unsupported"] = total_unsupported_count
    component["UnsupportedRate"] = total_unsupported_rate
    component["CDT"]  = total_dut_time

    # remove the columns that are not needed
    for name, component in components.items():
        del component["EnvFail"]
        del component["Skipped"]
        del component["ScriptError"]
        del component["Unsupported"]

    syslog_htm = paths.get_syslog_htm(None, bool(offset))
    (rows, cols, links) = ([],[],{"SysLogs":[]})
    colors = {"PassRate":[], "EnvFailRate":[], "SkippedRate":[], "ScriptErrorRate":[], "UnsupportedRate":[]}
    align = {col: True for col in ["Feature Name"]}
    for name, component in components.items():
        links["SysLogs"].append(syslog_htm if component["SysLogs"] else None)
        component["TimeTaken"] = utils.time_format(int(component["TimeTaken"]))
        component["CDT"] = utils.time_format(int(component["CDT"]))
        row = [name]
        row.extend(component.values())
        rows.append(row)
        cols = list(component.keys())
        cols.insert(0, "Feature Name")
        colors["PassRate"].append(Result.get_color(component["PassRate"]))
        colors["EnvFailRate"].append(Result.get_color_red(component["EnvFailRate"]))
        colors["SkippedRate"].append(Result.get_color_red(component["SkippedRate"]))
        colors["ScriptErrorRate"].append(Result.get_color_red(component["ScriptErrorRate"]))
        colors["UnsupportedRate"].append(Result.get_color_red(component["UnsupportedRate"]))

    [_, logs_path, _] = _get_logs_path()
    features_csv = paths.get_features_csv(logs_path, bool(offset))
    features_htm = paths.get_features_htm(logs_path, bool(offset))
    utils.write_html_table3(cols, rows, features_htm, links=links, colors=colors, align=align)
    utils.write_csv_file(cols, rows, features_csv)

def _report_data_generation(execution_start, execution_end,
                            session_init_time, total_tc_time):

    [_, logs_path, _] = _get_logs_path()

    tcresults_csv = paths.get_tc_results_csv(logs_path)
    tcresults_htm = paths.get_tc_results_htm(logs_path)
    results_csv = paths.get_results_csv(logs_path)
    results_htm = paths.get_results_htm(logs_path)

    generate_features_report(results_csv, tcresults_csv)
    tc_rows = Result.read_report_csv(tcresults_csv)
    links, indexes = get_header_info(ReportType.TESTCASES, ["Result", "Module"], False)
    for row in tc_rows:
        mlog = paths.get_mlog_path(row[indexes["Module"]])
        links["Module"].append(mlog)
        links["Result"].append(mlog)
    align = {col: True for col in ["Feature", "TestCase", "Description", "Function", "Module", "Devices"]}
    Result.write_report_html(tcresults_htm, tc_rows, ReportType.TESTCASES, False, links=links, align=align)

    save_failed_function_list(results_csv)
    generate_module_report(results_csv, tcresults_csv)
    func_rows = Result.read_report_csv(results_csv)
    links, indexes = get_header_info(ReportType.FUNCTIONS, ["Module", "Result", "Syslogs"], False)
    for row in func_rows:
        syslog_htm = paths.get_syslog_htm()
        mlog = paths.get_mlog_path(row[indexes["Module"]])
        links["Module"].append(mlog)
        links["Result"].append(mlog)
        links["Syslogs"].append(syslog_htm)
    align = {col: True for col in ["Module", "TestFunction", "Description", "Devices"]}
    Result.write_report_html(results_htm, func_rows, ReportType.FUNCTIONS, False, links=links, align=align)

    # syslogs
    syslog_csv = paths.get_syslog_csv(logs_path)
    syslog_htm = paths.get_syslog_htm(logs_path)
    syslog_rows = Result.read_report_csv(syslog_csv)
    links, indexes = get_header_info(ReportType.SYSLOGS, ["Device", "Module"], False)
    for row in syslog_rows:
        dlog = paths.get_dlog_path(row[indexes["Device"]])
        mlog = paths.get_mlog_path(row[indexes["Module"]])
        links["Device"].append(dlog)
        links["Module"].append(mlog)
    align = {col: True for col in ["Module", "TestFunction", "LogMessage"]}
    Result.write_report_html(syslog_htm, syslog_rows, ReportType.SYSLOGS, False, links=links, align=align)

    # stats
    stats_csv = paths.get_stats_csv(logs_path)
    stats_rows = Result.read_report_csv(stats_csv)
    links, indexes = get_header_info(ReportType.STATS, ["Module"], False)
    for row in stats_rows:
        mlog = paths.get_mlog_path(row[indexes["Module"]])
        links["Module"].append(mlog)
    stats_htm = paths.get_stats_htm(logs_path)
    align = {col: True for col in ["Module", "Function", "Description"]}
    Result.write_report_html(stats_htm, stats_rows, ReportType.STATS, False, links=links, align=align)

    # sysinfo
    sysinfo_csv = paths.get_sysinfo_csv(logs_path)
    sysinfo_rows = Result.read_report_csv(sysinfo_csv)
    links, indexes = get_header_info(ReportType.SYSINFO, ["Module"], False)
    for row in sysinfo_rows:
        mlog = paths.get_mlog_path(row[indexes["Module"]])
        links["Module"].append(mlog)
    sysinfo_htm = paths.get_sysinfo_htm(logs_path)
    align = {col: True for col in ["Module"]}
    Result.write_report_html(sysinfo_htm, sysinfo_rows, ReportType.SYSINFO, False, links=links, align=align)

    tc_result_dict = {}
    for key in results_map:
        if key:
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
    for key in results_map:
        if key:
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
        if col_result:
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

    logs_path = _get_logs_path()[1]
    root_logs_path = _get_logs_path(True)[1]

    if batch.configure(config, logs_path, root_logs_path):
        # create psuedo workarea for the master
        wa = _create_work_area2(config)
        tcm = tcmap.load()
        batch.set_tcmap(tcm)
        batch.set_logger(wa._context.log)

def unconfigure(config):

    if not batch.unconfigure(config):
        return

    # delete psuedo workarea for the master
    _delete_work_area()

def parse_batch_args(numprocesses, buckets, augment_modules_csv):
    [_, logs_path, _] = _get_logs_path()
    return batch.parse_args(numprocesses, buckets, logs_path, augment_modules_csv)

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
    #dbg_msg = "Devices used in the entire module till now {} {}:".format(fixturedef.scope, fixturedef.argname)
    #wa.event(dbg_msg, wa._get_devices_usage_list())
    pass

def format_nodeid(nodeid):
    module, func = paths.parse_nodeid(nodeid)
    return "{}::{}".format(module, func) if module else func

def get_request_module_id(request):
    mid = request.node.nodeid
    if not mid: mid = request.node.name
    return format_nodeid(mid)

def get_request_function_id(request):
    fid = request.node.nodeid
    if not fid: fid = request.node.name
    return format_nodeid(fid)

def hook_event(wa, name, fixturedef):
    wa.event(name, format_nodeid(fixturedef.baseid), fixturedef.argname)

def fixture_post_finalizer(fixturedef, request):
    dtrace("fixture_post_finalizer", fixturedef, request, current_test)

    wa = get_work_area()
    if not wa: return None

    if fixturedef.argname == "global_module_hook":
        current_test.phase = "global_module_finish"
        if not current_module.global_module_finalized:
            mid = get_request_module_id(request)
            result = "Pass: {}/{}".format(wa.module_tc_executed-wa.module_tc_fails, wa.module_tc_executed)
            wa.event("Framework Module Hook Finalize:", mid, result)
            current_module.global_module_finalized = True
            wa.log_time("Framework Module Hook Finilize")
            wa.module_log_init(None)
            used_devices = wa._get_devices_usage_list()
            wa.event("Devices used:", mid, len(used_devices), wa._get_devices_usage_list())
            batch.verify_bucket(mid, len(used_devices), wa.module_tc_fails)
            wa._set_device_usage_collection(False)
    elif fixturedef.argname == "global_function_hook":
        current_test.phase = "global_function_finish"
        fid = get_request_function_id(request)
        wa.event("Framework Function Hook Finalize:", fid)
        wa.log_time("Framework Function Hook Finilize")
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
            current_module.user_module_finalized = True
            hook_event(wa, "Module Hook Finalize:", fixturedef)
            wa._post_module_epilog(fixturedef.baseid, True)
            set_current_result()
            time_taken = get_elapsed(current_module.epilog_start, True, min_time)
            wa._context.publish2(fixturedef.baseid, None, None, time_taken, None, "", "Module Epilog")
            current_module.epilog_start = None
            wa.log_time("User Module {} Hook Finilize".format(fixturedef.baseid))
            log_devices_used_until_now(wa, fixturedef)
            wa._set_device_usage_collection(False)
    elif fixturedef.scope == "function":
        current_test.phase = "test_function_finish"
        hook_event(wa, "Function Hook Finalize:", fixturedef)
        wa._post_function_epilog(fixturedef.baseid)
        wa.log_time("User Function {} Hook Finilize".format(fixturedef.baseid))
        log_devices_used_until_now(wa, fixturedef)
        wa._set_device_usage_collection(False)
    elif fixturedef.scope == "class":
        current_test.phase = "test_class_finish"
        hook_event(wa, "Class Hook Finalize:", fixturedef)
        wa.log_time("User Class {} Hook Finilize".format(fixturedef.baseid))
    else:
        current_test.phase = "misc_finish"
        hook_event(wa, "Misc Hook Finalize:", fixturedef)
        wa.log_time("Misc {} Hook scope {} Finilize".format(fixturedef.baseid, fixturedef.scope))

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
            hook_event(wa, "SKIP Module Hook:", fixturedef)
            pytest.skip(wa.abort_module_msg)
        wa.log_time("User Module {} Hook Start".format(fixturedef.baseid))
        wa._pre_module_prolog(fixturedef.baseid)
        current_test.hook = "test_module"
        current_test.phase = "test_module_begin"
        set_current_result()
        hook_event(wa, "Module Hook:", fixturedef)
        wa.instrument(None, "pre-user-module")
        current_module.name = fixturedef.baseid
        current_module.name = mid
        current_test.nodeid = ""
        current_module.user_module_finished = False
        current_module.user_module_finalized = False
        log_devices_used_until_now(wa, fixturedef)
    elif fixturedef.scope == "function":
        fid = get_request_function_id(request)
        if current_module.result_desc:
            # report config fail when the module failed
            desc = wa._context.report("ConfigFail", "module_config_failed", current_module.result_desc)
            pytest.skip(desc)
        if wa.abort_module_msg:
            hook_event(wa, "SKIP Function Hook:", fixturedef)
            pytest.skip(wa.abort_module_msg)
        wa.log_time("User Function {} Hook Start".format(fixturedef.baseid))
        current_test.hook = "test_function"
        current_test.phase = "test_function_begin"
        current_test.nodeid = fid
        wa._pre_function_prolog(current_test.nodeid)
        hook_event(wa, "Function Hook:", fixturedef)
        wa.instrument(None, "pre-user-func")
        log_devices_used_until_now(wa, fixturedef)
    elif fixturedef.scope == "class":
        wa.log_time("User Class {} Hook Start".format(fixturedef.baseid))
        current_test.hook = "test_class"
        current_test.phase = "test_class_begin"
        hook_event(wa, "Class Hook:", fixturedef)
        current_module.user_class_finished = False
    else:
        wa.log_time("Misc {} Hook scope {} Start".format(fixturedef.baseid, fixturedef.scope))
        current_test.hook = "misc"
        current_test.phase = "misc_begin"
        hook_event(wa, "Misc Hook:", fixturedef)

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
        current_test.phase = "test_module_end"
        wa._set_device_usage_collection(False)
        log_devices_used_until_now(wa, fixturedef)
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
            hook_event(wa, "Module Hook Finish:", fixturedef)
            wa.log_time("User Module {} Hook end".format(fixturedef.baseid))
    elif fixturedef.scope == "function":
        current_test.phase = "test_function_end"
        log_devices_used_until_now(wa, fixturedef)
        wa.instrument(None, "post-user-func")
        wa._post_function_prolog(fixturedef.baseid)
        hook_event(wa, "Function Hook Finish:", fixturedef)
        wa.log_time("User Function {} Hook end".format(fixturedef.baseid))
    elif fixturedef.scope == "class":
        current_test.phase = "test_class_end"
        wa._set_device_usage_collection(False)
        if not wa.cfg.module_epilog:
            fixturedef._finalizers = []
        if not current_module.user_class_finished:
            current_module.user_class_finished = True
            # current_module.result can't be used as its value is ConfigFail
            # hence using current_module.result_desc
            if not current_module.result_desc:
                wa._post_class_prolog(fixturedef.baseid, True)
            else:
                wa._post_class_prolog(fixturedef.baseid, False)
        hook_event(wa, "Class Hook Finish:", fixturedef)
        wa.log_time("User Class {} Hook end".format(fixturedef.baseid))
    else:
        current_test.phase = "misc_end"
        hook_event(wa, "Misc Hook Finish:", fixturedef)
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
        if isend: return _delete_work_area()
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

