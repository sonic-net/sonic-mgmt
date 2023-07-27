import os
import re
import sys
import shutil
import psutil
import socket
import signal
import logging
from random import randint
from random import Random
from operator import itemgetter
from spytest.dicts import SpyTestDict
from spytest.testbed import Testbed
import spytest.spydist as dist
from spytest import paths
from spytest import env
from spytest import tcmap
from spytest import item_utils
from spytest.st_time import get_timenow
from spytest.st_time import get_elapsed
from spytest.st_time import get_timestamp
from spytest.st_time import parse as time_parse
from spytest.version import get_git_ver
import utilities.common as utils
import utilities.parallel as putils
# from utilities.tracer import Tracer


def trace_calls(event, data, fpath, line):
    utils.write_file("/tmp/batch.log", line + "\n", "a")


def batch_init_env(wa):
    wa.debug_level = env.getint("SPYTEST_BATCH_DEBUG_LEVEL", "0")
    wa.max_bucket_setups = env.getint("SPYTEST_BATCH_MAX_BUCKET_SETUPS", "200")


def batch_init():
    # Tracer.register(trace_calls, "batch", include=os.path.abspath(__file__))
    wa = SpyTestDict()
    wa.j2dict = SpyTestDict()
    wa.context = None
    wa.get_gw_name = {}
    wa.root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    wa.tests = os.path.join(wa.root, "tests")
    wa.workers = SpyTestDict()
    wa.sched = None
    wa.parse_logs = []
    wa.buckets = []
    wa.nes_nodeids = []
    wa.print_func = None
    wa.custom_scheduling = False
    wa.logs_path = ""
    wa.executed = SpyTestDict()
    wa.rerun_nodeids = SpyTestDict()
    wa.trace_file = None
    wa.logger = None
    wa.reverse_run_order = False
    wa.testbed_count = 1
    wa.custom_node_name = False
    wa.largest_bucket = 200
    wa.testbed_devices = {}
    wa.testbed_name = {}
    wa.device_last_used = {}
    wa.tclist_cache = {}
    wa.chip_coverate_history = {}
    wa.platform_coverate_history = {}

    # None disable backup/rerun nodes
    # 0 create same number of backup/rerun nodes
    # * create fixed number of backup/rerun nodes
    wa.backup_nodes = None
    wa.backup_nodes_multiplier = 1
    wa.rerun_nodes = None
    wa.rerun_list = []
    wa.rerun_nodes_multiplier = 1
    wa.default_topo_pref = 1
    wa.module_csv = None
    wa.module_rows = []
    wa.append_modules_csv = []
    wa.change_modules_csv = []
    wa.repeated_tests = None
    wa.abort_run = None
    wa.lock = putils.Lock()

    wa.make_scheduler = make_scheduler
    wa.configure_nodes = configure_nodes
    wa.trace = trace
    wa.debug = debug
    wa.begin_node = begin_node
    wa.configure_node = configure_node
    wa.finish_node = finish_node

    batch_init_env(wa)

    return wa


def load_module_csv():
    wa.module_csv, wa.module_rows, wa.repeated, wa.renamed = \
        tcmap.read_module_csv(wa.append_modules_csv, wa.change_modules_csv)
    return wa.module_rows, wa.repeated


def load_coverage_history():
    coverage_history_url = env.get("SPYTEST_COVERAGE_HISTORY_URL", "")
    if not coverage_history_url: return
    csv_file = os.path.join(wa.logs_path, "coverage_history.csv")
    utils.download_url(coverage_history_url, csv_file)
    wa.chip_coverate_history, wa.platform_coverate_history = \
        tcmap.read_coverage_history(csv_file)


def init_type_nodes():
    node_types = ["one", "two", "three", "four"]
    backup_nodes = env.get("SPYTEST_BATCH_BACKUP_NODES")
    if backup_nodes is None:
        pass
    elif backup_nodes == "none":
        wa.backup_nodes_multiplier = 0
        wa.backup_nodes = None
    elif backup_nodes in node_types:
        wa.backup_nodes_multiplier = node_types.index(backup_nodes) + 1
        wa.backup_nodes = 0
    elif not utils.is_integer(backup_nodes):
        print("SPYTEST_BATCH_BACKUP_NODES={} is invalid".format(backup_nodes))
        wa.backup_nodes = None
    else:
        wa.backup_nodes = int(backup_nodes)

    rerun_nodes = env.get("SPYTEST_BATCH_RERUN_NODES")
    if rerun_nodes is None:
        pass
    elif rerun_nodes == "none":
        wa.rerun_nodes_multiplier = 0
        wa.rerun_nodes = None
    elif rerun_nodes in node_types:
        wa.rerun_nodes_multiplier = node_types.index(rerun_nodes) + 1
    elif not utils.is_integer(rerun_nodes):
        print("SPYTEST_BATCH_RERUN_NODES={} is invalid".format(rerun_nodes))
        wa.rerun_nodes = None
    else:
        wa.rerun_nodes = int(rerun_nodes)

    batch_rerun = env.get("SPYTEST_BATCH_RERUN", None)
    if batch_rerun: wa.rerun_list = batch_rerun.split(",")


def is_deadnode_recovery():
    return bool(env.get("SPYTEST_BUCKETS_DEADNODE_RECOVERY", "1") != "0")


def ftrace(msg):
    if wa.logs_path:
        if not wa.trace_file:
            wa.trace_file = os.path.join(wa.logs_path, "batch_debug.log")
            utils.write_file(wa.trace_file, "")
        if msg:
            prefix = "{}: ".format(get_timestamp())
            # prefix = "{} {}".format(get_worker_id(), prefix)
            # prefix = "{} {}".format(os.getpid(), prefix)
            utils.write_file(wa.trace_file, "{}{}\n".format(prefix, msg), "a")


def debug(*args, **kwargs):
    if wa.debug_level > 1 and wa.logger:
        trace(*args, **kwargs)
    else:
        ftrace(" ".join(map(str, args)))


def verbose(*args, **kwargs):
    if wa.debug_level > 0:
        debug(*args, **kwargs)


def level_trace_try(lvl, *args, **kwargs):
    msg = " ".join(map(str, args))
    ftrace(msg)
    if wa.logger:
        wa.logger.log(lvl, msg)
        return
    if wa.print_func is None:
        wa.parse_logs.append(msg)
        return
    if wa.parse_logs:
        wa.print_func("\n")
        for log in wa.parse_logs:
            wa.print_func("{}\n".format(log))
        wa.parse_logs = []
    wa.print_func("\n{}\n".format(msg))


def level_trace(lvl, *args, **kwargs):
    try: level_trace_try(lvl, *args, **kwargs)
    except Exception: pass


def trace(*args, **kwargs):
    level_trace(logging.INFO, *args, **kwargs)


def warn(*args, **kwargs):
    level_trace(logging.WARNING, *args, **kwargs)


def check_worker_status(node_modules, collection):
    if wa.lock.acquire(timeout=120):
        max_time = env.getint("SPYTEST_BATCH_DEAD_NODE_MAX_TIME", "0")
        skip_testbed_info_update = False
        for worker in wa.workers.values():
            if worker.pid == 0: continue
            if worker.completed is not False: continue
            if not worker.started: continue
            if worker.last_report:
                elapsed = get_elapsed(worker.last_report, False)
            else:
                elapsed = 0
            try:
                status = psutil.Process(int(worker.pid)).status()
                executing = node_modules.get(worker.gw_node, [])
                if not executing:
                    executing = "???"
                elif executing[0] < len(collection):
                    executing = collection[executing[0]]
                else:
                    executing = executing[0]
                verbose("STATUS {} {} {} {} {}".format(worker.name, worker.pid, status, elapsed, executing))
                if status == psutil.STATUS_ZOMBIE:
                    trace("{} is Dead Zombie {}".format(worker.name, executing))
                    skip_testbed_info_update = True
                    finish_node_locked(None, worker.name, True, None, "Zombie")
                elif worker.terminated:
                    trace("Kill Stuck Node {} PID {}".format(worker.name, worker.pid))
                    try: os.kill(int(worker.pid), signal.SIGKILL)
                    except Exception: pass
                    finish_node_locked(None, worker.name, True, None, "Stuck")
                    skip_testbed_info_update = True
                elif max_time > 0 and elapsed > max_time:
                    trace("Terminate Stuck Node {} PID {} elapsed {} {}".format(worker.name, worker.pid, elapsed, executing))
                    psutil.Process(int(worker.pid)).terminate()
                    worker.terminated = True
            except Exception:
                trace("Exception while status check {}".format("\n".join(utils.stack_trace(None, True))))
        wa.lock.release()
        if not skip_testbed_info_update:
            _show_testbed_info()


def save_report():
    save_running_report()
    save_progress_report()
    save_pending_report()
    if wa.rerun_list:
        save_rerun_report()


def save_running_report():
    # prepare running rows
    header, rows = ['#', "Module", "Function", "TestCase", "Node", "Status"], []
    all_modules, all_functions, all_testcases, all_nodes = {}, {}, {}, {}
    for nodeid in wa.executed:
        [node_name, status] = wa.executed[nodeid]
        if status != "Queued": continue
        if not node_name or is_infra_test(nodeid): continue
        module, func = paths.parse_nodeid(nodeid)
        all_modules[module] = 1; all_functions[func] = 1; all_nodes[node_name] = 1
        for tcid in _get_tclist(func):
            all_testcases[tcid] = 1
            rows.append([len(rows) + 1, module, func, tcid, node_name, status])

    # create running links
    links = {"Module": [], "Node": [], "Status": [], }
    for row in rows:
        links["Node"].append(row[4])
        links["Status"].append(paths.get_session_log(row[4]))

    # save running files
    filepath = os.path.join(wa.logs_path, "batch_running.csv")
    utils.write_csv_file(header, rows, filepath)
    filepath = os.path.splitext(filepath)[0] + '.html'
    align = {col: True for col in ["Module", "Function", "TestCase"]}
    links["Node"].append(None); links["Status"].append(None)
    rows.append(["", len(all_modules), len(all_functions), len(all_testcases), len(all_nodes), ""])
    utils.write_html_table3(header, rows, filepath, links=links, align=align)


def save_progress_report():
    # prepare progress rows
    header, rows = ['#', "Module", "Function", "TestCase", "Node", "Status"], []
    all_modules, all_functions, all_testcases, all_nodes = {}, {}, {}, {}
    for nodeid in wa.executed:
        [node_name, status] = wa.executed[nodeid]
        if not node_name or is_infra_test(nodeid): continue
        module, func = paths.parse_nodeid(nodeid)
        all_modules[module] = 1; all_functions[func] = 1; all_nodes[node_name] = 1
        for tcid in _get_tclist(func):
            all_testcases[tcid] = 1
            rows.append([len(rows) + 1, module, func, tcid, node_name, status])

    # create progress links
    links = {"Module": [], "Node": [], "Status": [], }
    for row in rows:
        links["Node"].append(row[4])
        links["Status"].append(paths.get_session_log(row[4]))

    # save progress files
    filepath = os.path.join(wa.logs_path, "batch_progress.csv")
    utils.write_csv_file(header, rows, filepath)
    filepath = os.path.splitext(filepath)[0] + '.html'
    align = {col: True for col in ["Module", "Function", "TestCase"]}
    links["Node"].append(None); links["Status"].append(None)
    rows.append(["", len(all_modules), len(all_functions), len(all_testcases), len(all_nodes), ""])
    utils.write_html_table3(header, rows, filepath, links=links, align=align)


def save_pending_report():
    # prepare pending rows
    header, rows = ['#', "Module", "Function", "TestCase", "Nodes"], []
    all_modules, all_functions, all_testcases = {}, {}, {}
    for nodeid in wa.executed:
        [node_name, _] = wa.executed[nodeid]
        if node_name or is_infra_test(nodeid): continue
        module, func = paths.parse_nodeid(nodeid)
        nodes = wa.sched.find_matching_nodes(module)
        all_modules[module] = 1; all_functions[func] = 1
        for tcid in _get_tclist(func):
            all_testcases[tcid] = 1
            rows.append([len(rows) + 1, module, func, tcid, nodes])

    # save pending files
    filepath = os.path.join(wa.logs_path, "batch_pending.csv")
    utils.write_csv_file(header, rows, filepath)
    filepath = os.path.splitext(filepath)[0] + '.html'
    align = {col: True for col in ["Module", "Function", "TestCase", "Nodes"]}
    rows.append(["", len(all_modules), len(all_functions), len(all_testcases), ""])
    utils.write_html_table3(header, rows, filepath, align=align)


def save_rerun_report():

    # prepare rerun rows
    header, rows = ['#', "Module", "Function", "TestCase", "Nodes"], []
    all_modules, all_functions, all_testcases = {}, {}, {}
    for nodeid in wa.rerun_nodeids:
        if is_infra_test(nodeid): continue
        module, func = paths.parse_nodeid(nodeid)
        nodes = wa.sched.find_matching_nodes(module)
        all_modules[module] = 1; all_functions[func] = 1
        for tcid in _get_tclist(func):
            all_testcases[tcid] = 1
            rows.append([len(rows) + 1, module, func, tcid, nodes])

    # save rerun files
    filepath = os.path.join(wa.logs_path, "batch_rerun.csv")
    utils.write_csv_file(header, rows, filepath)
    filepath = os.path.splitext(filepath)[0] + '.html'
    align = {col: True for col in ["Module", "Function", "TestCase", "Nodes"]}
    rows.append(["", len(all_modules), len(all_functions), len(all_testcases), ""])
    utils.write_html_table3(header, rows, filepath, align=align)


def save_finished_testbeds():

    # 0: disable 1: save free pods 2: save free devices
    cfg = env.get("SPYTEST_BATCH_SAVE_FREE_DEVICES", "1")
    if cfg not in ["1", "2"]: return

    all_workers = list(wa.workers.values())

    # prepare all devices list
    for worker in all_workers:
        if worker.testbed not in wa.testbed_devices:
            devices = worker.tb_obj.get_device_names("DUT")
            wa.testbed_devices[worker.testbed] = devices
            wa.testbed_name[worker.testbed] = worker.tb_obj.get_name()

    # debug("wa.testbed_devices {}".format(wa.testbed_devices))

    # assume all root/pod testbeds are free
    free_pod = {}
    for worker in all_workers:
        if not worker.parent_testbed:
            free_pod[worker.testbed] = True

    # mark the root/pod testbeds are not free if any of their devices are in use
    for worker in all_workers:
        if worker.completed is False:
            testbed = worker.parent_testbed or worker.testbed
            free_pod[testbed] = False

    # create/update free pod devices
    free_pod_devices, free_pod_devices2 = [], []
    for worker in all_workers:
        if not worker.parent_testbed and free_pod[worker.testbed]:
            devices = wa.testbed_devices[worker.testbed]
            free_pod_devices.extend(devices)
            for device in devices:
                name = wa.testbed_name[worker.testbed]
                if name:
                    dev_name = "{}:{}".format(name, device)
                    free_pod_devices2.append(dev_name)

    # save the free pod devices into file
    if cfg == "1" and free_pod_devices:
        filepath = os.path.join(wa.logs_path, "batch_free_devices.txt")
        old = utils.read_lines(filepath); old.sort()
        free_pod_devices.sort(); content = "\n".join(free_pod_devices)
        if old == free_pod_devices:
            debug("SKIP update free pod devices {}".format(free_pod_devices))
        else:
            trace("update free pod devices {}".format(free_pod_devices))
            utils.write_file(filepath, content)

    # save the free pod devices into file
    if cfg == "1" and free_pod_devices2:
        filepath = os.path.join(wa.logs_path, "batch_free_devices2.txt")
        old = utils.read_lines(filepath); old.sort()
        free_pod_devices2.sort(); content = "\n".join(free_pod_devices2)
        if old == free_pod_devices2:
            debug("SKIP update free pod devices {}".format(free_pod_devices2))
        else:
            trace("update free pod devices {}".format(free_pod_devices2))
            utils.write_file(filepath, content)

    # assume all devies are free
    free_devices = {}
    for worker in all_workers:
        for device in wa.testbed_devices[worker.testbed]:
            free_devices[device] = True

    # mark the device not free if it in use in any worker
    for worker in all_workers:
        if worker.completed is False:
            for device in wa.testbed_devices[worker.testbed]:
                free_devices[device] = False

    # save the free devices into file
    if cfg == "2" and free_devices:
        filepath = os.path.join(wa.logs_path, "batch_free_devices.txt")
        old = utils.read_lines(filepath); old.sort();
        free_devices_list = [k for k, v in free_devices.items() if v]
        free_devices_list.sort(); content = "\n".join(free_devices_list)
        if old == free_devices_list:
            debug("SKIP update free devices {}".format(free_devices_list))
        else:
            trace("update free devices {}".format(free_devices_list))
            utils.write_file(filepath, content)


def report(op, nodeid, node_name):
    op = op.lower()
    if op == "load":
        wa.executed[nodeid] = ["", "Pending"]
        return
    elif op == "reload":
        wa.executed[nodeid] = ["", "PendingAgain"]
        return
    elif op == "rerun":
        wa.executed[nodeid] = ["", "PendingReRun"]
        wa.rerun_nodeids[nodeid] = ["", "PendingReRun"]
    elif op == "nes-partial":
        wa.executed[nodeid] = ["", "PartialNes"]
    elif op == "nes-full":
        wa.executed[nodeid] = ["", "FullNes"]
    elif op == "add":
        wa.executed[nodeid] = [node_name, "Queued"]
        return
    elif op == "remove":
        wa.executed.pop(nodeid, None)
        return
    elif op == "finish":
        if nodeid in wa.executed:
            wa.executed[nodeid] = [node_name, "Completed"]
    try:
        save_report()
        _show_testbed_info(False)
    except Exception as exp:
        print(exp)


def shutdown():
    if is_master():
        trace("batch shutdown")


class SpyTestScheduling(object):
    def __init__(self, config, wa, count):
        self.config = config
        if count:
            self.count = count
        elif config:
            self.count = len(config.getvalue("tx"))
        else:
            self.count = 1
        self.order_support = True
        self.topo_support = True
        self.node_modules = SpyTestDict()
        self.collections = {}
        self.collection = []
        self.collection_is_completed = False
        self.main_modules = SpyTestDict()
        self.rerun_modules = SpyTestDict()
        self.rerun_nodeids = {}
        self.use_basenames = False
        self.module_data = {}
        self.base_names = {}
        self.wa = wa
        self.default_bucket = int(env.get("SPYTEST_BATCH_DEFAULT_BUCKET", "1"))
        self.default_order = 2
        self.default_topo = ""
        self.max_order = self.default_order
        self._load_buckets()

        self.test_spytest_infra_first = None
        self.test_spytest_infra_second = None
        self.test_spytest_infra_last = None

    def _list_files(self, entry, pattern="*"):
        path = os.path.join(wa.repeated_tests, entry) if wa.repeated_tests else entry
        if os.path.isfile(path):
            return [entry]
        return utils.list_files(entry, pattern)

    def _load_buckets(self):
        for row in wa.module_rows or load_module_csv()[0]:
            if not row or row[0].startswith("#"): continue
            if len(row) < 3:
                print("1. Invalid module params: {}".format(row))
                continue
            tpref = utils.integer_parse(row[2])
            if tpref is None:
                tpref = wa.default_topo_pref
            else:
                row.pop(2)
            if len(row) < 3:
                print("2. Invalid module params: {}".format(row))
                continue
            topo = self.default_topo
            if len(row) > 3: topo = ",".join([str(i).strip() for i in row[3:]])
            bucket, order, name0 = [str(i).strip() for i in row[:3]]
            if bucket.startswith("#"): continue
            verbose("3. Module params: {} {} {} {}".format(bucket, order, name0, topo))
            for name in self._list_files(name0, "test_*.py"):
                md = self.get_module_data(name, tpref)
                md.bucket = utils.integer_parse(bucket, self.default_bucket)
                md.order = utils.integer_parse(order, self.default_order)
                md.topo = topo
                md.tpref = tpref
                if self.max_order < md.order:
                    self.max_order = md.order
                self.set_module_data(md, name)
                basename = os.path.basename(name)
                if basename in self.base_names:
                    trace("duplicate basename {}".format(basename))
                else:
                    self.base_names[basename] = name

    def set_worker_node_locked(self, node, value):
        gid = get_gw_name(node.gateway)
        worker = self.wa.workers[gid]
        worker.gw_node = value
        worker.gw_node_time = get_timenow()

    def add_node(self, node):
        debug("================ add_node {} ===========".format(node))
        wa.lock.acquire()
        if node not in self.node_modules:
            self.node_modules[node] = []
        self.set_worker_node_locked(node, node)
        self.collection_is_completed = False
        wa.lock.release()

    def remove_node(self, node):
        debug("================ remove_node {} ===========".format(node))
        wa.lock.acquire()
        self.node_modules.pop(node, None)
        self.set_worker_node_locked(node, None)
        wa.lock.release()

    def add_restarted_node(self, node):
        gid = get_gw_name(node.gateway)
        debug("================ add_restarted_node {} ===========".format(gid))
        for minfo in self.main_modules.values():
            if gid in minfo.nodes:
                minfo.nodes.append(gid)
        self._show_module_info()

    def _is_active_locked(self, node):
        gid = get_gw_name(node.gateway)
        worker = self.wa.workers[gid]
        if worker.excluded: retval = False
        elif not worker.completed: retval = True
        elif not worker.started: retval = True
        else: retval = False
        verbose("================ active({}) = {} ===========".format(gid, retval))
        return retval

    @property
    def tests_finished(self):
        if not self.collection_is_completed:
            return False
        rv1, rv2 = True, True
        wa.lock.acquire()
        for node, modules in self.node_modules.items():
            if self._is_active_locked(node):
                rv1 = False
        for node, modules in self.node_modules.items():
            if len(modules) >= 2:
                rv2 = False
        wa.lock.release()
        verbose("================ tests_finished {} {} ===========".format(rv1, rv2))
        return bool(rv1 and rv2)

    @property
    def nodes(self):
        return list(self.node_modules.keys())

    @property
    def has_pending(self):
        wa.lock.acquire()
        rv = False
        for node, modules in self.node_modules.items():
            if self._is_active_locked(node):
                rv = True
            elif modules:
                rv = True
        wa.lock.release()
        debug("================ has_pending {} ===========".format(rv))
        return rv

    def _get_topo_pref(self, mname, default=None):
        default = default or wa.default_topo_pref
        if mname not in self.module_data: return [default]
        all_tpref = list(self.module_data[mname].keys())
        random_tpref = [tpref for tpref in all_tpref]
        seed = utils.get_random_seed()
        Random(seed).shuffle(random_tpref)
        user_tpref = env.get("SPYTEST_BATCH_TOPO_PREF", "0").split(",")
        if default not in user_tpref: user_tpref.append(default)
        retval = []
        for tpref in user_tpref:
            tpref_int = utils.integer_parse(tpref)
            tpref_int = default if tpref_int is None else tpref_int
            if tpref_int != 0:
                if tpref_int in all_tpref and tpref_int not in retval:
                    retval.append(tpref_int)
            else:
                for tpref in random_tpref:
                    if tpref not in retval:
                        retval.append(tpref)
        if len(retval) > 1:
            trace("{} Topo Pref {}".format(mname, retval))
        return retval

    def set_module_data(self, md, mname):
        if mname not in self.module_data:
            self.module_data[mname] = SpyTestDict()
        self.module_data[mname][md.tpref] = md

    def get_module_data(self, mname, tpref=None):
        tpref = tpref or wa.default_topo_pref
        md = SpyTestDict()
        if mname in self.module_data and tpref in self.module_data[mname]:
            md.topo = self.module_data[mname][tpref].topo
            md.order = self.module_data[mname][tpref].order
            md.bucket = self.module_data[mname][tpref].bucket
            md.tpref = self.module_data[mname][tpref].tpref
            md.default = False
        else:
            md.topo = self.default_topo
            md.order = self.default_order
            md.bucket = self.default_bucket
            md.tpref = tpref
            md.default = True
        return md

    def add_nodeid(self, nodeid, action, modules):
        report(action, nodeid, "")
        nodeid2 = item_utils.map_nodeid(nodeid)
        mname = nodeid2.split("::", 1)[0]
        if mname in wa.renamed:
            warn("Node ID {} is renamed in repeat".format(nodeid))
            return None
        md = self.get_module_data(mname)
        if self.use_basenames and md.default:
            mname = os.path.basename(mname)
            md = self.get_module_data(mname)
        if self.use_basenames and mname in self.base_names:
            mname = self.base_names[mname]
            md = self.get_module_data(mname)
        if nodeid not in self.collection:
            warn("Node ID {} is invalid".format(nodeid))
            return None
        if mname not in modules:
            modules[mname] = SpyTestDict()
            module = modules[mname]
            module.node_indexes = []
            module.nodes = []
            if md.default and action == "load":
                msg = "Module {} is not found in {} for nodeid {}"
                warn(msg.format(mname, wa.module_csv, nodeid))
        modules[mname].node_indexes.append(self.collection.index(nodeid))
        modules[mname].used_tpref = md.tpref
        return mname

    def add_node_collection(self, node, collection):
        gid = get_gw_name(node.gateway)
        debug("[{}]: ===== Collected {}".format(gid, len(collection)))
        self.collections[node] = collection
        if len(self.collections) < self.count:
            debug("[{}]: ===== Wait for all other node collections".format(gid))
            return

        # check if this is restarted node
        if self.collection:
            self.add_restarted_node(node)
            return

        if self.collection_is_completed: return

        nodes = list(self.collections.keys())
        indexes = list(self.collections.values())
        all_ok = True
        for i in range(1, len(indexes)):
            if indexes[0] != indexes[i]:
                all_ok = False
                warn("node {} collection differs from {} Counts {} vs {}".format(nodes[0], nodes[i], len(indexes[0]), len(indexes[i])))
                if len(indexes[0]) == len(indexes[i]):
                    for j, (first, second) in enumerate(zip(indexes[0], indexes[i])):
                        if first != second:
                            warn("{} {}/{} != {}/{}".format(j, nodes[0], first, nodes[i], second))
        if not all_ok:
            abort_run(1, "Collection Count Mismatch")

        if is_debug_collection():
            for index, nodeid in enumerate(collection):
                verbose("Collection: {} {}".format(index, nodeid))
            abort_run(1, "Collection Debug Exit")

        # last node has registered the collection
        # read tcmap again to use the inventory info
        tcmap.save(filepath=os.path.join(wa.logs_path, "tcmap-original.csv"), printerr=wa.trace)
        tcmap.load(tcmap_csv=os.path.join(wa.logs_path, gid, "tcmap.csv"))
        wa.tclist_cache = {}
        wa.tcmap = tcmap.get()
        tcmap.save(filepath=os.path.join(wa.logs_path, "tcmap-collected.csv"), printerr=wa.trace)

        # generate module list
        self.collection = collection
        for index, nodeid in enumerate(collection):
            debug("Collection: {} {}".format(index, nodeid))
            rv = is_infra_test(nodeid)
            if rv == 1:
                self.test_spytest_infra_first = self.collection.index(nodeid)
            elif rv == 2:
                self.test_spytest_infra_second = self.collection.index(nodeid)
            elif rv == 3:
                self.test_spytest_infra_last = self.collection.index(nodeid)
            else:
                self.add_nodeid(nodeid, "load", self.main_modules)
        report("save", "", "")
        self.update_matching_nodes(self.main_modules, True)
        for mname, minfo in self.main_modules.items():
            debug("Collection: {} {} {}".format(mname, ",".join(minfo.nodes),
                  ",".join([str(i) for i in minfo.node_indexes])))
        self.collection_is_completed = True

        # start worker monitoring
        poll_time = env.getint("SPYTEST_BATCH_POLL_STATUS_TIME", "0")
        if poll_time > 0:
            max_time = env.getint("SPYTEST_BATCH_DEAD_NODE_MAX_TIME", "0")
            trace("Start Monitoring poll_time={} max_time={} DBG={}".format(poll_time, max_time, wa.debug_level))
            putils.callback(poll_time, 10, check_worker_status, self.node_modules, self.collection)

    def find_active_nodes(self, names):
        active = []
        for name in names:
            if self.wa.workers[name].completed is False:
                active.append(name)
        return active

    def find_matching_nodes(self, name):
        if name not in self.main_modules:
            return ""
        nodes = self.main_modules[name].nodes
        nodes = self.find_active_nodes(nodes)
        return " ".join(nodes)

    def update_matching_nodes(self, modules, init):

        # smallest,largest,larger,equal
        match_order = env.get("SPYTEST_BATCH_MATCHING_BUCKET_ORDER", "larger,largest")
        match_order_list = match_order.split(",")
        if len(match_order_list) == 1 and match_order_list[0] == "exact":
            only_exact_match = True
            match_order_list = ["matching"]
        else:
            only_exact_match = False
            match_order_list.insert(0, "matching")

        nes_modules = []
        for mname, minfo in modules.items():
            minfo.nodes = []

            for model in match_order_list:
                if model not in ["matching", "equal", "larger", "largest", "smallest"]:
                    msg = "unknown batch matching bucket order model {}".format(model)
                    debug(msg)
                    continue
                for tpref in self._get_topo_pref(mname):
                    if not minfo.nodes and model in ["matching"]:  # pickup testbed in the matching bucket
                        md = self.get_module_data(mname, tpref)
                        trace("TRY-1 {} {} {} {}".format(mname, md.bucket, tpref, md.topo))
                        for worker in wa.workers.values():
                            if wa.largest_bucket == worker.bucket: continue
                            if md.bucket <= worker.bucket and md.bucket >= worker.min_bucket:
                                if only_exact_match and md.bucket != worker.bucket: continue
                                debug("MATCH-1 {} {} {} {} with {} {} {} {}".format(mname, md.bucket, tpref, md.topo,\
                                                                                    worker.name, worker.bucket, worker.min_bucket, worker.tb_obj.get_topo(name0=False)))
                                if md.topo:
                                    dbg = env.getint("SPYTEST_BATCH_DEBUG_ENSURE_MIN_TOPOLOGY")
                                    [errs, _] = worker.tb_obj.ensure_min_topology_norandom(md.topo, match_dut_name=1, debug=dbg)
                                    worker.tb_obj.reset_derived()
                                    if errs:
                                        msg = "non matching testbed {} to execute bucket {} {} {}"
                                        debug(msg.format(worker.name, md.bucket, mname, md.topo))
                                        continue
                                msg = "matched testbed {} to execute bucket {} {} {}"
                                trace(msg.format(worker.name, md.bucket, mname, md.topo))
                                minfo.nodes.append(worker.name)
                                minfo.used_tpref = tpref

                for tpref in self._get_topo_pref(mname):
                    if not minfo.nodes and model in ["equal"]:  # pickup testbed in the same bucket
                        md = self.get_module_data(mname, tpref)
                        trace("TRY-2 {} {} {}".format(mname, tpref, md.topo))
                        for worker in wa.workers.values():
                            if md.bucket <= worker.bucket and md.bucket >= worker.min_bucket:
                                if not minfo.nodes:
                                    msg = "Using same bucket {} testbed {} to execute {} {}"
                                    trace(msg.format(worker.bucket, worker.name, mname, md.topo))
                                minfo.nodes.append(worker.name)
                                minfo.used_tpref = tpref

                if not minfo.nodes and model in ["smallest"]:  # pickup testbed in the smallest bucket
                    cmp_bucket = self.wa.min_bucket
                    for worker in wa.workers.values():
                        if cmp_bucket <= worker.bucket and cmp_bucket >= worker.min_bucket:
                            if not minfo.nodes:
                                msg = "Using smallest bucket {} testbed {} to execute {}"
                                trace(msg.format(worker.bucket, worker.name, mname))
                            minfo.nodes.append(worker.name)
                            minfo.used_tpref = wa.default_topo_pref

                if not minfo.nodes and model in ["larger"]:  # pickup testbed in the larger bucket
                    for tpref in self._get_topo_pref(mname):
                        md = self.get_module_data(mname, tpref)
                        trace("TRY-3 {} {} {}".format(mname, tpref, md.topo))
                        for bucket in range(md.bucket + 1, self.wa.largest_bucket):
                            if minfo.nodes: break
                            for worker in wa.workers.values():
                                if worker.bucket != bucket: continue
                                dbg = env.getint("SPYTEST_BATCH_DEBUG_ENSURE_MIN_TOPOLOGY")
                                [errs, _] = worker.tb_obj.ensure_min_topology_norandom(md.topo, debug=dbg)
                                worker.tb_obj.reset_derived()
                                if errs: continue
                                if not minfo.nodes:
                                    msg = "Using higher bucket {} testbed {} to execute {} {}"
                                    trace(msg.format(worker.bucket, worker.name, mname, md.topo))
                                minfo.nodes.append(worker.name)
                                minfo.used_tpref = tpref

                if not minfo.nodes and model in ["largest"]:  # pickup testbed in the largest bucket
                    cmp_bucket = self.wa.max_bucket
                    for worker in wa.workers.values():
                        if cmp_bucket <= worker.bucket and cmp_bucket >= worker.min_bucket:
                            if not minfo.nodes:
                                msg = "Using largest bucket {} testbed {} to execute {}"
                                trace(msg.format(worker.bucket, worker.name, mname))
                            minfo.nodes.append(worker.name)
                            minfo.used_tpref = wa.default_topo_pref

            if not minfo.nodes:
                for item_index in minfo.node_indexes:
                    nes_modules.append(mname)
                    self.wa.nes_nodeids.append(self.collection[item_index])

        if init:
            for mname, minfo in modules.items():
                if mname in nes_modules:
                    msg = "NO suitable testbed in bucket {} to execute {}"
                    md = self.get_module_data(mname, minfo.used_tpref)
                    trace(msg.format(md.bucket, mname))
            self._show_module_info()

        _show_testbed_info()

    def _show_module_info(self, show=True):
        header = ["#", "Module", "Bucket", "Functions", "Tests", "Pref", "Topology", "Nodes"]
        mcount, fcount, tcount, rows = 0, 0, 0, []
        for mname, minfo in self.main_modules.items():
            count1, count2 = len(minfo.node_indexes), 0
            for index in minfo.node_indexes:
                func = paths.parse_nodeid(self.collection[index])[1]
                count2 = count2 + len(_get_tclist(func.replace("::", ".")))
            mcount = mcount + 1
            fcount = fcount + count1
            tcount = tcount + count2
            nodes = " ".join(minfo.nodes)
            md = self.get_module_data(mname, minfo.used_tpref)
            mname2 = paths.get_mlog_basename(mname)
            rows.append([mname2, md.bucket, count1, count2, md.tpref, md.topo, nodes])
        rows = sorted(rows, key=itemgetter(1), reverse=True)
        for index, row in enumerate(rows):
            row.insert(0, index + 1)

        if is_deadnode_recovery():
            # save the batch status
            filepath = os.path.join(wa.logs_path, "batch_modules.csv")
            rows.append(["", "", "", fcount, tcount, "", "", ""])
            utils.write_csv_file(header, rows, filepath)
            filepath = os.path.join(wa.logs_path, "batch_modules.html")
            align = {col: True for col in ["Module", "Topology", "Nodes"]}
            utils.write_html_table3(header, rows, filepath, align=align)
        elif show:
            trace("Modules: {} Functions: {} Tests: {}".format(mcount, fcount, tcount))
            trace("\n" + utils.sprint_vtable(header, rows))

    def mark_test_complete(self, node, item_index, duration=0):
        wa.lock.acquire()
        name = get_gw_name(node.gateway)
        item_list = self.collection[item_index]
        if item_index in self.node_modules[node]:
            self.node_modules[node].remove(item_index)
            report("finish", item_list, name)
            debug("[{}]: ===== Completed {} {}".format(name, item_index, item_list))
        else:
            trace("[{}]: ===== Already Completed {} {}".format(name, item_index, item_list))
        self._schedule_node_locked(node)
        debug("[{}]: ===== NewList {}".format(name, self.node_modules[node]))
        wa.lock.release()

    def _assign_pretest(self, node):
        name = get_gw_name(node.gateway)
        worker = self.wa.workers[name]
        if worker.load_infra_tests and env.match("SPYTEST_BATCH_PREPEND_INFRA_TEST", "1", "1"):
            worker.load_infra_tests = False
            if self.test_spytest_infra_first is not None and \
               self.test_spytest_infra_second is not None:
                self.node_modules[node].append(self.test_spytest_infra_first)
                self.node_modules[node].append(self.test_spytest_infra_second)
                trace("[{}]: ===== Assigned Pre-Tests".format(name))
                return True
        return False

    def _assign_test(self, node, modules=None):
        name = get_gw_name(node.gateway)
        worker = self.wa.workers[name]
        modules = modules or self.main_modules
        orders = list(range(0, self.max_order + 1))
        if env.match("SPYTEST_BATCH_ORDER_HIGH2LOW", "1", "1"):
            orders = reversed(orders)
        for order in orders:
            for mname, minfo in modules.items():
                if name not in minfo.nodes: continue
                md = self.get_module_data(mname, minfo.used_tpref)
                if self.order_support and md.order != order:
                    continue
                if self._assign_pretest(node):
                    return True
                del modules[mname]
                self.node_modules[node].extend(minfo.node_indexes)
                if self.test_spytest_infra_last is not None:
                    if env.match("SPYTEST_BATCH_APPEND_INFRA_TEST", "1", "1"):
                        self.node_modules[node].append(self.test_spytest_infra_last)
                worker.assigned = worker.assigned + len(minfo.node_indexes)
                debug("[{}]: ===== Assigned order:{} {} {}".format(name, md.order, mname, minfo.node_indexes))
                for item_index in minfo.node_indexes:
                    report("add", self.collection[item_index], name)
                report("save", "", "")
                return True
        return False

    def _pending_count(self, worker, modules=None, dbg=False):
        count, modules = 0, modules or self.main_modules
        for mname, minfo in modules.items():
            if not minfo.nodes: continue
            if not worker or worker.name in minfo.nodes:
                pending = len(minfo.node_indexes)
                count = count + pending
                if not dbg or pending < 1: continue
                debug("Pending: {} {} {}".format(mname, minfo.node_indexes, minfo.nodes))
        return count

    def _schedule_node_locked(self, node, finished=None):
        name = get_gw_name(node.gateway)
        worker = self.wa.workers[name]
        if node.shutting_down:
            verbose("[{}]: ===== Shutting Down".format(name))
            return
        if worker.excluded:
            verbose("[{}]: ===== Exclude".format(name))
            node.shutdown()
            return
        if worker.completed is None:
            verbose("[{}]: ===== Completed Dead".format(name))
            return
        if worker.completed is True:
            verbose("[{}]: ===== Completed".format(name))
            return
        if not worker.started:
            verbose("[{}]: ===== Not Started".format(name))
            return

        # update applicable count
        self._update_applicable()

        # nothing to do if the node is already executing more than 1
        prev_count = len(self.node_modules[node])
        if prev_count >= 2:
            msg = "[{}]: ===== Running Current {} Applicable {}"
            debug(msg.format(name, prev_count, worker.applicable))
            return

        # Need to load at least one test
        msg = "[{}]: ===== Loading Current {} Applicable {}"
        debug(msg.format(name, prev_count, worker.applicable))

        # we need to iterate twice to handle one test modules
        for _ in range(0, 2):
            if len(self.node_modules[node]) >= 2:
                break
            if worker.node_type == "Main":
                self._assign_test(node, self.main_modules)
            elif worker.node_type == "Backup":
                self._assign_test(node, self.main_modules)
            elif worker.node_type == "ReRun":
                self._assign_test(node, self.rerun_modules)

        # send new tests if we have added
        indexes = self.node_modules[node][prev_count:]
        if indexes:
            debug("[{}]: ===== Sending {}".format(name, indexes))
            node.send_runtest_some(indexes)

        # print all running tests including newly added
        indexes = self.node_modules[node]
        if len(indexes) >= 2:
            debug("[{}]: ===== Running {}".format(name, indexes))
            return

        # trigger a shutdown if the node has at the max one test
        debug("[{}]: ===== Shutdown {}".format(name, indexes))
        node.shutdown()

    def unfinished_tests(self, node, name=None):
        if not node and name:
            for n in self.node_modules:
                gid = get_gw_name(n.gateway)
                if gid == name:
                    node = n
                    break
        if not node:
            return [None, []]
        retval = []
        for item_index in self.node_modules[node]:
            nodeid = self.collection[item_index]
            # if is_infra_test(nodeid): continue
            retval.append(nodeid)
        return node, retval

    def unfinished_count(self, node, name=None):
        node, funcs = self.unfinished_tests(node, name)
        if not node: return 0
        name = get_gw_name(node.gateway)
        worker = self.wa.workers[name]
        if worker.assigned > 0:
            return len(funcs)
        return 0

    def schedule(self, finished=None, error=None):
        wa.lock.acquire()
        self.schedule_locked(finished, error)
        wa.lock.release()

    def schedule_locked(self, finished=None, error=None):
        debug("schedule current finished={} error={}".format(finished, error))
        # debug("\n".join(utils.stack_trace(None, True)))
        seen_workers = {}
        for node, modules in self.node_modules.items():
            gid = get_gw_name(node.gateway)
            worker = wa.workers[gid]
            seen_workers[worker.name] = 1
            if gid != finished:
                verbose("schedule: this {}".format(gid))
                self._schedule_node_locked(node, finished)
                continue
            funcs = self.unfinished_tests(node)[1]
            debug("handle finished {} assigned {} running {}".format(gid, worker.assigned, len(funcs)))
            if not funcs:
                debug("schedule: no applicable tests for {}".format(gid))
                continue
            lines = []
            for item_index in modules:
                nodeid = self.collection[item_index]
                report("remove", nodeid, gid)
                if is_infra_test(nodeid): continue
                lines.append(nodeid)
            if worker.assigned <= len(funcs):
                non_infra_count = 0
                for nodeid in lines:
                    if not is_infra_test(nodeid):
                        non_infra_count = non_infra_count + 1
                        # self.add_nodeid(nodeid, "reload", self.main_modules)
                        report("nes-full", nodeid, gid)
                if non_infra_count > 0:
                    # self.update_matching_nodes(self.main_modules, False)
                    msg = "{} finished without executing any tests."
                    # msg = msg + " Adding back to pool"
                    lines.insert(0, msg.format(gid))
                    trace("\n - ".join(lines))
                    if not rerun_these_nodeids(worker, funcs, True):
                        worker.nes_full.extend(funcs)
                worker.assigned = 0
            else:
                for nodeid in lines:
                    if not is_infra_test(nodeid):
                        report("nes-partial", nodeid, gid)
                msg = "[{}]: ===== unfinished test cases"
                lines.insert(0, msg.format(gid))
                trace("\n - ".join(lines))
                if not rerun_these_nodeids(worker, funcs, True):
                    worker.nes_partial.extend(funcs)
            report("save", "", "")

            for worker in wa.workers.values():
                if worker.name not in seen_workers:
                    if worker.gw_node is None:
                        verbose("schedule: worker {} is Not Available".format(worker.name))
                    else:
                        verbose("schedule: worker {} is not seen".format(worker.name))
            self._update_applicable()

    # update the applicable and pending tests per worker
    def _update_applicable(self):
        for worker in wa.workers.values():
            if worker.completed is None:
                worker.applicable = 0
            else:
                worker.applicable = self._pending_count(worker)


def _show_testbed_topo(show=True):
    header = ["Node", "Topology"]
    rows = []
    for worker in wa.workers.values():
        topo = worker.tb_obj.get_topo()
        rows.append([worker.name, topo])
    retval = utils.sprint_vtable(header, rows)
    if show: trace(retval)
    return retval


def _read_pid(wa):
    for worker in wa.workers.values():
        filepath = paths.get_pid_log(os.path.join(wa.logs_path, worker.name))
        try: worker.pid = utils.read_lines(filepath)[0]
        except Exception: pass


def _show_testbed_devices(show=False):

    comp_time_map = SpyTestDict()
    nodes = SpyTestDict()

    for i in range(2):
        for worker in wa.workers.values():
            devices = worker.tb_obj.get_device_names("DUT")
            name = worker.tb_obj.get_name()
            if name in [None, "", "unknown"]:
                name = os.path.commonprefix(devices)
                name = ''.join([i for i in name if i.isalnum()])
            for device in devices:
                model = worker.tb_obj.get_device_param(device, "model", '')
                chip = worker.tb_obj.get_device_param(device, "chip", '')
                rev = worker.tb_obj.get_device_param(device, "chip_rev", '')
                ptestbed = worker.parent_testbed or worker.testbed
                ptestbed = os.path.basename(ptestbed)
                key = "{}-{}".format(ptestbed, device)
                if key not in nodes:
                    nodes[key] = [ptestbed, name, device, model, chip, rev]
                if i == 0 and worker.completed is not False:
                    comp_time_map[key] = worker.complete_time
                    nodes[key].append(worker.name)
                elif i == 1 and worker.completed is False:
                    comp_time_map[key] = None

    header = ["Testbed", "Name", "Device", "Unused Since", "Unused Duration", "Model", "Chip", "Rev", "Nodes"]
    rows = []
    for key, comp_time in comp_time_map.items():
        ptestbed, name, device, model, chip, rev = nodes[key][:6]
        node_csv = ",".join(nodes[key][6:] if len(nodes[key]) > 6 else [])
        if comp_time:
            elapsed = get_elapsed(comp_time, True)
            comp_time = get_timestamp(False, comp_time)
        else:
            comp_time = elapsed = ""
        rows.append([ptestbed, name, device, comp_time, elapsed, model, chip, rev, node_csv])

    def sort_func(y):
        return utils.time_parse(y[2])

    # sort the modules on total execution time
    rows = sorted(rows, key=sort_func, reverse=True)

    retval = utils.sprint_vtable(header, rows)
    if show: trace("\n" + retval)

    # save the devices status
    filepath = os.path.join(wa.logs_path, "batch_devices.html")
    align = {col: True for col in ["Nodes"]}
    utils.write_html_table3(header, rows, filepath, align=align, total=None)


def _get_tclist(func):
    if func not in wa.tclist_cache:
        if env.get("SPYTEST_REPEAT_MODULE_SUPPORT") == "0":
            func1 = func
        else:
            try: func1 = func.split("[")[0]
            except Exception: func1 = func
        tclist = wa.tcmap.get("tclist", {})
        func2 = func1.replace("::", ".")
        if func1 in tclist:
            wa.tclist_cache[func] = tclist.get(func1)
        elif func2 in tclist:
            wa.tclist_cache[func] = tclist.get(func2)
        else:
            wa.tclist_cache[func] = ["--no-mapped-testcases--"]
    return wa.tclist_cache[func]


def testbed_display(fname):
    if not fname: return fname
    fname = fname.replace("testbed_", "")
    fname = fname.replace(".yaml", "")
    return fname


def _show_testbed_info(show=True):
    header1 = ["Node", "Type", "Buckets", "Node Testbed",
               "Status", "Devices", "Parent Testbed", "PID"]
    header2 = ["#", "Node", "Type", "Buckets", "Node Testbed", "Status", "Devices", "Comment",
               "Parent Testbed", "PID", "Start Time", "End Time",
               "Duration", "Executed", "Running", "Potential", "NES", "Topology", "Previous Nodes"]
    header3 = ["#", "Module", "Function", "TestCase", "Node", "Type"]
    rows1, rows2, rows3, nes_funcs = [], [], [], []
    all_nes_nodes, all_nes_modules = {}, {}
    all_nes_functions, all_nes_testcases = {}, {}

    # init totals
    total_wait_count, total_run_count, total_nes = 0, 0, 0
    total_start_time = total_end_time = get_timestamp(False)
    total_running, total_executed, total_applicable = 0, 0, 0

    _read_pid(wa)

    # handle NES when no applicable testbeds are available
    for nes in wa.nes_nodeids:
        module, func = paths.parse_nodeid(nes)
        if is_infra_test(func): continue
        all_nes_nodes[""], all_nes_modules[module] = 1, 1
        for tcid in _get_tclist(func):
            all_nes_functions[func], all_nes_testcases[tcid] = 1, 1
            rows3.append([len(rows3) + 1, module, func, tcid, "", "FULL"])
        nes_funcs.append(func)

    links2 = {"Node": [], "Node Testbed": [], "Status": [], "Parent Testbed": [], "Executed": []}
    for worker in wa.workers.values():
        comment = worker.comment
        fname = os.path.basename(worker.testbed)
        fname_disp = testbed_display(fname)

        # build status
        if worker.excluded == 1: status = "Exclude0"
        elif worker.excluded == 2: status = "Exclude1"
        elif worker.errored: status = "Error"
        elif worker.completed is None: status = "Dead"
        elif worker.completed: status = "Completed"
        elif worker.started: status = "Running"
        else: status = "Waiting"
        if status == "Running": total_run_count = total_run_count + 1
        if status == "Waiting": total_wait_count = total_wait_count + 1

        dut_list = worker.tb_obj.get_device_names("DUT")
        topology = worker.tb_obj.get_topo().replace(",", " ")
        parent_testbed = worker.parent_testbed
        if parent_testbed: parent_testbed = os.path.basename(parent_testbed)
        parent_testbed_disp = testbed_display(parent_testbed)
        min_bucket = 1 if worker.min_bucket == 0 else worker.min_bucket
        if min_bucket == worker.bucket:
            bucket_range = "{}".format(worker.bucket)
        else:
            bucket_range = "{}-{}".format(min_bucket, worker.bucket)
        rows1.append([worker.name, worker.node_type, bucket_range, fname_disp,
                      status, " ".join(dut_list), parent_testbed_disp, worker.pid])

        start_time, complete_time, elapsed = "", "", ""
        if worker.start_time:
            start_time = get_timestamp(False, worker.start_time)
            total_start_time = min(total_start_time, start_time)
        if worker.complete_time:
            complete_time = get_timestamp(False, worker.complete_time)
            total_end_time = max(total_end_time, complete_time)
            elapsed = get_elapsed(worker.start_time, True, 0, worker.complete_time)
        else:
            total_end_time = max(total_end_time, get_timestamp(False))
            elapsed = get_elapsed(worker.start_time, True, 0, get_timenow())

        # count running
        if wa.sched and worker.completed is False:
            running = wa.sched.unfinished_count(None, worker.name)
        else:
            running = 0
        total_running = total_running + running

        # count executed
        if worker.assigned > running:
            executed = worker.assigned - running
        else:
            executed = 0
        total_executed = total_executed + executed

        # count applicable
        applicable = worker.applicable
        total_applicable = wa.sched._pending_count(None) if wa.sched else 0

        session_log = paths.get_session_log(worker.name)

        # count NES
        nes = 0
        for nodeid in worker.nes_full:
            _, func = paths.parse_nodeid(nodeid)
            if is_infra_test(func): continue
            nes = nes + 1
        for nodeid in worker.nes_partial:
            _, func = paths.parse_nodeid(nodeid)
            if is_infra_test(func): continue
            nes = nes + 1
        total_nes = total_nes + nes

        dut_html_list, pnodes_html_list = [], []
        for dut in dut_list:
            dut_label = worker.tb_obj.get_dut_label(dut)
            dut_link = paths.get_dlog_path(dut_label, worker.name)
            dut_html = "<a href='{}'>{}</a>".format(dut_link, dut)
            dut_html_list.append(dut_html)
            last_node = worker.device_last_used.get(dut, "")
            last_node_html = "<a href='{}'>{}</a>".format(last_node, last_node)
            pnodes_html_list.append(last_node_html)
        dut_html = " ".join(dut_html_list)
        pnodes_html = " ".join(pnodes_html_list)

        snum = len(rows2) + 1
        rows2.append([snum, worker.name, worker.node_type, bucket_range, fname_disp,
                      status, dut_html, comment, parent_testbed_disp, worker.pid,
                      start_time, complete_time, elapsed, executed, running,
                      applicable, nes, topology, pnodes_html])
        links2["Node"].append(worker.name)
        links2["Node Testbed"].append(fname)
        links2["Status"].append(session_log)
        if parent_testbed != "None":
            links2["Parent Testbed"].append(parent_testbed)
        else:
            links2["Parent Testbed"].append("")
        if executed > 0:
            links2["Executed"].append(paths.get_results_htm(worker.name))
        else:
            links2["Executed"].append("")

        # handle NES because of dead nodes
        node3 = "<a href='{}'>{}</a>".format(session_log, worker.name)
        for nodeid in worker.nes_full:
            module, func = paths.parse_nodeid(nodeid)
            if is_infra_test(func): continue
            all_nes_nodes[node3], all_nes_modules[module] = 1, 1
            for tcid in _get_tclist(func):
                all_nes_functions[func], all_nes_testcases[tcid] = 1, 1
                rows3.append([len(rows3) + 1, module, func, tcid, node3, "FULL"])
            nes_funcs.append(func)
        for nodeid in worker.nes_partial:
            module, func = paths.parse_nodeid(nodeid)
            if is_infra_test(func): continue
            all_nes_nodes[node3], all_nes_modules[module] = 1, 1
            for tcid in _get_tclist(func):
                all_nes_functions[func], all_nes_testcases[tcid] = 1, 1
                rows3.append([len(rows3) + 1, module, func, tcid, node3, "PARTIAL"])
            nes_funcs.append(func)

    retval = utils.sprint_vtable(header1, rows1)
    if is_deadnode_recovery():
        # save the batch status
        filepath = os.path.join(wa.logs_path, "batch_summary.html")
        align = {col: True for col in ["Comment", "Devices", "Topology", "Previous Nodes"]}
        total_elapsed = get_elapsed(time_parse(total_start_time), True, 0, time_parse(total_end_time))
        total_count = len(rows2)
        total_status = "Completed" if total_run_count == 0 else "Running"
        rows2.append([total_count, "", "", "", "", total_status, "", "", "", "",
                      total_start_time, total_end_time, total_elapsed,
                      total_executed, total_running, total_applicable,
                      total_nes, "", ""])
        utils.write_html_table3(header2, rows2, filepath, links2, align=align)

        # save the batch nes
        filepath = os.path.join(wa.logs_path, "batch_nes.csv")
        utils.write_csv_file(header3, rows3, filepath)
        rows3.append([len(rows3), len(all_nes_modules), len(all_nes_functions),
                      len(all_nes_testcases), len(all_nes_nodes), ""])
        filepath = os.path.splitext(filepath)[0] + '.html'
        align = {col: True for col in ["Module", "Function", "TestCase"]}
        utils.write_html_table3(header3, rows3, filepath, align=align)
        filepath = os.path.join(wa.logs_path, "batch_nes_functions.txt")
        utils.write_file(filepath, "\n".join(nes_funcs))
        _show_testbed_devices()
    elif show: trace("\n" + retval)

    return retval


def init_stdout(config, logs_path):

    if is_worker():
        # create the stdout for the workers
        filepath = paths.get_stdout_log(logs_path)
        sys.stdout = open(filepath, 'w')

    if is_master():

        # create the console file for the master
        tr = config.pluginmanager.getplugin('terminalreporter')
        if tr is not None:
            folder = os.path.join(logs_path, "master")
            if not os.path.exists(folder):
                os.makedirs(folder)
            filepath = paths.get_stdout_log(folder)
            config._pytestsessionfile = open(filepath, 'w')
            oldwrite = tr._tw.write

            def tee_write(s, **kwargs):
                if not is_deadnode_recovery():
                    oldwrite(s, **kwargs)
                else:
                    debug(s, **kwargs)
                config._pytestsessionfile.write(str(s))
            tr._tw.write = tee_write
            wa.print_func = tee_write


def sub_report_path(logs_path, name):
    if not logs_path:
        return os.path.join("sub-reports", name)
    return os.path.join(logs_path, "sub-reports", name)


def update_dashboard_html():
    if is_worker(): return
    logs_path = wa.logs_path
    wa.j2dict.feature_reports = []
    if not tcmap.get_current_releases():
        wa.j2dict.feature_reports.append(["Features", wa.j2dict.results_features])
    else:
        wa.j2dict.feature_reports.append(["All Features", wa.j2dict.results_features])
        wa.j2dict.feature_reports.append(["New Features", wa.j2dict.results_new_features])
        wa.j2dict.feature_reports.append(["Regression Features", wa.j2dict.results_regression_features])
    if wa.context and wa.context.cfg:
        for name in wa.context.cfg.sub_report.keys():
            features_htm = paths.get_features_htm(sub_report_path(None, name), is_master())
            wa.j2dict.feature_reports.append(["{} Features".format(name), features_htm])

    if wa.context and not wa.context.is_feature_supported("gnmi"):
        wa.j2dict.message_coverage = str(None)

    # generate the html
    dashboard_html = "dashboard.html"
    dashboard_path = os.path.join(os.path.dirname(__file__), dashboard_html)
    content = utils.j2_apply(None, dashboard_path, **wa.j2dict)
    utils.write_file(os.path.join(logs_path, dashboard_html), content)


def create_dashboard():
    if is_worker(): return
    logs_path = wa.logs_path
    wa.j2dict.is_batch = is_batch()
    wa.j2dict.is_bucket = str(bool(wa.workers))
    wa.j2dict.is_master = str(is_master())
    consolidated = is_master()
    wa.j2dict.features_summary = paths.get_features_summary_htm(consolidated=consolidated)
    wa.j2dict.execution_summary = paths.get_summary_htm(consolidated=consolidated)
    wa.j2dict.results_features = paths.get_features_htm(consolidated=consolidated)
    wa.j2dict.results_new_features = paths.get_new_features_htm(consolidated=consolidated)
    wa.j2dict.results_regression_features = paths.get_regression_features_htm(consolidated=consolidated)
    wa.j2dict.results_modules = paths.get_modules_htm(consolidated=consolidated)
    wa.j2dict.results_functions = paths.get_results_htm(consolidated=consolidated)
    wa.j2dict.results_testcases = paths.get_tc_results_htm(consolidated=consolidated)
    wa.j2dict.results_stats = paths.get_stats_htm(consolidated=consolidated)
    wa.j2dict.results_audit = paths.get_audit_htm(consolidated=consolidated)
    wa.j2dict.results_syslog = paths.get_syslog_htm(consolidated=consolidated)
    wa.j2dict.results_msysinfo = paths.get_msysinfo_htm(consolidated=consolidated)
    wa.j2dict.results_fsysinfo = paths.get_fsysinfo_htm(consolidated=consolidated)
    wa.j2dict.results_dsysinfo = paths.get_dsysinfo_htm(consolidated=consolidated)
    wa.j2dict.results_coverage = paths.get_coverage_htm(consolidated=consolidated)
    wa.j2dict.message_coverage = paths.get_msg_coverage_htm(consolidated=consolidated)
    wa.j2dict.device_inventory = paths.get_device_inventory_htm(consolidated=consolidated)
    wa.j2dict.platform_inventory = paths.get_platform_inventory_htm(consolidated=consolidated)
    wa.j2dict.chip_inventory = paths.get_chip_inventory_htm(consolidated=consolidated)
    wa.j2dict.results_alerts = paths.get_alerts_log(consolidated=consolidated)
    wa.j2dict.results_functions_png = paths.get_results_png(consolidated=consolidated)
    wa.j2dict.results_testcases_png = paths.get_tc_results_png(consolidated=consolidated)
    wa.j2dict.results_defaults = paths.get_defaults_htm(False)
    wa.j2dict.results_devfeat = paths.get_devfeat_htm(False)
    # wa.j2dict.cdn = utils.get_cdn_base("") # using CDN web
    wa.j2dict.cdn = ""  # using local web
    utils.copy_web_include(logs_path)  # using local web
    update_dashboard_html()


def configure(config, logs_path, root_logs_path):
    wa.logs_path = logs_path
    trace("Batch Debug Level {}".format(wa.debug_level))
    wa.repeated_tests = os.path.join(root_logs_path, "repeated_tests")
    wa.tcmap = dict()
    load_module_csv()
    load_coverage_history()
    init_stdout(config, logs_path)
    dist.configure(config, logs_path, is_worker(), wa)
    create_dashboard()
    if is_master():
        create_repeated_files(config)
    elif not is_batch():
        create_repeated_files(config)
    if wa.repeated_tests and os.path.exists(wa.repeated_tests):
        if config.args and wa.repeated_tests not in config.args:
            config.args.append(wa.repeated_tests)
    return is_master()


def create_repeated_files(config):

    repeated = wa.repeated
    utils.delete_folder(wa.repeated_tests)
    for path, entries in repeated.items():
        for ent in entries:
            if not ent.repeat_name:
                continue
            mname1 = path.replace(".py", "")
            mname1 = "{}--{}.py".format(mname1, ent.repeat_name)
            mname2 = os.path.basename(mname1).replace(".py", "")
            mname2 = mname2.replace("-", "_")
            fpath = os.path.join(wa.repeated_tests, mname1)
            content1 = "from utilities.common import set_repeat\n"
            content2 = "set_repeat('{}', '{}', '{}', '{}')"
            content2 = content2.format(mname2, path, ent.repeat_name, ent.repeat_topo)
            utils.write_file(fpath, content1 + content2)
            debug("Created {}".format(fpath))


def is_renamed(nodeid):
    nodeid2 = item_utils.map_nodeid(nodeid)
    mname = nodeid2.split("::", 1)[0]
    return bool(mname in wa.renamed)


def set_abort_run(abort_run):
    wa.abort_run = abort_run


def set_logger(logger):
    wa.logger = logger


def set_tcmap(tcmap):
    wa.tcmap = tcmap


def set_workarea(context):
    wa.context = context
    update_dashboard_html()


def unconfigure(config):
    retval = is_master()
    if retval:
        debug("============== batch unconfigure =====================")
        if wa.custom_scheduling and wa.sched:
            wa.sched._pending_count(None, dbg=True)
    for line in utils.dump_connections("batch unconfig: "):
        trace(line)
    return retval


def finish():
    return is_master()


def make_scheduler(config, log, count=0):
    debug("============== batch make_scheduler =====================")
    if wa.custom_scheduling:
        wa.sched = SpyTestScheduling(config, wa, count)
    else:
        from xdist.scheduler import LoadFileScheduling
        wa.sched = LoadFileScheduling(config, log)
    _show_testbed_info()
    return wa.sched


def get_node_prefix():
    if wa.custom_node_name:
        return "N"
    return "gw"


def parse_node_index(name, default=None):
    prefix = get_node_prefix()
    gw = re.search(r'{}([0-9]+)'.format(prefix), name)
    if not gw: gw = re.search(r'gw([0-9]+)', name)
    try: return int(gw.group(1))
    except Exception: return default


def build_node_name(index, prefix=""):
    if get_node_prefix() == "gw":
        return "gw{}".format(int(index))
    return "N{:03d}".format(int(index))


def configure_nodes(config, specs):
    debug("============== batch configure_nodes =====================")
    if not specs: return
    for spec in specs:
        index = parse_node_index(spec.id)
        if index is not None:
            spec.id = build_node_name(index)
            wa.get_gw_name[spec.id] = spec.id
            spec.env["OLD_ID"] = spec.id


def ensure_gw_name(gateway, func=""):
    name = gateway.id
    if name in wa.get_gw_name:
        return wa.get_gw_name[name]
    if name not in wa.workers:
        try: old_id = gateway.spec.env.get("OLD_ID", None)
        except Exception: old_id = None;
        if old_id not in wa.workers:
            trace("[{}]: ===== {} unknown".format(name, func))
            return None
        trace("[{}]: ===== {} restarted as {}".format(old_id, func, name))
        clone_worker(wa.workers[old_id], name); old_id = name
        wa.get_gw_name[old_id] = name
        return old_id
    return None


def get_gw_name(gateway, func=""):
    return gateway.id


def configure_node(node):
    debug("============== batch configure_node =====================")
    if not wa.custom_scheduling: return
    name = get_gw_name(node.gateway, "configure_node")
    if not name: return
    worker = wa.workers[name]
    debug("[{}]: ===== configure_node testbed: {}".format(name, worker.testbed))
    worker.completed = False
    worker.excluded = 0
    worker.complete_time = None


def begin_node(gateway):
    debug("============== batch begin_node =====================")
    if not wa.custom_scheduling: return
    name = ensure_gw_name(gateway, "begin_node")
    if not name: return
    debug("begin_node {}".format(gateway))
    worker = wa.workers[name]
    worker.completed = False
    worker.excluded = 0
    worker.complete_time = None


def slist_add(l, sl, ex=[]):
    for e in sl:
        if e in ex: continue
        if e in l: continue
        l.append(e)


def finish_node(node, error, reader):
    if not wa.custom_scheduling:
        return
    wa.lock.acquire()
    finish_node_locked(node.gateway, None, error, reader)
    wa.lock.release()


def rerun_these_nodeids(worker, nodeids, is_nes=False):
    change = False
    if is_nes and "NES" not in wa.rerun_list:
        return change
    if not wa.rerun_list or worker.gw_node_index >= wa.testbed_count:
        return change
    for nodeid in nodeids:
        if nodeid in wa.sched.rerun_nodeids: continue
        wa.sched.rerun_nodeids[nodeid] = 1
        trace("============== Rerun {} {}".format(worker.name, nodeid))
        if wa.sched.add_nodeid(nodeid, "Rerun", wa.sched.rerun_modules):
            change = True
    # TODO: check if we can cache the main modules and read from it instead
    if change:
        wa.sched.update_matching_nodes(wa.sched.rerun_modules, False)
    return change


def finish_node_locked(gw, gid, error, reader, status=None):
    status0 = "DEAD" if error else "FINISH"
    status = status or status0
    gid = gid or get_gw_name(gw, "finish_node")
    trace("============== NODE({}) {} {}".format(gid, status, gid))

    if gid not in wa.workers:
        trace("finish_node--unknown {}".format(gid))
        return

    # used in multiple places below
    time_now = get_timenow()

    worker = wa.workers[gid]
    if worker.completed is not False or worker.started is False:
        debug("============== CHECK: NODE {} {} {}".format(gid, worker.completed, worker.started))
        worker.errored = True
        worker.completed = None
        worker.complete_time = time_now
        # debug("\n".join(utils.stack_trace(None, True)))
        return

    ptestbed = worker.parent_testbed or worker.testbed

    if wa.rerun_list and worker.gw_node_index < wa.testbed_count:
        results_file = paths.get_results_csv(os.path.join(wa.logs_path, worker.name))
        debug("============== NODE {} {}".format(results_file, gid))
        rows = reader(results_file) if reader else []
        nodeids = []
        for row in rows:
            if row[2] not in wa.rerun_list: continue
            func = row[1].replace(".", "::")
            if func:
                nodeid = "{}::{}".format(row[0], func)
                nodeids.append(nodeid)
        rerun_these_nodeids(worker, nodeids)

    # mark the worker as excluded if node_dead file is present
    file_path = os.path.join(wa.logs_path, worker.name, "node_dead")
    try: excluded_devices = utils.read_lines(file_path)[0].split()
    except Exception: excluded_devices = []
    if excluded_devices: worker.excluded = 1

    # read node_dead_reason file is present
    file_path = os.path.join(wa.logs_path, worker.name, "node_dead_reason")
    node_dead_reason = "".join(utils.read_lines(file_path))
    if worker.terminated:
        worker.comment = "Unresponsive Node Killed"
    elif os.path.exists(file_path):
        worker.comment = node_dead_reason
    elif status == "DEAD":
        worker.comment = "Node Killed"

    trace("============== Completed {} {} {}".format(worker.name, worker.comment, node_dead_reason))

    # mark that the current node is completed
    worker.completed = None if error else True
    worker.complete_time = time_now

    # add the excluded devices to global list
    slist_add(wa.excluded_devices[ptestbed], excluded_devices)

    # add the devices in the current testbed into free devices list
    devices = worker.tb_obj.get_device_names("DUT")
    slist_add(wa.free_devices[ptestbed], devices, excluded_devices)

    # mark the device as last used in current worker
    for device in devices:
        wa.device_last_used[ptestbed][device] = worker.name

    # add the device info loaded devices if they have executed tests
    func_count = wa.sched.unfinished_count(None, gid)
    if worker.assigned > func_count:
        slist_add(wa.loaded_devices, devices, excluded_devices)

    # dump debug information
    msg = "[{}]: ===== Finished assigned {} unfinished {}"
    msg = msg.format(gid, worker.assigned, func_count)
    if excluded_devices:
        msg = "{} excluded devices: {}".format(msg, ",".join(excluded_devices))
    debug(msg)

    # indicate if we need to skip the image loading
    if worker.completed is not False:
        mark_used_node(worker)

    # mark the workers that can be started or excluded
    for name, worker in wa.workers.items():
        if worker.errored:
            verbose("[{}]: ===== Already Finished Error".format(name))
            continue
        if worker.completed is None:
            verbose("[{}]: ===== Already Finished Dead".format(name))
            continue
        if worker.completed is True:
            verbose("[{}]: ===== Already Finished".format(name))
            continue
        if worker.started:
            verbose("[{}]: ===== Already Started".format(name))
            continue
        if worker.excluded:
            verbose("[{}]: ===== Already Excluded".format(name))
            continue
        if not worker.gw_node:
            verbose("[{}]: ===== Not Available".format(name))
            continue

        # wait for small time to allow the xdist settle
        pause_time = env.getint("SPYTEST_BATCH_NODE_PAUSE_TIME", "0")
        if pause_time > 0:
            gw_node_elapsed = get_elapsed(worker.gw_node_time, end=time_now)
            if gw_node_elapsed < pause_time:
                debug("[{}]: ===== Small Pause".format(name))
                continue

        ptestbed = worker.parent_testbed or worker.testbed
        pdevices = wa.free_devices.get(ptestbed, [])
        if not pdevices:
            debug("[{}]: ===== No devives free in TB {}".format(name, ptestbed))
            continue
        devices = worker.tb_obj.get_device_names("DUT")
        excluded_devices = wa.excluded_devices.get(ptestbed, [])
        pdevices_csv = ",".join(pdevices)
        ptestbed_name = os.path.basename(ptestbed)

        # exclude the testbed if any of the needed device is in exclude pool
        if any(dut in excluded_devices for dut in devices):
            worker.completed = None
            worker.complete_time = time_now
            worker.excluded = 2
            slist_add(wa.free_devices[ptestbed], devices, excluded_devices)
            msg = "[{}]: ===== Excluded PTB: {} Free: {} Excluded: {}"
            msg = msg.format(name, ptestbed_name, pdevices_csv, ",".join(excluded_devices))
            debug(msg)
            continue

        # search if all devices in the current worker are in free pool
        worker.started = all(dut in pdevices for dut in devices)
        worker.start_time = time_now if worker.started else None
        worker.last_report = time_now if worker.started else None
        loaded = all(dut in wa.loaded_devices for dut in devices)
        msg = "Start" if worker.started else "Wait"
        msg = "[{}]: ===== {} Need {}".format(name, msg, ",".join(devices))
        msg = "{} Loaded {} Applicable {}".format(msg, loaded, worker.applicable)
        msg = "{} PTB: {} Free: {}".format(msg, ptestbed_name, pdevices_csv)
        if excluded_devices:
            msg = "{} Excluded: {}".format(msg, ",".join(excluded_devices))
        debug(msg)
        if worker.started:
            wa.free_devices[ptestbed] = utils.filter_list(pdevices, devices)
            for device in devices:
                worker.device_last_used[device] = wa.device_last_used[ptestbed][device]

        # indicate if we need to skip the image loading
        mark_used_node(worker)

    # start the marked tests
    wa.sched.schedule_locked(gid, error)

    # update the reports
    _show_testbed_info()
    save_report()
    try:
        save_finished_testbeds()
    except Exception as exp:
        debug("Failed to save finished testbeds {}".format(repr(exp)))
        debug("\n".join(utils.stack_trace(None, True)))


def mark_used_node(worker):
    devices = worker.tb_obj.get_device_names("DUT")
    loaded = all(dut in wa.loaded_devices for dut in devices)
    # indicate if we need to skip the image loading
    if loaded:
        utils.write_file(os.path.join(wa.logs_path, worker.name, "node_used"), "")
    else:
        utils.delete_file(os.path.join(wa.logs_path, worker.name, "node_used"))


def normalize_nodeid(nodeid):
    # parts = nodeid.split("::")
    return nodeid


def log_report_master(report):
    nodeid = normalize_nodeid(report.nodeid)
    if is_infra_test(nodeid): return
    if not is_deadnode_recovery(): return
    name = get_gw_name(report.node.gateway)
    try:
        worker = wa.workers[name]
        worker.last_report = get_timenow()
    except Exception:
        trace("Failed to find worker {}".format(name))
    wasxfail = getattr(report, "wasxfail", None)
    # trace("\n============================================\n")
    # trace(name, nodeid, "when:", report.when,
    # "skipped:", report.skipped, "worker:", report.worker_id,
    # "passed:", report.passed, "outcome:", report.outcome, wasxfail)
    # trace("\n============================================\n")
    if report.when == 'setup':
        if wasxfail:
            trace("[{}]: {}: {}".format(name, "XFAIL", nodeid))
        elif report.skipped:
            trace("[{}]: {}: {}".format(name, "SKIP", nodeid))
        elif not report.passed:
            trace("[{}]: {}: {}".format(name, "ERROR", nodeid))
        else:
            trace("[{}]: {}: {}".format(name, "EXEC", nodeid))
    elif report.when == 'call':
        if wasxfail:
            trace("[{}]: {}: {}".format(name, "XFAIL", nodeid))
        elif report.skipped:
            trace("[{}]: {}: {}".format(name, "XFAIL", nodeid))
        elif not report.passed:
            trace("[{}]: {}: {}".format(name, "FAILED", nodeid))
        else:
            trace("[{}]: {}: {}".format(name, "PASSED", nodeid))
    elif report.when == 'teardown-unused':
        if report.skipped:
            trace("[{}]: {}: {}".format(name, "XFAIL", nodeid))
        elif not report.passed:
            trace("[{}]: {}: {}".format(name, "FAIL", nodeid))
        else:
            trace("[{}]: {}: {}".format(name, "PASS", nodeid))
    # trace("\n--------------------------------------------\n")
    # debug(utils.sprint_obj(report, "REPORT"))
    # trace("\n--------------------------------------------\n")


def _create_bucket_testbeds(tb_objs, buckets, logs_path):

    ret_list, testbed_files, topologies = [], [], {}

    for i in range(1, env.max_buckets + 1):
        topologies[i] = env.get("SPYTEST_TOPO_{}".format(i), "D1")

    def copy_file(src, index, bucket, inst):
        dst = "testbed_{}_{}_{}.yaml".format(index, bucket, inst)
        new_filename = os.path.join(logs_path, dst)
        shutil.copy(src, new_filename)
        os.chmod(new_filename, 0o644)
        testbed_files.append(new_filename)
        return dst, new_filename

    # testbed for default bucket
    prev_bucket = 0 if not buckets else buckets[0] + 1
    for index, tb in enumerate(tb_objs):
        file_path = tb.get_file_path()
        bucket, min_bucket, testbed = wa.largest_bucket, prev_bucket, file_path
        fname, fpath = copy_file(testbed, index + 1, min_bucket, 0)
        trace("Copying Testbed {} as {}".format(testbed, [fname]))
        msg = "Use {} for Buckets(>={}) with devices {}"
        trace(msg.format(fname, bucket, tb.get_device_names("DUT")))
        ret_list.append([bucket, min_bucket, None, [fpath]])

    # create mini testbed files for each bucket
    for i, bucket in enumerate(buckets):
        # trace("============> create mini testbed files for {} bucket".format(bucket))
        try: min_bucket = buckets[i + 1] + 1
        except Exception: min_bucket = 1
        if bucket not in topologies:
            msg = "bucket {} is not found in supported, using higher bucket {} testbed"
            warn(msg.format(bucket, prev_bucket))
            continue

        errmsg = "Failed to create testbed for bucket {} topo {} using higher bucket {} testbed"
        errmsg = errmsg.format(bucket, topologies[bucket], prev_bucket)
        for index, tb in enumerate(tb_objs):
            possible_topos = []
            # identify the node topologies matching bucket topology
            for topo in topologies[bucket].split("||"):
                # trace("============> identify testbed for {}".format(topo))
                slist, props = tb.identify_topology(wa.logger, tb, None,
                                                    wa.max_bucket_setups, topo)[0:2]
                if not slist or len(slist) <= 0:
                    if "D1" not in topo:
                        trace("============> no match for {}".format(topo))
                    continue
                # randomize the node topologies from the testbed
                seed = utils.get_random_seed()
                Random(seed).shuffle(slist)
                possible_topos.append([slist, props])
            if not possible_topos:
                continue

            # found at least one topology for bucket
            errmsg = None

            # randomize the node topologies from all testbeds
            Random(seed).shuffle(possible_topos)

            # create node testbed files for mini topologies across all buckets
            tmp_tbs, inst = [], 0
            for [slist, props] in possible_topos:
                for duts_dict in slist:
                    dut_list = Testbed.get_dut_list(duts_dict)
                    mini_testbed = tb.rebuild_topo_file(dut_list, props)
                    yaml_file = Testbed.write_file(mini_testbed, "batch_testbed_", ".yaml")
                    inst = inst + 1
                    fname, fpath = copy_file(yaml_file, index + 1, bucket, inst)
                    os.remove(yaml_file)
                    msg = "Created {} for bucket({}-{}) with devices {}"
                    trace(msg.format(fname, min_bucket, bucket, duts_dict))
                    tmp_tbs.append(fpath)
            ret_list.append([bucket, min_bucket, testbed_files[index], tmp_tbs])
            prev_bucket = bucket

        # trace error message if any
        if errmsg: warn(errmsg)

    return ret_list


def parse_args(numprocesses, buckets_csv, logs_path, append_modules_csv, change_modules_csv):

    wa.append_modules_csv = append_modules_csv
    wa.change_modules_csv = change_modules_csv

    batch_init_env(wa)
    init_type_nodes()

    if get_worker_id(): return []

    filename = env.get("SPYTEST_TESTBED_FILE", "testbed.yaml")
    parts = filename.split(",")
    count = len(parts)
    if env.get("SPYTEST_FILE_MODE", "0") != "0":
        if numprocesses and count < numprocesses:
            for _ in range(count, numprocesses):
                parts.append(parts[0])
            count = numprocesses
    [_, count, parts] = parse_buckets(count, parts, buckets_csv, logs_path)
    os.environ["SPYTEST_TESTBED_FILE"] = parts[0]
    if numprocesses or count > 1 or buckets_csv:
        os.environ["SPYTEST_BATCH_RUN"] = "1"
        numprocesses2 = len(wa.workers) or 1
        numprocesses = numprocesses or 0
        if numprocesses2 > numprocesses:
            numprocesses = numprocesses2
        retval = ["-n", str(numprocesses)]
        max_restart = env.getint("SPYTEST_BATCH_DEAD_NODE_MAX_RESTART", "0")
        retval.extend(["--max-worker-restart", str(max_restart)])
        #######################################################################
        # this is not working when the paths are not specified in command line
        #######################################################################
        # if is_deadnode_recovery() and buckets > 0:
        # retval.append("batch/test_spytest_infra.py")
        #######################################################################
        return dist.parse_args(count, retval)
    return []


def create_worker(i, j, node_type, prefix="", auto_start=True):
    name = build_node_name(i, prefix)
    bucket = wa.buckets[j]
    tb_obj = wa.testbed_objs[j]
    worker = SpyTestDict()
    worker.gw_node_index = i
    worker.testbed_index = j
    worker.gw_node = None
    worker.gw_node_time = get_timenow()
    worker.node_type = node_type
    worker.name = name
    worker.bucket = bucket
    worker.min_bucket = wa.min_buckets[j]
    worker.testbed = wa.testbeds[j]
    worker.parent_testbed = wa.parent_testbeds[j]
    worker.tb_obj = tb_obj
    worker.completed = False
    worker.terminated = False
    worker.excluded = 0
    worker.comment = ""
    worker.complete_time = None
    worker.assigned = 0
    worker.nes_partial = []
    worker.nes_full = []
    worker.load_infra_tests = is_deadnode_recovery()
    worker.pid = 0
    worker.applicable = 0
    worker.errored = False
    if not auto_start:
        worker.started = False
    elif i >= wa.testbed_count:
        worker.started = False
    elif wa.reverse_run_order:
        worker.started = True if bucket >= wa.buckets[-1] else False
    else:
        worker.started = True if bucket >= wa.buckets[0] else False
    worker.start_time = get_timenow() if worker.started else None
    worker.last_report = get_timenow() if worker.started else None
    return worker


def clone_worker(worker, name):
    node_type = "Cloned-{}".format(worker.name)
    s = create_worker(worker.gw_node_index, worker.testbed_index, node_type, auto_start=False)
    s.name = name
    register_worker(s)
    return s


def register_worker(worker):
    wa.workers[worker.name] = worker
    wa.free_devices[worker.testbed] = []
    wa.excluded_devices[worker.testbed] = []
    wa.loaded_devices = []
    ptestbed = worker.parent_testbed or worker.testbed
    wa.device_last_used[ptestbed] = {}
    worker.device_last_used = {}
    # add testbed file environment variable
    os.environ["SPYTEST_TESTBED_FILE_{}".format(worker.name)] = worker.testbed


def abort_run(val, reason):
    if wa.abort_run:
        wa.abort_run(val, reason)
    else:
        os._exit(val)


def log_verion_info():
    trace("VERSION: {}".format(get_git_ver()))
    trace("HOSTNAME: {}".format(socket.gethostname()))
    trace("ROOT_PATH: {}".format(wa.root))
    trace("Python: {}.{}.{}".format(sys.version_info.major,
                                    sys.version_info.minor, sys.version_info.micro))


def parse_buckets(count, testbeds, buckets_csv, logs_path):
    wa.logs_path = logs_path
    wa.testbeds = testbeds
    wa.testbed_count = count

    if buckets_csv:
        # force to use custom scheduling
        wa.custom_scheduling = True
    else:
        wa.custom_scheduling = bool(env.get("SPYTEST_SCHEDULING"))

    if not wa.custom_scheduling:
        # add testbed file environment variables
        for i, part in enumerate(testbeds):
            os.environ["SPYTEST_TESTBED_FILE_gw{}".format(i)] = part
        return [0, count, testbeds]

    log_verion_info()
    trace("============> Buckets = {}".format(buckets_csv))

    # init return values
    tb_objs = []

    # read the buckets in reverse order
    bucket_list = []
    for bucket in buckets_csv.split(","):
        if bucket:
            bucket_list.append(int(bucket))
    bucket_list = sorted(bucket_list, key=int, reverse=True)
    trace("============> Buckets - Sorted = {}".format(bucket_list))

    # create testbed objects for testbed files
    trace("============> Parsing Testbed files")
    for testbed in testbeds:
        # wa.logger = wa.logger or logging.getLogger()
        tb = Testbed(testbed, logger=wa.logger, flex_dut=True)
        if not tb.is_valid():
            msg = "testbed file {} is not valid".format(testbed)
            trace(msg)
            abort_run(100, msg)
        # trace("Testbed: {}".format(testbed))
        # trace("  Devices: {}".format(tb.get_device_names("DUT")))
        tb_objs.append(tb)

    # initialize collected lists
    for key in ["testbeds", "buckets", "min_buckets", "parent_testbeds", "testbed_objs"]:
        wa[key] = []
    for key in ["free_devices", "excluded_devices"]:
        wa[key] = dict()

    # use given testbeds for tests needs higher topology
    # than the specified buckets
    trace("============> Creating Bucket Testbed files")
    data = _create_bucket_testbeds(tb_objs, bucket_list, logs_path)
    for bucket, min_bucket, parent_testbed, tbs in sorted(data, reverse=True):
        for testbed in tbs:
            wa.buckets.append(bucket)
            wa.min_buckets.append(min_bucket)
            wa.testbeds.append(testbed)
            wa.parent_testbeds.append(parent_testbed)

    trace("============> Parse Bucket Testbed files")
    for testbed in wa.testbeds:
        fname = os.path.basename(testbed)
        tb = Testbed(testbed, logger=wa.logger, flex_dut=True)
        if not tb.is_valid():
            msg = "testbed file {} is not valid".format(testbed)
            trace(msg)
            abort_run(100, msg)
        msg = "Topology({}): {}"
        trace(msg.format(fname, tb.get_topo()))
        wa.testbed_objs.append(tb)

    wa.workers.clear()
    wa.testbed_count = len(wa.testbeds)
    wa.logs_path = logs_path

    min_bucket, max_bucket = wa.buckets[0], wa.buckets[0]
    for i in range(0, wa.testbed_count):
        worker = create_worker(i, i, "Main")
        if worker.bucket < min_bucket:
            min_bucket = worker.bucket
        elif worker.bucket > max_bucket:
            max_bucket = worker.bucket
        register_worker(worker)
    wa.min_bucket = min_bucket
    wa.max_bucket = max_bucket

    # add backup and/or rerun nodes
    new_workers, node_index = [], len(wa.workers)
    for node_type in ["Backup", "ReRun"]:
        trace("============> Add {} Nodes".format(node_type))
        if node_type == "Backup":
            type_nodes = wa.backup_nodes
            nodes_multiplier = wa.backup_nodes_multiplier
        else:
            type_nodes = wa.rerun_nodes
            nodes_multiplier = wa.rerun_nodes_multiplier
        if type_nodes is None: continue
        for bucket in range(max_bucket, min_bucket - 1, -1):
            new_bucket_workers = []
            for worker in wa.workers.values():
                if worker.bucket != bucket: continue
                for type_node in range(type_nodes or nodes_multiplier):
                    new_worker = create_worker(node_index, worker.testbed_index, node_type)
                    debug("Create {} node {} for {} {}".format(node_type, type_node, worker.name, new_worker.name))
                    new_bucket_workers.append(new_worker)
                    # new_bucket_workers.insert(0, new_worker)
                    node_index = node_index + 1
                if type_nodes != 0:
                    # fixed number of backup/rerun nodes already created
                    break  # go to next bucket
            # ramdomize the new bucket workers to avoid always using first
            # seed = utils.get_random_seed()
            # Random(seed).shuffle(new_bucket_workers)
            new_workers.extend(new_bucket_workers)

    # register all the new workers
    for new_worker in new_workers:
        register_worker(new_worker)

    # let the testbeds in min bucket handle all lower buckets
    for worker in wa.workers.values():
        if worker.bucket <= min_bucket:
            worker.min_bucket = 0

    trace("=======================================================")
    _show_testbed_topo()
    _show_testbed_info()
    return [len(wa.buckets), len(wa.testbeds), wa.testbeds]

# TODO: What is this used for???


def verify_bucket(nodeid, used, fails):
    if is_infra_test(nodeid):
        pass
    elif fails != 0:
        trace("SKIP verify bucket", nodeid, fails, used)
    elif not wa.custom_scheduling:
        debug("Not valid for current scheduling type", nodeid, fails, used)
    elif nodeid not in wa.sched.main_modules:
        trace("Module not found in modules.csv", nodeid)
    elif wa.sched.main_modules[nodeid].bucket != used:
        trace("Mismatch bucket information", nodeid, used, wa.sched.main_modules[nodeid].bucket)


def worker_register(obj):
    if is_debug_collection() and not is_batch():
        abort_run(1, "Collection Debug Exit")


def is_debug_collection():
    return bool(env.get("SPYTEST_DEBUG_COLLECTION", "0") != "0")


def is_batch():
    return bool(env.get("SPYTEST_BATCH_RUN"))


def is_master():
    return bool(not is_worker() and is_batch())


def get_worker_id():
    return env.get("PYTEST_XDIST_WORKER")


def is_worker():
    return bool(get_worker_id())


def is_member():
    return bool(is_worker() or not is_batch())


def get_member_count():
    return len(wa.workers) or 1


def get_dead_member_count():
    count = 0
    for worker in wa.workers.values():
        if worker.completed is None:
            count = count + 1
    return count


def is_infra_test(name):
    if name is None:
        if is_deadnode_recovery():
            return 5
        return 0
    if "test_spytest_infra_first" in name:
        return 1
    if "test_spytest_infra_second" in name:
        return 2
    if "test_spytest_infra_last" in name:
        return 3
    if "test_spytest_infra" in name:
        return 4
    return 0


def simulate_deadnode(*args, **kwargs):
    enval = utils.integer_parse(env.get("SPYTEST_BUCKETS_DEADNODE_SIMULATE", "0"), 0)
    if enval <= 0 or not is_batch(): return
    # enval applicable bits 1:session 2:module 3:function 4:exclude
    for scope in args:
        if not (enval & (1 << scope)): continue
        dead_node = False
        if scope == 0 and randint(0, 100) > 80: dead_node = True
        elif scope == 1 and randint(0, 100) > 90: dead_node = True
        elif scope == 2 and randint(0, 100) > 95: dead_node = True
        elif scope == 3 and randint(0, 100) > 90:
            dut = kwargs.get("dut", "D1")
            file_path = os.path.join(wa.logs_path, "node_dead")
            utils.write_file(file_path, " " + dut, "a")
            dead_node = True
        if dead_node:
            msg = "Simulating dead node scope {}".format(scope)
            warn(msg)
            abort_run(1, msg)


wa = batch_init()
