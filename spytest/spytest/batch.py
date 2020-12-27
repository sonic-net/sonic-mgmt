import os
import re
import sys
import csv
import shutil
import logging
from random import randint
from random import Random
from operator import itemgetter
from spytest.dicts import SpyTestDict
from spytest.testbed import Testbed
import spytest.spydist as dist
import spytest.paths as paths
import spytest.env as env
import spytest.tcmap as tcmap
from spytest.st_time import get_timenow
from spytest.st_time import get_elapsed
from spytest.st_time import get_timestamp
import utilities.common as utils

############################ TODO #####################################
# Support for configured number backup nodes for each bucket to pick up
# when the main node is dead - say 2 backup nodes
#
# Support for rerun nodes
#######################################################################

wa = SpyTestDict()
wa.slaves = SpyTestDict()
wa.sched = None
wa.parse_logs = []
wa.buckets = []
wa.nes_nodeids = []
wa.dead_slaves = []
wa.print_func = None
wa.custom_scheduling = False
wa.debug_level = 0
wa.logs_path = ""
wa.executed = SpyTestDict()
wa.trace_file = None
wa.logger = None
wa.reverse_run_order = False
wa.count = 1
wa.custom_node_name = False

# None disable backup/rerun nodes
# 0 create same number of backup/rerun nodes
# * create fixed number of backup/rerun nodes
wa.backup_nodes = None
wa.backup_nodes_multiplier = 1
wa.rerun_nodes = None
wa.rerun_nodes_multiplier = 1
wa.default_model_topo_pref = "default"
wa.module_csv = None
wa.augment_modules_csv = []
wa.repeat_info = True

#logging.basicConfig(level=logging.DEBUG)
#wa.logger = logging.getLogger()

def load_module_csv():
    wa.module_csv = env.get("SPYTEST_MODULE_CSV_FILENAME", "modules.csv")
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    reporting = os.path.join(root, "reporting")
    wa.module_rows, wa.repeated, rows = [], {}, []

    # read the csv files
    for filepath in wa.module_csv.split(","):
        csv_file = filepath
        if not os.path.exists(filepath):
            csv_file = os.path.join(reporting, filepath)
            if not os.path.exists(csv_file):
                trace("module csv {} not found".format(filepath))
                continue
        with open(csv_file, 'r') as fd:
            for row in csv.reader(fd):
                rows.append(row)
            fd.close()

    # append augmented lines
    for line in wa.augment_modules_csv:
        line2 = " ".join(utils.make_list(line))
        for row in csv.reader([line2]):
            rows.append(row)

    # parse the rows
    for row in rows:
        if not row or row[0].startswith("#"): continue
        if len(row) < 3: continue
        bucket, order, name0 = [str(i).strip() for i in row[:3]]
        if bucket.startswith("#"): continue
        parts = name0.split(".py.")
        if len(parts) > 1:
            if not wa.repeat_info:
                continue
            if env.get("SPYTEST_REPEAT_MODULE_SUPPORT", "0") == "0":
                continue
            name = "{}--{}.py".format(parts[0], parts[1])
            module_row = [bucket, order, name]
            pname = "{}.py".format(parts[0])
            if pname not in wa.repeated:
                wa.repeated[pname] = []
            wa.repeated[pname].append(SpyTestDict(path=pname, repeat_name=parts[1]))
        else:
            module_row = [bucket, order, name0]
        module_row.extend(row[3:])
        wa.module_rows.append(module_row)

def init_type_nodes():

    backup_nodes = env.get("SPYTEST_BATCH_BACKUP_NODES")
    if backup_nodes is None:
        pass
    elif backup_nodes == "two":
        wa.backup_nodes_multiplier = 2
        wa.backup_nodes = 0
    elif backup_nodes == "three":
        wa.backup_nodes_multiplier = 3
        wa.backup_nodes = 0
    else:
        try: wa.backup_nodes = int(backup_nodes)
        except Exception: wa.backup_nodes = None

    rerun_nodes = env.get("SPYTEST_BATCH_RERUN_NODES")
    if rerun_nodes is None:
        pass
    elif rerun_nodes == "two":
        wa.rerun_nodes_multiplier = 2
        wa.rerun_nodes = 0
    elif rerun_nodes == "three":
        wa.rerun_nodes_multiplier = 3
        wa.rerun_nodes = 0
    else:
        try: wa.rerun_nodes = int(rerun_nodes)
        except Exception: wa.rerun_nodes = None

def is_deadnode_recovery():
    return bool(env.get("SPYTEST_BUCKETS_DEADNODE_RECOVERY", "1") != "0")

def ftrace(msg):
    if wa.logs_path:
        if not wa.trace_file:
            wa.trace_file = os.path.join(wa.logs_path, "batch_debug.log")
            utils.write_file(wa.trace_file, "")
        utils.write_file(wa.trace_file, "{} {}\n".format(get_timestamp(), msg), "a")

def debug(*args, **kwargs):
    if wa.debug_level > 0:
        trace(*args, **kwargs)
    else:
        ftrace(" ".join(map(str,args)))

def level_trace(lvl, *args, **kwargs):
    msg = " ".join(map(str,args))
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

def trace(*args, **kwargs):
    level_trace(logging.INFO, *args, **kwargs)

def warn(*args, **kwargs):
    level_trace(logging.WARNING, *args, **kwargs)

def save_report():

    # show running
    (header, rows) = (['#', "Module", "Function", "TestCase", "Node", "Status"], [])
    links = {"Module":[], "Node":[],"Status":[],}
    for nodeid in wa.executed:
        [node_name, status] = wa.executed[nodeid]
        if not node_name: continue
        if is_infra_test(nodeid): continue
        module, func = paths.parse_nodeid(nodeid)
        links["Node"].append(node_name)
        links["Status"].append(paths.get_session_log(node_name))
        if "tclist" not in wa.tcmap:
            rows.append([len(rows)+1, module, func, func, node_name, status])
        elif func not in wa.tcmap.tclist:
            rows.append([len(rows)+1, module, func, func, node_name, status])
        else:
            for tcid in wa.tcmap.tclist[func]:
                rows.append([len(rows)+1, module, func, tcid, node_name, status])

    filepath = os.path.join(wa.logs_path, "batch_progress.csv")
    utils.write_csv_file(header, rows, filepath)
    filepath = os.path.splitext(filepath)[0]+'.html'
    align = {col: True for col in ["Module", "Function", "TestCase"]}
    utils.write_html_table3(header, rows, filepath, links=links, align=align, total=False)

    # show pending
    (header, rows) = (['#', "Module", "Function", "TestCase", "Status", "Nodes"], [])
    for nodeid in wa.executed:
        [node_name, status] = wa.executed[nodeid]
        if node_name: continue
        if is_infra_test(nodeid): continue
        module, func = paths.parse_nodeid(nodeid)
        nodes = wa.sched.find_matching_modes(module)
        if "tclist" not in wa.tcmap:
            rows.append([len(rows)+1, module, func, func, status, nodes])
        elif func not in wa.tcmap.tclist:
            rows.append([len(rows)+1, module, func, func, status, nodes])
        else:
            for tcid in wa.tcmap.tclist[func]:
                rows.append([len(rows)+1, module, func, tcid, status, nodes])

    filepath = os.path.join(wa.logs_path, "batch_pending.csv")
    utils.write_csv_file(header, rows, filepath)
    filepath = os.path.splitext(filepath)[0]+'.html'
    align = {col: True for col in ["Module", "Function", "TestCase", "Nodes"]}
    utils.write_html_table3(header, rows, filepath, align=align, total=False)

def report(op, nodeid, node_name):
    if op == "load":
        wa.executed[nodeid] = ["", "Pending"]
        return
    elif op == "reload":
        wa.executed[nodeid] = ["", "PendingAgain"]
        return
    elif op == "rerun":
        wa.executed[nodeid] = ["", "PendingReRun"]
    elif op == "nes-partial":
        wa.executed[nodeid] = ["", "PartialNes"]
    elif op == "nes-full":
        wa.executed[nodeid] = ["", "FullNes"]
    elif op == "add":
        wa.executed[nodeid] = [node_name, "Queued"]
        return
    elif op == "remove":
        if nodeid in wa.executed:
            del wa.executed[nodeid]
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
    pass

class SpyTestScheduling(object):
    def __init__(self, config, wa, log=None):
        self.config = config
        if config:
            self.count = len(config.getvalue("tx"))
        else:
            self.count = 1
        self.order_support = True
        self.topo_support = True
        self.node_modules = {}
        self.collection = []
        self.collection_is_completed = False
        self.main_modules = SpyTestDict()
        self.rerun_modules = SpyTestDict()
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

    def list_files(self, entry, pattern="*"):
        path = os.path.join(wa.logs_path, "repeated_tests", entry)
        if os.path.isfile(path):
            return [entry]
        return utils.list_files(entry, pattern)

    def _load_buckets(self):
        for row in wa.module_rows:
            if not row or row[0].startswith("#"): continue
            if utils.integer_parse(row[0]) is None:
                tpref = row.pop(0)
            else:
                tpref = wa.default_model_topo_pref
            if len(row) < 3: continue
            topo = self.default_topo
            if len(row) > 3: topo = ",".join([str(i).strip() for i in row[3:]])
            bucket, order, name0 = [str(i).strip() for i in row[:3]]
            if bucket.startswith("#"): continue
            for name in self.list_files(name0, "test_*.py"):
                md = self.get_module_data(name)
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

    def add_node(self, node):
        self.node_modules[node] = []

    def remove_node(self, node):
        self.node_modules.pop(node)

    def is_node_active(self, node):
        slave = self.wa.slaves[node.gateway.id]
        if slave.excluded: return False
        if not slave.completed: return True
        if not slave.started: return True
        return False

    @property
    def tests_finished(self):
        if not self.collection_is_completed: return False
        for node, modules in self.node_modules.items():
            if self.is_node_active(node): return False
        debug("================ tests_finished 1 ===========")
        for node, modules in self.node_modules.items():
            if len(modules) >= 2: return False
        debug("================ tests_finished 2 ===========")
        return True

    @property
    def nodes(self):
        return list(self.node_modules.keys())

    @property
    def has_pending(self):
        debug("================ has_pending ===========")
        for node, modules in self.node_modules.items():
            if self.is_node_active(node): return True
            if modules: return True
        return False

    def get_module_topo_pref(self, mname, default=None):
        default = default or wa.default_model_topo_pref
        if mname not in self.module_data: return [default]
        module_data_tpref = list(self.module_data[mname].keys())
        user_pref = env.get("SPYTEST_BATCH_MODULE_TOPO_PREF", default).split("|")
        if default not in user_pref: user_pref.append(default)
        retval = []
        for pref in user_pref:
            if pref in module_data_tpref:
                retval.append(pref)
        return retval

    def set_module_data(self, md, mname):
        if mname not in self.module_data:
            self.module_data[mname] = SpyTestDict()
        self.module_data[mname][md.tpref] = md

    def get_module_data(self, mname, tpref=None):
        tpref = tpref or wa.default_model_topo_pref
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
        mname = nodeid.split("::", 1)[0]
        md = self.get_module_data(mname)
        if md.default:
            mname = os.path.basename(mname)
            md = self.get_module_data(mname)
        if mname in self.base_names:
            mname = self.base_names[mname]
            md = self.get_module_data(mname)
        if mname not in modules:
            modules[mname] = SpyTestDict()
            module = modules[mname]
            module.node_indexes = []
            module.nodes = []
            if md.default and action == "load":
                warn("Module {} is not found in {}".format(mname, wa.module_csv))
                warn(self.module_data)
        modules[mname].node_indexes.append(self.collection.index(nodeid))
        modules[mname].used_tpref = md.tpref

    def add_node_collection(self, node, collection):
        self.count = self.count - 1
        if self.count > 0: return
        if self.collection_is_completed: return

        # last node has registered the collection
        # generate module list
        self.collection_is_completed = True
        self.collection = collection
        for nodeid in collection:
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
        self.update_matching_modes(self.main_modules, True)

    def find_active_nodes(self, names):
        active = []
        for name in names:
            if self.wa.slaves[name].completed is False:
                active.append(name)
        return active

    def find_matching_modes(self, name):
        if name not in self.main_modules:
            return ""
        nodes = self.main_modules[name].nodes
        nodes = self.find_active_nodes(nodes)
        return " ".join(nodes)

    def update_matching_modes(self, modules, init):

        #smallest,largest,larger,equal
        match_order = env.get("SPYTEST_BATCH_MATCHING_BUCKET_ORDER", "larger,largest")
        match_order_list = match_order.split(",")
        match_order_list.insert(0, "matching")

        nes_modules = []
        for mname, minfo in modules.items():
            minfo.nodes = []

            for model in match_order_list:
                if model not in ["matching", "equal", "larger", "largest", "smallest"]:
                    msg = "unknown batch matching bucket order model {}".format(model)
                    debug(msg)
                    continue
                for tpref in self.get_module_topo_pref(mname):
                    if not minfo.nodes and model in ["matching"]: # pickup testbed in the matching bucket
                        md = self.get_module_data(mname, tpref)
                        trace("TRY-1 {} {} {}".format(mname, tpref, md.topo))
                        for slave in wa.slaves.values():
                            if md.bucket <= slave.bucket and \
                               md.bucket >= slave.min_bucket:
                                debug("MATCH-1 {} {} {} with {} {}".format(mname, tpref, md.topo,\
                                         slave.name, slave.tb_obj.get_topo(name0=False)))
                                if md.topo:
                                    [errs, _] = slave.tb_obj.ensure_min_topology_norandom(md.topo, match_dut_name=1)
                                    slave.tb_obj.reset_derived()
                                    if errs:
                                        msg = "non matching testbed {} to execute bucket {} {} {}"
                                        debug(msg.format(slave.name, md.bucket, mname, md.topo))
                                        continue
                                msg = "matched testbed {} to execute bucket {} {} {}"
                                trace(msg.format(slave.name, md.bucket, mname, md.topo))
                                minfo.nodes.append(slave.name)
                                minfo.used_tpref = tpref

                for tpref in self.get_module_topo_pref(mname):
                    if not minfo.nodes and model in ["equal"]: # pickup testbed in the same bucket
                        md = self.get_module_data(mname, tpref)
                        trace("TRY-2 {} {} {}".format(mname, tpref, md.topo))
                        for slave in wa.slaves.values():
                            if md.bucket <= slave.bucket and \
                               md.bucket >= slave.min_bucket:
                                if not minfo.nodes:
                                    msg = "Using same bucket {} testbed {} to execute {} {}"
                                    trace(msg.format(slave.bucket, slave.name, mname, md.topo))
                                minfo.nodes.append(slave.name)
                                minfo.used_tpref = tpref

                if not minfo.nodes and model in ["smallest"]: # pickup testbed in the smallest bucket
                    cmp_bucket = self.wa.min_bucket
                    for slave in wa.slaves.values():
                        if cmp_bucket <= slave.bucket and cmp_bucket >= slave.min_bucket:
                            if not minfo.nodes:
                                msg = "Using smallest bucket {} testbed {} to execute {}"
                                trace(msg.format(slave.bucket, slave.name, mname))
                            minfo.nodes.append(slave.name)
                            minfo.used_tpref = wa.default_model_topo_pref

                if not minfo.nodes and model in ["larger"]: # pickup testbed in the larger bucket
                    for tpref in self.get_module_topo_pref(mname):
                        md = self.get_module_data(mname, tpref)
                        trace("TRY-3 {} {} {}".format(mname, tpref, md.topo))
                        for bucket in range(md.bucket+1, 100):
                            if minfo.nodes: break
                            for slave in wa.slaves.values():
                                if slave.bucket != bucket: continue
                                [errs, _] = slave.tb_obj.ensure_min_topology_norandom(md.topo)
                                slave.tb_obj.reset_derived()
                                if errs: continue
                                if not minfo.nodes:
                                    msg = "Using higher bucket {} testbed {} to execute {} {}"
                                    trace(msg.format(slave.bucket, slave.name, mname, md.topo))
                                minfo.nodes.append(slave.name)
                                minfo.used_tpref = tpref

                if not minfo.nodes and model in ["largest"]: # pickup testbed in the largest bucket
                    cmp_bucket = self.wa.max_bucket
                    for slave in wa.slaves.values():
                        if cmp_bucket <= slave.bucket and cmp_bucket >= slave.min_bucket:
                            if not minfo.nodes:
                                msg = "Using largest bucket {} testbed {} to execute {}"
                                trace(msg.format(slave.bucket, slave.name, mname))
                            minfo.nodes.append(slave.name)
                            minfo.used_tpref = wa.default_model_topo_pref

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
        header = ["#", "Module", "Bucket", "Tests", "Pref", "Topology", "Nodes"]
        (mcount, tcount, rows) = (0, 0, [])
        for mname, minfo in self.main_modules.items():
            count = len(minfo.node_indexes)
            mcount = mcount + 1
            tcount = tcount + count
            nodes = " ".join(minfo.nodes)
            md = self.get_module_data(mname, minfo.used_tpref)
            mname2 = paths.get_mlog_basename(mname)
            rows.append([mname2, md.bucket, count, md.tpref, md.topo, nodes])
        rows = sorted(rows, key=itemgetter(1), reverse=True)
        for index, row in enumerate(rows):
            row.insert(0, index+1)
        retval = utils.sprint_vtable(header, rows)
        if show:
            trace("Modules: {} Functions: {}".format(mcount, tcount))

        if is_deadnode_recovery():
            # save the batch status
            filepath = os.path.join(wa.logs_path, "batch_modules.html")
            align = {col: True for col in ["Module", "Topology", "Nodes"]}
            utils.write_html_table3(header, rows, filepath, align=align, total=False)
        elif show:
            trace("\n" + retval)

        return retval

    def mark_test_complete(self, node, item_index, duration=0):
        debug("Remove", item_index, "From", node, self.node_modules[node])
        if item_index in self.node_modules[node]:
            self.node_modules[node].remove(item_index)
            report("finish", self.collection[item_index], node.gateway.id)
            debug("============== completed", item_index, self.collection[item_index])
        else:
            trace("============== already completed", item_index, self.collection[item_index])
        self._schedule_node(node)
        debug("NewList", node, self.node_modules[node])

    def _assign_pretest(self, node, name):
        slave = self.wa.slaves[name]
        if slave.load_infra_tests:
            slave.load_infra_tests = False
            if self.test_spytest_infra_first is not None and \
               self.test_spytest_infra_second is not None:
                self.node_modules[node].append(self.test_spytest_infra_first)
                self.node_modules[node].append(self.test_spytest_infra_second)
                trace("[{}]: ===== Assigned Pre-Tests".format(node.gateway.id))
                return True
        return False

    def _assign_test(self, node, name, modules):
        slave = self.wa.slaves[name]
        for order in range(0, self.max_order + 1):
            for mname,minfo in modules.items():
                if name not in minfo.nodes: continue
                md = self.get_module_data(name, minfo.used_tpref)
                if self.order_support and md.order != order:
                    continue
                if not self._assign_pretest(node, name):
                    del modules[mname]
                    self.node_modules[node].extend(minfo.node_indexes)
                    slave.assigned = slave.assigned + len(minfo.node_indexes)
                    debug("ASSIGNED", name, md.order, mname, minfo.node_indexes)
                    for item_index in minfo.node_indexes:
                        report("add", self.collection[item_index], node.gateway.id)
                    report("save", "", "")
                return True
        return False

    def _schedule_node(self, node):
        name = node.gateway.id
        debug("================ _schedule_node =========== {}".format(node))
        slave = self.wa.slaves[name]
        if node.shutting_down: return
        if slave.excluded:
            node.shutdown()
            return
        if slave.completed: return
        if not slave.started: return
        prev_count = len(self.node_modules[node])
        if prev_count >= 2: return
        debug("================ load =========== {} {}".format(node, prev_count))
        for _ in range(0,2):
            if len(self.node_modules[node]) < 2:
                if slave.node_type == "Main":
                    self._assign_test(node, name, self.main_modules)
                elif slave.node_type == "Backup":
                    self._assign_test(node, name, self.main_modules)
                    #self._assign_test(node, name, self.backup_modules)
                elif slave.node_type == "ReRun":
                    self._assign_test(node, name, self.main_modules)
                    #self._assign_test(node, name, self.rerun_modules)
        indexes = self.node_modules[node][prev_count:]
        if indexes: node.send_runtest_some(indexes)
        if len(self.node_modules[node]) >= 2: return
        debug("================ shutdown =========== {} {}".format(node, indexes))
        node.shutdown()

    def unfinished_tests(self, node, name=None):
        if not node and name:
            for n in self.node_modules:
                if n.gateway.id == name:
                    node = n
                    break
        if not node:
            return [None, []]
        retval = []
        for item_index in self.node_modules[node]:
            retval.append(self.collection[item_index])
        return [node, retval]

    def unfinished_count(self, node, name=None):
        [node, funcs] = self.unfinished_tests(node, name)
        if not node: return 0
        slave = self.wa.slaves[node.gateway.id]
        if slave.assigned > 0:
            return len(funcs)
        return 0

    def schedule(self, finished=None, error=None):
        debug("start", utils.get_proc_name())
        for node in self.node_modules:
            if node.gateway.id != finished:
                self._schedule_node(node)
                continue
            _, func_list = self.unfinished_tests(node)
            if not func_list:
                continue
            slave = wa.slaves[node.gateway.id]
            lines = []
            for item_index in self.node_modules[node]:
                report("remove", self.collection[item_index], node.gateway.id)
                lines.append(self.collection[item_index])
            if slave.assigned <= len(func_list):
                non_infra_count = 0
                for nodeid in lines:
                    if not is_infra_test(nodeid):
                        non_infra_count = non_infra_count + 1
                        #self.add_nodeid(nodeid, "reload", self.main_modules)
                        report("nes-full", nodeid, node.gateway.id)
                if non_infra_count > 0:
                    #self.update_matching_modes(self.main_modules, False)
                    slave.nes_full.extend(func_list)
                    msg = "{} finished without executing any tests."
                    #msg = msg + " Adding back to pool"
                    lines.insert(0, msg.format(node.gateway.id))
                    trace("\n - ".join(lines))
                slave.assigned = 0
            else:
                for nodeid in lines:
                    if not is_infra_test(nodeid):
                        report("nes-partial", nodeid, node.gateway.id)
                msg = "unfinished test cases"
                slave.nes_partial.extend(func_list)
                lines.insert(0, msg)
                trace("\n - ".join(lines))
            report("save", "", "")


def _show_testbed_topo(show=True):
    header = ["Node", "Topology"]
    rows = []
    for slave in wa.slaves.values():
        topo = slave.tb_obj.get_topo()
        rows.append([slave.name, topo])
    retval = utils.sprint_vtable(header, rows)
    if show: trace(retval)
    return retval

def _read_pid(wa):
    for slave in wa.slaves.values():
        filepath = paths.get_pid_log(os.path.join(wa.logs_path, slave.name))
        try: slave.pid = utils.read_lines(filepath)[0]
        except Exception: pass

def _show_testbed_devices(show=False):

    access_time = SpyTestDict()
    nodes = SpyTestDict()

    for i in range(2):
        for slave in wa.slaves.values():
            devices = slave.tb_obj.get_device_names("DUT")
            for device in devices:
                key = device
                if key not in nodes:
                    nodes[key] = []
                if i == 0 and slave.completed is not False:
                    access_time[key] = slave.complete_time
                    nodes[key].append(slave.name)
                elif i == 1 and slave.completed is False:
                    access_time[key] = None
                    nodes[key] = []

    header = ["Device", "Unused Since", "Unused Duration", "Nodes"]
    rows = []
    for key, value in access_time.items():
        if value:
            elapsed = get_elapsed(value, True)
            value = get_timestamp(False, value)
            rows.append([key, value, elapsed, ",".join(nodes[key])])
        else:
            rows.append([key, "", "", ""])

    def sort_func(y):
        return utils.time_parse(y[2])

    # sort the modules on total execution time
    rows = sorted(rows, key=sort_func, reverse=True)

    retval = utils.sprint_vtable(header, rows)
    if show: trace("\n" + retval)

    # save the devices status
    filepath = os.path.join(wa.logs_path, "batch_devices.html")
    align = {col: True for col in ["Nodes"]}
    utils.write_html_table3(header, rows, filepath, align=align, total=False)

def _get_tclist(func):
    tclist = []
    if "tclist" not in wa.tcmap:
        tclist.append("")
    elif func not in wa.tcmap.tclist:
        tclist.append("--no-mapped-testcases--")
    else:
        for tcid in wa.tcmap.tclist[func]:
            tclist.append(tcid)
    return tclist

def _show_testbed_info(show=True):
    header1 = ["Node", "Type", "Buckets", "Node Testbed",
              "Status", "Devices", "Parent Testbed", "PID"]
    header2 = ["#", "Node", "Type", "Buckets", "Node Testbed", "Status",
               "Devices", "Parent Testbed", "PID", "Start Time", "End Time",
               "Duration", "Executed", "Running", "NES", "Topology"]
    header3 = ["#", "Module", "Function", "TestCase", "Node", "Type"]
    rows1, rows2, rows3 = [], [], []
    nes_funcs = []
    _read_pid(wa)
    for nes in wa.nes_nodeids:
        module, func = paths.parse_nodeid(nes)
        for tcid in _get_tclist(func):
            rows3.append([len(rows3)+1, module, func, tcid, "", "FULL"])
        nes_funcs.append(func)
    links2 = {"Node":[],"Node Testbed":[],"Status":[],"Parent Testbed":[],"Executed":[]}
    for slave in wa.slaves.values():
        fname = os.path.basename(slave.testbed)
        if slave.excluded == 1: status = "Exclude0"
        elif slave.excluded == 2: status = "Exclude1"
        elif slave.completed is None: status = "Dead"
        elif slave.completed: status = "Completed"
        elif slave.started: status = "Running"
        else: status = "Waiting"
        dut_list = slave.tb_obj.get_device_names("DUT")
        topology = slave.tb_obj.get_topo().replace(",", " ")
        parent_testbed = slave.parent_testbed
        if parent_testbed: parent_testbed = os.path.basename(parent_testbed)
        min_bucket = 1 if slave.min_bucket == 0 else slave.min_bucket
        if min_bucket == slave.bucket:
            bucket_range = "{}".format(slave.bucket)
        else:
            bucket_range = "{}-{}".format(min_bucket, slave.bucket)
        devices = " ".join(dut_list)
        rows1.append([slave.name, slave.node_type, bucket_range, fname,
                     status, devices, parent_testbed, slave.pid])
        start_time, complete_time, elapsed = "", "", ""
        if slave.start_time:
            start_time = get_timestamp(False, slave.start_time)
        if slave.complete_time:
            complete_time = get_timestamp(False, slave.complete_time)
            elapsed = get_elapsed(slave.start_time, True, 0, slave.complete_time)
        if wa.sched and slave.completed is False:
            running = wa.sched.unfinished_count(None, slave.name)
        else:
            running     = 0
        if slave.assigned > running:
            executed = slave.assigned - running
        else:
            executed = 0
        session_log = paths.get_session_log(slave.name)

        nes = len(slave.nes_full) + len(slave.nes_partial)
        devices = " ".join(dut_list)
        snum = len(rows2)+1
        rows2.append([snum, slave.name, slave.node_type, bucket_range, fname,
                      status, devices, parent_testbed, slave.pid, start_time,
                      complete_time, elapsed, executed, running, nes, topology])
        links2["Node"].append(slave.name)
        links2["Node Testbed"].append(fname)
        links2["Status"].append(session_log)
        if parent_testbed != "None":
            links2["Parent Testbed"].append(parent_testbed)
        else:
            links2["Parent Testbed"].append("")
        if executed > 0:
            links2["Executed"].append(paths.get_results_htm(slave.name))
        else:
            links2["Executed"].append("")

        status3 = "<a href='{}'>{}</a>".format(session_log, slave.name)
        for nes in slave.nes_full:
            module, func = paths.parse_nodeid(nes)
            for tcid in _get_tclist(func):
                rows3.append([len(rows3)+1, module, func, tcid, status3, "FULL"])
            nes_funcs.append(func)
        for nes in slave.nes_partial:
            module, func = paths.parse_nodeid(nes)
            for tcid in _get_tclist(func):
                rows3.append([len(rows3)+1, module, func, tcid, status3, "PARTIAL"])
            nes_funcs.append(func)

    retval = utils.sprint_vtable(header1, rows1)
    if is_deadnode_recovery():
        # save the batch status
        filepath = os.path.join(wa.logs_path, "batch_summary.html")
        align = {col: True for col in ["Devices", "Topology"]}
        utils.write_html_table3(header2, rows2, filepath, links2, align=align, total=False)

        # save the batch nes
        filepath = os.path.join(wa.logs_path, "batch_nes.html")
        align = {col: True for col in ["Module", "Function", "TestCase"]}
        utils.write_html_table3(header3, rows3, filepath, align=align, total=False)
        filepath = os.path.join(wa.logs_path, "batch_nes.csv")
        utils.write_csv_file(header3, rows3, filepath)
        filepath = os.path.join(wa.logs_path, "batch_nes_functions.txt")
        utils.write_file(filepath, "\n".join(nes_funcs))
        _show_testbed_devices()
    elif show: trace("\n" + retval)

    return retval

def init_stdout(config, logs_path):

    if is_slave():
        # create the stdout for the slaves
        filepath = paths.get_stdout_log(logs_path)
        sys.stdout = open(filepath, 'w')
        sys.stderr = sys.stdout

    if is_master():

        # create the console file for the master
        tr = config.pluginmanager.getplugin('terminalreporter')
        #config.pluginmanager.unregister(tr)
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

def create_dashboard(logs_path):
    if is_slave(): return
    dashboard_html = "dashboard.html"
    path = os.path.join(os.path.dirname(__file__), dashboard_html)
    kwargs = SpyTestDict(is_batch=is_batch())
    kwargs.is_bucket = str(bool(wa.slaves))
    kwargs.is_master = str(is_master())
    consolidated = is_master()
    kwargs.results_summary = paths.get_report_htm(consolidated=consolidated)
    kwargs.results_features = paths.get_features_htm(consolidated=consolidated)
    kwargs.results_modules = paths.get_modules_htm(consolidated=consolidated)
    kwargs.results_functions = paths.get_results_htm(consolidated=consolidated)
    kwargs.results_testcases = paths.get_tc_results_htm(consolidated=consolidated)
    kwargs.results_stats = paths.get_stats_htm(consolidated=consolidated)
    kwargs.results_syslog = paths.get_syslog_htm(consolidated=consolidated)
    kwargs.results_sysinfo = paths.get_sysinfo_htm(consolidated=consolidated)
    kwargs.results_alerts = paths.get_alerts_log(consolidated=consolidated)
    kwargs.results_functions_png = paths.get_results_png(consolidated=consolidated)
    kwargs.results_testcases_png = paths.get_tc_results_png(consolidated=consolidated)
    kwargs.results_defaults = paths.get_defaults_htm(False)
    kwargs.results_devfeat = paths.get_devfeat_htm(False)
    content = utils.j2_apply(None, path, **kwargs)
    utils.write_file(os.path.join(logs_path, dashboard_html), content)

def configure(config, logs_path, root_logs_path):
    wa.logs_path = logs_path
    wa.tcmap = dict()
    load_module_csv()
    init_stdout(config, logs_path)
    dist.configure(config, logs_path, is_slave())
    create_dashboard(logs_path)
    if is_master():
        create_repeated_files(config, root_logs_path)
        return True
    create_repeated_folder(config, root_logs_path)
    return False

def create_repeated_files(config, logs_path):

    dtests, first = None, True
    if wa.repeat_info:
        repeated = wa.repeated
    else:
        repeated = tcmap.get_repeated()
    for entries in repeated.values():
        for ent in entries:
            if not ent.repeat_name: continue
            if first:
                dtests = create_repeated_folder(config, logs_path)
                if config.args: config.args.append(dtests)
                first = False
            mname = ent.path.replace(".py", "")
            mname = "{}--{}.py".format(mname, ent.repeat_name)
            fpath = os.path.join(dtests, mname)
            content = "from utilities.common import set_repeat\n"
            content = content + "set_repeat('{}', '{}', '')".format(ent.path, ent.repeat_name)
            utils.write_file(fpath, content)

def create_repeated_folder(config, logs_path):
    dtests = os.path.join(logs_path, "repeated_tests")
    if not os.path.exists(dtests):
        os.makedirs(dtests)

    testpaths = config.getini("testpaths")
    testpaths.append(dtests)
    config.addinivalue_line("testpaths", testpaths)
    return dtests

def set_logger(logger):
    wa.logger = logger

def set_tcmap(tcmap):
    wa.tcmap = tcmap

def unconfigure(config):
    #debug("============== batch unconfigure =====================")
    return is_master()

def finish():
    return is_master()

def make_scheduler(config, log):
    debug("============== batch make_scheduler =====================")
    if wa.custom_scheduling:
        wa.sched = SpyTestScheduling(config, wa, log)
    else:
        from xdist.scheduler import LoadFileScheduling
        wa.sched = LoadFileScheduling(config, log)
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
    for spec in specs:
        index = parse_node_index(spec.id)
        if index is not None:
            spec.id = build_node_name(index)

def configure_node(node):
    debug("============== batch configure_node =====================")
    if not wa.custom_scheduling:
        return
    if node.gateway.id in wa.slaves:
        slave = wa.slaves[node.gateway.id]
        slave.gw_node = node
        slave.completed = False
        slave.excluded = 0
        slave.complete_time = None
        debug("configure_node {} testbed: {}".format(node, slave.testbed))
    else:
        trace("configure_node--unknown {}".format(node))

def begin_node(gateway):
    debug("============== batch begin_node =====================")
    if not wa.custom_scheduling:
        return
    if gateway.id in wa.slaves:
        debug("begin_node {}".format(gateway))
        slave = wa.slaves[gateway.id]
        slave.completed = False
        slave.excluded = 0
        slave.complete_time = None
    else:
        trace("begin_node--unknown {}".format(gateway))

def slist_add(l, sl, ex=[]):
    for e in sl:
        if e in ex: continue
        if e in l: continue
        l.append(e)

def finish_node(node, error, reader):
    status = "DEAD" if error else "FINISH"
    trace("============== NODE {} {}".format(status, node.gateway.id))

    if not wa.custom_scheduling:
        return

    if node.gateway.id not in wa.slaves:
        trace("finish_node--unknown {}".format(node))
        return

    slave = wa.slaves[node.gateway.id]
    ptestbed = slave.parent_testbed or slave.testbed

    rerun_list = env.get("SPYTEST_BATCH_RERUN")
    if rerun_list and slave.gw_node_index < wa.count:
        results_file = paths.get_results_csv(os.path.join(wa.logs_path, slave.name))
        debug("============== NODE {} {}".format(results_file, node.gateway.id))
        rows = reader(results_file)
        for row in rows:
            if row[2] in rerun_list.split(","):
                func = row[1].replace(".", "::")
                nodeid = "{}::{}".format(row[0], func)
                trace("============== Rerun {}".format(nodeid))
                wa.sched.add_nodeid(nodeid, "Rerun", wa.sched.rerun_modules)
        wa.sched.update_matching_modes(wa.sched.rerun_modules, False)

    # mark the slave as excluded if node_dead file is present
    file_path = os.path.join(wa.logs_path, slave.name, "node_dead")
    try: excluded_devices = utils.read_lines(file_path)[0].split()
    except Exception: excluded_devices = []
    if excluded_devices: slave.excluded = 1

    slave.completed = None if error else True
    slave.complete_time = get_timenow()

    # add the excluded devices to global list
    slist_add(wa.excluded_devices[ptestbed], excluded_devices)
    if excluded_devices:
        debug("Node {} Excluded Devices {}".format(node.gateway.id, excluded_devices))

    # add the devices in the current testbed into free devices list
    devices = slave.tb_obj.get_device_names("DUT")
    slist_add(wa.free_devices[ptestbed], devices, excluded_devices)

    # add the device info loaded devices if they have executed tests
    func_count = wa.sched.unfinished_count(node)
    debug("Node {} assigned {} unfinished {}".format(node.gateway.id, slave.assigned, func_count))
    if slave.assigned > func_count:
        slist_add(wa.loaded_devices, devices, excluded_devices)

    for name,slave in wa.slaves.items():
        if slave.started or slave.excluded: continue
        ptestbed = slave.parent_testbed or slave.testbed
        pdevices = wa.free_devices.get(ptestbed, [])
        if not pdevices: continue
        devices = slave.tb_obj.get_device_names("DUT")
        excluded_devices = wa.excluded_devices.get(ptestbed, [])
        if any(dut in excluded_devices for dut in devices):
            slave.completed = None
            slave.complete_time = get_timenow()
            slave.excluded = 2
            debug("Excluding slave {} excluded {}".format(name, excluded_devices))
            slist_add(wa.free_devices[ptestbed], devices, excluded_devices)
            debug("wa.free_devices", name, os.path.basename(ptestbed), wa.free_devices[ptestbed])
            continue

        # search if all devices in the current slave are in free pool
        slave.started =  all(dut in pdevices for dut in devices)
        slave.start_time = get_timenow() if slave.started else None
        loaded = all(dut in wa.loaded_devices for dut in devices)
        if slave.started:
            debug("Starting slave {} loaded {}".format(name, loaded))
            wa.free_devices[ptestbed] = utils.filter_list(pdevices, devices)
        else:
            debug("Waiting slave {} loaded {}".format(name, loaded))
        debug("wa.free_devices", slave.name, slave.started, os.path.basename(ptestbed), wa.free_devices[ptestbed])

        # indicate if we need to skip the image loading
        if loaded:
            utils.write_file(os.path.join(wa.logs_path, slave.name, "node_used"), "")
        else:
            utils.delete_file(os.path.join(wa.logs_path, slave.name, "node_used"))

    wa.sched.schedule(node.gateway.id, error)
    _show_testbed_info()
    save_report()

    if error:
        wa.dead_slaves.append(slave)

def log_report_master(report):
    if is_infra_test(report.nodeid): return
    if not is_deadnode_recovery(): return
    name=report.node.gateway.id
    wasxfail = getattr(report, "wasxfail", None)
    #trace("\n============================================\n")
    #trace(name, report.nodeid, "when:", report.when,
          #"skipped:", report.skipped, "worker:", report.worker_id,
          #"passed:", report.passed, "outcome:", report.outcome, wasxfail)
    #trace("\n============================================\n")
    if report.when == 'setup':
        if wasxfail:
            trace("[{}]: {}: {}".format(name, "XFAIL", report.nodeid))
        elif report.skipped:
            trace("[{}]: {}: {}".format(name, "SKIP", report.nodeid))
        elif not report.passed:
            trace("[{}]: {}: {}".format(name, "ERROR", report.nodeid))
        else:
            trace("[{}]: {}: {}".format(name, "EXEC", report.nodeid))
    elif report.when == 'call':
        if wasxfail:
            trace("[{}]: {}: {}".format(name, "XFAIL", report.nodeid))
        elif report.skipped:
            trace("[{}]: {}: {}".format(name, "XFAIL", report.nodeid))
        elif not report.passed:
            trace("[{}]: {}: {}".format(name, "FAILED", report.nodeid))
        else:
            trace("[{}]: {}: {}".format(name, "PASSED", report.nodeid))
    elif report.when == 'teardown-unused':
        if report.skipped:
            trace("[{}]: {}: {}".format(name, "XFAIL", report.nodeid))
        elif not report.passed:
            trace("[{}]: {}: {}".format(name, "FAIL", report.nodeid))
        else:
            trace("[{}]: {}: {}".format(name, "PASS", report.nodeid))
    #trace("\n--------------------------------------------\n")
    #debug(utils.sprint_obj(report, "REPORT"))
    #trace("\n--------------------------------------------\n")

topologies = {
    1 : "D1T1:2",
    2 : "D1T1:4 D1D2:6 D2T1:2",
    3 : "D1 D2 D3",
    4 : "D1T1:2 D2T1:2 D3T1:2 D4T1:2 D1D2:4 D2D3:4 D3D4:4 D4D1:4",
    5 : "D1 D2 D3 D4 D5",
    6 : "D1D3:4 D1D4:4 D1D5:2 D1D6:4 D2D3:4 D2D4:4 D2D5:4 D2D6:4 D3T1:2 D4T1:2 D5T1:2 D6T1:2",
    7 : "D1 D2 D3 D4 D5 D6 D7",
    8 : "D1 D2 D3 D4 D5 D6 D7 D8"
}

def _create_bucket_testbeds(tb_objs, buckets, logs_path):

    ret_list = []

    testbed_files = []

    topologies[1] = env.get("SPYTEST_TOPO_1", topologies[1])
    topologies[2] = env.get("SPYTEST_TOPO_2", topologies[2])
    topologies[3] = env.get("SPYTEST_TOPO_3", topologies[3])
    topologies[4] = env.get("SPYTEST_TOPO_4", topologies[4])
    topologies[5] = env.get("SPYTEST_TOPO_5", topologies[5])
    topologies[6] = env.get("SPYTEST_TOPO_6", topologies[6])
    topologies[7] = env.get("SPYTEST_TOPO_7", topologies[7])
    topologies[8] = env.get("SPYTEST_TOPO_8", topologies[8])

    def copy_file(src, index, bucket, inst):
        dst = "testbed_{}_{}_{}.yaml".format(index, bucket, inst)
        new_filename = os.path.join(logs_path, dst)
        shutil.copy(src, new_filename)
        os.chmod(new_filename, 0o644)
        testbed_files.append(new_filename)
        return (dst, new_filename)

    # testbed for default bucket
    prev_bucket = 0 if not buckets else buckets[0] + 1
    for index, tb in enumerate(tb_objs):
        file_path = tb.get_file_path()
        (bucket, min_bucket, testbed) = (100, prev_bucket, file_path)
        (fname, fpath) = copy_file(testbed, index+1, min_bucket, 0)
        trace("Copying Testbed {} as {}".format(testbed, [fname]))
        msg = "Use {} for Buckets(>={}) with devices {}"
        trace(msg.format(fname, bucket, tb.get_device_names("DUT")))
        ret_list.append([bucket, min_bucket, None, [fpath]])

    # create mini testbed files for each bucket
    for i,bucket in enumerate(buckets):
        trace("============> create mini testbed files for {} bucket".format(bucket))
        try: min_bucket = buckets[i+1] + 1
        except Exception: min_bucket = 1
        if bucket not in topologies:
            msg = "bucket {} is not found in supported, using higher bucket {} testbed"
            warn(msg.format(bucket, prev_bucket))
            continue
        for index, tb in enumerate(tb_objs):
            possible_topos = []
            for topo in topologies[bucket].split("||"):
                [slist, props, _] = tb.identify_topology(wa.logger, tb, None, 100, topo)
                if not slist or len(slist) <= 0:
                    continue
                seed = utils.get_random_seed()
                Random(seed).shuffle(slist)
                possible_topos.append([slist, props])
            if not possible_topos:
                msg = "Failed to create testbed for bucket {} topo {} using higher bucket {} testbed"
                warn(msg.format(bucket, topologies[bucket], prev_bucket))
                continue
            tmp_tbs, inst = [], 0
            for [slist, props] in possible_topos:
                for duts_dict in slist:
                    dut_list = Testbed.get_dut_list(duts_dict)
                    mini_testbed = tb.rebuild_topo_file(dut_list, props)
                    yaml_file = Testbed.write_file(mini_testbed, "batch_testbed_", ".yaml")
                    inst = inst + 1
                    (fname, fpath) = copy_file(yaml_file, index+1, bucket, inst)
                    msg = "Created {} for bucket({}-{}) with devices {}"
                    trace(msg.format(fname, min_bucket, bucket, duts_dict))
                    tmp_tbs.append(fpath)
            ret_list.append([bucket, min_bucket, testbed_files[index], tmp_tbs])
            prev_bucket = bucket

    return ret_list

def parse_args(numprocesses, buckets_csv, logs_path, augment_modules_csv):

    wa.augment_modules_csv = augment_modules_csv
    init_type_nodes()

    if get_slave_id(): return []

    filename = env.get("SPYTEST_TESTBED_FILE", "testbed.yaml")
    parts = filename.split(",")
    count = len(parts)
    if env.get("SPYTEST_FILE_MODE", "0") != "0":
        if numprocesses and count < numprocesses:
            for _ in range(count, numprocesses):
                parts.append(parts[0])
            count = numprocesses
    [_, count, parts] = parse_buckets(count, parts, buckets_csv, logs_path)
    for i,part in enumerate(parts):
        os.environ["SPYTEST_TESTBED_FILE_gw{}".format(i)] = part
    os.environ["SPYTEST_TESTBED_FILE"] = parts[0]
    if numprocesses or count > 1 or buckets_csv:
        os.environ["SPYTEST_BATCH_RUN"] = "1"
        numprocesses2 = len(wa.slaves) or 1
        numprocesses = numprocesses or 0
        if numprocesses2 > numprocesses:
            numprocesses = numprocesses2
        retval = ["-n", str(numprocesses)]
        retval.extend(["--max-worker-restart", str(0)])
        #######################################################################
        # this is not working when the paths are not specified in command line
        #######################################################################
        #if is_deadnode_recovery() and buckets > 0:
            #retval.append("batch/test_spytest_infra_1.py")
        #######################################################################
        return dist.parse_args(count, retval)
    return []

def create_slave(i, j, node_type, prefix=""):
    name = build_node_name(i, prefix)
    bucket = wa.buckets[j]
    tb_obj = wa.testbed_objs[j]
    slave = SpyTestDict()
    slave.gw_node_index = i
    slave.testbed_index = j
    slave.gw_node = None
    slave.node_type = node_type
    slave.name = name
    slave.bucket = bucket
    slave.min_bucket = wa.min_buckets[j]
    slave.testbed = wa.testbeds[j]
    slave.parent_testbed = wa.parent_testbeds[j]
    slave.tb_obj = tb_obj
    slave.completed = False
    slave.excluded = 0
    slave.complete_time = None
    slave.assigned = 0
    slave.nes_partial = []
    slave.nes_full = []
    slave.load_infra_tests = is_deadnode_recovery()
    slave.pid = 0
    if i >= wa.count:
        slave.started = False
    elif wa.reverse_run_order:
        slave.started = True if bucket >= wa.buckets[-1] else False
    else:
        slave.started = True if bucket >= wa.buckets[0] else False
    slave.start_time = get_timenow() if slave.started else None
    return slave

def register_slave(slave):
    wa.slaves[slave.name] = slave
    wa.free_devices[slave.testbed] = []
    wa.excluded_devices[slave.testbed] = []
    wa.loaded_devices = []

def parse_buckets(count, testbeds, buckets_csv, logs_path):
    wa.logs_path = logs_path
    wa.testbeds = testbeds
    wa.count = count

    if buckets_csv:
        # force to use custom scheduling
        wa.custom_scheduling = True
    else:
        wa.custom_scheduling = bool(env.get("SPYTEST_SCHEDULING"))

    if not wa.custom_scheduling:
        return [0, count, testbeds]

    #debug("============== parsing batch info =====================")
    trace("============> Buckets = {}".format(buckets_csv))

    # init return values
    (tb_objs) = ([])

    # concat all the bucket args
    buckets_csv = ",".join(buckets_csv) if buckets_csv else ""

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
        tb = Testbed(testbed, logger=wa.logger, flex_dut=True)
        if not tb.is_valid():
            msg = "testbed file {} is not valid"
            trace(msg.format(testbed))
            os._exit(100)
        #trace("Testbed: {}".format(testbed))
        #trace("  Devices: {}".format(tb.get_device_names("DUT")))
        tb_objs.append(tb)

    # initialize collected lists
    for key in ["testbeds", "buckets", "min_buckets", "parent_testbeds", "testbed_objs"]:
        wa[key] = []
    for key in ["free_devices", "excluded_devices"]:
        wa[key] = dict()

    # use given testbeds for tests needs higher topology
    # than the spefified buckets
    trace("============> Crearing Bucket Testbed files")
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
            msg = "testbed file {} is not valid"
            trace(msg.format(fname))
            os._exit(100)
        msg = "Topology({}): {}"
        trace(msg.format(fname, tb.get_topo()))
        wa.testbed_objs.append(tb)

    wa.slaves.clear()
    wa.count = len(wa.testbeds)
    wa.logs_path = logs_path

    min_bucket, max_bucket = wa.buckets[0], wa.buckets[0]
    for i in range(0, wa.count):
        slave = create_slave(i, i, "Main")
        if slave.bucket < min_bucket:
            min_bucket = slave.bucket
        elif slave.bucket > max_bucket:
            max_bucket = slave.bucket
        register_slave(slave)
    wa.min_bucket = min_bucket
    wa.max_bucket = max_bucket

    # add backup and/or rerun nodes
    new_slaves, node_index = [], len(wa.slaves)
    for node_type in ["Backup", "ReRun"]:
        trace("============> Add {} Nodes".format(node_type))
        if node_type == "Backup":
            type_nodes = wa.backup_nodes
            nodes_multiplier = wa.backup_nodes_multiplier
        else:
            type_nodes = wa.rerun_nodes
            nodes_multiplier = wa.rerun_nodes_multiplier
        if type_nodes is None: continue
        for bucket in range(max_bucket, min_bucket-1, -1):
            for slave in wa.slaves.values():
                if slave.bucket != bucket: continue
                max_type_nodes = nodes_multiplier if type_nodes == 0 else type_nodes
                for type_node in range(max_type_nodes):
                    # TODO: check on how to avoid using first combination always
                    new_slave = create_slave(node_index, slave.testbed_index, node_type)
                    debug("Create {} node {} for {} {}".format(node_type, type_node, slave.name, new_slave.name))
                    new_slaves.append(new_slave)
                    node_index = node_index + 1
                if type_nodes != 0:
                    # fixed number of backup/rerun nodes already created
                    break # go to next bucket
    for new_slave in new_slaves:
        register_slave(new_slave)

    # let the testbeds in min bucket handle all lower buckets
    for slave in wa.slaves.values():
        if slave.bucket <= min_bucket:
            slave.min_bucket = 0

    trace("=======================================================")
    _show_testbed_topo()
    _show_testbed_info()
    return [len(wa.buckets), len(wa.testbeds), wa.testbeds]

def verify_bucket(nodeid, used, fails):
    if fails != 0:
        trace("SKIP verify bucket", nodeid, fails, used)
    elif not wa.custom_scheduling:
        debug("Not valid for current scheduling type", nodeid, fails, used)
    elif nodeid not in wa.sched.main_modules:
        trace("Module not found in modules.csv", nodeid)
    elif wa.sched.main_modules[nodeid].bucket != used:
        trace("Mismatch bucket information", nodeid, used, wa.sched.main_modules[nodeid].bucket)

def is_batch():
    return bool(env.get("SPYTEST_BATCH_RUN"))

def is_master():
    return bool(not is_slave() and is_batch())

def get_slave_id():
    return env.get("PYTEST_XDIST_WORKER")

def is_slave():
    return bool(get_slave_id())

def is_member():
    return bool(is_slave() or not is_batch())

def get_member_count():
    return len(wa.slaves) or 1

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
    if env.get("SPYTEST_BUCKETS_DEADNODE_SIMULATE", "0") != "0":
        for scope in args:
            if scope == 0 and randint(0, 100) > 80: os._exit(1)
            if scope == 1 and randint(0, 100) > 90: os._exit(1)
            if scope == 2 and randint(0, 100) > 95: os._exit(1)
            if scope == 3 and randint(0, 100) > 90:
                dut = kwargs.get("dut", "D1")
                file_path = os.path.join(wa.logs_path, "node_dead")
                utils.write_file(file_path, " " + dut, "a")
                os._exit(1)

