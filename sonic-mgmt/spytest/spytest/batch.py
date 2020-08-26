import os
import sys
import csv
import shutil
from operator import itemgetter
from spytest.dicts import SpyTestDict
from spytest.testbed import Testbed
import spytest.spydist as dist
import utilities.common as utils

wa = SpyTestDict()
wa.parse_logs = []
wa.buckets = []
wa.print_func = None
wa.custom_scheduling = False
wa.debug_level = 0
wa.logs_path = ""
wa.executed = SpyTestDict()
wa.trace_file = None
wa.logger = None

def ftrace(msg):
    if not wa.trace_file:
        wa.trace_file = os.path.join(wa.logs_path, "batch_debug.log")
        utils.write_file(wa.trace_file, "")
    utils.write_file(wa.trace_file, "{}\n".format(msg), "a")

def debug(*args, **kwargs):
    if wa.debug_level > 0:
        trace(*args, **kwargs)
    else:
        ftrace(" ".join(map(str,args)))

def trace(*args, **kwargs):
    msg = " ".join(map(str,args))
    if wa.logger:
        wa.logger.info(msg)
    if wa.print_func is None:
        wa.parse_logs.append(msg)
        return
    if wa.parse_logs:
        wa.print_func("\n")
        for log in wa.parse_logs:
            wa.print_func("{}\n".format(log))
        wa.parse_logs = []
    wa.print_func("\n{}\n".format(msg))
    ftrace(msg)

def save_report():

    # show running
    (header, rows) = (['#', "Module", "Function", "TestCase", "Node", "Status"], [])
    for index, nodeid in enumerate(wa.executed):
        [node_name, status] = wa.executed[nodeid]
        if not node_name: continue
        parts = nodeid.split("::", 1)
        (module, func) = (parts[0], parts[1])
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
    utils.write_html_table(header, rows, filepath)

    # show pending
    (header, rows) = (['#', "Module", "Function", "TestCase", "Status"], [])
    for index, nodeid in enumerate(wa.executed):
        [node_name, status] = wa.executed[nodeid]
        if node_name: continue
        parts = nodeid.split("::", 1)
        (module, func) = (parts[0], parts[1])
        if "tclist" not in wa.tcmap:
            rows.append([len(rows)+1, module, func, func, status])
        elif func not in wa.tcmap.tclist:
            rows.append([len(rows)+1, module, func, func, status])
        else:
            for tcid in wa.tcmap.tclist[func]:
                rows.append([len(rows)+1, module, func, tcid, status])

    filepath = os.path.join(wa.logs_path, "batch_pending.csv")
    utils.write_csv_file(header, rows, filepath)
    filepath = os.path.splitext(filepath)[0]+'.html'
    utils.write_html_table(header, rows, filepath)

def report(op, nodeid, node_name):
    if op == "load":
        wa.executed[nodeid] = ["", "Pending"]
        return
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
    except Exception as exp:
        print(exp)

def shutdown():
    pass

class SpyTestScheduling(object):
    def __init__(self, config, wa, log=None):
        self.config = config
        self.count = len(config.getvalue("tx"))
        self.node_modules = {}
        self.collection_is_completed = False
        self.all_modules = SpyTestDict()
        self.buckets = {}
        self.order = {}
        self.order_support = True
        self.topo = {}
        self.topo_support = True
        self.base_names = {}
        self.wa = wa
        self.default_bucket = 4
        self.default_order = 2
        self.default_topo = ""
        self.max_order = self.default_order
        self._load_buckets()

    def _load_buckets(self):
        root = os.path.join(os.path.dirname(__file__), '..', "reporting")
        root = os.path.abspath(root)
        module_csv = os.getenv("SPYTEST_MODULE_CSV_FILENAME", "modules.csv")
        csv_file = os.path.join(root, module_csv)
        rows = []
        if os.path.exists(csv_file):
            with open(csv_file, 'r') as fd:
                for row in csv.reader(fd):
                    rows.append(row)
                fd.close()
        for row in rows:
            if len(row) < 3: continue
            topo = self.default_topo
            if len(row) > 3: topo = ",".join([str(i).strip() for i in row[3:]])
            bucket, order, name = [str(i).strip() for i in row[:3]]
            if bucket.startswith("#"): continue
            self.buckets[name] = utils.integer_parse(bucket, self.default_bucket)
            self.order[name] = utils.integer_parse(order, self.default_order)
            self.topo[name] = topo
            if self.max_order < self.order[name]:
                self.max_order = self.order[name]
            basename = os.path.basename(name)
            if basename in self.base_names:
                trace("duplicate basename {}".format(basename))
            else:
                self.base_names[basename] = name

    def add_node(self, node):
        self.node_modules[node] = []

    def remove_node(self, node):
        self.node_modules.pop(node)

    @property
    def tests_finished(self):
        if not self.collection_is_completed:
            return False
        for node, modules in self.node_modules.items():
            name = node.gateway.id
            if not self.wa.slaves[name].completed: return False
            if not self.wa.slaves[name].started: return False
            if len(modules) >= 2: return False
        debug("================ tests_finished ===========")
        return True

    @property
    def nodes(self):
        return list(self.node_modules.keys())

    @property
    def has_pending(self):
        debug("================ has_pending ===========")
        for node, modules in self.node_modules.items():
            name = node.gateway.id
            if not self.wa.slaves[name].completed: return True
            if not self.wa.slaves[name].started: return True
            if modules:
                return True
        return False

    def add_nodeid(self, nodeid, init):
        report("load", nodeid, "")
        mname = nodeid.split("::", 1)[0]
        if mname not in self.buckets:
            mname = os.path.basename(mname)
        if mname in self.base_names:
            mname = self.base_names[mname]
        if mname not in self.all_modules:
            self.all_modules[mname] = SpyTestDict()
            module = self.all_modules[mname]
            module.node_indexes = []
            module.nodes = []
            if mname in self.topo:
                module.topo = self.topo[mname]
            else:
                module.topo = self.default_topo
            if mname in self.order:
                module.order = self.order[mname]
            else:
                module.order = self.default_order
            if mname in self.buckets:
                module.bucket = self.buckets[mname]
            else:
                module.bucket = self.default_bucket
                if init:
                    trace("Module {} is not found in modules.csv".format(mname))
        self.all_modules[mname].node_indexes.append(self.collection.index(nodeid))

    def add_node_collection(self, node, collection):
        self.count = self.count - 1
        if self.count > 0:
            return

        # last node has registered the collection
        # generate module list
        self.collection_is_completed = True
        self.collection = collection
        for nodeid in collection:
            self.add_nodeid(nodeid, True)
        report("save", "", "")

        # identify the matching testbeds for custom topo
        for mname, minfo in self.all_modules.items():
            minfo.nodes = []
            for slave in wa.slaves.values():
                if minfo.bucket <= slave.bucket and \
                   minfo.bucket >= slave.min_bucket:
                    if minfo.topo:
                        [errs, p] = slave.tb_obj.ensure_min_topology(minfo.topo)
                        slave.tb_obj.reset_derived_devices()
                        if errs: continue
                    minfo.nodes.append(slave.name)
            if not minfo.nodes:
                # check if we can find match in higher buckets
                msg = "NO suitable testbed in bucket {} to execute {}"
                trace(msg.format(minfo.bucket, mname))
                for bucket in range(minfo.bucket+1, 100):
                    if minfo.nodes: break
                    for slave in wa.slaves.values():
                        if slave.bucket != bucket: continue
                        [errs, p] = slave.tb_obj.ensure_min_topology(minfo.topo)
                        slave.tb_obj.reset_derived_devices()
                        if not errs:
                            msg = "Using testbed {} to execute {}"
                            trace(msg.format(slave.name, mname))
                            minfo.nodes.append(slave.name)
                            break
                if not minfo.nodes:
                    # execute it gw0 as last option
                    msg = "Using testbed {} to execute {}"
                    trace(msg.format("gw0", mname))
                    minfo.nodes.append("gw0")
        self._show_module_info()
        _show_testbed_info()

    def _show_module_info(self, show=True):
        header = ["Module", "Bucket", "Tests", "Topology", "Nodes"]
        (mcount, tcount, rows) = (0, 0, [])
        for mname, minfo in self.all_modules.items():
            count = len(minfo.node_indexes)
            mcount = mcount + 1
            tcount = tcount + count
            nodes = ",".join(minfo.nodes)
            rows.append([mname, minfo.bucket, count, minfo.topo, nodes])
        rows = sorted(rows, key=itemgetter(1), reverse=True)
        retval = utils.sprint_vtable(header, rows)
        if show:
            trace("Modules: {} Functions: {}".format(mcount, tcount))
            trace(retval)
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

    def _assign_test(self, node, name):
        slave = self.wa.slaves[name]
        for order in range(0, self.max_order + 1):
            for mname,minfo in self.all_modules.items():
                if name not in minfo.nodes: continue
                if minfo.order != order and self.order_support:
                    continue
                del self.all_modules[mname]
                self.node_modules[node].extend(minfo.node_indexes)
                slave.executed = slave.executed + len(minfo.node_indexes)
                debug("ASSIGNED", name, minfo.order, mname, minfo.node_indexes)
                for item_index in minfo.node_indexes:
                    report("add", self.collection[item_index], node.gateway.id)
                report("save", "", "")
                return True
        return False

    def _schedule_node(self, node):
        name = node.gateway.id
        debug("================ _schedule_node =========== {}".format(node))
        if self.wa.slaves[name].completed: return
        if not self.wa.slaves[name].started: return
        if node.shutting_down: return
        prev_count = len(self.node_modules[node])
        if prev_count >= 2: return
        debug("================ load =========== {} {}".format(node, prev_count))
        for i in range(0,2):
            if len(self.node_modules[node]) < 2:
                self._assign_test(node, name)
        indexes = self.node_modules[node][prev_count:]
        if indexes: node.send_runtest_some(indexes)
        if len(self.node_modules[node]) >= 2:
            return
        debug("================ shutdown =========== {} {}".format(node, indexes))
        node.shutdown()

    def unfinished(self, node):
        return len(self.node_modules[node])

    def schedule(self, finished=None, error=None):
        debug("start", utils.get_proc_name())
        for node in self.node_modules:
            if node.gateway.id != finished:
                self._schedule_node(node)
                continue
            unfinished_tests = self.unfinished(node)
            if unfinished_tests <= 0:
                continue
            slave = wa.slaves[node.gateway.id]
            lines = []
            for item_index in self.node_modules[node]:
                report("remove", self.collection[item_index], node.gateway.id)
                lines.append(self.collection[item_index])
            report("save", "", "")
            if slave.executed <= unfinished_tests:
                for nodeid in lines:
                    self.add_nodeid(nodeid, False)
                msg = "{} finished without executing any tests."
                #msg = msg + " Adding back to pool"
                lines.insert(0, msg.format(node.gateway.id))
                trace("\n - ".join(lines))
                slave.executed = 0
            else:
                msg = "unfinished test cases"
                lines.insert(0, msg)
                trace("\n - ".join(lines))


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
    file_prefix = os.getenv("SPYTEST_FILE_PREFIX", "results")
    for slave in wa.slaves.values():
        filepath = os.path.join(wa.logs_path, slave.name, "{}_pid.txt".format(file_prefix))
        try: slave.pid = utils.read_lines(filepath)[0]
        except: pass

def _show_testbed_info(show=True):
    header = ["Node", "Buckets", "Node Testbed",
              "Status", "Devices", "Parent Testbed", "PID"]
    rows = []
    _read_pid(wa)
    for slave in wa.slaves.values():
        fname = os.path.basename(slave.testbed)
        if slave.completed is None: status = "Dead"
        elif slave.completed: status = "Completed"
        elif slave.started: status = "Running"
        else: status = "Waiting"
        devices = ",".join(slave.tb_obj.get_device_names("DUT"))
        parent_testbed = slave.parent_testbed
        if parent_testbed: parent_testbed = os.path.basename(parent_testbed)
        min_bucket = 1 if slave.min_bucket == 0 else slave.min_bucket
        if min_bucket == slave.bucket:
            bucket_range = "{}".format(slave.bucket)
        else:
            bucket_range = "{}-{}".format(min_bucket, slave.bucket)
        rows.append([slave.name, bucket_range, fname,
                     status, devices, parent_testbed, slave.pid])
    retval = utils.sprint_vtable(header, rows)
    if show: trace(retval)
    return retval

def init_stdout(config, logs_path):

    file_prefix = os.getenv("SPYTEST_FILE_PREFIX", "results")

    if is_slave():
        # create the stdout for the slaves
        filepath = "{}_stdout.log".format(file_prefix)
        filepath = os.path.join(logs_path, filepath)
        sys.stdout = open(filepath, 'w')
        sys.stderr = sys.stdout

    if is_master():
        # create the console file for the master
        tr = config.pluginmanager.getplugin('terminalreporter')
        if tr is not None:
            folder = os.path.join(logs_path, "master")
            if not os.path.exists(folder):
                os.makedirs(folder)
            filepath = os.path.join(folder, "{}_stdout.log".format(file_prefix))
            config._pytestsessionfile = open(filepath, 'w')
            oldwrite = tr._tw.write
            def tee_write(s, **kwargs):
                oldwrite(s, **kwargs)
                config._pytestsessionfile.write(str(s))
            tr._tw.write = tee_write
            wa.print_func = tee_write

def configure(config, logs_path):
    debug("============== batch configure =====================")
    wa.tcmap = dict()
    wa.logs_path = logs_path
    init_stdout(config, logs_path)
    dist.configure(config, logs_path, is_slave())
    return is_master()

def set_logger(logger):
    wa.logger = logger

def set_tcmap(tcmap):
    wa.tcmap = tcmap

def unconfigure(config):
    debug("============== batch unconfigure =====================")
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

def configure_nodes(config):
    debug("============== batch configure_nodes =====================")

def configure_node(node):
    debug("============== batch configure_node =====================")
    if not wa.custom_scheduling:
        return
    if node.gateway.id in wa.slaves:
        slave = wa.slaves[node.gateway.id]
        slave.completed = False
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
    else:
        trace("begin_node--unknown {}".format(gateway))

def finish_node(node, error):
    msg = "============== batch finish {} ====================="
    trace(msg.format(node.gateway.id))
    if not wa.custom_scheduling:
        return
    if node.gateway.id not in wa.slaves:
        trace("finish_node--unknown {}".format(node))
        return
    debug("finish_node {}".format(node))
    slave = wa.slaves[node.gateway.id]
    slave.completed = None if error else True
    # add the devices in the current testbed into free devices list
    devices = slave.tb_obj.get_device_names("DUT")

    # add the device info loaded devices if they have executed tests
    unfinished_tests = wa.sched.unfinished(node)
    debug("Node {} executed {} unfinished {}".format(node.gateway.id, slave.executed, unfinished_tests))
    if slave.executed > unfinished_tests:
        wa.loaded_devices.extend(devices)

    if slave.parent_testbed:
        wa.free_devices[slave.parent_testbed].extend(devices)
    else:
        wa.free_devices[slave.testbed].extend(devices)
    for name,slave in wa.slaves.items():
        if slave.started: continue
        ptestbed = slave.parent_testbed
        pdevices = wa.free_devices[ptestbed]
        devices = slave.tb_obj.get_device_names("DUT")
        # search if all devices in the current slave are in free pool
        slave.started =  all(dut in pdevices for dut in devices)
        loaded = all(dut in wa.loaded_devices for dut in devices)
        if slave.started:
            debug("Starting slave {} loaded {}".format(name, loaded))
            wa.free_devices[ptestbed] = utils.filter_list(pdevices, devices)
        else:
            debug("Waiting slave {} loaded {}".format(name, loaded))
        debug("wa.free_devices", slave.name, slave.started, ptestbed, wa.free_devices[ptestbed])

        # indicate if we need to skip the image loading
        if loaded:
            utils.write_file(os.path.join(wa.logs_path, slave.name, "slave_used"), "")
        else:
            utils.delete_file(os.path.join(wa.logs_path, slave.name, "slave_used"))

    wa.sched.schedule(node.gateway.id, error)
    _show_testbed_info()

    if error:
        trace("=======================================")
        trace("============ NODE DEAD {} =============".format(node.gateway.id))
        trace("=======================================")

topologies = {
    1 : "D1T1:2",
    2 : "D1T1:4 D1D2:6 D2T1:2",
    3 : "D1 D2 D3",
    4 : "D1T1:2 D2T1:2 D3T1:2 D4T1:2 D1D2:4 D2D3:4 D3D4:4 D4D1:4",
    5 : "D1 D2 D3 D4 D5",
    6 : "D1D3:4 D1D4:4 D1D5:2 D1D6:4 D2D3:4 D2D4:4 D2D5:4 D2D6:4 D3T1:2 D4T1:2 D5T1:2 D6T1:2",
    7 : "D1 D2 D3 D4 D5 D6 D7"
}

def _create_bucket_testbeds(tb_objs, buckets, logs_path):

    ret_list = []

    testbed_files = []

    topologies[1] = os.getenv("SPYTEST_TOPO_1", topologies[1])
    topologies[2] = os.getenv("SPYTEST_TOPO_2", topologies[2])
    topologies[3] = os.getenv("SPYTEST_TOPO_3", topologies[3])
    topologies[4] = os.getenv("SPYTEST_TOPO_4", topologies[4])
    topologies[5] = os.getenv("SPYTEST_TOPO_5", topologies[5])
    topologies[6] = os.getenv("SPYTEST_TOPO_6", topologies[6])
    topologies[7] = os.getenv("SPYTEST_TOPO_7", topologies[7])

    def copy_file(src, index, bucket, inst):
        dst = "testbed_{}_{}_{}.yaml".format(index, bucket, inst)
        new_filename = os.path.join(logs_path, dst)
        shutil.copy(src, new_filename)
        testbed_files.append(new_filename)
        return (dst, new_filename)

    # testbed fort default bucket
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
        try: min_bucket = buckets[i+1] + 1
        except: min_bucket = 1
        if bucket not in topologies:
            msg = "bucket {} is not found in supported, using higher bucket {} testbed"
            trace(msg.format(bucket, prev_bucket))
            continue
        for index, tb in enumerate(tb_objs):
            topo = topologies[bucket]
            [slist, props, errs] = tb.identify_topology(None, tb, None, 100, topo)
            if not slist or len(slist) <= 0:
                msg = "Failed to create testbed for bucket {} topo {} using higher bucket {} testbed"
                trace(msg.format(bucket, topo, prev_bucket))
                continue
            tmp_tbs = []
            for j,duts_dict in enumerate(slist):
                dut_list = Testbed.get_dut_list(duts_dict)
                mini_testbed = tb.rebuild_topo_file(dut_list, props)
                yaml_file = Testbed.write_file(mini_testbed, "batch_testbed_", ".yaml")
                (fname, fpath) = copy_file(yaml_file, index+1, bucket, j+1)
                msg = "Created {} for bucket({}-{}) with devices {}"
                trace(msg.format(fname, min_bucket, bucket, duts_dict))
                tmp_tbs.append(fpath)
            ret_list.append([bucket, min_bucket, testbed_files[index], tmp_tbs])
            prev_bucket = bucket

    return ret_list

def parse_args(numprocesses, buckets, logs_path):
    if os.getenv("SPYTEST_BATCH_DEBUG"):
        wa.debug_level = 1
    if os.getenv("PYTEST_XDIST_WORKER"):
        return []
    filename = os.getenv("SPYTEST_TESTBED_FILE", "testbed.yaml")
    parts = filename.split(",")
    count = len(parts)
    if numprocesses and count < numprocesses and os.getenv("SPYTEST_FILE_MODE"):
        for index in range(count, numprocesses):
            parts.append(parts[0])
        count = numprocesses
    [count, parts] = parse_buckets(count, parts, buckets, logs_path)
    for i,part in enumerate(parts):
        os.environ["SPYTEST_TESTBED_FILE_gw{}".format(i)] = part
    os.environ["SPYTEST_TESTBED_FILE"] = parts[0]
    if numprocesses or count > 1:
        os.environ["SPYTEST_BATCH_RUN"] = "1"
        return dist.parse_args(count, ["-n", str(count), "--max-worker-restart", str(0)])
    return []

def parse_buckets(count, testbeds, buckets_csv, logs_path):
    wa.testbeds = testbeds
    wa.count = count

    if buckets_csv:
        # force to use custom scheduling
        wa.custom_scheduling = True
    else:
        wa.custom_scheduling = bool(os.getenv("SPYTEST_SCHEDULING", None))

    if not wa.custom_scheduling:
        return [count, testbeds]

    trace("============== parsing batch info =====================")
    trace("Buckets = {}".format(buckets_csv))

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
    trace("Buckets - Sorted = {}".format(bucket_list))

    # create testbed objects for testbed files
    for j,testbed in enumerate(testbeds):
        tb = Testbed(testbed, flex_dut=True)
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
    for key in ["free_devices"]:
        wa[key] = dict()

    # use given testbeds for tests needs higher topology
    # than the spefified buckets
    data = _create_bucket_testbeds(tb_objs, bucket_list, logs_path)
    for bucket, min_bucket, parent_testbed, tbs in sorted(data, reverse=True):
        for index,testbed in enumerate(tbs):
            wa.buckets.append(bucket)
            wa.min_buckets.append(min_bucket)
            wa.testbeds.append(testbed)
            wa.parent_testbeds.append(parent_testbed)

    for testbed in wa.testbeds:
        fname = os.path.basename(testbed)
        tb = Testbed(testbed, flex_dut=True)
        if not tb.is_valid():
            msg = "testbed file {} is not valid"
            trace(msg.format(fname))
            os._exit(100)
        msg = "Topology({}): {}"
        trace(msg.format(fname, tb.get_topo()))
        wa.testbed_objs.append(tb)

    wa.slaves = SpyTestDict()
    wa.count = len(wa.testbeds)
    wa.logs_path = logs_path

    min_bucket = wa.buckets[0]
    for i in range(0, wa.count):
        node = "gw{}".format(i)
        bucket = wa.buckets[i]
        testbed = wa.testbeds[i]
        tb_obj = wa.testbed_objs[i]
        slave = SpyTestDict()
        slave.name = node
        slave.bucket = bucket
        slave.min_bucket = wa.min_buckets[i]
        slave.testbed = testbed
        slave.parent_testbed = wa.parent_testbeds[i]
        slave.tb_obj = tb_obj
        slave.completed = False
        slave.executed = 0
        slave.pid = 0
        slave.started = True if bucket >= wa.buckets[0] else False
        wa.slaves[node] = slave
        wa.free_devices[testbed] = []
        wa.loaded_devices = []
        if bucket < min_bucket:
            min_bucket = bucket

    # let the testbeds in min bucket handled all lower buckets
    for name, slave in wa.slaves.items():
        if slave.bucket <= min_bucket:
            slave.min_bucket = 0

    trace("=======================================================")
    _show_testbed_topo()
    _show_testbed_info()
    return [len(wa.testbeds), wa.testbeds]

def verify_bucket(nodeid, used, fails):
    if fails != 0:
        trace("SKIP verify bucket", nodeid, fails, used)
    elif not wa.custom_scheduling:
        debug("Not valid for current scheduling type")
    elif nodeid not in wa.sched.all_modules:
        trace("Module not found in modules.csv", nodeid)
    elif wa.sched.all_modules[nodeid].bucket != used:
        trace("Mismatch bucket information", nodeid, used, wa.sched.all_modules[nodeid].bucket)

def is_batch():
    return bool(os.getenv("SPYTEST_BATCH_RUN"))

def is_master():
    return bool(not is_slave() and is_batch())

def get_slave_id():
    return os.getenv("PYTEST_XDIST_WORKER")

def is_slave():
    return bool(get_slave_id())

def is_member():
    return bool(is_slave() or not is_batch())

def get_member_count():
    return wa.count

