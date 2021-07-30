from __future__ import print_function

import os
import rpyc
import signal
import threading
import time

import pytest
from multiprocessing import Process

import spytest
from spytest.dicts import SpyTestDict
import spytest.env as env

import utilities.common as utils

wa = SpyTestDict()
wa.parse_logs = []

# new batch implementation variables
wa.start_slaves_from_master = True
wa.slave_index = 1
wa.debug_level = 1

def debug(*args, **kwargs):
    if wa.debug_level > 0:
        trace(*args, **kwargs)

def trace(*args, **kwargs):
    msg = " ".join(map(str,args))
    print(msg)

class BatchService(rpyc.Service):
    def __init__(self):
        self.ready = False
        self.items = []
        self.status = []
        self.slave_pids = {}

    def set_items(self, items):
        self.items = items
        self.status = []
        for _ in items:
            self.status.append(0)
        self.ready = True

    def on_connect(self, conn):
        debug("BatchService connected", conn)

    def on_disconnect(self, conn):
        debug("BatchService disconnected", conn)

    def exposed_shutdown(self):
        for pid in self.slave_pids:
            os.kill(pid, signal.SIGTERM)

    def exposed_is_ready(self, pid):
        if pid not in self.slave_pids:
            self.slave_pids[pid] = 0
        return self.ready

    def exposed_has_pending(self):
        for i in range(0, len(self.status)):
            if self.status[i] != 2:
                return True
        return False

    def exposed_finish_test(self, nodeid):
        for i, ent in enumerate(self.items):
            if ent.nodeid == nodeid:
                self.status[i] = 2

    def exposed_get_test(self):
        for i, _ in enumerate(self.items):
            if self.status[i] == 0:
                self.status[i] = 1
                return self.items[i].nodeid
        return None

class BatchMaster(object):
    def __init__(self, config, logs_path):
        self.config = config
        self.logs_path = logs_path
        self.service = BatchService()
        self.port = 0
        self.server = None
        self.thread = None

    @pytest.hookimpl(trylast=True)
    def pytest_collection_modifyitems(self, session, config, items):
        debug("master:", session, config, items)
        self.service.set_items(items)

    @pytest.mark.trylast
    def pytest_sessionstart(self, session):
        debug("master: pytest_sessionstart", session)
        self.server = rpyc.utils.server.ThreadedServer(self.service)
        self.port = self.server.port
        filename = os.path.join(self.logs_path, "batch.server")
        utils.write_file(filename, str(self.server.port))
        self.thread = threading.Thread(target=self.server.start)
        self.thread.start()

    def pytest_sessionfinish(self, session):
        debug("master: pytest_sessionfinish", session)

    def pytest_runtestloop(self):
        if wa.start_slaves_from_master:
            slaves_init(self.logs_path)
        try:
            conn = rpyc.connect("127.0.0.1", self.port)
            while 1:
                if not getattr(conn.root, "has_pending")():
                    break
                debug("master: pytest_runtestloop")
                time.sleep(5)
        except KeyboardInterrupt:
            trace("master: interrupted")
            getattr(conn.root, "shutdown")()
            time.sleep(5)
        os._exit(0)

    def pytest_terminal_summary(self, terminalreporter):
        debug("master: pytest_terminal_summary", terminalreporter)

class BatchSlave(object):

    def __init__(self, config, logs_path):
        self.config = config
        self.items = []
        self.logs_path = logs_path

    @pytest.mark.trylast
    def pytest_sessionstart(self, session):
        debug("slave: pytest_sessionstart", session)

    def pytest_sessionfinish(self, session):
        debug("slave: pytest_sessionfinish", session)

    @pytest.hookimpl(trylast=True)
    def pytest_collection_modifyitems(self, session, config, items):
        debug("slave: pytest_collection_modifyitems", session, config, items)
        self.items = items

    def pytest_runtestloop(self):

        def search_nodeid(entries, nodeid):
            for ent in entries:
                if nodeid == ent.nodeid:
                    return ent
            return None

        def finish_test(item):
            getattr(conn.root, "finish_test")(item.nodeid)

        def get_test(entries):
            while 1:
                nodeid = getattr(conn.root, "get_test")()
                if not nodeid:
                    break
                item = search_nodeid(entries, nodeid)
                if item:
                    return item
            return None

        # connect to batch server
        conn = None
        for _ in range(0, 10):
            try:
                filename = os.path.join(self.logs_path, "..", "batch.server")
                lines = utils.read_lines(filename)
                port = int(lines[0])
                conn = rpyc.connect("127.0.0.1", port)
                if conn and conn.root:
                    break
                time.sleep(2)
            except Exception as exp:
                print("connect to batch server", exp, filename, port)
                time.sleep(2)

        try:
            item_list = []

            # wait for master ready
            is_ready = getattr(conn.root, "is_ready")
            while not is_ready(os.getpid()):
                trace("slave: waiting for master")
                time.sleep(2)

            # get first item
            item = get_test(self.items)
            if item:
                item_list.append(item)

            while 1:
                # check if there is some thing to do
                if not item_list:
                    break

                # get next item
                item = get_test(self.items)
                if item:
                    item_list.append(item)

                # get the item and next for the current execution
                [item, nextitem] = [item_list.pop(0), None]
                if item_list:
                    nextitem = item_list[-1]

                debug("slave: pytest_runtestloop", item, nextitem)
                self.config.hook.pytest_runtest_protocol(item=item, nextitem=nextitem)
                finish_test(item)
        except KeyboardInterrupt:
            trace("slave: interrupted")
        conn.close()
        trace("")
        os._exit(0)

    def pytest_terminal_summary(self, terminalreporter):
        debug("slave: pytest_terminal_summary", terminalreporter)

def get_impl_type():
    return 0 # not yet supported
    #new_bach_run = env.get("SPYTEST_BATCH_RUN_NEW")
    #if new_bach_run == "2":
        #return 2
    #return 1 if bool(new_bach_run) else 0

def shutdown():
    if get_impl_type() == 0:
        return
    if wa.server: wa.server.stop()
    if wa.service: wa.service.close()

def slave_main(index, testbed_file, logs_path):

    os.environ["PYTEST_XDIST_WORKER"] = str(index)
    key = "SPYTEST_TESTBED_FILE_gw{}".format(index)
    os.environ[key] = testbed_file
    os.environ["SPYTEST_TESTBED_FILE"] = testbed_file
    spytest.main.main(True)

def slave_start(testbed_file, logs_path):
    debug("starting slave", testbed_file, wa.slave_index)
    p = Process(target=slave_main, args=(wa.slave_index,testbed_file,logs_path))
    p.start()
    wa.slave_index = wa.slave_index + 1

def slaves_init(logs_path):
    if get_impl_type() == 2:
        # present auto slave init
        return
    count = wa.count
    for index in range(0, count):
        key = "SPYTEST_TESTBED_FILE_gw{}".format(index)
        slave_start(env.get(key), logs_path)

def configure(config, logs_path, is_slave):
    if get_impl_type() == 0:
        return
    if is_slave:
        debug("============== batch configure slave =====================")
        slave = BatchSlave(config, logs_path)
        config.pluginmanager.register(slave, "batch.slave")
    else:
        debug("============== batch configure master =====================")
        if "SPYTEST_BATCH_RUN" in os.environ:
            del os.environ["SPYTEST_BATCH_RUN"]
        master = BatchMaster(config, logs_path)
        config.pluginmanager.register(master, "batch.master")

def parse_args(count, l):
    if get_impl_type() == 0:
        return l
    wa.count = count
    return []

