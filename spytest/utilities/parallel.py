
import sys
import time
import traceback
import threading
import utilities.common as utils

# change this to 1 to force single entry thread calls
min_items = 2

shutting_down = False
def set_shutting_down():
    global shutting_down
    shutting_down = True

in_parallel = 0
def set_in_parallel(val):
    global in_parallel
    if val:
        in_parallel = in_parallel + 1
    else:
        in_parallel = in_parallel - 1

def get_in_parallel():
    return in_parallel

def wait_for_threads(threads):
    while True:
        alive = False
        for index, thread in enumerate(threads):
            thread.join(timeout=1)
            if thread.is_alive():
                alive=True
        if not alive or shutting_down:
            break

def exec_foreach (use_threads, items, func, *args, **kwargs):
    set_in_parallel(True)
    retvals = list()
    exceptions = list()
    def _thread_func(index, *args, **kwargs):
        try:
            retvals[index] = func(*args, **kwargs)
            exceptions[index] = None
        except Exception as e1:
            retvals[index] = None
            exceptions[index] = traceback.format_exc()
        except SystemExit as e2:
            retvals[index] = None
            exceptions[index] = e2

    threads = list()
    args_list = list(args)
    args_list.insert(0, "")
    args_list.insert(0, retvals)
    index = 0
    for item in items:
        retvals.append(None)
        exceptions.append(None)
        args_list[0] = index
        index = index + 1
        args_list[1] = item
        args = tuple(args_list)
        if not use_threads or len(items) < min_items:
            _thread_func(*args, **kwargs)
        else:
            x = threading.Thread(target=_thread_func, args=args, kwargs=kwargs)
            threads.append(x)
            x.start()
    wait_for_threads(threads)
    set_in_parallel(False)
    for exp in exceptions:
        if isinstance(exp, SystemExit):
            sys.exit()
    return [retvals, exceptions]

# remove this once refactored
class ExecAllFunc(utils.ExecAllFunc):
    pass

# rename this once refactored
class ExecAllFunc_todo_rename(object):
    def __init__(self, func, *args, **kwargs):
        self.func = func
        self.args = args
        self.kwargs = kwargs

def exec_all(use_threads, entries, first_on_main=False):
    set_in_parallel(True)
    retvals = list()
    exceptions = list()
    def _thread_func(func, index, *args, **kwargs):
        try:
            retvals[index] = func(*args, **kwargs)
            exceptions[index] = None
        except Exception as e1:
            retvals[index] = None
            exceptions[index] = traceback.format_exc()
        except SystemExit as e2:
            retvals[index] = None
            exceptions[index] = e2

    f_args = None
    f_kwargs = {}
    threads = list()
    index = 0
    for entry in entries:
        if isinstance(entry, utils.ExecAllFunc):
            kwargs = entry.kwargs
            entry2 = [entry.func]
            entry2.extend(list(entry.args))
        else:
            kwargs = {}
            entry2 = entry
        entry2.insert(1, index)
        index = index + 1
        args = tuple(entry2)
        retvals.append(None)
        exceptions.append(None)
        if not f_args and first_on_main:
            f_args = args
            f_kwargs = kwargs
        elif not use_threads or len(entries) < min_items:
            _thread_func(*args, **kwargs)
        else:
            x = threading.Thread(target=_thread_func, args=args, kwargs=kwargs)
            threads.append(x)
            x.start()
    if first_on_main:
        _thread_func(*f_args, **f_kwargs)
    wait_for_threads(threads)
    set_in_parallel(False)
    for exp in exceptions:
        if isinstance(exp, SystemExit):
            sys.exit()
    return [retvals, exceptions]

def exec_parallel(use_threads, items, func, kwarg_list,*args):
    """
    Author:sooria.gajendrababu@broadcom.com
    Info: parallel execution function for APIs with only kwargs
    :param args:
    :return:

    Usage:
    dict1 ={"local_asn":dut1_as,'neighbor_ip':enable_bfd_list_1,'config':'yes'}
    dict2 ={"local_asn":dut3_as,'neighbor_ip':enable_bfd_list_2,'config':'yes'}
    exec_parallel(True,[dut1,dut3],bfd.configure_bfd,[dict1,dict2])
    """
    set_in_parallel(True)
    retvals = list()
    exceptions = list()
    def _thread_func(index, *args, **kwargs):
        try:
            retvals[index] = func(*args, **kwargs)
            exceptions[index] = None
        except Exception as e1:
            retvals[index] = None
            exceptions[index] = traceback.format_exc()
        except SystemExit as e2:
            retvals[index] = None
            exceptions[index] = e2
    threads = list()
    args_list = list(args)
    args_list.insert(0, "")
    args_list.insert(0, retvals)
    index = 0
    for item,kwargs in zip(items,kwarg_list):
        retvals.append(None)
        exceptions.append(None)
        args_list[0] = index
        index = index + 1
        args_list[1] = item
        args = tuple(args_list)
        if not use_threads or len(items) < min_items:
            _thread_func(*args, **kwargs)
        else:
            x = threading.Thread(target=_thread_func, args=args, kwargs=kwargs)
            threads.append(x)
            x.start()
    wait_for_threads(threads)
    set_in_parallel(False)
    for exp in exceptions:
        if isinstance(exp, SystemExit):
            sys.exit()
    return [retvals, exceptions]

class ExecuteBackgroud(object):
    def __init__(self):
        self.finished = False
        self.func = None
        self.args = ()
        self.kwargs = ()
        self.event = threading.Event()
        self.event.clear()
        self.t = threading.Thread(target=self._thread_func)

    def start(self, func, *args, **kwargs):
        self.finished = False
        self.func = func
        self.args = args
        self.kwargs = kwargs
        self.t.start()

    def run(self):
        self.event.set()

    def stop(self):
        self.finished = True
        self.event.set()
        time.sleep(1)

    def is_valid(self):
        return bool(self.func)

    def _thread_func(self):
        try:
            while True:
                self.event.wait()
                if self.finished:
                    return
                if self.func:
                    self.func(*self.args, **self.kwargs)
                self.event.clear()
        except Exception as e1:
            print(e1)
        except SystemExit as e2:
            print(e2)

def ensure_no_exception(values):
    """
    Importing st in function because this file has been imported by
    framework so we cannot import framework API here
    :param values:
    :return:
    """
    from spytest import st
    for exp in values:
        if exp is not None:
            st.report_fail("exception_observed", exp)
    return True


