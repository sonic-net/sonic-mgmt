import sys
import time
import ctypes
import traceback
import threading
import utilities.common as utils

class thread_with_exception(threading.Thread):
    def __init__(self, *args, **kwargs):
        threading.Thread.__init__(self, *args, **kwargs)

    def get_id(self):

        # returns id of the respective thread
        if hasattr(self, '_thread_id'):
            return self._thread_id
        for id, thread in threading._active.items():
            if thread is self:
                return id

    def raise_exception(self):
        thread_id = self.get_id()
        res = ctypes.pythonapi.PyThreadState_SetAsyncExc(thread_id,
              ctypes.py_object(SystemExit))
        if res > 1:
            ctypes.pythonapi.PyThreadState_SetAsyncExc(thread_id, 0)
            print('Exception raise failure')

class thread_with_trace(threading.Thread):
  def __init__(self, *args, **keywords):
    threading.Thread.__init__(self, *args, **keywords)
    self.killed = False

  def start(self):
    self.__run_backup = self.run
    self.run = self.__run
    threading.Thread.start(self)

  def __run(self):
    sys.settrace(self.globaltrace)
    self.__run_backup()
    self.run = self.__run_backup

  def globaltrace(self, frame, event, arg):
    if event == 'call':
      return self.localtrace
    else:
      return None

  def localtrace(self, frame, event, arg):
    if self.killed:
      if event == 'line':
        raise SystemExit()
    return self.localtrace

  def kill(self):
    self.killed = True

def create_thread(**kwargs):
    return threading.Thread(**kwargs)

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

def wait_for_parallel(count=60, delay=10):
    for _ in range(count):
        if not in_parallel:
            return True
        time.sleep(delay)
    return False

_post_parallel_func = None
_post_parallel_kwargs = None
def set_post_parallel(func, **kwargs):
    global _post_parallel_func
    global _post_parallel_kwargs
    _post_parallel_func = func
    _post_parallel_kwargs = kwargs

def post_parallel():
    if _post_parallel_func:
        _post_parallel_func(**_post_parallel_kwargs)

all_threads = []
def wait_for_threads(threads):
    for thread in threads:
        if thread not in all_threads:
            all_threads.append(thread)
    while True:
        alive = False
        for thread in threads:
            if not thread: continue
            thread.join(timeout=1)
            if thread.is_alive():
                alive=True
        if not alive or shutting_down:
            break
    for thread in threads:
        if thread in all_threads:
            all_threads.remove(thread)

def get_current_thread():
    return threading.currentThread()

def get_thread_name(thread=None):
    thread = thread or get_current_thread()
    name = thread.name.replace("MainThread", "Thread-0")
    try:
        num = int(name.replace("Thread-", ""))
        name = "T%04d: " % (num)
    except Exception:
        pass
    return name

def is_main_thread():
    main_thid = "T%04d: " % (0)
    return bool(get_thread_name() == main_thid)

threadLocal = None
def get_thread_local():
    global threadLocal
    if not threadLocal:
        threadLocal = threading.local()
    return threadLocal

def save_call_stack(value):
    threadLocal = get_thread_local()
    threadLocal.call_stack = value

def get_call_stack():
    threadLocal = get_thread_local()
    value = getattr(threadLocal, 'call_stack', [])
    return value

def exec_foreach2 (use_threads, on_except, items, func, *args, **kwargs):
    if func is None or not callable(func):
        raise ValueError("Expecting callable function")
    set_in_parallel(True)
    retvals, exceptions, call_stack, threads = [], [], [], []
    def _thread_func(index, *args, **kwargs):
        save_call_stack(call_stack[index])
        try:
            retvals[index] = func(*args, **kwargs)
            exceptions[index] = None
        except Exception:
            retvals[index] = None
            exceptions[index] = traceback.format_exc()
        except SystemExit as e2:
            retvals[index] = None
            exceptions[index] = e2

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
            threads.append(None)
            call_stack.append([])
            _thread_func(*args, **kwargs)
        else:
            call_stack.append(utils.get_call_stack(2))
            x = create_thread(target=_thread_func, args=args, kwargs=kwargs)
            threads.append(x)
            x.start()
    wait_for_threads(threads)
    set_in_parallel(False)
    post_parallel()
    for exp in exceptions:
        if isinstance(exp, SystemExit):
            sys.exit()

    ensure_no_exception(exceptions, on_except)
    return [retvals, exceptions, threads]

def exec_foreach (use_threads, items, func, *args, **kwargs):
    rv = exec_foreach2(use_threads, "abort", items, func, *args, **kwargs)
    return [rv[0], rv[1]]

# remove this once refactored
class ExecAllFunc(utils.ExecAllFunc):
    pass

# rename this once refactored
class ExecAllFunc_todo_rename(object):
    def __init__(self, func, *args, **kwargs):
        self.func = func
        self.args = args
        self.kwargs = kwargs

def exec_all2(use_threads, on_except, entries, first_on_main=False, wait_on_main=0):
    set_in_parallel(True)
    retvals, exceptions, call_stack, threads = [], [], [], []
    def _thread_func(func, index, *args, **kwargs):
        save_call_stack(call_stack[index])
        try:
            retvals[index] = func(*args, **kwargs)
            exceptions[index] = None
        except Exception:
            retvals[index] = None
            exceptions[index] = traceback.format_exc()
        except SystemExit as e2:
            retvals[index] = None
            exceptions[index] = e2

    f_args = None
    f_kwargs = {}
    index = 0
    for entry in entries:
        if isinstance(entry, utils.ExecAllFunc):
            kwargs = entry.kwargs
            entry2 = [entry.func]
            entry2.extend(list(entry.args))
        else:
            kwargs = {}
            entry2 = entry
        if entry2[0] is None or not callable(entry2[0]):
            set_in_parallel(False)
            raise ValueError("Expecting callable function")
        entry2.insert(1, index)
        index = index + 1
        args = tuple(entry2)
        retvals.append(None)
        exceptions.append(None)
        if not f_args and first_on_main:
            f_args = args
            f_kwargs = kwargs
            threads.append(None)
            call_stack.append([])
        elif not use_threads or len(entries) < min_items:
            threads.append(None)
            call_stack.append([])
            _thread_func(*args, **kwargs)
        else:
            call_stack.append(utils.get_call_stack(2))
            x = create_thread(target=_thread_func, args=args, kwargs=kwargs)
            threads.append(x)
            x.start()
    if first_on_main:
        if wait_on_main:
            time.sleep(wait_on_main)
        _thread_func(*f_args, **f_kwargs)
    wait_for_threads(threads)
    set_in_parallel(False)
    post_parallel()
    for exp in exceptions:
        if isinstance(exp, SystemExit):
            sys.exit()

    ensure_no_exception(exceptions, on_except)
    return [retvals, exceptions, threads]

def exec_all(use_threads, entries, first_on_main=False, wait_on_main=0):
    rv = exec_all2(use_threads, "abort", entries, first_on_main, wait_on_main)
    return [rv[0], rv[1]]

def exec_parallel2(use_threads, on_except, items, func, kwarg_list,*args):
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
    if func is None or not callable(func):
        raise ValueError("Expecting callable function")
    set_in_parallel(True)
    retvals, exceptions, call_stack, threads = [], [], [], []
    def _thread_func(index_, *args, **kwargs):
        save_call_stack(call_stack[index_])
        try:
            retvals[index_] = func(*args, **kwargs)
            exceptions[index_] = None
        except Exception:
            retvals[index_] = None
            exceptions[index_] = traceback.format_exc()
        except SystemExit as e2:
            retvals[index_] = None
            exceptions[index_] = e2
    args_list = list(args)
    args_list.insert(0, "")
    args_list.insert(0, retvals)
    index_ = 0
    for item,kwargs in zip(items,kwarg_list):
        retvals.append(None)
        exceptions.append(None)
        args_list[0] = index_
        index_ = index_ + 1
        args_list[1] = item
        args = tuple(args_list)
        if not use_threads or len(items) < min_items:
            threads.append(None)
            call_stack.append([])
            _thread_func(*args, **kwargs)
        else:
            call_stack.append(utils.get_call_stack(2))
            x = create_thread(target=_thread_func, args=args, kwargs=kwargs)
            threads.append(x)
            x.start()
    wait_for_threads(threads)
    set_in_parallel(False)
    post_parallel()
    for exp in exceptions:
        if isinstance(exp, SystemExit):
            sys.exit()
    ensure_no_exception(exceptions, on_except)
    return [retvals, exceptions, threads]

def exec_parallel(use_threads, items, func, kwarg_list,*args):
    rv = exec_parallel2(use_threads, "abort", items, func, kwarg_list,*args)
    return [rv[0], rv[1]]

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

def ensure_no_exception(values, action="abort"):
    """
    Importing st in function because this file has been imported by
    framework so we cannot import framework API here
    :param values:
    :return:
    """
    from spytest import st
    for exp in values:
        if exp is None: continue
        elif action == "abort": st.report_fail("exception_observed", exp)
        elif action == "trace": st.error("exception in thread: {}".format(exp))
    return True

class Lock(object):
    def __init__(self):
        self.lock = threading.Lock()
        self.cond = threading.Condition(threading.Lock())
        self.owner = None

    def trace(self, msg):
        #if self.owner: print("{} = {}".format(msg, self.owner))
        pass

    def acquire(self, block=True, timeout=None):
        if not timeout:
            self.trace("current")
            retval = self.lock.acquire(block)
            if retval:
                self.owner = utils.get_location(1)
                self.trace("new1")
            return retval
        with self.cond:
            current_time = start_time = time.time()
            while current_time < start_time + timeout:
                if self.lock.acquire(False):
                    self.owner = utils.get_location(1)
                    self.trace("new2")
                    return True
                self.trace("wait")
                self.cond.wait(timeout - current_time + start_time)
                current_time = time.time()
        return False

    def release(self):
        self.trace("old")
        self.owner = None
        return self.lock.release()

def callback(interval, init_wait, func, *args, **kwargs):
    def _thread_func():
        if init_wait > 0: time.sleep(init_wait)
        while True:
            func(*args, **kwargs)
            time.sleep(interval)
    t = threading.Thread(target=_thread_func)
    t.daemon = True
    t.start()
