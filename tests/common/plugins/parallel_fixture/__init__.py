import bisect
import contextlib
import ctypes
import enum
import functools
import logging
import pytest
import threading
import time
import traceback
import sys

from concurrent.futures import CancelledError
from concurrent.futures import FIRST_EXCEPTION
from concurrent.futures import ALL_COMPLETED
from concurrent.futures import Future
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError
from concurrent.futures import wait


class TaskScope(enum.Enum):
    """Defines the lifecycle scopes for parallel task."""
    SESSION = 0
    MODULE = 1
    CLASS = 2
    FUNCTION = 3


class ParallelTaskRuntimeError(BaseException):
    pass


class ParallelTaskTerminatedError(BaseException):
    pass


def raise_async_exception(tid, exc_type):
    """Injects an exception into the specified thread."""
    if not isinstance(tid, int):
        raise TypeError("Thread ID must be an integer")

    ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_long(tid),
                                               ctypes.py_object(exc_type))


_log_context = threading.local()
_original_log_factory = logging.getLogRecordFactory()


def _prefixed_log_factory(*args, **kwargs):
    record = _original_log_factory(*args, **kwargs)
    # Check if we are inside a parallel task wrapper
    prefix = getattr(_log_context, "prefix", None)
    if prefix:
        # Prepend the prefix to the log message
        # This handles standard logging.info("msg") calls
        record.msg = f"{prefix} {record.msg}"
    return record


# Apply the factory globally
logging.setLogRecordFactory(_prefixed_log_factory)


class ParallelFixtureManager(object):

    DEFAULT_WAIT_TIMEOUT = 180
    THREAD_POOL_POLLING_INTERVAL = 0.1

    TASK_SCOPE_SESSION = TaskScope.SESSION
    TASK_SCOPE_MODULE = TaskScope.MODULE
    TASK_SCOPE_CLASS = TaskScope.CLASS
    TASK_SCOPE_FUNCTION = TaskScope.FUNCTION

    class ParallelTaskFuture(Future):
        """A Future subclass that supports timeout handling with thread interruption."""

        @property
        def default_result(self):
            if hasattr(self, '_default_result'):
                return self._default_result
            return None

        @default_result.setter
        def default_result(self, value):
            self._default_result = value

        @property
        def timeout(self):
            if hasattr(self, '_timeout'):
                return self._timeout
            return None

        @timeout.setter
        def timeout(self, value):
            self._timeout = value

        def result(self, timeout=None, interrupt_when_timeout=False,
                   return_default_on_timeout=False):
            try:
                return super().result(timeout=timeout)
            except TimeoutError:
                task_name = self.task_name
                if self.cancel():
                    logging.warning("[Parallel Fixture] Task %s timed out and was cancelled.", task_name)
                elif self.running() and interrupt_when_timeout:
                    task_context = getattr(self, 'task_context', None)
                    if task_context and hasattr(task_context, 'tid'):
                        tid = task_context.tid
                        if tid:
                            logging.warning(
                                "[Parallel Fixture] Task %s timed out. Interrupting thread %s.",
                                task_name, tid
                            )
                            raise_async_exception(tid, ParallelTaskTerminatedError)
                        else:
                            logging.warning("[Parallel Fixture] Task %s timed out but TID not found.", task_name)
                if return_default_on_timeout:
                    logging.info("[Parallel Fixture] Task %s returning default result on timeout: %s",
                                 task_name, self.default_result)
                    return self.default_result
                raise

    class ParallelTaskContext(object):
        """Context information for a parallel task."""
        def __init__(self, tid=None, start_time=None, end_time=None, task_name=None):
            self.tid = tid
            self.start_time = start_time
            self.end_time = end_time
            self.task_name = task_name

    def __init__(self, worker_count):
        self.terminated = False
        self.worker_count = worker_count
        self.executor = ThreadPoolExecutor(max_workers=worker_count)

        # Initialize buckets for all defined scopes
        self.setup_futures = {scope: [] for scope in TaskScope}
        self.teardown_futures = {scope: [] for scope in TaskScope}
        self.current_scope = None

        # Start the background monitor thread
        self.monitor_lock = threading.Lock()
        self.active_futures = set()
        self.done_futures = set()
        self.is_monitor_running = True
        self.monitor_thread = threading.Thread(target=self._monitor_workers, daemon=True)
        self.monitor_thread.start()

    def _monitor_workers(self):
        """Monitor thread pool tasks."""
        i = 0
        while True:
            future_threads = {}
            with self.monitor_lock:
                done_futures = set()
                for f in self.active_futures:
                    tid = f.task_context.tid
                    if tid is not None:
                        future_threads[tid] = f
                    if f.done():
                        done_futures.add(f)
                        if f.exception():
                            logging.info("[Parallel Fixture] Detect exception from task %s: %s",
                                         f.task_name, f.exception())
                        else:
                            logging.info("[Parallel Fixture] Detect task %s is done", f.task_name)
                self.active_futures -= done_futures
                self.done_futures |= done_futures

            if i % 100 == 0:
                # Log the running task of each thread pool worker
                # every 10 seconds
                log_msg = ["[Parallel Fixture] Current worker threads status:"]
                current_time = time.time()
                if self.executor._threads:
                    current_threads = list(self.executor._threads)
                    current_threads.sort(key=lambda t: (len(t.name), t.name))
                    for thread in current_threads:
                        if thread.is_alive():
                            if thread.ident in future_threads:
                                start_time = future_threads[thread.ident].task_context.start_time
                                log_msg.append(f"Thread {thread.name}: "
                                               f"{future_threads[thread.ident].task_name}, "
                                               f"{current_time - start_time}s")
                            else:
                                log_msg.append(f"Thread {thread.name}: idle")
                        else:
                            log_msg.append(f"Thread {thread.name}: terminated")
                else:
                    log_msg.append("No alive worker thread found.")
                logging.info("\n".join(log_msg))

            if not self.is_monitor_running:
                break

            time.sleep(ParallelFixtureManager.THREAD_POOL_POLLING_INTERVAL)
            i += 1

    def _resolve_scope(self, scope):
        """Ensure scope is a TaskScope Enum member."""
        if isinstance(scope, TaskScope):
            return scope
        try:
            return TaskScope(scope)
        except ValueError:
            raise ValueError(f"Invalid scope '{scope}'. "
                             f"Must be one of {[e.value for e in TaskScope]}")

    def _cancel_futures(self, futures):
        for future in futures:
            future.cancel()

    def _wait_for_futures(self, futures, timeout,
                          wait_strategy=FIRST_EXCEPTION, reraise=True,
                          raise_timeout_error=True):
        if not futures:
            return

        # Wait for all futures to complete
        done, not_done = wait(futures, timeout=timeout, return_when=wait_strategy)

        # Check for exceptions in completed tasks
        for future in done:
            if future.exception():
                # If any exception is raised, cancel the rest
                self._cancel_futures(not_done)
                if reraise:
                    raise ParallelTaskRuntimeError from future.exception()

        # Wait timeout, cancel the rest
        if not_done:
            # Attempt cancel to cleanup
            self._cancel_futures(not_done)
            if raise_timeout_error:
                raise TimeoutError(
                    f"Parallel Tasks Timed Out! "
                    f"{len(not_done)} tasks failed to complete within {timeout}s: "
                    f"{[f.task_name for f in not_done]}"
                )

    def _format_task_name(self, func, *args, **kwargs):
        task_name = f"{func.__name__}"
        if args:
            task_name += f"({args}"
        if kwargs:
            task_name += f", {kwargs}"
        if args or kwargs:
            task_name += ")"
        return task_name

    def _wrap_task(self, func, task_context):

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            tid = threading.get_ident()
            task_context.tid = tid
            task_context.start_time = time.time()
            current_thread = threading.current_thread().name

            prefix = f"[Parallel Fixture][{current_thread}][{task_context.task_name}]"
            # Set thread-local context for logging module
            _log_context.prefix = prefix
            try:
                return func(*args, **kwargs)
            except Exception:
                _, exc_value, exc_traceback = sys.exc_info()
                logging.error("[Parallel Fixture] Task %s exception:\n%s",
                              task_context.task_name,
                              traceback.format_exc())
                raise exc_value.with_traceback(exc_traceback)
            finally:
                _log_context.prefix = None
                task_context.end_time = time.time()
                logging.debug("[Parallel Fixture] Task %s finished in %.2f seconds",
                              task_context.task_name, task_context.end_time - task_context.start_time)

        return wrapper

    def wait_for_tasks_completion(self, futures, timeout=DEFAULT_WAIT_TIMEOUT,
                                  wait_strategy=ALL_COMPLETED, reraise=True):
        """Block until all given tasks are done."""
        logging.debug("[Parallel Fixture] Waiting for tasks to finish, timeout: %s", timeout)
        self._wait_for_futures(futures, timeout, wait_strategy, reraise)

    def submit_setup_task(self, scope, func, *args, **kwargs):
        """Submit a setup task to the parallel fixture manager."""
        scope = self._resolve_scope(scope)
        task_name = self._format_task_name(func, *args, **kwargs)
        logging.info("[Parallel Fixture] Submit setup task (%s): %s", scope, task_name)
        task_context = ParallelFixtureManager.ParallelTaskContext(task_name=task_name)
        wrapped_func = self._wrap_task(func, task_context)
        future = self.executor.submit(wrapped_func, *args, **kwargs)
        future.__class__ = ParallelFixtureManager.ParallelTaskFuture
        future.task_name = task_name
        future.task_context = task_context
        self.setup_futures[scope].append(future)
        with self.monitor_lock:
            self.active_futures.add(future)
        return future

    def submit_teardown_task(self, scope, func, *args, **kwargs):
        """Submit a teardown task to the parallel fixture manager."""
        scope = self._resolve_scope(scope)
        task_name = self._format_task_name(func, *args, **kwargs)
        logging.info("[Parallel Fixture] Submit teardown task (%s): %s", scope, task_name)
        task_context = ParallelFixtureManager.ParallelTaskContext(task_name=task_name)
        wrapped_func = self._wrap_task(func, task_context)
        future = self.executor.submit(wrapped_func, *args, **kwargs)
        future.__class__ = ParallelFixtureManager.ParallelTaskFuture
        future.task_name = task_name
        future.task_context = task_context
        self.teardown_futures[scope].append(future)
        with self.monitor_lock:
            self.active_futures.add(future)
        return future

    def wait_for_setup_tasks(self, scope,
                             timeout=DEFAULT_WAIT_TIMEOUT,
                             wait_strategy=FIRST_EXCEPTION, reraise=True):
        """Block until all setup tasks in a specific scope are done."""
        logging.debug("[Parallel Fixture] Waiting for setup tasks to finish, scope: %s, timeout: %s", scope, timeout)
        scope = self._resolve_scope(scope)
        futures = self.setup_futures.get(scope, [])
        self._wait_for_futures(futures, timeout, wait_strategy, reraise)

    def wait_for_teardown_tasks(self, scope,
                                timeout=DEFAULT_WAIT_TIMEOUT,
                                wait_strategy=FIRST_EXCEPTION, reraise=True):
        """Block until all teardown tasks in a specific scope are done."""
        logging.debug("[Parallel Fixture] Waiting for teardown tasks to finish, scope: %s, timeout: %s", scope, timeout)
        scope = self._resolve_scope(scope)
        futures = self.teardown_futures.get(scope, [])
        self._wait_for_futures(futures, timeout, wait_strategy, reraise)

    def terminate(self):
        """Terminate the parallel fixture manager."""

        if self.terminated:
            return

        logging.info("[Parallel Fixture] Terminating parallel fixture manager")

        self.terminated = True

        # Stop the monitor
        self.is_monitor_running = False
        self.monitor_thread.join()

        # Cancel any pending futures
        for future in self.active_futures:
            future.cancel()

        # Force terminate the thread pool workers that are still running
        running_futures = [future for future in self.active_futures if not future.done()]
        logging.debug("[Parallel Fixture] Running tasks to be terminated: %s", [_.task_name for _ in running_futures])
        if running_futures:
            logging.debug("[Parallel Fixture] Force interrupt thread pool workers")
            running_futures_tids = [future.task_context.tid for future in running_futures
                                    if future.task_context.tid is not None]
            for thread in self.executor._threads:
                if thread.is_alive() and thread.ident in running_futures_tids:
                    raise_async_exception(thread.ident, ParallelTaskTerminatedError)

        logging.debug("[Parallel Fixture] Current worker threads: %s",
                      [thread.is_alive() for thread in self.executor._threads])
        # Wait for all threads to terminate
        self.executor.shutdown(wait=True)
        logging.debug("[Parallel Fixture] Current worker threads: %s",
                      [thread.is_alive() for thread in self.executor._threads])

        cancel_futures = []
        stopped_futures = []
        pending_futures = []
        done_futures = self.done_futures
        for future in self.active_futures:
            try:
                exc = future.exception(0.1)
                if isinstance(exc, ParallelTaskTerminatedError):
                    stopped_futures.append(future)
            except CancelledError:
                cancel_futures.append(future)
            except TimeoutError:
                # NOTE: should never hit this as all futures are either
                # cancelled or stopped with ParallelTaskTerminatedError
                pending_futures.append(future)

        logging.debug(f"[Parallel Fixture] The fixture manager is terminated:\n"
                      f"stopped tasks {[_.task_name for _ in stopped_futures]},\n"
                      f"canceled tasks {[_.task_name for _ in cancel_futures]},\n"
                      f"pending tasks {[_.task_name for _ in pending_futures]},\n"
                      f"done tasks {[(_.task_name, _.exception()) for _ in done_futures]}.")

    def reset(self):
        """Reset the parallel fixture manager."""
        if not self.terminated:
            raise RuntimeError("Cannot reset a running parallel fixture manager.")

        # Reinitialize buckets for all defined scopes
        self.setup_futures = {scope: [] for scope in TaskScope}
        self.teardown_futures = {scope: [] for scope in TaskScope}
        self.current_scope = None

        self.active_futures.clear()
        self.done_futures.clear()
        self.executor = ThreadPoolExecutor(max_workers=self.worker_count)
        self.is_monitor_running = True
        self.monitor_thread = threading.Thread(target=self._monitor_workers, daemon=True)
        self.monitor_thread.start()
        self.terminated = False

    def check_for_exception(self):
        """Check done futures and re-raise any exception."""
        with self.monitor_lock:
            for future in self.done_futures:
                if future.exception():
                    raise ParallelTaskRuntimeError from future.exception()

    def is_task_finished(self, future):
        return future.done() and future.exception() is None

    def __del__(self):
        self.terminate()


@contextlib.contextmanager
def log_function_call_duration(func_name):
    start = time.time()
    logging.debug("[Parallel Fixture] Start %s", func_name)
    yield
    logging.debug("[Parallel Fixture] End %s, duration %s", func_name, time.time() - start)


# -----------------------------------------------------------------
# the parallel manager fixture
# -----------------------------------------------------------------


_PARALLEL_MANAGER = None


@pytest.fixture(scope="session", autouse=True)
def parallel_manager(tbinfo):
    dut_count = len(tbinfo.get("duts", []))
    worker_count = max(dut_count * 8, 16)
    global _PARALLEL_MANAGER
    _PARALLEL_MANAGER = ParallelFixtureManager(worker_count=worker_count)
    _PARALLEL_MANAGER.current_scope = TaskScope.SESSION
    return _PARALLEL_MANAGER


# -----------------------------------------------------------------
# the setup barrier fixtures
# -----------------------------------------------------------------


@pytest.fixture(scope="session", autouse=True)
def setup_barrier_session(parallel_manager):
    """Barrier to wait for all session level setup tasks to finish."""
    with log_function_call_duration("setup_barrier_session"):
        parallel_manager.wait_for_setup_tasks(TaskScope.SESSION)
    parallel_manager.current_scope = TaskScope.MODULE
    yield
    return


@pytest.fixture(scope="module", autouse=True)
def setup_barrier_module(parallel_manager):
    """Barrier to wait for all module level setup tasks to finish."""
    with log_function_call_duration("setup_barrier_module"):
        parallel_manager.wait_for_setup_tasks(TaskScope.MODULE)
    parallel_manager.current_scope = TaskScope.CLASS
    yield
    return


@pytest.fixture(scope="class", autouse=True)
def setup_barrier_class(parallel_manager):
    """Barrier to wait for all class level setup tasks to finish."""
    with log_function_call_duration("setup_barrier_class"):
        parallel_manager.wait_for_setup_tasks(TaskScope.CLASS)
    parallel_manager.current_scope = TaskScope.FUNCTION
    yield
    return


@pytest.fixture(scope="function", autouse=True)
def setup_barrier_function(parallel_manager):
    """Barrier to wait for all function level setup tasks to finish."""
    with log_function_call_duration("setup_barrier_function"):
        parallel_manager.wait_for_setup_tasks(TaskScope.FUNCTION)
    parallel_manager.current_scope = None
    yield
    return


# -----------------------------------------------------------------
# the teardown barrier fixtures
# -----------------------------------------------------------------


@pytest.fixture(scope="session", autouse=True)
def teardown_barrier_session(parallel_manager):
    """Barrier to wait for all session level teardown tasks to finish."""
    yield
    with log_function_call_duration("teardown_barrier_session"):
        parallel_manager.wait_for_teardown_tasks(TaskScope.SESSION)
    parallel_manager.current_scope = None


@pytest.fixture(scope="module", autouse=True)
def teardown_barrier_module(parallel_manager):
    """Barrier to wait for all module level teardown tasks to finish."""
    yield
    with log_function_call_duration("teardown_barrier_module"):
        parallel_manager.wait_for_teardown_tasks(TaskScope.MODULE)
    parallel_manager.current_scope = TaskScope.SESSION


@pytest.fixture(scope="class", autouse=True)
def teardown_barrier_class(parallel_manager):
    """Barrier to wait for all class level teardown tasks to finish."""
    yield
    with log_function_call_duration("teardown_barrier_class"):
        parallel_manager.wait_for_teardown_tasks(TaskScope.CLASS)
    parallel_manager.current_scope = TaskScope.MODULE


@pytest.fixture(scope="function", autouse=True)
def teardown_barrier_function(parallel_manager):
    """Barrier to wait for all function level teardown tasks to finish."""
    yield
    with log_function_call_duration("teardown_barrier_function"):
        parallel_manager.wait_for_teardown_tasks(TaskScope.FUNCTION)
    parallel_manager.current_scope = TaskScope.CLASS


# -----------------------------------------------------------------
# pytest hooks
# -----------------------------------------------------------------


@pytest.hookimpl(wrapper=True)
def pytest_runtest_setup(item):
    """
    HOOK: Runs once BEFORE every fixture setup.
    Reorder the setup/teardown barriers to ensure barriers should run
    after ALL fixtures of the same-scope.
    """
    logging.debug("[Parallel Fixture] Setup barrier fixtures")

    barriers = {
        TaskScope.SESSION.value: ["teardown_barrier_session",
                                  "setup_barrier_session"],
        TaskScope.MODULE.value: ["teardown_barrier_module",
                                 "setup_barrier_module"],
        TaskScope.CLASS.value: ["teardown_barrier_class",
                                "setup_barrier_class"],
        TaskScope.FUNCTION.value: ["teardown_barrier_function",
                                   "setup_barrier_function"]
    }
    fixtureinfo = item._fixtureinfo
    current_fixture_names = fixtureinfo.names_closure[:]

    logging.debug("[Parallel Fixture] Fixture order before:\n%s", current_fixture_names)

    for fixtures in barriers.values():
        for fixture in fixtures:
            current_fixture_names.remove(fixture)
    current_fixture_scopes = []
    for fixture in current_fixture_names:
        fixture_defs = fixtureinfo.name2fixturedefs.get(fixture, [])
        if not fixture_defs:
            fixture_scope = current_fixture_scopes[-1]
        else:
            try:
                fixture_scope = TaskScope[fixture_defs[0].scope.upper()].value
            except Exception:
                logging.debug("[Parallel Fixture] Unknown fixture scope for %r,"
                              "default to previous scope", fixture_defs)
                fixture_scope = current_fixture_scopes[-1]
        current_fixture_scopes.append(fixture_scope)

    # NOTE: Inject the barriers to ensure they are running last
    # in the fixtures of the same scope.
    for scope, fixtures in barriers.items():
        for fixture in fixtures:
            if fixture.startswith("setup"):
                insert_pos = bisect.bisect_right(current_fixture_scopes, scope)
                current_fixture_names.insert(insert_pos, fixture)
                current_fixture_scopes.insert(insert_pos, scope)
            if fixture.startswith("teardown"):
                insert_pos = bisect.bisect_left(current_fixture_scopes, scope)
                current_fixture_names.insert(insert_pos, fixture)
                current_fixture_scopes.insert(insert_pos, scope)

    logging.debug("[Parallel Fixture] Fixture order after:\n%s", current_fixture_names)
    fixtureinfo.names_closure[:] = current_fixture_names

    yield
    return


@pytest.hookimpl(tryfirst=True)
def pytest_fixture_setup(fixturedef, request):
    """
    HOOK: Runs BEFORE every fixture setup.
    If a background task failed while the PREVIOUS fixture was running,
    we catch it here and stop the next fixture from starting.
    """
    if _PARALLEL_MANAGER:
        logging.debug("[Parallel Fixture] Check for fixture exceptions before running %r", fixturedef)
        _PARALLEL_MANAGER.check_for_exception()


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_call(item):
    """
    HOOK: Runs BEFORE the test function starts.
    Happy path to terminate the parallel fixture manager.
    All tasks should be done as those barrier fixtures should catch them
    all.
    """
    logging.debug("[Parallel Fixture] Wait for tasks to finish before test function")
    parallel_manager = _PARALLEL_MANAGER
    if parallel_manager:
        try:
            for scope in TaskScope:
                parallel_manager.wait_for_setup_tasks(scope)
        finally:
            parallel_manager.terminate()


def pytest_exception_interact(call, report):
    """
    HOOK: Runs WHEN an exception occurs.
    Sad path to terminate the parallel fixture manager.
    When a ParallelTaskRuntimeError is detected, tries to poll
    the rest running tasks and terminate the parallel manager.
    """
    parallel_manager = _PARALLEL_MANAGER
    if parallel_manager and report.when == "setup":
        reraise = not isinstance(call.excinfo.value, ParallelTaskRuntimeError)
        logging.debug("[Parallel Fixture] Wait for tasks to finish after exception occurred in setup %s",
                      call.excinfo.value)
        try:
            for scope in TaskScope:
                parallel_manager.wait_for_setup_tasks(scope, wait_strategy=ALL_COMPLETED, reraise=reraise)
        finally:
            parallel_manager.terminate()


def pytest_runtest_teardown(item, nextitem):
    """
    HOOK: Runs once BEFORE all fixture teardown.
    Reset the parallel manager.
    """
    logging.debug("[Parallel Fixture] Reset parallel manager before teardown")
    parallel_manager = _PARALLEL_MANAGER
    if parallel_manager:
        parallel_manager.reset()
        parallel_manager.current_scope = TaskScope.FUNCTION


def pytest_runtest_logreport(report):
    """
    HOOK: Runs once AFTER all fixture teardown.
    Terminate the parallel manager.
    """
    logging.debug("[Parallel Fixture] Terminate parallel manager after teardown")
    parallel_manager = _PARALLEL_MANAGER
    if parallel_manager:
        parallel_manager.terminate()
