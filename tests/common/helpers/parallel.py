import ansible
import datetime
import logging
import math
import os
import shutil
import signal
import tempfile
import threading
import time
import traceback
from multiprocessing import Process, Manager, Pipe, TimeoutError
from multiprocessing.pool import ThreadPool
from ansible.executor.process.worker import WorkerProcess

from psutil import wait_procs

from tests.common.helpers.assertions import pytest_assert as pt_assert

logger = logging.getLogger(__name__)


def patch_ansible_worker_process():
    """Patch AnsibleWorkerProcess to avoid logging deadlock after fork."""

    def start(self):
        self._save_stdin()
        try:
            return super(WorkerProcess, self).start()
        finally:
            self._new_stdin.close()

    WorkerProcess.start = start


# NOTE: https://github.com/google/python-atfork/blob/main/atfork/stdlib_fixer.py
# This is to avoid any deadlock issues with logging module after fork.
_forked_handlers = set()
_forked_handlers_lock = threading.Lock()
os.register_at_fork(before=logging._acquireLock,
                    after_in_parent=logging._releaseLock,
                    after_in_child=logging._releaseLock)
display = ansible.utils.display.Display()
os.register_at_fork(before=display._lock.acquire,
                    after_in_parent=display._lock.release,
                    after_in_child=display._lock.release)


def fix_logging_handler_fork_lock():
    """Prevent logging handlers from deadlocking after fork."""
    # Collect all loggers including root
    loggers = [logging.getLogger()] + list(logging.Logger.manager.loggerDict.values())
    handlers = set()
    for logger in loggers:
        if hasattr(logger, 'handlers'):
            handlers.update(logger.handlers)
    for handler in handlers:
        new_handlers = []
        with _forked_handlers_lock:
            if handler not in _forked_handlers and handler.lock is not None:
                os.register_at_fork(before=handler.lock.acquire,
                                    after_in_parent=handler.lock.release,
                                    after_in_child=handler.lock.release)
                new_handlers.append(handler)
                _forked_handlers.add(handler)

        if new_handlers:
            logging.debug("Add handler %s to forked handlers list", new_handlers)


class SonicProcess(Process):
    """
    Wrapper class around multiprocessing.Process that would capture the exception thrown if the Process throws
    an exception when run.

    This exception (including backtrace) can be logged in test log
    to provide better info of why a particular Process failed.
    """
    def __init__(self, *args, **kwargs):
        Process.__init__(self, *args, **kwargs)
        self._pconn, self._cconn = Pipe(duplex=False)  # unidirectional: child_conn can send, parent_conn can recv
        self._exception = None
        self._exception_read = False  # Flag to track read status

    def run(self):
        try:
            Process.run(self)
            self._cconn.send(None)
        except Exception as e:
            tb = traceback.format_exc()
            self._cconn.send((e, tb))
            raise e
        finally:
            self._cconn.close()  # Close the child-side pipe

    # for wait_procs
    def wait(self, timeout):
        return self.join(timeout=timeout)

    # for wait_procs
    def is_running(self):
        return self.is_alive()

    @property
    def exception(self):
        """Read exception data once and close parent-side pipe."""
        if not self._exception_read:
            try:
                if self._pconn.poll():
                    self._exception = self._pconn.recv()
            except (EOFError, OSError):
                pass
            finally:
                self._pconn.close()
                self._exception_read = True
        return self._exception


def parallel_run(
    target, args, kwargs, nodes_list, timeout=None, concurrent_tasks=24, init_result=None
):
    """Run target function on nodes in parallel

    Args:
        target (function): The target function to be executed in parallel.
        args (list of tuple): List of arguments for the target function.
        kwargs (dict): Keyword arguments for the target function. It will be extended with two keys: 'node' and
            'results'. The 'node' key will hold an item of the nodes list. The 'result' key will hold an instance of
            multiprocessing.Manager().dict(). It is a proxy of the shared dict that will be used by each process for
            returning execution results.
        nodes (list of nodes): List of nodes to be used by the target function
        timeout (int or float, optional): Total time allowed for the spawned multiple processes to run. Defaults to
            None. When timeout is specified, this function will wait at most 'timeout' seconds for the processes to
            run. When time is up, this function will try to terminate or even kill all the processes.

    Raises:
        flag.: In case any of the spawned process cannot be terminated, fail the test.

    Returns:
        dict: An instance of multiprocessing.Manager().dict(). It is a proxy to the shared dict that is used by all the
            spawned processes.
    """
    nodes = [node for node in nodes_list]

    # Callback API for wait_procs
    def on_terminate(worker):
        logger.info("process {} terminated with exit code {}".format(
            worker.name, worker.exitcode)
        )

    def force_terminate(workers, init_result):
        # Some processes cannot be terminated. Try to kill them and raise flag.
        running_processes = [worker for worker in workers if worker.is_alive()]
        if len(running_processes) > 0:
            logger.info(
                'Found processes still running: {}. Try to kill them.'.format(str(running_processes))
            )
            for p in running_processes:
                # If sanity check process is killed, it still has init results.
                # set its failed to True.
                if init_result:
                    init_result['failed'] = True
                    results[list(results.keys())[0]] = init_result
                else:
                    results[p.name] = {'failed': True}
                try:
                    os.kill(p.pid, signal.SIGKILL)
                except OSError as err:
                    logger.error("Unable to kill {}:{}, error:{}".format(
                        p.pid, p.name, err
                    ))

                    pt_assert(
                        False,
                        """Processes running target "{}" could not be terminated.
                        Unable to kill {}:{}, error:{}""".format(target.__name__, p.pid, p.name, err)
                    )

    workers = []
    results = Manager().dict()
    start_time = datetime.datetime.now()
    tasks_done = 0
    total_tasks = len(nodes)
    tasks_running = 0
    total_timeout = timeout * math.ceil(
        len(nodes)/float(concurrent_tasks)
    ) if timeout else None
    failed_processes = {}

    # Before spawning the child process, ensure current thread is
    # holding the logging handler locks to avoid deadlock in child process.
    fix_logging_handler_fork_lock()

    while tasks_done < total_tasks:
        # If execution time of processes exceeds timeout, need to force
        # terminate them all.
        if total_timeout is not None:
            if (datetime.datetime.now() - start_time).seconds > total_timeout:
                logger.error('Process execution time exceeds {} seconds.'.format(
                    str(total_timeout)
                ))
                break

        while len(nodes) and tasks_running < concurrent_tasks:
            node = nodes.pop(0)
            # For sanity check process, initial results in case of timeout.
            if init_result:
                init_result["host"] = node.hostname
                results[node.hostname] = init_result
            kwargs['node'] = node
            kwargs['results'] = results
            process_name = "{}--{}".format(target.__name__, node)
            worker = SonicProcess(
                        name=process_name, target=target, args=args,
                        kwargs=kwargs
                    )
            worker.start()
            tasks_running += 1
            logger.debug('Started process {} running target "{}"'.format(
                worker.pid, process_name
            ))
            workers.append(worker)

        gone, alive = wait_procs(workers, timeout=timeout, callback=on_terminate)
        workers = alive

        logger.debug("task completed {}, running {}".format(
            len(gone), len(alive)
        ))

        # Sometimes the child processes finished run but still alive, causing exception hidden.
        # It mainly caused by child processes hang on send() if parent doesn't read from the pipe.
        # Therefore, explicitly check the processes exception to prevent any error miss.
        logger.info("Force read exception regardless of whether the process exited normally.")
        for worker in gone + alive:
            worker_exception = worker.exception  # Force-read to prevent pipe hangs
            if worker_exception is not None:
                logger.info(f"Process {worker.name} has exception, is_alive={worker.is_running()}, record the error.")
                failed_processes[worker.name] = {
                    'exit_code': worker.exitcode,
                    'exception': worker_exception
                }

        if len(gone) == 0:
            logger.debug("all processes have timedout")
            tasks_running -= len(workers)
            tasks_done += len(workers)
            force_terminate(workers, init_result)
            del workers[:]
        else:
            tasks_running -= len(gone)
            tasks_done += len(gone)

    # In case of timeout force terminate spawned processes
    for worker in workers:
        if worker.is_alive():
            logger.error('Process {} is alive, force terminate it.'.format(
                worker.name
            ))
            worker.terminate()
            # If sanity check process is killed, it still has init results.
            # set its failed to True.
            if init_result:
                init_result['failed'] = True
                results[list(results.keys())[0]] = init_result
            else:
                results[worker.name] = {'failed': True}

    end_time = datetime.datetime.now()
    delta_time = end_time - start_time

    # force terminate any workers still running
    force_terminate(workers, init_result)

    # if we have failed processes, we should log the exception and exit code
    # of each Process and fail
    if len(list(failed_processes.keys())):
        for process_name, process in list(failed_processes.items()):
            p_exitcode = ""
            p_exception = ""
            p_traceback = ""
            if 'exception' in process and process['exception']:
                p_exception = process['exception'][0]
                p_traceback = process['exception'][1]
                p_exitcode = process['exit_code']
            # For analyzed matched syslog, don't need to log the traceback
            if "analyze_logs" in process_name and "Match Messages" in str(p_exception):
                failure_message = 'Got matched syslog in processes "{}" exit code:"{}"\n{}'.format(
                    process_name, p_exitcode, p_exception
                )
            else:
                failure_message = 'Processes "{}" failed with exit code "{}"\nException:\n{}\nTraceback:\n{}'.format(
                    list(failed_processes.keys()), p_exitcode, p_exception, p_traceback)
            pt_assert(False, failure_message)

    logger.info(
        'Completed running processes for target "{}" in {} seconds'.format(
            target.__name__, str(delta_time)
        )
    )

    return dict(results)


def reset_ansible_local_tmp(target):
    """Decorator for resetting ansible default local tmp dir for parallel multiprocessing.Process

    Args:
        target (function): The function to be decorated.
    """

    def wrapper(*args, **kwargs):

        # Reset the ansible default local tmp directory for the current subprocess
        # Otherwise, multiple processes could share a same ansible default tmp directory and there could be conflicts
        from ansible import constants
        original_default_local_tmp = constants.DEFAULT_LOCAL_TMP
        prefix = 'ansible-local-{}'.format(os.getpid())
        constants.DEFAULT_LOCAL_TMP = tempfile.mkdtemp(prefix=prefix)
        logger.info(f"Change ansible local tmp directory from {original_default_local_tmp}"
                    f" to {constants.DEFAULT_LOCAL_TMP}")
        try:
            target(*args, **kwargs)
        finally:
            # User of tempfile.mkdtemp need to take care of cleaning up.
            shutil.rmtree(constants.DEFAULT_LOCAL_TMP)
            # in case the there's other ansible module calls after the reset_ansible_local_tmp
            # in the same process, we need to restore back by default to avoid conflicts
            constants.DEFAULT_LOCAL_TMP = original_default_local_tmp
            logger.info(f"Restored ansible default local tmp directory to: {original_default_local_tmp}")

    wrapper.__name__ = target.__name__

    return wrapper


def parallel_run_threaded(target_functions, timeout=10, thread_count=2):
    """
    Run target functions with a thread pool.

    @param target_functions: list of target functions to execute
    @param timeout: timeout seconds, default 10
    @param thread_count: thread count, default 2
    """
    pool = ThreadPool(thread_count)
    results = [pool.apply_async(func) for func in target_functions]

    start_time = time.time()
    while time.time() - start_time <= timeout:
        alive_functions = [func for func, result in zip(target_functions, results) if not result.ready()]
        if alive_functions:
            time.sleep(0.2)
        else:
            pool.close()
            pool.join()
            break
    else:
        raise TimeoutError("%s seconds timeout waiting for %r to finish" % (timeout, alive_functions))

    outputs = []
    for func, result in zip(target_functions, results):
        try:
            output = result.get()
        except Exception as error:
            logging.error("Target function %r errored:\n%s", func, traceback.format_exc())
            raise error
        outputs.append(output)
    return outputs
