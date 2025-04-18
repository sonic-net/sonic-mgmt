import datetime
import logging
import math
import os
import pickle
import shutil
import signal
# import sys
import tempfile
import time
import traceback
from multiprocessing import Process, Manager, TimeoutError, SimpleQueue
from multiprocessing.pool import ThreadPool

from psutil import wait_procs

from tests.common.helpers.assertions import pytest_assert as pt_assert

logger = logging.getLogger(__name__)


class SonicProcess(Process):
    """
    Wrapper class around multiprocessing.Process that captures exceptions
    and sends them to the parent process using a Queue.
    """
    def __init__(self, *args, queue=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._queue = queue
        self._exception = None

    def run(self):
        try:
            logger.info("[chunangli] process started.")
            if self._target:
                self._target(*self._args, **self._kwargs)
            self._queue.put((self.name, None))  # No exception occurred
            logger.info("[chunangli] process finished.")
        except Exception as e:
            logger.info(f"[chunangli] process error caught: {e}.")
            serialized = pickle.dumps(e)
            logger.info(f"[chunangli] Serialized size: {len(serialized) / 1024:.2f} KB")
            tb = traceback.format_exc()
            # self._queue.put((self.name, (str(e), tb)))
            self._queue.put((self.name, ("match: 666", tb)))
            logger.info("[chunangli] process send data 666 finished.")
            self.set_exception(e)
            # sys.exit(1)  # Ensure process exits with error code
        finally:
            logger.info(f"[chunangli] process {self.name} exiting run() cleanly")

    def wait(self, timeout):
        return self.join(timeout=timeout)

    # for wait_procs
    def is_running(self):
        return self.is_alive()

    def set_exception(self, exception):
        self._exception = exception

    @property
    def exception(self):
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

    logger.info(f"[chunangli] parallel run function: {target.__name__}, timeout: {timeout}, use simpleQueue.")

    nodes = list(nodes_list)
    results = Manager().dict()
    exception_queue = SimpleQueue()
    workers = []
    failed_processes = {}

    start_time = datetime.datetime.now()
    tasks_done = 0
    tasks_running = 0
    total_tasks = len(nodes)
    total_timeout = timeout * math.ceil(len(nodes) / float(concurrent_tasks)) if timeout else None

    def on_terminate(worker):
        logger.info("process {} terminated with exit code {}".format(worker.name, worker.exitcode))
        logger.info(f"[chunangli] on_terminate, worker= {worker.__dict__}")

    def force_terminate(workers, init_result):
        running_processes = [worker for worker in workers if worker.is_alive()]
        if running_processes:
            logger.info('Found processes still running: {}. Try to kill them.'.format(str(running_processes)))
            for p in running_processes:
                if init_result:
                    init_result['failed'] = True
                    results[list(results.keys())[0]] = init_result
                else:
                    results[p.name] = {'failed': True}
                try:
                    os.kill(p.pid, signal.SIGKILL)
                except OSError as err:
                    logger.error(f"Unable to kill {p.pid}:{p.name}, error:{err}")
                    pt_assert(
                        False,
                        f"""Processes running target "{target.__name__}" could not be terminated.
                               Unable to kill {p.pid}:{p.name}, error:{err}"""
                    )

    while tasks_done < total_tasks:
        if total_timeout and (datetime.datetime.now() - start_time).seconds > total_timeout:
            logger.error(f'Process execution time exceeds {total_timeout} seconds.')
            break

        while len(nodes) and tasks_running < concurrent_tasks:
            node = nodes.pop(0)
            if init_result:
                init_result["host"] = node.hostname
                results[node.hostname] = init_result
            kwargs['node'] = node
            kwargs['results'] = results
            process_name = f"{target.__name__}--{node}"
            worker = SonicProcess(
                name=process_name,
                target=target,
                args=args,
                kwargs=kwargs,
                queue=exception_queue,
            )
            worker.start()
            tasks_running += 1
            logger.debug(f'Started process {worker.pid} running target "{process_name}"')
            workers.append(worker)

        gone, alive = wait_procs(workers, timeout=timeout, callback=on_terminate)
        workers = alive

        logger.debug(f"task completed {len(gone)}, running {len(alive)}")

        if len(gone) == 0:
            logger.debug("all processes have timed out")
            tasks_running -= len(workers)
            tasks_done += len(workers)
            force_terminate(workers, init_result)
            del workers[:]
        else:
            tasks_running -= len(gone)
            tasks_done += len(gone)

        # Handle any exceptions returned by subprocesses
        while not exception_queue.empty():
            name, exc = exception_queue.get()
            if exc:
                failed_processes[name] = {
                    "exit_code": next((p.exitcode for p in gone if p.name == name), -1),
                    "exception": exc
                }

    # Final cleanup
    for worker in workers:
        if worker.is_alive():
            logger.error(f'Process {worker.name} is alive, exitcode={worker.exitcode}, force terminating it.')
            worker.terminate()
            if init_result:
                init_result['failed'] = True
                results[list(results.keys())[0]] = init_result
            else:
                results[worker.name] = {'failed': True}

    force_terminate(workers, init_result)

    if failed_processes:
        for process_name, process in failed_processes.items():
            p_exception = process['exception'][0]
            p_traceback = process['exception'][1]
            p_exitcode = process['exit_code']
            pt_assert(
                False,
                f'Processes "{list(failed_processes.keys())}" failed with exit code "{p_exitcode}"\n'
                f'Exception:\n{p_exception}\nTraceback:\n{p_traceback}'
            )

    end_time = datetime.datetime.now()
    delta_time = end_time - start_time

    logger.info(f'Completed running processes for target "{target.__name__}" in {delta_time} seconds')

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
        prefix = 'ansible-local-{}'.format(os.getpid())
        constants.DEFAULT_LOCAL_TMP = tempfile.mkdtemp(prefix=prefix)
        try:
            target(*args, **kwargs)
        finally:
            # User of tempfile.mkdtemp need to take care of cleaning up.
            shutil.rmtree(constants.DEFAULT_LOCAL_TMP)

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
