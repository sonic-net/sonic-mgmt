import datetime
import logging
import math
import os
import shutil
import tempfile
import signal
import traceback

from multiprocessing import Process, Manager, Pipe
from psutil import wait_procs

from tests.common.helpers.assertions import pytest_assert as pt_assert

logger = logging.getLogger(__name__)

class SonicProcess(Process):
    """
    Wrapper class around multiprocessing.Process that would capture the exception thrown if the Process throws
    an exception when run.

    This exception (including backtrace) can be logged in test log to provide better info of why a particular Process failed.
    """
    def __init__(self, *args, **kwargs):
        Process.__init__(self, *args, **kwargs)
        self._pconn, self._cconn = Pipe()
        self._exception = None

    def run(self):
        try:
            Process.run(self)
            self._cconn.send(None)
        except Exception as e:
            tb = traceback.format_exc()
            self._cconn.send((e, tb))
            raise e

    # for wait_procs
    def wait(self, timeout):
        return self.join(timeout=timeout)

    # for wait_procs
    def is_running(self):
        return self.is_alive()

    @property
    def exception(self):
        if self._pconn.poll():
            self._exception = self._pconn.recv()
        return self._exception


def parallel_run(
    target, args, kwargs, nodes_list, timeout=None, concurrent_tasks=24
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
            worker.name, worker.returncode)
        )

    def force_terminate(workers):
        # Some processes cannot be terminated. Try to kill them and raise flag.
        running_processes = [worker for worker in workers if worker.is_alive()]
        if len(running_processes) > 0:
            logger.info(
                'Found processes still running: {}. Try to kill them.'.format( #lgtm [py/clear-text-logging-sensitive-data]
                    str(running_processes)
                )
            )
            for p in running_processes:
                results[p.name] = [{'failed': True}]
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

        if len(gone) == 0:
            logger.debug("all processes have timedout")
            tasks_running -= len(workers)
            tasks_done += len(workers)
            force_terminate(workers)
            del workers[:]
        else:
            tasks_running -= len(gone)
            tasks_done += len(gone)

        # check if we have any processes that failed - have exitcode non-zero
        for worker in gone:
            if worker.exitcode != 0:
                failed_processes[worker.name] = {}
                failed_processes[worker.name]['exit_code'] = worker.exitcode
                failed_processes[worker.name]['exception'] = worker.exception

    # In case of timeout force terminate spawned processes
    for worker in workers:
        if worker.is_alive():
            logger.error('Process {} is alive, force terminate it.'.format(
                worker.name
            ))
            worker.terminate()
            results[worker.name] = [{'failed': True}]

    end_time = datetime.datetime.now()
    delta_time = end_time - start_time

    # force terminate any workers still running
    force_terminate(workers)

    # if we have failed processes, we should log the exception and exit code
    # of each Process and fail
    if len(failed_processes.keys()):
        for process_name, process in failed_processes.items():
            p_exitcode = ""
            p_exception = ""
            p_traceback = ""
            if 'exception' in process and process['exception']:
                p_exception = process['exception'][0]
                p_traceback = process['exception'][1]
                p_exitcode = process['exit_code']
            pt_assert(
                False,
                'Processes "{}" failed with exit code "{}"\nException:\n{}\nTraceback:\n{}'.format(
                    list(failed_processes.keys()), p_exitcode, p_exception, p_traceback
                )
            )

    logger.info(
        'Completed running processes for target "{}" in {} seconds'.format(
            target.__name__, str(delta_time)
        )
    )

    return results


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
