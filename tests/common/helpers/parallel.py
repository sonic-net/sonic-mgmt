import datetime
import logging
import os
import signal
from multiprocessing import Process, Manager
from tests.common.helpers.assertions import pytest_assert as pt_assert

logger = logging.getLogger(__name__)


def parallel_run(target, args, kwargs, nodes, timeout=None):
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
    workers = []
    results = Manager().dict()
    start_time = datetime.datetime.now()
    for node in nodes:
        kwargs['node'] = node
        kwargs['results'] = results
        worker = Process(target=target, args=args, kwargs=kwargs)
        worker.start()
        logger.debug('Started process {} running target "{}"'.format(worker.pid, target.__name__))
        workers.append(worker)

    for worker in workers:
        logger.debug('Wait for process "{}" to complete, timeout={}'.format(worker.pid, timeout))
        worker.join(timeout)
        logger.debug('Process "{}" completed'.format(worker.pid))

        # If execution time of processes exceeds timeout, need to force terminate them all.
        if timeout is not None:
            if (datetime.datetime.now() - start_time).seconds > timeout:
                logger.error('Process execution time exceeds {} seconds.'.format(str(timeout)))
                break

    # Force terminate spawned processes
    for worker in workers:
        if worker.is_alive():
            logger.error('Process {} is still alive, try to force terminate it.'.format(worker.pid))
            worker.terminate()

    end_time = datetime.datetime.now()
    delta_time = end_time - start_time

    # Some processes cannot be terminated. Try to kill them and raise flag.
    running_processes = [worker for worker in workers if worker.is_alive()]
    if len(running_processes) > 0:
        logger.error('Found processes still running: {}. Try to kill them.'.format(str(running_processes)))
        for p in running_processes:
            try:
                os.kill(p.pid, signal.SIGKILL)
            except OSError:
                pass

        pt_assert(False, \
            'Processes running target "{}" could not be terminated. Tried killing them. But please check'.format(target.__name__))

    logger.info('Completed running processes for target "{}" in {} seconds'.format(target.__name__, str(delta_time)))

    return results
