import datetime
import logging
import math
import os
import signal
import traceback
from multiprocessing import Process, Manager, Queue

logger = logging.getLogger(__name__)


class SonicProcess(Process):
    """
    Wrapper around multiprocessing.Process that captures exceptions and sends them through a Queue.
    """

    def __init__(self, *args, exception_queue: Queue = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.exception_queue = exception_queue

    def run(self):
        try:
            logger.info("[SonicProcess] Process started: %s", self.name)
            super().run()
            if self.exception_queue:
                self.exception_queue.put((self.name, None))
            logger.info("[SonicProcess] Process finished: %s", self.name)
        except Exception as e:
            tb = traceback.format_exc()
            logger.error("[SonicProcess] Exception in process %s: %s", self.name, tb)
            if self.exception_queue:
                self.exception_queue.put((self.name, (e, tb)))
            raise


def wait_procs(workers, timeout=None, callback=None):
    gone, alive = [], []
    # start = datetime.datetime.now()

    for p in workers:
        p.join(timeout)
        if not p.is_alive():
            gone.append(p)
            if callback:
                callback(p)
        else:
            alive.append(p)

    return gone, alive


def parallel_run(target, args, kwargs, nodes_list, timeout=None, concurrent_tasks=24, init_result=None):
    logger.info("[parallel_run] Function: %s, Timeout: %s", target.__name__, timeout)

    nodes = list(nodes_list)
    workers = []
    results = Manager().dict()
    start_time = datetime.datetime.now()
    tasks_done = 0
    total_tasks = len(nodes)
    tasks_running = 0
    total_timeout = timeout * math.ceil(len(nodes) / float(concurrent_tasks)) if timeout else None
    failed_processes = {}
    exception_queue = Queue()

    def on_terminate(worker):
        logger.info("[on_terminate] Process %s terminated with exit code %s", worker.name, worker.exitcode)

    def force_terminate(workers):
        running = [p for p in workers if p.is_alive()]
        if running:
            logger.warning("[force_terminate] Killing running processes: %s", running)
            for p in running:
                if init_result:
                    init_result['failed'] = True
                    results[list(results.keys())[0]] = init_result
                else:
                    results[p.name] = {'failed': True}
                try:
                    os.kill(p.pid, signal.SIGKILL)
                except OSError as e:
                    logger.error("[force_terminate] Unable to kill %s: %s", p.name, e)

    while tasks_done < total_tasks:
        if total_timeout and (datetime.datetime.now() - start_time).seconds > total_timeout:
            logger.error("[parallel_run] Execution time exceeds timeout: %s", total_timeout)
            break

        while nodes and tasks_running < concurrent_tasks:
            node = nodes.pop(0)
            if init_result:
                init_result["host"] = getattr(node, 'hostname', str(node))
                results[str(node)] = init_result
            kwargs['node'] = node
            kwargs['results'] = results
            pname = f"{target.__name__}--{node}"
            worker = SonicProcess(
                name=pname, target=target, args=args, kwargs=kwargs,
                exception_queue=exception_queue
            )
            worker.start()
            tasks_running += 1
            workers.append(worker)

        gone, alive = wait_procs(workers, timeout=timeout, callback=on_terminate)
        workers = alive
        tasks_done += len(gone)
        tasks_running -= len(gone)

        for _ in range(len(gone)):
            try:
                name, exc = exception_queue.get(timeout=1)
                if exc:
                    failed_processes[name] = {
                        "exception": exc,
                        "exit_code": next((p.exitcode for p in gone if p.name == name), -1)
                    }
            except Exception as e:
                logger.warning("[parallel_run] Exception queue timeout or error: %s", e)

        if not gone and workers:
            logger.warning("[parallel_run] All processes timed out")
            force_terminate(workers)
            tasks_done += len(workers)
            tasks_running -= len(workers)
            workers.clear()

    for worker in workers:
        if worker.is_alive():
            logger.error("[parallel_run] Process still alive: %s", worker.name)
            worker.terminate()
            if init_result:
                init_result['failed'] = True
                results[list(results.keys())[0]] = init_result
            else:
                results[worker.name] = {'failed': True}

    force_terminate(workers)

    if failed_processes:
        for name, info in failed_processes.items():
            exc, tb = info['exception']
            exit_code = info['exit_code']
            raise RuntimeError(
                f"Process '{name}' failed with exit code {exit_code}\nException: {exc}\nTraceback:\n{tb}")

    logger.info("[parallel_run] Completed in %s", datetime.datetime.now() - start_time)
    return dict(results)
