import datetime
import logging
import math
import os
import pickle
import queue
import signal
import traceback
from multiprocessing import Process, Manager, SimpleQueue

from tests.common.helpers.assertions import pytest_assert as pt_assert

logger = logging.getLogger(__name__)


class SonicProcess(Process):
    def __init__(self, *args, queue=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._queue = queue
        self._exception = None

    def run(self):
        try:
            logger.info(f"[{self.name}] process started.")
            if self._target:
                self._target(*self._args, **self._kwargs)
            self._queue.put((self.name, None))  # No exception
            logger.info(f"[{self.name}] process finished.")
        except Exception as e:
            serialized = pickle.dumps(e)
            logger.info(f"[{self.name}] Serialized exception size: {len(serialized) / 1024:.2f} KB")
            tb = traceback.format_exc()
            self._queue.put((self.name, (str(e), tb)))
            logger.error(f"[{self.name}] exception: {e}\n{tb}")
            self._exception = e
        finally:
            logger.info(f"[{self.name}] exiting run()")

    @property
    def exception(self):
        return self._exception


def parallel_run(
        target, args, kwargs, nodes_list, timeout=None, concurrent_tasks=24, init_result=None
):
    logger.info(f"Running target '{target.__name__}' with timeout={timeout}")

    results = Manager().dict()
    exception_queue = SimpleQueue()
    failed_processes = {}

    start_time = datetime.datetime.now()
    tasks_done = 0
    total_tasks = len(nodes_list)
    total_timeout = timeout * math.ceil(total_tasks / concurrent_tasks) if timeout else None

    def launch_process(node):
        nonlocal args, kwargs
        process_name = f"{target.__name__}--{node}"
        kwargs['node'] = node
        kwargs['results'] = results
        proc = SonicProcess(
            name=process_name,
            target=target,
            args=args,
            kwargs=kwargs,
            queue=exception_queue,
        )
        proc.start()
        logger.info(f"Started {proc.name} with PID {proc.pid}")
        return proc

    def force_terminate(proc):
        if proc.is_alive():
            logger.warning(f"Force killing {proc.name} (pid={proc.pid})")
            try:
                os.kill(proc.pid, signal.SIGKILL)
            except Exception as e:
                logger.error(f"Failed to kill {proc.name}: {e}")

    nodes = list(nodes_list)
    running = []

    while tasks_done < total_tasks:
        if total_timeout and (datetime.datetime.now() - start_time).total_seconds() > total_timeout:
            logger.error(f"Timeout reached: {total_timeout} seconds")
            break

        # Launch up to concurrent_tasks
        while len(nodes) > 0 and len(running) < concurrent_tasks:
            node = nodes.pop(0)
            if init_result:
                node_result = init_result.copy()
                node_result['host'] = node.hostname
                results[node.hostname] = node_result
            proc = launch_process(node)
            running.append(proc)

        # Check for completed processes
        alive = []
        for proc in running:
            proc.join(timeout=0)
            if proc.is_alive():
                alive.append(proc)
            else:
                tasks_done += 1

        running = alive

        # This avoids relying on empty() and ensures you don’t miss any data from child processes.
        while True:
            try:
                name, exc = exception_queue.get()
                if exc:
                    failed_processes[name] = {
                        "exception": exc,
                        "exit_code": next((p.exitcode for p in running if p.name == name), -1)
                    }
            except queue.Empty:
                break

    # Final cleanup
    for proc in running:
        logger.warning(f"Cleaning up {proc.name}, still alive? {proc.is_alive()}")
        force_terminate(proc)

    if failed_processes:
        for name, info in failed_processes.items():
            pt_assert(False,
                      f"""
                                Process '{name}' failed with exit code {info['exit_code']}
                                Exception: {info['exception'][0]}
                                Traceback:
                                {info['exception'][1]}
                                """
                      )

    duration = datetime.datetime.now() - start_time
    logger.info(f"Completed all processes in {duration.total_seconds()} seconds")

    return dict(results)
