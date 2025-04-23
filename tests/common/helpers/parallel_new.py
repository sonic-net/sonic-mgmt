import datetime
import logging
import math
import os
import signal
import traceback
from multiprocessing import Manager, Process, Queue

from psutil import wait_procs

from tests.common.helpers.assertions import pytest_assert as pt_assert

logger = logging.getLogger(__name__)


class SonicProcess(Process):
    """
    Wrapper class around multiprocessing.Process that would capture the exception thrown if the Process throws
    an exception when run.

    This exception (including backtrace) can be logged in test log
    to provide better info of why a particular Process failed.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._queue = Queue()
        self._exception = None

    def run(self):
        try:
            logger.info("[chunangli] process started.")
            super().run()
            self._queue.put(None)
            logger.info("[chunangli] process finished.")
        except Exception as e:
            logger.info(f"[chunangli] process error caught: {e}.")
            tb = traceback.format_exc()
            logger.info(f"[chunangli] process sending traceback: {tb}.")
            self._queue.put(("matched: 6", tb))
            logger.info("[chunangli] process small data sent.")
            # self._queue.put((str(e), tb))
            # logger.info("[chunangli] process traceback sent.")
            import sys
            logger.info("[chunangli] sys.exit(1) : Ensure process terminates here.")
            sys.exit(1)  # Ensure process terminates here

    def wait(self, timeout):
        return self.join(timeout=timeout)

    def is_running(self):
        return self.is_alive()

    @property
    def exception(self):
        logger.info("[chunangli] process catch exception.")
        if not self._queue.empty():
            logger.info("[chunangli] process get from not emptry Queue.")
            self._exception = self._queue.get()
            logger.info("[chunangli] process get from not emptry Queue finished.")
        return self._exception


def parallel_run(
        target, args, kwargs, nodes_list, timeout=None, concurrent_tasks=24, init_result=None
):
    logger.info(f"[chunangli] parallel run function: {target.__name__}, timeout: {timeout}")

    nodes = [node for node in nodes_list]

    def on_terminate(worker):
        logger.info("[chunangli] process {} terminated with exit code {}".format(
            worker.name, worker.exitcode)
        )
        logger.info(f"[chunangli] on_terminate, worker= {worker.__dict__}")

    def force_terminate(workers, init_result):
        running_processes = [worker for worker in workers if worker.is_alive()]
        if running_processes:
            logger.info(
                '[chunangli] Found processes still running: {}. Try to kill them.'.format(str(running_processes))
            )
            for p in running_processes:
                if init_result:
                    init_result['failed'] = True
                    results[list(results.keys())[0]] = init_result
                else:
                    results[p.name] = {'failed': True}
                try:
                    os.kill(p.pid, signal.SIGKILL)
                except OSError as err:
                    logger.error(f"[chunangli] Unable to kill {p.pid}:{p.name}, error:{err}")
                    pt_assert(
                        False,
                        f"""[chunangli] Processes running target \"{target.__name__}\" could not be terminated.
                        Unable to kill {p.pid}:{p.name}, error:{err}"""
                    )

    workers = []
    results = Manager().dict()
    start_time = datetime.datetime.now()
    tasks_done = 0
    total_tasks = len(nodes)
    tasks_running = 0
    total_timeout = timeout * math.ceil(len(nodes) / float(concurrent_tasks)) if timeout else None
    failed_processes = {}

    while tasks_done < total_tasks:
        if total_timeout and (datetime.datetime.now() - start_time).seconds > total_timeout:
            logger.error(f"[chunangli] Process execution time exceeds {total_timeout} seconds.")
            break

        while nodes and tasks_running < concurrent_tasks:
            node = nodes.pop(0)
            if init_result:
                init_result["host"] = node.hostname
                results[node.hostname] = init_result
            kwargs['node'] = node
            kwargs['results'] = results
            process_name = f"{target.__name__}--{node}"
            worker = SonicProcess(name=process_name, target=target, args=args, kwargs=kwargs)
            worker.start()
            tasks_running += 1
            logger.debug(f"[chunangli] Started process {worker.pid} running target \"{process_name}\"")
            workers.append(worker)

        gone, alive = wait_procs(workers, timeout=timeout, callback=on_terminate)
        workers = alive

        logger.debug(f"[chunangli] task completed {len(gone)}, running {len(alive)}")

        for worker in alive:
            logger.info(f"[chunangli] alive worker.name={worker.name}, worker.exitcode={worker.exitcode}")
            if worker.exitcode != 0:
                failed_processes[worker.name] = {
                    'exit_code': worker.exitcode,
                    'exception': worker.exception
                }

        if not gone:
            logger.debug("[chunangli] all processes have timed out")
            tasks_running -= len(workers)
            tasks_done += len(workers)
            force_terminate(workers, init_result)
            workers.clear()
        else:
            tasks_running -= len(gone)
            tasks_done += len(gone)

        for worker in gone:
            logger.info(f"[chunangli] gone worker.name={worker.name}, worker.exitcode={worker.exitcode}")
            if worker.exitcode != 0:
                failed_processes[worker.name] = {
                    'exit_code': worker.exitcode,
                    'exception': worker.exception
                }

    for worker in workers:
        if worker.is_alive():
            logger.error(f"[chunangli] Process {worker.name} is alive, exitcode={worker.exitcode}, force terminate it.")
            worker.terminate()
            if init_result:
                init_result['failed'] = True
                results[list(results.keys())[0]] = init_result
            else:
                results[worker.name] = {'failed': True}

    end_time = datetime.datetime.now()
    delta_time = end_time - start_time

    force_terminate(workers, init_result)

    if failed_processes:
        for process_name, process in failed_processes.items():
            p_exitcode = process.get('exit_code', '')
            p_exception = process.get('exception', ('', ''))[0]
            p_traceback = process.get('exception', ('', ''))[1]
            pt_assert(
                False,
                f"[chunangli] Processes \"{list(failed_processes.keys())}\" failed with "
                f"exit code \"{p_exitcode}\"\nException:\n{p_exception}\nTraceback:\n{p_traceback}"
            )

    logger.info(
        f"[chunangli] Completed running processes for target \"{target.__name__}\" in {delta_time} seconds"
    )

    return dict(results)
