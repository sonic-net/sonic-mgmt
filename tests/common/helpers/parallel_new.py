import logging
import traceback
from multiprocessing import Process, Queue

logger = logging.getLogger(__name__)


class SonicProcess(Process):
    def __init__(self, *args, exception_queue=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.exception_queue = exception_queue

    def run(self):
        try:
            logger.info(f"[chunangli][{self.name}] Process started.")
            super().run()
            if self.exception_queue:
                self.exception_queue.put((self.name, None))
        except Exception as e:
            tb = traceback.format_exc()
            logger.error(f"[chunangli][{self.name}] Caught exception: {e}")
            if self.exception_queue:
                self.exception_queue.put((self.name, (repr(e), tb)))
        finally:
            if self.exception_queue:
                self.exception_queue.close()
                self.exception_queue.cancel_join_thread()
            logger.info(f"[chunangli][{self.name}] Process exiting.")


def parallel_run(target_func, items, timeout=10):
    processes = []
    exception_queue = Queue()
    failed_processes = {}

    for i in items:
        proc = SonicProcess(
            name=f"worker-{i}",
            target=target_func,
            args=(i,),
            exception_queue=exception_queue
        )
        proc.start()
        processes.append(proc)

    # Wait for all to finish with timeout
    for proc in processes:
        proc.join(timeout)
        if proc.is_alive():
            logger.warning(f"[chunangli][{proc.name}] Timed out — killing.")
            proc.terminate()
            proc.join()

    # Drain exception queue
    while not exception_queue.empty():
        name, exc = exception_queue.get()
        if exc:
            failed_processes[name] = {
                "exception": exc[0],
                "traceback": exc[1]
            }

    logger.info(f"[chunangli]Failed processes: {failed_processes}")
    return failed_processes
