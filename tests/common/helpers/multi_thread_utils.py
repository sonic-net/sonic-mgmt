# from concurrent.futures import Future, as_completed
# from concurrent.futures.thread import ThreadPoolExecutor
# from typing import Optional, List
#
#
# class SafeThreadPoolExecutor(ThreadPoolExecutor):
#     """An enhanced thread pool executor
#
#     Everytime we submit a task, it will store the feature in self.features
#     On the __exit__ function, it will wait all the tasks to be finished,
#     And check any exceptions that are raised during the task executing
#     """
#     def __init__(self, *args, **kwargs):
#         super().__init__(*args, **kwargs)
#         self.features: Optional[List[Future]] = []
#
#     def submit(self, __fn, *args, **kwargs):
#         f = super().submit(__fn, *args, **kwargs)
#         self.features.append(f)
#         return f
#
#     def __exit__(self, exc_type, exc_val, exc_tb):
#         for future in as_completed(self.features):
#             # if exception caught in the sub-thread, .result() will raise it in the main thread
#             _ = future.result()
#         self.shutdown(wait=True)
#         return False
import logging
import threading
from multiprocessing.pool import ThreadPool
from typing import Optional, List, Any


def _thread_debug_init():
    """Initializer run in each worker thread upon creation."""
    thread = threading.current_thread()
    logging.debug(f"!!!![DEBUG] Thread started: {thread.name} (ident={thread.ident})!!!!")


class SafeThreadPoolExecutor:
    """A drop-in replacement for ThreadPoolExecutor that uses multiprocessing.pool.ThreadPool
    under the hood. This class collects AsyncResult objects on submit, and on exit
    waits for all tasks to finish and bubbles up any exceptions.
    """

    def __init__(self, max_workers: int, *args: Any, **kwargs: Any):
        """
        Args:
            max_workers: number of worker threads (maps to ThreadPool's 'processes' parameter).
            *args, **kwargs: ignored (only here to match ThreadPoolExecutor signature).
        """
        # Create a ThreadPool with 'max_workers' threads
        self._pool = ThreadPool(processes=max_workers, initializer=_thread_debug_init)
        # Keep a list of AsyncResult objects returned by apply_async()
        self._results: List = []

    def submit(self, fn, *args, **kwargs):
        """
        Schedule fn(*args, **kwargs) to run in a worker thread.
        Returns an AsyncResult-like object (multiprocessing.pool.AsyncResult) whose .get()
        will return the result or re-raise any exception from the worker.
        """
        async_res = self._pool.apply_async(fn, args, kwargs)
        self._results.append(async_res)
        return async_res

    def shutdown(self, wait: bool = True):
        """
        Stop accepting new tasks and optionally wait for running ones to finish.
        """
        # Prevent new tasks
        self._pool.close()
        if wait:
            self._pool.join()

    def __enter__(self):
        # Support the 'with' statement
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # First, wait for each submitted task to complete and surface exceptions.
        for async_res in self._results:
            # .get() will block until the task finishes, and re-raise any exception.
            async_res.get()

        # Then, shut down the pool (close + join)
        self.shutdown(wait=True)
        # Returning False ensures that any exception in the with-block is not suppressed.
        return False
