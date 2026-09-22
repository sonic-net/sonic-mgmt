import multiprocessing.pool
from multiprocessing.pool import ThreadPool
from typing import List


class SafeThreadPoolExecutor:
    """
    A thread pool executor that collects all AsyncResult objects and waits for their completion.

    Example Usage:

    with SafeThreadPoolExecutor(max_workers=len(duthosts)) as executor:
        for duthost in duthosts:
            executor.submit(example_func, duthost, localhost)

    Behavior Summary:
      1. On instantiation, starts `max_workers` threads via ThreadPool.
      2. Each thread runs the submitted function (e.g., `example_func(arg1, arg2)`) in parallel.
      3. When the `with` block scope ends, execution moves to `__exit__`, where it blocks on each `AsyncResult.get()`
         in turn to wait for all tasks to finish.
      4. If all threads succeed without raising, the pool is shut down cleanly.
      5. If any thread raises an exception, `.get()` re-raises that exception in the main thread.
    """

    def __init__(self, max_workers, *args, **kwargs):
        """
        Create a ThreadPool with `max_workers` threads and initialize an empty list to collect results.

        Args:
            max_workers: number of worker threads (maps to ThreadPool's `processes` parameter).
            *args, **kwargs: ignored (only here to match ThreadPoolExecutor signature).
        """
        self._pool = ThreadPool(processes=max_workers)
        self._results: List["multiprocessing.pool.ApplyResult"] = []

    def submit(self, fn, *args, **kwargs):
        """
        Schedule fn(*args, **kwargs) to run in a worker thread.
        Returns an ApplyResult object whose .get() will return the result or re-raise any exception from the worker.
        """
        # Wrap the user‐provided fn in a wrapper to catch any BaseException, and convert that BaseException into
        # a regular RuntimeError so ThreadPool's "except Exception" block will catch and enqueue it.
        def _wrapper(*fn_args, **fn_kwargs):
            try:
                return fn(*fn_args, **fn_kwargs)
            except BaseException as be:
                raise RuntimeError("Thread worker aborted: " + repr(be))

        async_res = self._pool.apply_async(_wrapper, args, kwargs)
        self._results.append(async_res)
        return async_res

    def shutdown(self, wait=True):
        """
        Stop accepting new tasks and optionally wait for running ones to finish.
        """
        # Prevent new tasks
        self._pool.close()
        if wait:
            # Wait for all tasks to finish
            self._pool.join()

    def __enter__(self):
        """
        Support the "with" statement.
        """
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Wait for each submitted task to complete and surface exceptions.
        """
        for async_res in self._results:
            # .get() will block until the task finishes, and re-raise any exception to the main thread.
            async_res.get()

        # Shut down the pool by close + join.
        self.shutdown(wait=True)
        # Returning False to ensure that any exception in the "with" statement is not suppressed.
        return False
