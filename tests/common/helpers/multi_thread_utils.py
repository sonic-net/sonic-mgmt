from concurrent.futures import Future
from typing import List
# from concurrent.futures.thread import ThreadPoolExecutor
# from typing import Optional, List


class SafeThreadPoolExecutor:
    """
    A no-op replacement for ThreadPoolExecutor:
    - submit() runs the work immediately, without any threads
    - features accumulates all the completed Futures
    - __exit__ will re-raise the first exception from any of them
    """
    def __init__(self, *args, **kwargs):
        self.features: List[Future] = []

    def submit(self, fn, *args, **kwargs):
        f = Future()
        try:
            result = fn(*args, **kwargs)
            f.set_result(result)
        except Exception as e:
            f.set_exception(e)
        self.features.append(f)
        return f

    def shutdown(self, wait=True, cancel_futures=True):
        # no threads to shut down
        pass

    def __enter__(self):
        # allow "with SafeThreadPoolExecutor(...) as executor:"
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        errors = []
        for f in self.features:
            try:
                f.result()
            except Exception as e:
                print(f"[SafeThreadPoolExecutor] Caught exception: {e}")
                errors.append(e)

        if errors:
            raise errors[0]

        return False


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
#         # for future in as_completed(self.features):
#         #     # if exception caught in the sub-thread, .result() will raise it in the main thread
#         #     try:
#         #         _ = future.result()
#         #     except Exception as e:
#         #         print(f"[SafeThreadPoolExecutor] Caught exception: {e}")
#         #         raise
#         # self.shutdown(wait=True)
#         # return False
#         # First, prevent any new tasks and wait for running ones to finish
#         self.shutdown(wait=True, cancel_futures=True)
#
#         # Collect exceptions from all futures
#         errors = []
#         for f in self.features:
#             try:
#                 f.result()
#             except Exception as e:
#                 print(f"[SafeThreadPoolExecutor] Caught exception: {e}")
#                 errors.append(e)
#
#         # If any task failed, re-raise the first exception
#         if errors:
#             raise errors[0]
#
#         # Returning False will not suppress any exception from the with-block itself
#         return False
