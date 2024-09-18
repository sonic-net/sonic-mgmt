from concurrent.futures import Future, as_completed
from concurrent.futures.thread import ThreadPoolExecutor
from typing import Optional, List


class SafeThreadPoolExecutor(ThreadPoolExecutor):
    """An enhanced thread pool executor

    Everytime we submit a task, it will store the feature in self.features
    On the __exit__ function, it will wait all the tasks to be finished,
    And check any exceptions that are raised during the task executing
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.features: Optional[List[Future]] = []

    def submit(self, __fn, *args, **kwargs):
        f = super().submit(__fn, *args, **kwargs)
        self.features.append(f)
        return f

    def __exit__(self, exc_type, exc_val, exc_tb):
        for future in as_completed(self.features):
            # if exception caught in the sub-thread, .result() will raise it in the main thread
            _ = future.result()
        self.shutdown(wait=True)
        return False
