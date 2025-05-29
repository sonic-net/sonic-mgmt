from concurrent.futures import ProcessPoolExecutor, Future
from typing import List, Optional, Type
import traceback


class SafeProcessPoolExecutor(ProcessPoolExecutor):
    """
    A ProcessPoolExecutor that collects all futures and on context exit
    will wait for completion and re-raise the first exception seen.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._futures: List[Future] = []

    def submit(self, fn, *args, **kwargs) -> Future:
        f = super().submit(fn, *args, **kwargs)
        self._futures.append(f)
        return f

    def __exit__(self, exc_type: Optional[Type[BaseException]], exc_val: Optional[BaseException], exc_tb) -> bool:
        # First, prevent new tasks and wait for running ones
        self.shutdown(wait=True)

        # Collect exceptions from all futures
        errors: List[BaseException] = []
        for f in self._futures:
            try:
                f.result()
            except Exception as e:
                # capture traceback for debugging if you like
                traceback.print_exception(type(e), e, e.__traceback__)
                errors.append(e)

        # If any task failed, re-raise the first exception
        if errors:
            raise errors[0]

        # Returning False lets any exception in the with-block propagate
        return False
