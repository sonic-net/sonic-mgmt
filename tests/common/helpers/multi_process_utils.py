from concurrent.futures import ProcessPoolExecutor, Future, as_completed
from typing import List, Optional, Type


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
        for future in as_completed(self._futures):
            # if exception caught in the sub-thread, .result() will raise it in the main thread
            _ = future.result()
        self.shutdown(wait=True)
        return False
