from concurrent.futures import ThreadPoolExecutor, as_completed

class TaskRunner(object):
    """
    A helper class for running tasks parallelly
    """
    def __init__(self, max_worker=1):
        self._all_tasks = {}
        self._threadpool = ThreadPoolExecutor(max_workers=max_worker)

    def submit_task(self, name, target, *args, **kwargs):
        """
        @summary: Submit a task and params to task pool
        """
        self._all_tasks.update({self._threadpool.submit(target, *args, **kwargs):name})

    def task_results(self, timeout=None):
        """
        @summary: A method for polling task results.
                The caller will bolck until result is available or timeout
        @param timeout: The timeout for polling task results. None means forever
        @return: A generator
        """
        for future in as_completed(self._all_tasks.keys(), timeout=timeout):
            name = self._all_tasks[future]
            try:
                result = {'result':future.result()}
            except Exception as e:
                result = {'result': repr(e)}

            yield name, result
        self._all_tasks.clear()

    def shutdown(self):
        """
        @summary: Shutdown the threadpool immediately. All unrunning tasks will be cancelled
        """
        self._threadpool.shutdown(wait=False)

