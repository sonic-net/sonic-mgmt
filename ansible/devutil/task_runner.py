from concurrent.futures import ThreadPoolExecutor, as_completed

class TaskRunner(object):

    def __init__(self, max_worker=1):
        self._all_tasks = {}
        self._threadpool = ThreadPoolExecutor(max_workers=max_worker)
    
    def submit_task(self, name, target, *args, **kwargs):
        self._all_tasks.update({self._threadpool.submit(target, *args, **kwargs):name})

    def task_results(self, timeout=None):
        for future in as_completed(self._all_tasks.keys(), timeout=timeout):
            name = self._all_tasks[future]
            try:
                result = {'result':future.result()}
            except Exception as e:
                result = {'result': repr(e)}
            
            yield name, result
        self._all_tasks.clear()
    
    def shutdown(self):
        self._threadpool.shutdown(wait=False)
