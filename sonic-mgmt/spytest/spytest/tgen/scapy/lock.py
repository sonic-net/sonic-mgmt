import time
import threading

class Lock(object):
    def __init__(self):
        self.lock = threading.Lock()
        self.cond = threading.Condition(threading.Lock())

    def acquire(self, block=True, timeout=None):
        if not timeout:
            return self.lock.acquire(block)
        with self.cond:
            current_time = start_time = time.time()
            while current_time < start_time + timeout:
                if self.lock.acquire(False):
                    return True
                self.cond.wait(timeout - current_time + start_time)
                current_time = time.time()
        return False

    def release(self):
        return self.lock.release()

