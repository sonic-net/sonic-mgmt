import os
import threading

from spytest import paths

from utilities.common import write_file, logargs
from utilities.common import rename_file

ftrace_files = {}
ftrace_lock = threading.Lock()


def _get_logs_path(master=False):
    user_root = os.getenv("SPYTEST_USER_ROOT", os.getcwd())
    logs_path = os.getenv("SPYTEST_LOGS_PATH", user_root)
    worker_id = os.getenv("PYTEST_XDIST_WORKER")
    if worker_id and not master:
        logs_path = os.path.join(logs_path, worker_id)
    if not os.path.isabs(logs_path):
        logs_path = os.path.join(user_root, logs_path)
    if not os.path.exists(logs_path):
        os.makedirs(logs_path)
    return [user_root, logs_path, worker_id]


def _get_file_path(prefix):
    return paths.get_file_path(prefix, "txt", _get_logs_path()[1])


def ftrace_reset():
    if ftrace_lock: ftrace_lock.acquire()
    for prefix, old_path in ftrace_files.items():
        new_path = _get_file_path(prefix)
        if old_path != new_path:
            rename_file(old_path, new_path)
            ftrace_files[prefix] = new_path
    if ftrace_lock: ftrace_lock.release()


def ftrace_prefix(prefix, *args, **kwargs):
    if ftrace_lock: ftrace_lock.acquire()
    if prefix not in ftrace_files:
        ftrace_files[prefix] = _get_file_path(prefix)
        write_file(ftrace_files[prefix], "")
    content = logargs(*args, **kwargs) + "\n"
    write_file(ftrace_files[prefix], content, "a")
    if ftrace_lock: ftrace_lock.release()
    return content.strip()


def ftrace(*args, **kwargs):
    ftrace_prefix("ftrace", *args, **kwargs)


def print_ftrace(*args, **kwargs):
    content = ftrace_prefix("ftrace", *args, **kwargs)
    print(content)
