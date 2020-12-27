import os
import sys
import time
import logging
import datetime
import traceback
import threading

from lock import Lock

def time_delta(elapsed):
    seconds = elapsed.total_seconds()
    msec = elapsed.microseconds/1000
    hour = seconds // 3600
    seconds = seconds % 3600
    minutes = seconds // 60
    seconds = seconds % 60
    return "%d:%02d:%02d,%03d" % (hour, minutes, seconds, msec)

def get_log_lvl_name(lvl):
    lvl_map = {"INFO" : "INFO ", "WARNING": "WARN "}
    if lvl in lvl_map:
        return lvl_map[lvl]
    return lvl

def get_thread_name():
    name = threading.current_thread().name
    name = name.replace("MainThread", "Thread-0")
    try:
        num = int(name.replace("Thread-", ""))
        name = "T%04d: " % (num)
    except Exception: pass
    try:
        num = int(name.replace("Pyro-Worker-", ""))
        name = "P%04d: " % (num)
        name = "T%04d: " % (0)
    except Exception: pass
    return name

class LogFormatter(object):

    def __init__(self):
        self.start_time = time.time()
        self.node_name = ""

    def format(self, record):
        elapsed_seconds = record.created - self.start_time
        elapsed = datetime.timedelta(seconds=elapsed_seconds)
        time_stamp = time_delta(elapsed)
        thid = get_thread_name()
        lvl = get_log_lvl_name(record.levelname)
        try:
            msg = record.getMessage()
        except Exception:
            msg = "Exception getting message from record"
        if self.node_name:
            prefix = "{} {} {}{}".format(time_stamp, self.node_name, thid, lvl)
        else:
            prefix = "{} {}{}".format(time_stamp, thid, lvl)
        return "{} {}".format(prefix, msg)

class Logger(object):
    def __init__(self, dry=False, name="scapy-tgen", logs_dir = None):
        self.dry = dry
        self.dbg = 1
        self.log_file = None
        self.node_name = ""
        self.lock = Lock()
        self.fmt = LogFormatter()
        self.logger = logging.getLogger(name)

        if logs_dir:
            self.logs_dir = logs_dir
        else:
            self.logs_dir = os.getenv("SCAPY_TGEN_LOGS_PATH", "server")
        self.logs_dir2 = self.logs_dir

        if not self.dry:
            self.remove_stdout()
        #self.create_combined_log()

        self.log_file = None
        self.file_handler = None
        self.set_log_file(None)

    def remove_stdout(self):
        stdlog = logging.StreamHandler(sys.stdout)
        stdlog.setLevel(logging.ERROR if not self.dry else logging.DEBUG)
        ch = logging.StreamHandler()
        ch.setLevel(logging.ERROR if not self.dry else logging.DEBUG)
        ch.setFormatter(self.fmt)
        self.logger.addHandler(ch)
        self.logger.removeHandler(stdlog)
        self.logger.propagate = False

    def ensure_parent(self, log_file):
        from utils import Utils
        Utils.ensure_parent(log_file)

    def create_combined_log(self):
        log_file = os.path.join(self.logs_dir2, "all.log")
        self.ensure_parent(log_file)
        self.file_handler = logging.FileHandler(log_file)
        self.file_handler.setFormatter(self.fmt)
        self.file_handler.setLevel(logging.DEBUG)
        self.logger.addHandler(self.file_handler)

    def set_node_name(self, name, msg=""):
        self.banner("set_node_name: {} current '{}' new '{}'".format(msg, self.node_name, name))
        self.node_name = name
        if self.fmt:
            self.fmt.node_name = name
        self.logs_dir2 = os.path.join(self.logs_dir, name)

    def set_log_file(self, log_file):

        if self.log_file:
            self.banner("Close file {}".format(self.log_file))

        if self.file_handler:
            self.logger.removeHandler(self.file_handler)
            self.file_handler = None

        if log_file:
            if self.logs_dir2:
                log_file = os.path.join(self.logs_dir2, log_file)
            self.ensure_parent(log_file)
            self.file_handler = logging.FileHandler(log_file)
            self.file_handler.setFormatter(self.fmt)
            self.file_handler.setLevel(logging.DEBUG)
            self.logger.addHandler(self.file_handler)

        self.log_file = log_file

        if self.log_file:
            self.banner("Open file {}".format(self.log_file))

        return self.log_file


    def get_log(self, filename=None):
        if not filename:
            filename2 = self.log_file
        elif not os.path.exists(filename) and self.logs_dir2:
            filename2 = os.path.join(self.logs_dir2, filename)
        elif not os.path.exists(filename) and self.logs_dir:
            filename2 = os.path.join(self.logs_dir, filename)
        else:
            filename2 = None

        if not filename2:
            return self.error("Failed to find log file {}".format(filename))

        try:
            fh = open(filename2, 'r')
            data = fh.readlines()
            fh.close()
            data = map(str.strip, data)
            return "\n".join(data)
        except Exception:
            return self.error("Failed to read log file {}".format(filename2))

    def todo(self, etype, name, value):
        msg = "{}: {} = {}".format(etype, name, value)
        self.error(msg)
        raise ValueError(msg)

    def _log(self, lvl, msg):
        if not msg.strip(): return
        self.lock.acquire()
        for line in msg.split("\n"):
            self.logger.log(lvl, line)
        self.lock.release()
        return msg

    def log(self, *args, **kwargs):
        msg = " ".join(map(str,args))
        return self._log(logging.INFO, msg)

    def info(self, *args, **kwargs):
        msg = " ".join(map(str,args))
        return self._log(logging.INFO, msg)

    def warning(self, *args, **kwargs):
        msg = ["#"*80, " ".join(map(str,args)), "#"*80]
        return self._log(logging.WARNING, "\n".join(msg))

    def debug(self, *args, **kwargs):
        msg = " ".join(map(str,args))
        return self._log(logging.DEBUG, msg)

    def banner(self, *args, **kwargs):
        msg = ["#"*80, " ".join(map(str,args)), "#"*80]
        return self.info("\n".join(msg))

    def error(self, *args, **kwargs):
        msg = ""
        #msg = msg + "=================================== "
        msg = msg + " ".join(map(str,args))
        #msg = msg + "=================================== "
        return self._log(logging.ERROR, msg)

    def log_exception(self, e, msg):
        self.logger.error("=========== exception ==================")
        self.logger.error(msg)
        self.logger.error("=========== exception ==================")
        self.logger.error(msg, traceback.format_exc())
        self.lock.acquire()
        self.logger.exception(e)
        self.lock.release()

    @staticmethod
    def setup():
        logging.basicConfig()
        logger = logging.getLogger()
        logger.setLevel(logging.DEBUG)

