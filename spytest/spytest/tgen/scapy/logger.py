import os
import sys
import time
import logging
import datetime
import traceback

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

class LogFormatter(object):

    def __init__(self):
        self.start_time = time.time()
        self.node_name = ""

    def format(self, record):
        elapsed_seconds = record.created - self.start_time
        elapsed = datetime.timedelta(seconds=elapsed_seconds)
        time_stamp = time_delta(elapsed)
        lvl = get_log_lvl_name(record.levelname)
        try:
            msg = record.getMessage()
        except Exception:
            msg = "Exception getting message from record"
        if self.node_name:
            return "{} {} {} {}".format(time_stamp, self.node_name, lvl, msg)
        else:
            return "{} {} {}".format(time_stamp, lvl, msg)

class Logger(object):
    def __init__(self, dry=False, name="scapy-tgen", logs_dir = None):
        self.dry = dry
        self.dbg = 1
        self.log_file = None
        self.lock = Lock()
        self.fmt = LogFormatter()
        self.logger = logging.getLogger(name)
        stdlog = logging.StreamHandler(sys.stdout)
        stdlog.setLevel(logging.ERROR if not self.dry else logging.DEBUG)
        ch = logging.StreamHandler()
        ch.setLevel(logging.ERROR if not self.dry else logging.DEBUG)
        ch.setFormatter(self.fmt)
        self.logger.addHandler(ch)
        self.logger.removeHandler(stdlog)
        self.logger.propagate = False
        self.log_file = None
        self.file_handler = None
        if logs_dir:
            self.logs_dir = logs_dir
        else:
            self.logs_dir = os.getenv("SCAPY_TGEN_LOGS_PATH", "server")
        self.set_log_file(None)

    @staticmethod
    def ensure_parent(filename):
        path = os.path.dirname(filename)
        path = os.path.abspath(path)
        if not os.path.exists(path):
            os.makedirs(path)

    def set_node_name(self, name):
        if self.fmt:
            self.fmt.node_name = name

    def set_log_file(self, log_file):
        if self.file_handler:
            self.logger.removeHandler(self.file_handler)
            self.file_handler = None

        if log_file:
            if self.logs_dir:
                log_file = os.path.join(self.logs_dir, log_file)
            self.ensure_parent(log_file)
            self.file_handler = logging.FileHandler(log_file)
            self.file_handler.setFormatter(self.fmt)
            self.file_handler.setLevel(logging.DEBUG)
            self.logger.addHandler(self.file_handler)

        self.log_file = log_file

    def get_log(self, filename=None):
        if not filename:
            filename = self.log_file
        elif not os.path.exists(filename) and self.logs_dir:
            filename = os.path.join(self.logs_dir, filename)

        if not filename:
            return ""
        try:
            fh = open(filename, 'r')
            data = fh.readlines()
            fh.close()
            data = map(str.strip, data)
            return "\n".join(data)
        except Exception:
             return ""

    def todo(self, etype, name, value):
        msg = "{}: {} = {}".format(etype, name, value)
        self.error(msg)
        raise ValueError(msg)

    def debug(self, *args, **kwargs):
        msg = " ".join(map(str,args))
        self._log(logging.DEBUG, msg)

    def _log(self, lvl, msg):
        if not msg.strip(): return
        self.lock.acquire()
        for line in msg.split("\n"):
            self.logger.log(lvl, line)
        self.lock.release()

    def log(self, *args, **kwargs):
        msg = " ".join(map(str,args))
        self._log(logging.INFO, msg)

    def info(self, *args, **kwargs):
        msg = " ".join(map(str,args))
        self._log(logging.INFO, msg)

    def error(self, *args, **kwargs):
        msg = ""
        #msg = msg + "=================================== "
        msg = msg + " ".join(map(str,args))
        #msg = msg + "=================================== "
        self._log(logging.ERROR, msg)

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

