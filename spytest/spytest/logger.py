import re
import logging
import sys
import traceback
import threading
import os
import time
import datetime
from spytest.st_time import get_timestamp
import spytest.env as env

def get_thread_name():
    name = threading.current_thread().name
    name = name.replace("MainThread", "Thread-0")
    try:
        num = int(name.replace("Thread-", ""))
        name = "T%04d: " % (num)
    except Exception:
        pass
    return name

def get_log_lvl_name(lvl):
    lvl_map = {"INFO" : "INFO ", "WARNING": "WARN "}
    if lvl in lvl_map:
        return lvl_map[lvl]
    return lvl

def time_delta(elapsed):
    seconds = elapsed.total_seconds()
    msec = elapsed.microseconds/1000
    hour = seconds // 3600
    seconds = seconds % 3600
    minutes = seconds // 60
    seconds = seconds % 60
    return "%d:%02d:%02d,%03d" % (hour, minutes, seconds, msec)

class LogFormatter(object):

    def __init__(self, is_elapsed):
        self.is_elapsed = is_elapsed
        self.start_time = time.time()

    def format(self, record):
        if self.is_elapsed:
            elapsed_seconds = record.created - self.start_time
            elapsed = datetime.timedelta(seconds=elapsed_seconds)
            time_stamp = time_delta(elapsed)
        else:
            time_stamp = get_timestamp(True)
        thid = get_thread_name()
        lvl = get_log_lvl_name(record.levelname)
        msg = record.getMessage()
        return "{} {}{} {}".format(time_stamp, thid, lvl, msg)

class Logger(object):

    def __init__(self, file_prefix=None, filename=None, name='', level=logging.INFO, tlog=False, mlog=True):
        """
        Initialization of the logger object
        :param filename: filename where the logs will be generated. spytest.log if not passed
        :type filename: str
        :param name: name of the instance from where the logs or written
        :type name: str
        :param level: logging level
        """
        self.logdir = None
        self.name = name
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)
        self.dut_loggers = dict()
        self.alert_logger = None
        self.tc_log_support = tlog
        self.tc_log_handler = None
        self.module_log_support = mlog
        self.module_log_handler = None
        self.module_logger = None
        self.module_only_log_support = True
        self.file_prefix = file_prefix
        self.use_elapsed_time_fmt = bool(env.get("SPYTEST_LOGS_TIME_FMT_ELAPSED", "0") == "1")
        self.module_only_log_support = bool(env.get("SPYTEST_LOGS_MODULE_ONLY_SUPPORT", "0") == "1")

        logfile = filename if filename else "spytest.log"
        logfile = self._add_prefix(logfile)
        self.logdir = os.path.dirname(logfile)
        self.add_file_handler(self.logger, logfile, add_prefix=False)

        # Handler for Console logs
        if env.get("SPYTEST_NO_CONSOLE_LOG", "0") == "0":
            console_handler = logging.StreamHandler(sys.stdout)
            fmt = LogFormatter(self.use_elapsed_time_fmt)
            console_handler.setFormatter(fmt)
            self.logger.addHandler(console_handler)

        # Handler for Alert logs
        if not self.alert_logger:
            logfile_path = "alerts.log"
            self.alert_logger = logging.getLogger(logfile_path)
            self.add_file_handler(self.alert_logger, logfile_path)
            self.alert_logger.propagate = False

    def __del__(self):
        pass

    def add_file_handler(self, logger, logfile, add_prefix=True):
        if add_prefix:
            logfile = self._add_prefix(logfile)
        logdir = os.path.dirname(logfile)
        if logdir and not os.path.exists(logdir):
            os.makedirs(logdir)

        file_handler = logging.FileHandler(logfile, 'w')
        fmt = LogFormatter(self.use_elapsed_time_fmt)
        file_handler.setFormatter(fmt)
        logger.addHandler(file_handler)
        return file_handler

    def _add_prefix(self, filename):
        if self.file_prefix:
            return "{}_{}".format(self.file_prefix, filename)
        if self.logdir:
            filename = os.path.join(self.logdir, filename)
        return filename

    def info(self, msg, dut=None, split_lines=False, exc_info=False, dst=None):
        self.log(logging.INFO, msg, dut, split_lines, exc_info=exc_info, dst=dst)

    def error(self, msg, dut=None, split_lines=False, exc_info=True, dst=None):
        self.log(logging.ERROR, msg, dut, split_lines, exc_info=exc_info, dst=dst)

    def debug(self, msg, dut=None, split_lines=False, dst=None):
        self.log(logging.DEBUG, msg, dut, split_lines, dst=dst)

    def warning(self, msg, dut=None, split_lines=False, dst=None):
        self.log(logging.WARNING, msg, dut, split_lines, dst=dst)

    def exception(self, msg, dut=None, split_lines=False, dst=None):
        msg2 = "{}\n{}".format(msg, traceback.format_exc())
        self.log(logging.ERROR, msg2, dut, split_lines, dst=dst)

    def set_lvl(self, lvl):
        if lvl == "debug":
            self.logger.setLevel(logging.DEBUG)

    def log(self, lvl, msg, dut=None, split_lines=False, exc_info=False, dst=None):

        if isinstance(dut, list):
            for d in dut:
                self.log(lvl, msg, d, split_lines, exc_info=exc_info, dst=dst)
            return
        if dut:
            self.dut_log(dut, msg, lvl, split_lines, exc_info=exc_info, dst=dst)
        elif split_lines:
            for line in msg.splitlines():
                self.log(lvl, line, exc_info=exc_info, dst=dst)
        else:
            dst = dst or ["all", "module"]
            if "all" in dst:
                self.logger.log(lvl, msg, exc_info=exc_info)
            if "module" in dst and self.module_only_log_support:
                if self.module_logger:
                    self.module_logger.log(lvl, msg, exc_info=exc_info)
                    self.flush_handlers(self.module_logger)

    def _tostring(self, msg):
        msg = re.sub(r'(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]', ' ', msg)
        msg = re.sub(r'[^\x00-\x7F]+', ' ', msg)
        try:
            return msg.encode('ascii', 'ignore').decode('ascii')
        except Exception as exp:
            print(str(exp))
        return "non-ascii characters"

    @staticmethod
    def get_dlog_name(dut):
        return "dlog-{0}.log".format(dut)

    # per device LOG, the message can single or list of messages
    def dut_log(self, dut, msg, lvl=logging.INFO, split_lines=False, conn=None,
                exc_info=False, dst=None, prefix=""):

        if isinstance(msg, list):
            for line in msg:
                self.dut_log(dut, line, lvl, False, conn,
                             exc_info=exc_info, dst=dst, prefix=prefix)
            return

        if split_lines:
            for line in msg.splitlines():
                self.dut_log(dut, line, lvl, False, conn,
                             exc_info=exc_info, dst=dst, prefix=prefix)
            return

        if dut not in self.dut_loggers:
            logfile_path = self.get_dlog_name(dut)
            self.dut_loggers[dut] = logging.getLogger(logfile_path)
            self.add_file_handler(self.dut_loggers[dut], logfile_path)
            self.dut_loggers[dut].propagate = False

        msg1 = "{}{}".format(prefix, self._tostring(msg))
        if conn: msg2 = "[{}-{}] {}".format(dut, conn, msg1)
        else:    msg2 = "[{}] {}".format(dut, msg1)

        dst = dst or ["all", "module", "dut"]

        # add main log
        if "all" in dst:
            self.logger.log(lvl, msg2, exc_info=exc_info)
            self.flush_handlers(self.logger)

        # add module log
        if "module" in dst and self.module_only_log_support:
            if self.module_logger:
                self.module_logger.log(lvl, msg2, exc_info=exc_info)
                self.flush_handlers(self.module_logger)

        # add DUT log
        if "dut" in dst:
            if conn: msg2 = "[{}] {}".format(conn, msg1)
            else:    msg2 = "{}".format(msg1)
            self.dut_loggers[dut].log(lvl, msg2, exc_info=exc_info)
            self.flush_handlers(self.dut_loggers[dut])

    def flush_handlers(self, logger):
        for handler in logger.handlers:
            handler.flush()

    def close_handler(self, handler, logger=None):
        if handler:
            handler.close()
            logger = logger or self.logger
            logger.removeHandler(handler)
        return None

    def tc_log_init(self, test_name):
        if not self.tc_log_support: return
        self.tc_log_handler = self.close_handler(self.tc_log_handler)
        if not test_name: return
        logfile_path = "{}.log".format(test_name)
        rv = self.add_file_handler(self.logger, logfile_path)
        self.tc_log_handler = rv

    def module_log_init(self, module_name):
        if not self.module_log_support: return
        self.module_log_handler = self.close_handler(self.module_log_handler,
                                                     self.module_logger)
        if not module_name: return
        logfile_path = "{}.log".format(module_name)
        if self.module_only_log_support:
            self.module_logger = logging.getLogger(logfile_path)
            rv = self.add_file_handler(self.module_logger, logfile_path)
            self.module_logger.propagate = False
        else:
            self.module_logger = self.logger
            rv = self.add_file_handler(self.module_logger, logfile_path)
        self.module_log_handler = rv

    def alert(self, msg, lvl=logging.INFO, exc_info=False):

        if isinstance(msg, list):
            for line in msg:
                self.alert(line, lvl, exc_info=exc_info)
            return

        if self.alert_logger:
            self.alert_logger.log(lvl, msg, exc_info=exc_info)
            self.flush_handlers(self.alert_logger)

class NullHandler(logging.Handler):
    def emit(self, record):
        pass
def getNoneLogger():
    logger = logging.getLogger("dummy")
    logger.addHandler(NullHandler())
    return logger

