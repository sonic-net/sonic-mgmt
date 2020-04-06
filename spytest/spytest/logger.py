import logging
import sys
import traceback
import threading
import os
import time
import datetime
from spytest.st_time import get_timestamp

def get_thread_name():
    name = threading.current_thread().name
    name = name.replace("MainThread", "Thread-0")
    try:
        num = int(name.replace("Thread-", ""))
        name = "T%04d: " % (num)
    except:
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
    """
    todo: Update Documentation
    """

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
        self.tc_log_handler = None
        self.module_log_handler = None
        self.file_prefix = file_prefix
        self.tc_log_handler_support = tlog
        self.module_log_handler_support = mlog
        self.use_elapsed_time_fmt = bool(os.getenv("SPYTEST_LOGS_TIME_FMT_ELAPSED", "0") == "1")
        self.tc_log_fmt = None
        self.module_log_fmt = None
        self.base_fmt = LogFormatter(self.use_elapsed_time_fmt)

        logfile = filename if filename else "spytest.log"

        logfile = self._add_prefix(logfile)

        self.logdir = os.path.dirname(logfile)
        self.add_file_handler(self.logger, logfile)

        # Handler for Console logs
        if not os.getenv("SPYTEST_NO_CONSOLE_LOG"):
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(self.base_fmt)
            self.logger.addHandler(console_handler)

    def __del__(self):
        pass

    def add_file_handler(self, logger, logfile):
        logdir = os.path.dirname(logfile)
        if logdir and not os.path.exists(logdir):
            os.makedirs(logdir)

        file_handler = logging.FileHandler(logfile, 'w')
        file_handler.setFormatter(self.base_fmt)
        logger.addHandler(file_handler)

    def _add_prefix(self, filename):
        if self.file_prefix:
            return "{}_{}".format(self.file_prefix, filename)
        if self.logdir:
            filename = os.path.join(self.logdir, filename)
        return filename

    def info(self, msg, dut=None, split_lines=False, exc_info=False):
        """
        todo: Update Documentation
        :param msg:
        :type msg:
        :param dut:
        :type dut:
        :return:
        :rtype:
        """

        self.log(logging.INFO, msg, dut, split_lines, exc_info=exc_info)

    def error(self, msg, dut=None, split_lines=False, exc_info=True):
        """
        todo: Update Documentation
        :param msg:
        :type msg:
        :param dut:
        :type dut:
        :return:
        :rtype:
        """
        self.log(logging.ERROR, msg, dut, split_lines, exc_info=exc_info)

    def debug(self, msg, dut=None, split_lines=False):
        """
        todo: Update Documentation
        :param msg:
        :type msg:
        :param dut:
        :type dut:
        :return:
        :rtype:
        """
        self.log(logging.DEBUG, msg, dut, split_lines)

    def warning(self, msg, dut=None, split_lines=False):
        """
        todo: Update Documentation
        :param msg:
        :type msg:
        :param dut:
        :type dut:
        :return:
        :rtype:
        """
        self.log(logging.WARNING, msg, dut, split_lines)

    def exception(self, msg, dut=None, split_lines=False):
        """
        todo: Update Documentation
        :param msg:
        :type msg:
        :param dut:
        :type dut:
        :return:
        :rtype:
        """
        msg2 = "{}\n{}".format(msg, traceback.format_exc())
        self.log(logging.ERROR, msg2, dut, split_lines)

    def set_lvl(self, lvl):
        """
        todo: Update Documentation
        :param lvl:
        :type lvl:
        :return:
        :rtype:
        """
        if lvl == "debug":
            self.logger.setLevel(logging.DEBUG)

    def log(self, lvl, msg, dut=None, split_lines=False, exc_info=False):
        """
        todo: Update Documentation
        :param lvl:
        :type lvl:
        :param msg:
        :type msg:
        :param dut:
        :type dut:
        :return:
        :rtype:
        """
        if dut:
            self.dut_log(dut, msg, lvl, split_lines, exc_info=exc_info)
        elif split_lines:
            for line in msg.splitlines():
                self.logger.log(lvl, line, exc_info=exc_info)
        else:
            self.logger.log(lvl, msg, exc_info=exc_info)

    def dut_log(self, dut, msg, lvl=logging.INFO, skip_general=False,
                split_lines=False, conn=None, exc_info=False):

        if isinstance(msg, list):
            for line in msg:
                self.dut_log(dut, line, lvl, skip_general, False, conn, exc_info=exc_info)
            return

        if split_lines:
            for line in msg.splitlines():
                self.dut_log(dut, line, lvl, skip_general, False, conn, exc_info=exc_info)
            return

        if dut not in self.dut_loggers:
            logfile_path = "{0}.log".format(dut)
            self.dut_loggers[dut] = logging.getLogger(logfile_path)
            logfile_path = self._add_prefix(logfile_path)
            self.add_file_handler(self.dut_loggers[dut], logfile_path)
            self.dut_loggers[dut].propagate = False

        try:
            msg1 = str(msg)
        except UnicodeEncodeError as exp:
            msg1 = unicode(msg)

        # add main log
        if not skip_general:
            if conn:
                msg2 = "[{}-{}] {}".format(dut, conn, msg1)
            else:
                msg2 = "[{}] {}".format(dut, msg1)
            self.logger.log(lvl, msg2, exc_info=exc_info)
            for handler in self.logger.handlers:
                handler.flush()

        # add DUT log
        if conn:
            msg2 = "[{}] {}".format(conn, msg1)
        else:
            msg2 = "{}".format(msg1)
        self.dut_loggers[dut].log(lvl, msg2, exc_info=exc_info)
        for handler in self.dut_loggers[dut].handlers:
            handler.flush()

    def tc_log_init(self, test_name):
        if not self.tc_log_handler_support:
            return
        if self.tc_log_handler:
            self.tc_log_handler.close()
            self.logger.removeHandler(self.tc_log_handler)
            self.tc_log_handler = None

        if test_name:
            logfile_path = self._add_prefix("{}.log".format(test_name))
            self.tc_log_handler = logging.FileHandler(logfile_path, 'w')
            self.tc_log_fmt = LogFormatter(self.use_elapsed_time_fmt)
            self.tc_log_handler.setFormatter(self.tc_log_fmt)
            self.logger.addHandler(self.tc_log_handler)

    def module_log_init(self, module_name):
        if not self.module_log_handler_support:
            return
        if self.module_log_handler:
            self.module_log_handler.close()
            self.logger.removeHandler(self.module_log_handler)
            self.module_log_handler = None

        if module_name:
            logfile_path = self._add_prefix("{}.log".format(module_name))
            self.module_log_handler = logging.FileHandler(logfile_path, 'w')
            self.module_log_fmt = LogFormatter(self.use_elapsed_time_fmt)
            self.module_log_handler.setFormatter(self.module_log_fmt)
            self.logger.addHandler(self.module_log_handler)

if __name__ == "__main__":
    logger = Logger("ut", "logs.log")
    logger.info("generic info 1")
    logger.dut_log("D1", "dut-1 info 1")
    logger.dut_log("D2", "dut-2 info 1")
    logger.dut_log("D1", "dut-1 info 1", conn="SSH")
    logger.dut_log("D2", "dut-2 info 1", conn="SSH")
    logger.error("generic error 1")
    logger.warning("generic warning 1")
    logger.dut_log("D1", "dut-1 info 1", lvl=logging.WARNING)
    logger.dut_log("D2", "dut-2 info 1", lvl=logging.WARNING)

