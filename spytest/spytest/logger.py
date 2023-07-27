import logging
import sys
import traceback
import os
import time
import datetime

from spytest.st_time import get_timestamp
from spytest import env
from utilities import ctrl_chars
from utilities.parallel import get_thread_name

LEVEL_AUDIT = logging.INFO + 1
logging.addLevelName(LEVEL_AUDIT, 'AUDIT')

LEVEL_NOTICE = logging.INFO + 2
logging.addLevelName(LEVEL_NOTICE, 'NOTICE')

LEVEL_TOPO = logging.INFO + 3
logging.addLevelName(LEVEL_TOPO, 'TOPO')

LEVEL_TXTFSM = logging.DEBUG + 1
logging.addLevelName(LEVEL_TXTFSM, 'TFSM')

lvl_map = {"INFO": "INFO ", "WARNING": "WARN ",
           "TFSM": "TFSM ", "TOPO": "TOPO "}


def get_log_lvl_name(lvl):
    if lvl in lvl_map:
        return lvl_map[lvl]
    return lvl


def add_log_lvl_name(name, disp):
    lvl_map[name] = disp


def time_delta(elapsed):
    seconds = elapsed.total_seconds()
    msec = elapsed.microseconds / 1000
    hour = seconds // 3600
    seconds = seconds % 3600
    minutes = seconds // 60
    seconds = seconds % 60
    return "%d:%02d:%02d,%03d" % (hour, minutes, seconds, msec)


class LogFormatter(object):

    def __init__(self, is_elapsed, show_lvl=True):
        self.is_elapsed = is_elapsed
        self.show_lvl = show_lvl
        self.start_time = time.time()

    def bld(self, msg, levelname=None, ts=None):
        if self.is_elapsed:
            ts = ts or time.time()
            elapsed_seconds = ts - self.start_time
            elapsed = datetime.timedelta(seconds=elapsed_seconds)
            time_stamp = time_delta(elapsed)
        else:
            time_stamp = get_timestamp(True)
        thid = get_thread_name()
        lvl = get_log_lvl_name(levelname or "INFO")
        if not self.show_lvl:
            return "{} {}{}".format(time_stamp, thid, msg)
        return "{} {}{} {}".format(time_stamp, thid, lvl, msg)

    def format(self, record):
        return self.bld(record.getMessage(), record.levelname, ts=record.created)


class Logger(object):

    def __init__(self, file_prefix=None, filename=None, name='SPyTest', level=logging.INFO, tlog=False, mlog=True):
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
        self.phase = None
        self.level = level
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)
        self.dut_loggers = dict()
        self.alert_logger = None
        self.audit_logger = None
        self.tc_log_support = tlog
        self.tc_log_handler = None
        # module_log_support 0: disabled 1: both session and module log 2: module only log
        module_log_support = env.getint("SPYTEST_LOGS_PER_MODULE_SUPPORT", 1)
        self.module_log_support = module_log_support if mlog else 0
        self.module_log_handler = None
        self.module_logger = None
        self.file_prefix = file_prefix
        self.use_elapsed_time_fmt = env.match("SPYTEST_LOGS_TIME_FMT_ELAPSED", "1", "0")
        self.dut_log_support = env.match("SPYTEST_LOGS_PER_DUT_SUPPORT", "1", "1")
        self.audit_log_support = env.match("SPYTEST_LOGS_AUDIT_SUPPORT", "1", "1")

        logfile = filename if filename else "spytest.log"
        logfile = self._add_prefix(logfile)
        self.logdir = os.path.dirname(logfile)

        self.fmt = {
            False: LogFormatter(self.use_elapsed_time_fmt, show_lvl=False),
            True: LogFormatter(self.use_elapsed_time_fmt, show_lvl=True)
        }

        self.add_file_handler(self.logger, logfile, add_prefix=False)

        # Handler for Console logs
        if env.match("SPYTEST_NO_CONSOLE_LOG", "0", "0"):
            console_handler = logging.StreamHandler(sys.stdout)
            fmt = self.fmt[True]
            console_handler.setFormatter(fmt)
            self.logger.addHandler(console_handler)

        # Handler for Alert logs
        if not self.alert_logger:
            logfile_path = "alerts.log"
            self.alert_logger = logging.getLogger(logfile_path)
            self.alert_logger.setLevel(self.level)
            self.add_file_handler(self.alert_logger, logfile_path)
            self.alert_logger.propagate = False

        # Handler for Audit logs
        if not self.audit_logger and self.audit_log_support:
            logfile_path = "audit.log"
            self.audit_logger = logging.getLogger(logfile_path)
            self.audit_logger.setLevel(self.level)
            self.add_file_handler(self.audit_logger, logfile_path, show_lvl=False)
            self.audit_logger.propagate = False

    def __del__(self):
        pass

    def add_file_handler(self, logger, logfile, add_prefix=True,
                         append=False, show_lvl=True):
        if add_prefix:
            logfile = self._add_prefix(logfile)
        logdir = os.path.dirname(logfile)
        if logdir and not os.path.exists(logdir):
            os.makedirs(logdir)

        if not append:
            try: os.remove(logfile)
            except Exception: pass
        file_handler = logging.FileHandler(logfile, "a")
        fmt = self.fmt[show_lvl]
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

    def notice(self, msg, dut=None, split_lines=False, exc_info=True, dst=None):
        self.log(LEVEL_NOTICE, msg, dut, split_lines, exc_info=exc_info, dst=dst)

    def audit(self, msg, split_lines=False, exc_info=True, dst=None):
        if split_lines:
            for line in msg.splitlines():
                self.audit(line, exc_info=exc_info, dst=dst)
            return

        # add audit and session log
        if self.audit_log_support:
            dst = dst or ["all", "module", "audit"]
            self._log(None, msg, LEVEL_AUDIT, exc_info, dst)

    def dut(self, msg, dut=None, split_lines=False, exc_info=True, dst=None):
        self.log(logging.ERROR, msg, dut, split_lines, exc_info=exc_info, dst=dst)

    def debug(self, msg, dut=None, split_lines=False, dst=None):
        self.log(logging.DEBUG, msg, dut, split_lines, dst=dst)

    def txtfsm(self, msg, dut=None, split_lines=False, dst=None):
        self.log(LEVEL_TXTFSM, msg, dut, split_lines, dst=dst)

    def warning(self, msg, dut=None, split_lines=False, dst=None):
        self.log(logging.WARNING, msg, dut, split_lines, dst=dst)

    def exception(self, msg, dut=None, split_lines=False, dst=None):
        msg2 = "{}\n{}".format(str(msg), traceback.format_exc())
        self.log(logging.ERROR, msg2, dut, split_lines, dst=dst)

    def set_phase(self, phase):
        self.phase = phase

    def set_lvl(self, lvl):
        if lvl == "debug":
            self.logger.setLevel(logging.DEBUG)

    def add_lvl(self, lvl, name, disp=None):
        logging.addLevelName(lvl, name)
        add_log_lvl_name(name, disp or name)
        return lvl

    def bld(self, msg, lvl=logging.INFO, dut=None, split_lines=False, prefix="", show_lvl=False):

        if dut:
            msg1 = "{}{}".format(prefix, ctrl_chars.tostring(msg))
            msg = "[{}] {}".format(dut, msg1)

        return self.fmt[show_lvl].bld(msg, logging.getLevelName(lvl))

    def log(self, lvl, msg, dut=None, split_lines=False, exc_info=False, dst=None):

        # handle multiple duts
        if isinstance(dut, list):
            for d in dut:
                self.log(lvl, msg, d, split_lines, exc_info=exc_info, dst=dst)
            return

        # handle dut specific logs
        if dut:
            self.dut_log(dut, msg, lvl, split_lines, exc_info=exc_info, dst=dst)
            return

        # handle message with multiple lines
        if split_lines:
            for line in msg.splitlines():
                self.log(lvl, line, exc_info=exc_info, dst=dst)
            return

        # add module and session log
        dst = dst or ["all", "module"]
        return self._log(dut, msg, lvl, exc_info, dst)

    def trace(self, msg):
        if isinstance(msg, list):
            for line in msg:
                self.trace(line)
        else:
            for line in msg.splitlines():
                print(line)

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

        if self.dut_log_support and dut not in self.dut_loggers:
            logfile_path = self.get_dlog_name(dut)
            self.dut_loggers[dut] = logging.getLogger(logfile_path)
            self.dut_loggers[dut].setLevel(self.level)
            self.add_file_handler(self.dut_loggers[dut], logfile_path)
            self.dut_loggers[dut].propagate = False

        dst = dst or ["all", "module", "dut"]

        # add DUT log
        if self.dut_log_support and "dut" in dst:
            msg1 = "{}{}".format(prefix, ctrl_chars.tostring(msg))
            if conn: msg2 = "[{}] {}".format(conn, msg1)
            else: msg2 = "{}".format(msg1)
            self.dut_loggers[dut].log(lvl, msg2, exc_info=exc_info)
            self.flush_handlers(self.dut_loggers[dut])

        # add module and session log
        return self._log(dut, msg, lvl, exc_info, dst, conn, prefix)

    def _log(self, dut, msg, lvl, exc_info, dst, conn=None, prefix=""):

        if dut:
            msg1 = "{}{}".format(prefix, ctrl_chars.tostring(msg))
            if conn: msg = "[{}-{}] {}".format(dut, conn, msg1)
            else: msg = "[{}] {}".format(dut, msg1)

        # add main log
        if "all" in dst and (not self.module_logger or self.module_log_support != 2):
            self.logger.log(lvl, msg, exc_info=exc_info)
            self.flush_handlers(self.logger)

        # add module log
        if "module" in dst and self.module_logger:
            self.module_logger.log(lvl, msg, exc_info=exc_info)
            self.flush_handlers(self.module_logger)

        # add audit log
        if "audit" in dst and self.audit_logger:
            self.audit_logger.log(lvl, msg, exc_info=exc_info)
            self.flush_handlers(self.audit_logger)

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

    def module_log_init(self, module_name, append=False):
        if not self.module_log_support:
            # nothing to do as it is not supported
            return

        # close the current module handler
        self.close_handler(self.module_log_handler, self.module_logger)

        # no need to create logger if module name is not specified
        if not module_name:
            self.module_log_handler = None
            self.module_logger = None
            return

        # create module logger
        logfile_path = "{}.log".format(module_name)
        self.module_logger = logging.getLogger(logfile_path)
        self.module_logger.setLevel(self.level)
        rv = self.add_file_handler(self.module_logger, logfile_path, append=append)
        self.module_logger.propagate = False
        self.module_log_handler = rv

    def alert(self, msg, lvl=logging.INFO, exc_info=False):

        if isinstance(msg, list):
            for index, line in enumerate(msg):
                self.alert(line, lvl, exc_info=exc_info)
                if index > 20:
                    self.alert("Truncated...", lvl)
                    break
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
