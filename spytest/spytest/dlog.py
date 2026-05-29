import logging

from spytest.ftrace import ftrace_prefix
from spytest import env

LEVEL_SUCCESS = logging.INFO
LEVEL_FAILURE = logging.ERROR
LEVEL_ABORT = logging.WARNING - 1
LEVEL_NOT_RUN = logging.WARNING - 2
LEVEL_SEND = logging.INFO - 1
LEVEL_RECV = logging.INFO - 2
LEVEL_HEADER = logging.INFO - 3
LEVEL_STEP = logging.INFO - 4
LEVEL_START_TEST = logging.INFO - 5
LEVEL_VERBOSE = logging.DEBUG - 5
LEVEL_DEBUG = logging.DEBUG
LEVEL_INFO = logging.INFO
LEVEL_WARN = logging.WARNING
LEVEL_ERROR = logging.ERROR

logging.addLevelName(LEVEL_ABORT, "ABORT")
logging.addLevelName(LEVEL_NOT_RUN, "NOTRUN")
logging.addLevelName(LEVEL_SEND, "SEND")
logging.addLevelName(LEVEL_RECV, "RECV")
logging.addLevelName(LEVEL_HEADER, "HEADER")
logging.addLevelName(LEVEL_STEP, "STEP")
logging.addLevelName(LEVEL_START_TEST, "STARTEST")
logging.addLevelName(LEVEL_VERBOSE, "VERBOSE")


class DebugLogger():
    def __init__(self, logger=None, name="dbg", en_log=None, en_trace=None):
        self.logger = logger
        if en_trace is None:
            en_trace = env.match("SPYTEST_DLOG_ENABLE_TRACE", "1", "0")
        if en_log is None:
            en_log = env.match("SPYTEST_DLOG_ENABLE_LOG", "1", "0")
        self.en_trace = en_trace
        self.en_log = en_log
        self.name = name
        self.no_silent = True

    def set_log_level(self, en_trace, en_log):
        if en_trace is not None:
            self.en_trace = en_trace
        if en_log is not None:
            self.en_log = en_log

    def set_logger(self, logger):
        self.logger = logger

    def log(self, lvl, name, message, split=True):
        if not self.en_trace and not self.en_log:
            return
        lines = str(message).splitlines() if split else [message]
        for line in lines:
            if not line.strip():
                continue
            if self.en_trace:
                ftrace_prefix(self.name, "{}: {}".format(name, line))
            if self.en_log and self.logger:
                self.logger.log(lvl, "LIVE: {}".format(line))

    def verbose(self, message):
        self.log(LEVEL_VERBOSE, "VERBOSE", message)

    def debug(self, message):
        self.log(LEVEL_DEBUG, "DEBUG", message)

    def info(self, message):
        self.log(LEVEL_INFO, "INFO", message)

    def warn(self, message):
        self.log(LEVEL_WARN, "WARN", message)

    def error(self, message):
        self.log(LEVEL_ERROR, "ERROR", message)

    def exception(self, exception):
        self.log(LEVEL_ERROR, "EXCEPTION", str(exception))

    def not_run(self, message):
        self.log(LEVEL_NOT_RUN, "NOT RUN", message)

    def send(self, device, message):
        self.log(LEVEL_SEND, "SEND", message)

    def recv(self, device, message):
        self.log(LEVEL_RECV, "RECV", message)

    def header(self, message):
        self.log(LEVEL_HEADER, "HEADER", message)

    def step(self, message, **kwargs):
        self.log(LEVEL_STEP, "STEP", message)

    def abort(self, message):
        self.log(LEVEL_ABORT, "ABORT", message)

    def success(self, message):
        self.log(LEVEL_SUCCESS, "SUCCESS", message)

    def fail(self, message, **kwargs):
        self.log(LEVEL_FAILURE, "FAIL", message)
