import os
import sys
import logging
import threading
import traceback

class Logger(object):
    def __init__(self, dry=False, name="scapy-tgen"):
        self.dry = dry
        self.dbg = 1
        self.log_file = None
        self.screen_lock = threading.Lock()
        self.fmt = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
        self.logger = logging.getLogger(name)
        stdlog = logging.StreamHandler(sys.stdout)
        stdlog.setLevel(logging.ERROR)
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)
        ch.setFormatter(self.fmt)
        self.logger.addHandler(ch)
        self.logger.removeHandler(stdlog)
        self.logger.propagate = False
        self.log_file = None
        self.file_handler = None
        self.logs_dir = os.getenv("SCAPY_TGEN_LOGS_PATH", "server")
        self.set_log_file(None)

    @staticmethod
    def ensure_parent(filename):
        path = os.path.dirname(filename)
        path = os.path.abspath(path)
        if not os.path.exists(path):
            os.makedirs(path)

    def set_log_file(self, log_file):
        if self.file_handler:
            self.logger.removeHandler(self.file_handler)
            self.file_handler = None

        if log_file:
            if self.logs_dir:
                log_file = os.path.join(self.logs_dir, log_file)
            self.ensure_parent(log_file)
            self.file_handler = logging.FileHandler(log_file)
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
        except:
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
        with self.screen_lock:
            self.logger.log(lvl, msg)

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
        with self.screen_lock:
            self.logger.exception(e)

    @staticmethod
    def setup():
        logging.basicConfig()
        logger = logging.getLogger()
        logger.setLevel(logging.DEBUG)

