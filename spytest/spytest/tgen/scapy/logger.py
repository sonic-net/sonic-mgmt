import os
import sys
import time
import logging
import datetime
import traceback
import threading

from lock import Lock
from funcs import read_lines


def time_delta(elapsed):
    seconds = elapsed.total_seconds()
    msec = elapsed.microseconds / 1000
    hour = seconds // 3600
    seconds = seconds % 3600
    minutes = seconds // 60
    seconds = seconds % 60
    return "%d:%02d:%02d,%03d" % (hour, minutes, seconds, msec)


def get_log_lvl_name(lvl):
    lvl_map = {"INFO": "INFO ", "WARNING": "WARN "}
    if lvl in lvl_map:
        return lvl_map[lvl]
    return lvl


def get_thread_name():
    name = threading.current_thread().name
    name = name.replace("MainThread", "Thread-0")
    try:
        num = int(name.replace("Thread-", ""))
        name = "T%04d: " % (num)
    except Exception:
        pass
    try:
        num = int(name.replace("Pyro-Worker-", ""))
        name = "P%04d: " % (num)
        name = "T%04d: " % (0)
    except Exception:
        pass
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
    def __init__(self, dry=False, name="scapy-tgen", logs_dir=None):
        self.dry = dry
        self.dbg = 1
        self.log_file = None
        self.addl_logs = {}
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

        self.all_file_handler = None
        self.create_combined_log()

        self.log_file = None
        self.file_handler = None
        self.set_log_file("init.log")

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

    def ensure_folder(self, log_file):
        from utils import Utils
        Utils.ensure_folder(log_file)

    def create_combined_log(self):
        log_file = os.path.join(self.logs_dir2, "all.log")
        self.ensure_parent(log_file)
        self.all_file_handler = logging.FileHandler(log_file)
        self.all_file_handler.setFormatter(self.fmt)
        self.all_file_handler.setLevel(logging.DEBUG)
        self.logger.addHandler(self.all_file_handler)

    def create_link(self, name):
        self.logs_dir2 = os.path.join(self.logs_dir, name)
        cmd = "cd {0}/..; rm -f {1}; mkdir -p {2}; ln -s {3}/{1} {1}"
        cmd = cmd.format(self.logs_dir, name, self.logs_dir2, os.path.basename(self.logs_dir))
        os.system(cmd)
        return self.logs_dir2

    def set_node_name(self, name, msg=""):
        self.banner("set_node_name: {} current '{}' new '{}'".format(msg, self.node_name, name))
        self.node_name = name
        if self.fmt:
            self.fmt.node_name = name
        self.create_link("current")
        if name:
            self.create_link(name)

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
            pyver = "{}.{}.{}".format(sys.version_info.major, sys.version_info.minor,
                                      sys.version_info.micro)
            self.banner("Python: {}".format(pyver))
            self.banner("Open file {}".format(self.log_file))

        return self.log_file

    def get_log_path(self, filename=None):
        if not filename:
            filename2 = self.log_file
        elif not os.path.exists(filename) and self.logs_dir2:
            filename2 = os.path.join(self.logs_dir2, filename)
        elif not os.path.exists(filename) and self.logs_dir:
            filename2 = os.path.join(self.logs_dir, filename)
        else:
            filename2 = None

        if not filename2:
            return self.error("Failed to find file {}".format(filename))

        return filename2

    def get_log(self, filename=None):
        filename2 = self.get_log_path(filename)
        if not filename2:
            return None

        lines = read_lines(filename2, None)
        if lines is None:
            lines = [self.error("Failed to read log file {}".format(filename2))]

        for filename2 in self.addl_logs.get(filename, []):
            lines.append("=============== {} ============".format(filename2))
            lines = read_lines(filename2, None)
            if lines is None:
                lines.append(self.error("Failed to read log file {}".format(filename2)))

        return "\n".join(lines)

    def get_pcap(self, filename=None):
        filename2 = self.get_log_path(filename)
        if not filename2:
            return None

        if not filename2.endswith(".pcap"):
            filename2 = "{}.pcap".format(filename2)

        lines = read_lines(filename2, None)
        if lines is None:
            lines = [self.error("Failed to read pcap file {}".format(filename2))]

        return "\n".join(lines)

    def write_pcap(self, pkt, append=True, filename=None):
        filename = filename or self.get_log_path()
        if not filename:
            return False
        if not filename.endswith(".pcap"):
            filename = "{}.pcap".format(filename)
        # self.info("capture packet to {}".format(filename))
        from scapy.all import wrpcap
        wrpcap(filename, pkt, append=append)
        return True

    def mkfile(self, ftype, suffix, extn, backup=False):
        if suffix:
            ftype = "{}_{}".format(ftype, suffix)
        filename = "{}.{}".format(ftype, extn)
        retval = self.get_logs_path(filename)
        if backup:
            time_spec = datetime.datetime.utcnow().strftime("%Y_%m_%d_%H_%M_%S_%f")
            try:
                os.rename(retval, "{}.{}".format(retval, time_spec))
            except Exception:
                pass
        return retval

    def get_logs_path(self, filename=None):
        if not filename:
            return self.logs_dir2
        return os.path.join(self.logs_dir2, filename)

    def todo(self, etype, name, value):
        msg = "{}: {} = {}".format(etype, name, value)
        raise ValueError(self.error(msg))

    def _log(self, lvl, msg):
        if not msg.strip():
            return
        self.lock.acquire()
        for line in msg.split("\n"):
            self.logger.log(lvl, line)
        self.lock.release()
        return msg

    def log(self, *args, **kwargs):
        msg = " ".join(map(str, args))
        return self._log(logging.INFO, msg)

    def info(self, *args, **kwargs):
        msg = " ".join(map(str, args))
        return self._log(logging.INFO, msg)

    def warning(self, *args, **kwargs):
        msg = ["#" * 80, " ".join(map(str, args)), "#" * 80]
        return self._log(logging.WARNING, "\n".join(msg))

    def debug(self, *args, **kwargs):
        msg = " ".join(map(str, args))
        return self._log(logging.DEBUG, msg)

    def banner(self, *args, **kwargs):
        msg = ["#" * 80, " ".join(map(str, args)), "#" * 80]
        return self.info("\n".join(msg))

    def error(self, *args, **kwargs):
        msg = ""
        # msg = msg + "=================================== "
        msg = msg + " ".join(map(str, args))
        # msg = msg + "=================================== "
        return self._log(logging.ERROR, msg)

    def log_exception(self, e, msg):
        self.logger.error("=========== exception ==================")
        self.logger.error(msg)
        self.logger.error("=========== exception ==================")
        self.logger.error(msg, traceback.format_exc())
        self.lock.acquire()
        self.logger.exception(e)
        self.lock.release()

    def dump(self, msg, obj):
        ll = ["=========== {} ==================".format(msg)]
        ll.append(repr(obj))
        ll.append("=============================")
        self.logger.info("\n".join(ll))

    @staticmethod
    def setup():
        logging.basicConfig()
        logger = logging.getLogger()
        logger.setLevel(logging.DEBUG)

    def register_log(self, logfile):
        if not self.log_file or not logfile:
            return
        if self.log_file not in self.addl_logs:
            self.addl_logs[self.log_file] = []
        if logfile not in self.addl_logs[self.log_file]:
            self.addl_logs[self.log_file].append(logfile)
