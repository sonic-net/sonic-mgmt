
from spytest.st_time import get_timenow
from spytest.dicts import SpyTestDict
import spytest.logger as logger

class Profile(object):

    def __init__(self):
        self.pnfound = 0
        self.tg_total_wait = 0
        self.tc_total_wait = 0
        self.tg_total_wait = 0
        self.tc_cmd_time = 0
        self.tc_cmds = []
        self.tg_cmd_time = 0
        self.tg_cmds = []
        self.helper_cmd_time = 0
        self.helper_cmds = []
        self.cmds = []
        self.profile_ids = dict()
        self.canbe_parallel = []

    def init(self):
        self.__init__()

    def start(self, msg, dut=None, data=None):
        msg = msg.replace("\r", "")
        msg = msg.replace("\n", "\\n")
        count = len(self.profile_ids)
        self.profile_ids[count] = [get_timenow(), dut, msg, data]
        return count

    def stop(self, pid):
        [start_time, dut, msg, data] = self.profile_ids[pid]
        delta = get_timenow() - start_time
        cmd_time = int(delta.total_seconds() * 1000)
        thid = logger.get_thread_name()
        if dut:
            if pid > 0 and thid == "T0000: ":
                [_, pdut, pmsg, _] = self.profile_ids[pid-1]
                if pmsg == msg and dut != pdut:
                    self.canbe_parallel.append([start_time, msg, dut, pdut])
            if "spytest-helper.py" in msg:
                self.helper_cmds.append([start_time, thid, dut, msg, cmd_time])
                self.helper_cmd_time = self.helper_cmd_time + cmd_time
                self.cmds.append([start_time, thid, "HELPER", dut, msg, cmd_time])
            else:
                self.tc_cmds.append([start_time, thid, dut, msg, cmd_time])
                self.tc_cmd_time = self.tc_cmd_time + cmd_time
                self.cmds.append([start_time, thid, "CMD", dut, msg, cmd_time])
        else:
            self.tg_cmds.append([start_time, thid, dut, msg, cmd_time])
            self.tg_cmd_time = self.tg_cmd_time + cmd_time
            self.cmds.append([start_time, thid, "TG", dut, msg, cmd_time])
        return data

    def wait(self, val, is_tg=False):
        start_time = get_timenow()
        thid = logger.get_thread_name()
        if is_tg:
            self.tg_total_wait = self.tg_total_wait + val
            self.cmds.append([start_time, thid, "TGWAIT", None, "TG sleep", val])
        else:
            self.tc_total_wait = self.tc_total_wait + val
            self.cmds.append([start_time, thid, "WAIT", None, "static delay", val])

    def prompt_nfound(self, cmd):
        start_time = get_timenow()
        thid = logger.get_thread_name()
        self.pnfound = self.pnfound + 1
        self.cmds.append([start_time, thid, "PROMPT_NFOUND", None, cmd, ""])

    def get_stats(self):
        stats = SpyTestDict()
        stats.tg_total_wait = self.tg_total_wait
        stats.tc_total_wait = self.tc_total_wait
        stats.tc_cmd_time = self.tc_cmd_time
        stats.tc_cmds = self.tc_cmds
        stats.tg_cmd_time = self.tg_cmd_time
        stats.tg_cmds = self.tg_cmds
        stats.helper_cmd_time = self.helper_cmd_time
        stats.helper_cmds = self.helper_cmds
        stats.cmds = self.cmds
        stats.canbe_parallel = self.canbe_parallel
        stats.pnfound = self.pnfound
        return stats

obj = Profile()
def init():
    return obj.init()

def start(msg, dut=None, data=None):
    return obj.start(msg, dut, data)

def stop(pid):
    return obj.stop(pid)

def wait(val, is_tg=False):
    return obj.wait(val, is_tg)

def get_stats():
    return obj.get_stats()

def prompt_nfound(cmd):
    return obj.prompt_nfound(cmd)

