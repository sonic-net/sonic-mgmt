
class Emulation(object):

    def __init__(self, pif, name):
        self.name = name
        self.pif = pif
        self.logger = pif.logger
        self.utils = pif.utils
        self.nslist = []
        self.cleanup()

    def __del__(self):
        self.cleanup()

    def cleanup(self):
        self.stop()

    def _file(self, ns, extn, backup=False):
        return self.logger.mkfile(self.name, ns, extn, backup)

    def stop(self):
        if self.pif.dbg > 3:
            self.pif.os_system("ps -ef")
        for ns in self.nslist[:]:
            self.stop_one(ns)
        root = self.logger.get_logs_path()
        for pidfile in self.utils.list_files(root, "{}_*.pid".format(self.name)):
            self.pif.kill_by_pidfile(pidfile)

    def stop_one(self, ns):
        logfile = self._file(ns, "log")
        pidfile = self._file(ns, "pid")
        self.pif.log_large_file(logfile)
        self.logger.info(self.utils.cat_file(pidfile))
        self.pif.kill_by_pidfile(pidfile, ns)
        if ns in self.nslist:
            self.nslist.remove(ns)
        return True
