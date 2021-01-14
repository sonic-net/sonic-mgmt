import sys
import csv

class Replay(object):

    def __init__(self, filepath):
        self.filepath = filepath
        self.modules = {}
        self.rows = []
        self.load()

    def load(self):
        self.rows = []
        with open(self.filepath, 'r') as fd:
            for row in csv.reader(fd):
                self.rows.append(row)
            fd.close()
        return self.rows

    def exclude(self, cmd):
        if cmd.startswith("show "): return True
        if cmd.startswith("sudo show "): return True
        if cmd.startswith("do show "): return True
        if cmd.startswith("do sudo show "): return True
        if cmd.startswith("/sbin/ifconfig "): return True
        if cmd.startswith("sudo ping "): return True
        return False

    def process(self):
        for row in self.rows:
            phase, module, _, dut, mode, cmd = [str(i).strip() for i in row[:6]]
            if phase != "test": continue
            cmd = "{} {}".format(cmd, " ".join(row[6:])).strip()
            if self.exclude(cmd): continue
            if module not in self.modules: self.modules[module] = []
            self.modules[module].append([dut, mode, cmd])
            print(mode, dut, cmd)

if __name__ == "__main__":
    infile = sys.argv[1] if len(sys.argv) > 1 else "results_all.cli"
    r = Replay(infile)
    r.process()

