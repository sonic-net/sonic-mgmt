import os
import sys
import time
import glob
import random
import socket
import struct
import inspect
import fnmatch
import threading

from collections import deque
from itertools import islice
from tempfile import mkstemp
import subprocess

try:
    from StringIO import StringIO ## for Python 2
except ImportError:
    from io import StringIO ## for Python 3

from logger import Logger

class Utils(object):
    def __init__(self, dry=False, logger=None):
        self.dry = dry
        self.logger = logger or Logger()
        self.tmp_files = []

    def __del__(self):
        for fname in self.tmp_files:
            self.fdel(fname)
        self.tmp_files = []

    def fdel(self, fname):
        if os.path.exists(fname):
            os.remove(fname)
            return True
        return False

    def fread(self, fname, default=""):
        try:
            with open(fname, 'r') as fd:
                return fd.read()
        except Exception:
            pass
        return default

    def fwrite(self, content, fname = "", mode="w"):
        if fname == "" or self.dry:
            tmp_dir = os.getenv("TMPDIR", "/tmp/scapy-tgen/tmp/")
            Utils.ensure_folder(tmp_dir)
            _, fname = mkstemp(prefix=tmp_dir)
            self.tmp_files.append(fname)
        else:
            Utils.ensure_parent(fname)
        with open(fname, mode) as fd:
            fd.write(content)
        return fname

    def fhead(self, fname, count, default=""):
        try:
            lines = []
            with open(fname, 'r') as fd:
                for line in islice(fd, count):
                    lines.append(line)
            return "".join(lines).strip()
        except Exception:
            pass
        return default

    def ftail(self, fname, count, default=""):
        try:
            lines = []
            with open(fname, 'r') as fd:
                for line in deque(fd, maxlen=count):
                    lines.append(line)
            return "".join(lines).strip()
        except Exception:
            pass
        return default

    def wc_l(self, fname):
        try:
            return sum(1 for i in open(fname, 'rb'))
        except Exception:
            return -1

    @staticmethod
    def process_exec(cmd):
        p = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (out, err) = p.communicate()
        p.wait()
        return out or err

    def cmdexec(self, cmd, msg=None, dbg=True):
        if dbg:
            self.logger.debug("cmdexec: " + cmd)
        if self.dry: return "skipped-for-dry-run"
        return self.process_exec(cmd)

    def shexec(self, *args):
        cmds = "".join(args)
        fname = self.fwrite(cmds)
        logfile = fname + ".1"
        self.logger.debug("shexec: " + cmds)
        if not self.dry:
            cmd = "sh -x %s > %s 2>&1" % (fname, logfile)
            os.system(cmd)
            output = self.fread(logfile)
            self.logger.debug(output)
            os.unlink(logfile)
        os.unlink(fname)

    def lshexec(self, cmdlist):
        cmds = [cmd for cmd in cmdlist if cmd.strip()]
        self.shexec("\n".join(cmds))

    def tshexec(self, cmdlist):
        threads = []
        for cmds in cmdlist:
            th = threading.Thread(target=self.shexec, args=(cmds))
            th.start()
            threads.append(th)
        for th in threads:
            th.join()

    def cat_file(self, filepath):
        marker = "#######################"
        content = self.fread(filepath).strip()
        return "\n{0} {1}\n{0}\n".format(marker, content)

    def line_info(self):
        stk = inspect.stack()
        self.logger.debug(stk[1][1],":",stk[1][2],":", stk[1][3])

    @staticmethod
    def min_value(v1, v2):
        return v1 if v1 < v2 else v2

    @staticmethod
    def incrementMac(mac, step):
        step = step.replace(':', '').replace(".",'')
        mac = mac.replace(':', '').replace(".",'')
        nextMac = int(mac, 16) + int(step, 16)
        return  ':'.join(("%012X" % nextMac)[i:i+2] for i in range(0, 12, 2))

    @staticmethod
    def decrementMac(mac, step):
        step = step.replace(':', '').replace(".",'')
        mac = mac.replace(':', '').replace(".",'')
        nextMac = int(mac, 16) - int(step, 16)
        return  ':'.join(("%012X" % nextMac)[i:i+2] for i in range(0, 12, 2))

    @staticmethod
    def randomMac():
        return "02:00:00:%02x:%02x:%02x" % (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))

    @staticmethod
    def incrementIPv4(ip, step):
        ip2int = lambda ipstr: struct.unpack('!I', socket.inet_aton(ipstr))[0]
        int2ip = lambda n: socket.inet_ntoa(struct.pack('!I', n))
        return int2ip(ip2int(ip)+ip2int(step))

    @staticmethod
    def decrementIPv4(ip, step):
        ip2int = lambda ipstr: struct.unpack('!I', socket.inet_aton(ipstr))[0]
        int2ip = lambda n: socket.inet_ntoa(struct.pack('!I', n))
        return int2ip(ip2int(ip)-ip2int(step))

    @staticmethod
    def randomIpv4():
        return ".".join(map(str, (random.randint(0, 255) for _ in range(4))))

    @staticmethod
    def valid_ip6(address):
        VALID_CHARACTERS = 'ABCDEFabcdef:0123456789'
        address_list = address.split(':')
        return (
            len(address_list) == 8
            and all(len(current) <= 4 for current in address_list)
            and all(current in VALID_CHARACTERS for current in address)
        )

    @staticmethod
    def ipv4_ip2long(ip):
        quads = ip.split('.')
        if len(quads) == 1:
            # only a network quad
            quads = quads + [0, 0, 0]
        elif len(quads) < 4:
            # partial form, last supplied quad is host address, rest is network
            host = quads[-1:]
            quads = quads[:-1] + [0, ] * (4 - len(quads)) + host

        lngip = 0
        for q in quads:
            lngip = (lngip << 8) | int(q)
        return lngip

    @staticmethod
    def ipv4_long2ip(l):
        return '%d.%d.%d.%d' % (l >> 24 & 255, l >> 16 & 255, l >> 8 & 255, l & 255)

    @staticmethod
    def ipv6_ip2long(ip):
        if '.' in ip:
          # convert IPv4 suffix to hex
          chunks = ip.split(':')
          v4_int = Utils.ipv4_ip2long(chunks.pop())
          if v4_int is None:
                return None
          chunks.append('%x' % ((v4_int >> 16) & 0xffff))
          chunks.append('%x' % (v4_int & 0xffff))
          ip = ':'.join(chunks)

        halves = ip.split('::')
        hextets = halves[0].split(':')
        if len(halves) == 2:
            h2 = halves[1].split(':')
            for _ in range(8 - (len(hextets) + len(h2))):
                hextets.append('0')
            for h in h2:
                hextets.append(h)
          # end if

        lngip = 0
        for h in hextets:
            if h == '': h = '0'
            lngip = (lngip << 16) | int(h, 16)
        return lngip

    @staticmethod
    def ipv6_long2ip(l):
        # format as one big hex value
        hex_str = '%032x' % l
        # split into double octet chunks without padding zeros
        hextets = ['%x' % int(hex_str[x:x + 4], 16) for x in range(0, 32, 4)]

        # find and remove left most longest run of zeros
        dc_start, dc_len = (-1, 0)
        run_start, run_len = (-1, 0)
        for idx, hextet in enumerate(hextets):
            if hextet == '0':
                run_len += 1
                if run_start == -1:
                    run_start = idx
                if run_len > dc_len:
                    dc_len, dc_start = (run_len, run_start)
            else:
                run_len, run_start = (0, -1)
          # end for
        if dc_len > 1:
            dc_end = dc_start + dc_len
            if dc_end == len(hextets):
                hextets += ['']
            hextets[dc_start:dc_end] = ['']
            if dc_start == 0:
                hextets = [''] + hextets
        # end if

        return ':'.join(hextets)

    @staticmethod
    def incrementIPv6(ip, step):
        return Utils.ipv6_long2ip(Utils.ipv6_ip2long(ip)+Utils.ipv6_ip2long(step))

    @staticmethod
    def decrementIPv6(ip, step):
        return Utils.ipv6_long2ip(Utils.ipv6_ip2long(ip)-Utils.ipv6_ip2long(step))

    @staticmethod
    def intval(d, prop, default):
        val = d.get(prop, "{}".format(default))
        return int(val)

    @staticmethod
    def tobytes(s):
        if sys.version_info[0] < 3:
            return buffer(s) # pylint: disable=undefined-variable
        return s.encode()

    @staticmethod
    def get_env_int(name, default):
        try:
            return int(os.getenv(name, default))
        except Exception:
            pass
        return default

    @staticmethod
    def msleep(delay, block=1):
        mdelay = delay /1000.0
        now = time.time()
        while now + mdelay > time.time():
            time.sleep(block/1000.0)

    @staticmethod
    def usleep(delay, block=1):
        mdelay = delay /1000000.0
        now = time.time()
        while now + mdelay > time.time():
            time.sleep(block/1000000.0)

    @staticmethod
    def make_list(arg):
        if isinstance(arg, list):
            return arg
        return [arg]

    def exec_func(self, func, *args, **kwargs):
        this_stderr, this_stdout = StringIO(), StringIO()
        save_stderr, save_stdout = sys.stderr, sys.stdout
        sys.stderr, sys.stdout = this_stderr, this_stdout
        func(*args, **kwargs)
        sys.stderr, sys.stdout = save_stderr, save_stdout
        msgs = map(str.strip, [this_stdout.getvalue(), this_stderr.getvalue()])
        return self.logger.debug("\n".join([s for s in msgs if s]))

    def exec_cmd(self, cmd):
        ret = self.cmdexec(cmd, dbg=False)
        ret = "\n".join([s for s in ret.split("\n") if s])
        return self.logger.debug(ret)

    @staticmethod
    def list_files_tree(dir_path, pattern="*"):
        matches = []
        for root, _, filenames in os.walk(dir_path):
            for filename in fnmatch.filter(filenames, pattern):
                matches.append(os.path.join(root, filename))
        return matches

    @staticmethod
    def list_files(entry, pattern="*"):
        if os.path.isdir(entry):
            return Utils.list_files_tree(entry, pattern)
        if os.path.isfile(entry):
            return [entry]
        return glob.glob(entry)

    @staticmethod
    def ensure_folder(path):
        path = os.path.abspath(path)
        if not os.path.exists(path):
            os.makedirs(path)

    @staticmethod
    def ensure_parent(filename):
        path = os.path.dirname(filename)
        Utils.ensure_folder(path)

    @staticmethod
    def get_ip_addr_dev(intf, ns=None):
        cmd = "ip addr show dev {}".format(intf)
        if ns: cmd = "ip netns exec {} {}".format(ns, cmd)
        output = Utils.process_exec(cmd).split()
        retval = {}
        for x in ['inet', 'inet6', 'state', 'link/ether', 'ether']:
            if x in output:
                idx = output.index(x)
                retval[x] = output[idx+1]
        print(cmd, output, retval)
        return retval


