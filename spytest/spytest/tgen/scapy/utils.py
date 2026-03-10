import os
import re
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
from dicts import SpyTestDict

try:
    from StringIO import StringIO  # for Python 2
except ImportError:
    from io import StringIO  # for Python 3

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

    @staticmethod
    def kwargs_get_strip(name, default, **kws):
        val = kws.get(name, default) or default
        return val.strip() if val else val

    @staticmethod
    def file_write(content, fname="", mode="w", tmp_files=None):
        if fname == "":
            tmp_dir = os.getenv("TMPDIR", "/tmp/scapy-tgen/tmp/")
            Utils.ensure_folder(tmp_dir)
            _, fname = mkstemp(prefix=tmp_dir)
            if tmp_files is not None:
                tmp_files.append(fname)
        else:
            Utils.ensure_parent(fname)
        with open(fname, mode) as fd:
            fd.write(content)
        return fname

    def fwrite(self, content, fname="", mode="w"):
        if self.dry:
            fname = ""
        return Utils.file_write(content, fname, mode, self.tmp_files)

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
        return Utils.decode(out or err)

    @staticmethod
    def decode(data):
        try:
            return data.decode("utf-8")
        except Exception:
            return data

    def cmdexec(self, cmd, dbg=True):
        if dbg:
            self.logger.debug("cmdexec: " + cmd)
        if self.dry:
            return "skipped-for-dry-run"
        return self.process_exec(cmd)

    def shexec(self, *args):
        cmds = "".join(args)
        fname = self.fwrite(cmds)
        logfile = fname + ".1"
        self.logger.debug("shexec: " + cmds)
        output = ""
        if not self.dry:
            cmd = "sh -x %s > %s 2>&1" % (fname, logfile)
            os.system(cmd)
            output = self.fread(logfile)
            self.logger.debug(output)
            os.unlink(logfile)
        os.unlink(fname)
        return output

    def lshexec(self, cmdlist):
        cmds = [cmd for cmd in cmdlist if cmd.strip()]
        return self.shexec("\n".join(cmds))

    def tshexec(self, cmdlist):
        threads = []
        for cmds in cmdlist:
            th = threading.Thread(target=self.shexec, args=(cmds))
            th.start()
            threads.append(th)
        for th in threads:
            th.join()

    def cat_file(self, filepath):
        content = self.fread(filepath).strip()
        if not content:
            return ""
        marker = "#######################"
        return "\n{0} {1}\n{0}\n".format(marker, content)

    def line_info(self):
        stk = inspect.stack()
        self.logger.debug(stk[1][1], ":", stk[1][2], ":", stk[1][3])

    @staticmethod
    def min_value(v1, v2):
        return v1 if v1 < v2 else v2

    @staticmethod
    def max_value(v1, v2):
        return v1 if v1 > v2 else v2

    @staticmethod
    def incrementMac(mac, step):
        step = step.replace(':', '').replace(".", '')
        mac = mac.replace(':', '').replace(".", '')
        nextMac = int(mac, 16) + int(step, 16)
        return ':'.join(("%012X" % nextMac)[i:i + 2] for i in range(0, 12, 2))

    @staticmethod
    def decrementMac(mac, step):
        step = step.replace(':', '').replace(".", '')
        mac = mac.replace(':', '').replace(".", '')
        nextMac = int(mac, 16) - int(step, 16)
        return ':'.join(("%012X" % nextMac)[i:i + 2] for i in range(0, 12, 2))

    @staticmethod
    def randomMac():
        return "02:00:00:%02x:%02x:%02x" % (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))

    @staticmethod
    def incrementIPv4(ip, step):
        def ip2int(ipstr):
            return struct.unpack("!I", socket.inet_aton(ipstr))[0]

        def int2ip(n):
            return socket.inet_ntoa(struct.pack("!I", n))
        return int2ip(ip2int(ip) + ip2int(step))

    @staticmethod
    def decrementIPv4(ip, step):
        def ip2int(ipstr):
            return struct.unpack("!I", socket.inet_aton(ipstr))[0]

        def int2ip(n):
            return socket.inet_ntoa(struct.pack("!I", n))
        return int2ip(ip2int(ip) - ip2int(step))

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
    def ipv4_long2ip(ll):
        return '%d.%d.%d.%d' % (ll >> 24 & 255, ll >> 16 & 255, ll >> 8 & 255, ll & 255)

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
            if h == '':
                h = '0'
            lngip = (lngip << 16) | int(h, 16)
        return lngip

    @staticmethod
    def ipv6_long2ip(ll):
        # format as one big hex value
        hex_str = '%032x' % ll
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
        return Utils.ipv6_long2ip(Utils.ipv6_ip2long(ip) + Utils.ipv6_ip2long(step))

    @staticmethod
    def decrementIPv6(ip, step):
        return Utils.ipv6_long2ip(Utils.ipv6_ip2long(ip) - Utils.ipv6_ip2long(step))

    @staticmethod
    def intval(d, prop, default):
        val = d.get(prop, "{}".format(default))
        return int(float(val))

    @staticmethod
    def tobytes(s):
        if isinstance(s, bytes):
            return s
        try:
            return s.encode()
        except Exception:
            return bytes(s)

    @staticmethod
    def get_env_int(name, default):
        try:
            return int(os.getenv(name, str(default)))
        except Exception:
            pass
        return default

    @staticmethod
    def clock():
        return time.time()

    @staticmethod
    def msleep(delay, block=1):
        unit_time = block / 1000.0
        end_time = time.time() + delay / 1000.0
        while True:
            time.sleep(unit_time)
            if end_time <= time.time():
                break

    @staticmethod
    def usleep(delay, block=1):
        unit_time = block / 1000000.0
        end_time = time.time() + delay / 1000000.0
        while True:
            time.sleep(unit_time)
            if end_time <= time.time():
                break

    @staticmethod
    def make_list(arg, uniq=False):
        rv = arg if isinstance(arg, list) else [arg]
        return Utils.make_uniq(rv) if uniq else rv

    @staticmethod
    def make_uniq(arg):
        if not isinstance(arg, list):
            raise ValueError("input should be list")
        rv = []
        for ent in arg:
            if ent not in rv:
                rv.append(ent)
        return rv

    def exec_func(self, msg, func, *args, **kwargs):
        this_stderr, this_stdout = StringIO(), StringIO()
        save_stderr, save_stdout = sys.stderr, sys.stdout
        sys.stderr, sys.stdout = this_stderr, this_stdout
        func(*args, **kwargs)
        sys.stderr, sys.stdout = save_stderr, save_stdout
        msgs = map(str.strip, [this_stdout.getvalue(), this_stderr.getvalue()])
        msgs = [s for s in msgs if s]
        if msg:
            msgs.insert(0, msg)
        return self.logger.debug("\n".join(msgs))

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

    def ns_debug(self, ns, msg):
        rv = "{}\n{}".format(msg, self.cmdexec("ip netns list"))
        raise ValueError(self.logger.error(rv))

    def nsexec(self, ns, cmd, abort=True):
        rv = self.cmdexec("ip netns exec ns_{} {}".format(ns, cmd))
        if abort and "Cannot open network namespace" in rv:
            self.ns_debug(ns, rv)
        return rv

    def get_ip_addr_dev(self, intf, ns=None):
        cmd = "ip addr show dev {}".format(intf)
        if ns:
            output = self.nsexec(ns, cmd).split()
        else:
            output = self.cmdexec(cmd).split()
        retval = {}
        for x in ['inet', 'inet6', 'state', 'link/ether', 'ether']:
            if x in output:
                idx = output.index(x)
                retval[x] = output[idx + 1]
        return retval, cmd, output

    @staticmethod
    def parse_mac(output):
        match = re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", output)
        if not match:
            return None
        return match.groups()[0]

    @staticmethod
    def unused(*args):
        pass

    @staticmethod
    def flatten_list(ll, rv=None, uniq=False):
        rv = rv or []
        for i in Utils.make_list(ll):
            if isinstance(i, list):
                rv.extend(Utils.flatten_list(i, rv))
            else:
                rv.append(i)
        return Utils.make_uniq(rv) if uniq else rv

    @staticmethod
    def clone(**kws):
        rv = SpyTestDict()
        for key, value in kws.items():
            rv[key] = value
        return rv

    @staticmethod
    def success(**kwargs):
        res = SpyTestDict()
        res.status = "1"
        for key, value in kwargs.items():
            res[key] = value
        return res

    @staticmethod
    def os_fork(pid_file):
        try:
            pid = os.fork()
            if pid > 0:
                os._exit(0)
            if pid_file:
                Utils.file_write(str(os.getpid()), pid_file)
        except OSError as exc:
            print("Error forking", exc)

    @staticmethod
    def redirect_logs(log_file):
        fd = os.open('/dev/null', os.O_RDWR)
        os.dup2(fd, sys.__stdin__.fileno())
        if log_file is not None:
            fake_stdout = open(log_file, 'a', 1)
            sys.stdout = fake_stdout
            sys.stderr = fake_stdout
            fd = fake_stdout.fileno()
        os.dup2(fd, sys.__stdout__.fileno())
        os.dup2(fd, sys.__stderr__.fileno())
        if log_file is None:
            os.close(fd)

    @staticmethod
    def deamonize(pid_file, log_file):
        Utils.os_fork(None)
        os.setsid()
        Utils.os_fork(pid_file)
        Utils.redirect_logs(log_file)

    @staticmethod
    def md5sum(value):
        from hashlib import md5
        # nosemgrep-next-line
        hasher = md5(value)
        return hasher.digest()

    @staticmethod
    def prefix_length_to_netmask(prefix_length):
        mask = (0xffffffff >> (32 - prefix_length)) << (32 - prefix_length)
        return (str((0xff000000 & mask) >> 24) + '.'
                + str((0x00ff0000 & mask) >> 16) + '.'
                + str((0x0000ff00 & mask) >> 8) + '.'
                + str((0x000000ff & mask)))


class RunTimeException(RuntimeError):
    def __init__(self, *args):
        lines = ["Run Time Exception:"]
        for arg in args:
            lines.append(str(arg))
        message = "\n".join(lines)
        super(RunTimeException, self).__init__(message)
