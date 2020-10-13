import os
import sys
import time
import random
import socket
import struct
import inspect

from tempfile import mkstemp
import subprocess

from logger import Logger

class Utils(object):
    def __init__(self, dry=False, logger=None):
        self.dry = dry
        self.logger = logger or Logger()

    def fread(self, fname, default=""):
        with open(fname, 'r') as myfile:
            return myfile.read()
        return default

    def fwrite(self, content, fname = ""):
        if fname == "" or self.dry:
            _, fname = mkstemp()
        else:
            directory = os.path.dirname(fname)
            if not os.path.exists(directory):
                os.makedirs(directory)
        with open(fname, "w") as fd:
            fd.write(content)
        return fname

    def cmdexec(self, cmd, msg=None):
        self.logger.debug("cmdexec: " + cmd)
        if self.dry: return "skipped-for-dry-run"
        p = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (out, err) = p.communicate()
        p.wait()
        return out or err

    def shexec(self, cmds):
        fname = self.fwrite(cmds)
        logfile = fname + ".1"
        self.logger.debug("shexec: " + cmds)
        if not self.dry:
            cmd = "sh %s > %s 2>&1" % (fname, logfile)
            os.system(cmd)
            output = self.fread(logfile)
            self.logger.debug(output)
            os.unlink(logfile)
        os.unlink(fname)

    def line_info(self):
        stk = inspect.stack()
        self.logger.debug(stk[1][1],":",stk[1][2],":", stk[1][3])

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
            for z in range(8 - (len(hextets) + len(h2))):
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
            return buffer(s)
        return s.encode()

    @staticmethod
    def get_env_int(name, default):
        try:
            return int(os.getenv(name, default))
        except:
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

