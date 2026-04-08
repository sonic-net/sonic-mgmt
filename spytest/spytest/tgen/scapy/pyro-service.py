
import os
import sys
import time
import logging
import random
import socket
import fcntl
import struct
import threading

try:
    from Pyro5.compatibility import Pyro4
    from Pyro5.nameserver import start_ns as startNS
except Exception:
    import Pyro4
    from Pyro4.naming import startNS

from service import ScapyService

use_ns = False
default_port = 8009
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(name)s:%(levelname)s: %(message)s')
logger = logging.getLogger()

# os.environ["PYRO_LOGFILE"] = "pyro.log"
# os.environ["PYRO_LOGLEVEL"] = "DEBUG"
logging.getLogger("Pyro4").setLevel(logging.DEBUG)
logging.getLogger("Pyro4.core").setLevel(logging.DEBUG)

Pyro4.config.SERIALIZERS_ACCEPTED = set(["pickle", "serpent"])
Pyro4.config.SERIALIZER = 'pickle'
Pyro4.config.ONEWAY_THREADED = False

for key, value in Pyro4.config.asDict().items():
    logger.info("%s = %s", key, value)


def get_ip_address(ifname, default="0.0.0.0", nolog=False):
    try:
        ifname = ifname.encode('utf-8')
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(), 0x8915,  # SIOCGIFADDR
            struct.pack('256s', ifname[:15])
        )[20:24])
    except Exception as exp:
        if not nolog:
            logger.exception(exp)
        return default


def web_server(port=80):

    if sys.version_info[0] >= 3:
        import http.server as SimpleHTTPServer
        import http.server as BaseHTTPServer
        import socketserver as SocketServer
    else:
        import SimpleHTTPServer
        import BaseHTTPServer
        import SocketServer

    class ThreadingSimpleServer(SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer):
        pass

    class ServerHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
        def guess_type(self, path):
            for extn in [".log", ".tgen", ".cmd", ".env", ".cfg"]:
                if path.endswith(extn):
                    return 'text/plain'
            return SimpleHTTPServer.SimpleHTTPRequestHandler.guess_type(self, path)

    os.chdir("/")
    server = ThreadingSimpleServer(('', port), ServerHandler)
    thread = threading.Thread(target=server.serve_forever)
    thread.setDaemon(True)
    thread.start()


class NameServer(threading.Thread):
    def __init__(self, hostname, hmac=None):
        super(NameServer, self).__init__()
        self.setDaemon(1)
        self.hostname = hostname
        self.hmac = hmac
        self.started = threading.Event()

    def run(self):
        try:
            self.uri, self.ns_daemon, self.bc_server = \
                startNS(self.hostname, hmac=self.hmac)
        except Exception:
            self.uri, self.ns_daemon, self.bc_server = \
                startNS(self.hostname)

        self.started.set()
        if self.bc_server:
            self.bc_server.runInThread()
        self.ns_daemon.requestLoop()


def startNameServer(host, hmac=None):
    ns = NameServer(host, hmac=hmac)
    ns.start()
    ns.started.wait()
    return ns


def next_free_port(min_port=5000, max_port=6000, used=[]):
    # nosemgrep-next-line
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    while True:
        if len(used) >= (max_port - min_port):
            break
        port = random.randint(min_port, max_port)
        if port in used:
            continue
        used.append(port)
        try:
            sock.bind(('', port))
            sock.close()
            return port
        except OSError:
            pass
    raise IOError('no free ports')


class CustomDaemon(Pyro4.Daemon):

    def __init__(self, host=None, port=0):
        super(CustomDaemon, self).__init__(host=host, port=port)

    def clientDisconnect(self, conn):
        try:
            logger.info("client disconnects: %s", conn.sock.getpeername())
            logger.info("Remove Connection %s", id(conn))
            obj = conn.pyroInstances.get(PyRoScapyService)
            logger.info("Remove Instance %s", id(obj))
            del obj
        except Exception as exp:
            logger.exception(exp)


@Pyro4.behavior(instance_mode="session", instance_creator=lambda clazz: clazz.create_instance())
class PyRoScapyService(ScapyService):
    @classmethod
    def create_instance(cls):
        obj = cls()
        logger.info("Created %s", id(obj))
        obj.correlation_id = Pyro4.current_context.correlation_id
        return obj


def main():
    pyver = "{}.{}.{}".format(sys.version_info.major, sys.version_info.minor,
                              sys.version_info.micro)
    try:
        use_port = int(os.getenv("SPYTEST_SCAPY_INST_PORT", str(default_port)))
    except Exception:
        use_port = default_port
    logger.info("Python: %s", pyver)
    logger.info("NS = %s PORT = %d", str(use_ns), use_port)
    os.environ["PYRO_DETAILED_TRACEBACK"] = "1"
    for _ in range(10):
        try:
            port = use_port or next_free_port()
            host = get_ip_address('mgmt', None, True)
            if not host:
                host = get_ip_address('eth0', None, True)
            if host:
                logger.info("Creating Deamon %s:%d", str(host), port)
                custom_daemon = CustomDaemon(host=host, port=port)
            else:
                logger.info("Creating Deamon %d", port)
                custom_daemon = CustomDaemon(port=port)
            break
        except Exception as exp:
            logger.exception(exp)
            custom_daemon = None
            time.sleep(2)

    if use_ns:
        startNameServer("0.0.0.0")

    web_server()

    logger.info("PYRO ScapyService started: %s", custom_daemon)
    Pyro4.Daemon.serveSimple(
        {
            PyRoScapyService: "scapy-tgen"
        },
        ns=use_ns, daemon=custom_daemon, verbose=True)


if __name__ == "__main__":
    main()
