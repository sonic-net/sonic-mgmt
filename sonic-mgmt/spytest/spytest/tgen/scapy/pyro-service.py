
import os
import time
import logging
import threading

import Pyro4
from Pyro4 import naming
from service import ScapyService

Pyro4.config.SERIALIZERS_ACCEPTED = set(["pickle"])
Pyro4.config.SERIALIZER = 'pickle'

logging.basicConfig()
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

#os.environ["PYRO_LOGFILE"] = "pyro.log"
#os.environ["PYRO_LOGLEVEL"] = "DEBUG"
logging.getLogger("Pyro4").setLevel(logging.DEBUG)
logging.getLogger("Pyro4.core").setLevel(logging.DEBUG)

import socket
import fcntl
import struct

def get_ip_address(ifname, default="0.0.0.0"):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(), 0x8915,  # SIOCGIFADDR
            struct.pack('256s', ifname[:15])
        )[20:24])
    except Exception:
        return default

class NameServer(threading.Thread):
    def __init__(self, hostname, hmac=None):
        super(NameServer, self).__init__()
        self.setDaemon(1)
        self.hostname = hostname
        self.hmac = hmac
        self.started = threading.Event()

    def run(self):
        self.uri, self.ns_daemon, self.bc_server = \
             naming.startNS(self.hostname, hmac=self.hmac)
        self.started.set()
        if self.bc_server:
            self.bc_server.runInThread()
        self.ns_daemon.requestLoop()


def startNameServer(host, hmac=None):
    ns = NameServer(host, hmac=hmac)
    ns.start()
    ns.started.wait()
    return ns

class CustomDaemon(Pyro4.Daemon):
    def clientDisconnect(self, conn):
        try:
            logger.info("client disconnects: %s", conn.sock.getpeername())
            logger.info("Remove Connection %s", id(conn))
            obj = conn.pyroInstances.get(PyRoScapyService)
            logger.info("Remove Instance %s", id(obj))
            del obj
        except Exception:
            pass

@Pyro4.behavior(instance_mode="session", instance_creator=lambda clazz: clazz.create_instance())
class PyRoScapyService(ScapyService):
    @classmethod
    def create_instance(cls):
        obj = cls()
        logger.info("Created %s", id(obj))
        obj.correlation_id = Pyro4.current_context.correlation_id
        return obj

def main():
    use_ns = True
    os.environ["PYRO_DETAILED_TRACEBACK"] = "1"
    for _ in range(10):
        try:
            #custom_daemon = CustomDaemon(port=8009, host="0.0.0.0")
            host = get_ip_address('mgmt', None)
            if host:
                custom_daemon = CustomDaemon(host=host)
            else:
                custom_daemon = CustomDaemon()
            break
        except Exception as exp:
            logger.info(exp)
            custom_daemon = None
            time.sleep(2)

    if use_ns: startNameServer("0.0.0.0")

    logger.info("PYRO ScapyService started: %s", custom_daemon)
    Pyro4.Daemon.serveSimple(
        {
            PyRoScapyService: "scapy-tgen"
        },
        ns=use_ns, daemon = custom_daemon, verbose=True)

if __name__=="__main__":
    main()

