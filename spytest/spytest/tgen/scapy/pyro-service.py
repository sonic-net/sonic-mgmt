
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
        # If required, you *can* override this to do custom resource freeing.
        # But this is not needed if your resource objects have a proper 'close' method;
        # this method is called by Pyro itself once the client connection gets closed.
        # In this example this override is only used to print out some info.
        try:
            print("client disconnects:", conn.sock.getpeername())
            print("    resources: ", [r.name for r in conn.tracked_resources])
        except Exception:
            pass

@Pyro4.behavior(instance_mode="session", instance_creator=lambda clazz: clazz.create_instance())
class PyRoScapyService(ScapyService):
    @classmethod
    def create_instance(cls):
        obj = cls()
        print("Created {}".format(id(obj)))
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
            print(exp)
            custom_daemon = None
            time.sleep(2)

    if use_ns: startNameServer("0.0.0.0")

    print("PYRO ScapyService started: {}".format(custom_daemon))
    Pyro4.Daemon.serveSimple(
        {
            PyRoScapyService: "scapy-tgen"
        },
        ns=use_ns, daemon = custom_daemon, verbose=True)

if __name__=="__main__":
    main()

