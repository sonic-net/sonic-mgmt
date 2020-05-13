
import os
import sys
import time
import logging
import warnings

root = os.path.abspath(os.path.join(os.path.dirname(__file__)))
sys.path.append(root)
sys.path.insert(0, os.path.join(root, "scapy-2.4.3"))
sys.path.insert(0, os.path.join(root, "Pyro4-4.77", "src"))
sys.path.insert(0, os.path.join(root, "Serpent-serpent-1.29"))

import Pyro4
from server import ScapyServer

from scapy.config import Conf
try: print("SCAPY VERSION = {}".format(Conf().version))
except: print("SCAPY VERSION = UNKNOWN")

warnings.filterwarnings("ignore", "BaseException.message")

logging.basicConfig()
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

#os.environ["PYRO_LOGFILE"] = "pyro.log"
#os.environ["PYRO_LOGLEVEL"] = "DEBUG"
logging.getLogger("Pyro4").setLevel(logging.DEBUG)
logging.getLogger("Pyro4.core").setLevel(logging.DEBUG)

@Pyro4.expose
@Pyro4.behavior(instance_mode="single")
class ScapyService(object):
    def __init__(self):
        self.server = ScapyServer(dry=False)

    def server_control(self, *args, **kws):
        return self.server.exposed_server_control(*args, **kws)
    def tg_connect(self, *args, **kws):
        return self.server.exposed_tg_connect(*args, **kws)
    def tg_disconnect(self, *args, **kws):
        return self.server.exposed_tg_disconnect(*args, **kws)
    def tg_traffic_control(self, *args, **kws):
        return self.server.exposed_tg_traffic_control(*args, **kws)
    def tg_interface_control(self, *args, **kws):
        return self.server.exposed_tg_interface_control(*args, **kws)
    def tg_packet_control(self, *args, **kws):
        return self.server.exposed_tg_packet_control(*args, **kws)
    def tg_packet_stats(self, *args, **kws):
        return self.server.exposed_tg_packet_stats(*args, **kws)
    def tg_traffic_config(self, *args, **kws):
        return self.server.exposed_tg_traffic_config(*args, **kws)
    def tg_interface_config(self, *args, **kws):
        return self.server.exposed_tg_interface_config(*args, **kws)
    def tg_traffic_stats(self, *args, **kws):
        return self.server.exposed_tg_traffic_stats(*args, **kws)
    def tg_emulation_bgp_config(self, *args, **kws):
        return self.server.exposed_tg_emulation_bgp_config(*args, **kws)
    def tg_emulation_bgp_route_config(self, *args, **kws):
        return self.server.exposed_tg_emulation_bgp_route_config(*args, **kws)
    def tg_emulation_bgp_control(self, *args, **kws):
        return self.server.exposed_tg_emulation_bgp_control(*args, **kws)
    def tg_emulation_igmp_config(self, *args, **kws):
        return self.server.exposed_tg_emulation_igmp_config(*args, **kws)
    def tg_emulation_multicast_group_config(self, *args, **kws):
        return self.server.exposed_tg_emulation_multicast_group_config(*args, **kws)
    def tg_emulation_multicast_source_config(self, *args, **kws):
        return self.server.exposed_tg_emulation_multicast_source_config(*args, **kws)
    def tg_emulation_igmp_group_config(self, *args, **kws):
        return self.server.exposed_tg_emulation_igmp_group_config(*args, **kws)
    def tg_emulation_igmp_control(self, *args, **kws):
        return self.server.exposed_tg_emulation_igmp_control(*args, **kws)

# install packages needed
install_packages = False
if install_packages:
    os.system("apt-get install -y iputils-arping")
    #os.system("pip install pybrctl")
    #os.system("pip install pyroute2")

def main():
    Pyro4.config.SERIALIZERS_ACCEPTED.add('pickle')
    Pyro4.config.SERIALIZERS_ACCEPTED.remove('serpent')
    os.environ["PYRO_DETAILED_TRACEBACK"] = "1"
    for i in range(10):
        try:
            custom_daemon = Pyro4.Daemon(port=8009, host="0.0.0.0")
            break
        except Exception as exp:
            print(exp)
            custom_daemon = None
            time.sleep(2)

    print("PYRO ScapyService started: {}".format(custom_daemon))
    Pyro4.Daemon.serveSimple(
        {
            ScapyService: "scapy-tgen"
        },
        ns=False, daemon = custom_daemon)

if __name__=="__main__":
    main()

