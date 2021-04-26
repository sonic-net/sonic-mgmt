import os
import Pyro4
#import threading
from datetime import datetime

from server import ScapyServer

@Pyro4.expose
class ScapyService(object):
    def __init__(self):
        print("scapy-service-start")
        dry = bool(os.getenv("SPYTEST_SCAPY_DRYRUN", "0") == "1")
        #name = threading.current_thread().name
        time_spec = datetime.utcnow().strftime("%Y_%m_%d_%H_%M_%S_%f")
        name = "inst-{}".format(time_spec)
        self.server = ScapyServer(dry=dry, name=name)
        self.server.trace_api("scapy-service-started")

    def __del__(self):
        self.server.trace_api("scapy-service-finish")
        del self.server
        self.server = None

    def server_control(self, *args, **kws):
        self.server.trace_api(*args, **kws)
        return self.server.exposed_server_control(*args, **kws)
    def tg_connect(self, *args, **kws):
        self.server.trace_api(*args, **kws)
        return self.server.exposed_tg_connect(*args, **kws)
    def tg_disconnect(self, *args, **kws):
        self.server.trace_api(*args, **kws)
        return self.server.exposed_tg_disconnect(*args, **kws)
    def tg_traffic_control(self, *args, **kws):
        self.server.trace_api(*args, **kws)
        return self.server.exposed_tg_traffic_control(*args, **kws)
    def tg_interface_control(self, *args, **kws):
        self.server.trace_api(*args, **kws)
        return self.server.exposed_tg_interface_control(*args, **kws)
    def tg_packet_control(self, *args, **kws):
        self.server.trace_api(*args, **kws)
        return self.server.exposed_tg_packet_control(*args, **kws)
    def tg_packet_stats(self, *args, **kws):
        self.server.trace_api(*args, **kws)
        return self.server.exposed_tg_packet_stats(*args, **kws)
    def tg_traffic_config(self, *args, **kws):
        self.server.trace_api(*args, **kws)
        return self.server.exposed_tg_traffic_config(*args, **kws)
    def tg_interface_config(self, *args, **kws):
        self.server.trace_api(*args, **kws)
        return self.server.exposed_tg_interface_config(*args, **kws)
    def tg_traffic_stats(self, *args, **kws):
        self.server.trace_api(*args, **kws)
        return self.server.exposed_tg_traffic_stats(*args, **kws)
    def tg_emulation_bgp_config(self, *args, **kws):
        self.server.trace_api(*args, **kws)
        return self.server.exposed_tg_emulation_bgp_config(*args, **kws)
    def tg_emulation_bgp_route_config(self, *args, **kws):
        self.server.trace_api(*args, **kws)
        return self.server.exposed_tg_emulation_bgp_route_config(*args, **kws)
    def tg_emulation_bgp_control(self, *args, **kws):
        self.server.trace_api(*args, **kws)
        return self.server.exposed_tg_emulation_bgp_control(*args, **kws)
    def tg_emulation_igmp_config(self, *args, **kws):
        self.server.trace_api(*args, **kws)
        return self.server.exposed_tg_emulation_igmp_config(*args, **kws)
    def tg_emulation_multicast_group_config(self, *args, **kws):
        self.server.trace_api(*args, **kws)
        return self.server.exposed_tg_emulation_multicast_group_config(*args, **kws)
    def tg_emulation_multicast_source_config(self, *args, **kws):
        self.server.trace_api(*args, **kws)
        return self.server.exposed_tg_emulation_multicast_source_config(*args, **kws)
    def tg_emulation_igmp_group_config(self, *args, **kws):
        self.server.trace_api(*args, **kws)
        return self.server.exposed_tg_emulation_igmp_group_config(*args, **kws)
    def tg_emulation_igmp_control(self, *args, **kws):
        self.server.trace_api(*args, **kws)
        return self.server.exposed_tg_emulation_igmp_control(*args, **kws)

