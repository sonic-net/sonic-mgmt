import copy

from dicts import SpyTestDict
from driver import ScapyDriver
from logger import Logger
from utils import Utils

def initStatistics(stats):
    stats.clear()
    stats["framesSent"] = 0
    stats["bytesSent"] = 0
    stats["framesReceived"] = 0
    stats["bytesReceived"] = 0
    stats["oversizeFramesReceived"] = 0
    stats["userDefinedStat1"] = 0
    stats["userDefinedStat2"] = 0
    stats["captureFilter"] = 0

def incrStat(stats, name, val = 1):
    if name in stats:
        val = val + stats[name]
    stats[name] = val
    return val

class ScapyStream(object):
    def __init__(self, port, stream_id, track_port, *args, **kws):
        self.port = port
        self.track_port = track_port
        self.stream_id = stream_id
        self.args = args
        self.kws = copy.copy(kws)
        self.enable = True
        self.enable2 = False
        self.stats = SpyTestDict()
        initStatistics(self.stats)
        #print("ScapyStream: {} {} {}".format(self.port, self.stream_id, kws))
        if track_port:
            track_port.track_streams.append(self)
        self.track_pkts = []

    def __del__(self):
        print("ScapyStream {} exiting...".format(self.stream_id))
        if self.track_port:
            self.track_port.track_streams.remove(self)

    def incrStat(self, name, val = 1):
        val = incrStat(self.stats, name, val)
        #print("incrStat: {} {} {} = {}".format(self.port, self.stream_id, name, val))
        return val

    def __str__(self):
        return ''.join([('%s=%s' % x) for x in self.kws.items()])

class ScapyInterface(object):
    def __init__(self, port, index, *args, **kws):
        self.port = port.name
        self.iface = port.iface
        self.index = index
        self.args = args
        self.kws = copy.copy(kws)
        self.enable = True
        self.name = "{}_{}".format(self.port, self.index)
        self.name = self.name.replace("/", "_")
        self.igmp_hosts = SpyTestDict()

    def add_igmp_host(self, *args, **kws):
        index = len(self.igmp_hosts)
        host_handle = "igmp-{}-{}-{}".format(self.port, self.index, index)
        host = SpyTestDict()
        host.host_handle = host_handle
        host.update(kws)
        self.igmp_hosts[host_handle] = host
        return host_handle

class ScapyPort(object):
    def __init__(self, name, iface, dry=False, dbg=0, logger=None):
        self.name = name
        self.port_handle = "port-{}".format(name)
        self.iface = iface
        self.dry = dry
        self.dbg = dbg
        self.logger = logger or Logger()
        self.utils = Utils(self.dry, logger=self.logger)
        self.streams = SpyTestDict()
        self.track_streams = []
        self.interfaces = SpyTestDict()
        self.stats = SpyTestDict()
        initStatistics(self.stats)
        self.driver = ScapyDriver(self, self.dry, self.dbg, self.logger)
        self.admin_status = True

    def __del__(self):
        self.logger.debug("ScapyPort {} exiting...".format(self.name))
        self.cleanup()
        del self.driver

    def clean_interfaces(self):
        for handle in self.interfaces.keys():
            self.driver.deleteInterface(self.interfaces[handle])
            del self.interfaces[handle]

    def clean_streams(self):
        self.driver.stopTransmit()
        self.streams.clear()
        for stream in self.track_streams:
            stream.track_port = None
            stream.track_pkts = []
        self.track_streams = []

    def cleanup(self):
        self.logger.debug("ScapyPort {} cleanup...".format(self.name))
        self.clean_interfaces()
        self.driver.cleanup()
        self.clean_streams()

    def set_admin_status(self, val):
        self.admin_status = val

    def get_admin_status(self):
        return self.admin_status

    def incrStat(self, name, val = 1):
        return incrStat(self.stats, name, val)

    def getStats(self):
        return self.stats

    def getStreamStats(self):
        res = []
        for stream_id, stream in self.streams.items():
            res.append([stream, stream.stats])
        return res

    def traffic_control(self, *args, **kws):
        action = kws.get('action', None)
        if action == "run":
            for intf in self.interfaces.values():
                arp_send_req = kws.get('arp_send_req', "0")
                if arp_send_req == "1":
                    self.driver.send_arp(intf, intf.index)
            self.driver.startTransmit(**kws)
        elif action == "stop":
            self.driver.stopTransmit(**kws)
        elif action == "reset":
            self.clean_streams()
        elif action == "clear_stats":
            initStatistics(self.stats)
            for stream in self.streams.values():
                initStatistics(stream.stats)
            self.driver.clear_stats()
        else:
            self.error("unsupported", "traffic_control: action", action)
        return True

    def packet_control(self, *args, **kws):
        action = kws.get('action', None)
        if action == "start":
            self.driver.startCapture()
        elif action == "stop":
            return self.driver.stopCapture()
        elif action == "reset":
            return self.driver.clearCapture()
        else:
            self.error("unsupported", "packet_control: action", action)
        return True

    def packet_stats(self, *args, **kws):
        return self.driver.getCapture()

    def stream_validate(self, handle):
        return bool(handle in self.streams)

    def stream_encode(self, index):
        return "stream-{}-{}".format(self.name, index)

    def traffic_config(self, track_port, *args, **kws):
        res = SpyTestDict()
        mode = kws.get('mode', None)
        if mode == "create":
            index = len(self.streams)
            res.stream_id = self.stream_encode(index)
            stream = ScapyStream(self.name, res.stream_id, track_port, *args, **kws)
            self.streams[res.stream_id] = stream
        elif mode == "remove":
            stream_id = kws.get('stream_id', None)
            if stream_id not in self.streams:
                self.error("invalid", "stream_id", stream_id)
            self.driver.stopTransmit(handle = stream_id)
        elif mode == "enable":
            stream_id = kws.get('stream_id', None)
            if stream_id not in self.streams:
                self.error("invalid", "stream_id", stream_id)
            self.streams[stream_id].enable = True
        elif mode == "disable":
            stream_id = kws.get('stream_id', None)
            if stream_id not in self.streams:
                self.error("invalid", "stream_id", stream_id)
            self.streams[stream_id].enable = False
        elif mode == "modify":
            stream_id = kws.get('stream_id', None)
            if stream_id not in self.streams:
                self.error("invalid", "stream_id", stream_id)
            self.streams[stream_id].kws.update(kws)
        else:
            self.error("unsupported", "traffic_config: mode", mode)
        return res

    def find_interface(self, handle):
        if handle in self.interfaces:
            return self.interfaces[handle]
        return None

    def igmp_host_validate(self, handle):
        for intf in self.interfaces.values():
            if handle in intf.igmp_hosts:
                return True
        return False

    def interface_validate(self, handle):
        return bool(handle in self.interfaces)

    def interface_encode(self, index):
        return "iface-{}-{}".format(self.name, index)

    def interface_config(self, *args, **kws):
        res = SpyTestDict()
        res.status = "1"
        mode = kws.get('mode', None)
        send_ping = kws.get('send_ping', None)
        ping_dst = kws.get('ping_dst', None)
        arp_send_req = kws.get('arp_send_req', None)
        count = self.utils.intval(kws, "count", 1)
        if mode == "config":
            index = len(self.interfaces)
            handle = self.interface_encode(index)
            interface = ScapyInterface(self, index, *args, **kws)
            self.interfaces[handle] = interface
            self.driver.createInterface(interface)
            if count > 1:
                res.handle = [handle for i in range(count)]
            else:
                res.handle = handle
        elif mode == "destroy":
            handle = kws.get('handle', None)
            if isinstance(handle, list):
                handle = handle[0]
            if not self.interface_validate(handle):
                self.error("invalid", "handle", handle)
            self.driver.deleteInterface(self.interfaces[handle])
            del self.interfaces[handle]
        elif mode == None and send_ping and ping_dst:
            handle = kws.get('protocol_handle', None)
            if isinstance(handle, list):
                handle = handle[0]
            if not self.interface_validate(handle):
                self.error("invalid", "protocol_handle", handle)
            index = self.interfaces[handle].index
            rv = self.driver.ping(self.interfaces[handle], ping_dst, index)
            res[self.port_handle] = SpyTestDict()
            res[self.port_handle].ping_details = rv
        elif mode == None and arp_send_req:
            handle = kws.get('protocol_handle', None)
            if isinstance(handle, list):
                handle = handle[0]
            if not self.interface_validate(handle):
                self.error("invalid", "protocol_handle", handle)
            index = self.interfaces[handle].index
            rv = self.driver.send_arp(self.interfaces[handle], index)
            res[self.port_handle] = SpyTestDict()
        else:
            self.error("unsupported", "interface_config: mode", mode)
        return res

    def emulation_bgp_config(self, *args, **kws):
        res = SpyTestDict()
        res.status = "1"
        mode = kws.get('mode', None)
        if mode in ["enable", "disable"]:
            handle = kws.get('handle', None)
            res.handle = handle
            if isinstance(handle, list):
                handle = handle[0]
            if not self.interface_validate(handle):
                self.error("invalid", "handle", handle)
            intf = self.interfaces[handle]
            intf.bgp_kws = copy.copy(kws)
        else:
            self.error("unsupported", "emulation_bgp_config: mode", mode)
        return res

    def emulation_bgp_route_config(self, *args, **kws):
        res = SpyTestDict()
        res.status = "1"
        mode = kws.get('mode', None)
        if mode in ["add", "remove"]:
            handle = kws.get('handle', None)
            res.handle = handle
            if isinstance(handle, list):
                handle = handle[0]
            if not self.interface_validate(handle):
                self.error("invalid", "handle", handle)
            intf = self.interfaces[handle]
            intf.bgp_kws.update(kws)
        else:
            self.error("unsupported", "emulation_bgp_route_config: mode", mode)
        return res

    def emulation_bgp_control(self, *args, **kws):
        res = SpyTestDict()
        res.status = "1"
        mode = kws.get('mode', None)
        if mode in ["start", "stop"]:
            handle = kws.get('handle', None)
            if isinstance(handle, list):
                handle = handle[0]
            if not self.interface_validate(handle):
                self.error("invalid", "handle", handle)
            intf = self.interfaces[handle]
            if mode == "start":
                retval = self.driver.config_bgp(True, intf)
            else:
                retval = self.driver.config_bgp(False, intf)
            if not retval:
                self.error("Failed", "emulation_bgp_control: mode", mode)
        else:
            self.error("unsupported", "emulation_bgp_control: mode", mode)
        return res

    def emulation_igmp_config(self, *args, **kws):
        res = SpyTestDict()
        res.status = "1"
        mode = kws.get('mode', None)
        if mode in ["create"]:
            handle = kws.get('handle', None)
            res.handle = handle
            if isinstance(handle, list):
                handle = handle[0]
            if not self.interface_validate(handle):
                self.error("invalid", "handle", handle)
            intf = self.interfaces[handle]
            res.host_handle = intf.add_igmp_host(*args, **kws)
        else:
            self.error("unsupported", "emulation_igmp_config: mode", mode)
        return res

    def emulation_igmp_group_config(self, *args, **kws):
        res = SpyTestDict()
        res.status = "1"
        mode = kws.get('mode', "create")
        handle = kws.get('handle', None)
        host_handle = kws.get('session_handle', handle)
        for intf in self.interfaces.values():
            if host_handle in intf.igmp_hosts:
                if mode == "clear_all":
                    intf.igmp_hosts[host_handle].update(kws)
                else:
                    intf.igmp_hosts[host_handle].update(kws)
                res.group_handle = host_handle
                return res
        self.error("Invalid", "emulation_igmp_group_config: session_handle", host_handle)

    def emulation_igmp_control(self, *args, **kws):
        res = SpyTestDict()
        res.status = "1"
        host_handle = kws.get('handle', None)
        mode = kws.get('mode', "start")
        for intf in self.interfaces.values():
            if host_handle in intf.igmp_hosts:
                self.driver.config_igmp(mode, intf, intf.igmp_hosts[host_handle])
                return res
        self.error("Invalid", "emulation_igmp_control: handle", host_handle)

    def error(self, etype, name, value):
        msg = "{}: {} = {}".format(etype, name, value)
        self.logger.error("=================== {} ==================".format(msg))
        raise ValueError(msg)

