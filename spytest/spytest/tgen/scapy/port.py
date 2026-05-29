import os
import copy

from dicts import SpyTestDict
from driver import ScapyDriver
from logger import Logger
from utils import Utils
from lock import Lock
from stats import port_stats_init


def incrStat(stats, name, val=1):
    if name in stats:
        val = val + stats[name]
    stats[name] = val
    return val


class ScapyStream(object):
    def __init__(self, port, index, stream_id, track_ports, *args, **kws):
        self.port = port
        self.index = index
        self.track_ports = track_ports or []
        self.stream_id = stream_id
        self.args = args
        self.kws = copy.copy(kws)
        self.enable = True
        self.enable2 = False
        self.stats = port_stats_init()
        # print("ScapyStream: {} {} {}".format(self.port, self.stream_id, kws))
        for track_port in self.track_ports:
            track_port.track_streams.append(self)
        self.stream_lock = Lock()
        self.stats_lock = Lock()

    def __del__(self):
        print("ScapyStream {} exiting...".format(self.stream_id))
        for track_port in self.track_ports:
            track_port.track_streams.remove(self)

    def get_sid(self):
        return '{:08x}'.format((int(self.port) << 16) + (int(self.index)))

    def lock(self):
        self.stream_lock.acquire()

    def unlock(self):
        self.stream_lock.release()

    def incrStat(self, name, val=1):
        self.stats_lock.acquire()
        val = incrStat(self.stats, name, val)
        self.stats_lock.release()
        # print("incrStat: {} {} {} = {}".format(self.port, self.stream_id, name, val))
        return val

    def clearStat(self, name):
        self.stats_lock.acquire()
        old = self.stats[name]
        self.stats[name] = 0
        self.stats_lock.release()
        return old

    def __str__(self):
        return ''.join([('%s=%s' % x) for x in self.kws.items()])


class ScapyInterface(object):
    def __init__(self, port, index, handle, *args, **kws):
        self.port = port.name
        self.iface = port.iface
        self.index = index
        self.handle = handle
        self.intf = self
        self.args = args
        self.kws = copy.copy(kws)
        self.enable = True
        self.name = "{}_{}".format(self.port, self.index)
        self.name = self.name.replace("/", "_")
        self.igmp_hosts = SpyTestDict()
        self.igmp_queriers = SpyTestDict()
        self.bgp_routes = SpyTestDict()
        self.gwmac = SpyTestDict()
        self.mymac = []
        self.ospf_sessions = SpyTestDict()
        self.dhcp_servers = SpyTestDict()

    def add_dhcp_server(self, *args, **kws):
        index = len(self.dhcp_servers)
        handle = "dhcp-server-{}-{}-{}".format(self.port, self.index, index)
        server = SpyTestDict()
        server.index = index
        server.kws = copy.copy(kws)
        server.intf = self
        server.deleted = False
        server.connect = False
        server.handle = handle
        self.dhcp_servers[handle] = server
        server.dhcp_relay_agents = SpyTestDict()
        return server

    def add_dhcp_relay_agent(self, server, *args, **kws):
        index = len(server.dhcp_relay_agents)
        handle = "dhcp-relay-{}-{}-{}-{}"
        handle = handle.format(self.port, self.index, server.index, index)
        agent = SpyTestDict()
        agent.index = index
        agent.kws = copy.copy(kws)
        agent.intf = self
        agent.server = server
        agent.deleted = False
        agent.connect = False
        agent.handle = handle
        server.dhcp_relay_agents[handle] = agent
        return agent

    def add_igmp_host(self, *args, **kws):
        index = len(self.igmp_hosts)
        host_handle = "igmp-host-{}-{}-{}".format(self.port, self.index, index)
        host = SpyTestDict()
        host.index = index
        host.kws = copy.copy(kws)
        host.intf = self
        host.host_handle = host_handle
        host.handle = host_handle
        self.igmp_hosts[host_handle] = host
        return host

    def add_igmp_querier(self, *args, **kws):
        index = len(self.igmp_queriers)
        querier_handle = "igmp-querier-{}-{}-{}".format(self.port, self.index, index)
        querier = SpyTestDict()
        querier.index = index
        querier.kws = copy.copy(kws)
        querier.intf = self
        querier.enable = True
        querier.querier_handle = querier_handle
        querier.handle = querier_handle
        self.igmp_queriers[querier_handle] = querier
        return querier

    def add_bgp_route(self, *args, **kws):
        index = len(self.bgp_routes)
        route_handle = "bgp-route-{}-{}-{}".format(self.port, self.index, index)
        route = SpyTestDict()
        route.index = index
        route.kws = copy.copy(kws)
        route.enable = True
        route.intf = self
        route.route_handle = route_handle
        route.handle = route_handle
        self.bgp_routes[route_handle] = route
        return route

    def add_ospf_session(self, *args, **kws):
        index = len(self.ospf_sessions)
        handle = "ospf-session-{}-{}-{}".format(self.port, self.index, index)
        session = SpyTestDict()
        session.index = index
        session.kws = copy.copy(kws)
        session.intf = self
        session.deleted = False
        session.active = False
        session.handle = handle
        self.ospf_sessions[handle] = session
        session.routes = SpyTestDict()
        return session

    def add_ospf_route(self, session, *args, **kws):
        index = len(session.routes)
        handle = "ospf-route-{}-{}-{}-{}"
        handle = handle.format(self.port, self.index, session.index, index)
        route = SpyTestDict()
        route.index = index
        route.kws = copy.copy(kws)
        route.session = session
        route.deleted = False
        route.handle = handle
        session.routes[handle] = route
        return route


class ScapyPort(object):
    def __init__(self, name, iface, dry=False, dbg=0, logger=None):
        self.name = name
        self.port_handle = "port-{}".format(name)
        self.iface = iface
        self.dry = dry
        self.dbg = dbg
        self.errs = []
        self.logger = logger or Logger()
        self.utils = Utils(self.dry, logger=self.logger)
        self.streams = SpyTestDict()
        self.track_streams = []
        self.interfaces = SpyTestDict()
        self.stats = port_stats_init()
        self.driver = ScapyDriver(self, self.dry, self.dbg, self.logger)
        self.admin_status = True
        self.dhcp_clients = SpyTestDict()
        self.dot1x_clients = SpyTestDict()
        self.stats_lock = Lock()

    def __del__(self):
        self.logger.debug("ScapyPort {} exiting...".format(self.name))
        self.cleanup()
        del self.driver

    def clean_interfaces(self):
        for handle in list(self.interfaces.keys()):
            self.logger.info("Removing interface {}".format(handle))
            self.driver.deleteInterface(self.interfaces[handle], True)
            del self.interfaces[handle]

    def clean_streams(self):
        self.driver.stopTransmit()
        for sid in self.streams:
            self.logger.info("Removing stream {}".format(sid))
        self.streams.clear()
        for stream in self.track_streams:
            stream.lock()
            stream.track_ports = []
            stream.unlock()
        self.track_streams = []

    def cleanup(self):
        self.logger.debug("ScapyPort {} cleanup...".format(self.name))
        self.clean_interfaces()
        self.driver.cleanup()
        self.clean_streams()

    def show(self):
        self.logger.info(self)
        self.logger.info(self.iface)
        self.logger.info(self.interfaces)

    def add_dhcp_client(self, *args, **kws):
        index = len(self.dhcp_clients)
        handle = "dhcp-client-{}-{}".format(self.name, index)
        client = SpyTestDict()
        client.index = index
        client.kws = copy.copy(kws)
        client.port = self
        client.deleted = False
        client.active = False
        client.handle = handle
        self.dhcp_clients[handle] = client
        client.groups = SpyTestDict()
        return client

    def add_dhcp_group(self, client, *args, **kws):
        index = len(client.groups)
        handle = "dhcp-client-group-{}-{}-{}"
        handle = handle.format(self.name, client.index, index)
        group = SpyTestDict()
        group.index = index
        group.kws = copy.copy(kws)
        group.client = client
        group.deleted = False
        group.handle = handle
        client.groups[handle] = group
        return group

    def add_dot1x_client(self, *args, **kws):
        index = len(self.dot1x_clients)
        handle = "dot1x-client-{}-{}".format(self.name, index)
        client = SpyTestDict()
        client.index = index
        client.kws = copy.copy(kws)
        client.port = self
        client.deleted = False
        client.active = False
        client.handle = handle
        client.intf = None
        client.mode = ""
        self.dot1x_clients[handle] = client
        return client

    def get_alerts(self):
        errs = []
        errs.extend(self.errs)
        errs.extend(self.driver.get_alerts())
        self.errs = []
        return errs

    def get_all_handles(self):
        handles = []
        for ih, intf in self.interfaces.items():
            handles.append(ih)
            for brh in intf.bgp_routes:
                handles.append(brh)
        return handles

    def set_admin_status(self, val):
        self.admin_status = val

    def get_admin_status(self):
        return self.admin_status

    def incrStat(self, name, val=1):
        self.stats_lock.acquire()
        rv = incrStat(self.stats, name, val)
        self.stats_lock.release()
        return rv

    def getStats(self):
        self.stats_lock.acquire()
        rv = self.stats
        self.stats_lock.release()
        return rv

    def getStreamStats(self):
        res = []
        for _, stream in self.streams.items():
            res.append([stream, stream.stats])
        return res

    def traffic_control_complete(self, *args, **kws):
        self.driver.startTransmitComplete(**kws)

    def traffic_control(self, *args, **kws):
        action = kws.get('action', None)
        if action == "run":
            for intf in self.interfaces.values():
                arp_send_req = kws.get('arp_send_req', "0")
                if arp_send_req == "1":
                    # self.driver.send_arp(intf, intf.index)
                    self.driver.send_arp(intf, 0)
            self.driver.startTransmit(**kws)
            return True
        elif action == "stop":
            self.driver.stopTransmit(**kws)
        elif action == "reset":
            self.clean_streams()
        elif action == "clear_stats":
            self.stats_lock.acquire()
            port_stats_init(self.stats)
            for stream in self.streams.values():
                port_stats_init(stream.stats)
            self.stats_lock.release()
            self.driver.clear_stats()
        else:
            self.error("unsupported", "traffic_control: action", action)
        return False

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

    def get_all_streams(self):
        return list(self.streams.keys())

    def stream_validate(self, handles):
        for handle in Utils.make_list(handles):
            if handle not in self.streams:
                return False
        return True

    def stream_encode(self, index):
        return "stream-{}-{}".format(self.name, index)

    def traffic_config(self, track_ports, validate_stream_id, *args, **kws):
        res = SpyTestDict()
        mode = kws.get('mode', None)
        stream_id_list = Utils.make_list(kws.get('stream_id', []))
        if mode == "create":
            index = len(self.streams)
            res.stream_id = self.stream_encode(index)
            stream = ScapyStream(self.name, index, res.stream_id, track_ports, *args, **kws)
            self.streams[res.stream_id] = stream
            track_port_names = [track_port.port_handle for track_port in stream.track_ports]
            self.logger.debug("New stream {} tracking {} ...".format(res.stream_id, track_port_names))
        elif mode == "remove":
            for stream_id in stream_id_list:
                if stream_id not in self.streams:
                    if not validate_stream_id:
                        break
                    self.error("invalid", "traffic_config-remove-stream_id", stream_id)
                self.driver.stopTransmit(handle=stream_id)
        elif mode == "enable":
            for stream_id in stream_id_list:
                if stream_id not in self.streams:
                    if not validate_stream_id:
                        break
                    self.error("invalid", "traffic_config-enable-stream_id", stream_id)
                self.streams[stream_id].enable = True
        elif mode == "disable":
            for stream_id in stream_id_list:
                if stream_id not in self.streams:
                    if not validate_stream_id:
                        break
                    self.error("invalid", "traffic_config-disable-stream_id", stream_id)
                self.streams[stream_id].enable = False
        elif mode == "modify":
            for stream_id in stream_id_list:
                if stream_id not in self.streams:
                    if not validate_stream_id:
                        break
                    self.error("invalid", "traffic_config-modify-stream_id", stream_id)
                self.streams[stream_id].kws.update(kws)
        elif mode == "reset":
            self.streams = SpyTestDict()
        else:
            self.error("unsupported", "traffic_config: mode", mode)
        return res

    def find_interface(self, handle):
        if handle in self.interfaces:
            return self.interfaces[handle]
        route = self.get_bgp_route(handle)
        if route:
            return route
        route = self.get_ospf_route(handle)
        if route:
            return route.session.intf
        return None

    def validate_interface(self, intf):
        if self.driver.validate_interface(intf):
            return intf
        return None

    def igmp_host_validate(self, handle):
        for intf in self.interfaces.values():
            if handle in intf.igmp_hosts:
                return True
        return False

    def get_bgp_route(self, handle):
        for intf in self.interfaces.values():
            if handle in intf.bgp_routes:
                return intf.bgp_routes[handle]
        return None

    def get_ospf_route(self, handle):
        for intf in self.interfaces.values():
            for session in intf.ospf_sessions.values():
                if handle in session.routes:
                    return session.routes[handle]
        return None

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
        vlan_id_count = self.utils.intval(kws, "vlan_id_count", 0)
        if mode == "config":
            if count > 256:
                self.error("too large > 256", "count", count)
            if vlan_id_count > 256:
                self.error("too large > 256", "vlan_id_count", vlan_id_count)
            index = len(self.interfaces)
            handle = self.interface_encode(index)
            interface = ScapyInterface(self, index, handle, *args, **kws)
            self.interfaces[handle] = interface
            self.driver.createInterface(interface)
            if count > 1:
                res.handle = [handle for _ in range(count)]
            elif vlan_id_count > 1:
                res.handle = [handle for _ in range(vlan_id_count)]
            else:
                res.handle = handle
            self.logger.debug("New interface {}...".format(res.handle))
        elif mode == "destroy":
            handle = self.get_single("handle", **kws)
            if not self.interface_validate(handle):
                try:
                    self.error("invalid", "interface_config-destroy-handle", handle)
                except Exception:
                    return res
            self.driver.deleteInterface(self.interfaces[handle])
            del self.interfaces[handle]
        elif mode == "modify":
            for intf in self.interfaces.values():
                intf.kws.update(kws)
        elif mode is None and send_ping and ping_dst:
            handle = self.get_single("protocol_handle", **kws)
            if not self.interface_validate(handle):
                self.error("invalid", "interface_config-ping-protocol_handle", handle)
            # index = self.interfaces[handle].index
            # rv = self.driver.ping(self.interfaces[handle], ping_dst, index)
            rv = self.driver.ping(self.interfaces[handle], ping_dst, 0)
            res[self.port_handle] = SpyTestDict()
            res[self.port_handle].ping_details = rv
        elif mode is None and arp_send_req:
            handle = self.get_single("protocol_handle", **kws)
            if not self.interface_validate(handle):
                self.error("invalid", "interface_config-arp-protocol_handle", handle)
            # index = self.interfaces[handle].index
            # self.driver.send_arp(self.interfaces[handle], index)
            self.driver.send_arp(self.interfaces[handle], 0)
            res[self.port_handle] = SpyTestDict()
        else:
            self.error("unsupported", "interface_config: mode", mode)
        return res

    def emulation_bgp_config(self, *args, **kws):

        # verify mode
        mode = kws.get('mode', None)
        if mode not in ["enable", "disable"]:
            self.error("unsupported", "emulation_bgp_config: mode", mode)
            return {}

        # verify handle
        handle = self.get_single("handle", **kws)
        if not self.interface_validate(handle):
            self.error("invalid", "emulation_bgp_config-handle", handle)

        # apply config
        intf = self.interfaces[handle]
        intf.bgp_kws = copy.copy(kws)
        # retval = self.driver.control_bgp(mode, intf)
        # if not retval: self.error("Failed", "emulation_bgp_config: mode", mode)

        return self.utils.success(handle=handle)

    def emulation_bgp_route_config(self, *args, **kws):

        # verify mode
        mode = kws.pop('mode', None)
        if mode not in ["add", "remove"]:
            self.error("unsupported", "emulation_bgp_route_config: mode", mode)

        handle = self.get_single("handle", **kws)
        if mode in ["add", "remove"]:
            intf = self.find_interface(handle)
            if not intf:
                self.error("invalid", "emulation_bgp_route_config-handle", handle)
            if mode == "add":
                route = intf.add_bgp_route(*args, **kws)
                retval = self.driver.control_bgp_route(mode, route)
            else:
                retval = False
                for route in intf.intf.bgp_routes.values():
                    if route.kws.get("prefix", None) == kws.get("prefix", None):
                        retval = self.driver.control_bgp_route(mode, route)
            if not retval:
                self.error("Failed", "emulation_bgp_route_config: mode", mode)
            return self.utils.success(handle=route.route_handle)

        # handle withdraw, readvertize
        try:
            route = self.get_bgp_route(handle)
        except Exception as exp:
            self.error("failed to parge route", str(exp), handle)
        if not route:
            self.error("invalid", "emulation_bgp_route_config", handle)

        retval = self.driver.control_bgp_route(mode, route)

        return self.utils.success()

    def emulation_bgp_control(self, *args, **kws):

        # verify mode
        mode = kws.get('mode', None)
        if mode not in ["start", "stop", "link_flap", "full_route_flap"]:
            self.error("unsupported", "emulation_bgp_control: mode", mode)

        # verify handle
        handle = self.get_single("handle", **kws)
        if self.interface_validate(handle):
            intf = self.interfaces[handle]
        else:
            route = self.get_bgp_route(handle)
            if not route:
                self.error("invalid", "emulation_bgp_control-handle", handle)
            intf = route.intf

        # apply
        retval = self.driver.control_bgp(mode, intf)
        if not retval:
            self.error("Failed", "emulation_bgp_control: mode", mode)

        return self.utils.success()

    def emulation_igmp_config(self, *args, **kws):
        mode = kws.get('mode', None)
        if mode not in ["create", "delete", "modify"]:
            self.error("unsupported", "emulation_igmp_config: mode", mode)
        handle = self.get_single("handle", **kws)
        if mode == "create":
            if handle in self.interfaces:
                intf = self.interfaces[handle]
                host = intf.add_igmp_host(*args, **kws)
                return self.utils.success(host_handle=host.host_handle,
                                          igmp_host_handle=host.host_handle)

        for intf in self.interfaces.values():
            if handle in intf.igmp_hosts:
                if mode == "modify":
                    intf.igmp_hosts[handle].kws.update(kws)
                else:
                    del intf.igmp_hosts[handle]
                return self.utils.success()

        return None

    def emulation_igmp_group_config(self, *args, **kws):
        host_handle = kws.get('session_handle', kws.get('handle', None))
        mode = kws.get('mode', None)
        for intf in self.interfaces.values():
            if host_handle not in intf.igmp_hosts:
                continue
            if mode == "clear_all":
                intf.igmp_hosts[host_handle].kws["group_pool_data"] = []
                intf.igmp_hosts[host_handle].kws["source_pool_data"] = []
                return self.utils.success()
            intf.igmp_hosts[host_handle].kws.update(kws)
            self.logger.dump("IGMP HOST", intf.igmp_hosts[host_handle])
            return self.utils.success(group_handle=host_handle)
        self.error("Invalid", "emulation_igmp_group_config: session_handle", host_handle)

    def emulation_igmp_querier_config(self, *args, **kws):
        res = SpyTestDict()
        mode = kws.get('mode', None)
        if mode in ["delete"]:
            return res
        if mode not in ["create"]:
            self.error("unsupported", "emulation_igmp_querier_config: mode", mode)
        handle = kws.get('handle', None)
        for intf in self.interfaces.values():
            if not self.interface_validate(handle):
                return res
            intf = self.interfaces[handle]
            querier = intf.add_igmp_querier(*args, **kws)
            res.igmp_querier_handle = querier.querier_handle
            res.handle = querier.querier_handle
            res.status = "1"
            return res
        return res

    def emulation_igmp_control(self, *args, **kws):
        mode = kws.get('mode', "start")
        host_handle = kws.get('handle', None)
        for intf in self.interfaces.values():
            if host_handle in intf.igmp_hosts:
                self.driver.config_igmp(mode, intf, intf.igmp_hosts[host_handle])
                return self.utils.success()
        return None

    def emulation_igmp_querier_control(self, *args, **kws):
        mode = kws.get('mode', "start")
        querier_handle = kws.get('handle', None)
        for intf in self.interfaces.values():
            if querier_handle in intf.igmp_queriers:
                self.driver.control_igmp_querier(mode, intf, intf.igmp_queriers[querier_handle])
                return self.utils.success()
        return None

    def error(self, etype, name, value):
        msg = "{}: {} = {}".format(etype, name, value)
        self.logger.error("=================== {} ==================".format(msg))
        self.errs.append(msg)
        raise ValueError(msg)

    def get_single(self, prop, **kwargs):
        value = kwargs.get(prop, None)
        if isinstance(value, list):
            value = value[0]
        return value

    def emulation_ospf_config(self, *args, **kws):
        mode = kws.get('mode', None)
        if mode not in ["create", "delete", "modify"]:
            self.error("unsupported", "emulation_ospf_config: mode", mode)

        handle = self.get_single("handle", **kws)
        if mode in ["create"]:
            if handle in self.interfaces:
                intf = self.interfaces[handle]
                session = intf.add_ospf_session(*args, **kws)
                # TODO: add to driver
                return self.utils.success(handle=session.handle)
        elif mode in ["delete"]:
            for intf in self.interfaces.values():
                if handle in intf.ospf_sessions:
                    del intf.ospf_sessions[handle]
                    # TODO: remove from driver
                    return self.utils.success()
        elif mode in ["modify"]:
            for intf in self.interfaces.values():
                if handle in intf.ospf_sessions:
                    intf.ospf_sessions[handle].kws.update(kws)
                    # TODO: change in driver
                    return self.utils.success()

        return None

    def emulation_ospf_control(self, *args, **kws):
        mode = kws.get('mode', None)
        if mode not in ["start", "stop", "age_out_routes"]:
            self.error("unsupported", "emulation_ospf_control: mode", mode)

        handle = self.get_single("handle", **kws)
        for intf in self.interfaces.values():
            if handle in intf.ospf_sessions:
                session = intf.ospf_sessions[handle]
                if mode == "start":
                    session.active = True
                elif mode == "stop":
                    session.active = False
                if self.driver.control_ospf(mode, intf, intf.ospf_sessions[handle]):
                    return self.utils.success()

        return None

    def emulation_ospf_route_config(self, *args, **kws):
        mode = kws.get('mode', None)
        if mode not in ["create", "delete"]:
            self.error("unsupported", "emulation_ospf_route_config: mode", mode)

        handle = self.get_single("handle", **kws)
        if mode == "create":
            for intf in self.interfaces.values():
                if handle in intf.ospf_sessions:
                    session = intf.ospf_sessions[handle]
                    route = intf.add_ospf_route(session, *args, **kws)
                    return self.utils.success(handle=route.handle,
                                              ipv4_prefix_interface_handle=route.handle)

        if mode == "delete":
            for intf in self.interfaces.values():
                for session in intf.ospf_sessions.values():
                    if handle in session.routes:
                        session.routes[handle].deleted = True
                        del session.routes[handle]
                        return self.utils.success()

        return None

    def emulation_dhcp_client_config(self, *args, **kws):
        mode = kws.get('mode', None)
        if mode not in ["create", "reset"]:
            self.error("unsupported", "emulation_dhcp_client_config: mode", mode)
        handle = self.get_single("handle", **kws)
        if mode == "create":
            client = self.add_dhcp_client(*args, **kws)
            return self.utils.success(handles=client.handle, handle=client.handle)
        if mode == "reset":
            if handle in self.dhcp_clients:
                self.dhcp_clients[handle].deleted = True
                # del self.dhcp_clients[handle]
                return self.utils.success()
        return {}

    def emulation_dhcp_client_group_config(self, *args, **kws):
        mode = kws.get('mode', None)
        if mode not in ["create"]:
            self.error("unsupported", "emulation_dhcp_client_group_config: mode", mode)

        handle = self.get_single("handle", **kws)
        if mode == "create":
            if handle in self.dhcp_clients:
                client = self.dhcp_clients[handle]
                group = self.add_dhcp_group(client, *args, **kws)
                if kws.get("dhcp6_client_mode", "") != "DHCPV6":
                    return self.utils.success(handle=group.handle)
                return self.utils.success(handle=group.handle, dhcpv6_handle=group.handle)

        return None

    def emulation_dhcp_client_control(self, *args, **kws):
        action = kws.get('action', None)
        handle = self.get_single("handle", **kws)
        if action not in ["renew", "release", "bind", "rebind"]:
            self.error("unsupported", "emulation_dhcp_client_control: action", action)
        for client in self.dhcp_clients.values():
            if handle in client.groups:
                if self.driver.control_dhcpc(client.groups[handle], self, **kws):
                    return self.utils.success()
        return {}

    def emulation_dhcp_server_config(self, *args, **kws):
        mode = kws.get('mode', None)
        if mode not in ["create", "reset"]:
            self.error("unsupported", "emulation_dhcp_server_config: mode", mode)
        handle = self.get_single("handle", **kws)
        if mode == "create":
            if handle in self.interfaces:
                intf = self.interfaces[handle]
                server = intf.add_dhcp_server(*args, **kws)
                return self.utils.success(dhcp_handle=server.handle)
        if mode == "reset":
            for intf in self.interfaces.values():
                if handle in intf.dhcp_servers:
                    intf.dhcp_servers[handle].deleted = True
                    # del intf.dhcp_servers[handle]
                    self.driver.control_dhcps(intf.dhcp_servers[handle], intf, **kws)
                    return self.utils.success()
        return {}

    def emulation_dhcp_server_relay_agent_config(self, *args, **kws):
        mode = kws.get('mode', None)
        if mode not in ["create"]:
            self.error("unsupported", "emulation_dhcp_server_relay_agent_config: mode", mode)
        handle = self.get_single("handle", **kws)
        if mode == "create":
            for intf in self.interfaces.values():
                if handle in intf.dhcp_servers:
                    server = intf.dhcp_servers[handle]
                    agent = intf.add_dhcp_relay_agent(server, *args, **kws)
                    return self.utils.success(handle=agent.handle)
        return {}

    def emulation_dhcp_server_control(self, *args, **kws):
        action = kws.get('action', None)
        if action not in ["connect"]:
            self.error("unsupported", "emulation_dhcp_server_control: action", action)
        handle = self.get_single("dhcp_handle", **kws)
        for intf in self.interfaces.values():
            if handle in intf.dhcp_servers:
                intf.dhcp_servers[handle].connect = True
                if self.driver.control_dhcps(intf.dhcp_servers[handle], intf, **kws):
                    return self.utils.success()
        return {}

    def emulation_dot1x_config(self, *args, **kws):
        mode = kws.get('mode', None)
        if mode not in ["create", "delete"]:
            self.error("unsupported", "emulation_dot1x_config: mode", mode)
        if mode == "create":
            port_handle = kws.pop('port_handle', None)
            if self.port_handle == port_handle:
                client = self.add_dot1x_client(*args, **kws)
                if os.getenv("SPYTEST_SCAPY_DOT1X_IMPL", "1") == "2":
                    intf_kws = {"mode": "config"}
                    intf_kws["intf_ip_addr"] = kws.get("local_ip_addr", "0.0.0.0")
                    intf_kws["src_mac_addr"] = kws.get("mac_addr", "")
                    intf_kws["gateway"] = kws.get("gateway_ip_addr", "")
                    res = self.interface_config(**intf_kws)
                    client.intf = self.interfaces[res.handle]
                return self.utils.success(handle=client.handle)
        if mode == "delete":
            handle = self.get_single("handle", **kws)
            if handle in self.dot1x_clients:
                self.dot1x_clients[handle].deleted = True
                # del self.dot1x_clients[handle]
                return self.utils.success()
        return {}

    def emulation_dot1x_control(self, *args, **kws):
        mode = kws.get('mode', None)
        if mode not in ["start", "stop", "abort", "logout"]:
            self.error("unsupported", "emulation_dot1x_control: mode", mode)
        handle = self.get_single("handle", **kws)
        if handle in self.dot1x_clients:
            if self.driver.control_dot1x(mode, self.dot1x_clients[handle]):
                return self.utils.success()
        return {}
