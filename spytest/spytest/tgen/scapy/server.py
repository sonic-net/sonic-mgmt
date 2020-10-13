import os
import sys
import json
import time

from dicts import SpyTestDict
from port import ScapyPort
from logger import Logger

# create port map
portmap = SpyTestDict()
tgen_portmap_model = os.getenv("SCAPY_TGEN_PORTMAP", "eth1")
for i in range(0,16):
    if tgen_portmap_model == "ens6":
        portmap["1/{}".format(i+1)] = "ens{}".format(i+6)
        portmap["{}".format(i+1)] = "ens{}".format(i+6)
    elif tgen_portmap_model == "eth1":
        portmap["1/{}".format(i+1)] = "eth{}".format(i)
        portmap["{}".format(i+1)] = "eth{}".format(i)
    else:
        portmap["1/{}".format(i)] = "eth{}".format(i)
        portmap["{}".format(i)] = "eth{}".format(i)

class ScapyServer(object):
    def __init__(self, dry=False, dbg=0):
        self.dry = dry
        self.dbg = dbg
        self.ports = SpyTestDict()
        self.mgrps = SpyTestDict()
        self.msrcs = SpyTestDict()
        self.logger = Logger()
        os.system("ip -all netns del")
        os.system("sysctl -w net.bridge.bridge-nf-call-arptables=0")
        os.system("sysctl -w net.bridge.bridge-nf-call-ip6tables=0")
        os.system("sysctl -w net.bridge.bridge-nf-call-iptables=0")

    def __del__(self):
        self.logger.debug("ScapyServer exiting...")
        self.cleanup_ports()
        self.ports = SpyTestDict()
        self.mgrps = SpyTestDict()
        self.msrcs = SpyTestDict()

    def cleanup_ports(self):
        for key in self.ports.keys():
            self.ports[key].cleanup()
        for key in self.mgrps.keys():
            self.mgrps[key].cleanup()
        for key in self.msrcs.keys():
            self.msrcs[key].cleanup()

    def trace_args(self, *args, **kws):
        func = sys._getframe(1).f_code.co_name
        self.logger.debug(func, args, kws)

    def trace_result(self, res, min_dbg=2):
        if self.dbg >= min_dbg:
            self.logger.debug("RESULT:", json.dumps(res))
        return res

    def error(self, etype, name, value):
        msg = "{}: {} = {}".format(etype, name, value)
        self.logger.error("=================== {} ==================".format(msg))
        raise ValueError(msg)

    def make_list(self, arg):
        if isinstance(arg, list):
            return arg
        return [arg]

    def exposed_server_control(self, req, data, *args, **kws):
        self.trace_args(req, data, *args, **kws)
        retval = ""
        if req == "set-dbg-lvl":
            self.dbg = int(data)
        elif req == "set-dry-run":
            self.dry = data
        elif req == "set-max-pps":
            os.environ["SPYTEST_SCAPY_MAX_RATE_PPS"] = str(data)
        elif req == "init-log":
            self.logger.set_log_file(data)
        elif req == "read-log":
            retval = self.logger.get_log(data)
        elif req == "add-log":
            self.logger.info("#"*80)
            self.logger.info(data)
            self.logger.info("#"*80)
        elif req == "clean-all":
            for port in self.ports.values():
                port.clean_streams()
                port.clean_interfaces()
        else:
            self.error("Invalid", "server request", req)
        return retval

    def fix_port_name(self, pname):
        return pname.split("/")[-1].strip()

    def exposed_tg_connect(self, *args, **kws):
        self.trace_args(*args, **kws)
        port_list = kws.get('port_list', [])
        res = SpyTestDict()
        res.port_handle = SpyTestDict()
        delete_ports = []
        for pname0 in port_list:
            pname = self.fix_port_name(pname0)
            for pobj in self.ports.values():
                if pobj.name == pname:
                    delete_ports.append(pobj)
            pobj = ScapyPort(pname, portmap.get(pname), dry=self.dry,
                             dbg=self.dbg, logger=self.logger)
            self.ports[pobj.port_handle] = pobj
            res.port_handle[pname0] = pobj.port_handle
        for pobj in delete_ports:
            del pobj
        res.status = 1
        return self.trace_result(res)

    def exposed_tg_disconnect(self, *args, **kws):
        self.trace_args(*args, **kws)
        res = SpyTestDict()
        self.cleanup_ports()
        res.status = 1
        return self.trace_result(res)

    def exposed_tg_traffic_control(self, *args, **kws):
        self.trace_args(*args, **kws)
        handle = kws.get('handle', None)
        port_handle = kws.get('port_handle', None)
        res = True
        if port_handle:
            for port_handle in self.make_list(port_handle):
                port = self.ports[port_handle]
                if not port.traffic_control(*args, **kws):
                    res = False
        elif handle:
            for handle in self.make_list(handle):
                for port in self.ports.values():
                    if port.stream_validate(handle):
                        if not port.traffic_control(*args, **kws):
                            res = False
                        break
        else:
            for port in self.ports.values():
                if not port.traffic_control(*args, **kws):
                    res = False

        action = kws.get('action', None)
        if action in ["stop", "start"]:
            for port in self.ports.values():
                stats = port.getStats()
                msg = "{}: TX: {} RX: {}".format(port.name,
                         stats.framesSent, stats.framesReceived)
                self.logger.debug(msg)
        return self.trace_result(res)

    def ensure_port_handle(self, port_handle):
        if not port_handle:
            msg = "port_handle is not specified"
            raise ValueError(msg)
        if port_handle not in self.ports:
            msg = "port_handle {} is not valid".format(port_handle)
            raise ValueError(msg)
        return self.ports[port_handle]

    def exposed_tg_interface_control(self, *args, **kws):
        self.trace_args(*args, **kws)
        port_handle = kws.get('port_handle', None)
        port = self.ensure_port_handle(port_handle)
        mode = kws.get('mode', "aggregate")
        if mode == "break_link":
            port.set_admin_status(False)
            return True
        elif mode == "restore_link":
            port.set_admin_status(True)
            return True
        elif mode == "check_link":
            return port.get_admin_status()
        self.error("Invalid", "mode", mode)

    def exposed_tg_packet_control(self, *args, **kws):
        self.trace_args(*args, **kws)
        port_handle = kws.get('port_handle', None)
        if not port_handle:
            msg = "port_handle is not specified"
            raise ValueError(msg)
        port = self.ports[port_handle]
        res = port.packet_control(*args, **kws)
        return self.trace_result(res)

    def exposed_tg_packet_stats(self, *args, **kws):
        self.trace_args(*args, **kws)
        res = SpyTestDict()
        port_handle = kws.get('port_handle', None)
        mode = kws.get('mode', "aggregate")
        res["status"] = "1"
        if port_handle and port_handle in self.ports:
            port = self.ports[port_handle]
            pkts = port.packet_stats(*args, **kws)
            res[port_handle] = SpyTestDict()
            res[port_handle][mode] = SpyTestDict()
            res[port_handle][mode]["num_frames"] = len(pkts)
            res[port_handle]["frame"] = SpyTestDict()
            for i, pkt in enumerate(pkts):
                index = str(i)
                res[port_handle]["frame"][index] = SpyTestDict()
                res[port_handle]["frame"][index]["length"] = len(pkt)
                res[port_handle]["frame"][index]["frame_pylist"] = pkt
                res[port_handle]["frame"][index]["frame"] = " ".join(pkt)
        return self.trace_result(res, 3)

    def exposed_tg_traffic_config(self, *args, **kws):
        self.trace_args(*args, **kws)
        port_handle = kws.get('port_handle', None)
        stream_id = kws.get('stream_id', None)
        port_handle2 = kws.get('port_handle2', None)

        # check if track port is specified
        if port_handle2 and port_handle2 in self.ports:
            track_port = self.ports[port_handle2]
        else:
            track_port = None

        # get the port handle from stream if not specified
        if not port_handle and stream_id:
            for phandle, port in self.ports.items():
                if port.stream_validate(stream_id):
                    port_handle = phandle
                    break

        # bailout: we must have port handle
        if not port_handle:
            msg = "port_handle is not specified"
            raise ValueError(msg)

        # we may get multiple port handles also
        if isinstance(port_handle, list):
            port_handle_list = port_handle
        else:
            port_handle_list = [port_handle]

        # validate src emulation handle before adding stream
        emulation_src_handle = kws.get('emulation_src_handle', None)
        if emulation_src_handle:
            intf = self.find_intf(emulation_src_handle)
            if not intf:
                self.error("Invalid", "emulation_src_handle", emulation_src_handle)
            else:
                kws["emulation_src_handle"] = intf

        # validate dst emulation handle before adding stream
        emulation_dst_handle = kws.get('emulation_dst_handle', None)
        if emulation_dst_handle:
            intf = self.find_intf(emulation_dst_handle)
            if not intf:
                self.error("Invalid", "emulation_dst_handle", emulation_dst_handle)
            else:
                kws["emulation_dst_handle"] = intf

        # all well add stream to port
        res = SpyTestDict()
        for port_handle in port_handle_list:
            port = self.ports[port_handle]
            rv = port.traffic_config(track_port, *args, **kws)
            res.update(rv)

        return self.trace_result(res)

    def find_intf(self, handle):
        if isinstance(handle, list):
            handle = handle[0]
        for port in self.ports.values():
            intf = port.find_interface(handle)
            if intf:
                return intf
        return None

    def verify_handle(self, *args, **kws):
        port_handle = kws.get('port_handle', None)
        protocol_handle = kws.get('protocol_handle', None)
        handle = kws.get('handle', None)
        if not protocol_handle and not port_handle and not handle:
            msg = "Neither handle nor port_handle specified"
            raise ValueError(msg)
        if port_handle:
            return self.ports[port_handle]
        elif protocol_handle:
            if isinstance(protocol_handle, list):
                protocol_handle = protocol_handle[0]
            for port in self.ports.values():
                if port.interface_validate(protocol_handle):
                    return port
            self.error("Invalid", "protocol_handle", protocol_handle)
        else:
            if isinstance(handle, list):
                handle = handle[0]
            for port in self.ports.values():
                if port.interface_validate(handle):
                    return port
            self.error("Invalid", "handle", handle)

    def exposed_tg_interface_config(self, *args, **kws):
        self.trace_args(*args, **kws)
        port = self.verify_handle(*args, **kws)
        res = port.interface_config(*args, **kws)
        return self.trace_result(res)

    def exposed_tg_emulation_bgp_config(self, *args, **kws):
        self.trace_args(*args, **kws)
        port = self.verify_handle(*args, **kws)
        res = port.emulation_bgp_config(*args, **kws)
        return self.trace_result(res)

    def exposed_tg_emulation_bgp_route_config(self, *args, **kws):
        self.trace_args(*args, **kws)
        port = self.verify_handle(*args, **kws)
        res = port.emulation_bgp_route_config(*args, **kws)
        return self.trace_result(res)

    def exposed_tg_emulation_bgp_control(self, *args, **kws):
        self.trace_args(*args, **kws)
        port = self.verify_handle(*args, **kws)
        res = port.emulation_bgp_control(*args, **kws)
        return self.trace_result(res)

    def exposed_tg_emulation_igmp_config(self, *args, **kws):
        self.trace_args(*args, **kws)
        port = self.verify_handle(*args, **kws)
        res = port.emulation_igmp_config(*args, **kws)
        return self.trace_result(res)

    def exposed_tg_emulation_multicast_group_config(self, *args, **kws):
        self.trace_args(*args, **kws)
        mode = kws.get('mode', "create")
        index = len(self.mgrps)
        if mode == "create":
            group = SpyTestDict()
            group.update(kws)
            group.index = index
            group.name = "mgrp-{}".format(group.index)
            self.mgrps[group.name] = group
            res = SpyTestDict()
            res["status"] = "1"
            res["mul_group_handle"] = group.name
            return self.trace_result(res)
        self.error("Invalid", "emulation_multicast_group_config: mode", mode)

    def exposed_tg_emulation_multicast_source_config(self, *args, **kws):
        self.trace_args(*args, **kws)
        mode = kws.get('mode', "create")
        index = len(self.msrcs)
        if mode == "create":
            group = SpyTestDict()
            group.update(kws)
            group.index = index
            group.name = "msrc-{}".format(group.index)
            self.msrcs[group.name] = group
            res = SpyTestDict()
            res["status"] = "1"
            res["mul_source_handle"] = group.name
            return self.trace_result(res)
        self.error("Invalid", "emulation_multicast_source_config: mode", mode)

    def exposed_tg_emulation_igmp_group_config(self, *args, **kws):
        self.trace_args(*args, **kws)
        mode = kws.get('mode', "create")
        if mode not in ["create", "clear_all"]:
            self.error("Invalid", "emulation_igmp_group_config: mode", mode)
        elif mode in ["create"]:
            group_pool_handle = kws.get('group_pool_handle', None)
            if group_pool_handle not in self.mgrps:
                self.error("Invalid", "emulation_igmp_group_config: group_pool_handle", group_pool_handle)
            source_pool_handle = kws.get('source_pool_handle', None)
            if source_pool_handle not in self.msrcs:
                self.error("Invalid", "emulation_igmp_group_config: source_pool_handle", source_pool_handle)
        host_handle = kws.get('session_handle',  kws.get('handle', None))
        for port in self.ports.values():
            if port.igmp_host_validate(host_handle):
                if mode in ["create"]:
                    grp = self.mgrps[group_pool_handle]
                    grp_ip_addr_start = grp.get("ip_addr_start")
                    grp_num_groups = grp.get("num_groups", "1")
                    src = self.msrcs[source_pool_handle]
                    src_ip_addr_start = src.get("ip_addr_start")
                    src_num_groups = src.get("num_groups", "1")
                else:
                    grp_ip_addr_start = None
                    grp_num_groups = "0"
                    src_ip_addr_start = None
                    src_num_groups = "0"
                kws["grp_ip_addr_start"] = grp_ip_addr_start
                kws["grp_num_groups"] = grp_num_groups
                kws["src_ip_addr_start"] = src_ip_addr_start
                kws["src_num_groups"] = src_num_groups
                res = port.emulation_igmp_group_config(*args, **kws)
                return self.trace_result(res)
        self.error("Invalid", "emulation_igmp_group_config: session_handle", host_handle)

    def exposed_tg_emulation_igmp_control(self, *args, **kws):
        self.trace_args(*args, **kws)
        mode = kws.get('mode', "start")
        if mode not in ["start", "stop", "join", "leave"]:
            self.error("Invalid", "emulation_igmp_control: mode", mode)
        host_handle = kws.get('handle', None)
        for port in self.ports.values():
            if port.igmp_host_validate(host_handle):
                res = port.emulation_igmp_control(*args, **kws)
                return self.trace_result(res)

    def exposed_tg_traffic_stats(self, *args, **kws):
        self.trace_args(*args, **kws)
        res = SpyTestDict()
        res["status"] = "1"
        res["waiting_for_stats"] = "0"
        port_handle = kws.get('port_handle', None)
        stream_id = kws.get('stream', None)
        mode = kws.get('mode', "aggregate")
        time.sleep(5)
        if mode == "aggregate" and stream_id:
            for port in self.ports.values():
                for stream, stats in port.getStreamStats():
                    if stream_id == stream.stream_id:
                        res[mode] = SpyTestDict()
                        self.fill_stats(res[mode], stats, stats, True)
        elif mode == "aggregate":
            if not port_handle or port_handle not in self.ports:
                self.error("Invalid", "port_handle", port_handle)
            stats = self.ports[port_handle].getStats()
            res[port_handle] = SpyTestDict()
            res[port_handle][mode] = SpyTestDict()
            self.fill_stats(res[port_handle][mode], stats, stats)
        elif mode == "traffic_item":
            res[mode] = SpyTestDict()
            for port in self.ports.values():
                #self.fill_stats(res[mode]["aggregate"], stats, stats)
                for stream, stats in port.getStreamStats():
                    stream_id = stream.stream_id
                    res[mode][stream_id] = SpyTestDict()
                    self.fill_stats(res[mode][stream_id], stats, stats)
        elif mode in ["stream", "streams"]:
            res[port_handle] = SpyTestDict()
            res[port_handle]["stream"] = SpyTestDict()
            for port in self.ports.values():
                for stream, stats in port.getStreamStats():
                    stream_id = stream.stream_id
                    res[port_handle]["stream"][stream_id] = SpyTestDict()
                    self.fill_stats(res[port_handle]["stream"][stream_id], stats, stats)
        elif mode == "flow":
            if not port_handle or port_handle not in self.ports:
                self.error("Invalid", "port_handle", port_handle)
            stats = self.ports[port_handle].getStats()
            tracking = SpyTestDict()
            tracking["count"] = "2"
            tracking["1"] = SpyTestDict()
            tracking["1"]["tracking_name"] = "Traffic_Item"
            tracking["1"]["tracking_value"] = "stream_id"
            tracking["2"] = SpyTestDict()
            tracking["2"]["tracking_name"] = "vlanId"
            tracking["2"]["tracking_value"] = "100"
            res[mode] = SpyTestDict()
            res[mode]["1"] = SpyTestDict()
            res[mode]["1"]["rx"] = SpyTestDict()
            res[mode]["1"]["pgid_value"] = 'N/A'
            res[mode]["1"]["tracking"] = tracking
            res[mode]["1"]["flow_name"] = 'stream id'
            res[mode]["1"]["tx"] = SpyTestDict()
            res[mode]["2"] = SpyTestDict()
            res[mode]["2"]["rx"] = SpyTestDict()
            res[mode]["2"]["pgid_value"] = 'N/A'
            res[mode]["2"]["tracking"] = tracking
            res[mode]["2"]["flow_name"] = 'stream id'
            res[mode]["2"]["tx"] = SpyTestDict()
            self.fill_stats(res[mode]["1"], stats, stats)
            self.fill_stats(res[mode]["2"], stats, stats)
        else:
             self.logger.todo("unhandled", "mode", mode)
        return self.trace_result(res)

    def stat_value(self, val, detailed=False):
        if not detailed:
            return val
        return {"count":val, "max":0, "min":0, "sum":0, "avg":0}

    def fill_stats(self, res, tx_stats, rx_stats, detailed=False):
        res["tx"] = SpyTestDict()
        res["tx"]["total_pkt_rate"] = self.stat_value(1, detailed)
        res["tx"]["raw_pkt_count"] = self.stat_value(tx_stats.framesSent, detailed)
        res["tx"]["pkt_byte_count"] = self.stat_value(tx_stats.bytesSent, detailed)
        res["tx"]["total_pkts"] = self.stat_value(tx_stats.framesSent, detailed)
        res["rx"] = SpyTestDict()
        res["rx"]["raw_pkt_rate"] = self.stat_value(1, detailed)
        res["rx"]["raw_pkt_count"] = self.stat_value(rx_stats.framesReceived, detailed)
        res["rx"]["pkt_byte_count"] = self.stat_value(rx_stats.bytesReceived, detailed)
        res["rx"]["total_pkts"] = self.stat_value(rx_stats.framesReceived, detailed)
        res["rx"]["oversize_count"] = self.stat_value(rx_stats.oversizeFramesReceived, detailed)

if __name__ == '__main__':
    Logger.setup()
    from ut_streams import ut_stream_get
    server = ScapyServer(True, dbg=3)
    res = server.exposed_tg_connect(port_list=["1/1", "1/2"])
    (tg_ph_1, tg_ph_2) = res.port_handle.values()
    kwargs = ut_stream_get(0, port_handle=tg_ph_1, mac_dst_mode='list', mac_dst=["00.00.00.00.00.02", "00.00.00.00.00.04"])
    #res1 = server.exposed_tg_traffic_config(**kwargs)
    #server.exposed_tg_traffic_control(action="run", handle=res1["stream_id"])
    server.exposed_tg_interface_config (arp_send_req='1', src_mac_addr='00:00:00:00:00:02',
             vlan=1, intf_ip_addr='192.168.12.2', port_handle='port-1/2', mode='config',
             gateway='192.168.12.1', vlan_id=64)


