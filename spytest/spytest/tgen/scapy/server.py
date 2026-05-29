import os
import sys
import copy
import json
import time
from datetime import datetime

from dicts import SpyTestDict
from port import ScapyPort
from logger import Logger
from utils import Utils
from stats import dhcpc_stats_aggregate_init
from stats import dhcpc_stats_session_init
from stats import dhcps_stats_aggregate_init


class ScapyServer(object):
    def __init__(self, dry=False, dbg=0, name="scpy-tgen"):
        self.node_name = ""
        self.dry = dry
        self.dbg = dbg
        self.errs = []
        self.ports = SpyTestDict()
        self.mgrps = SpyTestDict()
        self.msrcs = SpyTestDict()
        self.portmap = SpyTestDict()
        self.model = os.getenv("SCAPY_TGEN_PORTMAP", "eth0")
        self.count = int(os.getenv("SCAPY_TGEN_PORT_COUNT", "16"))
        logs_root = os.getenv("SCAPY_TGEN_LOGS_PATH", "/tmp/scapy-tgen")
        time_spec = datetime.utcnow().strftime("%Y_%m_%d_%H_%M_%S_%f")
        logs_path = "{}/inst-{}".format(logs_root, time_spec)
        self.logger = Logger(logs_dir=logs_path, dry=dry, name=name)
        self.portmap_init(self.model, self.count)
        self.logger.set_node_name(self.node_name, "init")
        self.utils = Utils(self.dry, logger=self.logger)
        self.utils.exec_cmd("ifconfig -a")
        if not dry:
            self.utils.exec_cmd("sysctl -w net.bridge.bridge-nf-call-arptables=0")
            self.utils.exec_cmd("sysctl -w net.bridge.bridge-nf-call-ip6tables=0")
            self.utils.exec_cmd("sysctl -w net.bridge.bridge-nf-call-iptables=0")

    def __del__(self):
        self.logger.debug("ScapyServer exiting...")
        self.cleanup_ports()
        self.ports = SpyTestDict()
        self.mgrps = SpyTestDict()
        self.msrcs = SpyTestDict()

    def trace_api(self, *args, **kws):
        self.logger.debug(self.node_name, args, kws)

    def cleanup_ports(self):
        for key in self.ports.keys():
            self.ports[key].cleanup()
        self.mgrps.clear()
        self.msrcs.clear()

    def portmap_init(self, model, count):
        count = count or self.count
        self.portmap.clear()
        for i in range(0, count):
            if model == "ens6":
                self.portmap["1/{}".format(i + 1)] = "ens{}".format(i + 6)
                self.portmap["{}".format(i + 1)] = "ens{}".format(i + 6)
            elif model == "eth0":
                self.portmap["1/{}".format(i + 1)] = "eth{}".format(i)
                self.portmap["{}".format(i + 1)] = "eth{}".format(i)
            elif model == "eth1":
                self.portmap["1/{}".format(i + 1)] = "eth{}".format(i + 1)
                self.portmap["{}".format(i + 1)] = "eth{}".format(i + 1)
            elif model == "vde":
                self.portmap["1/{}".format(i + 1)] = "vde{}".format(i)
                self.portmap["{}".format(i + 1)] = "vde{}".format(i)
            elif model == "TP":
                self.portmap["1/{}".format(i + 1)] = "TP{}".format(i + 1)
                self.portmap["{}".format(i + 1)] = "TP{}".format(i + 1)
            elif model == "TG":
                self.portmap["1/{}".format(i + 1)] = "TG{}".format(i + 1)
                self.portmap["{}".format(i + 1)] = "TG{}".format(i + 1)
            else:
                self.portmap["1/{}".format(i)] = "eth{}".format(i)
                self.portmap["{}".format(i)] = "eth{}".format(i)

    def trace_result(self, res, min_dbg=0, delay=0):
        if self.dbg >= min_dbg:
            self.logger.debug("RESULT: {}".format(json.dumps(res)))
        if delay:
            time.sleep(delay)
        return res

    def error(self, etype, name, value, no_abort=False):
        msg = "{}: {} = {}".format(etype, name, value)
        self.logger.error("=================== {} ==================".format(msg))
        self.errs.append(msg)
        if not no_abort:
            raise ValueError(msg)

    def validate_node_name(self, node_name, *args, **kws):
        func = sys._getframe(1).f_code.co_name
        # self.logger.debug("validate_node_name:", self.node_name, node_name, func, args, kws)
        self.logger.debug(node_name, func, args, kws)
        if node_name != self.node_name:
            self.logger.error("node name mismatch need {} got {} for func {}".format(self.node_name, node_name, func))
            return False
        return True

    def exposed_server_control(self, node_name, req, data, *args, **kws):
        func = sys._getframe(0).f_code.co_name
        # self.logger.debug(self.node_name, node_name, func, req, data, args, kws)
        self.logger.debug(node_name, func, req, data, args, kws)
        retval = ""
        if req == "set-name" and not self.node_name:
            self.node_name = data
            self.logger.set_node_name(self.node_name, "set-name")
            self.logger.info("setting node name {}".format(self.node_name))
            return retval
        if node_name != self.node_name:
            self.logger.error("node name mismatch need {} got {} for {}".format(self.node_name, node_name, req))
            return retval
        if req == "set-dbg-lvl":
            self.dbg = int(data)
        elif req == "set-dry-run":
            self.dry = data
        elif req == "set-max-pps":
            os.environ["SPYTEST_SCAPY_MAX_RATE_PPS"] = str(data)
        elif req == "set-env" and args:
            os.environ[str(data)] = str(args[0])
        elif req == "init-log":
            retval = self.logger.set_log_file(data)
            self.logger.banner(node_name, self.node_name, req, data)
        elif req == "read-log":
            retval = self.logger.get_log(data)
        elif req == "read-pcap":
            retval = self.logger.get_pcap(data)
        elif req == "add-log":
            self.logger.banner(node_name, self.node_name, req, data)
        elif req == "clean-all":
            for port in self.ports.values():
                port.clean_streams()
                try:
                    port.clean_interfaces()
                except Exception:
                    pass
        elif req == "get-alerts":
            errs = []
            errs.extend(self.errs)
            for port in self.ports.values():
                errs.extend(port.get_alerts())
            self.errs = []
            retval = "\n".join(errs)
        elif req == "set-model":
            self.portmap_init(data, None)
        else:
            self.error("Invalid", "server request", req)
        return retval

    def fix_port_name(self, pname):
        return pname.split("/")[-1].strip()

    def exposed_tg_connect(self, node_name, *args, **kws):
        if not self.validate_node_name(node_name, *args, **kws):
            return ""
        port_list = kws.get('port_list', [])
        res = SpyTestDict()
        res.port_handle = SpyTestDict()
        delete_ports = []
        for pname0 in port_list:
            pname = self.fix_port_name(pname0)
            for pobj in self.ports.values():
                if pobj.name == pname:
                    delete_ports.append(pobj)
            iface = self.portmap.get(pname)
            if not iface:
                self.error("Invalid", "port name", pname)
            pobj = ScapyPort(pname, self.portmap.get(pname), dry=self.dry,
                             dbg=self.dbg, logger=self.logger)
            self.ports[pobj.port_handle] = pobj
            res.port_handle[pname0] = pobj.port_handle
        for pobj in [x for x in delete_ports]:
            self.logger.debug("deleting handle {} iface {}".format(pobj.port_handle, pobj.iface))
            del pobj
        res.status = 1
        return self.trace_result(res)

    def exposed_tg_disconnect(self, node_name, *args, **kws):
        if not self.validate_node_name(node_name, *args, **kws):
            return ""
        res = SpyTestDict()
        self.cleanup_ports()
        res.status = 1
        return self.trace_result(res)

    def all_stream_handles(self):
        rv = []
        for port in self.ports.values():
            rv.extend(port.get_all_streams())
        return rv

    def get_handle_map(self, stream_handle):
        rev_map, missing, rv = {}, [], SpyTestDict()
        stream_handles = Utils.flatten_list(stream_handle, uniq=True)
        for handle in stream_handles:
            for port in self.ports.values():
                if not port.stream_validate(handle):
                    continue
                rev_map[handle] = port
                if port not in rv:
                    rv[port] = [handle]
                else:
                    rv[port].append(handle)
            if handle not in rev_map and handle not in missing:
                missing.append(handle)
        return rv, missing

    def port_traffic_control(self, port, complete, *args, **kws):
        if port.traffic_control(*args, **kws):
            handle = kws.pop('handle', None)
            complete.append([port, handle])

    def show_debug_stats(self, prefix=""):
        for port in self.ports.values():
            stats = port.getStats()
            msg = "{}{}: TX: {} RX: {}".format(prefix, port.name,
                                               stats.framesSent, stats.framesReceived)
            self.logger.debug(msg)
            for stream, stats in port.getStreamStats():
                msg = "    {}: TX: {} RX: {}".format(stream.stream_id,
                                                     stats.framesSent, stats.framesReceived)
                self.logger.debug(msg)

    def exposed_tg_traffic_control(self, node_name, *args, **kws):
        if not self.validate_node_name(node_name, *args, **kws):
            return ""
        action = Utils.kwargs_get_strip('action', None, **kws)
        handle = kws.pop('handle', None)
        port_handle = kws.pop('port_handle', None)
        stream_handle = kws.pop('stream_handle', None)
        res = True
        complete = []
        wait = 0

        if action in ["stop", "start", "run"]:
            self.show_debug_stats("PRE")

        if port_handle:
            phandle_list = Utils.make_list(port_handle, uniq=True)
            for phandle in phandle_list:
                port = self.ports[phandle]
                wait = wait + 2
                self.port_traffic_control(port, complete, *args, **kws)
        elif handle or stream_handle:
            handle_map, missing = self.get_handle_map(handle or stream_handle)
            if missing:
                msg = "{} \n should be one of {}".format(missing, self.all_stream_handles())
                self.error("invalid", "stream(s)", msg)
            for port, handle_list in handle_map.items():
                for handle in handle_list:
                    kws["handle"] = handle
                    wait = wait + 2
                    self.port_traffic_control(port, complete, *args, **kws)
        else:
            for port in self.ports.values():
                wait = wait + 2
                self.port_traffic_control(port, complete, *args, **kws)

        # call complete callback
        for port, handle in complete:
            if not handle:
                kws.pop("handle", "")
            else:
                kws["handle"] = handle
            port.traffic_control_complete(*args, **kws)

        # wait for stats
        time.sleep(wait)

        if action in ["stop", "start", "run"]:
            self.show_debug_stats("POST")

        return self.trace_result(res)

    def ensure_port_handle(self, port_handle):
        if not port_handle:
            msg = "port_handle is not specified"
            raise ValueError(self.logger.error(msg))
        if port_handle not in self.ports:
            msg = "port_handle {} is not valid".format(port_handle)
            raise ValueError(self.logger.error(msg))
        return self.ports[port_handle]

    def exposed_tg_interface_control(self, node_name, *args, **kws):
        if not self.validate_node_name(node_name, *args, **kws):
            return ""
        port_handle = kws.get('port_handle', None)
        port = self.ensure_port_handle(port_handle)
        mode = Utils.kwargs_get_strip('mode', "aggregate", **kws)
        if mode == "break_link":
            port.set_admin_status(False)
            return True
        elif mode == "restore_link":
            port.set_admin_status(True)
            return True
        elif mode == "check_link":
            return port.get_admin_status()
        self.error("Invalid", "mode", mode)

    def exposed_tg_packet_control(self, node_name, *args, **kws):
        if not self.validate_node_name(node_name, *args, **kws):
            return ""
        port_handle = kws.get('port_handle', None)
        if not port_handle:
            msg = "port_handle is not specified"
            raise ValueError(self.logger.error(msg))

        res = True
        for phandle in Utils.make_list(port_handle, uniq=True):
            port = self.ports[phandle]
            res = res and port.packet_control(*args, **kws)
        return self.trace_result(res)

    def exposed_tg_packet_stats(self, node_name, *args, **kws):
        if not self.validate_node_name(node_name, *args, **kws):
            return ""
        res = SpyTestDict()
        port_handle = kws.get('port_handle', None)
        mode = Utils.kwargs_get_strip('mode', "aggregate", **kws)
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

    def exposed_tg_traffic_config(self, node_name, *args, **kws):
        if not self.validate_node_name(node_name, *args, **kws):
            return ""
        port_handle = kws.get('port_handle', None)
        stream_id = kws.get('stream_id', None)
        port_handle2 = kws.get('port_handle2', None)
        validate_stream_id = True

        # check if track port is specified
        track_ports = []
        for phandle in Utils.make_list(port_handle2 or [], uniq=True):
            if phandle not in self.ports:
                self.error("Invalid", "port_handle2", phandle)
            else:
                track_ports.append(self.ports[phandle])

        # get the port handle from stream if not specified
        if not port_handle and stream_id:
            port_handle = []
            handle_map, missing = self.get_handle_map(stream_id)
            if missing:
                msg = "{} \n should be one of {}".format(missing, self.all_stream_handles())
                self.error("invalid", "stream(s)", msg)
            validate_stream_id = False
            for phandle, port in self.ports.items():
                if port in handle_map and phandle not in port_handle:
                    port_handle.append(phandle)

        # bailout: we must have port handle
        if not port_handle:
            msg = "port_handle is not specified"
            raise ValueError(self.logger.error(msg))

        # validate src emulation handle before adding stream
        emulation_src_handle = kws.get('emulation_src_handle', None)
        if emulation_src_handle:
            intf = self.find_emulation_intf(emulation_src_handle)
            if not intf:
                self.error("Invalid", "emulation_src_handle", emulation_src_handle)
            else:
                kws["emulation_src_handle"] = intf

        # validate dst emulation handle before adding stream
        emulation_dst_handle = kws.get('emulation_dst_handle', None)
        if emulation_dst_handle:
            intf = self.find_emulation_intf(emulation_dst_handle)
            if not intf:
                self.error("Invalid", "emulation_dst_handle", emulation_dst_handle)
            else:
                kws["emulation_dst_handle"] = intf

        # all well add stream to port
        res = SpyTestDict()
        for phandle in Utils.make_list(port_handle, uniq=True):
            if phandle not in self.ports:
                self.error("Invalid", "port_handle", phandle)
            else:
                port = self.ports[phandle]
                rv = port.traffic_config(track_ports, validate_stream_id, *args, **kws)
                res.update(rv)

        return self.trace_result(res)

    def find_emulation_intf(self, handle):
        if isinstance(handle, list):
            handle = handle[0]
        if handle in self.mgrps:
            return self.mgrps[handle]
        for port in self.ports.values():
            intf = port.find_interface(handle)
            if intf:
                return port.validate_interface(intf)
        return None

    def get_all_handles(self):
        rv = {}
        for port in self.ports.values():
            for handle in port.get_all_handles():
                rv[handle] = port
        return rv

    def get_port_list(self, port_handle, param_name):
        port_list = []
        for phandle in Utils.make_list(port_handle or [], uniq=True):
            if phandle not in self.ports:
                self.error("Invalid", param_name, phandle)
            else:
                port_list.append(self.ports[phandle])
        return port_list

    def verify_handle(self, no_abort, *args, **kws):
        port_handle = kws.get('port_handle', None)
        protocol_handle = kws.get('protocol_handle', None)
        handle = kws.get('handle', None)
        if not protocol_handle and not port_handle and not handle:
            msg = "Neither handle nor port_handle specified"
            raise ValueError(self.logger.error(msg))
        if port_handle:
            return self.get_port_list(port_handle, "port_handle")

        intfs = self.get_all_handles()
        if protocol_handle:
            handle = protocol_handle
        if isinstance(handle, list):
            handle = handle[0]
        if handle in intfs:
            return [intfs[handle]]

        self.logger.info("valid interfaces: {}".format(intfs.keys()))
        if protocol_handle:
            self.error("Invalid", "protocol_handle", protocol_handle, no_abort)
        else:
            self.error("Invalid", "handle", handle, no_abort)

    def exposed_tg_interface_config(self, node_name, *args, **kws):
        if not self.validate_node_name(node_name, *args, **kws):
            return ""
        res = True
        mode = Utils.kwargs_get_strip('mode', None, **kws)
        for port in self.verify_handle(bool(mode == "destroy"), *args, **kws):
            res = res and port.interface_config(*args, **kws)
        if res:
            time.sleep(2)
        return self.trace_result(res)

    def exposed_tg_emulation_bgp_config(self, node_name, *args, **kws):
        if not self.validate_node_name(node_name, *args, **kws):
            return ""
        res = True
        for port in self.verify_handle(False, *args, **kws):
            res = res and port.emulation_bgp_config(*args, **kws)
        if res:
            time.sleep(2)
        return self.trace_result(res)

    def exposed_tg_emulation_bgp_route_config(self, node_name, *args, **kws):
        if not self.validate_node_name(node_name, *args, **kws):
            return ""
        res = True
        for port in self.verify_handle(False, *args, **kws):
            res = res and port.emulation_bgp_route_config(*args, **kws)
        if res:
            time.sleep(2)
        return self.trace_result(res)

    def exposed_tg_emulation_bgp_control(self, node_name, *args, **kws):
        if not self.validate_node_name(node_name, *args, **kws):
            return ""
        res = True
        for port in self.verify_handle(False, *args, **kws):
            res = res and port.emulation_bgp_control(*args, **kws)
        if res:
            time.sleep(2)
        return self.trace_result(res)

    def exposed_tg_emulation_multicast_group_config(self, node_name, *args, **kws):
        if not self.validate_node_name(node_name, *args, **kws):
            return ""
        mode = Utils.kwargs_get_strip('mode', "create", **kws)
        index = len(self.mgrps)
        if mode == "create":
            group = SpyTestDict()
            group.kws = copy.copy(kws)
            group.index = index
            group.name = "mgrp-{}".format(group.index)
            self.mgrps[group.name] = group
            res = SpyTestDict()
            res["status"] = "1"
            res["handle"] = group.name
            res["mul_group_handle"] = group.name
            res["multicast_group_handle"] = group.name
            return self.trace_result(res)
        self.error("Invalid", "emulation_multicast_group_config: mode", mode)

    def exposed_tg_emulation_multicast_source_config(self, node_name, *args, **kws):
        if not self.validate_node_name(node_name, *args, **kws):
            return ""
        mode = Utils.kwargs_get_strip('mode', "create", **kws)
        index = len(self.msrcs)
        if mode == "create":
            source = SpyTestDict()
            source.kws = copy.copy(kws)
            source.index = index
            source.name = "msrc-{}".format(source.index)
            self.msrcs[source.name] = source
            res = SpyTestDict()
            res["status"] = "1"
            res["handle"] = source.name
            res["mul_source_handle"] = source.name
            res["multicast_source_handle"] = source.name
            return self.trace_result(res)
        self.error("Invalid", "emulation_multicast_source_config: mode", mode)

    def exposed_tg_emulation_igmp_config(self, node_name, *args, **kws):
        if not self.validate_node_name(node_name, *args, **kws):
            return ""
        for port in self.ports.values():
            res = port.emulation_igmp_config(*args, **kws)
            if res:
                return self.trace_result(res, delay=2)
        self.error("Invalid", "exposed_tg_emulation_igmp_config", kws)
        return {}

    def exposed_tg_emulation_igmp_group_config(self, node_name, *args, **kws):
        if not self.validate_node_name(node_name, *args, **kws):
            return ""
        mode = Utils.kwargs_get_strip('mode', "create", **kws)
        if mode not in ["create", "clear_all"]:
            self.error("Invalid", "emulation_igmp_group_config: mode", mode)
        elif mode in ["create"]:
            group_pool_handle = kws.get('group_pool_handle', None)
            for ph in Utils.make_list(group_pool_handle):
                if ph not in self.mgrps:
                    self.error("Invalid", "emulation_igmp_group_config: group_pool_handle", ph)
            source_pool_handle = kws.get('source_pool_handle', None)
            if source_pool_handle:
                for ph in Utils.make_list(source_pool_handle):
                    if ph not in self.msrcs:
                        self.error("Invalid", "emulation_igmp_group_config: source_pool_handle", ph)
        host_handle = kws.get('session_handle', kws.get('handle', None))
        for port in self.ports.values():
            if not port.igmp_host_validate(host_handle):
                continue
            kws["group_pool_data"] = []
            kws["source_pool_data"] = []
            if mode in ["create"]:
                for ph in Utils.make_list(group_pool_handle):
                    grp = copy.copy(self.mgrps[group_pool_handle])
                    grp.enable = True
                    kws["group_pool_data"].append(grp)
                if source_pool_handle:
                    for ph in Utils.make_list(source_pool_handle):
                        src = copy.copy(self.msrcs[source_pool_handle])
                        src.enable = True
                        kws["source_pool_data"].append(src)
            res = port.emulation_igmp_group_config(*args, **kws)
            return self.trace_result(res)
        self.error("Invalid", "emulation_igmp_group_config: session_handle", host_handle)

    def exposed_tg_emulation_igmp_querier_config(self, node_name, *args, **kws):
        if not self.validate_node_name(node_name, *args, **kws):
            return ""
        res = {}
        for port in self.ports.values():
            res.update(port.emulation_igmp_querier_config(*args, **kws))
        if res:
            time.sleep(2)
        else:
            self.error("Invalid", "exposed_tg_emulation_igmp_querier_config", kws)
        return self.trace_result(res)

    def exposed_tg_emulation_igmp_control(self, node_name, *args, **kws):
        if not self.validate_node_name(node_name, *args, **kws):
            return ""
        mode = Utils.kwargs_get_strip('mode', "start", **kws)
        if mode not in ["start", "stop", "join", "leave"]:
            self.error("Invalid", "exposed_tg_emulation_igmp_control: mode", mode)
        handle = kws.get('handle', None)
        if not handle:
            self.error("Invalid", "exposed_tg_emulation_igmp_control: handle", handle)
        for port in self.ports.values():
            res = port.emulation_igmp_control(*args, **kws)
            if res:
                return self.trace_result(res, delay=2)
        self.error("Invalid", "exposed_tg_emulation_igmp_control", kws)
        return {}

    def exposed_tg_emulation_igmp_querier_control(self, node_name, *args, **kws):
        if not self.validate_node_name(node_name, *args, **kws):
            return ""
        for port in self.ports.values():
            res = port.emulation_igmp_querier_control(*args, **kws)
            if res:
                return self.trace_result(res, delay=2)
        self.error("Invalid", "exposed_tg_emulation_igmp_querier_control", kws)

    def exposed_tg_emulation_ospf_config(self, node_name, *args, **kws):
        if not self.validate_node_name(node_name, *args, **kws):
            return ""
        for port in self.ports.values():
            res = port.emulation_ospf_config(*args, **kws)
            if res:
                return self.trace_result(res, delay=2)
        return {}

    def exposed_tg_emulation_ospf_control(self, node_name, *args, **kws):
        if not self.validate_node_name(node_name, *args, **kws):
            return ""
        for port in self.ports.values():
            res = port.emulation_ospf_control(*args, **kws)
            if res:
                return self.trace_result(res, delay=2)
        return {}

    def exposed_tg_emulation_ospf_route_config(self, node_name, *args, **kws):
        if not self.validate_node_name(node_name, *args, **kws):
            return ""
        for port in self.ports.values():
            res = port.emulation_ospf_route_config(*args, **kws)
            if res:
                return self.trace_result(res, delay=2)
        return {}

    def exposed_tg_emulation_ospf_lsa_config(self, node_name, *args, **kws):
        if not self.validate_node_name(node_name, *args, **kws):
            return ""
        self.error("unsupported", "api", "tg_emulation_ospf_lsa_config")

    def exposed_tg_emulation_ospf_network_group_config(self, node_name, *args, **kws):
        if not self.validate_node_name(node_name, *args, **kws):
            return ""
        self.error("unsupported", "api", "tg_emulation_ospf_network_group_config")

    def exposed_tg_emulation_ospf_topology_route_config(self, node_name, *args, **kws):
        if not self.validate_node_name(node_name, *args, **kws):
            return ""
        self.error("unsupported", "api", "tg_emulation_ospf_topology_route_config")

    def exposed_tg_emulation_dhcp_config(self, node_name, *args, **kws):
        if not self.validate_node_name(node_name, *args, **kws):
            return ""
        port_handle = kws.get('port_handle', None)
        if not port_handle or port_handle not in self.ports:
            self.error("Invalid", "port_handle", port_handle)
        port = self.ports[port_handle]
        return port.emulation_dhcp_client_config(*args, **kws)

    def exposed_tg_emulation_dhcp_group_config(self, node_name, *args, **kws):
        if not self.validate_node_name(node_name, *args, **kws):
            return ""
        for port in self.ports.values():
            res = port.emulation_dhcp_client_group_config(*args, **kws)
            if res:
                return self.trace_result(res, delay=2)
        return {}

    def exposed_tg_emulation_dhcp_control(self, node_name, *args, **kws):
        if not self.validate_node_name(node_name, *args, **kws):
            return ""
        port_handle = kws.get('port_handle', None)
        if port_handle and port_handle in self.ports:
            port = self.ports[port_handle]
            return port.emulation_dhcp_client_control(*args, **kws)
        for port in self.ports.values():
            res = port.emulation_dhcp_client_control(*args, **kws)
            if res:
                return self.trace_result(res, delay=2)
        return {}

    def exposed_tg_emulation_dhcp_server_config(self, node_name, *args, **kws):
        if not self.validate_node_name(node_name, *args, **kws):
            return ""
        for port in self.ports.values():
            res = port.emulation_dhcp_server_config(*args, **kws)
            if res:
                return self.trace_result(res, delay=2)
        return {}

    def exposed_tg_emulation_dhcp_server_control(self, node_name, *args, **kws):
        if not self.validate_node_name(node_name, *args, **kws):
            return ""
        for port in self.ports.values():
            res = port.emulation_dhcp_server_control(*args, **kws)
            if res:
                return self.trace_result(res, delay=2)
        return {}

    def exposed_tg_emulation_dhcp_server_stats(self, node_name, *args, **kws):
        if not self.validate_node_name(node_name, *args, **kws):
            return ""
        res = SpyTestDict()
        mode = Utils.kwargs_get_strip('mode', "aggregate", **kws)
        if mode not in ["aggregate_stats", "aggregate"]:
            self.error("Invalid", "mode", mode)
        action = Utils.kwargs_get_strip('action', "get", **kws)
        if action not in ["clear", "collect"]:
            self.error("Invalid", "action", action)
        port_handle = kws.get('port_handle', None)
        if mode in ["aggregate_stats", "aggregate"]:
            res["aggregate"] = SpyTestDict()
            res["aggregate"][port_handle] = dhcps_stats_aggregate_init(port_handle)

        return self.trace_result(res)

    def exposed_tg_emulation_dhcp_server_relay_agent_config(self, node_name, *args, **kws):
        if not self.validate_node_name(node_name, *args, **kws):
            return ""
        for port in self.ports.values():
            res = port.emulation_dhcp_server_relay_agent_config(*args, **kws)
            if res:
                return self.trace_result(res, delay=2)
        return {}

    def exposed_tg_emulation_dhcp_stats(self, node_name, *args, **kws):
        if not self.validate_node_name(node_name, *args, **kws):
            return ""
        action = Utils.kwargs_get_strip('action', "get", **kws)
        mode = Utils.kwargs_get_strip('mode', "aggregate", **kws)
        port_handle = kws.get('port_handle', None)
        if mode not in ["detailed_session", "session", "aggregate_stats", "aggregate"]:
            self.error("Invalid", "mode", mode)
        res = SpyTestDict()

        if action == "clear":
            # todo
            pass
        elif mode in ["aggregate_stats", "aggregate"]:
            values = dhcpc_stats_aggregate_init(port_handle)
            res[port_handle] = SpyTestDict()
            res[port_handle]["aggregate"] = values
            res["aggregate"] = copy.copy(values)
        else:
            if port_handle in self.ports:
                port = self.ports[port_handle]
                res["session"] = SpyTestDict()
                for client in port.dhcp_clients.values():
                    for group_handle in client.groups:
                        res["session"][group_handle] = dhcpc_stats_session_init(group_handle)

        return self.trace_result(res)

    def fill_traffic_item_streams(self, port, report_streams, dbg_msgs, rev=False):
        for p in self.ports.values():
            for stream, stats in p.getStreamStats():
                for track_port in stream.track_ports:
                    dbg_msgs.append("{} tracking {}".format(stream.stream_id, track_port.port_handle))
                    if track_port == port:
                        if rev:
                            if self.dbg > 3:
                                report_streams.append([stream, stats, stats, port])
                            else:
                                report_streams.append([stream, port.getStats(), stats, port])
                        else:
                            if self.dbg > 3:
                                report_streams.append([stream, stats, stats, port])
                            else:
                                report_streams.append([stream, stats, port.getStats(), port])

    def exposed_tg_traffic_stats(self, node_name, *args, **kws):
        if not self.validate_node_name(node_name, *args, **kws):
            return ""
        res = SpyTestDict()
        res["status"] = "1"
        res["waiting_for_stats"] = "0"
        port_handle = kws.get('port_handle', list(self.ports.keys()))
        port_handles = Utils.make_list(port_handle)
        for port_handle in port_handles:
            if port_handle not in self.ports:
                self.error("Invalid", "port_handle", port_handle)
                continue
            port = self.ports[port_handle]
            mode = Utils.kwargs_get_strip('mode', "aggregate", **kws)
            time.sleep(5)
            if mode == "aggregate":
                stats = port.getStats()
                res[port_handle] = SpyTestDict()
                res[port_handle][mode] = SpyTestDict()
                res[port_handle]["name"] = port.iface
                self.fill_stats(res[port_handle][mode], stats, stats, port=port)
            elif mode == "traffic_item_0":
                res[mode] = SpyTestDict()
                for stream, stats in port.getStreamStats():
                    res[mode][stream.stream_id] = SpyTestDict()
                    self.fill_stats(res[mode][stream.stream_id], stats, stats, stream=stream)
                    for track_port in stream.track_ports:
                        for stream, stats in track_port.getStreamStats():
                            res[mode][stream.stream_id] = SpyTestDict()
                            self.fill_stats(res[mode][stream.stream_id], stats, stats, stream=stream)
            elif mode == "traffic_item":
                res[mode] = SpyTestDict()

                # identify the streams where given port is track port
                report_streams, dbg_msgs = [], []
                self.fill_traffic_item_streams(port, report_streams, dbg_msgs)
                for stream, _ in port.getStreamStats():
                    for track_port in stream.track_ports:
                        self.fill_traffic_item_streams(track_port, report_streams, dbg_msgs, True)
                if not report_streams:
                    self.logger.error("No traffic item identified for {}".format(port_handle))
                    for msg in dbg_msgs:
                        self.logger.error("CHK: {}".format(msg))

                # add the stats of the identified streams
                for stream, tx_stats, rx_stats, rx_port in report_streams:
                    if stream.stream_id in res[mode]:
                        self.logger.warning("Already Filled {}".format(stream.stream_id))
                        continue
                    res[mode][stream.stream_id] = SpyTestDict()
                    self.fill_stats(res[mode][stream.stream_id], tx_stats,
                                    rx_stats, port=rx_port, stream=stream)
                    # self.logger.error("RESULT", res)

            elif mode in ["stream", "streams"]:
                streams = Utils.make_list(kws.get('streams', []))
                rv, stats_list = self.fill_streams(res, port, streams)
                if not rv:
                    self.error("no-matching-stream", streams, stats_list)
            elif mode == "flow":
                stats = port.getStats()
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
                self.fill_stats(res[mode]["1"], stats, stats, port=port)
                self.fill_stats(res[mode]["2"], stats, stats, port=port)
            else:
                self.logger.todo("unhandled", "mode", mode)
        return self.trace_result(res)

    def stat_value(self, val, detailed=False):
        if not detailed:
            return val
        return {"count": val, "max": 0, "min": 0, "sum": 0, "avg": 0}

    def fill_stats(self, res, tx_stats, rx_stats, detailed=False, port=None, stream=None):
        if tx_stats:
            res["tx"] = SpyTestDict()
            # TODO compute the total_pkt_rate
            res["tx"]["total_pkt_rate"] = self.stat_value(1, detailed)
            res["tx"]["raw_pkt_count"] = self.stat_value(tx_stats.framesSent, detailed)
            res["tx"]["pkt_byte_count"] = self.stat_value(tx_stats.bytesSent, detailed)
            res["tx"]["total_pkts"] = self.stat_value(tx_stats.framesSent, detailed)
            res["tx"]["name"] = stream.stream_id if stream else ""
        if rx_stats:
            res["rx"] = SpyTestDict()
            # TODO compute the raw_pkt_rate
            res["rx"]["total_pkt_rate"] = self.stat_value(1, detailed)
            res["rx"]["raw_pkt_rate"] = self.stat_value(1, detailed)
            res["rx"]["raw_pkt_count"] = self.stat_value(rx_stats.framesReceived, detailed)
            res["rx"]["pkt_byte_count"] = self.stat_value(rx_stats.bytesReceived, detailed)
            res["rx"]["total_pkts"] = self.stat_value(rx_stats.framesReceived, detailed)
            res["rx"]["oversize_count"] = self.stat_value(rx_stats.oversizeFramesReceived, detailed)
            res["rx"]["name"] = port.port_handle if port else ""

    def fill_streams(self, res, port, stream_id_list=None):
        # stats = port.getStats()
        # self.logger.error("PORT", port.port_handle, stats)
        retval, stats_list = False, port.getStreamStats()
        for stream, stats in stats_list:
            if stream_id_list and stream.stream_id not in stream_id_list:
                continue
            retval = True
            # self.logger.error("STREAM", stream.stream_id, stats)
            res1 = res.setdefault(port.port_handle, SpyTestDict())
            res2 = res1.setdefault("stream", SpyTestDict())
            res3 = res2.setdefault(stream.stream_id, SpyTestDict())
            self.fill_stats(res3, stats, None, stream=stream)
            # self.logger.error("RESULT-1", res)
            for track_port in stream.track_ports:
                res4 = res.setdefault(track_port.port_handle, SpyTestDict())
                res4["name"] = track_port.iface
                res5 = res4.setdefault("stream", SpyTestDict())
                res6 = res5.setdefault(stream.stream_id, SpyTestDict())
                stats = track_port.getStats()
                # self.logger.error("TRACK-PORT", track_port.port_handle, stats)
                self.fill_stats(res6, None, stats, port=track_port)
                # self.logger.error("RESULT-2", res)
                # for stream2, stats in track_port.getStreamStats():
                # self.logger.error("TRACK-STREAM", stream2.stream_id, stats)

        return retval, stats_list

    def exposed_tg_custom_filter_config(self, node_name, *args, **kws):
        self.error("unsupported", "api", "tg_custom_filter_config")

    def exposed_tg_emulation_dot1x_config(self, node_name, *args, **kws):
        if not self.validate_node_name(node_name, *args, **kws):
            return ""
        for port in self.ports.values():
            res = port.emulation_dot1x_config(*args, **kws)
            if res:
                return self.trace_result(res, delay=2)
        self.error("Invalid", "exposed_tg_emulation_dot1x_config", kws)
        return {}

    def exposed_tg_emulation_dot1x_control(self, node_name, *args, **kws):
        if not self.validate_node_name(node_name, *args, **kws):
            return ""
        for port in self.ports.values():
            res = port.emulation_dot1x_control(*args, **kws)
            if res:
                return self.trace_result(res, delay=2)
        self.error("Invalid", "exposed_tg_emulation_dot1x_control", kws)
        return {}

    def exposed_tg_emulation_mld_config(self, node_name, *args, **kws):
        self.error("unsupported", "api", "tg_emulation_mld_config")

    def exposed_tg_emulation_mld_group_config(self, node_name, *args, **kws):
        self.error("unsupported", "api", "tg_emulation_mld_group_config")

    def exposed_tg_emulation_mld_querier_config(self, node_name, *args, **kws):
        self.error("unsupported", "api", "tg_emulation_mld_querier_config")

    def exposed_tg_emulation_mld_control(self, node_name, *args, **kws):
        self.error("unsupported", "api", "tg_emulation_mld_control")

    def exposed_tg_emulation_mld_querier_control(self, node_name, *args, **kws):
        self.error("unsupported", "api", "tg_emulation_mld_querier_control")

    def exposed_tg_emulation_ipv6_autoconfig(self, node_name, *args, **kws):
        self.error("unsupported", "api", "tg_emulation_ipv6_autoconfig")

    def exposed_tg_emulation_ipv6_autoconfig_control(self, node_name, *args, **kws):
        self.error("unsupported", "api", "tg_emulation_ipv6_autoconfig_control")
