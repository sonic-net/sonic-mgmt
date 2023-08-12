import os
import sys
import copy
import time
import logging
from collections import OrderedDict

from spytest import paths


class ScapyClient(object):

    def __init__(self, logger, tg_ip=None, tg_port=8009, tg_port_list=None, base=None):
        self.base = base
        self.conn = None
        self.logger = logger or logging.getLogger()
        self.use_pyro = True
        self.use_pyro_ns = False
        self.node_name = ""
        self.filemode = bool(os.getenv("SPYTEST_FILE_MODE", "0") != "0")
        self.tg_ip = tg_ip
        self.tg_port = tg_port
        self.tg_port_list = tg_port_list or []
        self.tg_port_handle = OrderedDict()

        root = os.path.join(os.path.dirname(__file__), '..')
        root = os.path.abspath(root)
        sys.path.append(os.path.join(root))

    def _set_port_handle(self, port, value):
        if self.base:
            self.base.set_port_handle(port, value)
        elif not port:
            self.tg_port_handle.clear()
        else:
            self.tg_port_handle[port] = value

    def _log_call(self, fname, **kwargs):
        if self.base:
            self.base.log_call(fname, **kwargs)
        else:
            opts = ', '.join(['{}={!r}'.format(k, v) for k, v in kwargs.items()])
            self.logger.info("REQ: {} {}".format(fname, opts))

    def _log_resp(self, fname, text):
        if self.base:
            self.base.log_resp(fname, text)
        else:
            self.logger.info("RESP: {} {}".format(fname, text))

    def _save_log(self, name, data):
        if self.base:
            self.base.save_log(name, data)
        else:
            self.logger.info("TODO {} {}".format(name, data))

    def _api_fail(self, msg):
        if self.base:
            self.base.api_fail(msg)
        else:
            self.logger.info("TODO {}".format(msg))

    def _log_info(self, *args):
        self.logger.info(*args)

    def log_remote_alerts(self, phase):
        func_name = "server_control"
        errs1 = "==================== REMOTE ALERTS ============================"
        errs2 = self._execute(func_name, self.conn.server_control, "get-alerts", "")
        errs3 = "==============================================================="
        if errs2.strip():
            msg = "\n".join(["\n", errs1, errs2, errs3, "\n"])
            self.logger.info(msg)
            if self.base:
                self.base.alert(msg)

    def server_control(self, phase, context):
        func_name = "server_control"
        if self.filemode:
            return
        elif phase == "clean-all":
            self._log_info("ScapyClient instrument: {} {}".format(phase, context))
            self._execute(func_name, self.conn.server_control, "clean-all", "")
        elif phase in ["pre-test", "pre-function-prolog"]:
            self._log_info("ScapyClient instrument: {} {}".format(phase, context))
            self._execute(func_name, self.conn.server_control, "add-log", "test-start {} {}".format(context, self.node_name))
            self.log_remote_alerts(phase)
        elif phase in ["post-test", "post-function-epilog"]:
            self._log_info("ScapyClient instrument: {} {}".format(phase, context))
            self._execute(func_name, self.conn.server_control, "add-log", "test-finish {} {}".format(context, self.node_name))
            self.log_remote_alerts(phase)
        elif phase == "pre-module-prolog":
            self._log_info("ScapyClient instrument: {} {}".format(phase, context))
            local_file = paths.get_mtgen_path(context)
            path = self._execute(func_name, self.conn.server_control, "init-log", local_file)
            self.logger.info("Server Logs Path {}".format(path))
            self.log_remote_alerts(phase)
        elif phase == "post-module-epilog":
            local_file = paths.get_mtgen_path(context)
            self._log_info("ScapyClient instrument ({}): {} {}".format(context, phase, local_file))
            try:
                data = self._execute(func_name, self.conn.server_control, "read-log", local_file)
                self._save_log(local_file, data)
            except Exception as exp:
                self._log_info("Failed to read log {} {}".format(context, str(exp)))
            try:
                local_file = local_file.replace(".tgen", ".pcap")
                data = self._execute(func_name, self.conn.server_control, "read-pcap", local_file)
                self._save_log(local_file, data)
            except Exception as exp:
                self._log_info("Failed to read pcap {} {}".format(context, str(exp)))
            self.log_remote_alerts(phase)
        else:
            self._log_info("ScapyClient instrument: ignored {} {}".format(phase, context))

    def rpyc_connect(self):
        import rpyc
        try:
            config = {"allow_pickle": True, "sync_request_timeout": 300,
                      "allow_public_attrs": True, "allow_all_attrs": True,
                      "instantiate_oldstyle_exceptions": True}
            return rpyc.connect(self.tg_ip, self.tg_port, config=config)
        except Exception as e:
            print(e)
            raise ValueError("Failed to connect to scapy server {}".format(e))

    def pyro_connect(self):
        import Pyro4
        if self.use_pyro_ns:
            uri = "PYRONAME:scapy-tgen@{}".format(self.tg_ip)
        else:
            uri = "PYRO:scapy-tgen@{}:{}".format(self.tg_ip, self.tg_port)
        Pyro4.config.SERIALIZER = "serpent"
        Pyro4.config.SERIALIZER = "pickle"
        Pyro4.config.PICKLE_PROTOCOL_VERSION = 2
        conn = Pyro4.Proxy(uri)
        import uuid
        conn._pyroHandshake = uuid.uuid4()
        conn._pyroBind()
        return conn

    def scapy_disconnect(self, dry_run=False):
        if self.filemode:
            return None

        if self.use_pyro:
            pass
        else:
            self.conn2.close()

    def scapy_connect(self, dry_run=False):
        self.tg_ns = 'scapy'

        if self.filemode:
            return None

        last_exception = None
        for _ in range(5):
            try:
                if self.use_pyro:
                    self.conn = self.pyro_connect()
                else:
                    self.conn2 = self.rpyc_connect()
                    self.conn = self.conn2.root
                last_exception = None
                break
            except Exception as exp:
                last_exception = exp
                time.sleep(10)
        if last_exception is not None:
            retval = {"status": "Failed to connect: {}".format(last_exception)}
            self.logger.warning(retval["status"])
            return retval

        try:
            dbg_lvl = int(os.getenv("SPYTEST_SCAPY_DBG_LVL", "1"))
        except Exception:
            dbg_lvl = 1
        try:
            max_pps = int(os.getenv("SPYTEST_SCAPY_MAX_PPS", "100"))
        except Exception:
            max_pps = 100
        model = os.getenv("SCAPY_TGEN_PORTMAP", "eth1")
        self.node_name = os.getenv("PYTEST_XDIST_WORKER", "")
        func_name = "server_control"
        last_exception = None
        for _ in range(5):
            try:
                self._execute(func_name, self.conn.server_control, "set-name", self.node_name)
                last_exception = None
                break
            except Exception as exp:
                last_exception = exp
                time.sleep(10)
        if last_exception is not None:
            retval = {"status": "Failed to connect: {}".format(last_exception)}
            self.logger.warning(retval["status"])
            return retval
        path = self._execute(func_name, self.conn.server_control, "init-log", "default.log")
        self.logger.info("Server Logs Path {}".format(path))
        self._execute(func_name, self.conn.server_control, "set-dbg-lvl", dbg_lvl)
        self._execute(func_name, self.conn.server_control, "set-dry-run", dry_run)
        self._execute(func_name, self.conn.server_control, "set-max-pps", max_pps)
        self._execute(func_name, self.conn.server_control, "set-model", model)
        self._execute(func_name, self.conn.server_control, "set-env",
                      "SPYTEST_SCAPY_DOT1X_IMPL", os.getenv("SPYTEST_SCAPY_DOT1X_IMPL", "1"))
        self._execute(func_name, self.conn.server_control, "set-env",
                      "SPYTEST_SCAPY_USE_BRIDGE", os.getenv("SPYTEST_SCAPY_USE_BRIDGE", "1"))
        res = self.tg_connect(port_list=self.tg_port_list)
        self._set_port_handle(None, None)
        for port in self.tg_port_list:
            self._set_port_handle(port, res['port_handle'][port])
        return None

    def log_api(self, *args, **kwargs):
        func = sys._getframe(1).f_code.co_name
        self._log_call(func, **kwargs)

    def fix_dict_values(self, kwargs):
        for key, value in kwargs.items():
            if type(value) is {}.values().__class__:
                if value != list(value):
                    self._log_info("TGen -- Change {} from {} to {}".format(key, value, list(value)))
                kwargs[key] = list(value)
            elif type(value) is {}.keys().__class__:
                if value != list(value):
                    self._log_info("TGen --- Change {} from {} to {}".format(key, value, list(value)))
                kwargs[key] = list(value)
            elif isinstance(value, int):
                kwargs[key] = str(value)
            elif isinstance(value, float):
                kwargs[key] = str(value)
            elif not isinstance(value, list):
                if value != str(value):
                    self._log_info("TGen - Change {} type {} from {} to {}".format(key, type(value), value, str(value)))
                kwargs[key] = str(value)

    def execute(self, func, *args, **kwargs):
        func_name = sys._getframe(1).f_code.co_name
        self.fix_dict_values(kwargs)
        retval = self._execute(func_name, func, *args, **kwargs)
        self._log_resp(func_name, retval)
        return retval

    def _execute(self, func_name, func, *args, **kwargs):
        for _ in range(3):
            try:
                res = func(self.node_name, *args, **kwargs)
                return copy.copy(res)
            except Exception as exp:
                msg = "\n{}\n{}".format(self.tg_ip, exp)
                if self.use_pyro:
                    import Pyro4
                    msg = msg + "\n" + "".join(Pyro4.util.getPyroTraceback())
                self._api_fail(msg)
                if "Failed to locate the nameserver" in msg:
                    time.sleep(10)
                    continue
                raise exp

    def sim_execute(self, *args, **kwargs):
        func_name = sys._getframe(1).f_code.co_name
        sim_id = getattr(self, "sim_id", 0) + 1
        self.sim_id = sim_id
        if func_name == "tg_traffic_config":
            return {"stream_id": str(sim_id)}
        elif func_name in ["tg_interface_config"]:
            return {"handle": str(sim_id)}
        elif func_name in ["tg_emulation_dhcp_server_config"]:
            return {"dhcp_handle": str(sim_id)}
        elif func_name in ["tg_emulation_dhcp_config"]:
            return {"handles": [str(sim_id)], "handle": str(sim_id)}
        elif func_name in ["tg_emulation_dhcp_group_config"]:
            return {"handle": str(sim_id)}
        elif func_name in ["tg_emulation_igmp_group_config"]:
            return {"group_handle": str(sim_id)}
        elif func_name in ["tg_emulation_mld_group_config"]:
            return {"group_handle": str(sim_id)}
        elif func_name in ["tg_emulation_bgp_config", "tg_emulation_bgp_route_config"]:
            return {"handle": str(sim_id)}
        elif func_name in ["tg_emulation_dot1x_config"]:
            return {"handle": str(sim_id)}
        elif func_name in ["tg_emulation_igmp_config"]:
            return {"host_handle": str(sim_id)}
        elif func_name in ["tg_emulation_mld_config"]:
            return {"host_handle": str(sim_id)}
        elif func_name in ["tg_emulation_multicast_group_config"]:
            return {"mul_group_handle": str(sim_id)}
        elif func_name in ["tg_emulation_multicast_source_config"]:
            return {"mul_source_handle": str(sim_id)}
        elif func_name == "tg_traffic_stats":
            rv = {"status": "1", "traffic_item": {}}
            ph = kwargs.get("port_handle", None)
            mode = kwargs.get("mode", "aggregate")
            ph_value = {mode: {}}
            ph_value[mode]["tx"] = {"raw_pkt_count": 0, "total_pkts": 0, "pkt_byte_count": 0}
            ph_value[mode]["rx"] = {"total_pkts": 0, "pkt_byte_count": 0}
            rv[ph] = ph_value
            return rv
        elif func_name == "tg_emulation_dhcp_stats":
            ph = kwargs.get("port_handle", None)
            mode = kwargs.get("mode", "aggregate")
            rv = {"status": "1", "traffic_item": {}, "ipv6": {ph: {}}}
            rv[mode] = {"currently_bound": 0}
            rv["ipv6"][ph][mode] = {"currently_bound": 0}
            return rv
        return None

    def tg_connect(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode:
            return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_connect, *args, **kwargs)

    def tg_disconnect(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode:
            return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_disconnect, *args, **kwargs)

    def tg_traffic_control(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode:
            return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_traffic_control, *args, **kwargs)

    def tg_interface_control(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode:
            return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_interface_control, *args, **kwargs)

    def tg_packet_control(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode:
            return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_packet_control, *args, **kwargs)

    def tg_packet_stats(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode:
            return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_packet_stats, *args, **kwargs)

    def tg_traffic_config(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode:
            return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_traffic_config, *args, **kwargs)

    def tg_interface_config(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode:
            return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_interface_config, *args, **kwargs)

    def tg_traffic_stats(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode:
            return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_traffic_stats, *args, **kwargs)

    def tg_emulation_bgp_config(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode:
            return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_emulation_bgp_config, *args, **kwargs)

    def tg_emulation_bgp_route_config(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode:
            return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_emulation_bgp_route_config, *args, **kwargs)

    def tg_emulation_bgp_control(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode:
            return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_emulation_bgp_control, *args, **kwargs)

    def tg_emulation_multicast_group_config(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode:
            return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_emulation_multicast_group_config, *args, **kwargs)

    def tg_emulation_multicast_source_config(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode:
            return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_emulation_multicast_source_config, *args, **kwargs)

    def tg_emulation_igmp_config(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode:
            return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_emulation_igmp_config, *args, **kwargs)

    def tg_emulation_igmp_group_config(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode:
            return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_emulation_igmp_group_config, *args, **kwargs)

    def tg_emulation_igmp_querier_config(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode:
            return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_emulation_igmp_querier_config, *args, **kwargs)

    def tg_emulation_igmp_control(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode:
            return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_emulation_igmp_control, *args, **kwargs)

    def tg_emulation_igmp_querier_control(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode:
            return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_emulation_igmp_querier_control, *args, **kwargs)

    def tg_emulation_mld_config(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode:
            return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_emulation_mld_config, *args, **kwargs)

    def tg_emulation_mld_group_config(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode:
            return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_emulation_mld_group_config, *args, **kwargs)

    def tg_emulation_mld_querier_config(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode:
            return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_emulation_mld_querier_config, *args, **kwargs)

    def tg_emulation_mld_control(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode:
            return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_emulation_mld_control, *args, **kwargs)

    def tg_emulation_mld_querier_control(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode:
            return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_emulation_mld_querier_control, *args, **kwargs)

    def tg_ospf_lsa_config(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode:
            return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_emulation_ospf_lsa_config, *args, **kwargs)

    def tg_emulation_ospf_config(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode:
            return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_emulation_ospf_config, *args, **kwargs)

    def tg_emulation_ospf_control(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode:
            return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_emulation_ospf_control, *args, **kwargs)

    def tg_emulation_ospf_route_config(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode:
            return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_emulation_ospf_route_config, *args, **kwargs)

    def tg_emulation_ospf_lsa_config(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode:
            return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_emulation_ospf_lsa_config, *args, **kwargs)

    def tg_emulation_ospf_network_group_config(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode:
            return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_emulation_ospf_network_group_config, *args, **kwargs)

    def tg_emulation_ospf_topology_route_config(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode:
            return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_emulation_ospf_topology_route_config, *args, **kwargs)

    def tg_emulation_dhcp_config(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode:
            return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_emulation_dhcp_config, *args, **kwargs)

    def tg_emulation_dhcp_control(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode:
            return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_emulation_dhcp_control, *args, **kwargs)

    def tg_emulation_dhcp_group_config(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode:
            return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_emulation_dhcp_group_config, *args, **kwargs)

    def tg_emulation_dhcp_server_config(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode:
            return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_emulation_dhcp_server_config, *args, **kwargs)

    def tg_emulation_dhcp_server_control(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode:
            return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_emulation_dhcp_server_control, *args, **kwargs)

    def tg_emulation_dhcp_server_stats(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode:
            return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_emulation_dhcp_server_stats, *args, **kwargs)

    def tg_emulation_dhcp_server_relay_agent_config(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode:
            return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_emulation_dhcp_server_relay_agent_config, *args, **kwargs)

    def tg_emulation_dhcp_stats(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode:
            return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_emulation_dhcp_stats, *args, **kwargs)

    def tg_custom_filter_config(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode:
            return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_custom_filter_config, *args, **kwargs)

    def tg_emulation_dot1x_config(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode:
            return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_emulation_dot1x_config, *args, **kwargs)

    def tg_emulation_dot1x_control(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode:
            return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_emulation_dot1x_control, *args, **kwargs)

    def tg_emulation_ipv6_autoconfig(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode:
            return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_emulation_ipv6_autoconfig, *args, **kwargs)

    def tg_emulation_ipv6_autoconfig_control(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode:
            return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_emulation_ipv6_autoconfig_control, *args, **kwargs)
