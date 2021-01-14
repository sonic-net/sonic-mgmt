import os
import sys
import copy
import time
import logging

import spytest.paths as paths

class ScapyClient(object):

    def __init__(self, logger, tg_ip=None, tg_port=8009, tg_port_list=None, base=None):
        self.base = base
        self.conn = None
        self.logger = logger or logging.getLogger()
        self.use_pyro = True
        self.node_name = ""
        self.filemode = bool(os.getenv("SPYTEST_FILE_MODE", "0") != "0")
        self.tg_ip = tg_ip
        self.tg_port = tg_port
        self.tg_port_list = tg_port_list or []
        self.tg_port_handle = {}

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
            self.logger.info("TODO {} {}".format(fname, opts))

    def save_log(self, name, data):
        if self.base:
            self.base.save_log(name, data)
        else:
            self.logger.info("TODO {} {}".format(name, data))

    def _api_fail(self, msg):
        if self.base:
            self.base.api_fail(msg)
        else:
            self.logger.info("TODO {}".format(msg))

    def log_info(self, *args):
        self.logger.info(*args)

    def log_remote_alerts(self, phase):
        func_name = "server_control"
        errs1 = "==================== REMOTE ALERTS ============================"
        errs2 = self._execute(func_name, self.conn.server_control, "get-alerts", "")
        errs3 = "==============================================================="
        if errs2.strip():
            self.logger.info("\n".join(["\n",errs1, errs2, errs3,"\n"]))

    def server_control(self, phase, context):
        func_name = "server_control"
        if self.filemode:
            return
        elif phase == "clean-all":
            self._execute(func_name, self.conn.server_control, "clean-all", "")
        elif phase == "pre-test":
            self._execute(func_name, self.conn.server_control, "add-log", "test-start {} {}".format(context, self.node_name))
            self.log_remote_alerts(phase)
        elif phase == "post-test":
            self._execute(func_name, self.conn.server_control, "add-log", "test-finish {} {}".format(context, self.node_name))
            self.log_remote_alerts(phase)
        elif phase == "pre-module-prolog":
            local_file = "{}.tgen".format(paths.get_mlog_name(context))
            path = self._execute(func_name, self.conn.server_control, "init-log", local_file)
            self.logger.info("Server Logs Path {}".format(path))
            self.log_remote_alerts(phase)
        elif phase == "post-module-epilog":
            self.log_info("ScapyClient instrument: {} {}".format(phase, context))
            local_file = "{}.tgen".format(paths.get_mlog_name(context))
            self.log_info("ScapyClient instrument: {} {}".format(phase, local_file))
            try:
                data = self._execute(func_name, self.conn.server_control, "read-log", local_file)
                self.save_log(local_file, data)
            except Exception as exp:
                self.log_info("Failed to read log {} {}".format(context, str(exp)))
            self.log_remote_alerts(phase)
        else:
            self.log_info("ScapyClient instrument: ignored {} {}".format(phase, context))

    def rpyc_connect(self):
        import rpyc
        try:
            config={"allow_pickle" : True, "sync_request_timeout": 300,
                    "allow_public_attrs": True, "allow_all_attrs": True,
                    "instantiate_oldstyle_exceptions" : True}
            return rpyc.connect(self.tg_ip, self.tg_port, config=config)
        except Exception as e:
            print (e)
            raise ValueError("Failed to connect to scapy server {}".format(e))

    def scapy_connect(self, dry_run=False):
        self.tg_ns = 'scapy'

        if self.filemode:
            return None

        if self.use_pyro:
            import Pyro4
            #uri = "PYRO:scapy-tgen@{}:{}".format(self.tg_ip, self.tg_port)
            uri = "PYRONAME:scapy-tgen@{}".format(self.tg_ip)
            Pyro4.config.SERIALIZER  = "pickle"
            self.conn = Pyro4.Proxy(uri)
        else:
            self.conn2 = self.rpyc_connect()
            self.conn = self.conn2.root

        try: dbg_lvl = int(os.getenv("SPYTEST_SCAPY_DBG_LVL", "1"))
        except Exception: dbg_lvl = 1
        try: max_pps = int(os.getenv("SPYTEST_SCAPY_MAX_PPS", "100"))
        except Exception: max_pps = 100
        model = os.getenv("SCAPY_TGEN_PORTMAP", "eth1")
        self.node_name = os.getenv("PYTEST_XDIST_WORKER", "")
        func_name = "server_control"
        for _ in range(5):
            try:
                self._execute(func_name, self.conn.server_control, "set-name", self.node_name)
                break
            except Exception:
                time.sleep(10)
        path = self._execute(func_name, self.conn.server_control, "init-log", "default")
        self.logger.info("Server Logs Path {}".format(path))
        self._execute(func_name, self.conn.server_control, "set-dbg-lvl", dbg_lvl)
        self._execute(func_name, self.conn.server_control, "set-dry-run", dry_run)
        self._execute(func_name, self.conn.server_control, "set-max-pps", max_pps)
        self._execute(func_name, self.conn.server_control, "set-model", model)
        res = self.tg_connect(port_list=self.tg_port_list)
        self._set_port_handle(None, None)
        for port in self.tg_port_list:
            self._set_port_handle(port, res['port_handle'][port])
        return None

    def log_api(self, *args, **kwargs):
        func = sys._getframe(1).f_code.co_name
        self._log_call(func, **kwargs)

    def fix_newstr(self, kwargs):
        from future.types import newstr
        for key, value in kwargs.items():
            if isinstance(value, newstr):
                kwargs[key] = str(value)

    def execute(self, func, *args, **kwargs):
        func_name = sys._getframe(1).f_code.co_name
        return self._execute(func_name, func, *args, **kwargs)

    def _execute(self, func_name, func, *args, **kwargs):
        #msg1 = " ".join(map(str,args))
        #msg2 = ','.join(['{}={!r}'.format(k,v) for k,v in kwargs.items()])
        #self.log_info("ScapyClient: {} {} {} {}".format(self.node_name, func_name, msg1, msg2))
        try:
            res = func(self.node_name, *args, **kwargs)
            return copy.copy(res)
        except Exception as exp:
            msg = "{}".format(exp)
            if self.use_pyro:
                import Pyro4
                msg = msg + "".join(Pyro4.util.getPyroTraceback())
            self._api_fail(msg)
            raise exp

    def sim_execute(self, *args, **kwargs):
        func_name = sys._getframe(1).f_code.co_name
        sim_id = getattr(self, "sim_id", 0) + 1
        self.sim_id = sim_id
        if func_name == "tg_traffic_config":
            return {"stream_id" : str(sim_id)}
        elif func_name in ["tg_interface_config"]:
            return {"handle" : str(sim_id)}
        elif func_name in ["tg_emulation_bgp_config", "tg_emulation_bgp_route_config"]:
            return {"handle" : str(sim_id)}
        elif func_name in ["tg_emulation_igmp_config"]:
            return {"host_handle" : str(sim_id)}
        elif func_name in ["tg_emulation_multicast_group_config"]:
            return {"mul_group_handle" : str(sim_id)}
        elif func_name in ["tg_emulation_multicast_source_config"]:
            return {"mul_source_handle" : str(sim_id)}
        elif func_name == "tg_traffic_stats":
            rv = {"status" : "1", "traffic_item": {}}
            tx_ph = kwargs.get("port_handle", None)
            mode = kwargs.get("mode", "aggregate")
            tx_ph_value = {mode: {}}
            tx_ph_value[mode]["tx"] = {"raw_pkt_count":0, "total_pkts":0, "pkt_byte_count":0}
            tx_ph_value[mode]["rx"] = {"total_pkts":0, "pkt_byte_count":0}
            rv[tx_ph] = tx_ph_value
            return rv
        return None

    def tg_connect(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode: return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_connect, *args, **kwargs)
    def tg_disconnect(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode: return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_disconnect, *args, **kwargs)
    def tg_traffic_control(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode: return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_traffic_control, *args, **kwargs)
    def tg_interface_control(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode: return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_interface_control, *args, **kwargs)
    def tg_packet_control(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode: return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_packet_control, *args, **kwargs)
    def tg_packet_stats(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode: return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_packet_stats, *args, **kwargs)
    def tg_traffic_config(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode: return self.sim_execute(*args, **kwargs)
        self.fix_newstr(kwargs)
        return self.execute(self.conn.tg_traffic_config, *args, **kwargs)
    def tg_interface_config(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode: return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_interface_config, *args, **kwargs)
    def tg_traffic_stats(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode: return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_traffic_stats, *args, **kwargs)
    def tg_emulation_bgp_config(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode: return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_emulation_bgp_config, *args, **kwargs)
    def tg_emulation_bgp_route_config(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode: return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_emulation_bgp_route_config, *args, **kwargs)
    def tg_emulation_bgp_control(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode: return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_emulation_bgp_control, *args, **kwargs)
    def tg_emulation_igmp_config(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode: return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_emulation_igmp_config, *args, **kwargs)
    def tg_emulation_multicast_group_config(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode: return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_emulation_multicast_group_config, *args, **kwargs)
    def tg_emulation_multicast_source_config(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode: return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_emulation_multicast_source_config, *args, **kwargs)
    def tg_emulation_igmp_group_config(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode: return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_emulation_igmp_group_config, *args, **kwargs)
    def tg_emulation_igmp_control(self, *args, **kwargs):
        self.log_api(*args, **kwargs)
        if self.filemode: return self.sim_execute(*args, **kwargs)
        return self.execute(self.conn.tg_emulation_igmp_control, *args, **kwargs)

