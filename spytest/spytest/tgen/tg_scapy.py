import os
import sys
import copy
import logging

class ScapyClient(object):

    def __init__(self, logger, port=8009):
        self.conn = None
        self.tg_port = port
        self.logger = logger or logging.getLogger()
        self.use_pyro = True
        self.filemode = bool(os.getenv("SPYTEST_FILE_MODE"))
        self.tg_ip = getattr(self, "tg_ip", None)
        self.tg_port_list = getattr(self, "tg_port_list", [])
        self.tg_port_handle = getattr(self, "tg_port_handle", {})

    def log_call(self, fname, **kwargs):
        self.logger.info("TODO {} {}".format(fname, **kwargs))

    def save_log(self, name, data):
        self.logger.info("TODO {} {}".format(name, data))

    def api_fail(self, msg):
        self.logger.info("TODO {}".format(msg))

    def log_info(self, *args):
        self.logger.info(*args)

    def server_control(self, phase, context):
        if self.filemode:
            return
        elif phase == "clean-all":
            self.execute(self.conn.server_control, "clean-all", "")
        elif phase == "pre-test":
            self.execute(self.conn.server_control, "add-log", "test-start " + context)
        elif phase == "post-test":
            self.execute(self.conn.server_control, "add-log", "test-finish " + context)
        elif phase == "pre-module-prolog":
            self.execute(self.conn.server_control, "init-log", context)
        elif phase == "post-module-epilog":
            data = self.execute(self.conn.server_control, "read-log", context)
            self.log_info("ScapyClient instrument: {} {}".format(phase, context))
            context = "tests_{}".format(context.replace(".py", ".tgen"))
            context = context.replace("/", "_")
            self.log_info("ScapyClient instrument: {} {}".format(phase, context))
            self.save_log(context, data)
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
            uri = "PYRO:scapy-tgen@{}:{}".format(self.tg_ip, self.tg_port)
            Pyro4.config.SERIALIZER  = "pickle"
            self.conn = Pyro4.Proxy(uri)
        else:
            self.conn2 = self.rpyc_connect()
            self.conn = self.conn2.root

        try: dbg_lvl = int(os.getenv("SPYTEST_SCAPY_DBG_LVL", "1"))
        except: dbg_lvl = 1
        try: max_pps = int(os.getenv("SPYTEST_SCAPY_MAX_PPS", "100"))
        except: max_pps = 100

        self.execute(self.conn.server_control, "set-dbg-lvl", dbg_lvl)
        self.execute(self.conn.server_control, "set-dry-run", dry_run)
        self.execute(self.conn.server_control, "set-max-pps", max_pps)
        self.execute(self.conn.server_control, "init-log", "default")
        res = self.tg_connect(port_list=self.tg_port_list)
        self.tg_port_handle.clear()
        for port in self.tg_port_list:
            self.tg_port_handle[port] = res['port_handle'][port]
        return None

    def log_api(self, *args, **kws):
        func = sys._getframe(1).f_code.co_name
        self.log_call(func, **kws)

    def fix_newstr(self, kws):
        from future.types import newstr
        for key, value in kws.items():
            if isinstance(value, newstr):
                kws[key] = str(value)

    def execute(self, func, *args, **kws):
        try:
            res = func(*args, **kws)
            return copy.copy(res)
        except Exception as exp:
            msg = "{}".format(exp)
            if self.use_pyro:
                import Pyro4
                msg = msg + "".join(Pyro4.util.getPyroTraceback())
            self.api_fail(msg)
            raise exp

    def tg_connect(self, *args, **kws):
        self.log_api(*args, **kws)
        if self.filemode: return None
        return self.execute(self.conn.tg_connect, *args, **kws)
    def tg_disconnect(self, *args, **kws):
        self.log_api(*args, **kws)
        if self.filemode: return None
        return self.execute(self.conn.tg_disconnect, *args, **kws)
    def tg_traffic_control(self, *args, **kws):
        self.log_api(*args, **kws)
        if self.filemode: return None
        return self.execute(self.conn.tg_traffic_control, *args, **kws)
    def tg_interface_control(self, *args, **kws):
        self.log_api(*args, **kws)
        if self.filemode: return None
        return self.execute(self.conn.tg_interface_control, *args, **kws)
    def tg_packet_control(self, *args, **kws):
        self.log_api(*args, **kws)
        if self.filemode: return None
        return self.execute(self.conn.tg_packet_control, *args, **kws)
    def tg_packet_stats(self, *args, **kws):
        self.log_api(*args, **kws)
        if self.filemode: return None
        return self.execute(self.conn.tg_packet_stats, *args, **kws)
    def tg_traffic_config(self, *args, **kws):
        self.log_api(*args, **kws)
        if self.filemode: return None
        self.fix_newstr(kws)
        return self.execute(self.conn.tg_traffic_config, *args, **kws)
    def tg_interface_config(self, *args, **kws):
        self.log_api(*args, **kws)
        if self.filemode: return None
        return self.execute(self.conn.tg_interface_config, *args, **kws)
    def tg_traffic_stats(self, *args, **kws):
        self.log_api(*args, **kws)
        if self.filemode: return None
        return self.execute(self.conn.tg_traffic_stats, *args, **kws)
    def tg_emulation_bgp_config(self, *args, **kws):
        self.log_api(*args, **kws)
        if self.filemode: return None
        return self.execute(self.conn.tg_emulation_bgp_config, *args, **kws)
    def tg_emulation_bgp_route_config(self, *args, **kws):
        self.log_api(*args, **kws)
        if self.filemode: return None
        return self.execute(self.conn.tg_emulation_bgp_route_config, *args, **kws)
    def tg_emulation_bgp_control(self, *args, **kws):
        self.log_api(*args, **kws)
        if self.filemode: return None
        return self.execute(self.conn.tg_emulation_bgp_control, *args, **kws)
    def tg_emulation_igmp_config(self, *args, **kws):
        self.log_api(*args, **kws)
        if self.filemode: return None
        return self.execute(self.conn.tg_emulation_igmp_config, *args, **kws)
    def tg_emulation_multicast_group_config(self, *args, **kws):
        self.log_api(*args, **kws)
        if self.filemode: return None
        return self.execute(self.conn.tg_emulation_multicast_group_config, *args, **kws)
    def tg_emulation_multicast_source_config(self, *args, **kws):
        self.log_api(*args, **kws)
        if self.filemode: return None
        return self.execute(self.conn.tg_emulation_multicast_source_config, *args, **kws)
    def tg_emulation_igmp_group_config(self, *args, **kws):
        self.log_api(*args, **kws)
        if self.filemode: return None
        return self.execute(self.conn.tg_emulation_igmp_group_config, *args, **kws)
    def tg_emulation_igmp_control(self, *args, **kws):
        self.log_api(*args, **kws)
        if self.filemode: return None
        return self.execute(self.conn.tg_emulation_igmp_control, *args, **kws)

