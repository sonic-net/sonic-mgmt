
from emulation import Emulation


class Dhcps(Emulation):

    def __init__(self, pif):
        super(Dhcps, self).__init__(pif, "dhcps")

    def control(self, server, intf, **kws):
        mode = kws.get("mode", "reset")
        action = kws.get("action", mode)
        ip_version = self.utils.intval(kws, "ip_version", 4)
        ns = "{}_{}".format(intf.name, 0)

        if server.dhcp_relay_agents:
            ent = list(server.dhcp_relay_agents.values())[0]
            start = ent.kws.get("relay_agent_ipaddress_pool", "0.0.0.0")
            step = ent.kws.get("relay_agent_ipaddress_step", "0.0.0.0")
            count = self.utils.intval(ent.kws, "relay_agent_ipaddress_count", 1)
        elif ip_version == 6:
            start = server.kws.get("addr_pool_start_addr", "2000::1")
            start = server.kws.get("ipaddress_pool", start)
            step = server.kws.get("step", "::1")
            count = self.utils.intval(server.kws, "addr_pool_addresses_per_server", 1)
            count = self.utils.intval(server.kws, "ipaddress_count", count)
        else:
            start = server.kws.get("ipaddress_pool", "0.0.0.0")
            step = server.kws.get("ipaddress_step", "0.0.0.1")
            count = self.utils.intval(server.kws, "ipaddress_count", 1)

        end = start
        for _ in range(count):
            if ip_version == 6:
                end = self.utils.incrementIPv6(end, step)
            else:
                end = self.utils.incrementIPv4(end, step)

        # kill existing server if any
        # pidfile = self.logger.mkfile("dhcpd", ns, "pid")
        # self.pif.kill_by_pidfile(pidfile, ns)
        self.stop_one(ns)

        if action in ["delete", "reset"]:
            return True

        logfile = self._file(ns, "log", True)
        pidfile = self._file(ns, "pid", True)

        # start dhcpd
        cmd = "dnsmasq -i veth1 -p0"
        cmd = "{} --dhcp-range={},{}".format(cmd, start, end)
        cmd = "{} --pid-file={}".format(cmd, pidfile)
        cmd = "{} --log-queries".format(cmd)
        cmd = "{} --log-dhcp".format(cmd)
        cmd = "{} --log-facility={}".format(cmd, logfile)
        output = self.utils.nsexec(ns, cmd)
        self.logger.debug("{} -- {}".format(cmd, output))
        if "dnsmasq: bad command line options" in output:
            return False
        self.logger.register_log(logfile)
        return True
