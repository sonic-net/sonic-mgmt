import os
import time
import textwrap

this_dir = os.path.join(os.path.dirname(__file__))
python = "/usr/bin/python"


def read_version():
    try:
        import exabgp.version
        return exabgp.version.version
    except Exception as e:
        print(str(e))
        return "3.4.17"


class ExaBgp(object):

    def __init__(self, pif):
        self.version = read_version()
        self.pif = pif
        self.logger = pif.logger
        self.utils = pif.utils
        self.nslist = []
        self.cleanup()

    def __del__(self):
        self.cleanup()

    def cleanup(self):
        self.stop()

    def _file(self, ns, extn, backup=False):
        return self.logger.mkfile("exabgpd", ns, extn, backup)

    def stop(self):
        if self.pif.dbg > 3:
            self.pif.os_system("ps -ef")
        for ns in self.nslist[:]:
            self.stop_one(ns)
        root = self.logger.get_logs_path()
        for pidfile in self.utils.list_files(root, "exabgpd_*.pid"):
            self.pif.kill_by_pidfile(pidfile)

    def stop_one(self, ns):
        logfile = self._file(ns, "log")
        pidfile = self._file(ns, "pid")
        self.pif.log_large_file(logfile)
        self.logger.info(self.utils.cat_file(pidfile))
        self.pif.kill_by_pidfile(pidfile, ns)
        if ns in self.nslist:
            self.nslist.remove(ns)
        return True

    def config_one(self, enable, intf, index=0):
        ns = "{}_{}".format(intf.name, index)
        if not enable:
            self.stop_one(ns)
            return True
        self.nslist.append(ns)

        logfile = self._file(ns, "log", True)
        pidfile = self._file(ns, "pid", True)
        envfile = self._file(ns, "env", True)
        cfgfile = self._file(ns, "cfg", True)

        ipv6_intf_addr = intf.kws.get("ipv6_intf_addr", "")
        if ipv6_intf_addr:
            family = "ipv6"
            intf_ip_addr = ipv6_intf_addr
        else:
            family = "ipv4"
            intf_ip_addr = intf.kws.get("intf_ip_addr", "")

        remote_ip_addr = intf.bgp_kws.get("remote_ip_addr", "0.0.0.0")
        remote_ipv6_addr = intf.bgp_kws.get("remote_ipv6_addr", "")
        if remote_ipv6_addr:
            remote_ip_addr = remote_ipv6_addr

        remote_as = self.utils.intval(intf.bgp_kws, "remote_as", 65001)
        local_as = self.utils.intval(intf.bgp_kws, "local_as", 65007)
        # enable_4_byte_as = self.utils.intval(intf.bgp_kws, "enable_4_byte_as", 0)
        # ip_version = self.utils.intval(intf.bgp_kws, "ip_version", 4)

        # create route config
        cmdfile, ip_cmdfile = self.config_route(enable, intf, index)

        # build router id from ns
        router_id = ns.replace("_", ".") + ".0"

        cmds_30 = textwrap.dedent("""
            group exabgp {{
                neighbor {2} {{
                    router-id {6};
                    local-address {0};
                    peer-as {3};
                    local-as {1};
                    auto-flush false;
                    group-updates true;
                    family {{
                        {8} unicast;
                    }}
                    process announce-routes {{
                        run {7} {4}/exabgp_routes.py {5};
                    }}
                }}
            }}
        """.format(intf_ip_addr, local_as, remote_ip_addr, remote_as, this_dir, cmdfile, router_id, python, family))

        cmds_40 = textwrap.dedent("""
            process announce-routes {{
                run {7} {4}/exabgp_routes.py {5};
                encoder json;
            }}
            neighbor {2} {{
                router-id {6};
                local-address {0};
                peer-as {3};
                local-as {1};
                auto-flush false;
                group-updates true;
                family {{
                    {8} unicast;
                }}
                api {{
                    processes [ announce-routes ];
                }}
            }}
        """.format(intf_ip_addr, local_as, remote_ip_addr, remote_as, this_dir, cmdfile, router_id, python, family))

        if self.version.startswith("4"):
            self.utils.fwrite(cmds_40, cfgfile)
        else:
            self.utils.fwrite(cmds_30, cfgfile)

        cmds = textwrap.dedent("""
            [exabgp.api]
            pipename = '{0}'
            cli = false

            [exabgp.daemon]
            pid = '{1}'
            daemonize = true
            drop = false
            user = root

            [exabgp.log]
            all = true
            message = true
            network = true
            packets = true
            parser = true
            rib = true
            routes = true
            timers = true
            level = DEBUG
            destination = '{2}'
        """.format(ns, pidfile, logfile))
        self.utils.fwrite(cmds, envfile)

        cmds = textwrap.dedent("""
            set -x
            #mkfifo //run/{0}.{{in,out}}
            #chmod 600 //run/{0}.{{in,out}}
            exabgp --env {1} {2}
        """.format(ns, envfile, cfgfile))
        sh_file = self.utils.fwrite(cmds)

        self.utils.nsexec(ns, "bash {}".format(sh_file))

        # self.utils.nsexec(ns, "bash {}".format(ip_cmdfile))
        self.utils.unused(ip_cmdfile)

        self.logger.info(self.utils.cat_file(envfile))
        self.logger.info(self.utils.cat_file(cfgfile))
        self.pif.log_large_file(cmdfile)
        time.sleep(5)
        self.logger.info(self.utils.cat_file(pidfile))
        self.pif.log_large_file(logfile)

        self.logger.register_log(logfile)

        return True

    def config_route(self, enable, intf, index=0):
        ns = "{}_{}".format(intf.name, index)
        cmdfile = self._file(ns, "cmd")
        ip_cmdfile = self._file(ns, "ip_cmd")
        cmds, ip_cmds = [], []

        for br in intf.bgp_routes.values():
            if not br.enable:
                continue
            self.logger.dump("BGP ROUTE", br)
            as_path = br.kws.get("as_path", None)
            as_seq = None
            if as_path and "as_seq:" in as_path:
                try:
                    as_seq = int(as_path.replace("as_path:", ""))
                except Exception:
                    as_seq = None

            num_routes = self.utils.intval(br.kws, "num_routes", 0)
            prefix = br.kws.get("prefix", "")
            if not prefix and num_routes > 0:
                msg = "Prefix not specified num_routes={}".format(num_routes)
                self.pif.error(msg)
            else:
                for _ in range(num_routes):
                    remote_ipv6_addr = intf.bgp_kws.get("remote_ipv6_addr", "")
                    if remote_ipv6_addr:
                        cmd = "announce route {}/128 next-hop self".format(prefix)
                        ip_cmd = "ip -6 addr add {}/128 dev veth1".format(prefix)
                        prefix = self.utils.incrementIPv6(prefix, "0:0:0:1::")
                    else:
                        cmd = "announce route {}/24 next-hop self".format(prefix)
                        ip_cmd = "ip addr add {}/24 dev veth1".format(prefix)
                        prefix = self.utils.incrementIPv4(prefix, "0.0.1.0")
                    # append as-path sequence
                    if as_seq:
                        cmd = cmd + "as-path [{}]".format(as_seq)
                    cmds.append(cmd)
                    ip_cmds.append(ip_cmd)
        self.utils.fwrite("\n".join(cmds), cmdfile)
        self.utils.fwrite("\n".join(ip_cmds), ip_cmdfile)
        #############################
        # TODO: batch routes
        # announce attribute next-hop self nlri 100.10.0.0/16 100.20.0.0/16
        #############################
        return cmdfile, ip_cmdfile

    def control(self, op, intf):
        retval = self.config_one(False, intf)
        if op not in ["disable", "stop"]:
            retval = self.config_one(True, intf)
        return retval

    def control_route(self, op, route):
        route.enable = bool(op != "remove")
        return self.control(op, route.intf)


if __name__ == "__main__":
    print(read_version())
