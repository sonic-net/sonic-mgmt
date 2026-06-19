import sys
import textwrap
import traceback
import ipaddress

try:
    pass
except Exception as exp:
    print(exp)
from scapy.config import Conf
from utils import Utils

try:
    print("SCAPY VERSION = {}".format(Conf().version))
except Exception:
    print("SCAPY VERSION = UNKNOWN")

if sys.version_info[0] >= 3:
    unicode = str


class PacketInterface(object):

    def __init__(self, pif):
        self.pif = pif
        self.iface = pif.iface
        self.dbg = pif.dbg
        self.logger = pif.logger
        self.utils = pif.utils

    def __del__(self):
        self.cleanup()

    def cleanup(self):
        print("ScapyPacket {} cleanup...".format(self.iface))
        self.logger.info("ScapyPacket {} cleanup...".format(self.iface))

    def if_delete_cmds(self, index, intf):
        ns = "{}_{}".format(intf.name, index)

        # remove the linux interface
        cmds = textwrap.dedent("""
            ip netns del ns_{0}
            ip link del veth_{0}
        """.format(ns))

        return ns, cmds

    def if_create_cmds(self, index, intf, ip4addr, ip4gw, ip6addr,
                       ip6gw, smac, vlan_id2, **kws):
        ns = "{}_{}".format(intf.name, index)

        vlan_enable = self.utils.intval(kws, "vlan", 0)
        veth_name = "veth0" if vlan_enable else "veth1"

        begin, finish, verify = "", "", ""

        # remove existing
        _, cmds = self.if_delete_cmds(index, intf)
        begin += cmds

        # create the linux interface
        begin += textwrap.dedent("""
            ip netns add ns_{0}
            ip netns list
            ip link add veth_{0} type veth peer name {2}
            ip link set {2} netns ns_{0}
            ip netns exec ns_{0} ethtool --offload {2} rx off  tx off > /dev/null 2>&1
            ip netns exec ns_{0} ip link set dev {2} up
            ip netns exec ns_{0} ethtool --offload {2} rx off tx off
            ip link set dev veth_{0} up
            ip link add name {1}-br type bridge
            ip link set dev veth_{0} master {1}-br
        """.format(ns, intf.iface, veth_name))

        if vlan_enable:
            begin += textwrap.dedent("""
                ip netns exec ns_{0} ip link add link veth0 name veth1 type vlan id {1}
                ip netns exec ns_{0} ip link set veth1 up
            """.format(ns, vlan_id2))

        # set interface mac address
        if smac != "00:00:00:00:00:00":
            begin += "\nip netns exec ns_{0} ip link set veth1 address {1}".format(ns, smac)

        # assign IPv4 to linux interface
        if ip4addr and ip4addr != "0.0.0.0":
            begin += "\nip netns exec ns_{0} ip addr add {1}/{2} dev veth1".format(ns, ip4addr, 24)
        if ip4gw:
            begin += "\nip netns exec ns_{0} ip route add default via {1}".format(ns, ip4gw)

        # assign IPv6 to linux interface
        if ip6addr:
            ip6prefix = self.utils.intval(intf.kws, "ipv6_prefix_length", 64)
            begin += "\nip netns exec ns_{0} ip -6 addr add {1}/{2} dev veth1".format(ns, ip6addr, ip6prefix)
        if ip6gw:
            begin += "\nip netns exec ns_{0} ip -6 route add default via {1}".format(ns, ip6gw)

        _, b, f, v = self.if_arp_cmds(index, intf, ip4addr, ip4gw, ip6addr, ip6gw, **kws)

        return ns, begin + b, finish + f, verify + v

    def if_arp_cmds(self, index, intf, ip4addr, ip4gw, ip6addr, ip6gw, **kws):
        ns = "{}_{}".format(intf.name, index)

        begin, finish, verify = "", "", ""

        # send Arp request
        arp_send_req = self.utils.intval(kws, "arp_send_req", 1)
        if arp_send_req:
            if ip4gw:
                finish += textwrap.dedent("""
                    ip netns exec ns_{0} arping -w 7 -c 1 -I veth1 {1}
                """.format(ns, ip4gw))
                verify += textwrap.dedent("""
                    ip netns exec ns_{0} ip neigh show
                """.format(ns))
            if ip6gw:
                finish += textwrap.dedent("""
                    ip netns exec ns_{0} ndisc6 -w 2000 {1} veth1
                """.format(ns, ip6gw))
                if ip6addr:
                    finish += textwrap.dedent("""
                        ip netns exec ns_{0} ndisc6 -w 2000 -s {2} {1} veth1
                    """.format(ns, ip6gw, ip6addr))
                verify += textwrap.dedent("""
                    ip netns exec ns_{0} ip -6 neigh show
                """.format(ns))

        if self.dbg > 1:
            verify += textwrap.dedent("""
                ip netns exec ns_{0} ifconfig veth1
                ip netns exec ns_{0} ip addr ls veth1
            """.format(ns))

        return ns, begin, finish, verify

    def store_cmds(self, cmd_list, b, f, v):
        cmd_list[0].append(b)
        cmd_list[1].append(f)
        cmd_list[2].append(v)

    def change_map(self, ns, is_add):
        pass

    def shexec(self, cmds):
        output = self.utils.lshexec(cmds)
        if "Cannot open network namespace" in output:
            self.logger.error(output)
            self.utils.ns_debug(None, "Cannot open network namespace")
        if self.dbg > 2:
            self.logger.debug(output)
        return output

    def if_create(self, intf):
        smac = intf.kws.get("src_mac_addr", "00:00:00:00:00:00").replace(".", ":")
        count = self.utils.intval(intf.kws, "count", 1)
        vlan_id = self.utils.intval(intf.kws, "vlan_id", 1)
        vlan_id_count = self.utils.intval(intf.kws, "vlan_id_count", 0)
        vlan_id_step = self.utils.intval(intf.kws, "vlan_id_step", 1)
        max_count = self.utils.max_value(count, vlan_id_count)

        ip4addr = intf.kws.get("intf_ip_addr", "")
        ip4addr_step = intf.kws.get("intf_ip_addr_step", "0.0.0.1")
        ip4gw = intf.kws.get("gateway", "")
        ip4gw_step = intf.kws.get("gateway_step", "0.0.0.0")

        ip6addr = intf.kws.get("ipv6_intf_addr", "")
        ip6addr_step = intf.kws.get("ipv6_intf_addr_step", "::1")
        ip6gw = intf.kws.get("ipv6_gateway", "")
        ip6gw_step = intf.kws.get("ipv6_gateway_step", "::0")

        cmd_list = [[], [], []]

        # set dual stack IPv4 & IPv6 Address
        if ip4addr and ip6addr:
            for index in range(max_count):
                ns, b, f, v = self.if_create_cmds(index, intf, ip4addr, ip4gw,
                                                  ip6addr, ip6gw, smac, vlan_id, **intf.kws)
                self.store_cmds(cmd_list, b, f, v)
                self.change_map(ns, True)
                ip4addr = self.utils.incrementIPv4(ip4addr, ip4addr_step)
                if ip4gw:
                    ip4gw = self.utils.incrementIPv4(ip4gw, ip4gw_step)
                ip6addr = self.utils.incrementIPv6(ip6addr, ip6addr_step)
                if ip6gw:
                    ip6gw = self.utils.incrementIPv6(ip6gw, ip6gw_step)
                if smac != "00:00:00:00:00:00":
                    smac = self.utils.incrementMac(smac, "00:00:00:00:00:01")
                vlan_id = vlan_id + vlan_id_step
        # set IPv4 Address
        elif ip4addr:
            for index in range(max_count):
                ns, b, f, v = self.if_create_cmds(index, intf, ip4addr, ip4gw,
                                                  None, None, smac, vlan_id, **intf.kws)
                self.store_cmds(cmd_list, b, f, v)
                self.change_map(ns, True)
                ip4addr = self.utils.incrementIPv4(ip4addr, ip4addr_step)
                if ip4gw:
                    ip4gw = self.utils.incrementIPv4(ip4gw, ip4gw_step)
                if smac != "00:00:00:00:00:00":
                    smac = self.utils.incrementMac(smac, "00:00:00:00:00:01")
                vlan_id = vlan_id + vlan_id_step
        # set IPv6 Address
        elif ip6addr:
            for index in range(max_count):
                ns, b, f, v = self.if_create_cmds(index, intf, None, None,
                                                  ip6addr, ip6gw, smac, vlan_id, **intf.kws)
                self.store_cmds(cmd_list, b, f, v)
                self.change_map(ns, True)
                ip6addr = self.utils.incrementIPv6(ip6addr, ip6addr_step)
                if ip6gw:
                    ip6gw = self.utils.incrementIPv6(ip6gw, ip6gw_step)
                if smac != "00:00:00:00:00:00":
                    smac = self.utils.incrementMac(smac, "00:00:00:00:00:01")
                vlan_id = vlan_id + vlan_id_step

        # execute collected commands
        cmds = cmd_list[0]
        if cmd_list[1]:
            cmds.append("sleep 2")
            cmds.extend(cmd_list[1])
        cmds.extend(cmd_list[2])

        output = self.shexec(cmds)
        if "wrong: Device does not exist" in output:
            msg = self.logger.error("Failed to create interface")
            raise ValueError(msg)

        self.logger.info("read the mac addresses of created interfaces")
        for index in range(max_count):
            ns = "{}_{}".format(intf.name, index)
            if_info, cmd, _ = self.utils.get_ip_addr_dev("veth1", ns)
            self.logger.info(cmd, if_info)
            mac_addr = if_info.get("link/ether", "00:00:00:00:00:00")
            intf.mymac.append(mac_addr)

    def if_delete(self, intf):
        count = self.utils.intval(intf.kws, "count", 1)
        vlan_id_count = self.utils.intval(intf.kws, "vlan_id_count", 0)
        max_count = self.utils.max_value(count, vlan_id_count)
        cmd_list = []
        for index in range(max_count):
            ns, cmds = self.if_delete_cmds(index, intf)
            cmd_list.append(cmds)
        self.change_map(ns, False)
        self.shexec(cmd_list)

    def if_validate(self, intf):
        ns = "{}_{}".format(intf.intf.name, 0)
        self.utils.get_ip_addr_dev("veth1", ns)
        return True

    def if_send_arp(self, intf):
        smac = intf.kws.get("src_mac_addr", "00:00:00:00:00:00").replace(".", ":")
        count = self.utils.intval(intf.kws, "count", 1)
        vlan_id_count = self.utils.intval(intf.kws, "vlan_id_count", 0)
        max_count = self.utils.max_value(count, vlan_id_count)

        # set IPv4 Address
        ip4addr = intf.kws.get("intf_ip_addr", "")
        ip4addr_step = intf.kws.get("intf_ip_addr_step", "0.0.0.1")
        ip4gw = intf.kws.get("gateway", "")
        ip4gw_step = intf.kws.get("gateway_step", "0.0.0.0")
        cmd_list = [[], [], []]
        if ip4addr:
            for index in range(max_count):
                ns, b, f, v = self.if_arp_cmds(index, intf, ip4addr, ip4gw, None, None, **intf.kws)
                self.store_cmds(cmd_list, b, f, v)
                self.change_map(ns, True)
                ip4addr = self.utils.incrementIPv4(ip4addr, ip4addr_step)
                if ip4gw:
                    ip4gw = self.utils.incrementIPv4(ip4gw, ip4gw_step)
                if smac != "00:00:00:00:00:00":
                    smac = self.utils.incrementMac(smac, "00:00:00:00:00:01")
        # set IPv6 Address
        ip6addr = intf.kws.get("ipv6_intf_addr", "")
        ip6addr_step = intf.kws.get("ipv6_intf_addr_step", "::1")
        ip6gw = intf.kws.get("ipv6_gateway", "")
        ip6gw_step = intf.kws.get("ipv6_gateway_step", "::0")
        if ip6addr:
            for index in range(max_count):
                ns, b, f, v = self.if_arp_cmds(index, intf, None, None, ip6addr, ip6gw, **intf.kws)
                self.store_cmds(cmd_list, b, f, v)
                self.change_map(ns, True)
                ip6addr = self.utils.incrementIPv6(ip6addr, ip6addr_step)
                if ip6gw:
                    ip6gw = self.utils.incrementIPv6(ip6gw, ip6gw_step)
                if smac != "00:00:00:00:00:00":
                    smac = self.utils.incrementMac(smac, "00:00:00:00:00:01")

        # execute collected commands
        cmds = cmd_list[0]
        if cmd_list[1]:
            cmds.append("sleep 2")
            cmds.extend(cmd_list[1])
        cmds.extend(cmd_list[2])
        self.shexec(cmds)

    def get_my_mac(self, intf, default="00:00:00:00:00:00"):
        ns = "{}_{}".format(intf.name, 0)
        cmd = "cat /sys/class/net/veth1/address"
        output = self.utils.nsexec(ns, cmd).lower()
        self.logger.debug("{} = {}".format(cmd, output))
        return output

    def get_arp_mac(self, intf, default, try_cache=True):

        try:
            ipv6gw = intf.kws.get("ipv6_gateway", "")
            ipv4gw = intf.kws.get("gateway", "0.0.0.0")
            ns = "{}_{}".format(intf.name, 0)
            self.logger.debug("get_arp_mac {} {}".format(ipv4gw, ipv6gw))

            # try getting from ARP cache
            if ipv4gw != "0.0.0.0":

                # check in interface gateway mac cache
                retval = intf.gwmac.get(ipv4gw, None)
                if try_cache and retval:
                    return retval

                for _ in range(3):
                    retval = self.read_ipv4_gwmac(ns, ipv4gw, 1)
                    if retval:
                        return retval

                    # try getting from arping output
                    cmd = "arping -w 7 -c 1 -I veth1 {}".format(ipv4gw)
                    output = self.utils.nsexec(ns, cmd).lower()
                    self.logger.debug("{} = \n {}".format(cmd, output))
                    retval = Utils.parse_mac(output)
                    if retval:
                        return retval

            elif ipv6gw:

                # check in interface gateway mac cache
                retval = intf.gwmac.get(ipv6gw, None)
                if try_cache and retval:
                    return retval

                retval = self.read_ipv6_gwmac(ns, ipv6gw)
                if retval:
                    return retval

        except Exception as exp:
            self.logger.info(exp)
            self.logger.info(traceback.format_exc())

        return default

    def ping(self, intf, ping_dst, index=0):
        ns = "{}_{}".format(intf.name, index)
        cmd = "ping -c 1 {}".format(ping_dst)
        try:
            ip = ipaddress.ip_address(unicode(ping_dst))
            if ip._version == 6:
                cmd = "ping6 -c 1 {}".format(ping_dst)
        except Exception as exp:
            self.pif.error(exp)

        # execute the command
        return self.utils.nsexec(ns, cmd)

    def send_arp(self, intf, index=0):
        ns = "{}_{}".format(intf.name, index)
        ip4gw = intf.kws.get("gateway", "0.0.0.0")
        ip6gw = intf.kws.get("ipv6_gateway", "")
        if ip6gw:
            cmd = "ndisc6 -w 2000 {} veth1".format(ip6gw)
        else:
            cmd = "arping -w 7 -c 1 -I veth1 {}".format(ip4gw)
        rv = self.utils.nsexec(ns, cmd)
        if ip6gw:
            mac = self.read_ipv6_gwmac(ns, ip6gw)
            intf.gwmac[ip6gw] = mac
        else:
            mac = Utils.parse_mac(rv.lower())
            intf.gwmac[ip4gw] = mac
        self.logger.debug("send_arp {} {} {}".format(ip4gw, ip6gw, mac))
        return rv

    def read_ipv6_gwmac(self, ns, ipv6gw, max_try=3):
        for i in range(max_try):
            cmd = "ip -6 neigh show {}".format(ipv6gw)
            output = self.utils.nsexec(ns, cmd).lower()
            self.logger.debug("Try-{} {} = \n {}".format(i + 1, cmd, output))
            retval = Utils.parse_mac(output)
            if retval:
                return retval
        return None

    def read_ipv4_gwmac(self, ns, ipv4gw, max_try=3):
        for _ in range(max_try):
            cmd = "arp -n {}".format(ipv4gw)
            output = self.utils.nsexec(ns, cmd).lower()
            self.logger.debug("{} = \n {}".format(cmd, output))
            retval = Utils.parse_mac(output)
            if retval:
                return retval
        return None
