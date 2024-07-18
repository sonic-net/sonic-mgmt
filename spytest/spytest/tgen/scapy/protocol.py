import copy
import binascii
import traceback

from scapy.packet import Padding
from scapy.layers.l2 import Dot1Q, Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dhcp6 import DUID_LLT
from scapy.layers.dhcp6 import DHCP6_Solicit
from scapy.layers.dhcp6 import DHCP6OptElapsedTime
from scapy.layers.dhcp6 import DHCP6OptClientId
from scapy.layers.dhcp6 import DHCP6OptIA_NA
from scapy.layers.eap import EAPOL, EAP
from scapy.contrib.ospf import OSPF_Hdr, OSPF_Hello, OSPF_DBDesc
from scapy.contrib.ospf import OSPF_LSAck, OSPF_LSA_Hdr, OSPF_LSUpd, OSPF_Link
from scapy.contrib.ospf import OSPF_External_LSA, OSPF_SummaryIP_LSA, OSPF_Router_LSA
from scapy.contrib.igmp import IGMP
from scapy.contrib.igmpv3 import IGMPv3, IGMPv3mr, IGMPv3gr, IGMPv3mq
from scapy.utils import chexdump


class PacketProtocol(object):

    def __init__(self, pif):
        self.pif = pif
        self.logger = pif.logger
        self.utils = pif.utils
        self.next_xid = 1

    def __del__(self):
        pass

    def process(self, port, pkt):

        if IP in pkt and pkt.proto == 89:
            self.ospf_rx(port, pkt)

        if BOOTP in pkt:
            self.dhcp_rx(port, pkt)

        if IGMP in pkt or IGMPv3 in pkt:
            self.igmp_rx(port, pkt)

        if EAP in pkt:
            self.dot1x_rx(port, pkt)

        self.igmp_tx_query_periodic(port)
        self.dot1x_tx_periodic(port)

    def pkt_write(self, file_path, pkt, append):
        try:
            self.logger.write_pcap(pkt, append=True, filename=file_path)
        except Exception as exp:
            self.logger.error("wrpcap error {}".format(str(exp)))

    def pkt_debug(self, recv, send, name, ifname="", dbg=0):
        file_path = self.logger.get_logs_path("{}.pcap".format(name))
        dbg = self.utils.max_value(dbg, self.pif.dbg)
        if recv:
            if dbg > 1:
                self.logger.info("=== RECV {} {}".format(name, recv.command()))
            if dbg > 2:
                self.logger.debug(chexdump(recv, True))
                msg = "=========== RECV {} ==================".format(name)
                self.utils.exec_func(msg, recv.show2)
            if dbg > 9:
                self.logger.write_pcap(recv)
                self.pkt_write(file_path, recv, append=True)
        if send:
            if dbg > 1:
                self.logger.info("=== SEND({}) {} {}".format(ifname, name, send.command()))
            if dbg > 2:
                self.logger.debug(chexdump(send, True))
                msg = "=========== SEND({}) {} =================".format(ifname, name)
                self.utils.exec_func(msg, send.show2)
            if dbg > 9:
                self.logger.write_pcap(send)
                self.pkt_write(file_path, send, append=True)

    def ospf_rx(self, port, pkt):
        ifname = port.iface
        ospf_pkt_type = pkt[OSPF_Hdr].type
        msg = "check OSPF session on {} {} to handle TYPE {}"
        self.logger.info(msg.format(port.port_handle, ifname, ospf_pkt_type))
        for iface in port.interfaces.values():
            self.logger.info(msg.format(iface.handle, ifname, ospf_pkt_type))
            for session in iface.ospf_sessions.values():
                self.logger.info(msg.format(session.handle, ifname, session.active))
                if not session.active:
                    continue
                try:
                    if ospf_pkt_type == 1:
                        resp = Ether() / IP(ttl=1) / OSPF_Hdr() / OSPF_Hello()
                        resp.src = "52:54:00:b6:f8:28"
                        resp.src = iface.mymac[0]
                        resp[IP].src = iface.kws["intf_ip_addr"]
                        neighbors = [pkt[OSPF_Hdr].src]
                        resp[OSPF_Hdr].src = session.kws["router_id"]
                        resp[OSPF_Hdr].area = session.kws["area_id"]
                        resp[OSPF_Hello].router = iface.kws["intf_ip_addr"]
                        resp[OSPF_Hello].router = pkt[OSPF_Hello].router
                        resp[OSPF_Hello].backup = pkt[OSPF_Hello].backup
                        resp[OSPF_Hello].neighbors = neighbors
                        resp[OSPF_Hello].options = pkt[OSPF_Hello].options
                        self.pkt_debug(pkt, resp, "ospf", ifname)
                        self.pif.send(resp, ifname, trace=True)
                    elif ospf_pkt_type == 2:
                        hdr_list = []
                        for route in session.routes.values():
                            if route.deleted:
                                continue
                            hdr = OSPF_LSA_Hdr()
                            count, start, step = 0, "", "0.0.1.0"
                            if route.kws["type"] == "ext_routes":
                                count = int(route.kws.get("external_number_of_prefix", 1))
                                start = route.kws.get("external_prefix_start")
                                hdr.type = 5
                            elif route.kws["type"] == "summary_routes":
                                count = int(route.kws.get("summary_number_of_prefix", 1))
                                start = route.kws.get("summary_prefix_start")
                                hdr.type = 3
                            elif route.kws["ipv4_prefix_route_origin"] in ["same_area", "summary", "external"]:
                                count = int(route.kws.get("ipv4_prefix_number_of_addresses", 1))
                                start = route.kws.get("ipv4_prefix_network_address")
                                if route.kws["ipv4_prefix_route_origin"] == "summary":
                                    hdr.type = 3
                                elif route.kws["ipv4_prefix_route_origin"] == "external":
                                    hdr.type = 5
                                else:
                                    hdr.type = 1
                            for _ in range(count):
                                hdr.id = start
                                start = self.utils.incrementIPv4(start, step)
                                hdr.adrouter = route.kws.get("router_id", session.kws["router_id"])
                                hdr_list.append(copy.copy(hdr))
                        try:
                            self.logger.debug("hdr_list length = {}".format(len(hdr_list)))
                        except Exception as exp:
                            self.logger.error(str(exp))

                        mtu = self.pif.get_int(iface.kws, "control_plane_mtu", pkt[OSPF_DBDesc].mtu)
                        size = len(OSPF_DBDesc(lsaheaders=[OSPF_LSA_Hdr()]))
                        chunk_size = mtu / size
                        chunked_list = [hdr_list[i:i + chunk_size] for i in range(0, len(hdr_list), chunk_size)]
                        chunk_last = len(chunked_list) - 1
                        for index, hdr_list in enumerate(chunked_list):
                            desc = OSPF_DBDesc(lsaheaders=hdr_list)
                            desc.mtu = mtu
                            desc.options = pkt[OSPF_DBDesc].options
                            desc.dbdescr = pkt[OSPF_DBDesc].dbdescr
                            desc.dbdescr = 0
                            if index == chunk_last:
                                desc.dbdescr = desc.dbdescr | "M"
                            desc.ddseq = pkt[OSPF_DBDesc].ddseq
                            resp = Ether() / IP() / OSPF_Hdr() / desc
                            resp.src = iface.mymac[0]
                            resp.dst = pkt.src
                            resp[IP].src = iface.kws["intf_ip_addr"]
                            resp[IP].dst = pkt[IP].src
                            resp[OSPF_Hdr].src = session.kws["router_id"]
                            resp[OSPF_Hdr].area = session.kws["area_id"]
                            self.pkt_debug(pkt, resp, "ospf", ifname)
                            self.pif.send(resp, ifname, trace=True)
                    elif ospf_pkt_type == 3:
                        lsa_list = []
                        # lsa = OSPF_Router_LSA()
                        # lsa.id = session.kws["router_id"]
                        # lsa.adrouter = session.kws["router_id"]
                        # lsa.metric = 20
                        # lsa.options = 0
                        # lsa_list.append(lsa)

                        link = OSPF_Link()
                        link.id = session.kws["router_id"]
                        link.data = "100.1.0.2"
                        link.metric = 10
                        lsa = OSPF_Router_LSA(linklist=[link])
                        lsa.id = session.kws["router_id"]
                        lsa.adrouter = session.kws["router_id"]
                        lsa.flags = 2
                        lsa.age = 0
                        lsa_list.append(lsa)

                        for route in session.routes.values():
                            if route.deleted:
                                continue
                            if route.kws["type"] == "ext_routes":
                                start = route.kws.get("external_prefix_start")
                                for _ in range(int(route.kws.get("external_number_of_prefix", 1))):
                                    lsa = OSPF_External_LSA()
                                    lsa.id = start
                                    start = self.utils.incrementIPv4(start, "0.0.1.0")
                                    lsa.adrouter = route.kws.get("router_id", session.kws["router_id"])
                                    lsa.metric = int(route.kws.get("external_prefix_metric", 20))
                                    lsa.options = 0
                                    lsa_list.append(lsa)
                            elif route.kws["type"] == "summary_routes":
                                start = route.kws.get("summary_prefix_start")
                                for _ in range(int(route.kws.get("summary_number_of_prefix", 1))):
                                    lsa = OSPF_SummaryIP_LSA()
                                    lsa.id = start
                                    start = self.utils.incrementIPv4(start, "0.0.1.0")
                                    lsa.adrouter = route.kws.get("router_id", session.kws["router_id"])
                                    lsa.metric = int(route.kws.get("summary_prefix_metric", 20))
                                    lsa.options = 0
                                    lsa_list.append(lsa)
                            elif route.kws["ipv4_prefix_route_origin"] in ["same_area", "summary", "external"]:
                                start = route.kws.get("ipv4_prefix_network_address")
                                for _ in range(int(route.kws.get("ipv4_prefix_number_of_addresses", 1))):
                                    if route.kws["ipv4_prefix_route_origin"] == "summary":
                                        lsa = OSPF_SummaryIP_LSA()
                                    elif route.kws["ipv4_prefix_route_origin"] == "external":
                                        lsa = OSPF_External_LSA()
                                    else:
                                        lsa = OSPF_Router_LSA()
                                    lsa.id = start
                                    start = self.utils.incrementIPv4(start, "0.0.1.0")
                                    lsa.adrouter = route.kws.get("router_id", session.kws["router_id"])
                                    lsa.metric = int(route.kws.get("ipv4_prefix_metric", 20))
                                    lsa.options = 0
                                    lsa_list.append(lsa)
                        resp = Ether() / IP() / OSPF_Hdr() / OSPF_LSUpd(lsalist=lsa_list)
                        resp.src = iface.mymac[0]
                        resp.dst = pkt.src
                        resp[IP].src = iface.kws["intf_ip_addr"]
                        resp[IP].dst = pkt[IP].src
                        resp[OSPF_Hdr].src = session.kws["router_id"]
                        resp[OSPF_Hdr].area = session.kws["area_id"]
                        self.pkt_debug(pkt, resp, "ospf", ifname)
                        self.pif.send(resp, ifname, trace=True)
                    elif ospf_pkt_type == 4:
                        lsalist = pkt[OSPF_LSUpd].lsalist
                        lsalist = []
                        for lsa in pkt[OSPF_LSUpd].lsalist:
                            # self.utils.exec_func("OSPF_LSUpd-LSA", lsa.show2)
                            hdr = OSPF_LSA_Hdr(type=lsa.type, id=lsa.id, adrouter=lsa.adrouter)
                            lsalist.append(hdr)
                        resp = Ether() / IP() / OSPF_Hdr() / OSPF_LSAck(lsaheaders=lsalist)
                        resp.src = iface.mymac[0]
                        resp.dst = pkt.src
                        resp[IP].src = iface.kws["intf_ip_addr"]
                        resp[IP].dst = pkt[IP].src
                        resp[OSPF_Hdr].src = session.kws["router_id"]
                        resp[OSPF_Hdr].area = session.kws["area_id"]
                        self.pkt_debug(pkt, resp, "ospf", ifname)
                        self.pif.send(resp, ifname, trace=True)
                    elif ospf_pkt_type == 5:
                        self.pkt_debug(pkt, None, "ospf")
                    else:
                        self.pkt_debug(pkt, None, "ospf")
                        self.logger.error("====== UNHANDLED {} ====".format(ospf_pkt_type))
                except Exception:
                    self.pkt_debug(pkt, None, "ospf")
                    self.logger.info(traceback.format_exc())
            return
        # self.logger.info("no OSPF session on {}".format(port.port_handle))
        # self.utils.exec_func(None, pkt.show2)

    def dhcp4_tx(self, port, group, action=0, recv=None, server_id="0.0.0.0",
                 requested_addr="0.0.0.0", server_mac="00:00:00:00:00:00"):
        encap = group.kws.get("encap", "ethernet_ii_vlan")
        mac_addr = group.kws.get("mac_addr", '00:11:01:00:00:01')
        vlan_id_count = self.utils.intval(group.kws, "vlan_id_count", 0)
        vlan_id_step = self.utils.intval(group.kws, "vlan_id_step", 1)
        vlan_id = self.utils.intval(group.kws, "vlan_id", 0)
        num_sessions = self.utils.intval(group.kws, "num_sessions", 0)
        max_count = self.utils.max_value(num_sessions, vlan_id_count)
        if action in [0, 3, 4, 5]:
            # use new xid for action == 0 i.e sending discover
            group.kws["xid"] = self.next_xid
            self.next_xid = self.next_xid + max_count
        for index in range(max_count):
            smac, dmac = mac_addr, 'ff:ff:ff:ff:ff:ff'
            iid, sip, dip = 0, '0.0.0.0', '255.255.255.255'
            res, ch = smac.split(":"), ""
            for i in res:
                ch = ch + chr(int(i, 16))
            options, param_req_list = [], [1, 3, 58, 59]
            xid = group.kws.get("xid", 0) + index

            if action == 0:
                options.append(("message-type", "discover"))
                options.append(("param_req_list", param_req_list))
            elif action == 1:
                options.append(("message-type", "request"))
                options.append(("server_id", server_id))
                options.append(("requested_addr", requested_addr))
                options.append(("param_req_list", param_req_list))
            elif action == 2:
                options.append(("message-type", "request"))
                options.append(("param_req_list", param_req_list))
                dmac = server_mac
                iid, sip, dip = 1, requested_addr, server_id
            elif action == 3:
                options.append(("message-type", "request"))
                dmac = group.kws.get("server_mac", server_mac)
                options.append(("param_req_list", param_req_list))
                sip = group.kws.get("requested_addr", requested_addr)
                dip = group.kws.get("server_id", server_id)
                iid = 2
            elif action == 4:
                options.append(("message-type", "request"))
                options.append(("param_req_list", param_req_list))
                sip = group.kws.get("requested_addr", requested_addr)
                iid = 3
            elif action == 5:
                options.append(("message-type", "release"))
                options.append(("server_id", server_id))
                dmac = group.kws.get("server_mac", server_mac)
                sip = group.kws.get("requested_addr", requested_addr)
                dip = group.kws.get("server_id", server_id)
                iid = 4
            options.append(("end", Padding()))

            pkt = Ether(src=smac, dst=dmac)
            if encap in ["ethernet_ii_vlan", "ethernet_ii"] and vlan_id > 0:
                # vlan_ether_type = self.pif.get_hex(group.kws, "vlan_ether_type", "0x8100")
                # pkt = pkt/Dot1Q(vlan=vlan_id, type=vlan_ether_type)
                pkt = pkt / Dot1Q(vlan=vlan_id)
            pkt = pkt / IP(id=iid, src=sip, dst=dip, flags="DF") / UDP()
            pkt = pkt / BOOTP(chaddr=ch, xid=xid)
            pkt = pkt / DHCP(options=options)
            # port.driver.enable_tx(pkt)
            self.pkt_debug(recv, pkt, "dhcp", port.iface)
            self.pif.send(pkt, port.iface, trace=True)
            vlan_id = vlan_id + vlan_id_step
            mac_addr = self.utils.incrementMac(mac_addr, "00:00:00:00:00:01")

    def mac_to_ipv6_linklocal(self, mac):
        # Remove the most common delimiters; dots, dashes, etc.
        exclude_chars = [' ', '.', ':', '-']
        mac_value = int("".join([c for c in mac if c not in exclude_chars]), 16)
        # Split out the bytes that slot into the IPv6 address
        # XOR the most significant byte with 0x02, inverting the
        # Universal / Local bit
        high2 = mac_value >> 32 & 0xffff ^ 0x0200
        high1 = mac_value >> 24 & 0xff
        low1 = mac_value >> 16 & 0xff
        low2 = mac_value & 0xffff
        return 'fe80::{:04x}:{:02x}ff:fe{:02x}:{:04x}'.format(high2, high1, low1, low2)

    def dhcp6_tx(self, port, group, action=0, recv=None, server_id_in=None,
                 requested_addr_in=None, server_mac="00:00:00:00:00:00"):
        encap = group.kws.get("encap", "ethernet_ii_vlan")
        mac_addr = group.kws.get("mac_addr", '00:11:01:00:00:01')
        vlan_id_count = self.utils.intval(group.kws, "vlan_id_count", 0)
        vlan_id_step = self.utils.intval(group.kws, "vlan_id_step", 1)
        vlan_id = self.utils.intval(group.kws, "vlan_id", 0)
        num_sessions = self.utils.intval(group.kws, "num_sessions", 0)
        max_count = self.utils.max_value(num_sessions, vlan_id_count)
        if action in [0, 3, 4, 5]:
            # use new xid for action == 0 i.e sending discover
            group.kws["xid"] = self.next_xid
            self.next_xid = self.next_xid + max_count
        for _ in range(max_count):
            smac, dmac = mac_addr, 'ff:ff:ff:ff:ff:ff'
            ip6_lloc = self.mac_to_ipv6_linklocal(smac)
            sip, dip = ip6_lloc, "ff02::1:2"
            res, ch = smac.split(":"), ""
            for i in res:
                ch = ch + chr(int(i, 16))
            options, param_req_list = [], [1, 3, 58, 59]
            requested_addr = requested_addr_in or sip
            server_id = server_id_in or dip

            if action == 0:
                dmac = "33:33:00:01:00:02"
                options.append(("message-type", "discover"))
                options.append(("param_req_list", param_req_list))
            elif action == 1:
                options.append(("message-type", "request"))
                options.append(("server_id", server_id))
                options.append(("requested_addr", requested_addr))
                options.append(("param_req_list", param_req_list))
            elif action == 2:
                options.append(("message-type", "request"))
                options.append(("param_req_list", param_req_list))
                dmac = server_mac
                sip, dip = requested_addr, server_id
            elif action == 3:
                options.append(("message-type", "request"))
                dmac = group.kws.get("server_mac", server_mac)
                options.append(("param_req_list", param_req_list))
                sip = group.kws.get("requested_addr", requested_addr)
                dip = group.kws.get("server_id", server_id)
            elif action == 4:
                options.append(("message-type", "request"))
                options.append(("param_req_list", param_req_list))
                sip = group.kws.get("requested_addr", requested_addr)
            elif action == 5:
                options.append(("message-type", "release"))
                options.append(("server_id", server_id))
                dmac = group.kws.get("server_mac", server_mac)
                sip = group.kws.get("requested_addr", requested_addr)
                dip = group.kws.get("server_id", server_id)
            options.append(("end", Padding()))

            pkt = Ether(src=smac, dst=dmac)
            if encap in ["ethernet_ii_vlan", "ethernet_ii"] and vlan_id > 0:
                # vlan_ether_type = self.pif.get_hex(group.kws, "vlan_ether_type", "0x8100")
                # pkt = pkt/Dot1Q(vlan=vlan_id, type=vlan_ether_type)
                pkt = pkt / Dot1Q(vlan=vlan_id)
            try:
                pkt = pkt / IPv6(src=sip, dst=dip, hlim=1) / UDP()
                pkt = pkt / DHCP6_Solicit()
                pkt = pkt / DHCP6OptElapsedTime()
                pkt = pkt / DHCP6OptClientId(duid=DUID_LLT(hwtype=1, lladdr=smac, type=1))
                pkt = pkt / DHCP6OptIA_NA()
                self.pkt_debug(recv, pkt, "dhcpv6", port.iface)
                self.pif.send(pkt, port.iface, trace=True)
                vlan_id = vlan_id + vlan_id_step
                mac_addr = self.utils.incrementMac(mac_addr, "00:00:00:00:00:01")
            except Exception as e:
                self.logger.info("=== SIP {} DIP {}".format(sip, dip))
                self.logger.error(e)
                raise e
            # port.driver.enable_tx(pkt)

    def dhcp_tx(self, port, group, action=0, recv=None, server_id=None,
                requested_addr=None, server_mac="00:00:00:00:00:00",
                ip_version=4):

        if ip_version != 4:
            self.dhcp6_tx(port, group, action, recv, server_id, requested_addr, server_mac)
        else:
            self.dhcp4_tx(port, group, action, recv, server_id or "0.0.0.0",
                          requested_addr or "0.0.0.0", server_mac)

    def read_dhcp_options(self, pkt):
        options = {}
        if DHCP in pkt:
            for option in pkt[DHCP].options:
                options[option[0]] = option[1]
        else:
            self.pkt_debug(pkt, None, "bootp without dhcp layer", dbg=3)
        return options

    def locate_group(self, port, pkt):
        xid = pkt[BOOTP].xid
        for client in port.dhcp_clients.values():
            for group in client.groups.values():
                vlan_id_count = self.utils.intval(group.kws, "vlan_id_count", 0)
                num_sessions = self.utils.intval(group.kws, "num_sessions", 0)
                max_count = self.utils.max_value(num_sessions, vlan_id_count)
                gxid = group.kws.get("xid", 0)
                if xid >= gxid and xid < (gxid + max_count):
                    return group
        return None

    def dhcp_rx(self, port, pkt):
        options = self.read_dhcp_options(pkt)
        if "message-type" in options:
            if options["message-type"] == 2:
                # offer received send request
                group = self.locate_group(port, pkt)
                self.dhcp_tx(port, group, 1, server_id=options["server_id"],
                             requested_addr=pkt[BOOTP].yiaddr, recv=pkt)
            if options["message-type"] == 5 and pkt[IP].id == 0:
                # ack received send renew request
                group = self.locate_group(port, pkt)
                self.dhcp_tx(port, group, 2, server_id=options["server_id"],
                             requested_addr=pkt[BOOTP].yiaddr, server_mac=pkt.src, recv=pkt)

    def igmp_tx_query(self, intf, querier, recv=None, gaddr="0.0.0.0"):
        if not querier.enable:
            return
        igmp_version = querier.kws.get("igmp_version", "v3")
        vlan_enable = self.utils.intval(intf.kws, "vlan", 0)
        vlan_id = self.utils.intval(intf.kws, "vlan_id", 0)
        sip = intf.kws.get("intf_ip_addr", "0.0.0.0")
        smac = intf.mymac[0]
        if self.pif.dbg > 2:
            self.logger.dump("IGMPQ-TX INTF", intf.kws)
            self.logger.dump("IGMPQ-TX HOST", querier)
        pkt = Ether(src=smac)
        if vlan_enable and vlan_id > 0:
            pkt = pkt / Dot1Q(vlan=vlan_id)
        if igmp_version in ["v1"]:
            pkt = pkt / IP(src=sip) / IGMP(type=0x11, gaddr=gaddr)
            pkt[IGMP].igmpize()
        elif igmp_version in ["v2"]:
            pkt = pkt / IP(src=sip) / IGMP(type=0x11, gaddr=gaddr)
            pkt[IGMP].igmpize()
        else:
            pkt = pkt / IP(src=sip) / IGMPv3(type=0x11) / IGMPv3mq(gaddr=gaddr)
            pkt[IGMPv3].igmpize()
        self.pkt_debug(recv, pkt, "igmp", intf.iface)
        self.pif.send(pkt, intf.iface, trace=True)

    def igmp_tx(self, mode, intf, host, recv=None):
        igmp_version = host.kws.get("igmp_version", "v3")
        vlan_enable = self.utils.intval(intf.kws, "vlan", 0)
        vlan_id = self.utils.intval(intf.kws, "vlan_id", 0)
        sip = intf.kws.get("intf_ip_addr", "0.0.0.0")
        smac = intf.mymac[0]
        if self.pif.dbg > 2:
            self.logger.dump("IGMP-TX INTF", intf.kws)
            self.logger.dump("IGMP-TX HOST", host)
        for grp in host.kws.get("group_pool_data", []):
            ip4_addr = grp.kws.get("ip_addr_start", "224.0.0.1")
            ip4_step = grp.kws.get("ip_addr_step", "0.0.0.1")
            for _ in range(self.utils.intval(grp.kws, "num_groups", 1)):
                if mode in ["start", "join"]:
                    v1_type, v2_type, v3_type = 0x12, 0x16, 0x22
                else:
                    v1_type, v2_type, v3_type = 0x17, 0x17, 0x22
                pkt = Ether(src=smac)
                if vlan_enable > 0 and vlan_id > 0:
                    pkt = pkt / Dot1Q(vlan=vlan_id)
                if igmp_version in ["v1"]:
                    pkt = pkt / IP(src=sip) / IGMP(type=v1_type, gaddr=ip4_addr)
                    pkt[IGMP].igmpize()
                elif igmp_version in ["v2"]:
                    pkt = pkt / IP(src=sip) / IGMP(type=v2_type, gaddr=ip4_addr)
                    pkt[IGMP].igmpize()
                else:
                    pkt = pkt / IP(src=sip) / IGMPv3(type=v3_type)
                    if mode not in ["start", "join"]:
                        pkt = pkt / IGMPv3mr(numgrp=1) / IGMPv3gr(rtype=3, maddr=ip4_addr)
                    else:
                        srcaddrs = []
                        for src in host.kws.get("source_pool_data", []):
                            ip4_src_addr = src.kws.get("ip_addr_start", "90.0.0.2")
                            ip4_src_step = src.kws.get("ip_addr_step", "0.0.0.1")
                            for _ in range(self.utils.intval(src.kws, "num_sources", 1)):
                                srcaddrs.append(ip4_src_addr)
                                ip4_src_addr = self.utils.incrementIPv4(ip4_src_addr, ip4_src_step)
                        rtype = 3 if grp.kws.get("g_filter_mode", "include") else 4
                        pkt = pkt / IGMPv3mr(numgrp=1) / IGMPv3gr(rtype=rtype, maddr=ip4_addr, srcaddrs=srcaddrs)
                    pkt[IGMPv3].igmpize()
                self.pkt_debug(recv, pkt, "igmp", intf.iface)
                self.pif.send(pkt, intf.iface, trace=True)
                ip4_addr = self.utils.incrementIPv4(ip4_addr, ip4_step)

    def igmp_rx(self, port, pkt):
        send_query, send_report = False, False
        if IGMP in pkt:
            send_query = bool(pkt[IGMP].type == 0x17)
            send_report = bool(pkt[IGMP].type == 0x11)
        elif IGMPv3 in pkt:
            send_report = bool(pkt[IGMPv3].type == 0x11)
            if IGMPv3gr in pkt and pkt[IGMPv3gr].numsrc <= 0:
                send_query = True

        for intf in port.interfaces.values():
            if send_query:
                for querier in intf.igmp_queriers.values():
                    self.igmp_tx_query(intf, querier, recv=pkt, gaddr=pkt.gaddr)
            elif send_report:
                for host in intf.igmp_hosts.values():
                    self.igmp_tx("join", intf, host, recv=pkt)

    def igmp_tx_query_periodic(self, port):
        now = self.utils.clock()
        for intf in port.interfaces.values():
            for querier in intf.igmp_queriers.values():
                tx_time = querier.get("tx_time", now)
                if tx_time < now:
                    continue
                self.igmp_tx_query(intf, querier)
                querier["tx_time"] = now + 60

    def dot1x_tx_periodic(self, port):
        now = self.utils.clock()
        for client in port.dot1x_clients.values():
            tx_time = client.get("tx_time", now)
            if tx_time < now:
                continue
            self.dot1x_tx(port, client)
            client["tx_time"] = now + 60

    def dot1x_tx(self, port, client):
        if client.mode != "start":
            return
        smac = client.kws.get("mac_addr", "00:00:00:00:00:00")
        if client.state in ["init", "logoff"]:
            eapol_type = 1 if client.state == "init" else 2
            for _ in range(self.utils.intval(client.kws, "num_sessions", 1)):
                pkt = Ether(src=smac, dst="01:80:c2:00:00:03")
                pkt = pkt / EAPOL(version=2, type=eapol_type)
                frame_size = 64
                padLen = int(frame_size - len(pkt) - 4)
                if padLen > 0:
                    padding = Padding(binascii.unhexlify('00' * padLen))
                    pkt = pkt / padding
                self.pkt_debug(None, pkt, "dot1x", port.iface, dbg=3)
                self.pif.send(pkt, port.iface, trace=True)
                smac = self.utils.incrementMac(smac, "00:00:00:00:00:01")

    def dot1x_rx(self, port, recv):
        if recv[EAP].code == 2 and recv[EAP].type == 2:
            for client in port.dot1x_clients.values():
                smac = client.kws.get("mac_addr", "00:00:00:00:00:00")
                username = client.kws.get("username", "test")
                for _ in range(self.utils.intval(client.kws, "num_sessions", 1)):
                    if recv.dst == smac:
                        pkt = Ether(src=smac, dst="01:80:c2:00:00:03")
                        pkt = pkt / EAPOL(version=2, type=0)
                        pkt = pkt / EAP(code=2, id=recv[EAP].id, type=1, identity=username)
                        self.pkt_debug(recv, pkt, "dot1x", port.iface, dbg=3)
                        self.pif.send(pkt, port.iface, trace=True)
                        client.state = ""
                        return
                    smac = self.utils.incrementMac(smac, "00:00:00:00:00:01")
        elif recv[EAP].code == 2 and recv[EAP].type == 4:
            for client in port.dot1x_clients.values():
                smac = client.kws.get("mac_addr", "00:00:00:00:00:00")
                username = client.kws.get("username", "test")
                password = client.kws.get("password", "test")
                for _ in range(self.utils.intval(client.kws, "num_sessions", 1)):
                    if recv.dst == smac:
                        pkt = Ether(src=smac, dst="01:80:c2:00:00:03")
                        pkt = pkt / EAPOL(version=2, type=0)
                        pkt = pkt / EAP(code=2, id=recv[EAP].id, type=4)
                        value = self.utils.md5sum(chr(recv[EAP].id) + self.utils.md5sum(password) + recv[EAP].value)
                        pkt[EAP].value = value
                        pkt[EAP].optional_name = username
                        self.pkt_debug(recv, pkt, "dot1x", port.iface, dbg=3)
                        self.pif.send(pkt, port.iface, trace=True)
                        client.state = ""
                        return
                    smac = self.utils.incrementMac(smac, "00:00:00:00:00:01")
