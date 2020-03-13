import ast
import json
import logging
import subprocess

from collections import defaultdict
from ipaddress import ip_address, ip_network

import ptf
import ptf.packet as scapy
import ptf.dataplane as dataplane

from ptf import config
from ptf.base_tests import BaseTest
from ptf.testutils import *
from ptf.mask import Mask

class VlanTest(BaseTest):
    def __init__(self):
        BaseTest.__init__(self)
        self.test_params = test_params_get()
    #--------------------------------------------------------------------------

    def log(self, message):
        logging.info(message)
    #--------------------------------------------------------------------------

    def shell(self, cmds):
        sp = subprocess.Popen(cmds, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = sp.communicate()
        rc = sp.returncode

        return stdout, stderr, rc
    #--------------------------------------------------------------------------

    def setUp(self):
        self.vlan_ports_list = ast.literal_eval(self.test_params["vlan_ports_list"])
        self.vlan_intf_list = ast.literal_eval(self.test_params["vlan_intf_list"])
        self.router_mac = self.test_params["router_mac"]

        for vlan_port in self.vlan_ports_list:
            vlan_port["pvid"] = int(vlan_port["pvid"])
            vlan_port["is_lag"] = eval(vlan_port["is_lag"])

        self.dataplane = ptf.dataplane_instance
        self.test_params = test_params_get()
        self.log("Create VLAN intf")

        for vlan_port in self.vlan_ports_list:
            for permit_vlanid in vlan_port["permit_vlanid"].keys():
                if int(permit_vlanid) != vlan_port["pvid"]:
                    port_list = vlan_port["port_indices"] if vlan_port["is_lag"] else [vlan_port["port_index"]]
                    for port in port_list:
                        self.shell(["ip", "link", "add", "link", "eth%d"%port,
                                    "name", "eth%d.%s"%(port, permit_vlanid),
                                    "type", "vlan", "id", str(permit_vlanid)])
                        self.shell(["ip", "link", "set",
                                    "eth%d.%s"%(port, permit_vlanid), "up"])

        self.setUpArpResponder()
        self.log("Start arp_responder")
        self.shell(["supervisorctl", "start", "arp_responder"])

        logging.info("VLAN test starting ...")
        pass
    #--------------------------------------------------------------------------

    def setUpArpResponder(self):
        vlan_ports_list = self.vlan_ports_list
        d = defaultdict(list)
        for vlan_port in vlan_ports_list:
            for permit_vlanid in vlan_port["permit_vlanid"].keys():
                port_list = vlan_port["port_indices"] if vlan_port["is_lag"] else [vlan_port["port_index"]]
                for port in port_list:
                    if int(permit_vlanid) == vlan_port["pvid"]:
                        iface = "eth%d" % port
                    else:
                        iface = "eth%d.%s" % (port, permit_vlanid)
                    d[iface].append(vlan_port["permit_vlanid"][str(permit_vlanid)]["peer_ip"])
        with open('/tmp/from_t1.json', 'w') as file:
            json.dump(d, file)

    #--------------------------------------------------------------------------
    def tearDown(self):
        logging.info("VLAN test ending ...")

        self.log("Stop arp_responder")
        self.shell(["supervisorctl", "stop", "arp_responder"])

        self.log("Delete VLAN intf")
        for vlan_port in self.vlan_ports_list:
            for permit_vlanid in vlan_port["permit_vlanid"].keys():
                if int(permit_vlanid) != vlan_port["pvid"]:
                    port_list = vlan_port["port_indices"] if vlan_port["is_lag"] else [vlan_port["port_index"]]
                    for port in port_list:
                        self.shell(["ip", "link", "delete", "eth%d.%s"%(port, permit_vlanid)])
        pass

    #--------------------------------------------------------------------------
    def build_icmp_packet(self, vlan_id,
                          src_mac="00:22:00:00:00:02", dst_mac="ff:ff:ff:ff:ff:ff",
                          src_ip="192.168.0.1", dst_ip="192.168.0.2", ttl=64):
        pkt = simple_icmp_packet(pktlen=100 if vlan_id == 0 else 104,
                                 eth_dst=dst_mac,
                                 eth_src=src_mac,
                                 dl_vlan_enable=False if vlan_id == 0 else True,
                                 vlan_vid=vlan_id,
                                 vlan_pcp=0,
                                 ip_src=src_ip,
                                 ip_dst=dst_ip,
                                 ip_ttl=ttl)
        return pkt

    #--------------------------------------------------------------------------
    def verify_packets_any_ports(self, test, pkt, ports=[], device_number=0):
        """
        Check that a packet is received on _any_ of the specified ports belonging to
        the given device (default device_number is 0).
        """
        received = False
        failures = []
        for device, port in ptf_ports():
            if device != device_number:
                continue
            if port in ports:
                logging.debug("Checking for pkt on device %d, port %d", device_number, port)
                result = dp_poll(test, device_number=device, port_number=port, exp_pkt=pkt)
                if isinstance(result, test.dataplane.PollSuccess):
                    received = True
                else:
                    failures.append((port, result))

        verify_no_other_packets(test)

        if not received:
            def format_failure(port, failure):
                return "On port %d:\n%s" % (port, failure.format())
            for f in failures:
                self.log("\nf: " + str(f))
            failure_report = "\n".join([format_failure(f[0], f[1]) for f in failures])
            test.fail("Did not receive expected packet on any of ports %r for device %d.\n%s"
                        % (ports, device_number, failure_report))

    #--------------------------------------------------------------------------
    def verify_icmp_packets(self, vlan_port, vlan_id):
        untagged_dst_ports = []
        tagged_dst_ports = []
        untagged_pkts = []
        tagged_pkts = []
        untagged_pkt = self.build_icmp_packet(0)
        tagged_pkt = self.build_icmp_packet(vlan_id)

        for port in self.vlan_ports_list:
            vlan_port_list = vlan_port["port_indices"] if vlan_port["is_lag"] else vlan_port["port_index"]
            port_list = port["port_indices"] if port["is_lag"] else port["port_index"]
            if vlan_port_list == port_list:
                # Skip src port
                continue
            if port["is_lag"]:
                if port["pvid"] == vlan_id:
                    self.log("Verify untagged packets from ports " + str(port_list))
                    self.verify_packets_any_ports(self, untagged_pkt, port_list)
                else:
                    self.log("Verify tagged packets from ports " + str(port_list))
                    self.verify_packets_any_ports(self, tagged_pkt, port_list)
            else:
                if port["pvid"] == vlan_id:
                    untagged_dst_ports.append(port_list)
                    untagged_pkts.append(untagged_pkt)
                elif vlan_id in map(int, port["permit_vlanid"].keys()):
                    tagged_dst_ports.append(port_list)
                    tagged_pkts.append(tagged_pkt)
        self.log("Verify untagged packets from ports " + str(untagged_dst_ports) + " tagged packets from ports " + str(tagged_dst_ports))
        verify_each_packet_on_each_port(self, untagged_pkts+tagged_pkts, untagged_dst_ports+tagged_dst_ports)

    #--------------------------------------------------------------------------
    def verify_icmp_packets_from_specified_lag(self, port_indices, vlan_id, src_mac, src_ip, dst_ip, ttl):
        self.log("Verify packet from port " + str(port_indices))
        exp_pkt = []
        for port in port_indices:
            pkt = self.build_icmp_packet(vlan_id, src_mac, self.dataplane.get_mac(0, port), src_ip, dst_ip, ttl)
            exp_pkt.append(pkt)
        verify_any_packet_any_port(self, exp_pkt, port_indices)

    #--------------------------------------------------------------------------
    def verify_icmp_packets_from_specified_port(self, port_id, vlan_id, src_mac, src_ip, dst_ip, ttl):
        self.log("Verify packet from port " + str(port_id))
        pkt = self.build_icmp_packet(vlan_id, src_mac, self.dataplane.get_mac(0, port_id), src_ip, dst_ip, ttl)
        verify_packet(self, pkt, port_id)

    #--------------------------------------------------------------------------
    def runTest(self):
        vlan_ports_list = self.vlan_ports_list
        vlan_intf_list = self.vlan_intf_list


        # Test case #1
        self.log("Test case #1 starting ...")
        # Send untagged packets from each port.
        # Verify packets egress without tag from ports whose PVID same with ingress port
        # Verify packets egress with tag from ports who include VLAN ID but PVID different from ingress port.
        for vlan_port in vlan_ports_list:
            pkt = self.build_icmp_packet(0)
            src_port = vlan_port["port_indices"][0] if vlan_port["is_lag"] else vlan_port["port_index"]
            self.log("Send untagged packet from {} ...".format(str(src_port)))
            self.log(pkt.sprintf("%Ether.src% %IP.src% -> %Ether.dst% %IP.dst%"))
            send(self, src_port, pkt)
            self.verify_icmp_packets(vlan_port, vlan_port["pvid"])

        # Test case #2
        self.log("Test case #2 starting ...")
        # Send tagged packets from each port.
        # Verify packets egress without tag from ports whose PVID same with ingress port
        # Verify packets egress with tag from ports who include VLAN ID but PVID different from ingress port.
        for vlan_port in vlan_ports_list:
            for permit_vlanid in map(int, vlan_port["permit_vlanid"].keys()):
                pkt = self.build_icmp_packet(permit_vlanid)
                src_port = vlan_port["port_indices"][0] if vlan_port["is_lag"] else vlan_port["port_index"]
                self.log("Send tagged({}) packet from {} ...".format(permit_vlanid, str(src_port)))
                self.log(pkt.sprintf("%Ether.src% %IP.src% -> %Ether.dst% %IP.dst%"))
                send(self, src_port, pkt)
                self.verify_icmp_packets(vlan_port, permit_vlanid)

        # Test case #3
        # Send packets with invalid VLAN ID
        # Verify no port can receive these pacekts
        self.log("Test case #3 starting ...")
        invalid_tagged_pkt = self.build_icmp_packet(4095)
        masked_invalid_tagged_pkt = Mask(invalid_tagged_pkt)
        masked_invalid_tagged_pkt.set_do_not_care_scapy(scapy.Dot1Q, "vlan")

        for vlan_port in vlan_ports_list:
            src_port = vlan_port["port_indices"][0] if vlan_port["is_lag"] else vlan_port["port_index"]
            dst_ports = []
            for port in vlan_ports_list:
                if port == vlan_port:
                    continue
                port_list = port["port_indices"] if port["is_lag"] else [port["port_index"]]
                dst_ports.extend(port_list)
            self.log("Send invalid tagged packet " + " from " + str(src_port) + "...")
            self.log(invalid_tagged_pkt.sprintf("%Ether.src% %IP.src% -> %Ether.dst% %IP.dst%"))
            send(self, src_port, invalid_tagged_pkt)
            self.log("Check on " + str(dst_ports) + "...")
            verify_no_packet_any(self, masked_invalid_tagged_pkt, dst_ports)

        # Test case #4
        # Send packets over VLAN interfaces.
        # Verify packets can be receive on the egress port.
        self.log("Test case #4 starting ...")

        target_list = []
        for vlan_port in vlan_ports_list:
            for vlan_id in vlan_port["permit_vlanid"].keys():
                item = {"vlan_id": int(vlan_id),
                        "peer_ip": vlan_port["permit_vlanid"][vlan_id]["peer_ip"],
                        "remote_ip": vlan_port["permit_vlanid"][vlan_id]["remote_ip"],
                        "pvid": vlan_port["pvid"], "is_lag": vlan_port["is_lag"]}

                if vlan_port["is_lag"]:
                    item["port_indices"] = vlan_port["port_indices"]
                else:
                    item["port_index"] = vlan_port["port_index"]

                target_list.append(item)

        for vlan_port in vlan_ports_list:
            src_port = vlan_port["port_indices"][0] if vlan_port["is_lag"] else vlan_port["port_index"]
            src_mac = self.dataplane.get_mac(0, src_port)
            dst_mac = self.router_mac
            for vlan_id in map(int, vlan_port["permit_vlanid"].keys()):
                # Test for for directly-connected routing
                src_ip = vlan_port["permit_vlanid"][str(vlan_id)]["peer_ip"]
                for target in target_list:
                    if vlan_id == target["vlan_id"]:
                        # Skip same VLAN forwarding
                        continue
                    pkt = self.build_icmp_packet(vlan_id if vlan_id != vlan_port["pvid"] else 0,
                                          src_mac, dst_mac, src_ip, target["peer_ip"])
                    send(self, src_port, pkt)
                    self.log("Send {} packet from {} ...".format("untagged" if vlan_id == 0 else "tagged(%d)"%vlan_id, src_port))
                    self.log(pkt.sprintf("%Ether.src% %IP.src% -> %Ether.dst% %IP.dst%"))
                    if target["is_lag"]:
                        self.verify_icmp_packets_from_specified_lag(target["port_indices"],
                                                                    target["vlan_id"] if target["vlan_id"] != target["pvid"] else 0,
                                                                    dst_mac, src_ip, target["peer_ip"], 63)
                    else:
                        self.verify_icmp_packets_from_specified_port(target["port_index"],
                                                                     target["vlan_id"] if target["vlan_id"] != target["pvid"] else 0,
                                                                     dst_mac, src_ip, target["peer_ip"], 63)

                # Test for for indirectly-connected routing
                src_ip = vlan_port["permit_vlanid"][str(vlan_id)]["remote_ip"]
                for target in target_list:
                    if vlan_id == target["vlan_id"]:
                        # Skip same VLAN forwarding
                        continue
                    pkt = self.build_icmp_packet(vlan_id if vlan_id != vlan_port["pvid"] else 0,
                                          src_mac, dst_mac, src_ip, target["remote_ip"])
                    self.log("Send {} packet from {} ...".format("untagged" if vlan_id == 0 else "tagged(%d)"%vlan_id, src_port))
                    self.log(pkt.sprintf("%Ether.src% %IP.src% -> %Ether.dst% %IP.dst%"))
                    send(self, src_port, pkt)
                    if target["is_lag"]:
                        self.verify_icmp_packets_from_specified_lag(target["port_indices"],
                                                                    target["vlan_id"] if target["vlan_id"] != target["pvid"] else 0,
                                                                    dst_mac, src_ip, target["remote_ip"], 63)
                    else:
                        self.verify_icmp_packets_from_specified_port(target["port_index"],
                                                                     target["vlan_id"] if target["vlan_id"] != target["pvid"] else 0,
                                                                     dst_mac, src_ip, target["remote_ip"], 63)

        # Test case #5
        # Send ICMP packets to VLAN interfaces.
        # Verify ICMP reply packets can be received from ingress port.
        self.log("Test case #5 starting ...")
        for vlan_port in vlan_ports_list:
            src_port = vlan_port["port_indices"][0] if vlan_port["is_lag"] else vlan_port["port_index"]
            src_mac = self.dataplane.get_mac(0, src_port)
            dst_mac = self.router_mac
            for vlan_id in map(int, vlan_port["permit_vlanid"].keys()):
                src_ip = vlan_port["permit_vlanid"][str(vlan_id)]["peer_ip"]
                for vlan_intf in vlan_intf_list:
                    if int(vlan_intf["vlan_id"]) != vlan_id:
                        continue
                    dst_ip = vlan_intf["ip"].split("/")[0]
                    pkt = self.build_icmp_packet(vlan_id if vlan_id != vlan_port["pvid"] else 0,
                                          src_mac, dst_mac, src_ip, dst_ip)
                    self.log("Send {} packet from {} ...".format("untagged" if vlan_id == 0 else "tagged(%d)"%vlan_id, src_port))
                    self.log(pkt.sprintf("%Ether.src% %IP.src% -> %Ether.dst% %IP.dst%"))
                    send(self, src_port, pkt)
                    exp_pkt = simple_icmp_packet(eth_src=self.router_mac,
                                           eth_dst=src_mac,
                                           dl_vlan_enable=True if vlan_id != vlan_port["pvid"] else False,
                                           vlan_vid=vlan_id if vlan_id != vlan_port["pvid"] else 0,
                                           vlan_pcp=0,
                                           ip_dst=src_ip,
                                           ip_src=dst_ip,
                                           icmp_type=0,
                                           icmp_code=0)

                    masked_exp_pkt = Mask(exp_pkt)
                    masked_exp_pkt.set_do_not_care_scapy(scapy.IP, "id")
                    port_list = vlan_port["port_indices"] if vlan_port["is_lag"] else [vlan_port["port_index"]]
                    verify_packets(self, masked_exp_pkt, list(str(port_list)))
                    self.log("Verify packet from port " + str(port_list))
    #--------------------------------------------------------------------------