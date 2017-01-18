import ptf.packet as scapy
import socket
import ptf.dataplane as dataplane

from ptf.testutils import *
from ptf.mask import Mask
import ipaddress

import pprint
import ipaddress

#---------------------------------------------------------------------
# Global variables
#---------------------------------------------------------------------
PREFIX_AND_PORT_SPLITTER=" "
PORT_LIST_SPLITTER=","
PORT_GROUP_SPLITTER=";"
PORT_COUNT = 32

class RouterUtility():
    def is_ipv4_address(self, ipaddr):
        '''
        @summary: Check address is valid IPv4 address.
        @param ipaddr IP address to check
        @return Boolean
        '''
        is_valid_ipv4 = True
        try :
            # building ipaddress fails for some of addresses unless unicode(ipaddr) is specified for both ipv4/ipv6
            # Example - 192.168.156.129, it is valid IPV4 address, send_packet works with it.
            ip = ipaddress.IPv4Address(unicode(ipaddr))
        except Exception, e :
            is_valid_ipv4 = False

        return is_valid_ipv4
    #---------------------------------------------------------------------
        
    def is_ipv6_address(self, ipaddr):
        '''
        @summary: Check address is valid IPv6 address.
        @param ipaddr IP address to check
        @return Boolean
        '''
        is_valid_ipv6 = True
        try :
            ip = ipaddress.IPv6Address(unicode(ipaddr))
        except Exception, e:
            is_valid_ipv6 = False

        return is_valid_ipv6
    #---------------------------------------------------------------------
    
    def verify_packet_any_port(self, pkt, ports=[], device_number=0):
        """
        @summary: Check that the packet is received on _any_ of the specified ports belonging to
        the given device (default device_number is 0).

        The function returns when either the expected packet is received or timeout (1 second).

        Also verifies that the packet is or received on any other ports for this
        device, and that no other packets are received on the device (unless --relax
        is in effect).
        @param pkt : packet to verify
        @param ports : list of ports

        @return: index of the port on which the packet is received and the packet.
        """
        received = False
        match_index = 0
        (rcv_device, rcv_port, rcv_pkt, pkt_time) = dp_poll(
         self,
         device_number=device_number,
         exp_pkt=pkt,
         timeout=1
        )

        if rcv_port in ports:
         match_index = ports.index(rcv_port)
         received = True

        return (match_index, rcv_pkt, received)
    #---------------------------------------------------------------------
    
    def create_ipv4_packets(self, ip_src, sport, dport, dest_ip_addr, destination_port_list):
        '''
        @summary: Check IPv4 route works.
        @sport: source tcp port
        @dport: destination tcp port
        @param ip_src: source IP to build packet with.
        @param dest_ip_addr: destination IP to build packet with.
        @param destination_port_list: list of ports on which to expect packet to come back from the switch        
        @return Boolean
        '''
        ip_dst = dest_ip_addr

        src_mac = self.dataplane.get_mac(0, 0)

        pkt = simple_tcp_packet(
                            eth_dst=self.router_mac,
                            eth_src=src_mac,
                            ip_src=ip_src,
                            ip_dst=ip_dst,
                            tcp_sport=sport,
                            tcp_dport=dport,
                            ip_ttl=64)
        exp_pkt = simple_tcp_packet(
                            eth_dst=self.dataplane.get_mac(0, 0),
                            eth_src=self.router_mac,
                            ip_src=ip_src,
                            ip_dst=ip_dst,
                            tcp_sport=sport,
                            tcp_dport=dport,
                            ip_ttl=63)
        masked_exp_pkt = Mask(exp_pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether,"dst")
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether,"src")

        return (pkt, masked_exp_pkt)
    #---------------------------------------------------------------------

    def create_ipv6_packets(self,  sport, dport, ip_src, dest_ip_addr, destination_port_list):
        '''
        @summary: Check IPv4 route works.
        @param ip_src: source IP to build packet with.
        @sport: source tcp port
        @dport: destination tcp port
        @param dest_ip_addr: destination IP to build packet with.
        @param destination_port_list: list of ports on which to expect packet to come back from the switch        
        @return Boolean
        '''

        ip_dst = dest_ip_addr
        src_mac = self.dataplane.get_mac(0, 0)
        pkt = simple_tcpv6_packet(
                                eth_dst=self.router_mac,
                                eth_src=src_mac,
                                ipv6_dst=ip_dst,
                                ipv6_src=ip_src,
                                tcp_sport=sport,
                                tcp_dport=dport,
                                ipv6_hlim=64)
        exp_pkt = simple_tcpv6_packet(
                                eth_dst=self.dataplane.get_mac(0, 0),
                                eth_src=src_mac,
                                ipv6_dst=ip_dst,
                                ipv6_src=ip_src,
                                tcp_sport=sport,
                                tcp_dport=dport,
                                ipv6_hlim=63)
        masked_exp_pkt = Mask(exp_pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether,"dst")
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether,"src")
        
        return (pkt, masked_exp_pkt)
    #---------------------------------------------------------------------
    
    def check_route(self, pkt, masked_exp_pkt, source_port_index, dest_ip_addr, destination_port_list, pkt_cnt):
        '''
        @summary: Check given route works.
        @param pkt: packet to send
        @param masked_exp_pkt: expected packet
        @param source_port_index: index of port to use for sending packet to switch
        @param dest_ip_addr: destination IP to build packet with.
        @param destination_port_list: list of ports on which to expect packet to come back from the switch        
        @param pkt_cnt: number of packets to send
        @return Boolean
        '''
        send_packet(self, source_port_index, pkt, pkt_cnt)

        (match_index,rcv_pkt, received) = self.verify_packet_any_port(masked_exp_pkt,destination_port_list)        
        if not received:
            print 'src_port:%d' % source_port_index,
            print 'FAIL for ip:%s' % dest_ip_addr ,
            pprint.pprint(destination_port_list)
        return received, match_index
    #---------------------------------------------------------------------
    