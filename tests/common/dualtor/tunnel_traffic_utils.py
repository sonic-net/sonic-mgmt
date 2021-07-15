"""Tunnel traffic verification utilities."""
import ipaddress
import logging
import operator
import pytest
import re

from ptf import mask, testutils
from scapy.all import IP, Ether
from tests.common.dualtor import dual_tor_utils
from tests.common.utilities import dump_scapy_packet_show_output
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert


def derive_queue_id_from_dscp(dscp):
    """ Derive queue id form DSCP using following mapping
          DSCP -> Queue mapping
            8          0
            5          2
            3          3
            4          4
            46         5
            48         6
            Rest       1
    """

    dscp_to_queue = { 8 : 0, 5 : 2, 3 : 3, 4 : 4, 46  : 5,  48 : 6}

    return dscp_to_queue.get(dscp, 1)

def queue_stats_check(dut, exp_queue):
    queue_counter = dut.shell('show queue counters | grep "UC"')['stdout']
    logging.debug('queue_counter:\n{}'.format(queue_counter))

    """
    regex search will look for following pattern in queue_counter outpute
    ----------------------------------------------------------------------------_---
    Port           TxQ    Counter/pkts     Counter/bytes     Drop/pkts    Drop/bytes
    -----------  -----  --------------  ---------------  -----------  --------------
    Ethernet124    UC1              10             1000            0             0
    """
    result = re.findall(r'\S+\s+UC%d\s+10+\s+\S+\s+\S+\s+\S+' % exp_queue, queue_counter)

    if result:
        for line in result:
            rec_queue = int(line.split()[1][2])
            if rec_queue != exp_queue:
                logging.debug("the expected Queue : {} not matching with received Queue : {}".format(exp_queue, rec_queue))
            else:
                logging.info("the expected Queue : {} matching with received Queue : {}".format(exp_queue, rec_queue))
                return True
    else:
        logging.debug("Could not find queue counter matches.")
    return False


@pytest.fixture(scope="function")
def tunnel_traffic_monitor(ptfadapter, tbinfo):
    """Return TunnelTrafficMonitor to verify inter-ToR tunnel traffic."""

    class TunnelTrafficMonitor(object):
        """Monit tunnel traffic from standby ToR to active ToR."""

        @staticmethod
        def _get_t1_ptf_port_indexes(dut, tbinfo):
            """Get the port indexes of those ptf port connecting to T1 switches."""
            pc_ports = dual_tor_utils.get_t1_ptf_pc_ports(dut, tbinfo)
            return [int(_.strip("eth")) for _ in reduce(operator.add, pc_ports.values(), [])]

        @staticmethod
        def _find_ipv4_lo_addr(config_facts):
            """Find the ipv4 Loopback0 address."""
            for addr in config_facts["LOOPBACK_INTERFACE"]["Loopback0"]:
                if isinstance(ipaddress.ip_network(addr), ipaddress.IPv4Network):
                    return addr.split("/")[0]

        @staticmethod
        def _build_tunnel_packet(outer_src_ip, outer_dst_ip):
            """Build the expected tunnel packet."""
            exp_pkt = testutils.simple_ip_packet(
                ip_src=outer_src_ip,
                ip_dst=outer_dst_ip,
                pktlen=20
            )
            exp_pkt = mask.Mask(exp_pkt)
            exp_pkt.set_do_not_care_scapy(Ether, "dst")
            exp_pkt.set_do_not_care_scapy(Ether, "src")
            exp_pkt.set_do_not_care_scapy(IP, "ihl")
            exp_pkt.set_do_not_care_scapy(IP, "tos")
            exp_pkt.set_do_not_care_scapy(IP, "len")
            exp_pkt.set_do_not_care_scapy(IP, "id")
            exp_pkt.set_do_not_care_scapy(IP, "flags")
            exp_pkt.set_do_not_care_scapy(IP, "frag")
            exp_pkt.set_do_not_care_scapy(IP, "ttl")
            exp_pkt.set_do_not_care_scapy(IP, "proto")
            exp_pkt.set_do_not_care_scapy(IP, "chksum")
            exp_pkt.set_ignore_extra_bytes()
            return exp_pkt

        @staticmethod
        def _check_ttl(packet):
            """Check ttl field in the packet."""
            outer_ttl, inner_ttl = packet[IP].ttl, packet[IP].payload[IP].ttl
            logging.info("Outer packet TTL: %s, inner packet TTL: %s", outer_ttl, inner_ttl)
            if outer_ttl != 255:
                return "outer packet's TTL expected TTL 255, actual %s" % outer_ttl
            return ""

        @staticmethod
        def _check_tos(packet):
            """Check ToS field in the packet."""

            def _disassemble_ip_tos(tos):
                return tos >> 2, tos & 0x3

            outer_tos, inner_tos = packet[IP].tos, packet[IP].payload[IP].tos
            outer_dscp, outer_ecn = _disassemble_ip_tos(outer_tos)
            inner_dscp, inner_ecn = _disassemble_ip_tos(inner_tos)
            logging.info("Outer packet DSCP: {0:06b}, inner packet DSCP: {1:06b}".format(outer_dscp, inner_dscp))
            logging.info("Outer packet ECN: {0:02b}, inner packet ECN: {0:02b}".format(outer_ecn, inner_ecn))
            check_res = []
            if outer_dscp != inner_dscp:
                check_res.append("outer packet DSCP not same as inner packet DSCP")
            if outer_ecn != inner_ecn:
                check_res.append("outer packet ECN not same as inner packet ECN")
            return " ,".join(check_res)

        @staticmethod
        def _check_queue(self, packet):
            """Check queue for encap packet."""

            def _disassemble_ip_tos(tos):
                return tos >> 2, tos & 0x3


            outer_tos, inner_tos = packet[IP].tos, packet[IP].payload[IP].tos
            outer_dscp, outer_ecn = _disassemble_ip_tos(outer_tos)
            inner_dscp, inner_ecn = _disassemble_ip_tos(inner_tos)
            logging.info("Outer packet DSCP: {0:06b}, inner packet DSCP: {1:06b}".format(outer_dscp, inner_dscp))
            check_res = []
            if outer_dscp != inner_dscp:
                check_res.append("outer packet DSCP not same as inner packet DSCP")
            exp_queue = derive_queue_id_from_dscp(outer_dscp)

            pytest_assert(wait_until(60, 5, queue_stats_check, self.standby_tor, exp_queue))
            return check_res

        def __init__(self, standby_tor, active_tor=None, existing=True):
            """
            Init the tunnel traffic monitor.

            @param standby_tor: standby ToR that does the encap.
            @param active_tor: active ToR that decaps the tunnel traffic.
            """
            self.active_tor = active_tor
            self.standby_tor = standby_tor
            self.listen_ports = sorted(self._get_t1_ptf_port_indexes(standby_tor, tbinfo))
            self.ptfadapter = ptfadapter

            standby_tor_cfg_facts = self.standby_tor.config_facts(
                host=self.standby_tor.hostname, source="running"
            )["ansible_facts"]
            self.standby_tor_lo_addr = self._find_ipv4_lo_addr(standby_tor_cfg_facts)
            if self.active_tor:
                active_tor_cfg_facts = self.active_tor.config_facts(
                    host=self.active_tor.hostname, source="running"
                )["ansible_facts"]
                self.active_tor_lo_addr = self._find_ipv4_lo_addr(active_tor_cfg_facts)
            else:
                self.active_tor_lo_addr = [
                    _["address_ipv4"] for _ in standby_tor_cfg_facts["PEER_SWITCH"].values()
                ][0]

            self.exp_pkt = self._build_tunnel_packet(self.standby_tor_lo_addr, self.active_tor_lo_addr)
            self.rec_pkt = None
            self.existing = existing

        def __enter__(self):
            # clear queue counters before IO to ensure _check_queue could get more precise result
            self.standby_tor.shell("sonic-clear queuecounters")
            self.ptfadapter.dataplane.flush()

        def __exit__(self, *exc_info):
            if exc_info[0]:
                return
            try:
                port_index, rec_pkt = testutils.verify_packet_any_port(
                    ptfadapter,
                    self.exp_pkt,
                    ports=self.listen_ports
                )
            except AssertionError as detail:
                logging.debug("Error occurred in polling for tunnel traffic", exc_info=True)
                if "Did not receive expected packet on any of ports" in str(detail):
                    if self.existing:
                        raise detail
                else:
                    raise detail
            else:
                self.rec_pkt = Ether(rec_pkt)
                rec_port = self.listen_ports[port_index]
                logging.info("Receive encap packet from PTF interface %s", "eth%s" % rec_port)
                logging.info("Encapsulated packet:\n%s", dump_scapy_packet_show_output(self.rec_pkt))
                if not self.existing:
                    raise RuntimeError("Detected tunnel traffic from host %s." % self.standby_tor.hostname)
                ttl_check_res = self._check_ttl(self.rec_pkt)
                tos_check_res = self._check_tos(self.rec_pkt)
                queue_check_res = self._check_queue(self, self.rec_pkt)
                check_res = []
                if ttl_check_res:
                    check_res.append(ttl_check_res)
                if tos_check_res:
                    check_res.append(tos_check_res)
                if queue_check_res:
                    check_res.append(queue_check_res)
                if check_res:
                    raise ValueError(", ".join(check_res) + ".")

    return TunnelTrafficMonitor
