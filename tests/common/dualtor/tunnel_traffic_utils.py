"""Tunnel traffic verification utilities."""
import ipaddress
import logging
import operator
import pytest
import re
import json

from functools import reduce
from ptf import mask, testutils
from scapy.all import IP, IPv6, Ether
from tests.common.dualtor import dual_tor_utils
from tests.common.utilities import dump_scapy_packet_show_output
from tests.common.utilities import wait_until
from tests.common.dualtor.dual_tor_utils import is_tunnel_qos_remap_enabled


def dut_dscp_tc_queue_maps(duthost):
    """
    A module level fixture to get QoS map from DUT host.
    Return a dict
    {
        "dscp_to_tc_map": {
            "AZURE": {
                "0": "1",
                ...
            },
            ...
        },
        "tc_to_queue_map": {
            "AZURE": {
                "0": "0",
                ...
            },
            ...
        },
        "tc_to_dscp_map": {
            "AZURE_TUNNEL": {
                "0": "8",
                ...
            }
        }
    }
    or an empty dict if failed to parse the output
    """
    maps = {}
    try:
        # dscp_to_tc_map
        maps['dscp_to_tc_map'] = json.loads(duthost.shell("sonic-cfggen -d --var-json 'DSCP_TO_TC_MAP'")['stdout'])
        # tc_to_queue_map
        maps['tc_to_queue_map'] = json.loads(duthost.shell("sonic-cfggen -d --var-json 'TC_TO_QUEUE_MAP'")['stdout'])
        # tc_to_dscp_map
        maps['tc_to_dscp_map'] = json.loads(duthost.shell("sonic-cfggen -d --var-json 'TC_TO_DSCP_MAP'")['stdout'])
    except Exception as e:
        logging.error("Failed to retrieve map on {}, exception {}".format(duthost.hostname, repr(e)))
    return maps


def derive_queue_id_from_dscp(duthost, dscp, is_tunnel):
    """
    Helper function to find Queue ID for a DSCP ID.
    """
    if is_tunnel_qos_remap_enabled(duthost) and is_tunnel:
        dscp_to_tc_map_name = "AZURE"
        tc_to_queue_map_name = "AZURE_TUNNEL"
        logging.info("Enable pcbb")
    else:
        dscp_to_tc_map_name = "AZURE"
        tc_to_queue_map_name = "AZURE"
    try:
        map = dut_dscp_tc_queue_maps(duthost)
        # Load dscp_to_tc_map
        tc_id = map['dscp_to_tc_map'][dscp_to_tc_map_name][str(dscp)]
        # Load tc_to_queue_map
        queue_id = map['tc_to_queue_map'][tc_to_queue_map_name][str(tc_id)]
    except Exception as e:
        logging.error("Failed to retrieve queue id for dscp {} on {}, exception {}"
                      .format(dscp, duthost.hostname, repr(e)))
        return
    return int(queue_id)


def derive_out_dscp_from_inner_dscp(duthost, inner_dscp):
    """
    Helper function to find outer DSCP ID for a inner DSCP ID.
    """
    if is_tunnel_qos_remap_enabled(duthost):
        tc_to_dscp_map_name = "AZURE_TUNNEL"
        map = dut_dscp_tc_queue_maps(duthost)
        # Load tc_to_dscp_map
        dscp_id = map['tc_to_dscp_map'][tc_to_dscp_map_name][str(inner_dscp)]
        return int(dscp_id)
    else:
        return inner_dscp


def queue_stats_check(dut, exp_queue, packet_count):
    queue_counter = dut.shell('show queue counters | grep "UC"')['stdout']
    logging.debug('queue_counter:\n{}'.format(queue_counter))
    # In case of other noise packets
    DIFF = max(10, packet_count * 0.1)

    """
    regex search will look for following pattern in queue_counter outpute
    ----------------------------------------------------------------------------_---
    Port           TxQ    Counter/pkts     Counter/bytes     Drop/pkts    Drop/bytes
    -----------  -----  --------------  ---------------  -----------  --------------
    Ethernet124    UC1             100           12,400            0             0
    """
    result = re.findall(r'\S+\s+UC%d\s+(\d+)+\s+\S+\s+\S+\s+\S+' % exp_queue, queue_counter)

    if result:
        for number in result:
            if int(number) <= packet_count + DIFF and int(number) >= packet_count:
                logging.info("the expected Queue : {} received expected numbers of packet {}"
                             .format(exp_queue, number))

                return True
        logging.debug("the expected Queue : {} did not receive expected numbers of packet : {}"
                      .format(exp_queue, packet_count))
        return False
    else:
        logging.debug("Could not find expected queue counter matches.")
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
            return [int(_.strip("eth")) for _ in reduce(operator.add, list(pc_ports.values()), [])]

        @staticmethod
        def _find_ipv4_lo_addr(config_facts):
            """Find the ipv4 Loopback0 address."""
            for addr in config_facts["LOOPBACK_INTERFACE"]["Loopback0"]:
                if isinstance(ipaddress.ip_network(addr), ipaddress.IPv4Network):
                    return addr.split("/")[0]

        @staticmethod
        def _build_tunnel_packet(outer_src_ip, outer_dst_ip, inner_packet=None):
            """Build the expected tunnel packet."""
            if inner_packet is None:
                exp_pkt = testutils.simple_ip_packet(
                    ip_src=outer_src_ip,
                    ip_dst=outer_dst_ip,
                    pktlen=20
                )
            else:
                exp_pkt = testutils.simple_ipv4ip_packet(
                    ip_src=outer_src_ip,
                    ip_dst=outer_dst_ip,
                    inner_frame=inner_packet
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
            if inner_packet is None:
                exp_pkt.set_ignore_extra_bytes()
            return exp_pkt

        @staticmethod
        def _check_ttl(packet):
            """Check ttl field in the packet."""
            outer_ttl = packet[IP].ttl
            if IP in packet[IP].payload:
                inner_ttl = packet[IP].payload[IP].ttl
            elif IPv6 in packet[IP].payload:
                inner_ttl = packet[IP].payload[IPv6].hlim
            else:
                return "Not a valid IPinIP or IPv6inIP tunnel packet"

            logging.info("Outer packet TTL: %s, inner packet TTL: %s", outer_ttl, inner_ttl)
            if outer_ttl != 255:
                return "outer packet's TTL expected TTL 255, actual %s" % outer_ttl
            return ""

        def _check_tos(self, packet):
            """Check ToS field in the packet."""

            def _disassemble_ip_tos(tos):
                return tos >> 2, tos & 0x3

            outer_tos = packet[IP].tos
            if IP in packet[IP].payload:
                inner_tos = packet[IP].payload[IP].tos
            elif IPv6 in packet[IP].payload:
                inner_tos = packet[IP].payload[IPv6].tc
            else:
                return "Not a valid IPinIP or IPv6inIP tunnel packet"

            outer_dscp, outer_ecn = _disassemble_ip_tos(outer_tos)
            inner_dscp, inner_ecn = _disassemble_ip_tos(inner_tos)
            logging.info("Outer packet DSCP: {0:06b}, inner packet DSCP: {1:06b}".format(outer_dscp, inner_dscp))
            logging.info("Outer packet ECN: {0:02b}, inner packet ECN: {1:02b}".format(outer_ecn, inner_ecn))
            check_res = []
            expected_outer_dscp = derive_out_dscp_from_inner_dscp(self.standby_tor, inner_dscp)
            if outer_dscp != expected_outer_dscp:
                check_res.append("outer packet DSCP {0:06b} not same as expected packet DSCP {1:06b}"
                                 .format(outer_dscp, expected_outer_dscp))
            if outer_ecn != inner_ecn:
                check_res.append("outer packet ECN {0:02b} not same as inner packet ECN {1:02b}"
                                 .format(outer_ecn, inner_ecn))
            return " ,".join(check_res)

        def _check_queue(self, packet):
            """Check queue for encap packet."""

            def _disassemble_ip_tos(tos):
                return tos >> 2, tos & 0x3

            outer_tos = packet[IP].tos
            if IP in packet[IP].payload:
                inner_tos = packet[IP].payload[IP].tos
            elif IPv6 in packet[IP].payload:
                inner_tos = packet[IP].payload[IPv6].tc
            else:
                return "Not a valid IPinIP or IPv6inIP tunnel packet"

            outer_dscp, _ = _disassemble_ip_tos(outer_tos)
            inner_dscp, _ = _disassemble_ip_tos(inner_tos)
            logging.info("Outer packet DSCP: {0:06b}, inner packet DSCP: {1:06b}".format(outer_dscp, inner_dscp))
            check_res = []
            # For Nvidia platforms, queue check for outer/inner dscp 2/2 and 6/6 will fail due to the diversity
            # in dscp remapping. Since we don't expect such packets in production, skip the queue check in this case.
            if self.standby_tor.is_nvidia_platform():
                logging.info("Skip the queue check for inner/outer dscp 2/2 and 6/6 on Nvidia platforms.")
                if (inner_dscp, outer_dscp) in [(2, 2), (6, 6)]:
                    return " ,".join(check_res)
            exp_queue = derive_queue_id_from_dscp(self.standby_tor, inner_dscp, True)
            logging.info("Expect queue: %s", exp_queue)
            if not wait_until(60, 5, 0, queue_stats_check, self.standby_tor, exp_queue, self.packet_count):
                check_res.append("no expect counter in the expected queue %s" % exp_queue)
            return " ,".join(check_res)

        def __init__(self, standby_tor, active_tor=None, existing=True, inner_packet=None,
                     check_items=("ttl", "tos", "queue"), packet_count=10, skip_traffic_test=False):
            """
            Init the tunnel traffic monitor.

            @param standby_tor: standby ToR that does the encap.
            @param active_tor: active ToR that decaps the tunnel traffic.
            """
            self.active_tor = active_tor
            self.standby_tor = standby_tor
            self.listen_ports = sorted(self._get_t1_ptf_port_indexes(standby_tor, tbinfo))
            self.ptfadapter = ptfadapter
            self.packet_count = packet_count
            self.skip_traffic_test = skip_traffic_test

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
                    _["address_ipv4"] for _ in list(standby_tor_cfg_facts["PEER_SWITCH"].values())
                ][0]

            self.existing = existing
            self.inner_packet = None
            if self.existing:
                self.inner_packet = inner_packet
            self.exp_pkt = self._build_tunnel_packet(self.standby_tor_lo_addr, self.active_tor_lo_addr,
                                                     inner_packet=self.inner_packet)
            self.rec_pkt = None
            self.check_items = check_items

        def __enter__(self):
            # clear queue counters before IO to ensure _check_queue could get more precise result
            self.standby_tor.shell("sonic-clear queuecounters")
            self.ptfadapter.dataplane.flush()

        def __exit__(self, *exc_info):
            if exc_info[0]:
                return
            if self.skip_traffic_test is True:
                logging.info("Skip tunnel traffic verify due to traffic test was skipped.")
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

                check_result = []
                for check_item in self.check_items:
                    check_func = getattr(self, "_check_%s" % check_item, None)
                    if check_func is not None:
                        result = check_func(self.rec_pkt)
                        if result:
                            check_result.append(result)

                if check_result:
                    raise ValueError(", ".join(check_result) + ".")

    return TunnelTrafficMonitor
