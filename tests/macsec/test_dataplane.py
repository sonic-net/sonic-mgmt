from time import sleep
import pytest
import logging
import re
import scapy.all as scapy
import ptf.testutils as testutils
from collections import Counter

from tests.common.devices.eos import EosHost
from .macsec_helper import create_pkt, create_exp_pkt, check_macsec_pkt,\
                           get_ipnetns_prefix, get_macsec_sa_name, get_macsec_counters
from .macsec_platform_helper import get_portchannel, find_portchannel_from_member

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.macsec_required,
    pytest.mark.topology("t0", "t2", "t0-sonic"),
]


class TestDataPlane():
    BATCH_COUNT = 10

    def test_server_to_neighbor(self, duthost, ctrl_links, downstream_links,
                                upstream_links, ptfadapter, wait_mka_establish):
        ptfadapter.dataplane.set_qlen(TestDataPlane.BATCH_COUNT * 100)

        down_link = list(downstream_links.values())[0]
        dut_macaddress = duthost.get_dut_iface_mac(list(ctrl_links.keys())[0])

        setattr(ptfadapter, "force_reload_macsec", True)

        for portchannel in list(get_portchannel(duthost).values()):
            members = portchannel["members"]

            if not members:
                continue

            is_protected_link = members[0] in ctrl_links
            peer_ports = []
            ptf_injected_ports = []
            for port_name in members:
                if is_protected_link:
                    assert port_name in ctrl_links
                    peer_ports.append(
                        int(re.search(r"(\d+)", ctrl_links[port_name]["port"]).group(1)))
                    ptf_injected_ports.append(
                        upstream_links[port_name]["ptf_port_id"])
                else:
                    assert port_name not in ctrl_links
            if not is_protected_link:
                continue

            up_link = upstream_links[members[0]]
            up_host_name = up_link["name"]
            up_host_ip = up_link["local_ipv4_addr"]
            payload = "{} -> {}".format(down_link["name"], up_host_name)
            logging.info(payload)
            # Source mac address is not useful in this test case and we use an arbitrary mac address as the source
            pkt = create_pkt(
                "00:01:02:03:04:05", dut_macaddress, "1.2.3.4", up_host_ip, bytes(payload, encoding='utf8'))
            exp_pkt = create_exp_pkt(pkt, pkt[scapy.IP].ttl - 1)

            fail_message = ""
            for port_name in members:
                up_link = upstream_links[port_name]
                testutils.send_packet(
                    ptfadapter, down_link["ptf_port_id"], pkt, TestDataPlane.BATCH_COUNT)
                result = check_macsec_pkt(test=ptfadapter,
                                          ptf_port_id=up_link["ptf_port_id"],  exp_pkt=exp_pkt, timeout=30)
                if result is None:
                    return
                fail_message += result
            pytest.fail(fail_message)

    def test_dut_to_neighbor(self, duthost, ctrl_links, upstream_links, wait_mka_establish):
        for up_port, up_link in list(upstream_links.items()):
            ret = duthost.command(
                "{} ping -c {} {}".format(get_ipnetns_prefix(duthost, up_port), 4, up_link['local_ipv4_addr']))
            assert not ret['failed']

    def test_neighbor_to_neighbor(self, duthost, ctrl_links, upstream_links, wait_mka_establish):
        portchannels = list(get_portchannel(duthost).values())
        for i in range(len(portchannels)):
            assert portchannels[i]["members"]
            requester = upstream_links[portchannels[i]["members"][0]]
            # Set DUT as the gateway of requester
            if isinstance(requester["host"], EosHost):
                requester["host"].eos_config(lines=["ip route 0.0.0.0/0 {}".format(
                    requester["peer_ipv4_addr"])], module_ignore_errors=True)
            else:
                requester["host"].shell("ip route add 0.0.0.0/0 via {}".format(
                    requester["peer_ipv4_addr"]), module_ignore_errors=True)
            for j in range(i + 1, len(portchannels)):
                if portchannels[i]["members"][0] not in ctrl_links and portchannels[j]["members"][0] not in ctrl_links:
                    continue
                responser = upstream_links[portchannels[j]["members"][0]]
                # Set DUT as the gateway of responser
                if isinstance(responser["host"], EosHost):
                    responser["host"].eos_config(lines=["ip route 0.0.0.0/0 {}".format(
                        responser["peer_ipv4_addr"])], module_ignore_errors=True)
                else:
                    responser["host"].shell("ip route add 0.0.0.0/0 via {}".format(
                        responser["peer_ipv4_addr"]), module_ignore_errors=True)
                # Ping from requester to responser
                assert not requester["host"].shell(
                    "ping -c 6 -v {}".format(responser["local_ipv4_addr"]))["failed"]
                if isinstance(responser["host"], EosHost):
                    responser["host"].eos_config(lines=["no ip route 0.0.0.0/0 {}".format(
                        responser["peer_ipv4_addr"])], module_ignore_errors=True)
                else:
                    responser["host"].shell("ip route del 0.0.0.0/0 via {}".format(
                        responser["peer_ipv4_addr"]), module_ignore_errors=True)
            if isinstance(requester["host"], EosHost):
                requester["host"].eos_config(lines=["no ip route 0.0.0.0/0 {}".format(
                    requester["peer_ipv4_addr"])], module_ignore_errors=True)
            else:
                requester["host"].shell("ip route del 0.0.0.0/0 via {}".format(
                    requester["peer_ipv4_addr"]), module_ignore_errors=True)

    def test_counters(self, duthost, ctrl_links, upstream_links, rekey_period, wait_mka_establish):
        if rekey_period:
            pytest.skip("Counter increase is not guaranteed in case rekey is happening")
        EGRESS_SA_COUNTERS = (
                'SAI_MACSEC_SA_STAT_OCTETS_ENCRYPTED',
                'SAI_MACSEC_SA_STAT_OUT_PKTS_ENCRYPTED',
                )
        INGRESS_SA_COUNTERS = (
                'SAI_MACSEC_SA_STAT_OCTETS_ENCRYPTED',
                'SAI_MACSEC_SA_STAT_IN_PKTS_OK',
                )
        PKT_NUM = 5
        PKT_OCTET = 1024

        # Select some one macsec link
        port_name = list(ctrl_links)[0]
        nbr_ip_addr = upstream_links[port_name]['local_ipv4_addr']
        pc = find_portchannel_from_member(port_name, get_portchannel(duthost))
        if pc:
            assert pc["status"] == "Up"
            up_ports = pc["members"]
        else:
            up_ports = [port_name]

        # Sum up start counter
        egress_start_counters = Counter()
        ingress_start_counters = Counter()
        for up_port in up_ports:
            assert up_port in ctrl_links

            asic = duthost.get_port_asic_instance(up_port)
            ns = duthost.get_namespace_from_asic_id(asic.asic_index) if duthost.is_multi_asic else ''
            egress_sa_name = get_macsec_sa_name(asic, up_port, True)
            ingress_sa_name = get_macsec_sa_name(asic, up_port, False)
            if not egress_sa_name or not ingress_sa_name:
                continue

            egress_start_counters += Counter(get_macsec_counters(asic, ns, egress_sa_name))
            ingress_start_counters += Counter(get_macsec_counters(asic, ns, ingress_sa_name))

        # Launch traffic
        ret = duthost.command(
            "{} ping -c {} -s {} {}".format(get_ipnetns_prefix(duthost, port_name), PKT_NUM, PKT_OCTET, nbr_ip_addr))
        assert not ret['failed']
        sleep(10)   # wait 10s for polling counters

        # Sum up end counter
        egress_end_counters = Counter()
        ingress_end_counters = Counter()
        for up_port in up_ports:
            asic = duthost.get_port_asic_instance(up_port)
            ns = duthost.get_namespace_from_asic_id(asic.asic_index) if duthost.is_multi_asic else ''
            egress_sa_name = get_macsec_sa_name(asic, up_port, True)
            ingress_sa_name = get_macsec_sa_name(asic, up_port, False)
            if not egress_sa_name or not ingress_sa_name:
                continue

            egress_end_counters += Counter(get_macsec_counters(asic, ns, egress_sa_name))
            ingress_end_counters += Counter(get_macsec_counters(asic, ns, ingress_sa_name))

        i = 'SAI_MACSEC_SA_ATTR_CURRENT_XPN'
        assert egress_end_counters[i] - egress_start_counters[i] >= PKT_NUM
        assert ingress_end_counters[i] - ingress_start_counters[i] >= PKT_NUM

        if duthost.facts["asic_type"] == "vs":
            # vsonic only has xpn counter
            return

        for i in EGRESS_SA_COUNTERS:
            if 'OCTETS' in i:
                assert egress_end_counters[i] - egress_start_counters[i] >= PKT_NUM * PKT_OCTET
            else:
                assert egress_end_counters[i] - egress_start_counters[i] >= PKT_NUM

        for i in INGRESS_SA_COUNTERS:
            if 'OCTETS' in i:
                assert ingress_end_counters[i] - ingress_start_counters[i] >= PKT_NUM * PKT_OCTET
            else:
                assert ingress_end_counters[i] - ingress_start_counters[i] >= PKT_NUM
