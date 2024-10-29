from time import sleep
import pytest
import logging
import re
import scapy.all as scapy
import ptf.testutils as testutils
from collections import Counter

from tests.common.devices.eos import EosHost
from .macsec_helper import create_pkt, create_exp_pkt, check_macsec_pkt,\
                           get_ipnetns_prefix, get_macsec_counters, clear_macsec_counters
from .macsec_platform_helper import get_portchannel, find_portchannel_from_member

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.macsec_required,
    pytest.mark.topology("t0", "t2"),
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

        def get_counters(duthost, up_ports):
            egress_counters = Counter()
            ingress_counters = Counter()
            for up_port in up_ports:

                egress_dict, ingress_dict = get_macsec_counters(duthost, up_port)

                egress_counters += Counter(egress_dict)
                ingress_counters += Counter(ingress_dict)

            return (egress_counters, ingress_counters)

        # multiple of rekey period to wait, to ensure a rekey has happened
        REKEY_PERIOD_WAIT_SCALE = 1.5
        PKT_OCTET = 1024
        if not rekey_period or duthost.facts["asic_type"] == "vs":
            # If no rekeys, or vsonic, only send 5 packets
            PKT_NUM = 5
        else:
            PKT_NUM = int(rekey_period * REKEY_PERIOD_WAIT_SCALE)

        # Counters which only go up
        MONOTONIC_COUNTERS = {
            "ingress": [
                'SAI_MACSEC_SA_STAT_OCTETS_ENCRYPTED',
            ],
            "egress": [
                'SAI_MACSEC_SA_STAT_OCTETS_ENCRYPTED',
            ],
        }

        # Counters which can reset during a rekey
        RESET_OVER_REKEY_COUNTERS = {
            "ingress": [
                'SAI_MACSEC_SA_ATTR_CURRENT_XPN',
                'SAI_MACSEC_SA_STAT_IN_PKTS_OK'
            ],
            "egress": [
                'SAI_MACSEC_SA_ATTR_CURRENT_XPN',
                'SAI_MACSEC_SA_STAT_OUT_PKTS_ENCRYPTED'
            ],
        }

        ALL_COUNTERS = {key: MONOTONIC_COUNTERS[key] + RESET_OVER_REKEY_COUNTERS[key] for key in MONOTONIC_COUNTERS}

        if rekey_period:
            # can only check monotonic counters if rekeying
            COUNTERS = MONOTONIC_COUNTERS
        else:
            COUNTERS = ALL_COUNTERS

        # Select some one macsec link
        port_name = list(ctrl_links)[0]
        nbr_ip_addr = upstream_links[port_name]['local_ipv4_addr']
        pc = find_portchannel_from_member(port_name, get_portchannel(duthost))
        if pc:
            assert pc["status"] == "Up"
            up_ports = pc["members"]
        else:
            up_ports = [port_name]

        for up_port in up_ports:
            assert up_port in ctrl_links

        # Sum up start counter
        egress_start_counters, ingress_start_counters = get_counters(duthost, up_ports)

        # Launch traffic at 1 sec intervals
        logging.info(f"Sending {PKT_NUM} packets")
        ret = duthost.command(
            "{} ping -c {} -s {} -i 1 {}".format(get_ipnetns_prefix(duthost, port_name),
                                                 PKT_NUM, PKT_OCTET, nbr_ip_addr))
        assert not ret['failed']
        sleep(10)   # wait 10s for polling counters

        # Sum up end counter
        egress_end_counters, ingress_end_counters = get_counters(duthost, up_ports)

        if duthost.facts["asic_type"] == "vs":
            # vsonic only has xpn counter
            i = 'SAI_MACSEC_SA_ATTR_CURRENT_XPN'
            assert egress_end_counters[i] - egress_start_counters[i] >= PKT_NUM
            assert ingress_end_counters[i] - ingress_start_counters[i] >= PKT_NUM
            return

        for counter in COUNTERS['egress']:
            if 'OCTETS' in counter:
                assert egress_end_counters[counter] - egress_start_counters[counter] >= PKT_NUM * PKT_OCTET
            else:
                assert egress_end_counters[counter] - egress_start_counters[counter] >= PKT_NUM

        for counter in COUNTERS['ingress']:
            if 'OCTETS' in counter:
                assert ingress_end_counters[counter] - ingress_start_counters[counter] >= PKT_NUM * PKT_OCTET
            else:
                assert ingress_end_counters[counter] - ingress_start_counters[counter] >= PKT_NUM

        # check that the counters get cleared
        clear_macsec_counters(duthost)

        egress_cleared_counters, ingress_cleared_counters = get_counters(duthost, up_ports)

        for counter in ALL_COUNTERS['egress']:
            assert egress_end_counters[counter] > egress_cleared_counters[counter]

        for counter in ALL_COUNTERS['ingress']:
            assert ingress_end_counters[counter] > ingress_cleared_counters[counter]

        # Wait a rekey period, and ensure the counters are still sane (ie. clear)
        if rekey_period:
            sleep_sec = rekey_period * REKEY_PERIOD_WAIT_SCALE
            logger.info(f"Waiting {sleep_sec} sec to allow for a rekey (rekey_period: {rekey_period})")
            sleep(sleep_sec)
            egress_cleared_counters, ingress_cleared_counters = get_counters(duthost, up_ports)

            for counter in ALL_COUNTERS['egress']:
                assert egress_end_counters[counter] > egress_cleared_counters[counter]

            for counter in ALL_COUNTERS['ingress']:
                assert ingress_end_counters[counter] > ingress_cleared_counters[counter]
