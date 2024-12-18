import ipaddr as ipaddress
import json
import pytest
import time
from tests.common import config_reload
from ptf.mask import Mask
import ptf.packet as scapy
import ptf.testutils as testutils
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology('any')
]


def build_pkt(dest_mac, ip_addr, ttl):
    pkt = testutils.simple_tcp_packet(
          eth_dst=dest_mac,
          eth_src="00:11:22:33:44:55",
          pktlen=100,
          ip_src="19.0.0.100",
          ip_dst=ip_addr,
          ip_ttl=ttl,
          tcp_dport=200,
          tcp_sport=100
    )
    exp_packet = Mask(pkt)
    exp_packet.set_do_not_care_scapy(scapy.Ether, "dst")
    exp_packet.set_do_not_care_scapy(scapy.Ether, "src")

    exp_packet.set_do_not_care_scapy(scapy.IP, "version")
    exp_packet.set_do_not_care_scapy(scapy.IP, "ihl")
    exp_packet.set_do_not_care_scapy(scapy.IP, "tos")
    exp_packet.set_do_not_care_scapy(scapy.IP, "len")
    exp_packet.set_do_not_care_scapy(scapy.IP, "flags")
    exp_packet.set_do_not_care_scapy(scapy.IP, "id")
    exp_packet.set_do_not_care_scapy(scapy.IP, "frag")
    exp_packet.set_do_not_care_scapy(scapy.IP, "ttl")
    exp_packet.set_do_not_care_scapy(scapy.IP, "chksum")
    exp_packet.set_do_not_care_scapy(scapy.IP, "options")

    exp_packet.set_do_not_care_scapy(scapy.TCP, "seq")
    exp_packet.set_do_not_care_scapy(scapy.TCP, "ack")
    exp_packet.set_do_not_care_scapy(scapy.TCP, "reserved")
    exp_packet.set_do_not_care_scapy(scapy.TCP, "dataofs")
    exp_packet.set_do_not_care_scapy(scapy.TCP, "window")
    exp_packet.set_do_not_care_scapy(scapy.TCP, "chksum")
    exp_packet.set_do_not_care_scapy(scapy.TCP, "urgptr")

    exp_packet.set_ignore_extra_bytes()
    return pkt, exp_packet


def test_lag_member_forwarding_packets(duthosts, enum_rand_one_per_hwsku_frontend_hostname, tbinfo, ptfadapter):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    lag_facts = duthost.lag_facts(host=duthost.hostname)['ansible_facts']['lag_facts']
    if not len(lag_facts['lags'].keys()):
        pytest.skip("No Lag found in this topology")
    portchannel_name = list(lag_facts['lags'].keys())[0]
    portchannel_dest_name = None
    recv_port = []
    if len(lag_facts['lags'].keys()) > 1:
        portchannel_dest_name = list(lag_facts['lags'].keys())[1]
        portchannel_dest_members = list(lag_facts['lags'][portchannel_dest_name]['po_stats']['ports'].keys())
        assert len(portchannel_dest_members) > 0
        for member in portchannel_dest_members:
            recv_port.append(mg_facts['minigraph_ptf_indices'][member])

    portchannel_members = list(lag_facts['lags'][portchannel_name]['po_stats']['ports'].keys())
    assert len(portchannel_members) > 0
    asic_name = lag_facts['names'][portchannel_name]
    dest_asic_name = lag_facts['names'][portchannel_dest_name]
    asic_idx = duthost.get_asic_id_from_namespace(asic_name)
    asichost = duthost.asic_instance_from_namespace(asic_name)
    dest_asichost = duthost.asic_instance_from_namespace(dest_asic_name)

    config_facts = asichost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    dest_config_facts = dest_asichost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    send_port = mg_facts['minigraph_ptf_indices'][portchannel_members[0]]
    holdtime = 0

    peer_device_ip_set = set()
    peer_device_dest_ip = None

    # Find test (1st)  port channel and fetch it's BGP neighbors
    # ipv4 and ipv6 ip address to verify case of ping to neighbor
    for peer_device_ip, peer_device_bgp_data in config_facts['BGP_NEIGHBOR'].items():
        if peer_device_bgp_data["name"] == config_facts['DEVICE_NEIGHBOR'][portchannel_members[0]]['name']:
            peer_device_ip_set.add(peer_device_ip)
            # holdtime to wait for BGP session to go down when lag member is marked as disable state.
            if not holdtime:
                holdtime = duthost.get_bgp_neighbor_info(peer_device_ip, asic_idx)["bgpTimerHoldTimeMsecs"]
        # Find test (2nd)  port channel and fetch it's BGP neighbors
        # ipv4 and ipv6 ip address to verify data forwarding across port-channel
        elif (portchannel_dest_name and not peer_device_dest_ip
              and peer_device_bgp_data["name"] ==
              dest_config_facts['DEVICE_NEIGHBOR'][portchannel_dest_members[0]]['name'] and
              ipaddress.IPNetwork(peer_device_ip).version == 4):
            peer_device_dest_ip = peer_device_ip

    # we should have v4 and v6 peer neighbors
    assert len(peer_device_ip_set) == 2
    assert holdtime > 0

    bgp_fact_info = asichost.bgp_facts()

    for ip in peer_device_ip_set:
        assert bgp_fact_info['ansible_facts']['bgp_neighbors'][ip]['state'] == 'established'

    for ip in peer_device_ip_set:
        if ipaddress.IPNetwork(ip).version == 4:
            rc = asichost.ping_v4(ip)
        else:
            rc = asichost.ping_v6(ip)
        assert rc

    rtr_mac = asichost.get_router_mac()
    ip_ttl = 121
    ip_route = peer_device_dest_ip

    def built_and_send_tcp_ip_packet(expected):
        pkt, exp_pkt = build_pkt(rtr_mac, ip_route, ip_ttl)
        testutils.send(ptfadapter, send_port, pkt, 10)
        if expected:
            (_, recv_pkt) = testutils.verify_packet_any_port(test=ptfadapter, pkt=exp_pkt,
                                                             ports=recv_port)
            assert recv_pkt
            # Make sure routing is done
            pytest_assert(scapy.Ether(recv_pkt).ttl == (ip_ttl - 1), "Routed Packet TTL not decremented")
        else:
            testutils.verify_no_packet_any(test=ptfadapter, pkt=exp_pkt,
                                           ports=recv_port)

    if peer_device_dest_ip:
        ptfadapter.dataplane.flush()
        built_and_send_tcp_ip_packet(True)

    lag_member_file_dir = duthost.shell('mktemp')['stdout']
    lag_member_config = []
    for portchannel_member_name in portchannel_members:
        lag_member_config.append({
            "LAG_MEMBER_TABLE:{}:{}".format(portchannel_name, portchannel_member_name): {
                "status": "disabled"
            },
            "OP": "SET"
        })
    try:
        # Copy json file to DUT
        duthost.copy(content=json.dumps(lag_member_config, indent=4), dest=lag_member_file_dir, verbose=False)
        json_set = "/dev/stdin < {}".format(lag_member_file_dir)
        result = duthost.docker_exec_swssconfig(json_set, "swss", asic_idx)
        if result["rc"] != 0:
            pytest.fail(
                "Failed to apply lag member configuration file: {}".format(result["stderr"])
            )

        # Make sure data forwarding starts to fail
        if peer_device_dest_ip:
            ptfadapter.dataplane.flush()
            built_and_send_tcp_ip_packet(False)

        # make sure ping should fail
        for ip in peer_device_ip_set:
            if ipaddress.IPNetwork(ip).version == 4:
                rc = asichost.ping_v4(ip)
            else:
                rc = asichost.ping_v6(ip)

            if rc:
                pytest.fail("Ping is still working on lag disable member for neighbor {}", ip)

        time.sleep(holdtime/1000)
        # Make sure BGP goes down
        bgp_fact_info = asichost.bgp_facts()
        for ip in peer_device_ip_set:
            if bgp_fact_info['ansible_facts']['bgp_neighbors'][ip]['state'] == 'established':
                pytest.fail("BGP is still enable on lag disable member for neighbor {}", ip)
    finally:
        duthost.shell('rm -f {}'.format(lag_member_file_dir))
        config_reload(duthost, config_source='config_db')
