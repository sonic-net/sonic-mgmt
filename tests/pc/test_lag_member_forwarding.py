import ipaddr as ipaddress
import json
import pytest
import logging
from tests.common import config_reload
from ptf.mask import Mask
import ptf.packet as scapy
import ptf.testutils as testutils
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]


@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exception(loganalyzer, duthosts):

    ignore_errors = [
        r".* ERR gbsyncd#syncd:.* sai_api_query: :- Invalid sai_api_t \d* passed.*",
        r".* ERR memory_checker: \[memory_checker\] Failed to get container ID of.*",
        r".* ERR memory_checker: \[memory_checker\] cgroup memory usage file.*"
        ]
    if loganalyzer:
        for duthost in duthosts:
            loganalyzer[duthost.hostname].ignore_regex.extend(ignore_errors)

    return None


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


def test_lag_member_forwarding_packets(duthosts, enum_rand_one_per_hwsku_frontend_hostname, tbinfo, ptfadapter,
                                       loganalyzer):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    lag_facts = duthost.lag_facts(host=duthost.hostname)['ansible_facts']['lag_facts']
    if not len(lag_facts['lags'].keys()):
        pytest.skip("No Lag found in this topology")
    if len(lag_facts['lags'].keys()) == 1:
        pytest.skip("Only one Lag found in this topology, skipping test")
    portchannel_name = None
    portchannel_dest_name = None
    recv_port = []

    # Select PortChannels where all BGP neighbors are established.
    # The test needs two: one to disable (portchannel_name) and one for
    # forwarding verification (portchannel_dest_name).
    all_pcs = list(lag_facts['lags'].keys())
    bgp_fact_info = duthost.asic_instance_from_namespace(
        lag_facts['names'][all_pcs[0]]).bgp_facts()

    def pc_bgp_all_established(pc_name):
        """Check if all BGP neighbors of a PortChannel are established."""
        pc_members = list(lag_facts['lags'][pc_name]['po_stats']['ports'].keys())
        if not pc_members:
            return False
        ns = lag_facts['names'][pc_name]
        ah = duthost.asic_instance_from_namespace(ns)
        cf = ah.config_facts(host=duthost.hostname, source="running")['ansible_facts']
        bf = ah.bgp_facts()['ansible_facts']
        member_device = cf.get('DEVICE_NEIGHBOR', {}).get(pc_members[0], {}).get('name', '')
        neighbor_ips = [ip for ip, data in cf.get('BGP_NEIGHBOR', {}).items()
                        if data.get('name') == member_device]
        if len(neighbor_ips) < 2:
            return False
        return all(bf.get('bgp_neighbors', {}).get(ip, {}).get('state') == 'established'
                   for ip in neighbor_ips)

    for pc in all_pcs:
        if pc_bgp_all_established(pc):
            if portchannel_name is None:
                portchannel_name = pc
            elif portchannel_dest_name is None:
                portchannel_dest_name = pc
                break

    if not portchannel_name or not portchannel_dest_name:
        pytest.skip("Need two PortChannels with all BGP neighbors established, "
                    "found: src={}, dst={}".format(portchannel_name, portchannel_dest_name))

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
            result = testutils.verify_packet_any_port(test=ptfadapter, pkt=exp_pkt, ports=recv_port)
            if isinstance(result, bool):
                logger.info("Using dummy testutils to skip traffic test, skip following verify steps.")
                return

            (_, recv_pkt) = result
            assert recv_pkt
            # Make sure routing is done
            pytest_assert(scapy.Ether(recv_pkt).ttl == (ip_ttl - 1), "Routed Packet TTL not decremented")
        else:
            testutils.verify_no_packet_any(test=ptfadapter, pkt=exp_pkt, ports=recv_port)

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

        # swssconfig returns before orchagent/syncd finishes applying the config.
        # Wait for ASIC_DB to reflect that LAG members of the tested LAG are
        # disabled before sending traffic, otherwise packets may still be forwarded.
        def check_lag_members_disabled_in_asic_db():
            """Check ASIC_DB for EGRESS_DISABLE=true on members of the LAG under test.

            Instead of looking up the LAG's SAI OID (which may not exist in
            COUNTERS_LAG_NAME_MAP on converged-peer testbeds), find the member
            port SAI OIDs and match them against LAG_MEMBER entries.
            """
            # Get SAI OIDs for the member ports we disabled
            member_port_oids = set()
            for member_name in portchannel_members:
                port_oid = asichost.shell(
                    "sonic-db-cli COUNTERS_DB HGET COUNTERS_PORT_NAME_MAP {}".format(
                        member_name),
                    module_ignore_errors=True
                )["stdout"].strip()
                if port_oid:
                    member_port_oids.add(port_oid)

            if len(member_port_oids) != len(portchannel_members):
                logger.warning("Could not find all port OIDs: expected %d, found %d",
                               len(portchannel_members), len(member_port_oids))
                return False

            # Find LAG_MEMBER entries whose PORT_ID matches our member ports
            all_member_keys = asichost.shell(
                "sonic-db-cli ASIC_DB KEYS 'ASIC_STATE:SAI_OBJECT_TYPE_LAG_MEMBER:*'"
            )["stdout_lines"]

            matched = 0
            for key in all_member_keys:
                port_id = asichost.shell(
                    "sonic-db-cli ASIC_DB HGET '{}' SAI_LAG_MEMBER_ATTR_PORT_ID".format(key)
                )["stdout"].strip()
                if port_id in member_port_oids:
                    egress_disable = asichost.shell(
                        "sonic-db-cli ASIC_DB HGET '{}' SAI_LAG_MEMBER_ATTR_EGRESS_DISABLE".format(
                            key)
                    )["stdout"].strip()
                    if egress_disable != "true":
                        return False
                    matched += 1

            return matched == len(member_port_oids)

        pytest_assert(
            wait_until(10, 0.5, 0, check_lag_members_disabled_in_asic_db),
            "LAG members of {} not disabled in ASIC_DB within 10s after swssconfig".format(
                portchannel_name)
        )
        logger.info("All LAG members of %s confirmed disabled in ASIC_DB", portchannel_name)

        if duthost.facts['asic_type'] == "vs":
            # VS SAI populates ASIC_DB but the Linux kernel teamdev doesn't
            # enforce LAG member disable in the dataplane, so packets still flow.
            # Skip traffic and BGP verification on VS.
            logger.info("KVM/VS SAI does not enforce LAG member disable in dataplane, "
                        "skip forwarding and BGP verify steps.")
            return

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
                pytest.fail("Ping is still working on lag disable member for neighbor {}".format(ip))

        def check_bgp_sessions_down():
            """Check if all BGP sessions for the disabled LAG member are down."""
            bgp_info = asichost.bgp_facts()
            for neighbor_ip in peer_device_ip_set:
                if bgp_info['ansible_facts']['bgp_neighbors'][neighbor_ip]['state'] == 'established':
                    return False
            return True

        holdtime_sec = holdtime / 1000
        pytest_assert(
            wait_until(holdtime_sec + 30, 10, 0, check_bgp_sessions_down),
            "BGP sessions are still established after disabling LAG members. "
            "Expected all sessions in {} to go down within {}s.".format(
                peer_device_ip_set, holdtime_sec)
        )
    finally:
        duthost.shell('rm -f {}'.format(lag_member_file_dir))
        config_reload(duthost, config_source='config_db', ignore_loganalyzer=loganalyzer)
