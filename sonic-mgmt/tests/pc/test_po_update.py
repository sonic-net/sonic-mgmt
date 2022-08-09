import random
import threading
import time
from queue import Queue

import pytest
import logging

from ptf import testutils, mask, packet

from tests.common import config_reload
import ipaddress

from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.voq.voq_helpers import verify_no_routes_from_nexthop

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]


@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exceptions(enum_rand_one_per_hwsku_frontend_hostname, loganalyzer):
    """
        Ignore expected failures logs during test execution.

        LAG tests are triggering following syncd complaints but the don't cause
        harm to DUT.

        Args:
            duthost: DUT fixture
            loganalyzer: Loganalyzer utility fixture
    """
    # when loganalyzer is disabled, the object could be None
    if loganalyzer:
        ignoreRegex = [
            ".*ERR syncd#syncd: :- process_on_fdb_event: invalid OIDs in fdb notifications, NOT translating and NOT storing in ASIC DB.*",
            ".*ERR syncd#syncd: :- process_on_fdb_event: FDB notification was not sent since it contain invalid OIDs, bug.*",
            ".*ERR syncd#syncd: :- translate_vid_to_rid: unable to get RID for VID.*",
        ]
        loganalyzer[enum_rand_one_per_hwsku_frontend_hostname].ignore_regex.extend(ignoreRegex)

    yield


@pytest.fixture(scope="function")
def reload_testbed_on_failed(request, duthosts, enum_rand_one_per_hwsku_frontend_hostname, loganalyzer):
    """
        Reload dut after test function finished
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    yield None
    if request.node.rep_call.failed:
        # if test case failed, means bgp session down or port channel status not recovered, execute config reload
        logging.info("Reloading config and restarting swss...")
        config_reload(duthost, safe_reload=True, ignore_loganalyzer=loganalyzer)


def test_po_update(duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_frontend_asic_index, tbinfo):
    """
    test port channel add/deletion as well ip address configuration
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asichost = duthost.asic_instance(enum_frontend_asic_index)
    int_facts = asichost.interface_facts()['ansible_facts']

    portchannel, portchannel_members = asichost.get_portchannel_and_members_in_ns(tbinfo)

    tmp_portchannel = "PortChannel999"
    # Initialize portchannel_ip and portchannel_members
    portchannel_ip = int_facts['ansible_interface_facts'][portchannel]['ipv4']['address']

    # Initialize flags
    remove_portchannel_members = False
    remove_portchannel_ip = False
    create_tmp_portchannel = False
    add_tmp_portchannel_members = False
    add_tmp_portchannel_ip = False

    logging.info("portchannel=%s" % portchannel)
    logging.info("portchannel_ip=%s" % portchannel_ip)
    logging.info("portchannel_members=%s" % portchannel_members)

    try:
        # Step 1: Remove portchannel members from portchannel
        for member in portchannel_members:
            asichost.config_portchannel_member(portchannel, member, "del")
        remove_portchannel_members = True

        # Step 2: Remove portchannel ip from portchannel
        asichost.config_ip_intf(portchannel, portchannel_ip + "/31", "remove")
        remove_portchannel_ip = True

        time.sleep(30)
        int_facts = asichost.interface_facts()['ansible_facts']
        pytest_assert(not int_facts['ansible_interface_facts'][portchannel]['link'])
        pytest_assert(wait_until(120, 10, 0, asichost.check_bgp_statistic, 'ipv4_idle', 1))

        # Step 3: Create tmp portchannel
        asichost.config_portchannel(tmp_portchannel, "add")
        create_tmp_portchannel = True

        # Step 4: Add portchannel member to tmp portchannel
        for member in portchannel_members:
            asichost.config_portchannel_member(tmp_portchannel, member, "add")
        add_tmp_portchannel_members = True

        # Step 5: Add portchannel ip to tmp portchannel
        asichost.config_ip_intf(tmp_portchannel, portchannel_ip + "/31", "add")
        int_facts = asichost.interface_facts()['ansible_facts']
        pytest_assert(int_facts['ansible_interface_facts'][tmp_portchannel]['ipv4']['address'] == portchannel_ip)
        add_tmp_portchannel_ip = True

        time.sleep(30)
        int_facts = asichost.interface_facts()['ansible_facts']
        pytest_assert(int_facts['ansible_interface_facts'][tmp_portchannel]['link'])
        pytest_assert(wait_until(120, 10, 0, asichost.check_bgp_statistic, 'ipv4_idle', 0))
    finally:
        # Recover all states
        if add_tmp_portchannel_ip:
            asichost.config_ip_intf(tmp_portchannel, portchannel_ip + "/31", "remove")

        time.sleep(5)
        if add_tmp_portchannel_members:
            for member in portchannel_members:
                asichost.config_portchannel_member(tmp_portchannel, member, "del")

        time.sleep(5)
        if create_tmp_portchannel:
            asichost.config_portchannel(tmp_portchannel, "del")
        if remove_portchannel_ip:
            asichost.config_ip_intf(portchannel, portchannel_ip + "/31", "add")
        if remove_portchannel_members:
            for member in portchannel_members:
                asichost.config_portchannel_member(portchannel, member, "add")
        pytest_assert(wait_until(120, 10, 0, asichost.check_bgp_statistic, 'ipv4_idle', 0))


def test_po_update_io_no_loss(duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_frontend_asic_index, tbinfo, ptfadapter, reload_testbed_on_failed):
    # GIVEN a lag topology, keep sending packets between 2 port channels
    # WHEN delete/add different members of a port channel
    # THEN no packets shall loss
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asichost = duthost.asic_instance(enum_frontend_asic_index)
    mg_facts = asichost.get_extended_minigraph_facts(tbinfo)

    dut_mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    # generate ip-pc pairs, be like:[("10.0.0.56", "10.0.0.57", "PortChannel0001")]
    peer_ip_pc_pair = [(pc["addr"], pc["peer_addr"], pc["attachto"]) for pc in
                       dut_mg_facts["minigraph_portchannel_interfaces"]
                       if
                       ipaddress.ip_address(pc['peer_addr']).version == 4]
    # generate pc tuples, fill in members,
    # be like:[("10.0.0.56", "10.0.0.57", "PortChannel0001", ["Ethernet48", "Ethernet52"])]
    pcs = [(pair[0], pair[1], pair[2], dut_mg_facts["minigraph_portchannels"][pair[2]]["members"]) for pair in
           peer_ip_pc_pair]

    if len(pcs) < 2:
        pytest.skip(
            "Skip test due to there is no enough port channel with at least 2 members exists in current topology.")

    # generate out_pc tuples similar to pc tuples, but that are on the same asic as asichost
    out_pcs = [(pair[0], pair[1], pair[2], mg_facts["minigraph_portchannels"][pair[2]]["members"]) for pair in
           peer_ip_pc_pair
           if pair[2] in mg_facts['minigraph_portchannels'] and len(mg_facts["minigraph_portchannels"][pair[2]]["members"]) >= 2]

    if len(out_pcs) < 1:
        pytest.skip(
            "Skip test as there are no port channels on asic {} on dut {}".format(enum_frontend_asic_index, duthost))
    # Select out pc from the port channels that are on the same asic as asichost
    out_pc = random.sample(out_pcs, k=1)[0]
    selected_pcs = random.sample(pcs, k=2)

    in_pc = selected_pcs[0]
    # Make sure the picked in_pc is not the same as the selected out_pc
    if in_pc[2] == out_pc[2]:
        in_pc = selected_pcs[1]

    # use first port of in_pc as input port
    # all ports in out_pc will be output/forward ports
    pc, pc_members = out_pc[2], out_pc[3]
    in_ptf_index = dut_mg_facts["minigraph_ptf_indices"][in_pc[3][0]]
    out_ptf_indices = map(lambda port: mg_facts["minigraph_ptf_indices"][port], out_pc[3])
    logging.info(
        "selected_pcs is: %s, in_ptf_index is %s, out_ptf_indices is %s" % (
            selected_pcs, in_ptf_index, out_ptf_indices))

    tmp_pc = "PortChannel999"
    pc_ip = out_pc[0]
    in_peer_ip = in_pc[1]
    out_peer_ip = out_pc[1]
    remove_pc_members = False
    remove_pc_ip = False
    create_tmp_pc = False
    add_tmp_pc_members = False
    add_tmp_pc_ip = False
    try:
        # Step 1: Remove port channel members from port channel
        for member in pc_members:
            asichost.config_portchannel_member(pc, member, "del")
        remove_pc_members = True

        # Step 2: Remove port channel ip from port channel
        asichost.config_ip_intf(pc, pc_ip + "/31", "remove")
        remove_pc_ip = True
        verify_no_routes_from_nexthop(duthosts, out_peer_ip)
        time.sleep(15)
        int_facts = asichost.interface_facts()['ansible_facts']
        pytest_assert(not int_facts['ansible_interface_facts'][pc]['link'])
        pytest_assert(wait_until(120, 10, 0, asichost.check_bgp_statistic, 'ipv4_idle', 1))

        # Step 3: Create tmp port channel with default min-links(1)
        asichost.config_portchannel(tmp_pc, "add")
        create_tmp_pc = True

        # Step 4: Add port channel members to tmp port channel
        for member in pc_members:
            asichost.config_portchannel_member(tmp_pc, member, "add")
        add_tmp_pc_members = True

        # Step 5: Add port channel ip to tmp port channel
        asichost.config_ip_intf(tmp_pc, pc_ip + "/31", "add")
        add_tmp_pc_ip = True

        int_facts = asichost.interface_facts()['ansible_facts']
        pytest_assert(int_facts['ansible_interface_facts'][tmp_pc]['ipv4']['address'] == pc_ip)

        time.sleep(15)
        int_facts = asichost.interface_facts()['ansible_facts']
        pytest_assert(int_facts['ansible_interface_facts'][tmp_pc]['link'])
        pytest_assert(wait_until(120, 10, 0, asichost.check_bgp_statistic, 'ipv4_idle', 0))

        # Keep sending packets, and add/del different members during that time, observe whether packets lose
        pkt = testutils.simple_ip_packet(
            eth_dst=duthost.facts["router_mac"],
            eth_src=ptfadapter.dataplane.get_mac(0, in_ptf_index),
            ip_src=in_peer_ip,
            ip_dst=out_peer_ip)

        exp_pkt = pkt.copy()
        exp_pkt = mask.Mask(exp_pkt)

        exp_pkt.set_do_not_care_scapy(packet.Ether, 'dst')
        exp_pkt.set_do_not_care_scapy(packet.Ether, 'src')
        exp_pkt.set_do_not_care_scapy(packet.IP, 'chksum')
        exp_pkt.set_do_not_care_scapy(packet.IP, 'ttl')

        ptfadapter.dataplane.flush()
        member_update_finished_flag = Queue(1)
        packet_sending_flag = Queue(1)

        def del_add_members():
            # wait for packets sending started, then starts to update pc members
            while packet_sending_flag.empty() or (not packet_sending_flag.get()):
                time.sleep(0.2)
            asichost.config_portchannel_member(tmp_pc, pc_members[0], "del")
            time.sleep(2)
            asichost.config_portchannel_member(tmp_pc, pc_members[0], "add")
            time.sleep(4)
            asichost.config_portchannel_member(tmp_pc, pc_members[1], "del")
            time.sleep(2)
            asichost.config_portchannel_member(tmp_pc, pc_members[1], "add")
            time.sleep(2)
            member_update_finished_flag.put(True)

        t = threading.Thread(target=del_add_members, name="del_add_members_thread")
        t.start()
        t_max = time.time() + 60
        send_count = 0
        stop_sending = False
        ptfadapter.dataplane.flush()
        time.sleep(1)
        while not stop_sending:
            # After 100 packets send, awake del_add_members thread, it happens only once.
            if send_count == 100:
                packet_sending_flag.put(True)

            testutils.send(ptfadapter, in_ptf_index, pkt)
            send_count += 1
            member_update_thread_finished = (not member_update_finished_flag.empty()) and member_update_finished_flag.get()
            reach_max_time = time.time() > t_max
            stop_sending = reach_max_time or member_update_thread_finished
        t.join(20)
        time.sleep(2)
        match_count = testutils.count_matched_packets_all_ports(ptfadapter, exp_pkt, ports=out_ptf_indices, timeout=10)
        logging.info("match_count: {}, send_count: {}".format(match_count, send_count))
        max_loss_rate = 0.01
        pytest_assert(match_count > send_count * (1 - max_loss_rate),
                      "Packets lost rate > {} during pc members add/removal, send_count: {}, match_count: {}".format(
                          max_loss_rate, send_count, match_count))
    finally:
        if add_tmp_pc_ip:
            asichost.config_ip_intf(tmp_pc, pc_ip + "/31", "remove")
            time.sleep(2)
        if add_tmp_pc_members:
            for member in pc_members:
                asichost.config_portchannel_member(tmp_pc, member, "del")
            time.sleep(2)
        if create_tmp_pc:
            asichost.config_portchannel(tmp_pc, "del")
        pytest_assert(wait_until(120, 10, 0, asichost.check_bgp_statistic, 'ipv4_idle', 1))
        if remove_pc_ip:
            asichost.config_ip_intf(pc, pc_ip + "/31", "add")
        if remove_pc_members:
            for member in pc_members:
                asichost.config_portchannel_member(pc, member, "add")
        pytest_assert(wait_until(120, 10, 0, asichost.check_bgp_statistic, 'ipv4_idle', 0))
