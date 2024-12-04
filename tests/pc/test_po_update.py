import random
import threading
import time
from queue import Queue

import pytest
import logging

from ptf import testutils, mask, packet

from tests.common import config_reload
import ipaddress

from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.reboot import wait_for_startup, reboot
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.sonic_db import VoqDbCli
from tests.common.helpers.voq_helpers import verify_no_routes_from_nexthop

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
            (".*ERR syncd[0-9]*#syncd: :- process_on_fdb_event: invalid OIDs in fdb notifications, "
             "NOT translating and NOT storing in ASIC DB.*"),
            (".*ERR syncd[0-9]*#syncd: :- process_on_fdb_event: FDB notification was not sent "
             "since it contain invalid OIDs, bug.*"),
            (".*ERR syncd[0-9]*#syncd: :- translate_vid_to_rid: unable to get RID for VID.*"),
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
        config_reload(duthost, safe_reload=True)


def _wait_until_pc_members_removed(asichost, pc_names):
    """
    Wait until all port channel members are removed.
    """
    if not wait_until(30, 5, 5, lambda: not asichost.get_portchannel_members(pc_names)):
        # Mark the test case as failed if port channel members are not removed.
        # The fixture reload_testbed_on_failed will do config reload to restore the DUT.
        pytest.fail("Portchannel members are not removed from {}".format(pc_names))


def has_bgp_neighbors(duthost, portchannel):
    return duthost.shell("show ip int | grep {} | awk '{{print $4}}'".format(portchannel))['stdout'] != 'N/A'


def pc_active(asichost, portchannel):
    return asichost.interface_facts()['ansible_facts']['ansible_interface_facts'][portchannel]['active']


def test_po_update(duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_frontend_asic_index, tbinfo):
    """
    test port channel add/deletion as well ip address configuration
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asichost = duthost.asic_instance(enum_frontend_asic_index)
    int_facts = asichost.interface_facts()['ansible_facts']

    port_channels_data = asichost.get_portchannels_and_members_in_ns(tbinfo)
    if not port_channels_data:
        pytest.skip(
            "Skip test as there are no port channels on asic {} on dut {}".format(enum_frontend_asic_index, duthost))

    portchannel = None
    portchannel_members = None
    for portchannel in port_channels_data:
        logging.info('Trying to get PortChannel: {} for test'.format(portchannel))
        if int_facts['ansible_interface_facts'][portchannel].get('ipv4'):
            portchannel_members = port_channels_data[portchannel]
            break

    pytest_assert(portchannel and portchannel_members, 'Can not get PortChannel interface for test')

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
        pytest_assert(
            has_bgp_neighbors(duthost, portchannel) and
            wait_until(120, 10, 0, asichost.check_bgp_statistic, 'ipv4_idle', 1)
            or not wait_until(10, 10, 0, pc_active, asichost, portchannel))

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
        pytest_assert(
            has_bgp_neighbors(duthost, tmp_portchannel) and
            wait_until(120, 10, 0, asichost.check_bgp_statistic, 'ipv4_idle', 0)
            or wait_until(10, 10, 0, pc_active, asichost, tmp_portchannel))
    finally:
        # Recover all states
        if add_tmp_portchannel_ip:
            asichost.config_ip_intf(tmp_portchannel, portchannel_ip + "/31", "remove")

        time.sleep(5)
        if add_tmp_portchannel_members:
            for member in portchannel_members:
                asichost.config_portchannel_member(tmp_portchannel, member, "del")

        _wait_until_pc_members_removed(asichost, tmp_portchannel)
        if create_tmp_portchannel:
            asichost.config_portchannel(tmp_portchannel, "del")
        if remove_portchannel_ip:
            asichost.config_ip_intf(portchannel, portchannel_ip + "/31", "add")
        if remove_portchannel_members:
            for member in portchannel_members:
                asichost.config_portchannel_member(portchannel, member, "add")

        time.sleep(5)
        pytest_assert(
            has_bgp_neighbors(duthost, portchannel) and
            wait_until(120, 10, 0, asichost.check_bgp_statistic, 'ipv4_idle', 0)
            or wait_until(10, 10, 0, pc_active, asichost, portchannel))


def test_po_update_io_no_loss(
        duthosts,
        enum_rand_one_per_hwsku_frontend_hostname,
        enum_frontend_asic_index,
        tbinfo,
        ptfadapter,
        reload_testbed_on_failed):
    # GIVEN a lag topology, keep sending packets between 2 port channels
    # WHEN delete/add different members of a port channel
    # THEN no packets shall loss
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asichost = duthost.asic_instance(enum_frontend_asic_index)
    mg_facts = asichost.get_extended_minigraph_facts(tbinfo)

    dut_mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    # generate ip-pc pairs, be like:[("10.0.0.56", "10.0.0.57", "PortChannel0001")]
    peer_ip_pc_pair = [(pc["addr"], pc["peer_addr"], pc["attachto"],
                        dut_mg_facts["minigraph_portchannels"][pc["attachto"]]['namespace'])
                       for pc in dut_mg_facts["minigraph_portchannel_interfaces"]
                       if ipaddress.ip_address(pc['peer_addr']).version == 4]
    # generate pc tuples, fill in members,
    # be like:[("10.0.0.56", "10.0.0.57", "PortChannel0001", ["Ethernet48", "Ethernet52"])]
    pcs = [(pair[0], pair[1], pair[2], dut_mg_facts["minigraph_portchannels"][pair[2]]["members"], pair[3]) for pair in
           peer_ip_pc_pair]

    if len(pcs) < 2:
        pytest.skip(
            "Skip test due to there is no enough port channel with at least 2 members exists in current topology.")

    # generate out_pc tuples similar to pc tuples, but that are on the same asic as asichost
    out_pcs = [
        (pair[0], pair[1], pair[2], mg_facts["minigraph_portchannels"][pair[2]]["members"], pair[3]) for pair in
        peer_ip_pc_pair
        if pair[2] in mg_facts['minigraph_portchannels']
        and len(mg_facts["minigraph_portchannels"][pair[2]]["members"]) >= 2]

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
    out_ptf_indices = [mg_facts["minigraph_ptf_indices"][port] for port in out_pc[3]]
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
        pytest_assert(
            has_bgp_neighbors(duthost, pc) and wait_until(120, 10, 0, asichost.check_bgp_statistic, 'ipv4_idle', 1)
            or not wait_until(10, 10, 0, pc_active, asichost, pc))

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
        pytest_assert(
            has_bgp_neighbors(duthost, tmp_pc) and wait_until(120, 10, 0, asichost.check_bgp_statistic, 'ipv4_idle', 0)
            or wait_until(10, 10, 0, pc_active, asichost, tmp_pc))

        # Keep sending packets, and add/del different members during that time, observe whether packets lose
        pkt = testutils.simple_ip_packet(
            eth_dst=duthost.asic_instance(duthost.get_asic_id_from_namespace(in_pc[4])).get_router_mac(),
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
            if send_count > 100:
                time.sleep(0.001)
            member_update_thread_finished = \
                (not member_update_finished_flag.empty()) and member_update_finished_flag.get()
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
        _wait_until_pc_members_removed(asichost, tmp_pc)
        if create_tmp_pc:
            asichost.config_portchannel(tmp_pc, "del")
        pytest_assert(
            has_bgp_neighbors(duthost, tmp_pc) and wait_until(120, 10, 0, asichost.check_bgp_statistic, 'ipv4_idle', 1)
            or not wait_until(10, 10, 0, pc_active, asichost, tmp_pc))
        if remove_pc_ip:
            asichost.config_ip_intf(pc, pc_ip + "/31", "add")
        if remove_pc_members:
            for member in pc_members:
                asichost.config_portchannel_member(pc, member, "add")

        time.sleep(5)
        pytest_assert(
            has_bgp_neighbors(duthost, pc) and wait_until(120, 10, 0, asichost.check_bgp_statistic, 'ipv4_idle', 0)
            or wait_until(10, 10, 0, pc_active, asichost, pc))


def increment_lag_id(duthost, upper_lagid_start):
    # Retrieve the current free LAG ID from the 'SYSTEM_LAG_IDS_FREE_LIST' in the CHASSIS_APP_DB
    current_free_lagid = int(duthost.shell("sonic-db-cli CHASSIS_APP_DB lindex 'SYSTEM_LAG_IDS_FREE_LIST' 0")['stdout'])
    # Temporary PortChannel name to be used in the configuration
    tmp_pc = "PortChannel999"
    # Loop through the range from current_free_lagid to upper_lagid_start (inclusive)
    for i in range(current_free_lagid, upper_lagid_start + 1):
        # Add the temporary PortChannel to increment the LAG ID
        duthost.asics[0].config_portchannel(tmp_pc, "add")
        # Remove the temporary PortChannel after incrementing the LAG ID
        duthost.asics[0].config_portchannel(tmp_pc, "del")

    # Retrieve the current free LAG ID again after the modifications
    current_free_lagid = int(
        duthost.shell("sonic-db-cli CHASSIS_APP_DB lindex 'SYSTEM_LAG_IDS_FREE_LIST' 0")['stdout'])
    logging.info("SYSTEM_LAG_IDS_FREE_LIST {}".format(current_free_lagid))
    # Assert that the current free LAG ID is greater than or equal to the upper limit (upper_lagid_start)
    pytest_assert(current_free_lagid >= upper_lagid_start,
                  "Increment Lag ID Current:{},> Upper:{}".format(current_free_lagid, upper_lagid_start))


def send_data(dut_mg_facts, duthost, ptfadapter):
    # Create a list of tuples for each port channel interface, containing the IP address, peer address,
    # port channel name, and its associated namespace. This is filtered for IPv4 addresses only.
    peer_ip_pc_pair = [(pc["addr"], pc["peer_addr"], pc["attachto"],
                        dut_mg_facts["minigraph_portchannels"][pc["attachto"]]['namespace'])
                       for pc in dut_mg_facts["minigraph_portchannel_interfaces"]
                       if ipaddress.ip_address(pc['peer_addr']).version == 4]

    # Create a list of tuples where each tuple contains the port channel IP, peer IP, port channel name,
    # members of the port channel, and its namespace.
    pcs = [(pair[0], pair[1], pair[2], dut_mg_facts["minigraph_portchannels"][pair[2]]["members"], pair[3])
           for pair in peer_ip_pc_pair]

    # Iterate over each port channel pair to send and verify packets between them
    for in_pc in pcs:
        for out_pc in pcs:
            # Skip if the input and output port channels are the same
            if in_pc[2] == out_pc[2]:
                continue
            # Call the function to send and verify the packet between input and output port channels
            send_and_verify_packet(in_pc, out_pc, dut_mg_facts, duthost, ptfadapter)


def send_and_verify_packet(in_pc, out_pc, dut_mg_facts, duthost, ptfadapter):
    # Get the PTF interface index for the first member of the input port channel
    in_ptf_index = dut_mg_facts["minigraph_ptf_indices"][in_pc[3][0]]
    # Get the PTF interface indices for all members of the output port channel
    out_ptf_indices = [dut_mg_facts["minigraph_ptf_indices"][port] for port in out_pc[3]]

    in_peer_ip = in_pc[1]
    out_peer_ip = out_pc[1]
    # Create a simple IP packet with the source and destination MAC addresses, IP source as input peer IP,
    # and IP destination as output peer IP
    pkt = testutils.simple_ip_packet(
        eth_dst=duthost.asic_instance(duthost.get_asic_id_from_namespace(in_pc[4])).get_router_mac(),
        eth_src=ptfadapter.dataplane.get_mac(0, in_ptf_index),
        ip_src=in_peer_ip,
        ip_dst=out_peer_ip)

    # Make a copy of the packet to define the expected packet
    exp_pkt = pkt.copy()
    exp_pkt = mask.Mask(exp_pkt)
    # Ignore certain fields in the expected packet such as destination MAC, source MAC, IP checksum, and TTL
    exp_pkt.set_do_not_care_scapy(packet.Ether, 'dst')
    exp_pkt.set_do_not_care_scapy(packet.Ether, 'src')
    exp_pkt.set_do_not_care_scapy(packet.IP, 'chksum')
    exp_pkt.set_do_not_care_scapy(packet.IP, 'ttl')

    # Flush the dataplane before sending the packet
    ptfadapter.dataplane.flush()
    # Send the packet through the input port channel
    testutils.send(ptfadapter, in_ptf_index, pkt)
    # Verify the expected packet is received on any of the output port channel members
    testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=out_ptf_indices)


def lag_set_sanity(duthosts):
    system_lag_id = {}
    # Create a VoqDbCli instance to interact with VOQ DB on the supervisor node
    voqdb = VoqDbCli(duthosts.supervisor_nodes[0])

    # Dump and store the current state of the SYSTEM_LAG_ID_TABLE
    system_lag_id["SYSTEM_LAG_ID_TABLE"] = voqdb.dump("SYSTEM_LAG_ID_TABLE")["SYSTEM_LAG_ID_TABLE"]['value']
    # Dump the system LAG ID set, which holds the assigned LAG IDs
    SYSTEM_LAG_ID_SET = voqdb.dump("SYSTEM_LAG_ID_SET")["SYSTEM_LAG_ID_SET"]['value']
    # Retrieve the start and end range for system LAG IDs from the database
    end = int(voqdb.dump("SYSTEM_LAG_ID_END")["SYSTEM_LAG_ID_END"]['value'])
    start = int(voqdb.dump("SYSTEM_LAG_ID_START")["SYSTEM_LAG_ID_START"]['value'])
    # Retrieve the list of free LAG IDs from the database
    LAG_IDS_FREE_LIST = voqdb.dump("SYSTEM_LAG_IDS_FREE_LIST")["SYSTEM_LAG_IDS_FREE_LIST"]['value']

    def verify_system_lag_sanity():
        # Combine the free LAG IDs and assigned LAG IDs into a set to check for uniqueness
        seen = set(LAG_IDS_FREE_LIST + SYSTEM_LAG_ID_SET)

        # Verify that the number of LAG IDs seen matches the expected range from start to end
        if len(seen) != (end - start + 1):
            logging.error(
                "Missing or extra values are found in SYSTEM_LAG_IDS_FREE_LIST:{} or SYSTEM_LAG_ID_SET:{}".format(
                    LAG_IDS_FREE_LIST, SYSTEM_LAG_ID_SET))
            return False

        # Check for duplicate values in both the free and assigned LAG ID lists
        if any(LAG_IDS_FREE_LIST.count(x) > 1 or SYSTEM_LAG_ID_SET.count(
                x) > 1 or x in LAG_IDS_FREE_LIST and x in SYSTEM_LAG_ID_SET for x in seen):
            logging.error(
                "Duplicate values found in SYSTEM_LAG_IDS_FREE_LIST:{} or SYSTEM_LAG_ID_SET:{}".format(
                    LAG_IDS_FREE_LIST, SYSTEM_LAG_ID_SET))
            return False
        # Log the current system LAG ID set for information purposes
        logging.info(SYSTEM_LAG_ID_SET)
        return True

    # Assert that the system LAG sanity check passes, using a wait_until function with a timeout
    pytest_assert(wait_until(220, 10, 0, verify_system_lag_sanity))


def test_po_update_with_higher_lagids(
        duthosts,
        enum_rand_one_per_hwsku_frontend_hostname,
        tbinfo,
        ptfadapter,
        reload_testbed_on_failed, localhost):
    """
    Test Port Channel Traffic with Higher LAG IDs:

    1. The test involves rebooting the DUT,
        which resets the LAG ID allocation, starting from 1.
    2. After the initial verification of traffic on the port channel (PC) mesh, the
       LAG ID allocation is incremented by temporarily adding and deleting port channels.
    3. Verify the LAG set sanity and ensure traffic stability.
    4. Repeat the process for the higher LAG IDs.
       """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    # Check if the device is a modular chassis and the topology is T2
    is_chassis = duthost.get_facts().get("modular_chassis")
    if not (is_chassis and tbinfo['topo']['type'] == 't2' and duthost.facts['switch_type'] == "voq"):
        # Skip the test if the setup is not T2 Chassis
        pytest.skip("Test is Applicable for T2 VOQ Chassis Setup")

    dut_mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    # Send initial data to the device
    send_data(dut_mg_facts, duthost, ptfadapter)
    # Get the supervisor node (suphost) for the modular chassis setup
    suphost = duthosts.supervisor_nodes[0]
    # Get the established BGP neighbors from the DUT
    up_bgp_neighbors = duthost.get_bgp_neighbors_per_asic("established")

    # Log information about cold reboot on the supervisor node
    logging.info("Cold reboot on supervisor node: %s", suphost.hostname)

    # Reboot the supervisor node and wait for critical processes to restart
    reboot(suphost, localhost, wait=240, safe_reboot=True)
    logging.info("Wait until all critical processes are fully started")
    wait_critical_processes(suphost)

    # Ensure all critical services have started on the supervisor node
    pytest_assert(wait_until(330, 20, 0, suphost.critical_services_fully_started),
                  "All critical services should fully started! {}".format(suphost.hostname))

    # For each linecard (frontend node), wait for startup and critical processes to start
    for linecard in duthosts.frontend_nodes:
        wait_for_startup(linecard, localhost, delay=10, timeout=300)
        dut_uptime = linecard.get_up_time()
        logging.info('DUT {} up since {}'.format(linecard.hostname, dut_uptime))

        logging.info("Wait until all critical processes are fully started")
        wait_critical_processes(linecard)

        # Ensure all critical services have started on the linecard
        pytest_assert(wait_until(330, 20, 0, linecard.critical_services_fully_started),
                      "All critical services should fully started! {}".format(linecard.hostname))

    # Perform a sanity check on the LAG set
    lag_set_sanity(duthosts)

    # Increment LAG IDs up to 500
    increment_lag_id(duthost, 500)

    # Perform a Config Reload to put the new lag ids on Portchannel
    config_reload(duthost, safe_reload=True)

    # Ensure BGP sessions are re-established after reload
    pytest_assert(wait_until(300, 10, 0,
                             duthost.check_bgp_session_state_all_asics, up_bgp_neighbors, "established"))

    # Perform another LAG set sanity check
    lag_set_sanity(duthosts)

    # Send data after the configuration reload
    send_data(dut_mg_facts, duthost, ptfadapter)

    # Get the unique port channels from the minigraph facts
    unique_portchannels = set([entry['attachto'] for entry in dut_mg_facts["minigraph_portchannel_interfaces"]])

    # Calculate the increment value based on available port channels
    inc = 1024 - len(unique_portchannels)

    # Increment LAG IDs based on the calculated increment value
    increment_lag_id(duthost, inc)

    # Perform a Config Reload to put the new lag ids on Portchannel
    config_reload(duthost, safe_reload=True)

    # Ensure BGP sessions are re-established after the second reload
    pytest_assert(wait_until(300, 10, 0,
                             duthost.check_bgp_session_state_all_asics, up_bgp_neighbors, "established"))

    # Perform a final LAG set sanity check
    lag_set_sanity(duthosts)

    # Send data one more time after the final sanity check
    send_data(dut_mg_facts, duthost, ptfadapter)
