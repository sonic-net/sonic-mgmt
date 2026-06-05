import pytest
import logging
import time
import ptf.testutils as testutils
import ptf.packet as packet
import ast

from tests.common.helpers.assertions import pytest_assert
from tests.common.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload
from ptf.mask import Mask


pytestmark = [pytest.mark.topology("t0", "t1")]

logger = logging.getLogger(__name__)

# ASIC DB key patterns
WRED_PROFILE_PATTERN = "ASIC_STATE:SAI_OBJECT_TYPE_WRED:oid:*"
SCHEDULER_PATTERN = "ASIC_STATE:SAI_OBJECT_TYPE_SCHEDULER:oid:*"
SRV6_MY_SID_PATTERN_PREFIX = "ASIC_STATE:SAI_OBJECT_TYPE_MY_SID_ENTRY:"
ROUTE_PATTERN_PREFIX = "ASIC_STATE:SAI_OBJECT_TYPE_ROUTE_ENTRY:"

PACKET_COUNT = 100
QUEUE = 3
BLOCKING_SCHEDULER = "SCHEDULER_BLOCK_DATA_PLANE"

# SRv6-related constants
LOCATOR_NAME = "loc_wred"
LOCATOR_PREFIX = "fcbb:bbbb:1::"
LOCATOR_SID_PREFIX = "fcbb:bbbb:1::/48"
NEXTHOP_PREFIX = "fcbb:bbbb:2::/48"
SRV6_OUTER_DIP = "fcbb:bbbb:1:2::"
SRV6_SHIFTED_DIP = "fcbb:bbbb:2::"

sonic_db_cli = "sonic-db-cli"
namespace = ""


@pytest.fixture(scope="module", autouse=True)
def checkpoint(duthost):
    create_checkpoint(duthost)
    yield
    try:
        rollback_or_reload(duthost)
    finally:
        delete_checkpoint(duthost)


@pytest.fixture(scope="module", autouse=True)
def set_namespace(duthost, enum_frontend_asic_index):
    global namespace
    if duthost.is_multi_asic:
        namespace = duthost.get_namespace_from_asic_id(enum_frontend_asic_index)
    else:
        namespace = ""


def get_namespace_option():
    global namespace
    if namespace:
        return f"-n {namespace}"
    else:
        return ""


@pytest.fixture(scope="module", autouse=True)
def set_sonic_db_cli(set_namespace):  # noqa F811
    global sonic_db_cli
    sonic_db_cli = f"sonic-db-cli {get_namespace_option()}"


# autouse=True so that we get the counts before any WRED profile or scheduler is created.
@pytest.fixture(scope="module", autouse=True)
def old_asic_db_counts(duthost):
    return {
        WRED_PROFILE_PATTERN: count_keys(duthost, "ASIC_DB", WRED_PROFILE_PATTERN),
        SCHEDULER_PATTERN: count_keys(duthost, "ASIC_DB", SCHEDULER_PATTERN)
    }


def count_keys(duthost, db, pattern):
    result = duthost.shell(f"{sonic_db_cli} {db} KEYS '{pattern}'")["stdout"].strip()
    if not result:
        return 0
    return len(result.splitlines())


def pattern_exists(duthost, db, key):
    return count_keys(duthost, db, key) > 0


@pytest.fixture(scope="module")
def enable_wred_counters(duthost):
    logger.info("Enabling WRED counters on the DUT.")
    duthost.shell("counterpoll wredqueue enable")


@pytest.fixture(scope="module")
def create_blocking_scheduler(duthost):
    logger.info(f"Creating the blocking scheduler '{BLOCKING_SCHEDULER}' on the DUT.")
    cmd = f"{sonic_db_cli} CONFIG_DB HSET 'SCHEDULER|{BLOCKING_SCHEDULER}' 'type' 'DWRR' 'weight' '15' \
          'pir' '1' 'cir' '1'"
    if duthost.facts["asic_type"] == "broadcom":
        cmd += " 'meter_type' 'packets'"
    duthost.shell(cmd)
    # No need to wait here since we will wait in the "setup" fixture.


@pytest.fixture(scope="module")
def is_srv6_supported(duthost):
    ret = False
    result = duthost.shell("crm show resources srv6-my-sid-entry", module_ignore_errors=True)
    # The output of the above command looks like this if SRv6 is supported:
    # Resource Name        Used Count    Available Count
    # -----------------  ------------  -----------------
    # srv6_my_sid_entry             0                128
    if result["rc"] == 0:
        for line in result["stdout"].splitlines():
            fields = line.split()
            if len(fields) >= 3 and fields[0] == "srv6_my_sid_entry":
                try:
                    ret = int(fields[2]) > 0
                except ValueError as e:
                    logger.error(f"Failed to parse SRv6 resource count: {e}")
                break
    logger.info(f"SRv6 is {'supported' if ret else 'NOT supported'} on this DUT.")
    return ret


@pytest.fixture(scope="module")
def configure_srv6(duthost, is_srv6_supported):
    if is_srv6_supported:
        logger.info("Configuring SRv6 on the DUT...")
        duthost.command(
            f"{sonic_db_cli} CONFIG_DB HSET 'SRV6_MY_LOCATORS|{LOCATOR_NAME}' \
              'prefix' '{LOCATOR_PREFIX}' 'func_len' '0'"
        )
        duthost.command(
            f"{sonic_db_cli} CONFIG_DB HSET 'SRV6_MY_SIDS|{LOCATOR_NAME}|{LOCATOR_SID_PREFIX}' \
              'action' 'uN' 'decap_dscp_mode' 'pipe'"
        )
        # Static route to NEXTHOP_PREFIX will be added later since it depends on the selected egress interface.
        # No need to wait here since we will wait in the "setup" fixture


# This fixture is not in module scope because we don't want to teardown other fixtures in module scope when
# we switch from "drop" to "ecn".
@pytest.fixture(params=["drop", "ecn"])
def create_wred_profile(duthost, request):
    profile_name = f"TEST_WRED_{request.param.upper()}"
    if request.param == "drop":
        ecn = "ecn_none"
    else:
        ecn = "ecn_green"
    logger.info(f"Creating the WRED profile '{profile_name}' with action '{request.param}' on the DUT.")
    duthost.shell(f"{sonic_db_cli} CONFIG_DB HSET 'WRED_PROFILE|{profile_name}' 'wred_green_enable' 'true'\
                    'ecn' '{ecn}' 'green_drop_probability' '100' 'green_max_threshold' '1'\
                    'green_min_threshold' '1'")
    # No need to wait here since we will wait in the "setup" fixture after applying the profile to the queue.
    return (request.param, profile_name)


def select_egress_interface_ipv4(duthost, portchannel_info):
    ip_interfaces = duthost.show_ip_interface()["ansible_facts"]["ip_interfaces"]
    for intf, info in ip_interfaces.items():
        if (intf.startswith("Ethernet") or intf.startswith("PortChannel")) and info["oper_state"].lower() == "up":
            neigh_ip = info.get("peer_ipv4", "")
            if not neigh_ip or neigh_ip.lower() == "n/a":
                continue

            if intf.startswith("PortChannel"):
                members = portchannel_info[intf]["members"]
            else:
                members = [intf]
            logger.info(f"Selected egress packet's dest IPv4 '{neigh_ip}' and egress interface '{intf}'.")
            return (neigh_ip, members)
    pytest.skip("No suitable egress interface found on the DUT.")


def select_egress_interface_ipv6(duthost, portchannel_info):
    ip_interfaces = duthost.show_ipv6_interfaces()
    for intf, info in ip_interfaces.items():
        if (intf.startswith("Ethernet") or intf.startswith("PortChannel")) and info["oper"].lower() == "up":
            neigh_ip = info.get("neighbor ip", "")
            if not neigh_ip or neigh_ip.lower() == "n/a":
                continue

            if intf.startswith("PortChannel"):
                members = portchannel_info[intf]["members"]
            else:
                members = [intf]
            logger.info(f"Selected egress packet's dest IPv6 '{neigh_ip}' and egress interface '{intf}'.")
            return (neigh_ip, members)
    pytest.skip("No suitable egress interface found on the DUT.")


def select_egress_interface(duthost, minigraph_facts, ipv4=True):
    """
    Find an Ethernet or a PortChannel interface that is oper UP and has a neighbor IP.
    Traffic sent to DUT will go out from interface.
    """
    portchannel_info = minigraph_facts["minigraph_portchannels"]
    if ipv4:
        return select_egress_interface_ipv4(duthost, portchannel_info)
    else:
        return select_egress_interface_ipv6(duthost, portchannel_info)


def select_ingress_port(duthost, exclude_ports=[]):
    """
        Returns the name of an oper UP Ethernet interface that is not in the exclude_ports list.
        PTF will send traffic to this interface.
    """
    interfaces_status = duthost.show_interface(command="status")["ansible_facts"]["int_status"]
    for intf, info in interfaces_status.items():
        if info["oper_state"].lower() == "up" and intf.startswith("Ethernet") and intf not in exclude_ports:
            logger.info(f"Selected '{intf}' as ingress port.")
            return intf
    pytest.skip("No suitable ingress port found on the DUT.")


def find_qos_mapping_table_name(duthost, egress_ports, qos_mapping):
    qos_table_name = ""
    for port in egress_ports:
        table = duthost.shell(f"{sonic_db_cli} CONFIG_DB HGET 'PORT_QOS_MAP|{port}' '{qos_mapping}'")["stdout"].strip()
        pytest_assert(table, f"{qos_mapping} is not defined for port {port}.")
        if qos_table_name and qos_table_name != table:
            pytest.skip(f"{qos_mapping} is not the same for all egress ports {egress_ports}.")
        qos_table_name = table
    return qos_table_name


def find_reverse_qos_mapping(duthost, egress_ports, qos_mapping, value_to_find):
    qos_table = find_qos_mapping_table_name(duthost, egress_ports, qos_mapping)
    qos_map_str = \
        duthost.shell(f"{sonic_db_cli} CONFIG_DB HGETALL '{qos_mapping.upper()}|{qos_table}'")["stdout"].strip()
    qos_map = ast.literal_eval(qos_map_str)
    for key, value in qos_map.items():
        if int(value) == value_to_find:
            return int(key)
    pytest.skip(f"Could not find a key mapped to value {value_to_find} in {qos_mapping.upper()}|{qos_table}.")


def find_tc_for_queue(duthost, egress_ports, queue):
    tc = find_reverse_qos_mapping(duthost, egress_ports, "tc_to_queue_map", queue)
    logger.info(f"The traffic class '{tc}' is mapped to queue '{queue}' for egress ports {egress_ports}.")
    return tc


def find_dscp_for_queue(duthost, egress_ports, queue):
    tc = find_tc_for_queue(duthost, egress_ports, queue)
    dscp = find_reverse_qos_mapping(duthost, egress_ports, "dscp_to_tc_map", tc)
    logger.info(f"The DSCP value '{dscp}' is mapped to traffic class '{tc}' for egress ports {egress_ports}.")
    return dscp


def check_asic_db_counts(duthost, old_counts, new_wred_profile):
    new_wred_profile_count = count_keys(duthost, "ASIC_DB", WRED_PROFILE_PATTERN)
    # We create two WRED profiles in total: TEST_WRED_ECN and TEST_WRED_DROP
    pytest_assert(new_wred_profile_count >= old_counts[WRED_PROFILE_PATTERN] + 1 and
                  new_wred_profile_count <= old_counts[WRED_PROFILE_PATTERN] + 2,
                  f"WRED profile {new_wred_profile} was not added to ASIC DB.")
    new_scheduler_count = count_keys(duthost, "ASIC_DB", SCHEDULER_PATTERN)
    pytest_assert(new_scheduler_count == old_counts[SCHEDULER_PATTERN] + 1,
                  f"Scheduler {BLOCKING_SCHEDULER} was not added to ASIC DB.")


@pytest.fixture(params=[
    ("no-SRv6", "ipv4"),
    ("no-SRv6", "ipv6"),
    ("SRv6", "ipv4"),
    ("SRv6", "ipv6"),
    ("SRv6-with-SRH", "ipv4"),
    ("SRv6-with-SRH", "ipv6")
], ids=[
    "ipv4",
    "ipv6",
    "SRv6_inner_ipv4",
    "SRv6_inner_ipv6",
    "SRv6_with_SRH_inner_ipv4",
    "SRv6_with_SRH_inner_ipv6"
])
def setup(duthost, tbinfo, request, enable_wred_counters, create_blocking_scheduler, create_wred_profile,  # noqa F811
          configure_srv6, is_srv6_supported, old_asic_db_counts):  # noqa F811
    minigraph_facts = duthost.get_extended_minigraph_facts(tbinfo)
    ptf_indices = minigraph_facts["minigraph_ptf_indices"]
    is_srv6_test = request.param[0].startswith("SRv6")

    if not is_srv6_supported and is_srv6_test:
        pytest.skip("SRv6 is not supported on this platform.")
    test_params = {}
    # test_params["inner_ip_version"] = Inner IP version for SRv6 packets or IP version for regular packets
    test_params["inner_ip_version"] = request.param[1]
    # test_params["ip_version"] = "ipv6" for SRv6 packets or IP version for regular packets
    test_params["ip_version"] = "ipv6" if is_srv6_test else request.param[1]
    test_params["srv6"] = is_srv6_test
    test_params["with_srh"] = request.param[0].endswith("with-SRH")
    neigh_ip, egress_ports = select_egress_interface(duthost, minigraph_facts,
                                                     ipv4=(test_params["ip_version"] == "ipv4"))
    test_params["neigh_ip"] = neigh_ip
    test_params["egress_ports"] = {port: ptf_indices[port] for port in egress_ports}
    ingress_port = select_ingress_port(duthost, exclude_ports=egress_ports)
    test_params["ingress_port_index"] = ptf_indices[ingress_port]
    policy, wred_profile_name = create_wred_profile
    test_params["policy"] = policy
    test_params["wred_profile_name"] = wred_profile_name
    test_params["dscp"] = find_dscp_for_queue(duthost, egress_ports, QUEUE)

    test_params["prev_scheduler"] = {}
    for port in egress_ports:
        logger.info(f"Setting the WRED profile of {port}|{QUEUE} to '{wred_profile_name}'.")
        duthost.shell(f"{sonic_db_cli} CONFIG_DB HSET 'QUEUE|{port}|{QUEUE}' 'wred_profile' '{wred_profile_name}'")
        test_params["prev_scheduler"][port] = \
            duthost.shell(f"{sonic_db_cli} CONFIG_DB HGET 'QUEUE|{port}|{QUEUE}' 'scheduler'")["stdout"].strip()
        logger.info(f"The original scheduler of {port}|{QUEUE} is '{test_params['prev_scheduler'][port]}'.")
        logger.info(f"Setting the scheduler of {port}|{QUEUE} to '{BLOCKING_SCHEDULER}'.")
        duthost.shell(f"{sonic_db_cli} CONFIG_DB HSET 'QUEUE|{port}|{QUEUE}' 'scheduler' '{BLOCKING_SCHEDULER}'")

    # Add a static route to NEXTHOP_PREFIX via the selected egress interface if testing with SRv6 packets.
    if is_srv6_test:
        logger.info(f"Adding a static route to {NEXTHOP_PREFIX} via {neigh_ip}.")
        duthost.shell(f"sudo config route add prefix {NEXTHOP_PREFIX} nexthop {neigh_ip}")

    logger.info("Waiting 10 seconds for the configuration to take effect.")
    time.sleep(10)  # Wait for the configuration to take effect

    # Verifying that the WRED profile, static route, blocking scheduler, and SRv6 configuration are applied to ASIC DB.
    check_asic_db_counts(duthost, old_asic_db_counts, wred_profile_name)
    if is_srv6_test:
        srv6_my_sid_pattern = f'{SRV6_MY_SID_PATTERN_PREFIX}*\\"sid\\":\\"{LOCATOR_PREFIX}\\"*'
        pytest_assert(pattern_exists(duthost, "ASIC_DB", srv6_my_sid_pattern),
                      f"SRv6 MY_SID entry for {LOCATOR_PREFIX} was not added to ASIC DB.")
        route_pattern = f'{ROUTE_PATTERN_PREFIX}*\\"dest\\":\\"{NEXTHOP_PREFIX}\\"*'
        pytest_assert(pattern_exists(duthost, "ASIC_DB", route_pattern),
                      f"Route entry for {NEXTHOP_PREFIX} was not added to ASIC DB.")

    logger.info(f"Test parameters: {test_params}")
    return test_params


def get_srv6_test_packet(dest_mac, inner_ip_version, ecn, dscp, with_srh):
    if inner_ip_version == "ipv4":
        inner_eth = testutils.simple_udp_packet()
        inner_ip = inner_eth["IP"]
    else:
        inner_eth = testutils.simple_udpv6_packet()
        inner_ip = inner_eth["IPv6"]

    if with_srh:
        pkt = testutils.simple_ipv6_sr_packet(
            eth_dst=dest_mac,
            ipv6_dst=SRV6_OUTER_DIP,
            ipv6_tc=testutils.ip_make_tos(0, ecn, dscp),
            srh_seg_left=1,
            srh_nh=4 if inner_ip_version == "ipv4" else 41,
            inner_frame=inner_ip
        )
    else:
        pkt = testutils.simple_ipv6ip_packet(
            eth_dst=dest_mac,
            ipv6_dst=SRV6_OUTER_DIP,
            ipv6_ecn=ecn,
            ipv6_dscp=dscp,
            inner_frame=inner_ip
        )
    return pkt


def get_test_packet(dest_mac, ip_version, neigh_ip, ect_enabled, dscp, srv6, with_srh):
    """
    For normal packets, ip_version is the IP version of the packet.
    For SRv6 packets, ip_version is the IP version of the inner packet.
    """
    ecn = 0b10 if ect_enabled else 0b00
    if srv6:
        return get_srv6_test_packet(dest_mac, ip_version, ecn, dscp, with_srh)
    if ip_version == "ipv4":
        pkt = testutils.simple_udp_packet(
            eth_dst=dest_mac,
            ip_dst=neigh_ip,
            ip_ecn=ecn,
            ip_dscp=dscp,
        )
    else:
        pkt = testutils.simple_udpv6_packet(
            eth_dst=dest_mac,
            ipv6_dst=neigh_ip,
            ipv6_ecn=ecn,
            ipv6_dscp=dscp,
        )
    return pkt


def get_congestion_packet(dest_mac, ip_version, dest_ip, ect_enabled, dscp):
    ecn = 0b10 if ect_enabled else 0b00
    if ip_version == "ipv4":
        pkt = testutils.simple_tcp_packet(
            eth_dst=dest_mac,
            ip_dst=dest_ip,
            ip_ecn=ecn,
            ip_dscp=dscp,
        )
    else:
        pkt = testutils.simple_tcpv6_packet(
            eth_dst=dest_mac,
            ipv6_dst=dest_ip,
            ipv6_ecn=ecn,
            ipv6_dscp=dscp,
        )
    return pkt


def get_expected_packet_mask_ipv4(pkt, expected_dest_ip):
    exp_pkt = pkt.copy()
    exp_pkt["IP"].ttl -= 1
    exp_pkt["IP"].tos |= 0b11  # Set ECN bits to '11' (CE)
    exp_pkt["IP"].dst = expected_dest_ip
    exp_pkt_mask = Mask(exp_pkt)
    exp_pkt_mask.set_do_not_care_packet(packet.Ether, "dst")
    exp_pkt_mask.set_do_not_care_packet(packet.Ether, "src")
    exp_pkt_mask.set_do_not_care_packet(packet.IP, "ihl")
    exp_pkt_mask.set_do_not_care_packet(packet.IP, "id")
    exp_pkt_mask.set_do_not_care_packet(packet.IP, "flags")
    exp_pkt_mask.set_do_not_care_packet(packet.IP, "chksum")
    exp_pkt_mask.set_do_not_care_packet(packet.UDP, "chksum")
    return exp_pkt_mask


def get_expected_packet_mask_ipv6(pkt, expected_dest_ip):
    exp_pkt = pkt.copy()
    exp_pkt["IPv6"].hlim -= 1
    exp_pkt["IPv6"].tc |= 0b11  # Set ECN bits to '11' (CE)
    exp_pkt["IPv6"].dst = expected_dest_ip
    exp_pkt_mask = Mask(exp_pkt)
    exp_pkt_mask.set_do_not_care_packet(packet.Ether, "dst")
    exp_pkt_mask.set_do_not_care_packet(packet.Ether, "src")
    exp_pkt_mask.set_do_not_care_packet(packet.IPv6, "fl")
    exp_pkt_mask.set_do_not_care_packet(packet.UDP, "chksum")
    return exp_pkt_mask


def get_expected_packet_mask(pkt, ip_version, expected_dest_ip):
    if ip_version == "ipv4":
        return get_expected_packet_mask_ipv4(pkt, expected_dest_ip)
    else:
        return get_expected_packet_mask_ipv6(pkt, expected_dest_ip)


def get_wred_counters(duthost, port, queue):
    wred_counters_str = \
        duthost.shell(f"show queue wredcounters {get_namespace_option()} --json {port}")["stdout"].strip()
    wred_counters = ast.literal_eval(wred_counters_str)
    return wred_counters[port][f"UC{queue}"]


def check_wred_counters(duthost, egress_ports, expect_drop, expect_zero=False):
    action = "drop" if expect_drop else "ECN"
    count = 0
    if expect_drop:
        counter_key = "wreddroppacket"
    else:
        counter_key = "ecnmarkedpacket"
    for port in egress_ports:
        wred_counters = get_wred_counters(duthost, port, QUEUE)
        queue_count_str = wred_counters.get(counter_key, "N/A")
        logger.info(f"WRED {action} counter for {port}|{QUEUE} is {queue_count_str}.")
        pytest_assert(queue_count_str.isdigit(),
                      f"Could not get the WRED {action} counter for queue {port}|{QUEUE}.")
        count += int(queue_count_str)
    if expect_zero:
        pytest_assert(count == 0,
                      f"Sum of WRED {action} counters ({count}) is not zero after clearing counters.")
    else:
        pytest_assert(count >= PACKET_COUNT,
                      f"Sum of WRED {action} counters ({count}) is less than {PACKET_COUNT}.")
    logger.info(f"Sum of WRED {action} counters across egress ports {egress_ports} is {count}.")


def clear_queue_wred_counters(duthost, egress_ports, expect_drop):
    logger.info("Clearing WRED counters on the DUT.")
    duthost.shell("sonic-clear queue wredcounters")
    check_wred_counters(duthost, egress_ports, expect_drop, expect_zero=True)


def create_congestion(ptfadapter, router_mac, ip_version, neigh_ip, dscp, ingress_port_index, egress_port_count):
    logger.info("Creating congestion on egress queues.")
    # Using TCP for congestion packets so that we can distinguish them from the test packets.
    pkt = get_congestion_packet(router_mac, ip_version, neigh_ip, ect_enabled=True, dscp=dscp)
    logger.info(f"Congestion packet: {pkt}")
    # The goal is to put at least 15KB of data into each egress queue. We send 20KB to each queue to account for
    # possible traffic imbalance among LAG members.
    pkt_len = len(pkt)
    num_packets = ((20000 + pkt_len - 1) // pkt_len) * egress_port_count
    logger.info(f"Sending {num_packets} congestion packets to ingress port {ingress_port_index}.")
    testutils.send(ptfadapter, ingress_port_index, pkt, count=num_packets)


def restore_original_schedulers(duthost, prev_schedulers):
    logger.info("Restoring original schedulers for all egress queues.")
    for port, scheduler in prev_schedulers.items():
        if scheduler:
            logger.info(f"Restoring scheduler of {port}|{QUEUE} to '{scheduler}'.")
            duthost.shell(f"{sonic_db_cli} CONFIG_DB HSET 'QUEUE|{port}|{QUEUE}' 'scheduler' '{scheduler}'")
    logger.info("Waiting 10 seconds for the configuration to take effect.")
    time.sleep(10)  # Wait for the configuration to take effect


@pytest.mark.parametrize("ect_enabled", [False, True], ids=["ect_disabled", "ect_enabled"])
def test_wred_counters(duthost, ptfadapter, setup, ect_enabled):
    test_params = setup
    expect_ecn = ect_enabled and test_params["policy"] == "ecn"
    router_mac = duthost.facts["router_mac"]
    pkt = get_test_packet(router_mac, test_params["inner_ip_version"], test_params["neigh_ip"],
                          ect_enabled, test_params["dscp"], test_params["srv6"], test_params["with_srh"])
    logger.info(f"Test packet: {pkt}")
    expected_dest_ip = SRV6_SHIFTED_DIP if test_params["srv6"] else test_params["neigh_ip"]
    exp_pkt_mask = get_expected_packet_mask(pkt, test_params["ip_version"], expected_dest_ip)
    clear_queue_wred_counters(duthost, list(test_params["egress_ports"].keys()), expect_drop=not expect_ecn)

    create_congestion(ptfadapter, router_mac, test_params["ip_version"], test_params["neigh_ip"],
                      test_params["dscp"], test_params["ingress_port_index"], len(test_params["egress_ports"]))

    ptfadapter.dataplane.flush()
    logger.info(f"Sending {PACKET_COUNT} test packets to ingress port {test_params['ingress_port_index']}.")
    testutils.send(ptfadapter, test_params["ingress_port_index"], pkt, count=PACKET_COUNT)

    # Restoring original schedulers so that egress queues are unblocked. This step is necessary since otherwise,
    # all test packets could remain in the queues and we cannot capture and verify egress packets.
    restore_original_schedulers(duthost, test_params["prev_scheduler"])
    if expect_ecn:
        _, received_pkt = testutils.verify_packet_any_port(ptfadapter, exp_pkt_mask,
                                                           ports=list(test_params["egress_ports"].values()))
        logger.info(f"Received packet: {packet.Ether(received_pkt)}")
    else:
        testutils.verify_no_packet_any(ptfadapter, exp_pkt_mask, ports=list(test_params["egress_ports"].values()))
    check_wred_counters(duthost, list(test_params["egress_ports"].keys()), expect_drop=not expect_ecn)
