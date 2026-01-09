import os
import time
import random
import logging
import pprint
import pytest
import json
import ptf.testutils as testutils
import ptf.mask as mask
import ptf.packet as packet
from collections import defaultdict
from tests.common.helpers.assertions import pytest_require, pytest_assert
from tests.common.utilities import get_upstream_neigh_type, get_downstream_neigh_type
from tests.common.portstat_utilities import parse_portstat
from ptf.testutils import (
    dp_poll,
)  # This is an example; adjust based on your actual usage

from .platform_handler import ECMPHashManager


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("any")
]


DEFAULT_SRC_IP = {"ipv4": "20.0.0.1", "ipv6": "60c0:a800::5"}

DOWNSTREAM_IP_PORT_MAP = {}

UPSTREAM_DST_IP = {"ipv4": "194.50.16.1", "ipv6": "2194:100::11"}

PACKET_COUNT = 100
PACKET_COUNT_MAX_DIFF = 5


def validate_testbed_for_ecmp_test(duthost, tbinfo):
    """Validate testbed configuration for ECMP hash testing.

    This function replaces the original hardcoded checks with platform-aware validation.
    It checks ASIC type, topology, and hardware SKU support through the platform handlers.

    Args:
        duthost: DUT host object
        tbinfo: Testbed info dictionary

    Raises:
        pytest.skip: If the DUT or testbed configuration is not supported
    """
    try:
        manager = ECMPHashManager(duthost, tbinfo)
        if not manager.is_supported():
            support_info = manager.get_support_info()
            pytest.skip(f"ECMP hash test not supported on DUT {duthost.hostname}: {support_info}")

        # Log detailed support information for debugging
        support_info = manager.get_support_info()
        logger.info(f"ECMP hash test validation passed for DUT {duthost.hostname}: {support_info}")

    except Exception as e:
        pytest.skip(f"ECMP hash test not supported on DUT {duthost.hostname}: {str(e)}")


@pytest.fixture(scope="module")
def setup(duthosts, rand_selected_dut, tbinfo):
    """Gather all required test information from DUT and tbinfo.

    Args:
        duthosts: All DUTs belong to the testbed.
        rand_one_dut_hostname: hostname of a random chosen dut to run test.
        tbinfo: A fixture to gather information about the testbed.

    Yields:
        A Dictionary with required test information.

    """
    # Validate testbed configuration for ECMP hash testing
    # This replaces the original hardcoded ASIC and topology checks
    validate_testbed_for_ecmp_test(rand_selected_dut, tbinfo)

    mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)
    topo = tbinfo["topo"]["type"]

    vlan_mac = None

    # Get the list of upstream/downstream ports
    downstream_ports = defaultdict(list)
    upstream_ports = defaultdict(list)
    downstream_port_ids = []
    upstream_port_ids = []
    upstream_port_id_to_router_mac_map = {}
    downstream_port_id_to_router_mac_map = {}
    downstream_port_id_to_interface_map = {}
    upstream_port_id_to_interface_map = {}

    # For M0_VLAN/MX/T0/dual ToR scenario, we need to use the VLAN MAC to interact with downstream ports
    # For T1/M0_L3 scenario, no VLANs are present so using the router MAC is acceptable
    downlink_dst_mac = (
        vlan_mac if vlan_mac is not None else rand_selected_dut.facts["router_mac"]
    )

    upstream_neigh_type = get_upstream_neigh_type(tbinfo)
    downstream_neigh_type = get_downstream_neigh_type(tbinfo)
    pytest_require(
        upstream_neigh_type is not None and downstream_neigh_type is not None,
        "Cannot get neighbor type for unsupported topo: {}".format(topo),
    )

    for interface, neighbor in list(mg_facts["minigraph_neighbors"].items()):
        port_id = mg_facts["minigraph_ptf_indices"][interface]
        if downstream_neigh_type in neighbor["name"].upper():
            downstream_ports[neighbor["namespace"]].append(interface)
            downstream_port_ids.append(port_id)
            downstream_port_id_to_router_mac_map[port_id] = downlink_dst_mac
            downstream_port_id_to_interface_map[port_id] = interface
        elif upstream_neigh_type in neighbor["name"].upper():
            upstream_ports[neighbor["namespace"]].append(interface)
            upstream_port_ids.append(port_id)
            upstream_port_id_to_router_mac_map[port_id] = rand_selected_dut.facts[
                "router_mac"
            ]
            upstream_port_id_to_interface_map[port_id] = interface

    setup_information = {
        "destination_mac": downstream_port_id_to_router_mac_map,
        "downstream_port_ids": downstream_port_ids,
        "upstream_port_ids": upstream_port_ids,
        "topo": topo,
        "vlan_mac": vlan_mac,
        "downstream_port_id_to_interface_map": downstream_port_id_to_interface_map,
        "upstream_port_id_to_interface_map": upstream_port_id_to_interface_map,
    }

    logger.info(
        "Gathered variables for hash tuples test:\n{}".format(
            pprint.pformat(setup_information)
        )
    )

    yield setup_information


@pytest.fixture(scope="function")
def set_ecmp_offset(duthost, tbinfo):
    """
    Change the ECMP hash offset temporarily for test, then restore it.
    Platform-independent implementation using ECMPHashManager.

    Args:
        duthost: The DUT host object
    """
    # Create platform-specific ECMP hash manager
    ecmp_manager = ECMPHashManager(duthost, tbinfo)

    # Check if platform is supported
    if not ecmp_manager.is_supported():
        pytest.skip(f"ECMP hash offset test not supported for hardware SKU: {ecmp_manager.hwsku}")

    # Backup original value
    original_value = ecmp_manager.backup_current_offset()
    logger.info(f"Original ECMP hash offset value: {original_value}")

    try:
        # Set test offset value
        ecmp_manager.set_test_offset()

        # Yield control back to the test
        yield
    finally:
        # Restore the original value
        ecmp_manager.restore_original_offset()


@pytest.fixture(scope="module", params=["ipv4", "ipv6"])
def ip_version(request):
    return request.param


@pytest.fixture(autouse=True)
def get_src_port(setup):
    """Get a source port for the current test."""
    src_ports = setup["downstream_port_ids"]
    src_port = random.choice(src_ports)
    logger.info("Selected source port {}".format(src_port))
    return src_port


@pytest.fixture(scope="function", autouse=True)
def manage_ptf_dataplane_logging(ptfadapter):
    """
    Temporarily reduce PTF dataplane logging to avoid spam from background traffic.
    This prevents continuous "Pkt len XX in on device 0, port YY" messages after test completion.
    """
    import logging as py_logging

    # Get the PTF dataplane logger
    ptf_dataplane_logger = py_logging.getLogger("dataplane")
    original_level = ptf_dataplane_logger.level

    # Set to WARNING to suppress DEBUG messages about every packet
    ptf_dataplane_logger.setLevel(py_logging.WARNING)
    logger.info(f"PTF dataplane logging level set to WARNING (was {original_level})")

    yield

    # Restore original logging level
    ptf_dataplane_logger.setLevel(original_level)
    logger.info(f"PTF dataplane logging level restored to {original_level}")


def get_dst_ports(setup):
    """Get the set of possible destination ports for the current test."""
    return setup["upstream_port_ids"]


def get_dst_ip(ip_version):
    """Get the default destination IP for the current test."""
    return UPSTREAM_DST_IP[ip_version]


def udp_packet(
    setup,
    ptfadapter,
    ip_version,
    src_port,
    src_ip=None,
    dst_ip=None,
    sport=1234,
    dport=80,
):
    """Generate a UDP packet for testing."""
    src_ip = src_ip or DEFAULT_SRC_IP[ip_version]
    dst_ip = dst_ip or get_dst_ip(ip_version)
    if ip_version == "ipv4":
        return testutils.simple_udp_packet(
            eth_dst=setup["destination_mac"][src_port],
            eth_src=ptfadapter.dataplane.get_mac(0, 0),
            ip_dst=dst_ip,
            ip_src=src_ip,
            udp_sport=sport,
            udp_dport=dport,
            ip_ttl=64,
        )
    else:
        return testutils.simple_udpv6_packet(
            eth_dst=setup["destination_mac"][src_port],
            eth_src=ptfadapter.dataplane.get_mac(0, 0),
            ipv6_dst=dst_ip,
            ipv6_src=src_ip,
            udp_sport=sport,
            udp_dport=dport,
            ipv6_hlim=64,
        )


def expected_mask_routed_packet(pkt):
    """Generate the expected mask for a routed packet, handling both IPv4 and IPv6."""
    exp_pkt = mask.Mask(pkt.copy())
    exp_pkt.set_do_not_care_scapy(packet.Ether, "dst")
    exp_pkt.set_do_not_care_scapy(packet.Ether, "src")

    # Check if the packet is IPv4 or IPv6 and set appropriate mask fields
    if packet.IP in pkt:
        exp_pkt.set_do_not_care_scapy(packet.IP, "chksum")
        exp_pkt.set_do_not_care_scapy(packet.IP, "ttl")
    elif packet.IPv6 in pkt:
        exp_pkt.set_do_not_care_scapy(packet.IPv6, "hlim")

    return exp_pkt


def sum_ifaces_counts(counter_out, ifaces, column):
    if len(ifaces) == 0:
        return 0
    if len(ifaces) == 1:
        return int(counter_out[ifaces[0]][column].replace(",", ""))
    return sum([int(counter_out[iface][column].replace(",", "")) for iface in ifaces])


def verfiy_packets_count(duthost, match_cnt):
    portstat_out = parse_portstat(duthost.command("portstat")["stdout_lines"])
    logger.info("Portstat output:\n{}".format(pprint.pformat(portstat_out)))

    # Find interfaces with tx_ok larger than PACKET_COUNT
    interfaces_with_high_tx = []
    for iface, stats in portstat_out.items():
        tx_ok = int(stats["tx_ok"].replace(",", ""))
        if tx_ok >= PACKET_COUNT:
            interfaces_with_high_tx.append(iface)

    if interfaces_with_high_tx:
        logger.info(
            f"Interfaces with tx_ok >= {PACKET_COUNT}: {interfaces_with_high_tx}"
        )
    else:
        logger.warning(f"No interfaces found with tx_ok >= {PACKET_COUNT}")

    # Assert that at least one interface forwarded enough packets
    pytest_assert(
        len(interfaces_with_high_tx) > 0,
        f"No interfaces found with tx_ok >= {PACKET_COUNT}",
    )

    # Assert that PTF matched the expected number of packets
    pytest_assert(
        match_cnt >= PACKET_COUNT,
        f"PTF matched {match_cnt} packets, which is less than the expected {PACKET_COUNT}",
    )
    # Sort interfaces by tx_ok count in descending order
    sorted_interfaces = sorted(
        interfaces_with_high_tx,
        key=lambda iface: int(portstat_out[iface]["tx_ok"].replace(",", "")),
        reverse=True,
    )

    # Return the interface with highest tx_ok count if available
    return sorted_interfaces[0] if sorted_interfaces else None


def save_test_results(duthost, test_results, ip_version, with_ecmpoffset=False):
    if with_ecmpoffset:
        file_name = (
            f"logs/{duthost.hostname}_{ip_version}_hash_tuples_test_results_ecmp.json"
        )
        file_name_formatted = f"logs/{duthost.hostname}_{ip_version}_hash_tuples_test_results_formatted_ecmp.json"
    else:
        file_name = (
            f"logs/{duthost.hostname}_{ip_version}_hash_tuples_test_results.json"
        )
        file_name_formatted = f"logs/{duthost.hostname}_{ip_version}_hash_tuples_test_results_formatted.json"
    try:
        local_results_file = os.path.join(os.getcwd(), file_name)
        with open(local_results_file, "w") as f:
            json.dump(test_results, f, indent=4)
        logger.info(f"Test results saved to {local_results_file}")
    except Exception as e:
        # Format the test results to organize by interface
        logger.error(f"Failed to save test results to file: {e}")
    format_results = {}

    # Process each pattern
    for pattern in test_results:
        format_results[pattern] = {}

        # Group by interface
        for case, data in test_results[pattern].items():
            interface = data["out_interface"]
            if not interface:
                continue

            if interface not in format_results[pattern]:
                format_results[pattern][interface] = {}
                format_results[pattern][interface]["tuples"] = {}
                format_results[pattern][interface]["count"] = 0

            # Add this tuple to the interface's list
            tuple_key = f"tuples_{case}"
            format_results[pattern][interface]["tuples"][tuple_key] = data["5_tuples"]
            format_results[pattern][interface]["count"] += 1

            # Store packet count temporarily
            if "packets_count" not in format_results[pattern][interface]:
                format_results[pattern][interface]["packets_count"] = data[
                    "packets_count"
                ]
                # Check for high variance in packet counts within each pattern

    # Move packets_count to the end for each interface
    for pattern in format_results:
        for interface in format_results[pattern]:
            packets_count = format_results[pattern][interface].pop(
                "packets_count", None
            )
            if packets_count:
                format_results[pattern][interface]["packets_count"] = packets_count

    logger.info("Formatted results by interface:")
    logger.info(json.dumps(format_results, indent=4))
    try:
        formatted_results_file = os.path.join(os.getcwd(), file_name_formatted)
        with open(formatted_results_file, "w") as f:
            json.dump(format_results, f, indent=4)
        logger.info(f"Formatted results saved to {formatted_results_file}")
    except Exception as e:
        logger.error(f"Failed to save formatted results to file: {e}")

    for pattern, interfaces in format_results.items():
        for interface, data in interfaces.items():
            packet_counts = []

            # Collect all packet counts for this interface under this pattern
            for tuple_key, _ in data["tuples"].items():
                if "count" in data:
                    packet_counts.append(data["count"])

            # If we have packet counts to compare
            if packet_counts:
                min_count = min(packet_counts)
                max_count = max(packet_counts)
                diff = max_count - min_count

                # If the difference is more than 4, fail the case
                if diff > PACKET_COUNT_MAX_DIFF:
                    error_msg = (
                        f"High variance in packet counts for {pattern} on {interface}: "
                        f"min={min_count}, max={max_count}, diff={diff}"
                    )
                    logger.error(error_msg)
                    pytest_assert(False, error_msg)


def compare_test_results(duthost, ip_version):
    """
    Compare test results with and without ECMP hash offset change.
    If results are identical, the test case has failed because the hash offset
    did not impact the packet distribution.

    Args:
        test_results: Results from the current test
        expected_results: Results from the previous test

    Returns:
        bool: True if different (test passed), False if identical (test failed)
    """
    logger.info("Comparing test results with and without ECMP hash offset")
    # Load the regular test results file
    regular_results_path = os.path.join(
        os.getcwd(),
        f"logs/{duthost.hostname}_{ip_version}_hash_tuples_test_results_formatted.json",
    )
    ecmp_results_path = os.path.join(
        os.getcwd(),
        f"logs/{duthost.hostname}_{ip_version}_hash_tuples_test_results_formatted_ecmp.json",
    )

    logger.info(f"Loading regular test results from {regular_results_path}")
    logger.info(f"Loading ECMP offset test results from {ecmp_results_path}")
    is_expected = None
    try:
        with open(regular_results_path, "r") as f:
            test_results = json.load(f)
    except Exception as e:
        logger.error(f"Failed to load regular test results: {e}")
        test_results = {}

    try:
        with open(ecmp_results_path, "r") as f:
            ecmp_test_results = json.load(f)
    except Exception as e:
        logger.error(f"Failed to load ECMP offset test results: {e}")
        ecmp_test_results = {}
    # Check if both are empty
    if not test_results and not ecmp_test_results:
        logger.error("Both test results are empty - cannot compare")
        is_expected = False

    # Check if one is empty and the other is not
    if bool(test_results) != bool(ecmp_test_results):
        logger.error("Results differ (one is empty, the other is not) - test passed")
        is_expected = False

    # Deep comparison of results
    for pattern in test_results:
        if pattern not in ecmp_test_results:
            logger.error(f"Pattern '{pattern}' not in ecmp test results - test passed")
            is_expected = False
            break

        for interface in test_results[pattern]:
            if interface not in ecmp_test_results[pattern]:
                logger.error(
                    f"Interface '{interface}' not in ecmp test results for pattern '{pattern}' - test failed"
                )
                is_expected = False
                break

            # Compare tuples for this interface
            if (
                test_results[pattern][interface]["tuples"]
                != ecmp_test_results[pattern][interface]["tuples"]
            ):
                logger.info(
                    f"Tuples differ for '{pattern}' on interface '{interface}' - test passed"
                )
                is_expected = True
            else:
                logger.error(
                    f"Tuples are identical for '{pattern}' on interface '{interface}' - test failed"
                )
                is_expected = False
                return is_expected

    return is_expected


def match_expected_packet(test, exp_packet, ports=[], device_number=0, timeout=1, exp_count=1):
    """
    Polls packets from the given ports and counts matches against expected_pkt.

    Returns a dict mapping port numbers to the count of matching packets.
    """
    last_matched_packet_time = time.time()
    total_rcv_pkt_cnt = 0
    match_counts = {}
    matched_port = None
    while True:
        if (time.time() - last_matched_packet_time) > timeout:
            logger.error("Timeout reached while polling for packets.")
            break

        result = dp_poll(test, device_number=device_number, timeout=timeout, exp_pkt=exp_packet)
        if isinstance(result, test.dataplane.PollSuccess):
            if result.port in ports:
                matched_port = result.port
                total_rcv_pkt_cnt += 1
                last_matched_packet_time = time.time()
                if total_rcv_pkt_cnt >= exp_count:
                    break
            else:
                logger.error("Received packet on unexpected port: {}".format(result.port))
        else:
            logger.error("Not PollSuccess, exiting poll loop.")
            break
    match_counts[matched_port] = total_rcv_pkt_cnt

    # Flush any remaining packets after verification completes
    test.dataplane.flush()

    # Give the dataplane a moment to settle
    time.sleep(0.1)

    return match_counts


def send_and_verify_packets(setup, ptfadapter, ip_version, get_src_port):
    base_sip = DEFAULT_SRC_IP[ip_version]
    base_dip = get_dst_ip(ip_version)
    base_sport = 100
    base_dport = 80
    proto = 17
    INCREMENT = 240
    # Dictionary to store test results for all patterns
    test_results = {
        "pattern_1": {},  # varying source ports
        "pattern_2": {},  # varying source IPs
        "pattern_3": {},  # varying destination ports
        "pattern_4": {},  # varying destination IPs
    }
    dst_ports = get_dst_ports(setup)

    # Flush any residual packets before starting the test
    ptfadapter.dataplane.flush()
    # Pattern 1: Varying source ports
    logger.info("Testing pattern 1: Varying source ports")

    for i, sport in enumerate(range(base_sport, base_sport + INCREMENT)):
        pkt = udp_packet(
            setup,
            ptfadapter,
            ip_version,
            get_src_port,
            src_ip=base_sip,
            dst_ip=base_dip,
            sport=sport,
            dport=base_dport,
        )
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, get_src_port, pkt, PACKET_COUNT)
        exp_pkt = expected_mask_routed_packet(pkt)
        match_cnt = match_expected_packet(ptfadapter, exp_pkt, ports=dst_ports, exp_count=PACKET_COUNT)
        matched_out_port = list(match_cnt.keys())[0]
        pytest_assert(
            match_cnt[matched_out_port] >= PACKET_COUNT,
            "DUT forwarded {} packets, but {} packets matched expected format, not in expected range".format(
                match_cnt[matched_out_port], match_cnt
            ),
        )
        out_interface = setup["upstream_port_id_to_interface_map"][matched_out_port]

        # Store results for this test case
        test_results["pattern_1"][str(i + 1)] = {
            "5_tuples": f"src={base_sip} dst={base_dip} sport={sport} dport={base_dport} proto={proto}",
            "out_interface": out_interface,
            "packets_count": match_cnt[matched_out_port],
        }
        logger.info(
            f"Pattern 1 case {i+1}: {base_sip} {base_dip} {sport} {base_dport} {proto} "
            f"Matched {match_cnt} packets on {out_interface}"
        )

    # Pattern 2: Varying source IPs
    logger.info("Testing pattern 2: Varying source IPs")

    for i in range(INCREMENT):
        if ip_version == "ipv4":
            last_octet = 2 + i
            src_ip = f"20.0.0.{last_octet}"
        else:
            last_octet = 2 + i
            src_ip = f"60c0:a800::{last_octet:04x}"  # noqa: E231
        pkt = udp_packet(
            setup,
            ptfadapter,
            ip_version,
            get_src_port,
            src_ip=src_ip,
            dst_ip=base_dip,
            sport=base_sport,
            dport=base_dport,
        )
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, get_src_port, pkt, PACKET_COUNT)
        exp_pkt = expected_mask_routed_packet(pkt)
        match_cnt = match_expected_packet(ptfadapter, exp_pkt, ports=dst_ports, exp_count=PACKET_COUNT)
        matched_out_port = list(match_cnt.keys())[0]
        pytest_assert(
            match_cnt[matched_out_port] >= PACKET_COUNT,
            "DUT forwarded {} packets, but {} packets matched expected format, not in expected range".format(
                match_cnt[matched_out_port], match_cnt
            ),
        )
        out_interface = setup["upstream_port_id_to_interface_map"][matched_out_port]

        # Store results for this test case
        test_results["pattern_2"][str(i + 1)] = {
            "5_tuples": f"src={src_ip} dst={base_dip} sport={base_sport} dport={base_dport} proto={proto}",
            "out_interface": out_interface,
            "packets_count": match_cnt[matched_out_port],
        }
        logger.info(
            f"Pattern 2 case {i+1}: {src_ip} {base_dip} {base_sport} {base_dport} {proto} "
            f"Matched {match_cnt} packets on {out_interface}"
        )

    # Pattern 3: Varying destination ports
    logger.info("Testing pattern 3: Varying destination ports")

    for i, dport in enumerate(range(base_dport, base_dport + INCREMENT)):
        pkt = udp_packet(
            setup,
            ptfadapter,
            ip_version,
            get_src_port,
            src_ip=base_sip,
            dst_ip=base_dip,
            sport=base_sport,
            dport=dport,
        )
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, get_src_port, pkt, PACKET_COUNT)
        exp_pkt = expected_mask_routed_packet(pkt)
        match_cnt = match_expected_packet(ptfadapter, exp_pkt, ports=dst_ports, exp_count=PACKET_COUNT)
        matched_out_port = list(match_cnt.keys())[0]
        pytest_assert(
            match_cnt[matched_out_port] >= PACKET_COUNT,
            "DUT forwarded {} packets, but {} packets matched expected format, not in expected range".format(
                match_cnt[matched_out_port], match_cnt
            ),
        )
        out_interface = setup["upstream_port_id_to_interface_map"][matched_out_port]

        # Store results for this test case
        test_results["pattern_3"][str(i + 1)] = {
            "5_tuples": f"src={base_sip} dst={base_dip} sport={base_sport} dport={dport} proto={proto}",
            "out_interface": out_interface,
            "packets_count": match_cnt[matched_out_port],
        }
        logger.info(
            f"Pattern 3 case {i+1}: {base_sip} {base_dip} {base_sport} {dport} {proto} "
            f"Matched {match_cnt} packets on {out_interface}"
        )

    # Pattern 4: Varying destination IPs
    logger.info("Testing pattern 4: Varying destination IPs")

    for i in range(INCREMENT):
        if ip_version == "ipv4":
            last_octet = 2 + i
            dst_ip = f"194.50.16.{last_octet}"
        else:
            last_octet = 2 + i
            dst_ip = f"20c1:d180::{last_octet:04x}"  # noqa: E231
        pkt = udp_packet(
            setup,
            ptfadapter,
            ip_version,
            get_src_port,
            src_ip=base_sip,
            dst_ip=dst_ip,
            sport=base_sport,
            dport=base_dport,
        )
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, get_src_port, pkt, PACKET_COUNT)
        exp_pkt = expected_mask_routed_packet(pkt)
        match_cnt = match_expected_packet(ptfadapter, exp_pkt, ports=dst_ports, exp_count=PACKET_COUNT)
        matched_out_port = list(match_cnt.keys())[0]
        pytest_assert(
            match_cnt[matched_out_port] >= PACKET_COUNT,
            "DUT forwarded {} packets, but {} packets matched expected format, not in expected range".format(
                match_cnt[matched_out_port], match_cnt
            ),
        )
        out_interface = setup["upstream_port_id_to_interface_map"][matched_out_port]

        # Store results for this test case
        test_results["pattern_4"] = test_results.get("pattern_4", {})
        test_results["pattern_4"][str(i + 1)] = {
            "5_tuples": f"src={base_sip} dst={dst_ip} sport={base_sport} dport={base_dport} proto={proto}",
            "out_interface": out_interface,
            "packets_count": match_cnt[matched_out_port],
        }
        logger.info(
            f"Pattern 4 case {i+1}: {base_sip} {dst_ip} {base_sport} {base_dport} {proto} "
            f"Matched {match_cnt} packets on {out_interface}"
        )

    # Flush dataplane to clear any residual packets after test completion
    ptfadapter.dataplane.flush()
    logger.info("Test completed - dataplane flushed")

    return test_results


def test_udp_packets(duthost, setup, ptfadapter, ip_version, get_src_port):
    """Verify that we can match and forward UDP packets with different patterns."""

    test_results = send_and_verify_packets(setup, ptfadapter, ip_version, get_src_port)

    # Print the test results
    logger.info("Test results:")
    logger.info(json.dumps(test_results, indent=4))
    save_test_results(duthost, test_results, ip_version)


def test_udp_packets_ecmp(
    duthost, tbinfo, setup, ptfadapter, ip_version, get_src_port, set_ecmp_offset
):
    """Verify that ECMP hash offset affects packet distribution patterns."""
    # Create platform-specific ECMP hash manager for logging current offset
    ecmp_manager = ECMPHashManager(duthost, tbinfo)

    logger.info(f"Running ECMP hash offset test for hardware SKU: {ecmp_manager.hwsku}")

    # Platform support check is already handled by setup fixture and set_ecmp_offset fixture
    current_offset = ecmp_manager.get_current_offset()
    logger.info(f"before test: Current ECMP hash offset value: {current_offset}")

    test_results = send_and_verify_packets(setup, ptfadapter, ip_version, get_src_port)

    # Print the test results
    logger.info("Test results:")
    logger.info(json.dumps(test_results, indent=4))
    save_test_results(duthost, test_results, ip_version, with_ecmpoffset=True)
    is_expected = compare_test_results(duthost, ip_version)
    pytest_assert(
        is_expected,
        "Test results are identical with and without ECMP hash offset change - test failed",
    )
