import json
import os
import pytest
import logging
import time
import ipaddress
import tempfile
import scapy.all as scapy
import ptf.testutils as testutils

from ptf.mask import Mask
from tests.common.config_reload import config_reload
from tests.common.helpers.srv6_helper import dump_packet_detail
from tests.common.reboot import reboot
from tests.packet_trimming.constants import (DEFAULT_SRC_PORT, DEFAULT_DST_PORT, DEFAULT_TTL, DUMMY_MAC, DUMMY_IPV6,
                                             DUMMY_IP, BATCH_PACKET_COUNT, PACKET_COUNT, BLOCK_QUEUE_PROFILE,
                                             BLOCK_DATA_PLANE_SCHEDULER_NAME, TRIM_QUEUE, PACKET_TYPE, SRV6_PACKETS,
                                             TRIM_QUEUE_PROFILE, TRIMMING_CAPABILITY, ACL_TABLE_NAME,
                                             ACL_RULE_PRIORITY, ACL_TABLE_TYPE_NAME, ACL_RULE_NAME, SRV6_MY_SID_LIST,
                                             SRV6_INNER_SRC_IP, SRV6_INNER_DST_IP, DEFAULT_QUEUE_SCHEDULER_CONFIG,
                                             SRV6_UNIFORM_MODE, SRV6_OUTER_SRC_IPV6, SRV6_INNER_SRC_IPV6,
                                             SRV6_INNER_DST_IPV6, SRV6_UN)

logger = logging.getLogger(__name__)


def configure_trimming_global(duthost, size, dscp, queue):
    """
    Configure global trimming settings.

    Args:
        duthost: DUT host object
        size (int): Trimming size in bytes
        dscp (int): DSCP value for trimmed packets
        queue (int): Queue index for trimmed packets
    """
    try:
        logger.info(f"Configuring trimming global: size={size}, dscp={dscp}, queue={queue}")
        cmd = f"config switch-trimming global --size {size} --dscp {dscp} --queue {queue}"
        duthost.shell(cmd)
        logger.info("Successfully configured global trimming")

    except Exception as e:
        logger.error(f"Exception occurred while configuring trimming global: {e}")
        raise


def get_trimming_global_status(duthost):
    """
    Get global trimming configuration status.

    Args:
        duthost: DUT host object

    Returns:
        dict: Dictionary containing trimming configuration or None if failed
    """
    try:
        result = duthost.shell("show switch-trimming global --json")
        logger.info(f"Trimming global status: {result['stdout']}")
        return json.loads(result['stdout'])

    except Exception as e:
        logger.error(f"Failed to get trimming global status: {e}")
        return None


def verify_trimming_config(duthost, size, dscp, queue):
    """
    Verify global trimming configuration meets expected values.

    Args:
        duthost: DUT host object
        size (int): Expected trimming size in bytes
        dscp (int): Expected DSCP value for trimmed packets
        queue (int): Expected queue index for trimmed packets

    Returns:
        bool: True if configuration matches expected values, False otherwise

    Raises:
        AssertionError: If any configuration value does not match expected value
    """
    try:
        logger.info(f"Verifying trimming configuration: expected size={size}, dscp={dscp}, queue={queue}")

        # Get current trimming configuration
        trimming_config = get_trimming_global_status(duthost)

        # Verify trimming configuration meets expectations
        assert trimming_config is not None, "Failed to get trimming configuration status"

        # Check if configuration values match the expected values
        assert int(trimming_config.get("size", 0)) == int(size), \
            f"Trimming size mismatch: expected {size}, got {trimming_config.get('size')}"

        assert int(trimming_config.get("dscp_value", 0)) == int(dscp), \
            f"DSCP value mismatch: expected {dscp}, got {trimming_config.get('dscp_value')}"

        assert int(trimming_config.get("queue_index", 0)) == int(queue), \
            f"Queue index mismatch: expected {queue}, got {trimming_config.get('queue_index')}"

        logger.info("Trimming configuration verification successful, all parameters match expected values")
        return True

    except Exception as e:
        logger.error(f"Exception occurred while verifying trimming configuration: {e}")
        raise


def generate_packet(duthost, packet_type, dst_addr, send_pkt_size, send_pkt_dscp, recv_pkt_size, recv_pkt_dscp):
    """
    Generate a packet of specified type and size.

    Args:
        duthost: DUT host object
        packet_type (str): Type of packet to construct ('ipv4_tcp', 'ipv4_udp', 'ipv6_tcp', 'ipv6_udp')
        dst_addr (str): Destination address (IPv4 address for ipv4_* types, IPv6 address for ipv6_* types)
        send_pkt_size (int): Send packet size.
        send_pkt_dscp (int): Send packet DSCP value.
        recv_pkt_size (int): Expected packet size after trimming
        recv_pkt_dscp (int): Expected DSCP value in received packets

    Returns:
        tuple: (pkt, exp_packet) - Generated packet and expected packet
    """
    # Set basic parameters
    src_port = DEFAULT_SRC_PORT
    dst_port = DEFAULT_DST_PORT
    router_mac = duthost.facts["router_mac"]
    src_mac = DUMMY_MAC
    ip_ttl = DEFAULT_TTL

    # Determine packet type flags
    is_ipv6 = packet_type.startswith('ipv6')
    is_tcp = packet_type.endswith('_tcp')

    # Get source and destination IP addresses based on packet type
    dst_ip = dst_addr
    src_ip = DUMMY_IPV6 if is_ipv6 else DUMMY_IP

    # For IPv6, convert DSCP to Traffic Class value (DSCP << 2)
    ipv6_send_tc = send_pkt_dscp << 2 if is_ipv6 else send_pkt_dscp
    ipv6_recv_tc = recv_pkt_dscp << 2 if is_ipv6 else recv_pkt_dscp

    # Prepare base parameters for send packet
    send_params = {
        'eth_src': src_mac,
        'eth_dst': router_mac,
        'pktlen': send_pkt_size
    }

    # Prepare base parameters for receive packet
    recv_params = {
        'eth_src': router_mac,
        'pktlen': recv_pkt_size
    }

    # Add IP layer parameters based on IP version
    if is_ipv6:  # IPv6
        send_params.update({
            'ipv6_src': src_ip,
            'ipv6_dst': dst_ip,
            'ipv6_hlim': ip_ttl,
            'ipv6_tc': ipv6_send_tc
        })
        recv_params.update({
            'ipv6_src': src_ip,
            'ipv6_dst': dst_ip,
            'ipv6_hlim': ip_ttl - 1,
            'ipv6_tc': ipv6_recv_tc
        })
    else:  # IPv4
        send_params.update({
            'ip_src': src_ip,
            'ip_dst': dst_ip,
            'ip_ttl': ip_ttl,
            'ip_dscp': send_pkt_dscp
        })
        recv_params.update({
            'ip_src': src_ip,
            'ip_dst': dst_ip,
            'ip_ttl': ip_ttl - 1,
            'ip_dscp': recv_pkt_dscp
        })

    # Add transport layer parameters based on protocol
    if is_tcp:  # TCP
        send_params.update({
            'tcp_sport': src_port,
            'tcp_dport': dst_port
        })
        recv_params.update({
            'tcp_sport': src_port,
            'tcp_dport': dst_port
        })
    else:  # UDP
        send_params.update({
            'udp_sport': src_port,
            'udp_dport': dst_port
        })
        recv_params.update({
            'udp_sport': src_port,
            'udp_dport': dst_port
        })

    # Create packets based on packet type
    if packet_type == 'ipv4_tcp':
        pkt = testutils.simple_tcp_packet(**send_params)
        exp_packet = testutils.simple_tcp_packet(**recv_params)
    elif packet_type == 'ipv4_udp':
        pkt = testutils.simple_udp_packet(**send_params)
        exp_packet = testutils.simple_udp_packet(**recv_params)
    elif packet_type == 'ipv6_tcp':
        pkt = testutils.simple_tcpv6_packet(**send_params)
        exp_packet = testutils.simple_tcpv6_packet(**recv_params)
    elif packet_type == 'ipv6_udp':
        pkt = testutils.simple_udpv6_packet(**send_params)
        exp_packet = testutils.simple_udpv6_packet(**recv_params)

    # Create masked expected packet
    masked_exp_packet = Mask(exp_packet)

    # Set fields to ignore in packet matching
    # Common Ethernet header fields to ignore
    masked_exp_packet.set_do_not_care_packet(scapy.Ether, "src")
    masked_exp_packet.set_do_not_care_packet(scapy.Ether, "dst")

    # After packet is trimmed, the checksum and IP length fields are not recalculated
    # So ignore check them in the expected packet
    if is_tcp:
        masked_exp_packet.set_do_not_care_packet(scapy.TCP, "chksum")
    else:  # UDP
        masked_exp_packet.set_do_not_care_packet(scapy.UDP, "chksum")
        masked_exp_packet.set_do_not_care_packet(scapy.UDP, "len")

    if not is_ipv6:  # IPv4
        masked_exp_packet.set_do_not_care_packet(scapy.IP, "id")
        masked_exp_packet.set_do_not_care_packet(scapy.IP, "chksum")
        masked_exp_packet.set_do_not_care_packet(scapy.IP, "len")
    else:  # IPv6
        masked_exp_packet.set_do_not_care_packet(scapy.IPv6, "plen")

    return pkt, masked_exp_packet


def create_blocking_scheduler(duthost):
    """
    Create a blocking scheduler for limiting egress traffic

    Args:
        duthost: DUT host object
    """
    logger.info(f"Creating blocking scheduler: {BLOCK_DATA_PLANE_SCHEDULER_NAME}")

    # Check if scheduler already exists
    cmd_check = f"sonic-db-cli CONFIG_DB exists 'SCHEDULER|{BLOCK_DATA_PLANE_SCHEDULER_NAME}'"
    result = duthost.shell(cmd_check)

    if result["stdout"].strip() == "1":
        logger.info(f"Blocking scheduler {BLOCK_DATA_PLANE_SCHEDULER_NAME} already exists")
    else:
        # Create blocking scheduler
        cmd_create = (
            f'sonic-db-cli CONFIG_DB hset "SCHEDULER|{BLOCK_DATA_PLANE_SCHEDULER_NAME}" '
            f'"type" DWRR "weight" 15 "pir" 1'
        )
        duthost.shell(cmd_create)
        logger.info(f"Successfully created blocking scheduler: {BLOCK_DATA_PLANE_SCHEDULER_NAME}")


def delete_blocking_scheduler(duthost):
    """
    Delete the blocking scheduler if it's not in use

    Args:
        duthost: DUT host object
    """
    logger.info(f"Checking if blocking scheduler {BLOCK_DATA_PLANE_SCHEDULER_NAME} can be deleted")

    # Check if scheduler is in use
    cmd_check = f"sonic-db-cli CONFIG_DB keys 'QUEUE|*' | grep -c '{BLOCK_DATA_PLANE_SCHEDULER_NAME}'"
    result = duthost.shell(cmd_check, module_ignore_errors=True)
    count = int(result["stdout"].strip())

    if count > 0:
        logger.info(f"Scheduler {BLOCK_DATA_PLANE_SCHEDULER_NAME} is still in use by {count} queues, not deleting")
    else:
        # Delete scheduler only if it's not in use
        logger.info(f"Deleting blocking scheduler: {BLOCK_DATA_PLANE_SCHEDULER_NAME}")
        cmd_delete = f"sonic-db-cli CONFIG_DB del 'SCHEDULER|{BLOCK_DATA_PLANE_SCHEDULER_NAME}'"
        duthost.shell(cmd_delete)
        logger.info(f"Successfully deleted blocking scheduler: {BLOCK_DATA_PLANE_SCHEDULER_NAME}")


def disable_egress_data_plane(duthost, dut_port, queue):
    """
    Disable egress data plane for a specific queue on a specific port.

    Args:
        duthost: DUT host object
        dut_port (str): DUT port name
        queue (str/int): Queue index to disable

    Returns:
        str: Original scheduler name for later restoration
    """
    # Convert queue to string format
    queue = str(queue)

    logger.info(f"Disabling egress data plane for port: {dut_port}, queue: {queue}")

    # Get original scheduler name
    cmd_get_scheduler = f"sonic-db-cli CONFIG_DB hget 'QUEUE|{dut_port}|{queue}' scheduler"
    result = duthost.shell(cmd_get_scheduler)

    original_scheduler = result["stdout"].strip()

    # Apply blocking scheduler to the specified queue
    cmd_block_q = f"sonic-db-cli CONFIG_DB hset 'QUEUE|{dut_port}|{queue}' scheduler {BLOCK_DATA_PLANE_SCHEDULER_NAME}"
    duthost.shell(cmd_block_q)

    logger.info(f"Successfully applied blocking scheduler to port {dut_port} queue {queue}")

    return original_scheduler


def enable_egress_data_plane(duthost, dut_port, queue, original_scheduler=None):
    """
    Restore egress data plane for a specific queue on a specific port.

    Args:
        duthost: DUT host object
        dut_port (str): DUT port name
        queue (str/int): Queue index to enable
        original_scheduler (str): Original scheduler name to restore. If None, will use default.
    """
    # Convert queue to string format
    queue = str(queue)

    logger.info(f"Enabling egress data plane for port: {dut_port}, queue: {queue}")

    # Determine scheduler to apply
    if original_scheduler is None:
        # Use default scheduler if original not provided
        original_scheduler = DEFAULT_QUEUE_SCHEDULER_CONFIG.get(queue)

    # Apply original or default scheduler
    if original_scheduler:
        cmd = f"sonic-db-cli CONFIG_DB hset 'QUEUE|{dut_port}|{queue}' scheduler {original_scheduler}"
        duthost.shell(cmd)
        logger.info(f"Restored scheduler '{original_scheduler}' for port {dut_port} queue {queue}")
    else:
        # Remove scheduler if no original or default found
        cmd = f"sonic-db-cli CONFIG_DB hdel 'QUEUE|{dut_port}|{queue}' scheduler"
        duthost.shell(cmd)
        logger.info(f"Removed scheduler for port {dut_port} queue {queue}")


def configure_trimming_action(duthost, buffer_profile_name, action):
    """
    Configure packet discard action for a specific buffer profile.

    Args:
        duthost: DUT host object
        buffer_profile_name: Name of the buffer profile to configure
        action: Packet discard action, must be either "trim" or "drop"
               - "on": Enable packet trimming
               - "off": Disable packet trimming (packets will be dropped)

    Returns:
        bool: True if configuration was successful, False otherwise
    """
    # Validate action parameter
    if action not in ["on", "off"]:
        logger.error(f"Invalid action: {action}. Must be either 'on' or 'off'")
        return False

    logger.info(f"Setting packet trimming action to '{action}' for buffer profile: {buffer_profile_name}")

    # Set packet trimming action using the new command format
    cmd_set = f"sudo config mmu -p {buffer_profile_name} -t {action}"
    duthost.shell(cmd_set)
    duthost.shell("show mmu")

    logger.info(f"Successfully set packet trimming action to '{action}' for buffer profile {buffer_profile_name}")
    return True


def get_buffer_profile_trimming_status(duthost, buffer_profile_name):
    """
    Get the current packet discard action for a specific buffer profile.

    Args:
        duthost: DUT host object
        buffer_profile_name: Name of the buffer profile to check

    Returns:
        str: Current packet discard action setting
             - "trim": Packet trimming is enabled
             - "drop": Packet trimming is disabled (packets are dropped)
             - None: If buffer profile doesn't exist or error occurred
    """
    logger.info(f"Checking packet discard action for buffer profile: {buffer_profile_name}")

    # Check if buffer profile exists
    cmd_check = f"redis-cli -n 4 exists 'BUFFER_PROFILE|{buffer_profile_name}'"
    result = duthost.shell(cmd_check)

    if result["stdout"].strip() == "0":
        logger.error(f"Buffer profile {buffer_profile_name} does not exist")
        return None

    # Get packet discard action
    cmd_get = f"redis-cli -n 4 hget 'BUFFER_PROFILE|{buffer_profile_name}' packet_discard_action"
    result = duthost.shell(cmd_get)
    action = result["stdout"].strip()

    # Validate the retrieved action
    if action not in ["trim", "drop"]:
        logger.warning(f"Unexpected packet discard action: {action}. Expected 'trim' or 'drop'")

    logger.info(f"Buffer profile {buffer_profile_name} has packet_discard_action set to: '{action}'")

    return action


def fill_egress_buffer(duthost, ptfadapter, port_id, buffer_size, target_queue, dst_ipv4_addr, dscp_value, interfaces):
    """
    Fill the specified port queue's buffer to trigger packet trimming.
    If multiple interfaces are provided, fill with the buffers of all interfaces.

    Args:
        duthost: DUT host object
        ptfadapter: PTF adapter object
        port_id: Source port ID for sending packets
        buffer_size: Buffer size to fill (in bytes)
        target_queue: Target queue number
        dst_ipv4_addr: Destination IPv4 address
        dscp_value: DSCP value used for classification to target queue
        interfaces: Single interface or list of interfaces to fill

    Returns:
        int: Actual number of packets sent
    """
    # Convert single interface to list if necessary
    if isinstance(interfaces, str):
        interfaces = [interfaces]

    logger.info(f"Filling buffer to trigger packet trimming for interfaces: {interfaces}")

    # Check queue counters before filling
    for interface in interfaces:
        logger.info(f"Queue counters before filling for {interface}:")
        duthost.shell(f"show queue counters {interface}")

    # Create a large packet to efficiently fill the buffer
    fill_packet_size = 1500  # Standard Ethernet MTU
    fill_packet_count = buffer_size // fill_packet_size * 2

    logger.info(f"Buffer size for queue {target_queue} is approximately {buffer_size} bytes")
    logger.info(f"Sending {fill_packet_count} packets of size {fill_packet_size} bytes to fill the buffer")

    # Create packet for buffer filling
    fill_packet = testutils.simple_udp_packet(
        eth_dst=duthost.facts["router_mac"],
        eth_src=DUMMY_MAC,
        ip_src=DUMMY_IP,
        ip_dst=dst_ipv4_addr,
        udp_sport=DEFAULT_SRC_PORT,
        udp_dport=DEFAULT_DST_PORT,
        ip_ttl=DEFAULT_TTL,
        ip_dscp=dscp_value,
        pktlen=fill_packet_size
    )

    # Send packets to fill the buffer in batches to avoid connection timeout
    ptfadapter.dataplane.flush()

    # Calculate number of batches
    num_batches = fill_packet_count // BATCH_PACKET_COUNT
    remaining_packets = fill_packet_count % BATCH_PACKET_COUNT

    total_sent_packets = 0
    max_retries = 10  # Maximum number of retries per batch

    # Send packets in batches
    logger.info(f"Sending packets in batches of {BATCH_PACKET_COUNT} packets each")

    batch_index = 0
    while batch_index < num_batches:
        retries = 0
        batch_success = False

        while not batch_success and retries < max_retries:
            try:
                logger.info(f"Sending batch {batch_index + 1}/{num_batches} ({BATCH_PACKET_COUNT} packets)")
                testutils.send(
                    ptfadapter,
                    port_id=port_id,
                    pkt=fill_packet,
                    count=BATCH_PACKET_COUNT
                )
                total_sent_packets += BATCH_PACKET_COUNT
                batch_success = True

            except Exception as e:
                retries += 1
                logger.warning(f"Batch {batch_index + 1} failed (attempt {retries}/{max_retries}): {e}")
                # Wait before retry
                time.sleep(2)

                # Flush dataplane to clear any pending data
                ptfadapter.dataplane.flush()

        # Increment batch index only if successful or we've exhausted retries
        batch_index += 1

    # Try to send remaining packets if there are any and we haven't already given up
    if remaining_packets > 0 and batch_index >= num_batches:
        try:
            logger.info(f"Sending remaining {remaining_packets} packets")
            testutils.send(
                ptfadapter,
                port_id=port_id,
                pkt=fill_packet,
                count=remaining_packets
            )
            total_sent_packets += remaining_packets
        except Exception as e:
            logger.warning(f"Failed to send remaining packets: {e}")
            # Not critical if we've already sent most packets

    logger.info(f"Buffer filling completed, sent {total_sent_packets} packets")

    # Check queue counters after filling
    for interface in interfaces:
        logger.info(f"Queue counters after filling for {interface}:")
        duthost.shell(f"show queue counters {interface}")

    return total_sent_packets


def verify_packet_trimming(duthost, ptfadapter, test_param, send_pkt_size, send_pkt_dscp, recv_pkt_size, recv_pkt_dscp,
                           packet_count=PACKET_COUNT, timeout=5, fill_buffer=True, expect_packets=True):
    """
    Verify packet trimming for all packet types with given parameters.

    Args:
        duthost: DUT host object
        ptfadapter: PTF adapter object
        test_param (dict): Test parameters containing:
            - dst_ipv4_addr: Destination IPv4 address
            - dst_ipv6_addr: Destination IPv6 address
            - downlink_port_ptf_id: Downlink port ID for sending packets
            - uplink_port_ptf_id: Uplink port ID(s) for receiving packets (integer or list)
            - uplink_port: List of uplink ports to apply trimming config
            - block_queue: Queue to block for triggering trimming
        send_pkt_size (int): Send packet size
        send_pkt_dscp (int): Send packet dscp
        recv_pkt_size (int): Expected packet size after trimming
        recv_pkt_dscp (int): Expected DSCP value in trimmed packets
        packet_count (int): Number of packets to send (default: 10)
        timeout (int): Timeout in seconds for packet verification (default: 5)
        fill_buffer (bool): Whether to fill buffer before testing trimming (default: True)
        expect_packets (bool): Whether to expect packets to be received (default: True)
                             If False, expects no packets to be received

    Returns:
        bool: True if all packet tests pass, False otherwise

    Raises:
        Exception: If packet verification fails
    """
    try:
        trimming_context = ConfigTrimming(
            duthost,
            test_param['uplink_port'],
            test_param['block_queue']
        )

        with trimming_context:
            # Fill the buffer first if requested
            if fill_buffer:
                # Get buffer configuration and size to calculate how many packets to send
                buffer_size = calculate_buffer_size_for_queue(
                    duthost,
                    test_param['uplink_port'],
                    test_param['block_queue']
                )

                # Fill buffer
                fill_egress_buffer(
                    duthost,
                    ptfadapter,
                    test_param['downlink_port_ptf_id'],
                    buffer_size,
                    test_param['block_queue'],
                    test_param['dst_ipv4_addr'],
                    send_pkt_dscp,
                    test_param['uplink_port']
                )

            # Test each packet type for trimming
            for packet_type in PACKET_TYPE:
                logger.info(f"Testing packet type: {packet_type}")

                # Get dst address
                dst_addr = (
                    test_param['dst_ipv4_addr'] if packet_type.startswith('ipv4') else test_param['dst_ipv6_addr'])

                # Generate packet
                pkt, exp_pkt = generate_packet(
                    duthost,
                    packet_type,
                    dst_addr,
                    send_pkt_size,
                    send_pkt_dscp,
                    recv_pkt_size,
                    recv_pkt_dscp
                )

                logger.info('Send packet format:\n ---------------------------')
                logger.info(f'{dump_packet_detail(pkt)}\n---------------------------')
                logger.info('Expect receive packet format:\n ---------------------------')
                logger.info(f'{dump_packet_detail(exp_pkt.exp_pkt)}\n---------------------------')

                # Flush data plane
                ptfadapter.dataplane.flush()

                # Send packet
                logger.info(f"Sending {packet_count} packets from port {test_param['downlink_port_ptf_id']}")
                testutils.send(
                    ptfadapter,
                    port_id=test_param['downlink_port_ptf_id'],
                    pkt=pkt,
                    count=packet_count
                )

                # Ensure uplink_port_ptf_id is in list format for ports parameter
                verify_ports = test_param['uplink_port_ptf_id']
                if not isinstance(verify_ports, list):
                    verify_ports = [verify_ports]

                # Verify packet based on expectation
                if expect_packets:
                    logger.info(
                        f"Expecting packets on ports {verify_ports} with size {recv_pkt_size} and DSCP {recv_pkt_dscp}")
                    testutils.verify_packet_any_port(
                        ptfadapter,
                        exp_pkt,
                        ports=verify_ports,
                        timeout=timeout
                    )
                    logger.info(
                        f"Successfully verified {packet_type} packet trimming with size {recv_pkt_size} "
                        f"and DSCP {recv_pkt_dscp}")
                else:
                    logger.info(f"Expecting NO packets on ports {verify_ports}")
                    testutils.verify_no_packet_any(
                        ptfadapter,
                        exp_pkt,
                        ports=verify_ports,
                        timeout=timeout
                    )
                    logger.info(f"Successfully verified NO {packet_type} packets were received as expected")

        return True

    except Exception as e:
        logger.error(f"Packet trimming verification failed: {str(e)}")
        raise


def verify_srv6_packet_with_trimming(duthost, ptfadapter, config_setup, test_param, send_pkt_size, send_pkt_dscp,
                                     recv_pkt_size, recv_pkt_dscp, fill_buffer=True):
    """
    Verify packet trimming for all packet types with given parameters.

    Args:
        duthost: DUT host object
        ptfadapter: PTF adapter object
        config_setup: config_setup
        test_param (dict): Test parameters containing:
            - dst_ipv4_addr: Destination IPv4 address
            - dst_ipv6_addr: Destination IPv6 address
            - downlink_port_ptf_id: Downlink port ID for sending packets
            - uplink_port_ptf_id: Uplink port ID(s) for receiving packets (integer or list)
            - uplink_port: List of uplink ports to apply trimming config
            - block_queue: Queue to block for triggering trimming
        send_pkt_size (int): Send packet size
        send_pkt_dscp (int): Send packet dscp
        recv_pkt_size (int): Expected packet size after trimming
        recv_pkt_dscp (int): Expected DSCP value in trimmed packets
        fill_buffer (bool): Whether to fill buffer before testing trimming (default: True)

    Returns:
        bool: True if all packet tests pass, False otherwise

    Raises:
        Exception: If packet verification fails
    """
    try:
        trimming_context = ConfigTrimming(
            duthost,
            test_param['uplink_port'],
            test_param['block_queue']
        )

        with trimming_context:
            # Fill the buffer first if requested
            if fill_buffer:
                # Get buffer configuration and size to calculate how many packets to send
                buffer_size = calculate_buffer_size_for_queue(
                    duthost,
                    test_param['uplink_port'],
                    test_param['block_queue']
                )

                # Fill buffer
                fill_egress_buffer(
                    duthost,
                    ptfadapter,
                    test_param['downlink_port_ptf_id'],
                    buffer_size,
                    test_param['block_queue'],
                    test_param['dst_ipv4_addr'],
                    send_pkt_dscp,
                    test_param['uplink_port']
                )

            validate_srv6_function(duthost, ptfadapter, config_setup, test_param, send_pkt_size, send_pkt_dscp,
                                   recv_pkt_size, recv_pkt_dscp)

    except Exception as e:
        logger.error(f"Packet trimming verification failed: {str(e)}")
        raise


def calculate_buffer_size_for_queue(duthost, interface, queue_id):
    """
    Calculate the approximate buffer size for a specific queue on an interface.

    Args:
        duthost: DUT host object
        interface (str): Interface name
        queue_id (str): Queue ID

    Returns:
        int: Approximate buffer size in bytes
    """
    try:
        # Get buffer profile for the queue
        cmd = f"redis-cli -n 4 HGET 'BUFFER_QUEUE|{interface}|{queue_id}' profile"
        result = duthost.shell(cmd)
        profile_name = result["stdout"].strip()
        logger.info(f"Queue {queue_id} on {interface} uses buffer profile: {profile_name}")

        # Get buffer profile details
        cmd = f"redis-cli -n 4 HGETALL 'BUFFER_PROFILE|{profile_name}'"
        result = duthost.shell(cmd)

        # Parse the profile details
        profile_details = {}
        lines = result["stdout"].strip().split("\n")
        for i in range(0, len(lines), 2):
            if i + 1 < len(lines):
                profile_details[lines[i]] = lines[i + 1]

        # Get buffer size from profile
        buffer_size = 0
        if "size" in profile_details:
            buffer_size = int(profile_details["size"])

        # Get pool name and its size
        if "pool" in profile_details:
            pool_name = profile_details["pool"]
            cmd = f"redis-cli -n 4 HGET 'BUFFER_POOL|{pool_name}' size"
            result = duthost.shell(cmd)
            pool_size = int(result["stdout"].strip())

            # If the profile has dynamic threshold, calculate maximum size
            if "dynamic_th" in profile_details:
                dynamic_th = profile_details["dynamic_th"]
                if dynamic_th == "7":
                    alpha = 64
                else:
                    alpha = 2 ** float(dynamic_th)

                # Simplified calculation assuming port_alpha=1
                buffer_scale = alpha / (alpha + 1)
                max_size = int(pool_size * buffer_scale)

                # Use the max_size if it's larger than the static size
                if max_size > buffer_size:
                    buffer_size = max_size

            # If we have no buffer size but have pool size, use a portion of pool
            if buffer_size == 0 and pool_size > 0:
                buffer_size = pool_size // 4  # Use 25% of pool as an estimate

        # If we still have no buffer size, use a default
        if buffer_size == 0:
            buffer_size = 1000000  # Default 1MB

        logger.info(f"Estimated buffer size for queue {queue_id} on {interface}: {buffer_size} bytes")
        return buffer_size

    except Exception as e:
        logger.warning(f"Error calculating buffer size: {str(e)}")
        return 1000000  # Default 1MB on error


class ConfigTrimming:
    """
    Context manager for blocking and restoring multiple egress ports.
    This is used to trigger packet trimming by blocking the egress queues.
    """

    def __init__(self, duthost, ports, queue):
        """
        Initialize the context manager.

        Args:
            duthost: DUT host object
            ports (list or str): List of port names or single port name
                               (e.g., ["Ethernet0", "Ethernet4"] or "Ethernet0")
            queue (int): Queue index
        """
        self.duthost = duthost
        self.ports = [ports] if isinstance(ports, str) else ports
        self.queue = queue
        # Store the original scheduler configuration for each port
        self.original_schedulers = {}

    def __enter__(self):
        """
        Block all specified egress ports by applying blocking scheduler.
        """
        try:
            for port in self.ports:
                logger.info(f"Blocking egress port {port} queue {self.queue}")
                original_scheduler = disable_egress_data_plane(self.duthost, port, self.queue)

                if not original_scheduler:
                    raise Exception(f"Failed to block egress port {port} queue {self.queue}")

                # Save the original scheduler configuration
                self.original_schedulers[port] = original_scheduler
                logger.info(f"Successfully blocked port {port} (original scheduler: {original_scheduler})")

            return self

        except Exception as e:
            logger.error(f"Failed to block egress ports: {e}")
            # Try to cleanup if setup fails
            self.__exit__(None, None, None)
            raise

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Restore original scheduler configuration for all ports when exiting the context.
        """
        restore_errors = []

        for port, original_scheduler in self.original_schedulers.items():
            try:
                if original_scheduler:
                    logger.info(f"Restoring original scheduler for port {port} queue {self.queue}")
                    enable_egress_data_plane(self.duthost, port, self.queue, original_scheduler)
                    logger.info(f"Successfully restored scheduler for port {port}")

            except Exception as e:
                error_msg = f"Exception while restoring port {port}: {str(e)}"
                logger.error(error_msg)
                restore_errors.append(error_msg)

        if restore_errors:
            raise Exception(f"Failed to restore some ports: {'; '.join(restore_errors)}")


def check_trimming_capability(duthost):
    """
    Check packet trimming capability in sai.profile.
    If the attribute is missing, add it and reload the configuration.

    Args:
        duthost: DUT host object

    Raises:
        RuntimeError: If any step in the check or update process fails
    """
    try:
        # Get platform and hwsku information
        platform = duthost.facts.get('platform')
        hwsku = duthost.facts.get('hwsku')

        if not platform or not hwsku:
            raise RuntimeError("Failed to get platform or hwsku information")

        # Construct SAI profile path
        sai_profile_path = f"/usr/share/sonic/device/{platform}/{hwsku}/sai.profile"
        logger.info(f"Checking SAI profile at: {sai_profile_path}")

        # Check if the file exists
        duthost.shell(f"ls {sai_profile_path}")

        # Check if configuration exists, if not add it
        # This uses shell || operator: if grep fails (left side), then execute right side
        cmd = (
            f"grep -q {TRIMMING_CAPABILITY} {sai_profile_path} || "
            f"(echo {TRIMMING_CAPABILITY} >> {sai_profile_path} && "
            f"echo 'added')"
        )
        result = duthost.shell(cmd)

        # If 'added' is in output, we added the configuration and need to reload
        if 'added' in result['stdout']:
            logger.info(f"Adding {TRIMMING_CAPABILITY} to SAI profile")

            # Reload configuration
            logger.info("Reloading configuration to apply changes...")
            config_reload(duthost, config_source='config_db', safe_reload=True)

            # Verify configuration was added
            duthost.shell(f"grep -q {TRIMMING_CAPABILITY} {sai_profile_path}")
            logger.info("SAI profile updated and configuration reloaded successfully")

        else:
            logger.info(f"Required configuration {TRIMMING_CAPABILITY} already exists in SAI profile")

    except Exception as e:
        if not isinstance(e, RuntimeError):
            error_msg = f"Exception occurred while checking/updating SAI profile: {str(e)}"
            logger.error(error_msg)
            raise RuntimeError(error_msg) from e
        raise


def configure_trimming_acl(duthost, test_ports):
    """
    Configure ACL rules for packet trimming tests with IPv4 and IPv6 support.
    Raises exceptions on failure instead of returning a status code.

    Args:
        duthost: DUT host object
        test_ports (list/str): Ports to apply ACL rules, can be a list or a single port name
    """
    logger.info(f"Configuring ACL rules for packet trimming with IPv4 and IPv6 support, ports: {test_ports}")

    # Ensure port list is in correct format (list of strings)
    if isinstance(test_ports, str):
        ports_list = [test_ports]
    else:
        ports_list = test_ports

    # Prepare ACL configuration with both IPv4 and IPv6 rules
    acl_config = {
        "ACL_RULE": {
            f"{ACL_TABLE_NAME}|{ACL_RULE_NAME}_ipv4": {
                "PACKET_ACTION": "DISABLE_TRIM",
                "PRIORITY": ACL_RULE_PRIORITY,
                "SRC_IP": f"{DUMMY_IP}/32"
            },
            f"{ACL_TABLE_NAME}|{ACL_RULE_NAME}_ipv6": {
                "PACKET_ACTION": "DISABLE_TRIM",
                "PRIORITY": ACL_RULE_PRIORITY,
                "SRC_IPV6": f"{DUMMY_IPV6}/128"
            }
        },
        "ACL_TABLE": {
            ACL_TABLE_NAME: {
                "policy_desc": "Packet trimming",
                "ports": ports_list,  # Using list format instead of comma-separated string
                "stage": "INGRESS",
                "type": ACL_TABLE_TYPE_NAME
            }
        },
        "ACL_TABLE_TYPE": {
            ACL_TABLE_TYPE_NAME: {
                "ACTIONS": [
                    "DISABLE_TRIM_ACTION"
                ],
                "BIND_POINTS": [
                    "PORT"
                ],
                "MATCHES": [
                    "SRC_IP",
                    "SRC_IPV6"
                ]
            }
        }
    }

    # Create temporary JSON file to store ACL configuration
    with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as temp_file:
        temp_file_path = temp_file.name
        json.dump(acl_config, temp_file, indent=4)

    # Copy JSON file to DUT
    dut_json_path = f"/tmp/acl_config_{ACL_TABLE_NAME}.json"
    duthost.copy(src=temp_file_path, dest=dut_json_path)

    # Remove temporary local file
    os.unlink(temp_file_path)

    # Apply ACL configuration
    logger.info(f"Applying ACL configuration: {dut_json_path}")
    duthost.shell(f"sonic-cfggen -w -j {dut_json_path}")

    # Verify ACL configuration
    logger.info("Verifying ACL configuration")
    result = duthost.shell("show acl table")
    logger.info(f"ACL tables:\n{result['stdout']}")

    result = duthost.shell("show acl rule")
    logger.info(f"ACL rules:\n{result['stdout']}")

    # Verify table was created successfully
    if ACL_TABLE_NAME not in result["stdout"]:
        raise RuntimeError(f"ACL table {ACL_TABLE_NAME} was not created successfully")

    # Verify both IPv4 and IPv6 rules were created
    if f"{ACL_RULE_NAME}_ipv4" not in result["stdout"] or f"{ACL_RULE_NAME}_ipv6" not in result["stdout"]:
        logger.warning("One or both IP rules may not have been created correctly")

    logger.info("ACL configuration with IPv4 and IPv6 rules applied successfully")


def cleanup_trimming_acl(duthost):
    """
    Clean up ACL rules for packet trimming tests using sonic-cfggen.
    Raises exceptions on failure instead of returning a status code.

    Args:
        duthost: DUT host object
    """
    logger.info(f"Cleaning up ACL rules for packet trimming, table: {ACL_TABLE_NAME}")

    # Delete ACL rules
    logger.info("Deleting ACL rules...")
    duthost.shell(f"sonic-db-cli CONFIG_DB DEL 'ACL_RULE|{ACL_TABLE_NAME}|{ACL_RULE_NAME}_ipv4'")
    duthost.shell(f"sonic-db-cli CONFIG_DB DEL 'ACL_RULE|{ACL_TABLE_NAME}|{ACL_RULE_NAME}_ipv6'")

    # Delete ACL table
    logger.info("Deleting ACL table...")
    duthost.shell(f"sonic-db-cli CONFIG_DB DEL 'ACL_TABLE|{ACL_TABLE_NAME}'")

    # Delete ACL table type
    logger.info(f"Deleting ACL table type {ACL_TABLE_TYPE_NAME}...")
    duthost.shell(f"sonic-db-cli CONFIG_DB DEL 'ACL_TABLE_TYPE|{ACL_TABLE_TYPE_NAME}'")

    # Show ACL table and rules for verification
    duthost.shell("show acl table")
    duthost.shell("show acl rule")

    logger.info("ACL rules cleanup completed successfully")


def set_buffer_profiles_for_block_and_trim_queues(duthost, interfaces, block_queue_id,
                                                  block_queue_profile=BLOCK_QUEUE_PROFILE, trim_queue_id=TRIM_QUEUE,
                                                  trim_queue_profile=TRIM_QUEUE_PROFILE):
    """
    Set buffer profiles for blocked queue and forward trimming packet queue.

    Args:
        duthost: DUT host object
        interfaces (list or str): Port names to configure, can be a list or single string
        block_queue_id: Queue index used for blocking traffic
        block_queue_profile (str): Buffer profile name to apply for blocking queue (default: BLOCK_QUEUE_PROFILE)
        trim_queue_id (int): Queue index used for packet trimming (default: TRIM_QUEUE)
        trim_queue_profile (str): Buffer profile name to apply for trimming queue (default: TRIM_QUEUE_PROFILE)

    Raises:
        RuntimeError: If any interface fails to be configured with the specified profiles
    """
    # Convert queue indices to string for Redis commands
    block_queue_id = str(block_queue_id)
    trim_queue_id = str(trim_queue_id)

    logger.info(f"Setting blocking queue ({block_queue_id}) buffer profile to '{block_queue_profile}' and "
                f"trimming queue ({trim_queue_id}) buffer profile to '{trim_queue_profile}', ports: {interfaces}")

    # Convert single interface to list
    if isinstance(interfaces, str):
        interfaces = [interfaces]

    for interface in interfaces:
        try:
            # Set buffer profile for the blocking queue
            block_cmd = f"redis-cli -n 4 hset 'BUFFER_QUEUE|{interface}|{block_queue_id}' profile {block_queue_profile}"
            duthost.shell(block_cmd)

            logger.info(
                f"Successfully set interface {interface} blocking queue {block_queue_id} "
                f"profile to {block_queue_profile}")

            # Set buffer profile for the trimming queue
            trim_cmd = f"redis-cli -n 4 hset 'BUFFER_QUEUE|{interface}|{trim_queue_id}' profile {trim_queue_profile}"
            duthost.shell(trim_cmd)

            logger.info(
                f"Successfully set interface {interface} trimming queue {trim_queue_id} "
                f"profile to {trim_queue_profile}")

        except Exception as e:
            if not isinstance(e, RuntimeError):
                raise RuntimeError(f"Exception while configuring interface {interface} queues: {str(e)}") from e
            raise


def prepare_service_port(duthost, service_port):
    """
    Prepare service port for packet trimming tests by checking existence,
    ensuring admin status is UP, and updating buffer configuration.

    Args:
        duthost: DUT host object
        service_port (str): Service port name

    Raises:
        RuntimeError: If service port does not exist or cannot be configured
    """
    logger.info(f"Preparing service port {service_port} for packet trimming tests")

    # Check if service port exists
    intfs_status = duthost.get_interfaces_status()
    if not intfs_status.get(service_port):
        pytest.fail("No service port exist")
    logger.info(f"Service port {service_port} exist")

    # Check if service port admin status is UP, if not, set admin status UP and update configurations
    if intfs_status[service_port]["admin"].upper() != "UP":
        logger.info(f"Service port {service_port} is not UP, configuring it")
        duthost.shell(f'config interface startup {service_port}')
    else:
        logger.info(f"Service port {service_port} is already UP, skipping configuration updates")

    # Update service port buffer configuration
    logger.info(f"Updating buffer configuration for {service_port}")
    update_service_port_buffer_profile(duthost, service_port)

    # Update service port QoS map configuration
    logger.info(f"Updating QoS map configuration for {service_port}")
    update_service_port_qos_map(duthost, service_port)

    logger.info(f"Service port {service_port} preparation completed successfully")


def update_service_port_buffer_profile(duthost, service_port):
    """
    Update service port buffer configuration.

    This function updates the buffer configuration for the service port by applying
    a specific buffer profile to its priority group and ingress profile list.

    Args:
        service_port:
        duthost: DUT host object

    Raises:
        RuntimeError: If configuration fails
    """
    logger.info(f"Updating buffer configuration for service port {service_port}")

    # Prepare buffer configuration for the service port
    buffer_config = {
        "BUFFER_PG": {
            f"{service_port}|0": {
                "profile": "ingress_lossy_profile"
            }
        },
        "BUFFER_PORT_INGRESS_PROFILE_LIST": {
            service_port: {
                "profile_list": "ingress_lossy_profile"
            }
        },
        "BUFFER_PORT_EGRESS_PROFILE_LIST": {
            service_port: {
                "profile_list": "egress_lossy_profile"
            }
        },
        "BUFFER_QUEUE": {
            f"{service_port}|1-6": {
                "profile": "egress_lossy_profile"
            }
        }
    }

    # Create temporary JSON file
    with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as temp_file:
        temp_file_path = temp_file.name
        json.dump(buffer_config, temp_file, indent=4)

    # Copy the JSON file to DUT
    dut_json_path = "/tmp/update_service_port.json"
    duthost.copy(src=temp_file_path, dest=dut_json_path)

    # Remove temporary file from local system
    os.unlink(temp_file_path)

    # Apply buffer configuration using sonic-cfggen
    logger.info("Applying service port buffer configuration")
    duthost.shell(f"sonic-cfggen -w -j {dut_json_path}")

    # Verify buffer configuration
    logger.info("Verifying buffer configuration")
    result = duthost.shell(f"redis-cli -n 4 HGETALL 'BUFFER_PG|{service_port}|0'")
    logger.info(f"BUFFER_PG|{service_port}|0 configuration:\n{result['stdout']}")

    result = duthost.shell(f"redis-cli -n 4 HGETALL 'BUFFER_PORT_INGRESS_PROFILE_LIST|{service_port}'")
    logger.info(f"BUFFER_PORT_INGRESS_PROFILE_LIST|{service_port} configuration:\n{result['stdout']}")

    if "ingress_lossy_profile" not in result["stdout"]:
        raise RuntimeError(f"Buffer configuration for {service_port} was not applied successfully")

    logger.info(f"Service port {service_port} buffer configuration updated successfully")


def update_service_port_qos_map(duthost, service_port):
    """
    Update QoS map configuration for the service port.

    Args:
        duthost: DUT host object
        service_port (str): Service port name to configure

    Raises:
        RuntimeError: If configuration fails
    """
    logger.info(f"Updating QoS map configuration for service port {service_port}")

    # Prepare QoS map configuration for the service port
    qos_map_config = {
        "PORT_QOS_MAP": {
            service_port: {
                "dscp_to_tc_map": "AZURE",
                "pfc_enable": "",
                "pfc_to_pg_map": "AZURE",
                "pfc_to_queue_map": "AZURE",
                "pfcwd_sw_enable": "",
                "tc_to_pg_map": "AZURE",
                "tc_to_queue_map": "AZURE"
            }
        }
    }

    # Create temporary JSON file
    with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as temp_file:
        temp_file_path = temp_file.name
        json.dump(qos_map_config, temp_file, indent=4)

    # Copy the JSON file to DUT
    dut_json_path = "/tmp/qos_map_service_port.json"
    duthost.copy(src=temp_file_path, dest=dut_json_path)

    # Remove temporary file from local system
    os.unlink(temp_file_path)

    # Apply QoS map configuration using sonic-cfggen
    logger.info("Applying service port QoS map configuration")
    duthost.shell(f"sonic-cfggen -w -j {dut_json_path}")

    # Verify QoS map configuration
    logger.info("Verifying QoS map configuration")
    result = duthost.shell(f"redis-cli -n 4 HGETALL 'PORT_QOS_MAP|{service_port}'")
    logger.info(f"PORT_QOS_MAP|{service_port} configuration:\n{result['stdout']}")

    if "AZURE" not in result["stdout"]:
        raise RuntimeError(f"QoS map configuration for {service_port} was not applied successfully")

    logger.info(f"Service port {service_port} QoS map configuration updated successfully")


def get_test_ports(upstream_links, downstream_links):
    """
    This function selects the first interface from upstream_links as uplink_port and
    the first interface from downstream_links as downlink_port.

    Args:
        upstream_links (dict): Dictionary of upstream links with interfaces as keys
        downstream_links (dict): Dictionary of downstream links with interfaces as keys

    Returns:
        tuple: (uplink_port, downlink_port)
              A tuple containing two dictionaries, each with a single key-value pair:
              - uplink_port: Dictionary with one interface from upstream_links
              - downlink_port: Dictionary with one interface from downstream_links

    Example:
        uplink_port:
        {'Ethernet96': {'name': 'ARISTA01T2', 'ptf_port_id': 48, 'local_ipv4_addr': '10.0.0.97',
                         'peer_ipv4_addr': '10.0.0.96', 'upstream_port': 'Ethernet1', 'host': <EosHost VM3807>}}

        downlink_port:
        {'Ethernet192': {'name': 'ARISTA81T0', 'ptf_port_id': 84, 'downstream_port': 'Ethernet1'}}
    """
    logger.info("Selecting the first interface from downstream and upstream links as test ports")
    logger.info(f"upstream_links: {upstream_links}")
    logger.info(f"downstream_links: {downstream_links}")

    # Get the first upstream link
    first_key_upstream = list(upstream_links.keys())[0]
    uplink_port = {first_key_upstream: upstream_links[first_key_upstream]}
    logger.info(f"Selected uplink port: {uplink_port}")

    # Get the first downstream link
    first_key_downstream = list(downstream_links.keys())[0]
    downlink_port = {first_key_downstream: downstream_links[first_key_downstream]}
    logger.info(f"Selected downlink port: {downlink_port}")

    return uplink_port, downlink_port


def get_interface_peer_addresses(mg_facts, interface_name):
    """
    Get IPv4 and IPv6 peer addresses of a specified interface from minigraph facts.

    Args:
        mg_facts (dict): Minigraph facts dictionary containing minigraph_interfaces
        interface_name (str): Interface name (e.g., "Ethernet96")

    Returns:
        tuple: (ipv4_peer_addr, ipv6_peer_addr)
              IPv4 and IPv6 peer addresses of the interface
              May return (None, None) if no peer addresses are found for the interface

    Note:
        This function assumes mg_facts contains valid 'minigraph_interfaces' data.
        It identifies IPv4 and IPv6 addresses by examining the IP version.
    """
    ipv4_peer_addr = None
    ipv6_peer_addr = None

    for interface in mg_facts['minigraph_interfaces']:
        if interface.get('attachto') == interface_name:
            # Check if this is an IPv4 or IPv6 address
            if 'peer_addr' in interface:
                # Create IP address object to determine version
                ip = ipaddress.ip_address(interface['peer_addr'])

                if ip.version == 4:
                    ipv4_peer_addr = interface['peer_addr']
                    logger.info(f"Found IPv4 peer address for {interface_name}: {ipv4_peer_addr}")
                elif ip.version == 6:
                    ipv6_peer_addr = interface['peer_addr']
                    logger.info(f"Found IPv6 peer address for {interface_name}: {ipv6_peer_addr}")

    if not ipv4_peer_addr and not ipv6_peer_addr:
        logger.warning(f"No peer addresses found for interface {interface_name}")

    return ipv4_peer_addr, ipv6_peer_addr


def validate_srv6_function(duthost, ptfadapter, dscp_mode, test_param, send_pkt_size, send_pkt_dscp, recv_pkt_size,
                           recv_pkt_dscp):
    """
    Validate SRv6 functionality

    Args:
        duthost: DUT host object
        ptfadapter: PTF adapter object
        dscp_mode (str): DSCP mode ('pipe' or 'uniform')
        test_param (dict): Test parameters dictionary containing interface and port information
        send_pkt_size (int): Size of the packet to send
        send_pkt_dscp (int): DSCP value of the packet to send
        recv_pkt_size (int): Expected size of the received packet after trimming
        recv_pkt_dscp (int): Expected DSCP value in the received packet
    """
    logger.info('Validate SRv6 table in APPL DB')
    for entry in SRV6_MY_SID_LIST:
        prefix = entry[1]
        duthost.shell(f'sonic-db-cli APPL_DB HGET "SRV6_MY_SID_TABLE:32:16:0:0:{prefix}" action')

    router_mac = duthost.facts["router_mac"]

    for srv6_packet in SRV6_PACKETS:
        logger.info('-------------------------------------------------------------------------')
        logger.info(f'SRv6 tunnel decapsulation mode: {dscp_mode}')
        logger.info(f'Send {PACKET_COUNT} SRv6 packets with action: {srv6_packet["action"]}')
        logger.info(f'Pkt Src MAC: {DUMMY_MAC}')
        logger.info(f'Pkt Dst MAC: {router_mac}')
        if srv6_packet['action'] == SRV6_UN:
            logger.info(f'Outer Pkt Src IP: {SRV6_INNER_DST_IPV6}')
            logger.info(f'Outer Pkt Dst IP: {srv6_packet["dst_ipv6"]}')
            if srv6_packet["exp_dst_ipv6"]:
                logger.info(f'Expect Outer Pkt Dst IP: {srv6_packet["exp_dst_ipv6"]}')
        if dscp_mode == SRV6_UNIFORM_MODE:
            if srv6_packet['outer_dscp']:
                logger.info(f'Outer DSCP value: {srv6_packet["outer_dscp"]}')
            if srv6_packet['exp_outer_dscp_uniform']:
                logger.info(f'Expect inner DSCP value: {srv6_packet["exp_outer_dscp_uniform"]}')
        else:
            if srv6_packet['inner_dscp']:
                logger.info(f'Inner DSCP value: {srv6_packet["inner_dscp"]}')
            if srv6_packet['exp_inner_dscp_pipe']:
                logger.info(f'Expect inner DSCP value: {srv6_packet["exp_inner_dscp_pipe"]}')
        logger.info(f'SRH Segment List: {srv6_packet["srh_seg_list"]}')
        logger.info(f'SRH Segment Left: {srv6_packet["srh_seg_left"]}')

        logger.info(f'Expect Segment Left: {srv6_packet["exp_srh_seg_left"]}')
        logger.info(f'Expect process result: {srv6_packet["exp_process_result"]}')
        logger.info('-------------------------------------------------------------------------')

        # Determine the IPv6 header length based on whether SRH (Segment Routing Header) is present
        if not srv6_packet['srh_seg_list']:
            # SRv6 packet without SRH
            ipv6_header_len = 40
        else:
            # SRv6 packet with SRH
            ipv6_header_len = 80

        # - SRv6 packet without SRH: IPv6 (40) + IPv4 (20) + UDP (8) + Payload = 256
        # - SRv6 packet with SRH: IPv6 (40) + SRH (40) + IPv4 (20) + UDP (8) + Payload = 256
        actual_recv_pkt_size = recv_pkt_size - ipv6_header_len

        srv6_pkt, exp_pkt = create_srv6_packet_for_trimming(
            outer_src_mac=DUMMY_MAC,
            outer_dst_mac=router_mac,
            outer_src_pkt_ip=SRV6_OUTER_SRC_IPV6,
            outer_dst_pkt_ip=srv6_packet['dst_ipv6'],
            srv6_action=srv6_packet['action'],
            inner_dscp=srv6_packet['inner_dscp'],
            outer_dscp=send_pkt_dscp,
            exp_outer_dst_pkt_ip=srv6_packet['exp_dst_ipv6'],
            exp_seg_left=srv6_packet['exp_srh_seg_left'],
            exp_inner_dscp=srv6_packet['inner_dscp'],
            exp_outer_dscp=recv_pkt_dscp,
            seg_left=srv6_packet['srh_seg_left'],
            sef_list=srv6_packet['srh_seg_list'],
            inner_pkt_ver=srv6_packet['inner_pkt_ver'],
            dscp_mode=dscp_mode,
            router_mac=router_mac,
            inner_src_ip=SRV6_INNER_SRC_IP,
            inner_dst_ip=SRV6_INNER_DST_IP,
            inner_src_ipv6=SRV6_INNER_SRC_IPV6,
            inner_dst_ipv6=SRV6_INNER_DST_IPV6,
            pkt_len=send_pkt_size,
            exp_pkt_len=actual_recv_pkt_size
        )

        # Ensure uplink_port_ptf_id is in list format for ports parameter
        verify_ports = test_param['uplink_port_ptf_id']
        if not isinstance(verify_ports, list):
            verify_ports = [verify_ports]

        send_verify_srv6_packet_for_trimming(
            ptfadapter=ptfadapter,
            pkt=srv6_pkt,
            exp_pkt=exp_pkt,
            exp_pro=srv6_packet["exp_process_result"],
            ptf_src_port_id=test_param['downlink_port_ptf_id'],
            ptf_dst_port_ids=verify_ports,
            packet_num=PACKET_COUNT
        )


def create_srv6_packet_for_trimming(
        outer_src_mac,
        outer_dst_mac,
        outer_src_pkt_ip,
        outer_dst_pkt_ip,
        srv6_action,
        inner_dscp,
        outer_dscp,
        exp_outer_dst_pkt_ip,
        exp_seg_left,
        exp_inner_dscp,
        exp_outer_dscp,
        seg_left,
        sef_list,
        inner_pkt_ver,
        dscp_mode,
        router_mac,
        inner_src_ip,
        inner_dst_ip,
        inner_src_ipv6,
        inner_dst_ipv6,
        pkt_len,
        exp_pkt_len):
    """
    Create SRv6 packets for testing

    Args:
        outer_src_mac (str): Outer source MAC address
        outer_dst_mac (str): Outer destination MAC address
        outer_src_pkt_ip (str): Outer source IP address
        outer_dst_pkt_ip (str): Outer destination IP address
        srv6_action (str): SRv6 action type
        inner_dscp (int): Inner DSCP value
        outer_dscp (int): Outer DSCP value
        exp_outer_dst_pkt_ip (str): Expected outer destination IP address
        exp_seg_left (int): Expected segment left value
        exp_inner_dscp (int): Expected inner DSCP value
        exp_outer_dscp (int): Expected outer DSCP value
        seg_left (int): Segment left value
        sef_list (list): Segment list
        inner_pkt_ver (str): Inner packet version ('4' for IPv4, '6' for IPv6)
        dscp_mode (str): DSCP mode ('pipe' or 'uniform')
        router_mac (str): Router MAC address
        inner_src_ip (str): Inner source IPv4 address
        inner_dst_ip (str): Inner destination IPv4 address
        inner_src_ipv6 (str): Inner source IPv6 address
        inner_dst_ipv6 (str): Inner destination IPv6 address
        pkt_len (int): Packet length
        exp_pkt_len (int): Expected packet length

    Returns:
        tuple: (srv6_pkt, exp_pkt) - Created SRv6 packet and expected packet
    """

    srv6_next_header = {
        scapy.IP: 4,
        scapy.IPv6: 41
    }

    if inner_pkt_ver == '4':
        inner_pkt = testutils.simple_udp_packet(
            eth_src=router_mac,
            ip_src=inner_src_ip,
            ip_dst=inner_dst_ip,
            ip_dscp=inner_dscp if inner_dscp else 0,
            pktlen=pkt_len
        )

        exp_inner_pkt = testutils.simple_udp_packet(
            eth_src=router_mac,
            ip_src=inner_src_ip,
            ip_dst=inner_dst_ip,
            ip_dscp=exp_inner_dscp,
            pktlen=exp_pkt_len
        )
        scapy_ver = scapy.IP

    else:
        inner_pkt = testutils.simple_udpv6_packet(
            eth_src=router_mac,
            ipv6_src=inner_src_ipv6,
            ipv6_dst=inner_dst_ipv6,
            ipv6_dscp=inner_dscp if inner_dscp else 0,
            pktlen=pkt_len
        )

        exp_inner_pkt = testutils.simple_udpv6_packet(
            eth_src=router_mac,
            ipv6_src=inner_src_ipv6,
            ipv6_dst=inner_dst_ipv6,
            ipv6_dscp=exp_inner_dscp,
            pktlen=exp_pkt_len
        )
        scapy_ver = scapy.IPv6

    if srv6_action == SRV6_UN:
        if exp_outer_dst_pkt_ip:
            if seg_left or sef_list:
                logger.info('Create SRv6 packets with SRH')
                srv6_pkt = testutils.simple_ipv6_sr_packet(
                    eth_dst=outer_dst_mac,
                    eth_src=outer_src_mac,
                    ipv6_src=outer_src_pkt_ip,
                    ipv6_dst=outer_dst_pkt_ip,
                    srh_seg_left=seg_left,
                    srh_seg_list=sef_list,
                    ipv6_tc=outer_dscp * 4 if outer_dscp else 0,
                    srh_nh=srv6_next_header[scapy_ver],
                    inner_frame=inner_pkt[scapy_ver],
                )
                exp_pkt = testutils.simple_ipv6_sr_packet(
                    eth_dst=outer_dst_mac,
                    eth_src=outer_src_mac,
                    ipv6_src=outer_src_pkt_ip,
                    ipv6_dst=exp_outer_dst_pkt_ip,
                    srh_seg_left=exp_seg_left,
                    srh_seg_list=sef_list,
                    ipv6_tc=exp_outer_dscp * 4,
                    srh_nh=srv6_next_header[scapy_ver],
                    inner_frame=exp_inner_pkt[scapy_ver],
                )
            else:
                logger.info('Create SRv6 packet with reduced SRH(no SRH header)')
                srv6_pkt = testutils.simple_ipv6ip_packet(
                    eth_dst=outer_dst_mac,
                    eth_src=outer_src_mac,
                    ipv6_src=outer_src_pkt_ip,
                    ipv6_dst=outer_dst_pkt_ip,
                    ipv6_tc=outer_dscp * 4 if outer_dscp else 0,
                    inner_frame=inner_pkt[scapy_ver],
                )
                exp_pkt = testutils.simple_ipv6ip_packet(
                    eth_dst=outer_dst_mac,
                    eth_src=outer_src_mac,
                    ipv6_src=outer_src_pkt_ip,
                    ipv6_dst=exp_outer_dst_pkt_ip,
                    ipv6_tc=exp_outer_dscp * 4,
                    inner_frame=exp_inner_pkt[scapy_ver],
                )

            exp_pkt['IPv6'].hlim -= 1
            exp_pkt = Mask(exp_pkt)

            logger.info('Do not care packet ethernet destination address')
            exp_pkt.set_do_not_care_packet(scapy.Ether, 'dst')
            logger.info('Do not care packet ethernet source address')
            exp_pkt.set_do_not_care_packet(scapy.Ether, 'src')

        else:
            if seg_left or sef_list:
                logger.info('Create SRv6 packets with SRH for USD flavor validation')
                srv6_pkt = testutils.simple_ipv6_sr_packet(
                    eth_dst=outer_dst_mac,
                    eth_src=outer_src_mac,
                    ipv6_src=outer_src_pkt_ip,
                    ipv6_dst=outer_dst_pkt_ip,
                    srh_seg_left=seg_left,
                    srh_seg_list=sef_list,
                    ipv6_tc=outer_dscp * 4 if outer_dscp else 0,
                    srh_nh=srv6_next_header[scapy_ver],
                    inner_frame=inner_pkt[scapy_ver],
                )
            else:
                logger.info('Create SRv6 packets without SRH for USD flavor validation')
                srv6_pkt = testutils.simple_ipv6ip_packet(
                    eth_dst=outer_dst_mac,
                    eth_src=outer_src_mac,
                    ipv6_src=outer_src_pkt_ip,
                    ipv6_dst=outer_dst_pkt_ip,
                    ipv6_tc=outer_dscp * 4 if outer_dscp else 0,
                    inner_frame=inner_pkt[scapy_ver],
                )

            if inner_pkt_ver == '4':
                exp_inner_pkt['IP'].ttl -= 1
                exp_pkt = Mask(exp_inner_pkt)
                logger.info('Do not care packet checksum')
                exp_pkt.set_do_not_care_packet(scapy.IP, "chksum")
            else:
                exp_inner_pkt['IPv6'].hlim -= 1
                exp_pkt = Mask(exp_inner_pkt)
            logger.info('Do not care packet ethernet destination address')
            exp_pkt.set_do_not_care_packet(scapy.Ether, 'dst')

        exp_pkt.set_do_not_care_packet(scapy.IPv6, "plen")
        exp_pkt.set_do_not_care_packet(scapy.IP, "chksum")
        exp_pkt.set_do_not_care_packet(scapy.IP, "len")
        exp_pkt.set_do_not_care_packet(scapy.UDP, "chksum")
        exp_pkt.set_do_not_care_packet(scapy.UDP, "len")

    return srv6_pkt, exp_pkt


def send_verify_srv6_packet_for_trimming(
        ptfadapter,
        pkt,
        exp_pkt,
        exp_pro,
        ptf_src_port_id,
        ptf_dst_port_ids,
        packet_num=10):
    """
    Send and verify SRv6 packets

    Args:
        ptfadapter: PTF adapter object
        pkt: Packet to send
        exp_pkt: Expected packet
        exp_pro (str): Expected process result ('forward' or 'drop')
        ptf_src_port_id (int): Source PTF port ID
        ptf_dst_port_ids (list): List of destination PTF port IDs
        packet_num (int): Number of packets to send (default: 10)
    """
    ptfadapter.dataplane.flush()
    logger.info(f'Send SRv6 packet(s) from PTF port {ptf_src_port_id} to upstream')
    testutils.send(ptfadapter, ptf_src_port_id, pkt, count=packet_num)
    logger.info('SRv6 packet format:\n ---------------------------')
    logger.info(f'{dump_packet_detail(pkt)}\n---------------------------')
    logger.info('Expect receive SRv6 packet format:\n ---------------------------')
    logger.info(f'{dump_packet_detail(exp_pkt.exp_pkt)}\n---------------------------')

    try:
        if exp_pro == 'forward':
            port_index, _ = testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=ptf_dst_port_ids)
            logger.info(f'Received packet(s) on port {ptf_dst_port_ids[port_index]}\n')
        elif exp_pro == 'drop':
            testutils.verify_no_packet_any(ptfadapter, exp_pkt, ports=ptf_dst_port_ids)
            logger.info(f'No packet received on {ptf_dst_port_ids}')
        else:
            logger.error(f'Wrong expected process result: {exp_pro}')
    except AssertionError as detail:
        raise detail


def reboot_dut(duthost, localhost, reboot_type):
    """
    Perform a reboot operation based on the specified type

    Args:
        duthost: DUT host object
        localhost: localhost object
        reboot_type: Type of reboot to perform. Options: 'reload' or 'cold'
    """
    # Perform the selected reboot
    if reboot_type == "reload":
        logger.info('Performing config reload')
        config_reload(duthost, safe_reload=True, check_intf_up_ports=True)
    else:  # cold reboot
        logger.info('Performing cold reboot')
        reboot(duthost, localhost, reboot_type=reboot_type, wait_warmboot_finalizer=True,
               safe_reboot=True, check_intf_up_ports=True, wait_for_bgp=True)
