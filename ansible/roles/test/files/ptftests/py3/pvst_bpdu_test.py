"""
PVST BPDU Test Script for SONiC

This script provides functionality to send Per-VLAN Spanning Tree (PVST) BPDU packets
for testing spanning tree protocol behavior on SONiC switches.

Usage:
    /usr/local/bin/ptf --test-dir ptftests/py3 pvst_bpdu_test.PvstBpduTest --platform remote \
     --log-file /tmp/pvst_bpdu_test.log --platform-dir ptftests -t '\
     send_port=[1,2];test_scenarios="config";vlan_id=1000;'

    /usr/local/bin/ptf --test-dir ptftests/py3 pvst_bpdu_test_san.PvstBpduTest --platform \
        remote --log-file /tmp/pvst_bpdu_test.log --platform-dir ptftests -t 'vlan_id=100; \
            bridge_priority=4096;bridge_mac="00:11:22:33:44:55";root_priority=4096;send_port=[1,2];\
                test_scenarios="config";hello_time=5;forward_delay=22;max_age=5;\
                message_age=8;root_mac="33:33:33:33:44:44";port_priority=240'

    /usr/local/bin/ptf --test-dir ptftests/py3 pvst_bpdu_test.PvstBpduTest --platform remote \
        --log-file /tmp/pvst_timer_validation.log --platform-dir ptftests \
            -t 'test_scenarios="validate_timers";vlan_id=1000;capture_port=1;expected_hello_time=5\
            ;expected_max_age=25;expected_forward_delay=20; \
                capture_duration=30;send_port=[1,2]'

    /usr/local/bin/ptf --test-dir ptftests/py3 pvst_bpdu_test.PvstBpduTest --platform remote \
    --log-file /tmp/pvst_backup_port_validation.log --platform-dir ptftests \
        -t 'test_scenarios="validate_backup_port";vlan_id=1000;capture_port=1;\
        replay_port=2;replay_delay=1;replay_all_bpdus=True; \
            capture_duration=30;'

    /usr/local/bin/ptf --test-dir ptftests/py3 pvst_bpdu_test.PvstBpduTest --platform remote \
    --log-file /tmp/pvst_path_cost_validation.log --platform-dir ptftests \
        -t 'test_scenarios="validate_path_cost";vlan_id=1000;capture_port=2;expected_root_path_cost=20000; \
            capture_duration=15;'

    /usr/local/bin/ptf --test-dir ptftests/py3 pvst_bpdu_test.PvstBpduTest --platform remote \
     --log-file /tmp/pvst_bridge_id_validation.log --platform-dir ptftests \
         -t 'test_scenarios="validate_root_bridge_id";vlan_id=1000;capture_port=2;\
         bridge_mac="33:33:33:33:44:44";bridge_priority=8192; \
             capture_duration=15;'

    /usr/local/bin/ptf --test-dir ptftests/py3 pvst_bpdu_test.PvstBpduTest --platform remote \
     --log-file /tmp/pvst_bridge_id_validation.log --platform-dir ptftests \
         -t 'test_scenarios="validate_bpdu_packet";vlan_id=1000;capture_port=1;\
         bridge_mac="33:33:33:33:44:44";bridge_priority=32768,expected_hello_time=5;\
         expected_max_age=25;expected_forward_delay=20; \
             capture_duration=15;'

   /usr/local/bin/ptf --test-dir ptftests/py3 pvst_bpdu_test.PvstBpduTest --platform remote  \
    --log-file /tmp/pvst_send_l2_packet.log --platform-dir ptftests  -t 'test_scenarios="validate_l2_packet"; \
         vlan_id=1000;send_port=1;receive_port=2;'


"""

import logging
import time
import struct
import random   # noqa: F401
from collections import defaultdict   # noqa: F401
import ptf
import ptf.packet as scapy   # noqa: F401
import ptf.testutils as testutils
from scapy.all import Raw, Dot1Q, Ether, ARP, hexdump, LLC, SNAP   # noqa: F401
from ptf.base_tests import BaseTest
from ptf.mask import Mask
from ptf.testutils import test_params_get
from ptf.testutils import send_packet   # noqa: F401
from ptf.testutils import verify_packet_any_port
from threading import Thread
import scapy.all as scapy2


class PvstBpduTest(BaseTest):

    """
    @summary: PVST BPDU Test Class

    This test class provides functionality to generate and send various types of
    PVST BPDU packets for testing spanning tree protocol behavior.

    Supported BPDU types:
    - Configuration BPDU
    - Topology Change Notification (TCN) BPDU
    - PVST+ BPDU with VLAN information
    """

    # Default BPDU parameters
    DEFAULT_ROOT_PRIORITY = 32768
    DEFAULT_BRIDGE_PRIORITY = 32768
    DEFAULT_BRIDGE_MAC = "00:01:02:03:04:05"
    DEFAULT_VLAN_ID = 1000
    DEFAULT_HELLO_TIME = 0x02
    DEFAULT_MAX_AGE = 0x14
    DEFAULT_FORWARD_DELAY = 0x0F
    DEFAULT_PORT_PRIORITY = 0x80
    DEFAULT_MESSAGE_AGE = 0
    DEFAULT_ROOT_PATH_COST = 0

    # LLC HEADER
    LLC_SNAP_DSAP = 0xaa
    LLC_SNAP_SSAP = 0xaa
    LLC_SNAP_FRAME = 0x03
    LLC_SNAP_OUI = 0x00000c
    LLC_SNAP_PROTO_ID = 0x010b

    # BPDU constants
    BPDU_SRC_MAC = DEFAULT_BRIDGE_MAC
    BPDU_DST_MAC = "01:00:0c:cc:cc:cd"
    BPDU_PROTOCOL_ID = 0x0000
    BPDU_VERSION = 0x00
    BPDU_TYPE_CONFIG = 0x00
    BPDU_TYPE_TCN = 0x80
    BPDU_FLAGS_TC = 0x01
    BPDU_FLAGS_TC_ACK = 0x80

    BPDU_LEN = 0x0032

    # VLAN tag
    ORIG_VLAN = 0x0000
    ORIG_VLAN_LEN = 0x0002

    def __init__(self):
        """
        @summary: Constructor
        """
        BaseTest.__init__(self)

        # Initialize default parameters
        self.captured_bpdus = []
        self.capture_thread = None
        self.capture_timeout = 30

        # Logging setup
        self.logger = logging.getLogger(__name__)

    def setUp(self):
        """
        @summary: Setup for the test
        """
        self.test_params = test_params_get()
        self.dataplane = ptf.dataplane_instance
        self.logger.info("Setting up PVST BPDU test")

    def create_bpdu_header(self, bpdu_type='config'):
        """
        @summary: Create BPDU header based on type
        @param bpdu_type: Type of BPDU ('config' or 'tcn')
        @return: BPDU header bytes
        """
        llc_header = struct.pack('!BBB',
                                 self.LLC_SNAP_DSAP,
                                 self.LLC_SNAP_SSAP,
                                 self.LLC_SNAP_FRAME)
        llc_header += self.LLC_SNAP_OUI.to_bytes(3, 'big')
        llc_header += struct.pack('!H', self.LLC_SNAP_PROTO_ID)

        if bpdu_type == 'config':
            # Configuration BPDU header
            header = struct.pack('!HBB',
                                 self.BPDU_PROTOCOL_ID,  # Protocol ID
                                 self.BPDU_VERSION,      # Version
                                 self.BPDU_TYPE_CONFIG)   # BPDU Type
        elif bpdu_type == 'tcn':
            # TCN BPDU header
            header = struct.pack('!HBB',
                                 self.BPDU_PROTOCOL_ID,  # Protocol ID
                                 self.BPDU_VERSION,      # Version
                                 self.BPDU_TYPE_TCN)      # BPDU Type

        else:
            raise ValueError(f"Unsupported BPDU type: {bpdu_type}")

        return llc_header + header

    def create_config_bpdu_payload(self):
        """
        @summary: Create Configuration BPDU payload
        @return: Configuration BPDU payload bytes
        """

        # Use defaults if not specified
        root_priority = self.test_params.get('root_priority', self.DEFAULT_ROOT_PRIORITY)
        root_mac = self.test_params.get('root_mac', self.DEFAULT_BRIDGE_MAC)
        bridge_priority = self.test_params.get('bridge_priority', self.DEFAULT_BRIDGE_PRIORITY)
        bridge_mac = self.test_params.get('bridge_mac', self.DEFAULT_BRIDGE_MAC)
        port_priority = self.test_params.get('port_priority', self.DEFAULT_PORT_PRIORITY)
        port_id = (port_priority << 8) + self.port_id
        message_age = self.test_params.get('message_age', self.DEFAULT_MESSAGE_AGE)
        max_age = self.test_params.get('max_age', self.DEFAULT_MAX_AGE)
        hello_time = self.test_params.get('hello_time', self.DEFAULT_HELLO_TIME)
        forward_delay = self.test_params.get('forward_delay', self.DEFAULT_FORWARD_DELAY)
        root_path_cost = self.test_params.get('root_path_cost', self.DEFAULT_ROOT_PATH_COST)

        # Convert MAC addresses to bytes
        root_mac_bytes = bytes.fromhex(root_mac.replace(':', ''))
        bridge_mac_bytes = bytes.fromhex(bridge_mac.replace(':', ''))

        # Create Configuration BPDU payload
        payload = struct.pack('!B', 0x00)  # Flags (no flags set)
        payload += struct.pack('!H', root_priority)  # Root Priority
        payload += root_mac_bytes  # Root MAC (6 bytes)
        payload += struct.pack('!I', root_path_cost)  # Root Path Cost
        payload += struct.pack('!H', bridge_priority)  # Bridge Priority
        payload += bridge_mac_bytes  # Bridge MAC (6 bytes)
        payload += struct.pack('!H', port_id)  # Port ID
        payload += struct.pack('!H', message_age << 8)  # Message Age
        payload += struct.pack('!H', max_age << 8)  # Max Age
        payload += struct.pack('!H', hello_time << 8)  # Hello Time
        payload += (forward_delay << 16).to_bytes(3, 'big')  # Forward Delay
        payload += struct.pack('!H', self.ORIG_VLAN)  # Orig VLAN
        payload += struct.pack('!H', self.ORIG_VLAN_LEN)  # Orig VLAN LEN
        payload += struct.pack('!H', self.vlan_id)  # Orig VLAN LEN

        return payload

    def create_tcn_bpdu_payload(self):
        """
        @summary: Create TCN BPDU payload

        @return: TCN BPDU payload bytes
        """
        # TCN BPDU has no additional payload beyond the header
        return b''

    def create_pvst_bpdu_packet(self):
        """
        @summary: Create a complete PVST BPDU packet
        @param vlan_id: VLAN ID (default: self.vlan_id)
        @param bpdu_type: BPDU type ('config' or 'tcn')
        @param kwargs: Additional parameters for BPDU payload
        @return: Complete BPDU packet as scapy packet
        """

        # Create BPDU header
        bpdu_header = self.create_bpdu_header(self.bpdu_type)

        # Create BPDU payload based on type
        if self.bpdu_type == 'config':
            bpdu_payload = self.create_config_bpdu_payload()
        elif self.bpdu_type == 'tcn':
            bpdu_payload = self.create_tcn_bpdu_payload()
        else:
            raise ValueError(f"Unsupported BPDU type: {self.bpdu_type}")

        # Combine header and payload
        bpdu_data = bpdu_header + bpdu_payload

        # Create Ethernet frame with VLAN tag
        eth_pkt = Ether(
            dst=self.BPDU_DST_MAC,
            src=self.BPDU_SRC_MAC,
            type=0x8100  # VLAN tag
        )

        # Add VLAN tag
        vlan_pkt = Dot1Q(vlan=self.vlan_id, type=self.BPDU_LEN)  # length

        # Add BPDU data as raw payload
        raw_pkt = Raw(load=bpdu_data)

        # Combine all layers
        packet = eth_pkt / vlan_pkt / raw_pkt

        return packet

    def verify_bpdu_received(self, dst_ports, timeout=5):
        """
        @summary: Verify that BPDU packets are received on specified ports

        @param dst_ports: List of ports to check for BPDU packets
        @param timeout: Timeout for packet verification
        @return: True if BPDU received, False otherwise
        """
        self.logger.info(f"Verifying BPDU reception on ports {dst_ports}")

        # Create expected packet mask (ignore some fields that might change)
        expected_packet = self.create_pvst_bpdu_packet()

        # Create mask to ignore variable fields
        mask = Mask(expected_packet)
        mask.set_do_not_care_scapy(Ether, "src")  # Source MAC might change
        mask.set_do_not_care_scapy(Raw, "load")   # BPDU content might be modified

        try:
            # Verify packet is received on any of the specified ports
            verify_packet_any_port(self, mask, dst_ports, timeout=timeout)
            self.logger.info("BPDU packet received successfully")
            return True
        except Exception as e:
            self.logger.warning(f"BPDU packet not received: {e}")
            return False

    def test_send_config_bpdu(self):
        """
        @summary: Test sending Configuration BPDU packets
        """
        self.logger.info("Testing Configuration BPDU transmission")

        # Set BPDU type to config
        self.bpdu_type = 'config'
        self.vlan_id = self.test_params.get('vlan_id', self.DEFAULT_VLAN_ID)

        for src_port in self.test_params['send_port']:
            self.port_id = src_port

            # Create BPDU packet
            packet = self.create_pvst_bpdu_packet()
            testutils.send_packet(self, src_port, packet)
            self.logger.info(f"Sent BPDU on port {src_port} successfully")

    def test_send_tcn_bpdu(self):
        """
        @summary: Test sending TCN BPDU packets
        """
        self.logger.info("Testing TCN BPDU transmission")

        # Set BPDU type to TCN
        self.bpdu_type = 'tcn'
        self.vlan_id = self.test_params.get('vlan_id', self.DEFAULT_VLAN_ID)

        for src_port in self.test_params['send_port']:
            self.port_id = src_port

            # Create BPDU packet
            packet = self.create_pvst_bpdu_packet()
            testutils.send_packet(self, src_port, packet)
            self.logger.info(f"Sent TCN BPDU on port {src_port} successfully")

    def parse_bpdu_packet(self, packet):
        """
        @summary: Parse BPDU packet and extract timer values

        @param packet: Captured packet (scapy packet object)
        @return: Dictionary with parsed BPDU data or None if not a valid BPDU
        """
        try:
            if packet.dst != self.BPDU_DST_MAC.lower():
                self.logger.info(f"parse_bpdu_packet - Destination MAC mismatch {packet.dst}")
                return None

            if packet.haslayer(LLC):
                if (
                    packet[LLC].dsap != self.LLC_SNAP_DSAP or
                    packet[LLC].ssap != self.LLC_SNAP_SSAP or
                    packet[LLC].ctrl != self.LLC_SNAP_FRAME
                ):
                    self.logger.info(f"parse_bpdu_packet - LLC/SNAP header mismatch "
                                     f"packet[LLC].ssap: {packet[LLC].ssap} "
                                     f"dsap: {packet[LLC].dsap} ctrl: {packet[LLC].ctrl}")
                    return None
            else:
                self.logger.info("parse_bpdu_packet - Packet has no LLC layer")
                return None

            if packet.haslayer(SNAP):
                if packet[SNAP].OUI != self.LLC_SNAP_OUI or packet[SNAP].code != self.LLC_SNAP_PROTO_ID:
                    self.logger.info("parse_bpdu_packet - SNAP OUI mismatch")
                    return None
            else:
                self.logger.info("parse_bpdu_packet - Packet has no SNAP layer")
                return None

            raw_data = bytes(packet[3])
            # Parse BPDU header (4 bytes)
            bpdu_start = 0

            protocol_id = struct.unpack('!H', raw_data[bpdu_start:bpdu_start+2])[0]
            version = raw_data[bpdu_start+2]
            bpdu_type = raw_data[bpdu_start+3]

            if protocol_id != self.BPDU_PROTOCOL_ID or version != self.BPDU_VERSION:
                self.logger.info("parse_bpdu_packet - Protocol ID or version mismatch")
                return None

            bpdu_data = {
                'bpdu_type': bpdu_type
            }

            # Parse Configuration BPDU payload
            if bpdu_type == self.BPDU_TYPE_CONFIG:
                payload_start = bpdu_start + 4
                if len(raw_data) < payload_start + 35:  # Minimum config BPDU size
                    self.logger.info("parse_bpdu_packet - Raw data length less than payload start + 35")
                    return None

                # Parse Configuration BPDU fields
                flags = raw_data[payload_start]
                root_priority = struct.unpack('!H', raw_data[payload_start+1:payload_start+3])[0]
                root_mac = ':'.join([f"{b:02x}" for b in raw_data[payload_start+3:payload_start+9]])
                root_path_cost = struct.unpack('!I', raw_data[payload_start+9:payload_start+13])[0]
                bridge_priority = struct.unpack('!H', raw_data[payload_start+13:payload_start+15])[0]
                bridge_mac = ':'.join([f"{b:02x}" for b in raw_data[payload_start+15:payload_start+21]])
                port_id = struct.unpack('!H', raw_data[payload_start+21:payload_start+23])[0]
                message_age = struct.unpack('!H', raw_data[payload_start+23:payload_start+25])[0] >> 8
                max_age = struct.unpack('!H', raw_data[payload_start+25:payload_start+27])[0] >> 8
                hello_time = struct.unpack('!H', raw_data[payload_start+27:payload_start+29])[0] >> 8
                forward_delay_bytes = raw_data[payload_start+29:payload_start+32]
                forward_delay = struct.unpack('!I', b'\x00' + forward_delay_bytes)[0] >> 16

                vlan_id = struct.unpack('!H', raw_data[payload_start+36:payload_start+38])[0]

                bpdu_data.update({
                    'vlan_id': vlan_id,
                    'flags': flags,
                    'root_priority': root_priority,
                    'root_mac': root_mac,
                    'root_path_cost': root_path_cost,
                    'bridge_priority': bridge_priority,
                    'bridge_mac': bridge_mac,
                    'port_id': port_id,
                    'message_age': message_age,
                    'max_age': max_age,
                    'hello_time': hello_time,
                    'forward_delay': forward_delay
                })

            elif bpdu_type == self.BPDU_TYPE_TCN:
                # TCN BPDU has no additional fields
                pass
            self.logger.info(f"BPDU parsed data: {bpdu_data}")
            return bpdu_data

        except Exception as e:
            self.logger.warning(f"Error parsing BPDU packet: {e}")
            return None

    def bpdu_capture_callback(self, packet):
        """
        @summary: Callback function for captured packets

        @param packet: Captured packet
        """
        self.logger.info(f"bpdu_capture_callback - Captured packet: {packet}")
        bpdu_data = self.parse_bpdu_packet(packet)
        if bpdu_data:
            self.logger.info(f"Captured BPDU: {bpdu_data}")
            self.captured_bpdus.append(bpdu_data)

    def start_bpdu_capture(self, interface, timeout=30):
        """
        @summary: Start capturing BPDU packets on specified interface

        @param interface: Interface name to capture on
        @param timeout: Capture timeout in seconds
        """
        self.captured_bpdus = []
        self.capture_timeout = timeout

        # Create packet filter for PVST BPDUs
        bpdu_filter = f"ether dst {self.BPDU_DST_MAC}"

        self.logger.info(f"Starting BPDU capture on {interface} for {timeout} seconds")

        def capture_worker():
            try:
                scapy2.sniff(
                    iface=interface,
                    filter=bpdu_filter,
                    prn=self.bpdu_capture_callback,
                    count=3,
                    store=0
                )
            except Exception as e:
                self.logger.error(f"Error in packet capture: {e}")

        self.capture_thread = Thread(target=capture_worker)
        self.capture_thread.daemon = True
        self.capture_thread.start()

    def stop_bpdu_capture(self):
        """
        @summary: Stop BPDU packet capture
        """
        if self.capture_thread and self.capture_thread.is_alive():
            self.logger.info("Stopping BPDU capture")
            # Wait for capture thread to finish
            self.capture_thread.join(timeout=5)

    def get_captured_bpdus(self, vlan_id=None, bpdu_type=None):
        """
        @summary: Get captured BPDU packets with optional filtering
        @param vlan_id: Filter by VLAN ID (optional)
        @param bpdu_type: Filter by BPDU type (optional)
        @return: List of filtered BPDU data dictionaries
        """
        filtered_bpdus = self.captured_bpdus.copy()

        if vlan_id is not None:
            filtered_bpdus = [bpdu for bpdu in filtered_bpdus if bpdu.get('vlan_id') == vlan_id]

        if bpdu_type is not None:
            filtered_bpdus = [bpdu for bpdu in filtered_bpdus if bpdu.get('bpdu_type') == bpdu_type]

        return filtered_bpdus

    def validate_bpdu_timers(self, expected_hello_time=None, expected_max_age=None,
                             expected_forward_delay=None, vlan_id=None):
        """
        @summary: Validate timer values in captured BPDU packets
        @param expected_hello_time: Expected hello time value
        @param expected_max_age: Expected max age value
        @param expected_forward_delay: Expected forward delay value
        @param vlan_id: VLAN ID to filter BPDUs (optional)
        @return: Dictionary with validation results
        """
        config_bpdus = self.get_captured_bpdus(vlan_id=vlan_id, bpdu_type=self.BPDU_TYPE_CONFIG)

        if not config_bpdus:
            return {
                'success': False,
                'error': f'No Configuration BPDUs captured for VLAN {vlan_id}',
                'captured_count': 0
            }

        validation_results = {
            'success': True,
            'captured_count': len(config_bpdus),
            'validated_bpdus': [],
            'errors': []
        }

        for bpdu in config_bpdus:
            bpdu_result = {
                'vlan_id': bpdu['vlan_id'],
                'timers': {
                    'hello_time': bpdu.get('hello_time'),
                    'max_age': bpdu.get('max_age'),
                    'forward_delay': bpdu.get('forward_delay')
                },
                'timer_validation': {}
            }

            # Validate hello time
            if expected_hello_time is not None:
                actual_hello = bpdu.get('hello_time', 0)
                if (actual_hello == expected_hello_time):
                    bpdu_result['timer_validation']['hello_time'] = 'PASS'
                else:
                    bpdu_result['timer_validation']['hello_time'] = 'FAIL'
                    validation_results['errors'].append(
                        f"Hello time mismatch: expected {expected_hello_time}, got {actual_hello}"
                    )
                    validation_results['success'] = False

            # Validate max age
            if expected_max_age is not None:
                actual_max_age = bpdu.get('max_age', 0)
                if (actual_max_age == expected_max_age):
                    bpdu_result['timer_validation']['max_age'] = 'PASS'
                else:
                    bpdu_result['timer_validation']['max_age'] = 'FAIL'
                    validation_results['errors'].append(
                        f"Max age mismatch: expected {expected_max_age}, got {actual_max_age}"
                    )
                    validation_results['success'] = False

            # Validate forward delay
            if expected_forward_delay is not None:
                actual_forward_delay = bpdu.get('forward_delay', 0)
                if (actual_forward_delay == expected_forward_delay):
                    bpdu_result['timer_validation']['forward_delay'] = 'PASS'
                else:
                    bpdu_result['timer_validation']['forward_delay'] = 'FAIL'
                    validation_results['errors'].append(
                        f"Forward delay mismatch: expected {expected_forward_delay}, got {actual_forward_delay}"
                    )
                    validation_results['success'] = False

            validation_results['validated_bpdus'].append(bpdu_result)

        return validation_results

    def test_validate_bpdu_timer_values(self):
        """
        @summary: Test case to validate BPDU timer values received from DUT

        This test captures BPDU packets sent by the DUT and validates that
        the timer values in the BPDUs match the expected configuration.
        """
        self.logger.info("Testing BPDU timer value validation")

        # Get test parameters
        vlan_id = self.test_params.get('vlan_id', self.DEFAULT_VLAN_ID)
        capture_port = self.test_params.get('capture_port', 1)  # PTF port to capture on
        expected_hello_time = self.test_params.get('expected_hello_time', 2)
        expected_max_age = self.test_params.get('expected_max_age', 20)
        expected_forward_delay = self.test_params.get('expected_forward_delay', 15)
        capture_duration = self.test_params.get('capture_duration', 30)

        self.logger.info(f"Capturing BPDUs on port {capture_port} for VLAN {vlan_id}")
        self.logger.info(f"Expected timers - Hello: {expected_hello_time}, "
                         f"Max Age: {expected_max_age}, Forward Delay: {expected_forward_delay}")

        # Start packet capture
        capture_interface = f"eth{capture_port}"
        self.start_bpdu_capture(capture_interface, timeout=capture_duration)

        # Wait for BPDUs to be captured
        time.sleep(capture_duration + 2)  # Extra time to ensure capture completes

        # Stop capture
        self.stop_bpdu_capture()

        # Validate captured BPDUs
        validation_results = self.validate_bpdu_timers(
            expected_hello_time=expected_hello_time,
            expected_max_age=expected_max_age,
            expected_forward_delay=expected_forward_delay,
            vlan_id=vlan_id
        )

        # Log results
        self.logger.info(f"Validation results: {validation_results}")

        if not validation_results['success']:
            error_msg = f"BPDU timer validation failed: {validation_results['errors']}"
            self.logger.error(error_msg)
            raise AssertionError(error_msg)

        self.logger.info(f"Successfully validated {validation_results['captured_count']} BPDU packets")

        # Log detailed results for each validated BPDU
        for bpdu in validation_results['validated_bpdus']:
            self.logger.info(f"BPDU on VLAN {bpdu['vlan_id']}: "
                             f"Hello={bpdu['timers']['hello_time']}, "
                             f"MaxAge={bpdu['timers']['max_age']}, "
                             f"ForwardDelay={bpdu['timers']['forward_delay']}")

    def test_validate_backup_port(self):
        """
        @summary: Specific test for capturing BPDUs and replaying them on another port

        This test is designed for backup port testing where we capture BPDUs
        from one port and replay them on another to simulate receiving own BPDUs.
        """
        self.logger.info("Testing BPDU capture and replay for backup port functionality")

        # Get test parameters
        capture_port = self.test_params.get('capture_port', 1)
        replay_port = self.test_params.get('replay_port', 2)
        capture_duration = self.test_params.get('capture_duration', 15)
        replay_delay = self.test_params.get('replay_delay', 5)

        if replay_port is None:
            self.logger.warning("No replay port specified for BPDU replay test")
            return

        # vlan_id = self.test_params.get('vlan_id', self.DEFAULT_VLAN_ID)

        self.logger.info(f"Capturing BPDUs from port {capture_port} and replaying on port {replay_port}")

        # Store captured BPDUs
        captured_bpdus = []

        def bpdu_capture_callback(packet):
            """Callback to capture and parse BPDU packets"""
            bpdu_data = self.parse_bpdu_packet(packet)
            if bpdu_data:
                self.logger.info(f"Captured BPDU data: {bpdu_data}")
                self.logger.info(f"Captured BPDU: {packet}")
                captured_bpdus.append({
                    'packet': packet,
                    'bpdu_data': bpdu_data
                })

        # Start BPDU capture
        self.logger.info(f"Starting BPDU capture on port {capture_port}")

        capture_interface = f"eth{capture_port}"
        bpdu_filter = f"ether dst {self.BPDU_DST_MAC}"

        def bpdu_capture_worker():
            try:
                scapy2.sniff(
                    iface=capture_interface,
                    filter=bpdu_filter,
                    prn=bpdu_capture_callback,
                    timeout=capture_duration,
                    store=0
                )
            except Exception as e:
                self.logger.error(f"Error in BPDU capture: {e}")

        # Start capture
        capture_thread = Thread(target=bpdu_capture_worker)
        capture_thread.daemon = True
        capture_thread.start()

        # Wait for capture to complete
        capture_thread.join(timeout=capture_duration + 5)

        self.logger.info(f"BPDU capture completed. Captured {len(captured_bpdus)} BPDUs")

        if not captured_bpdus:
            self.logger.warning("No BPDUs captured for replay")
            return

        # Wait before starting replay
        self.logger.info(f"Waiting {replay_delay} seconds before starting BPDU replay")
        time.sleep(replay_delay)

        # Replay the most recent BPDU (or all of them)
        replay_all = self.test_params.get('replay_all_bpdus', False)
        bpdus_to_replay = captured_bpdus if replay_all else [captured_bpdus[-1]]

        self.logger.info(f"Replaying {len(bpdus_to_replay)} BPDU(s) on port {replay_port}")

        for i, bpdu_info in enumerate(bpdus_to_replay):
            try:
                # Get the original packet
                original_packet = bpdu_info['packet']
                bpdu_data = bpdu_info['bpdu_data']

                # Create new packet with proper PVST structure
                new_packet = Ether(
                    dst=original_packet.dst,
                    src=original_packet.src,
                    type=0x8100
                ) / Dot1Q(
                    vlan=bpdu_data.get('vlan_id', 1),
                    type=self.BPDU_LEN  # Use length field for PVST
                ) / Raw(original_packet.payload)

                # Create a copy for replay
                replay_packet = new_packet.copy()

                # Send the BPDU on the replay port
                testutils.send_packet(self, replay_port, replay_packet)
                self.logger.info(f"Replayed BPDU {i+1}/{len(bpdus_to_replay)} on port {replay_port}")
                self.logger.info(f"Replayed BPDU details: VLAN {bpdu_data.get('vlan_id', 'Unknown')}, "
                                 f"Bridge Priority {bpdu_data.get('bridge_priority', 'Unknown')}")

                # Small delay between BPDU replays
                if i < len(bpdus_to_replay) - 1:
                    time.sleep(1)

            except Exception as e:
                self.logger.warning(f"Failed to reconstruct packet with VLAN tag: {e}")
                self.logger.info("Using original packet for replay")
                replay_packet = original_packet.copy()
                testutils.send_packet(self, replay_port, replay_packet)
                self.logger.info(f"Replayed BPDU {i+1}/{len(bpdus_to_replay)} on port {replay_port}")
                self.logger.info(f"Replayed BPDU details: VLAN {bpdu_data.get('vlan_id', 'Unknown')}, "
                                 f"Bridge Priority {bpdu_data.get('bridge_priority', 'Unknown')}")

                # Small delay between BPDU replays
                if i < len(bpdus_to_replay) - 1:
                    time.sleep(1)

            except Exception as e:
                self.logger.error(f"Error replaying BPDU {i+1}: {e}")

        self.logger.info("BPDU capture and replay test completed successfully")

    def test_validate_root_path_cost(self):
        """
        @summary: Test case to validate root path cost in captured BPDU packets

        This test captures BPDU packets sent by the DUT and validates that
        the root path cost field in the BPDUs matches the expected value.
        """
        self.logger.info("Testing BPDU root path cost validation")

        # Get test parameters
        vlan_id = self.test_params.get('vlan_id', self.DEFAULT_VLAN_ID)
        capture_port = self.test_params.get('capture_port', 1)  # PTF port to capture on
        expected_root_path_cost = self.test_params.get('expected_root_path_cost', 0)
        capture_duration = self.test_params.get('capture_duration', 15)

        self.logger.info(f"Capturing BPDUs on port {capture_port} for VLAN {vlan_id}")
        self.logger.info(f"Expected root path cost: {expected_root_path_cost}")

        # Start packet capture
        capture_interface = f"eth{capture_port}"
        self.start_bpdu_capture(capture_interface, timeout=capture_duration)

        # Wait for BPDUs to be captured
        time.sleep(capture_duration)  # Extra time to ensure capture completes

        # Stop capture
        self.stop_bpdu_capture()

        # Get captured BPDUs for this VLAN
        config_bpdus = self.get_captured_bpdus(vlan_id=vlan_id, bpdu_type=self.BPDU_TYPE_CONFIG)

        if not config_bpdus:
            error_msg = f'No Configuration BPDUs captured for VLAN {vlan_id}'
            self.logger.error(error_msg)
            raise AssertionError(error_msg)

        self.logger.info(f"Captured {len(config_bpdus)} Configuration BPDU(s) for validation")

        # Validate root path cost in each captured BPDU
        validation_results = {
            'success': True,
            'captured_count': len(config_bpdus),
            'validated_bpdus': [],
            'errors': []
        }

        for i, bpdu in enumerate(config_bpdus):
            actual_root_path_cost = bpdu.get('root_path_cost', 0)

            bpdu_result = {
                'bpdu_index': i + 1,
                'vlan_id': bpdu['vlan_id'],
                'actual_root_path_cost': actual_root_path_cost,
                'expected_root_path_cost': expected_root_path_cost,
                'validation': 'UNKNOWN'
            }

            # Check if root path cost matches expected value
            if (actual_root_path_cost == expected_root_path_cost):
                bpdu_result['validation'] = 'PASS'
                self.logger.info(f"BPDU {i+1}: Root path cost validation PASSED - "
                                 f"Expected: {expected_root_path_cost}, Actual: {actual_root_path_cost}")
            else:
                bpdu_result['validation'] = 'FAIL'
                error_msg = (f"BPDU {i+1}: Root path cost mismatch - "
                             f"Expected: {expected_root_path_cost}, Actual: {actual_root_path_cost}")
                validation_results['errors'].append(error_msg)
                validation_results['success'] = False
                self.logger.error(error_msg)

            # Log additional BPDU details for debugging
            self.logger.info(f"BPDU {i+1} details: "
                             f"VLAN={bpdu['vlan_id']}, "
                             f"Root Priority={bpdu.get('root_priority', 'N/A')}, "
                             f"Root MAC={bpdu.get('root_mac', 'N/A')}, "
                             f"Bridge Priority={bpdu.get('bridge_priority', 'N/A')}, "
                             f"Bridge MAC={bpdu.get('bridge_mac', 'N/A')}, "
                             f"Root Path Cost={actual_root_path_cost}")

            validation_results['validated_bpdus'].append(bpdu_result)

        # Log overall validation results
        self.logger.info(f"Root path cost validation results: {validation_results}")

        if not validation_results['success']:
            error_msg = f"Root path cost validation failed: {validation_results['errors']}"
            self.logger.error(error_msg)
            raise AssertionError(error_msg)

        self.logger.info(f"Successfully validated root path cost in "
                         f"{validation_results['captured_count']} BPDU packet(s)")

    def test_validate_bridge_mac_and_priority(self):
        """
        @summary: Test case to validate bridge MAC and bridge priority in captured BPDU packets

        This test captures BPDU packets sent by the DUT and validates that
        the bridge MAC and bridge priority fields in the BPDUs match the expected values.
        """
        self.logger.info("Testing BPDU bridge MAC and priority validation")

        # Get test parameters
        vlan_id = self.test_params.get('vlan_id', self.DEFAULT_VLAN_ID)
        capture_port = self.test_params.get('capture_port', 1)
        expected_bridge_mac = self.test_params.get('expected_bridge_mac', '')
        expected_bridge_priority = str(self.test_params.get('expected_bridge_priority', self.DEFAULT_BRIDGE_PRIORITY))
        capture_duration = self.test_params.get('capture_duration', 15)

        self.logger.info(f"Capturing BPDUs on port {capture_port} for VLAN {vlan_id}")
        self.logger.info(f"Expected bridge MAC: {expected_bridge_mac}")
        self.logger.info(f"Expected bridge priority: {expected_bridge_priority}")

        # Start packet capture
        capture_interface = f"eth{capture_port}"
        self.start_bpdu_capture(capture_interface, timeout=capture_duration)

        # Wait for capture
        time.sleep(capture_duration)

        # Stop capture
        self.stop_bpdu_capture()

        # Get captured BPDUs for this VLAN
        config_bpdus = self.get_captured_bpdus(vlan_id=vlan_id, bpdu_type=self.BPDU_TYPE_CONFIG)

        if not config_bpdus:
            error_msg = f'No Configuration BPDUs captured for VLAN {vlan_id}'
            self.logger.error(error_msg)
            raise AssertionError(error_msg)

        self.logger.info(f"Captured {len(config_bpdus)} Configuration BPDU(s) for validation")

        validation_results = {
            'success': True,
            'captured_count': len(config_bpdus),
            'validated_bpdus': [],
            'errors': []
        }

        for i, bpdu in enumerate(config_bpdus):
            actual_bridge_mac = bpdu.get('bridge_mac', '').lower()
            actual_bridge_priority = str(bpdu.get('bridge_priority', ''))

            bpdu_result = {
                'bpdu_index': i + 1,
                'vlan_id': bpdu['vlan_id'],
                'actual_bridge_mac': actual_bridge_mac,
                'expected_bridge_mac': expected_bridge_mac,
                'actual_bridge_priority': actual_bridge_priority,
                'expected_bridge_priority': expected_bridge_priority,
                'validation': {
                    'bridge_mac': 'UNKNOWN',
                    'bridge_priority': 'UNKNOWN'
                }
            }

            # Bridge MAC validation
            if actual_bridge_mac == expected_bridge_mac:
                bpdu_result['validation']['bridge_mac'] = 'PASS'
                self.logger.info(f"BPDU {i+1}: Bridge MAC match: {actual_bridge_mac}")
            else:
                bpdu_result['validation']['bridge_mac'] = 'FAIL'
                err = f"BPDU {i+1}: Bridge MAC mismatch - Expected: {expected_bridge_mac}, Got: {actual_bridge_mac}"
                validation_results['errors'].append(err)
                self.logger.error(err)
                validation_results['success'] = False

            # Bridge Priority validation
            if actual_bridge_priority == expected_bridge_priority:
                bpdu_result['validation']['bridge_priority'] = 'PASS'
                self.logger.info(f"BPDU {i+1}: Bridge Priority match: {actual_bridge_priority}")
            else:
                bpdu_result['validation']['bridge_priority'] = 'FAIL'
                err = (f"BPDU {i+1}: Bridge Priority mismatch - "
                       f"Expected: {expected_bridge_priority}, Got: {actual_bridge_priority}")
                validation_results['errors'].append(err)
                self.logger.error(err)
                validation_results['success'] = False

            self.logger.info(f"BPDU {i+1} details: "
                             f"VLAN={bpdu['vlan_id']}, "
                             f"Bridge MAC={actual_bridge_mac}, "
                             f"Bridge Priority={actual_bridge_priority}")

            validation_results['validated_bpdus'].append(bpdu_result)

        if not validation_results['success']:
            raise AssertionError(f"Bridge MAC/Priority validation failed: {validation_results['errors']}")

        self.logger.info(f"Successfully validated bridge MAC and "
                         f"priority in {validation_results['captured_count']} BPDU packet(s)")

    def test_validate_expected_bpdu_packet(self):
        """
        @summary: Test case to validate bridge MAC and bridge priority in captured BPDU packets

        This test captures BPDU packets sent by the DUT and validates that
        the bridge MAC and bridge priority fields in the BPDUs match the expected values.
        """
        self.logger.info("Testing BPDU bridge MAC and priority validation")

        # Get test parameters
        vlan_id = self.test_params.get('vlan_id', self.DEFAULT_VLAN_ID)
        capture_port = self.test_params.get('capture_port', 1)
        expected_bridge_mac = self.test_params.get('expected_bridge_mac', '')
        expected_bridge_priority = str(self.test_params.get('expected_bridge_priority', self.DEFAULT_BRIDGE_PRIORITY))
        expected_root_path_cost = self.test_params.get('expected_root_path_cost', 0)
        expected_hello_time = self.test_params.get('expected_hello_time', 2)
        expected_max_age = self.test_params.get('expected_max_age', 20)
        expected_forward_delay = self.test_params.get('expected_forward_delay', 15)
        capture_duration = self.test_params.get('capture_duration', 15)

        self.logger.info(f"Capturing BPDUs on port {capture_port} for VLAN {vlan_id}")
        self.logger.info(f"Expected bridge MAC: {expected_bridge_mac}")
        self.logger.info(f"Expected bridge priority: {expected_bridge_priority}")
        self.logger.info(f"Capturing BPDUs on port {capture_port} for VLAN {vlan_id}")
        self.logger.info(f"Expected root path cost: {expected_root_path_cost}")
        self.logger.info(f"Expected timers - Hello: {expected_hello_time}, "
                         f"Max Age: {expected_max_age}, Forward Delay: {expected_forward_delay}")

        # Start packet capture
        capture_interface = f"eth{capture_port}"
        self.start_bpdu_capture(capture_interface, timeout=capture_duration)

        # Wait for capture
        time.sleep(capture_duration)

        # Stop capture
        self.stop_bpdu_capture()

        # Get captured BPDUs for this VLAN
        config_bpdus = self.get_captured_bpdus(vlan_id=vlan_id, bpdu_type=self.BPDU_TYPE_CONFIG)

        if not config_bpdus:
            error_msg = f'No Configuration BPDUs captured for VLAN {vlan_id}'
            self.logger.error(error_msg)
            raise AssertionError(error_msg)

        self.logger.info(f"Captured {len(config_bpdus)} Configuration BPDU(s) for validation")

        validation_results = {
            'success': True,
            'captured_count': len(config_bpdus),
            'validated_bpdus': [],
            'errors': []
        }

        for i, bpdu in enumerate(config_bpdus):
            actual_bridge_mac = bpdu.get('bridge_mac', '').lower()
            actual_bridge_priority = str(bpdu.get('bridge_priority', ''))
            actual_root_path_cost = bpdu.get('root_path_cost', 0)
            actual_hello = bpdu.get('hello_time', 0)
            actual_max_age = bpdu.get('max_age', 0)
            actual_forward_delay = bpdu.get('forward_delay', 0)

            bpdu_result = {
                'bpdu_index': i + 1,
                'vlan_id': bpdu['vlan_id'],
                'actual_bridge_mac': actual_bridge_mac,
                'expected_bridge_mac': expected_bridge_mac,
                'actual_bridge_priority': actual_bridge_priority,
                'expected_bridge_priority': expected_bridge_priority,
                'actual_root_path_cost': actual_root_path_cost,
                'expected_root_path_cost': expected_root_path_cost,
                'actual_hello': actual_hello,
                'expected_hello_time': expected_hello_time,
                'actual_max_age': actual_max_age,
                'expected_max_age': expected_max_age,
                'actual_forward_delay': actual_forward_delay,
                'expected_forward_delay': expected_forward_delay,
                'validation': {
                    'bridge_mac': 'UNKNOWN',
                    'bridge_priority': 'UNKNOWN'
                }
            }

            # Bridge MAC validation
            if actual_bridge_mac == expected_bridge_mac:
                bpdu_result['validation']['bridge_mac'] = 'PASS'
                self.logger.info(f"BPDU {i+1}: Bridge MAC match: {actual_bridge_mac}")
            else:
                bpdu_result['validation']['bridge_mac'] = 'FAIL'
                err = f"BPDU {i+1}: Bridge MAC mismatch - Expected: {expected_bridge_mac}, Got: {actual_bridge_mac}"
                validation_results['errors'].append(err)
                self.logger.error(err)
                validation_results['success'] = False

            # Bridge Priority validation
            if actual_bridge_priority == expected_bridge_priority:
                bpdu_result['validation']['bridge_priority'] = 'PASS'
                self.logger.info(f"BPDU {i+1}: Bridge Priority match: {actual_bridge_priority}")
            else:
                bpdu_result['validation']['bridge_priority'] = 'FAIL'
                err = (f"BPDU {i+1}: Bridge Priority mismatch - "
                       f"Expected: {expected_bridge_priority}, Got: {actual_bridge_priority}")
                validation_results['errors'].append(err)
                self.logger.error(err)
                validation_results['success'] = False

            # Path Cost Validation
            if (actual_root_path_cost == expected_root_path_cost):
                bpdu_result['validation']['root_path_cost'] = 'PASS'
                self.logger.info(f"BPDU {i+1}: Root path cost validation PASSED - "
                                 f"Expected: {expected_root_path_cost}, Actual: {actual_root_path_cost}")
            else:
                bpdu_result['validation']['root_path_cost'] = 'FAIL'
                error_msg = (f"BPDU {i+1}: Root path cost mismatch - "
                             f"Expected: {expected_root_path_cost}, Actual: {actual_root_path_cost}")
                validation_results['errors'].append(error_msg)
                validation_results['success'] = False
                self.logger.error(error_msg)

            # Hello Time Validation
            if (actual_hello == expected_hello_time):
                bpdu_result['validation']['hello_time'] = 'PASS'
                self.logger.info(f"BPDU {i+1}: hello time validation PASSED - "
                                 f"Expected: {expected_hello_time}, Actual: {actual_hello}")
            else:
                bpdu_result['validation']['hello_time'] = 'FAIL'
                error_msg = (f"BPDU {i+1}: hello time mismatch - "
                             f"Expected: {expected_hello_time}, Actual: {actual_hello}")
                validation_results['errors'].append(error_msg)
                validation_results['success'] = False
                self.logger.error(error_msg)

            # Validate max age
            if (actual_max_age == expected_max_age):
                bpdu_result['validation']['max_age'] = 'PASS'
                self.logger.info(f"BPDU {i+1}: max age validation PASSED - "
                                 f"Expected: {expected_max_age}, Actual: {actual_max_age}")
            else:
                bpdu_result['validation']['max_age'] = 'FAIL'
                error_msg = (f"BPDU {i+1}:Max age mismatch - "
                             f"Expected :{expected_max_age}, got {actual_max_age}")
                validation_results['errors'].append(error_msg)
                validation_results['success'] = False
                self.logger.error(error_msg)

            # Validate forward delay
            if (actual_forward_delay == expected_forward_delay):
                bpdu_result['validation']['forward_delay'] = 'PASS'
                self.logger.info(f"BPDU {i+1}: forward delay validation PASSED - "
                                 f"Expected: {expected_forward_delay}, Actual: {actual_forward_delay}")
            else:
                bpdu_result['validation']['forward_delay'] = 'FAIL'
                error_msg = (f"BPDU {i+1}:Forward Delay mismatch - "
                             f"Expected :{expected_forward_delay}, got {actual_forward_delay}")
                validation_results['errors'].append(error_msg)
                validation_results['success'] = False
                self.logger.error(error_msg)

            self.logger.info(f"BPDU {i+1} details: "
                             f"VLAN={bpdu['vlan_id']}, "
                             f"Root Priority={bpdu.get('root_priority', 'N/A')}, "
                             f"Root MAC={bpdu.get('root_mac', 'N/A')}, "
                             f"Bridge Priority={bpdu.get('bridge_priority', 'N/A')}, "
                             f"Bridge MAC={bpdu.get('bridge_mac', 'N/A')}, "
                             f"Root Path Cost={actual_root_path_cost}")

            validation_results['validated_bpdus'].append(bpdu_result)

        if not validation_results['success']:
            raise AssertionError(f"Bridge MAC/Priority validation failed: {validation_results['errors']}")

        self.logger.info(f"Successfully validated bridge MAC and priority "
                         f"in {validation_results['captured_count']} BPDU packet(s)")

    def create_l2_packet(self, send_port, vlan_id):
        self.dataplane.flush()
        payload = f"Hello VLAN {vlan_id}".encode()
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=f"00:11:22:33:55:{send_port}", type=0x8100) / \
            Dot1Q(vlan=vlan_id) / \
            payload

        return pkt

    def verify_l2_expected_packet(self, vlan_id, send_port):
        payload = f"Hello VLAN {vlan_id}".encode()
        pad_len = 46 - len(payload)
        payload += b"\x00" * pad_len
        pkt = Ether(
            dst="ff:ff:ff:ff:ff:ff",
            src=f"00:11:22:33:55:{send_port}",
            type=0x0000
        ) / payload
        return pkt

    def test_validate_l2_packet(self):
        send_port = int(self.test_params["send_port"])
        recv_port = int(self.test_params["receive_port"])
        vlan_id = int(self.test_params.get("vlan_id", 1))
        verify_packet = self.test_params.get("verify_packet", True)
        self.logger.info(f"verify_packet {verify_packet}")

        l2_packet = self.create_l2_packet(send_port, vlan_id)

        expected_l2_packet = self.verify_l2_expected_packet(vlan_id, send_port)
        masked_pkt = Mask(expected_l2_packet)
        masked_pkt.set_do_not_care(12, len(expected_l2_packet) - 12)

        count_to_send = 100

        # Flush dataplane before test
        self.dataplane.flush()
        for i in range(count_to_send):
            testutils.send_packet(test=self, port_id=send_port, pkt=l2_packet)
        self.logger.info(f"packet send successfully {verify_packet}")

        if verify_packet:
            # Expecting 100 packets received
            matched_count = testutils.count_matched_packets_all_ports(
                self,
                masked_pkt,
                [recv_port],
                timeout=5
            )
            self.logger.info(f"Matched packet count: {matched_count}")
            assert matched_count == count_to_send, f"Expected {count_to_send} packets, got {matched_count}"

        else:
            # Expecting zero matching packets (e.g., due to filter/drop)
            matched_count = testutils.count_matched_packets_all_ports(
                self,
                masked_pkt,
                [recv_port],
                timeout=5
            )
            self.logger.info(f"Matched packet count (expecting 0): {matched_count}")
            assert matched_count == 0, f"Expected 0 packets, but got {matched_count}"

    def runTest(self):
        """
        @summary: Main test execution
        """
        self.logger.info("Starting PVST BPDU test")
        # Run different test scenarios based on parameters
        scenario = self.test_params.get('test_scenarios', 'config')

        if scenario == 'config':
            self.test_send_config_bpdu()
        elif scenario == 'tcn':
            self.test_send_tcn_bpdu()
        elif scenario == 'validate_timers':
            self.test_validate_bpdu_timer_values()
        elif scenario == 'validate_backup_port':
            self.test_validate_backup_port()
        elif scenario == 'validate_path_cost':
            self.test_validate_root_path_cost()
        elif scenario == 'validate_root_bridge_id':
            self.test_validate_bridge_mac_and_priority()
        elif scenario == 'validate_bpdu_packet':
            self.test_validate_expected_bpdu_packet()
        elif scenario == 'validate_l2_packet':
            self.test_validate_l2_packet()
        else:
            self.logger.warning(f"Unknown test scenario: {scenario}")

        self.logger.info("PVST BPDU test completed successfully")
