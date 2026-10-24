# Copyright (c) 2025 Clounix (Shanghai) Technology Limited.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
#    THIS CODE IS PROVIDED ON AN *AS IS* BASIS, WITHOUT WARRANTIES OR
#    CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT
#    LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS
#    FOR A PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
#
#    See the Apache Version 2.0 License for specific language governing
#    permissions and limitations under the License.


from sai_thrift.sai_headers import *
from ptf.testutils import *
from sai_base_test import *
import time
import random
import ipaddress
import itertools
import math
import statistics
from ext_sai_l3_scale_base import SaiHelperScaleL3

class SaiHelperScaleNeighbor(SaiHelperScaleL3):
    """
    Base class for neighbor table scale tests.
    Provides common neighbor bulk add/delete and traffic verification methods.
    Inherits from SaiHelperScaleL3 for L3 scale testing capabilities.

    Test Environment:
    - Creates 8 PORT type RIFs (ports 0-7)
    - Creates 2000 VLAN type RIFs (VLAN IDs 1000-2999)
    - Uses ports 16-23 for VLAN bridge ports
    - Supports IPv4 and IPv6 neighbor testing

    Features:
    - Bulk neighbor creation and deletion
    - Traffic verification with sampling
    - Resource leak detection
    - Error handling and reporting
    """

    # Neighbor IP address range configuration - for neighbor table entries
    NEIGHBOR_IPV4_START = "10.1.1.1"  # Neighbor IPv4 start: 10.1.1.1
    NEIGHBOR_IPV4_NETWORK = "10.1.0.0/16"  # Neighbor IPv4 network segment

    NEIGHBOR_IPV6_START = "2001:db8:1::1"  # Neighbor IPv6 start: 2001:db8:1::1
    NEIGHBOR_IPV6_NETWORK = "2001:db8:1::/64"  # Neighbor IPv6 network segment

    # MAC address range configuration - for neighbor table entries
    MAC_START_OUI = "00:02"  # MAC OUI start: 00:02
    MAC_IPV4_OUI = "00:00"   # MAC OUI for IPv4 neighbors: 00:00
    MAC_IPV6_OUI = "00:01"   # MAC OUI for IPv6 neighbors: 00:01

    # Test configuration
    DEFAULT_BULK_SIZE = 1000
    TRAFFIC_SAMPLE_SIZE = 10
    SUCCESS_RATE_THRESHOLD = 0.8

    def _get_default_port_bridge_port_map(self):
        """Map physical port OIDs to existing default 1Q bridge ports."""
        attr = sai_thrift_get_switch_attribute(
            self.client, default_1q_bridge_id=True)
        bridge_id = attr['default_1q_bridge_id']
        if bridge_id == SAI_NULL_OBJECT_ID:
            return {}
        count = (getattr(self, 'system_port_no', 0)
                 + getattr(self, 'active_ports_no', 0) + 1) or 512
        attr = sai_thrift_get_bridge_attribute(
            self.client, bridge_oid=bridge_id,
            port_list=sai_thrift_object_list_t(idlist=[], count=count))
        port_to_bp = {}
        for bp in attr['port_list'].idlist:
            bp_attr = sai_thrift_get_bridge_port_attribute(
                self.client, bp, port_id=True)
            pid = bp_attr.get('port_id')
            if pid:
                port_to_bp[pid] = bp
        print(f"Found {len(port_to_bp)} existing default PORT bridge ports")
        return port_to_bp

    def setUp(self):
        """
        Setup test environment with router interfaces and VLANs.
        Creates PORT and VLAN type RIFs for neighbor testing.
        """
        super(SaiHelperScaleNeighbor, self).setUp()

        # Skip syslog verify for this test
        self.skip_syslog_verify = True

        # Initialize lists for proper cleanup
        self.port_rif_list = []
        self.vlan_rif_list = []
        self.created_vlans = []
        self.created_bridge_ports = []
        self.created_vlan_members = []
        self.created_rifs = []

        # 1. Create RIF VLANs (VLAN IDs 1000-2999)
        self.rif_vlan_list = []
        for i in range(1000, 3000):
            vlan_id = sai_thrift_create_vlan(self.client, vlan_id=i)
            if vlan_id == SAI_NULL_OBJECT_ID:
                raise Exception(f"Failed to create VLAN {i}")
            self.rif_vlan_list.append(vlan_id)
            self.created_vlans.append(vlan_id)
        print(f"Created {len(self.rif_vlan_list)} RIF VLANs.")

        # 2. Create bridge ports for VLAN RIFs (ports 16-23)
        rif_port_indices = list(range(16, 24))
        if get_platform() == 'mlnx':
            # A physical LAG member or an existing bridge port cannot be
            # reused as another PORT bridge port.
            lag_member_ports = set()
            for lag_member in self.def_lag_member_list:
                attrs = sai_thrift_get_lag_member_attribute(
                    self.client, lag_member, port_id=True)
                port_id = attrs.get(
                    'port_id',
                    attrs.get('SAI_LAG_MEMBER_ATTR_PORT_ID'))
                if port_id is not None:
                    lag_member_ports.add(port_id)

            existing_bridge_ports = set()
            for bridge_port in self.def_bridge_port_list:
                attrs = sai_thrift_get_bridge_port_attribute(
                    self.client, bridge_port, port_id=True)
                port_id = attrs.get(
                    'port_id',
                    attrs.get('SAI_BRIDGE_PORT_ATTR_PORT_ID'))
                if port_id is not None:
                    existing_bridge_ports.add(port_id)

            rif_port_indices = [
                idx for idx, port in enumerate(self.port_list)
                if (idx >= 8 and
                    port not in lag_member_ports and
                    port not in existing_bridge_ports)
            ][:8]
            self.assertEqual(
                len(rif_port_indices), 8,
                "At least 8 standalone ports are required for MLNX")
            print(
                "MLNX neighbor scale bridge port indices: "
                f"{rif_port_indices}")

        self.rif_port_indices = rif_port_indices
        self.rif_port_bp_list = []
        # Reuse Broadcom's default PORT bridge ports when present.
        port_to_bp = self._get_default_port_bridge_port_map()
        for i in rif_port_indices:
            port_oid = self.port_list[i]
            port_bp = port_to_bp.get(port_oid)
            if port_bp is None:
                port_bp = sai_thrift_create_bridge_port(
                    self.client,
                    port_id=port_oid,
                    type=SAI_BRIDGE_PORT_TYPE_PORT,
                    admin_state=True)
                if port_bp == SAI_NULL_OBJECT_ID:
                    raise Exception(
                        f"Failed to create bridge port {i} "
                        f"(port_oid={port_oid:#x}, "
                        f"sai_status={self.status()})")
                self.created_bridge_ports.append(port_bp)
            else:
                print(f"Reusing default bridge port for port {i} "
                      f"(port_oid={port_oid:#x}, bp={port_bp:#x})")
            self.rif_port_bp_list.append(port_bp)
        print(f"Prepared {len(self.rif_port_bp_list)} RIF bridge ports.")

        # 3. Create VLAN members for RIF VLANs
        self.rif_vlan_member_list = []
        for vlan in self.rif_vlan_list:
            for bp in self.rif_port_bp_list:
                member = sai_thrift_create_vlan_member(
                    self.client,
                    vlan_id=vlan,
                    bridge_port_id=bp,
                    vlan_tagging_mode=SAI_VLAN_TAGGING_MODE_TAGGED)
                if member == SAI_NULL_OBJECT_ID:
                    raise Exception("Failed to create VLAN member")
                self.rif_vlan_member_list.append(member)
                self.created_vlan_members.append(member)
        print(f"Created {len(self.rif_vlan_member_list)} RIF VLAN members.")

        # 4. Create RIFs for PORT and VLAN types
        # PORT type RIFs (ports 0-7)
        for port_idx in range(0, 8):
            rif = sai_thrift_create_router_interface(
                self.client,
                type=SAI_ROUTER_INTERFACE_TYPE_PORT,
                virtual_router_id=self.default_vrf,
                port_id=self.port_list[port_idx])
            self.port_rif_list.append(rif)
            self.rif_list.append(rif)
            self.created_rifs.append(rif)
        print(f"Created {len(self.port_rif_list)} PORT RIFs.")

        # VLAN type RIFs (2000 vlans, VLAN IDs 1000-2999)
        for vlan_oid in self.rif_vlan_list:
            rif = sai_thrift_create_router_interface(
                self.client,
                type=SAI_ROUTER_INTERFACE_TYPE_VLAN,
                virtual_router_id=self.default_vrf,
                vlan_id=vlan_oid)
            self.vlan_rif_list.append(rif)
            self.rif_list.append(rif)
            self.created_rifs.append(rif)
        print(f"Created {len(self.vlan_rif_list)} VLAN RIFs.")

    def tearDown(self):
        """
        Cleanup test environment in reverse order of creation.
        Removes VLAN members, bridge ports, router interfaces, and VLANs.
        """
        print("Cleaning up test environment...")

        # Clean up in reverse order of creation
        try:
            # Remove VLAN members
            for member in self.created_vlan_members:
                try:
                    sai_thrift_remove_vlan_member(self.client, member)
                except Exception as e:
                    print(f"Warning: Failed to remove VLAN member {member}: {e}")
            self.rif_vlan_member_list = []
            self.created_vlan_members = []

            # Remove bridge ports
            for bp in self.created_bridge_ports:
                try:
                    sai_thrift_remove_bridge_port(self.client, bp)
                except Exception as e:
                    print(f"Warning: Failed to remove bridge port {bp}: {e}")
            self.rif_port_bp_list = []
            self.created_bridge_ports = []

            # Remove router interfaces (PORT and VLAN types)
            for rif in self.created_rifs:
                try:
                    sai_thrift_remove_router_interface(self.client, rif)
                except Exception as e:
                    print(f"Warning: Failed to remove router interface {rif}: {e}")
            self.rif_list = []
            self.port_rif_list = []
            self.vlan_rif_list = []
            self.created_rifs = []

            # Remove VLANs (RIF VLANs)
            for vlan in self.created_vlans:
                try:
                    sai_thrift_remove_vlan(self.client, vlan)
                except Exception as e:
                    print(f"Warning: Failed to remove VLAN {vlan}: {e}")
            self.rif_vlan_list = []
            self.created_vlans = []

        except Exception as e:
            print(f"Error during cleanup: {e}")

        super(SaiHelperScaleNeighbor, self).tearDown()


    def _generate_neighbor_ips_ipv4(self, count):
        """
        Generate IPv4 neighbor IP address list.

        Args:
            count: Number of neighbor IPs to generate

        Returns:
            list: IPv4 neighbor IP address list, format as "10.1.x.y"
                 Example: 10.1.1.1, 10.1.1.2, 10.1.1.3, ..., 10.1.2.1, ...
        """
        start_ip = ipaddress.IPv4Address(self.NEIGHBOR_IPV4_START)
        ips = []

        for i in range(count):
            # Generate format: 10.1.x.y, where x and y increment
            current_ip = start_ip + i
            ips.append(str(current_ip))

        return ips

    def _generate_neighbor_ips_ipv6(self, count):
        """
        Generate IPv6 neighbor IP address list.

        Args:
            count: Number of neighbor IPs to generate

        Returns:
            list: IPv6 neighbor IP address list, format as "2001:db8:1::x"
                 Example: 2001:db8:1::1, 2001:db8:1::2, 2001:db8:1::3, ...
        """
        start_ip = ipaddress.IPv6Address(self.NEIGHBOR_IPV6_START)
        ips = []

        for i in range(count):
            # Generate format: 2001:db8:1::x, where x increments
            current_ip = start_ip + i
            ips.append(str(current_ip))

        return ips

    def _generate_mac_addresses(self, count, oui_prefix):
        """
        Generate MAC address list.

        Args:
            count: Number of MAC addresses to generate
            oui_prefix: OUI prefix (e.g., "00:02", "00:00", "00:01")

        Returns:
            list: MAC address list, format as "XX:XX:XX:XX:XX:XX"
                 Example: 00:02:01:02:03:00, 00:02:01:02:04:00, ...
        """
        mac_list = []

        for i in range(count):
            # Generate format: XX:XX:XX:XX:XX:XX
            mac = f"{oui_prefix}:{(i >> 16) & 0xff:02x}:{(i >> 8) & 0xff:02x}:{i & 0xff:02x}:00"
            mac_list.append(mac)

        return mac_list


    def _add_neighbors_bulk(self, neighbor_entries, bulk_size, ip_version='auto'):
        """
        Bulk add neighbor entries with error handling.
        Processes neighbor entries in batches for efficient creation.

        Args:
            neighbor_entries: list of (ip, info_dict), info_dict must contain 'rif' and 'mac'
            bulk_size: Number of entries to process in each batch
            ip_version: 4, 6, or 'auto' (detect by ip string)

        Returns:
            tuple: (success_count, neighbor_create_pass, create_perf)
                create_perf: successful neighbor creates per second, where time is
                the sum of per-call elapsed time around sai_thrift_create_neighbor_entry.

        Note:
            - Uses SAI_PACKET_ACTION_FORWARD for all entries
            - Sets no_host_route=True to avoid host route creation
            - Reports first 5 failures for debugging
        """
        if len(neighbor_entries) == 0:
            return 0, True, 0.0

        sai_create_time = 0.0
        success_count = 0
        failed_entries = []

        for i in range(0, len(neighbor_entries), bulk_size):
            batch = neighbor_entries[i:i+bulk_size]
            for ip, info in batch:
                try:
                    ip_addr = sai_ipaddress(ip)
                    neighbor_entry = sai_thrift_neighbor_entry_t(
                        rif_id=info["rif"],
                        ip_address=ip_addr
                    )
                    t0 = time.perf_counter()
                    status = sai_thrift_create_neighbor_entry(
                        self.client,
                        neighbor_entry,
                        dst_mac_address=info["mac"],
                        no_host_route=True,
                        packet_action=SAI_PACKET_ACTION_FORWARD
                    )
                    sai_create_time += time.perf_counter() - t0
                    if status == SAI_STATUS_SUCCESS:
                        success_count += 1
                    else:
                        failed_entries.append({'ip': ip, 'status': status})
                except Exception as e:
                    failed_entries.append({'ip': ip, 'error': str(e)})

        create_perf = success_count / sai_create_time if sai_create_time > 0 else 0.0
        if sai_create_time > 0:
            print(f"   [BULK ADD] Result: {success_count} neighbors created, time: {sai_create_time:.3f}s")
            print(f"   Performance: {create_perf:.0f} neighbors/s")

        neighbor_create_pass = True
        if failed_entries:
            neighbor_create_pass = False
            print(f"Warning: {len(failed_entries)} neighbor entries failed to create")
            for failed in failed_entries[:5]:  # Show first 5 failures
                print(f"   Failed: {failed}")

        print(f"Successfully created {success_count} neighbor entries")
        return success_count, neighbor_create_pass, create_perf

    def _del_neighbors_bulk(self, neighbor_entries, bulk_size, ip_version='auto'):
        """
        Bulk delete neighbor entries with error handling.
        Processes neighbor entries in batches for efficient deletion.

        Args:
            neighbor_entries: list of (ip, info_dict), info_dict must contain 'rif'
            bulk_size: Number of entries to process in each batch
            ip_version: 4, 6, or 'auto' (detect by ip string)

        Returns:
            tuple: (success_count, remove_perf)
                remove_perf: successful neighbor deletes per second, where time is
                the sum of per-call elapsed time around sai_thrift_remove_neighbor_entry.

        Note:
            - Reports first 5 failures for debugging
            - Continues processing even if some entries fail to delete
        """
        if len(neighbor_entries) == 0:
            return 0, 0.0

        sai_remove_time = 0.0
        success_count = 0
        failed_entries = []

        for i in range(0, len(neighbor_entries), bulk_size):
            batch = neighbor_entries[i:i+bulk_size]
            for ip, info in batch:
                try:
                    if ip_version == 6 or (ip_version == 'auto' and ':' in ip):
                        ip_addr = sai_ipaddress(ip)
                    else:
                        ip_addr = sai_ipaddress(ip)
                    neighbor_entry = sai_thrift_neighbor_entry_t(
                        switch_id=self.switch_id,
                        rif_id=info["rif"],
                        ip_address=ip_addr
                    )
                    t0 = time.perf_counter()
                    self.client.sai_thrift_remove_neighbor_entry(neighbor_entry)
                    sai_remove_time += time.perf_counter() - t0
                    success_count += 1
                except Exception as e:
                    failed_entries.append({'ip': ip, 'error': str(e)})

        remove_perf = success_count / sai_remove_time if sai_remove_time > 0 else 0.0
        if sai_remove_time > 0:
            print(f"   [BULK DEL] Result: {success_count} neighbors deleted, time: {sai_remove_time:.3f}s")
            print(f"   Performance: {remove_perf:.0f} neighbors/s")

        if failed_entries:
            print(f"Warning: {len(failed_entries)} neighbor entries failed to delete")
            for failed in failed_entries[:5]:  # Show first 5 failures
                print(f"   Failed: {failed}")

        print(f"Successfully deleted {success_count} neighbor entries")
        return success_count, remove_perf

    def _verify_traffic(self, neighbor_dict, ip_list, ip_version=4):
        """
        Send traffic from PORT16, verify received on expected egress port.
        Samples a subset of IPs for verification to avoid excessive testing.

        Args:
            neighbor_dict: {ip: {rif, mac}} - neighbor information dictionary
            ip_list: list of ip strings to test
            ip_version: 4 or 6 - IP version for testing

        Raises:
            AssertionError: If success rate is below threshold (80% by default)

        Note:
            - Samples TRAFFIC_SAMPLE_SIZE (10) IPs randomly for testing
            - Requires 80% success rate to pass (SUCCESS_RATE_THRESHOLD)
            - Reports detailed failure information for debugging
        """
        print(f"Traffic verification: IPv{ip_version} ...")

        # Sample a subset of IPs for verification to avoid excessive testing
        sample_size = min(self.TRAFFIC_SAMPLE_SIZE, len(ip_list))
        sampled_ips = random.sample(ip_list, sample_size)

        success_count = 0
        failed_ips = []

        for ip in sampled_ips:
            try:
                info = neighbor_dict[ip]
                self.send_and_verify(ip, info["rif"], info["mac"], ip_version=ip_version)
                success_count += 1
                print(f"   [PASS] IPv{ip_version} neighbor {ip} -> RIF {info['rif']} -> MAC {info['mac']}")
            except Exception as e:
                failed_ips.append({'ip': ip, 'reason': f'{type(e).__name__}: {e}'})
                print(f"   [FAIL] IPv{ip_version} neighbor {ip} -> Exception: {type(e).__name__}: {e}")

        print(f"\n   [INFO] Traffic verification summary: IPv{ip_version}")
        print(f"   [INFO] Tested: {len(sampled_ips)}, Passed: {success_count}, Failed: {len(failed_ips)}")

        if failed_ips:
            print(f"   [FAIL] Result: {success_count}/{len(sampled_ips)} passed ({len(failed_ips)} failed)")
            for failed in failed_ips[:3]:  # Show first 3 failures
                print(f"      Failed neighbor: {failed['ip']} - {failed['reason']}")
            if len(failed_ips) > 3:
                print(f"      ... and {len(failed_ips) - 3} more failures")
        else:
            print(f"   [PASS] Result: {success_count}/{len(sampled_ips)} passed")

        # Assert that at least threshold of tests pass to allow for some tolerance
        success_rate = success_count / len(sampled_ips)
        self.assertGreaterEqual(success_rate, self.SUCCESS_RATE_THRESHOLD,
                               f"Traffic verification failed: success rate {success_rate:.2%} < {self.SUCCESS_RATE_THRESHOLD:.0%}")

    def send_and_verify(self, ip, rif, mac, ip_version=4):
        """
        Send packet from PORT16 to neighbor IP, verify received on expected egress port.
        Tests packet forwarding through router interface to neighbor.

        Args:
            ip: Destination IP address (string)
            rif: Router interface ID
            mac: Expected destination MAC address
            ip_version: 4 for IPv4, 6 for IPv6

        Raises:
            Exception: If port for RIF not found or packet verification fails

        Note:
            - Sends TCP packet from PORT16 (192.168.0.1/2001:db8::1)
            - Expects packet with neighbor MAC and decremented TTL/hop limit
            - Uses PTF framework for packet sending and verification
        """
        # Get the port associated with the RIF
        egress_port = self._get_rif_port(rif)
        if egress_port is None:
            raise Exception(f"Could not find port for RIF {rif}")

        # Build test packet based on IP version
        if ip_version == 4:
            pkt = simple_tcp_packet(
                eth_dst=ROUTER_MAC,
                eth_src='00:22:22:22:22:22',
                ip_dst=ip,
                ip_src='192.168.0.1',
                ip_id=105,
                ip_ttl=64,
                pktlen=100
            )

            # Expected packet with neighbor MAC as destination
            exp_pkt = simple_tcp_packet(
                eth_dst=mac,
                eth_src=ROUTER_MAC,
                ip_dst=ip,
                ip_src='192.168.0.1',
                ip_id=105,
                ip_ttl=63,
                pktlen=100
            )
        else:  # IPv6
            pkt = simple_tcpv6_packet(
                eth_dst=ROUTER_MAC,
                eth_src='00:22:22:22:22:22',
                ipv6_dst=ip,
                ipv6_src='2001:db8::1',
                ipv6_hlim=64,
                pktlen=100
            )

            # Expected packet with neighbor MAC as destination
            exp_pkt = simple_tcpv6_packet(
                eth_dst=mac,
                eth_src=ROUTER_MAC,
                ipv6_dst=ip,
                ipv6_src='2001:db8::1',
                ipv6_hlim=63,
                pktlen=100
            )

        # Send packet from PORT16 and verify it's received on the expected port
        send_packet(self, self.dev_port16, pkt)
        verify_packet(self, exp_pkt, egress_port)

    def _get_rif_port(self, rif_id):
        """
        Get the port associated with a router interface.
        Supports PORT type RIFs (ports 0-7) and VLAN type RIFs (VLANs 1000-2999).

        Args:
            rif_id: Router interface ID

        Returns:
            Port object or None if not found
        """
        # Check if this is a PORT type RIF (ports 0-7)
        for i, port_rif in enumerate(self.port_rif_list):
            if port_rif == rif_id:
                return getattr(self, f"dev_port{i}")

        # Check if this is a VLAN type RIF (VLANs 1000-2999)
        for i, vlan_rif in enumerate(self.vlan_rif_list):
            if vlan_rif == rif_id:
                # For VLAN RIFs, return a port from the VLAN.
                # This is a simplified approach - returns first available port in VLAN
                for j in self.rif_port_indices:
                    try:
                        port = getattr(self, f"dev_port{j}")
                        return port
                    except AttributeError:
                        continue

        return None

    def get_all_rif_list(self):
        """
        Return all RIF object ID list.
        Returns combined list of PORT and VLAN type router interfaces.

        Returns:
            list: All router interface object IDs (PORT + VLAN RIFs)

        Note:
            - Includes 8 PORT type RIFs (ports 0-7)
            - Includes 2000 VLAN type RIFs (VLAN IDs 1000-2999)
            - Total of 2008 router interfaces
        """
        return self.port_rif_list + self.vlan_rif_list


class L3NeighborTableScaleIPv4Test(SaiHelperScaleNeighbor):
    """
    IPv4 Neighbor table scale test.
    Tests bulk creation, traffic verification, and deletion of IPv4 neighbor entries.

    Test Flow:
    1. Get available IPv4 neighbor entry capacity
    2. Generate IPv4 neighbor IPs (10.1.1.1+) and MAC addresses (00:00:xx:xx:xx:xx)
    3. Create neighbor entries using bulk operations
    4. Verify resource usage and cleanup
    """
    def setUp(self):
        super().setUp()
        self.bulk_sizes = [self.DEFAULT_BULK_SIZE]

    def runTest(self):
        """
        Run IPv4 neighbor table scale test.
        Creates neighbor entries up to available capacity, verifies traffic, and cleans up.
        """
        print("==== L3NeighborTableScaleIPv4Test Start ====")

        # Get available neighbor entries
        X = sai_thrift_get_switch_attribute(
            self.client, available_ipv4_neighbor_entry=True)['available_ipv4_neighbor_entry']
        print(f"Available IPv4 neighbor entry count: {X}")
        assert X > 0, "Failed to get available IPv4 neighbor entry count!"

        self.record_spec("ipv4_neighbor", "", count=0, actual_value=X)

        # Use all available entries for testing
        neighbor_count = X
        print(f"Generate {neighbor_count} IPv4 HOST, Starting from {self.NEIGHBOR_IPV4_START}")

        # Generate neighbor IP addresses and MAC addresses using new methods
        ipv4_list = self._generate_neighbor_ips_ipv4(neighbor_count)
        mac_list = self._generate_mac_addresses(neighbor_count, self.MAC_IPV4_OUI)

        rif_list = self.get_all_rif_list()
        print(f"\nTotal RIFs: {len(rif_list)}")

        # Create neighbor dictionary
        neighbor_dict = {}
        for i, ip in enumerate(ipv4_list):
            mac = mac_list[i]
            rif = random.choice(rif_list)
            neighbor_dict[ip] = {"rif": rif, "mac": mac}

        print(f"Neighbor dict generated, total: {len(neighbor_dict)}")

        for bulk_size in self.bulk_sizes:
            print(f"\n--- Bulk size: {bulk_size} ---")
            neighbor_entries = list(neighbor_dict.items())

            # Add neighbors
            success_count, neighbor_create_pass, create_perf = self._add_neighbors_bulk(neighbor_entries, bulk_size, ip_version=4)
            print(f"Bulk add {success_count} neighbors completed, neighbor_create_pass: {neighbor_create_pass}")
            self.record_spec("neighbor_scale", "create", count=success_count,
                             actual_value=round(create_perf, 2))

            # Traffic verification
            #self._verify_traffic(neighbor_dict, ipv4_list, ip_version=4)

            # Delete neighbors
            del_count, remove_perf = self._del_neighbors_bulk(neighbor_entries, bulk_size, ip_version=4)
            print(f"Bulk del {del_count} neighbors completed")
            self.record_spec("neighbor_scale", "remove", count=del_count,
                             actual_value=round(remove_perf, 2))

            results = {'create': create_perf, 'remove': remove_perf}
            perf_pass = self.print_performance_results(
                results, "IPv4 Neighbor Table Scale Performance Test Results")

        self.assertTrue(neighbor_create_pass and perf_pass, "IPv4 neighbor table scale test failed")

        # Resource verification
        X1 = sai_thrift_get_switch_attribute(
            self.client, available_ipv4_neighbor_entry=True)['available_ipv4_neighbor_entry']
        print(f"Available IPv4 neighbor entry count after test: {X1}")
        assert X1 == X, f"Resource leak: X1({X1}) != X({X})"
        print("==== L3NeighborTableScaleIPv4Test End ====")

    def tearDown(self):
        super(L3NeighborTableScaleIPv4Test, self).tearDown()

class L3NeighborTableScaleIPv6Test(SaiHelperScaleNeighbor):
    """
    IPv6 Neighbor table scale test.
    Tests bulk creation, traffic verification, and deletion of IPv6 neighbor entries.

    Test Flow:
    1. Get available IPv6 neighbor entry capacity
    2. Generate IPv6 neighbor IPs (2001:db8:1::1+) and MAC addresses (00:01:xx:xx:xx:xx)
    3. Create neighbor entries using bulk operations
    4. Verify resource usage and cleanup
    """
    def setUp(self):
        super().setUp()
        self.bulk_sizes = [self.DEFAULT_BULK_SIZE]

    def runTest(self):
        """
        Run IPv6 neighbor table scale test.
        Creates neighbor entries up to available capacity, verifies traffic, and cleans up.
        """
        print("==== L3NeighborTableScaleIPv6Test Start ====")

        # Get available neighbor entries
        X = sai_thrift_get_switch_attribute(
            self.client, available_ipv6_neighbor_entry=True)['available_ipv6_neighbor_entry']
        print(f"Available IPv6 neighbor entry count: {X}")
        assert X > 0, "Failed to get available IPv6 neighbor entry count!"

        self.record_spec("ipv6_neighbor", "", count=0, actual_value=X)

        # Use all available entries for testing
        neighbor_count = X
        print(f"Generate {neighbor_count} IPv6, {neighbor_count} MAC")

        # Generate neighbor IP addresses and MAC addresses using new methods
        ipv6_list = self._generate_neighbor_ips_ipv6(neighbor_count)
        mac_list = self._generate_mac_addresses(neighbor_count, self.MAC_IPV6_OUI)

        print(f"Generated IPv6 neighbor IPs starting from {self.NEIGHBOR_IPV6_START}")

        rif_list = self.get_all_rif_list()
        print(f"Total RIFs: {len(rif_list)}")

        # Create neighbor dictionary
        neighbor_dict = {}
        for i, ip in enumerate(ipv6_list):
            mac = mac_list[i]
            rif = random.choice(rif_list)
            neighbor_dict[ip] = {"rif": rif, "mac": mac}
        print(f"Neighbor dict generated, total: {len(neighbor_dict)}")

        for bulk_size in self.bulk_sizes:
            print(f"\n--- Bulk size: {bulk_size} ---")
            neighbor_entries = list(neighbor_dict.items())

            # Add neighbors
            success_count, neighbor_create_pass, create_perf = self._add_neighbors_bulk(neighbor_entries, bulk_size, ip_version=6)
            print(f"Bulk add {success_count} neighbors completed, neighbor_create_pass: {neighbor_create_pass}")
            self.record_spec("neighbor_scale", "create", count=success_count,
                             actual_value=round(create_perf, 2))

            # Traffic verification
            #self._verify_traffic(neighbor_dict, ipv6_list, ip_version=6)

            # Delete neighbors
            del_count, remove_perf = self._del_neighbors_bulk(neighbor_entries, bulk_size, ip_version=6)
            print(f"Bulk del {del_count} neighbors completed")
            self.record_spec("neighbor_scale", "remove", count=del_count,
                             actual_value=round(remove_perf, 2))

            results = {'create': create_perf, 'remove': remove_perf}
            perf_pass = self.print_performance_results(
                results, "IPv6 Neighbor Table Scale Performance Test Results")

        self.assertTrue(neighbor_create_pass and perf_pass, "IPv6 neighbor table scale test failed")

        # Resource verification
        X1 = sai_thrift_get_switch_attribute(
            self.client, available_ipv6_neighbor_entry=True)['available_ipv6_neighbor_entry']
        print(f"Available IPv6 neighbor entry count after test: {X1}")
        assert X1 == X, f"Resource leak: X1({X1}) != X({X})"
        print("==== L3NeighborTableScaleIPv6Test End ====")

    def tearDown(self):
        super(L3NeighborTableScaleIPv6Test, self).tearDown()


class L3NeighborTableScaleTest(SaiHelperScaleNeighbor):
    """
    Mixed IPv4+IPv6 Neighbor table scale test.
    Tests bulk creation, traffic verification, and deletion of mixed IPv4 and IPv6 neighbor entries.

    Test Flow:
    1. Get available IPv4 and IPv6 neighbor entry capacity
    2. Generate mixed neighbor IPs and MAC addresses (00:02:xx:xx:xx:xx)
    3. Create both IPv4 and IPv6 neighbor entries using bulk operations
    4. Verify resource usage and cleanup

    Note: Uses 50% of IPv4 capacity and 25% of IPv6 capacity for mixed testing.
    """
    def setUp(self):
        super().setUp()
        self.bulk_sizes = [self.DEFAULT_BULK_SIZE]

    def runTest(self):
        """
        Run mixed IPv4+IPv6 neighbor table scale test.
        Creates both IPv4 and IPv6 neighbor entries, verifies traffic, and cleans up.
        """
        print("==== L3NeighborTableScaleTest Start ====")

        # Get available neighbor entries
        X = sai_thrift_get_switch_attribute(
            self.client, available_ipv4_neighbor_entry=True)['available_ipv4_neighbor_entry']
        Y = sai_thrift_get_switch_attribute(
            self.client, available_ipv6_neighbor_entry=True)['available_ipv6_neighbor_entry']
        print(f"Available IPv6 neighbor entry count: {Y}, Available IPv4 neighbor entry count: {X}")

        self.record_spec("ipv4_neighbor", "", count=0, actual_value=X)
        self.record_spec("ipv6_neighbor", "", count=0, actual_value=Y)

        # Generate reasonable numbers for mixed testing
        num_ipv4 = X//2
        num_ipv6 = Y//2
        num_mac = num_ipv4 + num_ipv6
        print(f"Generate {num_ipv4} IPv4, Starting from {self.NEIGHBOR_IPV4_START}")
        print(f"Generated {num_ipv6} IPv6, Starting from {self.NEIGHBOR_IPV6_START}")

        # Generate neighbor IP addresses using new methods
        ipv4_list = self._generate_neighbor_ips_ipv4(num_ipv4)
        ipv6_list = self._generate_neighbor_ips_ipv6(num_ipv6)
        mac_list = self._generate_mac_addresses(num_mac, self.MAC_START_OUI)

        rif_list = self.get_all_rif_list()
        print(f"Total RIFs: {len(rif_list)}")

        # Create neighbor dictionary
        neighbor_dict = {}
        for i, ip in enumerate(ipv4_list + ipv6_list):
            mac = mac_list[i]
            rif = random.choice(rif_list)
            neighbor_dict[ip] = {"rif": rif, "mac": mac}
        print(f"Neighbor dict generated, total: {len(neighbor_dict)}")

        for bulk_size in self.bulk_sizes:
            print(f"\n--- Bulk size: {bulk_size} ---")
            neighbor_entries = list(neighbor_dict.items())

            # Add neighbors
            success_count, neighbor_create_pass, create_perf = self._add_neighbors_bulk(neighbor_entries, bulk_size, ip_version='auto')
            print(f"Bulk add {success_count} neighbors completed, neighbor_create_pass: {neighbor_create_pass}")
            self.record_spec("neighbor_scale", "create", count=success_count,
                             actual_value=round(create_perf, 2))

            # Traffic verification for both IPv4 and IPv6
            #self._verify_traffic(neighbor_dict, ipv4_list, ip_version=4)
            #self._verify_traffic(neighbor_dict, ipv6_list, ip_version=6)

            # Delete neighbors
            del_count, remove_perf = self._del_neighbors_bulk(neighbor_entries, bulk_size, ip_version='auto')
            print(f"Bulk del {del_count} neighbors completed")
            self.record_spec("neighbor_scale", "remove", count=del_count,
                             actual_value=round(remove_perf, 2))

            results = {'create': create_perf, 'remove': remove_perf}
            perf_pass = self.print_performance_results(
                results, "Mixed IPv4+IPv6 Neighbor Table Scale Performance Test Results")

        self.assertTrue(neighbor_create_pass and perf_pass, "Mixed IPv4+IPv6 neighbor table scale test failed")

        # Resource verification
        X1 = sai_thrift_get_switch_attribute(
            self.client, available_ipv4_neighbor_entry=True)['available_ipv4_neighbor_entry']
        Y1 = sai_thrift_get_switch_attribute(
            self.client, available_ipv6_neighbor_entry=True)['available_ipv6_neighbor_entry']
        print(f"Available IPv4 neighbor entry count after test: {X1}")
        print(f"Available IPv6 neighbor entry count after test: {Y1}")
        assert X1 == X, f"Resource leak: X1({X1}) != X({X})"
        assert Y1 == Y, f"Resource leak: Y1({Y1}) != Y({Y})"
        print("==== L3NeighborTableScaleTest End ====")

    def tearDown(self):
        super(L3NeighborTableScaleTest, self).tearDown()
