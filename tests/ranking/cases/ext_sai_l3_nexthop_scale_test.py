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

class SaiHelperScaleNexthop(SaiHelperScaleL3):
    """
    Base class for nexthop table scale and performance tests.
    Provides common nexthop bulk add/delete and traffic verification methods.
    """

    # Route prefix address range configuration - for route table entries
    ROUTE_PREFIX_IPV4_START = "192.168.1.0"  # Route prefix start: 192.168.1.0/24
    ROUTE_PREFIX_IPV4_NETWORK = "192.168.0.0/16"  # Route prefix network segment

    ROUTE_PREFIX_IPV6_START = "2001:db8:100::"  # Route prefix start: 2001:db8:100::/64
    ROUTE_PREFIX_IPV6_NETWORK = "2001:db8:100::/64"  # Route prefix network segment

    # Nexthop IP address range configuration - for nexthop table entries
    NEXTHOP_IPV4_START = "10.1.1.1"  # Nexthop IP start: 10.1.1.1
    NEXTHOP_IPV4_NETWORK = "10.1.0.0/16"  # Nexthop IP network segment

    NEXTHOP_IPV6_START = "2001:db8:1::1"  # Nexthop IP start: 2001:db8:1::1
    NEXTHOP_IPV6_NETWORK = "2001:db8:1::/64"  # Nexthop IP network segment
    NEXTHOP_DST_MAC = "00:11:22:33:44:55"

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
        super(SaiHelperScaleNexthop, self).setUp()

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
                "MLNX nexthop scale bridge port indices: "
                f"{rif_port_indices}")

        # Reuse Broadcom's default PORT bridge ports when present.
        port_to_bp = self._get_default_port_bridge_port_map()
        self.rif_port_bp_list = []
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

        super(SaiHelperScaleNexthop, self).tearDown()


    def _generate_route_prefixes_ipv4(self, count):
        """
        Generate IPv4 route prefix list

        Args:
            count: Number of route prefixes to generate

        Returns:
            list: IPv4 route prefix list, format as "192.168.x.0/24"
        """
        start_ip = ipaddress.IPv4Address(self.ROUTE_PREFIX_IPV4_START)
        prefixes = []

        for i in range(count):
            # Generate format: 192.168.x.0/24, where x increments
            # Example: 192.168.1.0/24, 192.168.2.0/24, 192.168.3.0/24, ...
            current_ip = start_ip + (i * 256)  # Each prefix is separated by 256 addresses
            prefixes.append(f"{current_ip}/24")

        return prefixes

    def _generate_route_prefixes_ipv6(self, count):
        """
        Generate IPv6 route prefix list

        Args:
            count: Number of route prefixes to generate

        Returns:
            list: IPv6 route prefix list, format as "2001:db8:100::x/64"
        """
        start_ip = ipaddress.IPv6Address(self.ROUTE_PREFIX_IPV6_START)
        prefixes = []

        for i in range(count):
            # Generate format: 2001:db8:100::x/64, where x increments
            # Example: 2001:db8:100::/64, 2001:db8:101::/64, 2001:db8:102::/64, ...
            current_ip = start_ip + (i * (2**64))  # Each prefix is separated by 2^64 addresses
            prefixes.append(f"{current_ip}/64")

        return prefixes

    def _generate_nexthop_ips_ipv4(self, count):
        """
        Generate IPv4 nexthop IP address list

        Args:
            count: Number of nexthop IPs to generate

        Returns:
            list: IPv4 nexthop IP address list, format as "10.1.x.y"
        """
        start_ip = ipaddress.IPv4Address(self.NEXTHOP_IPV4_START)
        ips = []

        for i in range(count):
            # Generate format: 10.1.x.y, where x and y increment
            # Example: 10.1.1.1, 10.1.1.2, 10.1.1.3, ..., 10.1.2.1, ...
            current_ip = start_ip + i
            ips.append(str(current_ip))

        return ips

    def _generate_nexthop_ips_ipv6(self, count):
        """
        Generate IPv6 nexthop IP address list

        Args:
            count: Number of nexthop IPs to generate

        Returns:
            list: IPv6 nexthop IP address list, format as "2001:db8:1::x"
        """
        start_ip = ipaddress.IPv6Address(self.NEXTHOP_IPV6_START)
        ips = []

        for i in range(count):
            # Generate format: 2001:db8:1::x, where x increments
            # Example: 2001:db8:1::1, 2001:db8:1::2, 2001:db8:1::3, ...
            current_ip = start_ip + i
            ips.append(str(current_ip))

        return ips

    def _create_nexthops(self, nexthop_entries):
        for nh in nexthop_entries:
            nbr_entry = sai_thrift_neighbor_entry_t(
                rif_id=nh['rif'],
                ip_address=sai_ipaddress(nh['ip']))
            sai_thrift_create_neighbor_entry(
                self.client, nbr_entry, dst_mac_address=self.NEXTHOP_DST_MAC)
            nh['nbr_entry'] = nbr_entry

        start_time = time.perf_counter()
        success_count = 0
        for nh in nexthop_entries:
            nh_id = sai_thrift_create_next_hop(
                self.client,
                type=nh['type'],
                router_interface_id=nh['rif'],
                ip=sai_ipaddress(nh['ip'])
            )
            if isinstance(nh_id, int) and nh_id != SAI_NULL_OBJECT_ID:
                nh['nh_id'] = nh_id
                success_count += 1
            else:
                nh['nh_id'] = None
        total_time = time.perf_counter() - start_time

        perf = success_count / total_time if total_time > 0 else 0.0
        self.record_spec("nexthop_scale", "create",
                         count=len(nexthop_entries),
                         actual_value=round(perf, 2),
                         duration=round(total_time, 3))

    def _remove_nexthops(self, nexthop_entries):
        valid = [nh for nh in nexthop_entries
                 if isinstance(nh.get('nh_id'), int)
                 and nh['nh_id'] != SAI_NULL_OBJECT_ID]
        start_time = time.perf_counter()
        for nh in valid:
            sai_thrift_remove_next_hop(self.client, nh['nh_id'])
        total_time = time.perf_counter() - start_time

        perf = len(valid) / total_time if total_time > 0 else 0.0
        self.record_spec("nexthop_scale", "remove",
                         count=len(valid),
                         actual_value=round(perf, 2),
                         duration=round(total_time, 3))

        for nh in nexthop_entries:
            nbr_entry = nh.get('nbr_entry')
            if nbr_entry is None:
                continue
            try:
                sai_thrift_remove_neighbor_entry(self.client, nbr_entry)
            except Exception as e:
                print(f"Warning: Failed to remove neighbor for "
                      f"{nh.get('ip')}: {e}")

    def _verify_traffic(self, route_entries):
        # Pseudo code: should be implemented according to PTF/SAI environment
        # Send packets from PORT16, verify received on expected egress port
        pass

    def get_all_rif_list(self):
        return self.port_rif_list + self.vlan_rif_list

class L3IPv4NexthopScaleTest(SaiHelperScaleNexthop):
    """
    IPv4 Nexthop table scale and performance test
    """
    def setUp(self):
        super().setUp()
        self.bulk_size = 1000
        # Skip syslog verify for this test
        self.skip_syslog_verify = True


    def runTest(self):
        """
        Test IPv4 nexthop scale.

        This test performs the following steps:
        1. Determines the maximum number of nexthops the device supports.
        2. Creates the maximum number of nexthops, each associated with a random RIF.
        3. Prepares route entries, each pointing to a randomly selected nexthop.
        4. Performs bulk creation and removal of the routes.
        5. Cleans up all created nexthops.
        6. Verifies that all nexthop resources are correctly released.
        """
        print("\n==== L3IPv4NexthopScaleTest Start ====")

        # Routes here are only a vehicle for the nexthop test; the base bulk
        # route helpers record self._spec_name, so tag them as incidental.
        self._spec_name = "nexthop_route_scale"

        # Step 1: Determine the test scale based on available device resources.
        initial_nh_count = sai_thrift_get_switch_attribute(
            self.client, available_ipv4_nexthop_entry=True)['available_ipv4_nexthop_entry']
        available_route_count = sai_thrift_get_switch_attribute(
            self.client, available_ipv4_route_entry=True)['available_ipv4_route_entry']
        available_neighbor_count = sai_thrift_get_switch_attribute(
            self.client, available_ipv4_neighbor_entry=True)['available_ipv4_neighbor_entry']

        self.record_spec("ipv4_nexthop", "", count=0,
                         actual_value=initial_nh_count)

        nexthop_count_to_test = min(initial_nh_count,
                                    available_neighbor_count)
        route_count_to_test = min(nexthop_count_to_test, available_route_count)

        print(f"Device supports {initial_nh_count} IPv4 nexthop entries.")
        print(f"Testing with {nexthop_count_to_test} nexthops and {route_count_to_test} routes.")

        # Step 2: Generate and create nexthop entries.
        nexthop_ips = self._generate_nexthop_ips_ipv4(nexthop_count_to_test)
        rif_list = self.get_all_rif_list()
        nexthop_entries = []
        for ip in nexthop_ips:
            nexthop_entries.append({
                'type': SAI_NEXT_HOP_TYPE_IP,
                'rif': random.choice(rif_list),
                'ip': ip
            })

        self._create_nexthops(nexthop_entries)
        print(f"Successfully created {len(nexthop_entries)} nexthops.")

        # Step 3: Prepare route entries, associating each route with a random nexthop.
        route_prefixes = self.generate_ipv4_prefixes(24, start_ip="192.168.0.0", count=route_count_to_test)

        self.route_nh_map.clear()
        route_entries = []

        nexthop_oid_list = [
            nh['nh_id'] for nh in nexthop_entries
            if isinstance(nh.get('nh_id'), int)
            and nh['nh_id'] != SAI_NULL_OBJECT_ID]

        if not nexthop_oid_list:
            print("Warning: No nexthops were created. Skipping route operations.")
        else:
            print("Associating routes with random nexthops...")
            for prefix in route_prefixes:
                selected_nh_oid = random.choice(nexthop_oid_list)

                route_entry = sai_thrift_route_entry_t(
                    vr_id=self.default_vrf,
                    destination=sai_ipprefix(prefix)
                )
                route_entries.append(route_entry)
                self.route_nh_map[prefix] = {'nh': selected_nh_oid}
            print(f"Constructed {len(route_entries)} route entries.")

        try:
            # Step 4: Bulk create and then remove routes if any were prepared.
            if route_entries:
                self.bulk_create_routes(route_entries, self.bulk_size)
                #import pdb; pdb.set_trace()
                # self.verify_traffic() # Optional traffic verification can be added here
                self.bulk_remove_routes(route_entries, self.bulk_size)
        finally:
            # Step 5: Clean up all created nexthops to ensure resource release.
            self._remove_nexthops(nexthop_entries)
            print(f"Cleaned up {len(nexthop_entries)} nexthops.")

        # Step 6: Verify nexthop resource recovery.
        final_nh_count = sai_thrift_get_switch_attribute(
            self.client, available_ipv4_nexthop_entry=True)['available_ipv4_nexthop_entry']
        print(f"Available IPv4 nexthop entries after cleanup: {final_nh_count}")
        self.assertEqual(final_nh_count, initial_nh_count,
                         f"Nexthop resource leak detected: initial={initial_nh_count}, final={final_nh_count}")

        print("==== L3IPv4NexthopScaleTest End ====")

    def tearDown(self):
        super(L3IPv4NexthopScaleTest, self).tearDown()


class L3IPv6NexthopScaleTest(SaiHelperScaleNexthop):
    """
    IPv6 Nexthop table scale and performance test
    """
    def setUp(self):
        super().setUp()
        self.bulk_size = 1000
        # Skip syslog verify for this test
        self.skip_syslog_verify = True


    def runTest(self):
        """
        Test IPv6 nexthop scale.

        This test performs the following steps:
        1. Determines the maximum number of nexthops the device supports.
        2. Creates the maximum number of nexthops, each associated with a random RIF.
        3. Prepares route entries, each pointing to a randomly selected nexthop.
        4. Performs bulk creation and removal of the routes.
        5. Cleans up all created nexthops.
        6. Verifies that all nexthop resources are correctly released.
        """
        print("\n==== L3IPv6NexthopScaleTest Start ====")

        # Routes here are only a vehicle for the nexthop test; the base bulk
        # route helpers record self._spec_name, so tag them as incidental.
        self._spec_name = "nexthop_route_scale"

        # Step 1: Determine the test scale based on available device resources.
        initial_nh_count = sai_thrift_get_switch_attribute(
            self.client, available_ipv6_nexthop_entry=True)['available_ipv6_nexthop_entry']
        available_route_count = sai_thrift_get_switch_attribute(
            self.client, available_ipv6_route_entry=True)['available_ipv6_route_entry']
        available_neighbor_count = sai_thrift_get_switch_attribute(
            self.client, available_ipv6_neighbor_entry=True)['available_ipv6_neighbor_entry']

        self.record_spec("ipv6_nexthop", "", count=0,
                         actual_value=initial_nh_count)

        nexthop_count_to_test = min(initial_nh_count,
                                    available_neighbor_count)
        route_count_to_test = min(nexthop_count_to_test, available_route_count)

        print(f"Device supports {initial_nh_count} IPv6 nexthop entries.")
        print(f"Testing with {nexthop_count_to_test} nexthops and {route_count_to_test} routes.")

        # Step 2: Generate and create nexthop entries.
        nexthop_ips = self._generate_nexthop_ips_ipv6(nexthop_count_to_test)
        rif_list = self.get_all_rif_list()
        nexthop_entries = []
        for ip in nexthop_ips:
            nexthop_entries.append({
                'type': SAI_NEXT_HOP_TYPE_IP,
                'rif': random.choice(rif_list),
                'ip': ip
            })

        self._create_nexthops(nexthop_entries)
        print(f"Successfully created {len(nexthop_entries)} nexthops.")

        # Step 3: Prepare route entries, associating each route with a random nexthop.
        route_prefixes = self.generate_ipv6_prefixes(64, start_ip="2001:db8::", count=route_count_to_test)

        self.route_nh_map.clear()
        route_entries = []

        nexthop_oid_list = [
            nh['nh_id'] for nh in nexthop_entries
            if isinstance(nh.get('nh_id'), int)
            and nh['nh_id'] != SAI_NULL_OBJECT_ID]

        if not nexthop_oid_list:
            print("Warning: No nexthops were created. Skipping route operations.")
        else:
            print("Associating routes with random nexthops...")
            for prefix in route_prefixes:
                selected_nh_oid = random.choice(nexthop_oid_list)

                route_entry = sai_thrift_route_entry_t(
                    vr_id=self.default_vrf,
                    destination=sai_ipprefix(prefix)
                )
                route_entries.append(route_entry)
                self.route_nh_map[prefix] = {'nh': selected_nh_oid}
            print(f"Constructed {len(route_entries)} route entries.")

        try:
            # Step 4: Bulk create and then remove routes if any were prepared.
            if route_entries:
                self.bulk_create_routes(route_entries, self.bulk_size)
                #import pdb; pdb.set_trace()
                # self.verify_traffic() # Optional traffic verification can be added here
                self.bulk_remove_routes(route_entries, self.bulk_size)
        finally:
            # Step 5: Clean up all created nexthops to ensure resource release.
            self._remove_nexthops(nexthop_entries)
            print(f"Cleaned up {len(nexthop_entries)} nexthops.")

        # Step 6: Verify nexthop resource recovery.
        final_nh_count = sai_thrift_get_switch_attribute(
            self.client, available_ipv6_nexthop_entry=True)['available_ipv6_nexthop_entry']
        print(f"Available IPv6 nexthop entries after cleanup: {final_nh_count}")
        self.assertEqual(final_nh_count, initial_nh_count,
                         f"Nexthop resource leak detected: initial={initial_nh_count}, final={final_nh_count}")

        print("==== L3IPv6NexthopScaleTest End ====")

    def tearDown(self):
        super(L3IPv6NexthopScaleTest, self).tearDown()

class L3IPv4IPv6NexthopScaleTest(SaiHelperScaleNexthop):
    """
    IPv4+IPv6 Nexthop table scale and performance test
    """
    def setUp(self):
        super().setUp()
        self.bulk_size = 1000
        # Skip syslog verify for this test
        self.skip_syslog_verify = True


    def runTest(self):
        """
        Test mixed IPv4 and IPv6 nexthop scale.

        This test performs the following steps:
        1. Determines the test scale, using half of the available nexthop resources for each IP version.
        2. Creates the calculated number of IPv4 and IPv6 nexthops.
        3. Prepares a mixed list of IPv4 and IPv6 route entries, each pointing to a random nexthop.
        4. Performs bulk creation and removal of the mixed routes.
        5. Cleans up all created nexthops.
        6. Verifies that all nexthop resources for both IP versions are correctly released.
        """
        print("\n==== L3IPv4IPv6NexthopScaleTest Start ====")

        # Routes here are only a vehicle for the nexthop test; the base bulk
        # route helpers record self._spec_name, so tag them as incidental.
        self._spec_name = "nexthop_route_scale"

        # Step 1: Determine the test scale for both IPv4 and IPv6.
        initial_ipv4_nh_count = sai_thrift_get_switch_attribute(
            self.client, available_ipv4_nexthop_entry=True)['available_ipv4_nexthop_entry']
        initial_ipv6_nh_count = sai_thrift_get_switch_attribute(
            self.client, available_ipv6_nexthop_entry=True)['available_ipv6_nexthop_entry']

        self.record_spec("ipv4_nexthop", "", count=0,
                         actual_value=initial_ipv4_nh_count)
        self.record_spec("ipv6_nexthop", "", count=0,
                         actual_value=initial_ipv6_nh_count)

        available_ipv4_neighbor = sai_thrift_get_switch_attribute(
            self.client, available_ipv4_neighbor_entry=True)['available_ipv4_neighbor_entry']
        available_ipv6_neighbor = sai_thrift_get_switch_attribute(
            self.client, available_ipv6_neighbor_entry=True)['available_ipv6_neighbor_entry']

        # Use half of the available nexthops for each IP version to avoid resource exhaustion.
        ipv4_nexthop_count_to_test = min(
            initial_ipv4_nh_count // 2, available_ipv4_neighbor)
        ipv6_nexthop_count_to_test = min(
            initial_ipv6_nh_count // 2, available_ipv6_neighbor)

        ipv4_route_count_to_test = min(ipv4_nexthop_count_to_test, self.init_ipv4_route_count)
        ipv6_route_count_to_test = min(ipv6_nexthop_count_to_test, self.init_ipv6_route_count)

        print(f"Testing with {ipv4_nexthop_count_to_test} IPv4 nexthops and {ipv4_route_count_to_test} IPv4 routes.")
        print(f"Testing with {ipv6_nexthop_count_to_test} IPv6 nexthops and {ipv6_route_count_to_test} IPv6 routes.")

        # Step 2: Generate and create both IPv4 and IPv6 nexthop entries.
        nexthop_ips_v4 = self._generate_nexthop_ips_ipv4(ipv4_nexthop_count_to_test)
        nexthop_ips_v6 = self._generate_nexthop_ips_ipv6(ipv6_nexthop_count_to_test)

        rif_list = self.get_all_rif_list()
        all_nexthop_entries = []
        for ip in nexthop_ips_v4:
            all_nexthop_entries.append({'type': SAI_NEXT_HOP_TYPE_IP, 'rif': random.choice(rif_list), 'ip': ip})
        for ip in nexthop_ips_v6:
            all_nexthop_entries.append({'type': SAI_NEXT_HOP_TYPE_IP, 'rif': random.choice(rif_list), 'ip': ip})

        self._create_nexthops(all_nexthop_entries)
        print(f"Successfully created {len(all_nexthop_entries)} mixed nexthops.")

        # Step 3: Prepare mixed route entries with random nexthop assignment.
        route_prefixes_v4 = self.generate_ipv4_prefixes(24, start_ip="192.168.0.0", count=ipv4_route_count_to_test)
        route_prefixes_v6 = self.generate_ipv6_prefixes(64, start_ip="2001:db8::", count=ipv6_route_count_to_test)
        all_route_prefixes = route_prefixes_v4 + route_prefixes_v6

        self.route_nh_map.clear()
        route_entries = []

        nexthop_oid_list = [
            nh['nh_id'] for nh in all_nexthop_entries
            if isinstance(nh.get('nh_id'), int)
            and nh['nh_id'] != SAI_NULL_OBJECT_ID]

        if not nexthop_oid_list:
            print("Warning: No nexthops were created. Skipping route operations.")
        else:
            print("Associating routes with random nexthops...")
            for prefix in all_route_prefixes:
                selected_nh_oid = random.choice(nexthop_oid_list)
                route_entry = sai_thrift_route_entry_t(vr_id=self.default_vrf, destination=sai_ipprefix(prefix))
                route_entries.append(route_entry)
                self.route_nh_map[prefix] = {'nh': selected_nh_oid}
            print(f"Constructed {len(route_entries)} mixed route entries.")

        try:
            # Step 4: Bulk create and then remove routes if any were prepared.
            if route_entries:
                self.bulk_create_routes(route_entries, self.bulk_size)
                # self.verify_traffic() # Optional traffic verification can be added here
                self.bulk_remove_routes(route_entries, self.bulk_size)
        finally:
            # Step 5: Clean up all created nexthops to ensure resource release.
            self._remove_nexthops(all_nexthop_entries)
            print(f"Cleaned up {len(all_nexthop_entries)} nexthops.")

        # Step 6: Verify resource recovery for both IP versions.
        final_ipv4_nh_count = sai_thrift_get_switch_attribute(
            self.client, available_ipv4_nexthop_entry=True)['available_ipv4_nexthop_entry']
        final_ipv6_nh_count = sai_thrift_get_switch_attribute(
            self.client, available_ipv6_nexthop_entry=True)['available_ipv6_nexthop_entry']

        print(f"Available IPv4 nexthop entries after cleanup: {final_ipv4_nh_count}")
        print(f"Available IPv6 nexthop entries after cleanup: {final_ipv6_nh_count}")

        self.assertEqual(final_ipv4_nh_count, initial_ipv4_nh_count,
                         f"IPv4 Nexthop resource leak: initial={initial_ipv4_nh_count}, final={final_ipv4_nh_count}")
        self.assertEqual(final_ipv6_nh_count, initial_ipv6_nh_count,
                         f"IPv6 Nexthop resource leak: initial={initial_ipv6_nh_count}, final={final_ipv6_nh_count}")

        print("==== L3IPv4IPv6NexthopScaleTest End ====")

    def tearDown(self):
        super(L3IPv4IPv6NexthopScaleTest, self).tearDown()
