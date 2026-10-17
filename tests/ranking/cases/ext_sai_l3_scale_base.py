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
#
# The below software in this distribution may have been modified
# by Centec . All Centec Modifications
# are copyright © Centec(Suzhou) Technology Limited.
#

"""
SAI L3 Scale Test Base Module
Provides topology configuration and common test methods for L3 scale testing
"""

from sai_thrift.sai_headers import *
from ptf.testutils import *
from sai_base_test import *
import time
import random
import ipaddress


class SaiHelperScaleL3(PlatformSaiHelper):
    """Large-scale route test topology base class
    Configuration description:
    1. Use 17 ports (Port0-Port16)
    2. Create 8 sub-interfaces for each of the first 16 ports (VLAN 100-800)
    3. Configure IPv4/IPv6 routes, neighbors and next hops for each sub-interface
    4. Record all configurations in dictionaries for test case usage
    """

    def setUp(self):
        super(SaiHelperScaleL3, self).setUp()

        self.support_route_bulk_api = True
        print(f"\n  Bulk route API support: {self.support_route_bulk_api}\n")

        # Get current configurable IPv4 and IPv6 route counts
        self.init_ipv4_route_count = sai_thrift_get_switch_attribute(
            self.client, available_ipv4_route_entry=True)['available_ipv4_route_entry']
        self.init_ipv6_route_count = sai_thrift_get_switch_attribute(
            self.client, available_ipv6_route_entry=True)['available_ipv6_route_entry']
        print("Available IPv4 route entries: {}".format(self.init_ipv4_route_count) + ", IPv6 route entries: {}".format(self.init_ipv6_route_count))

        self.record_spec("ipv4_prefix", "", count=0,
                         actual_value=self.init_ipv4_route_count)
        self.record_spec("ipv6_prefix", "", count=0,
                         actual_value=self.init_ipv6_route_count)

        self.bulk_sizes = [4000, 8000, 16000, 20000, 32000]  # Bulk size list to test
        self.load_factor_bulk_size = 20000  # Bulk size for load factor test

        # Initialize configuration dictionaries
        self.sub_port_map = {}    # {port_id: [sub_port_id_list]}
        self.rif_info = {}        # {rif_id: {'port': port_id, 'vlan': vlan_id}}
        self.nh_v4_dict = {}      # {nh_index: {'port': port_id, 'ip': ipv4, 'rif': rif_id, 'nh': nh_id, 'mac': mac, 'vlan': vlan}}
        self.nh_v6_dict = {}      # {nh_index: {'port': port_id, 'ip': ipv6, 'rif': rif_id, 'nh': nh_id}}
        self.rif_list = []
        self.route_nh_map = {}
        self.subif_vlan_list = []
        self.expected_load_factor = 0.85  # Expected load factor 85%
        self.created_route_entries = []
        self._spec_name = "ipv4_route_scale"

        try:
            if 'test_case' in self.test_params:
                if self.test_params['test_case'] == 'Counter':
                    print("counter stress test in ptf64 env")
                    # self._create_counter_topology()
                else:
                    self._create_topology()
            else:
                self._create_topology()

        except Exception as e:
            self.tearDown()
            raise Exception(f"Failed to create topology: {e}")

    def _create_topology(self):
        """Create large-scale route test topology"""
        print("Creating large-scale L3 topology...")
        self.subif_vlan_list = [100, 200, 300, 400, 500, 600, 700, 800]

        nh_idx_v4 = 0  # IPv4 next hop index
        nh_idx_v6 = 0  # IPv6 next hop index

        # Iterate through the first 16 ports
        for port_idx in range(0, 16):
            port = self.port_list[port_idx]
            self.sub_port_map[port] = []

            # Create 8 sub-interfaces for each port
            for vlan in self.subif_vlan_list:
                # Create sub-interface
                sub_port = sai_thrift_create_router_interface(
                    self.client,
                    type=SAI_ROUTER_INTERFACE_TYPE_SUB_PORT,
                    port_id=port,
                    virtual_router_id=self.default_vrf,
                    admin_v4_state=True,
                    admin_v6_state=True,
                    outer_vlan_id=vlan)
                self.assertNotEqual(sub_port, SAI_NULL_OBJECT_ID)
                self.rif_list.append(sub_port)

                self.sub_port_map[port].append(sub_port)
                self.rif_info[sub_port] = {
                    'port': port_idx,
                    'vlan': vlan
                }

                # Configure IPv4 routes, neighbors and next hops
                ipv4_addr = f"10.{port_idx}.{vlan//100}.1"
                mac_addr = f"00:11:22:33:{port_idx:02x}:{vlan//100:02x}"

                # Create neighbor
                nbr_entry = sai_thrift_neighbor_entry_t(
                    rif_id=sub_port,
                    ip_address=sai_ipaddress(ipv4_addr))
                sai_thrift_create_neighbor_entry(
                    self.client,
                    nbr_entry,
                    dst_mac_address=mac_addr)

                # Create next hop
                nhop = sai_thrift_create_next_hop(
                    self.client,
                    type=SAI_NEXT_HOP_TYPE_IP,
                    router_interface_id=sub_port,
                    ip=sai_ipaddress(ipv4_addr))
                self.assertNotEqual(nhop, SAI_NULL_OBJECT_ID)

                self.nh_v4_dict[nh_idx_v4] = {
                    'port': port_idx,
                    'ip': ipv4_addr,
                    'rif': sub_port,
                    'nh': nhop,
                    'mac': mac_addr,
                    'vlan': vlan
                }
                nh_idx_v4 += 1

                # Configure IPv6 routes, neighbors and next hops
                ipv6_addr = f"2001:{port_idx}:{vlan}::1"

                # Create neighbor
                nbr_entry = sai_thrift_neighbor_entry_t(
                    rif_id=sub_port,
                    ip_address=sai_ipaddress(ipv6_addr))
                sai_thrift_create_neighbor_entry(
                    self.client,
                    nbr_entry,
                    dst_mac_address=mac_addr)

                # Create next hop
                nhop = sai_thrift_create_next_hop(
                    self.client,
                    type=SAI_NEXT_HOP_TYPE_IP,
                    router_interface_id=sub_port,
                    ip=sai_ipaddress(ipv6_addr))
                self.assertNotEqual(nhop, SAI_NULL_OBJECT_ID)

                self.nh_v6_dict[nh_idx_v6] = {
                    'port': port_idx,
                    'ip': ipv6_addr,
                    'rif': sub_port,
                    'nh': nhop,
                    'mac': mac_addr,
                    'vlan': vlan
                }
                nh_idx_v6 += 1

        print("Topology creation completed")
        print(f"   Sub-interfaces: {len(self.rif_info)}")
        print(f"   IPv4 next-hops: {len(self.nh_v4_dict)}")
        print(f"   IPv6 next-hops: {len(self.nh_v6_dict)}")

    def _create_counter_topology(self):
        """Create large-scale counter test topology"""
        print("Creating large-scale L3 topology...")
        nh_idx_v4 = 0  # IPv4 next hop index

        # Iterate through the first 16 ports
        for port_idx in range(0, 128):

            port = self.port_list[port_idx]
            print(f"port {port} index{port_idx}")
            port_rif = sai_thrift_create_router_interface(
                self.client,
                type=SAI_ROUTER_INTERFACE_TYPE_PORT,
                virtual_router_id=self.default_vrf,
                port_id=port)
            self.assertEqual(self.status(), SAI_STATUS_SUCCESS)
            setattr(self, "port%s_rif" % port_idx, port_rif)
            self.rif_list.append(port_rif)


            # Configure IPv4 routes, neighbors and next hops
            ipv4_addr = f"10.{port_idx}.{port_idx//100}.1"
            mac_addr = f"00:11:22:33:{port_idx:02x}:{port_idx//100:02x}"

            # Create neighbor
            nbr_entry = sai_thrift_neighbor_entry_t(
                rif_id=port_rif,
                ip_address=sai_ipaddress(ipv4_addr))
            sai_thrift_create_neighbor_entry(
                self.client,
                nbr_entry,
                dst_mac_address=mac_addr)

            # Create next hop
            nhop = sai_thrift_create_next_hop(
                self.client,
                type=SAI_NEXT_HOP_TYPE_IP,
                router_interface_id=port_rif,
                ip=sai_ipaddress(ipv4_addr))
            self.assertNotEqual(nhop, SAI_NULL_OBJECT_ID)

            ip_addr_subnet = f"10.10.{port_idx}.0/24"
            route_entry = sai_thrift_route_entry_t(
            vr_id=self.default_vrf, destination=sai_ipprefix(
                ip_addr_subnet))
            sai_thrift_create_route_entry(self.client, route_entry,
                                        next_hop_id=nhop)

            self.nh_v4_dict[nh_idx_v4] = {
                'port': port_idx,
                'rif':port_rif,
                'ip': ip_addr_subnet,
                'nh': nhop
            }
            nh_idx_v4 += 1

        print("Topology creation completed")
        print(f"   router-interfaces: {len(self.rif_list)}")
        print(f"   IPv4 next-hops: {len(self.nh_v4_dict)}")


    def tearDown(self):
        """Clean up topology configuration

        Removes all created SAI objects in reverse order:
        1. IPv4 and IPv6 neighbors and next hops
        2. Router interfaces (sub-interfaces)
        3. Base class cleanup
        """
        print("\nCleaning up large-scale L3 topology...")

        # Remove IPv4 neighbors and next hops
        for nh_info in self.nh_v4_dict.values():
            nbr_entry = sai_thrift_neighbor_entry_t(
                rif_id=nh_info['rif'],
                ip_address=sai_ipaddress(nh_info['ip']))
            sai_thrift_remove_neighbor_entry(self.client, nbr_entry)
            sai_thrift_remove_next_hop(self.client, nh_info['nh'])

        # Remove IPv6 neighbors and next hops
        for nh_info in self.nh_v6_dict.values():
            nbr_entry = sai_thrift_neighbor_entry_t(
                rif_id=nh_info['rif'],
                ip_address=sai_ipaddress(nh_info['ip']))
            sai_thrift_remove_neighbor_entry(self.client, nbr_entry)
            sai_thrift_remove_next_hop(self.client, nh_info['nh'])

        # Remove all sub-interfaces
        for rif_id in self.rif_info:
            sai_thrift_remove_router_interface(self.client, rif_id)

        print("Topology cleanup completed")

        super(SaiHelperScaleL3, self).tearDown()

    def _calc_and_report_perf(self, op_type, total_count, success_count,
                             fail_count, total_time, sai_time):
        """Calculate and report performance metrics with consistent formatting"""
        overall_perf = success_count / total_time if total_time > 0 else 0.0
        sai_perf = success_count / sai_time if sai_time > 0 else 0.0
        sai_ratio = sai_time / total_time * 100 if total_time > 0 else 0.0

        # Use status indicators
        if fail_count == 0:
            # Success case - don't show failure count
            print(f"   [PASS] Result: {success_count} routes {op_type}, time: {total_time:.3f}s")
        else:
            # Failure case - show failure count
            print(f"   [FAIL] Result: {success_count} routes {op_type}, {fail_count} failures, time: {total_time:.3f}s")

        print(f"   Overall performance: {overall_perf:.0f} routes/s")
        print(f"   SAI performance: {sai_perf:.0f} routes/s (ratio: {sai_ratio:.1f}%)")

        '''
        if fail_count > 0:
            self.assertEqual(fail_count, 0, f"Failed to {op_type.rstrip('d')} {fail_count} routes")
        '''

        """
        overall_perf means py perf test result
        sai_perf     means sai api perf result
        """
        return sai_perf

    def get_timetxt(self):
        result = self.run_host_container(
            ['tail', '-n', '4', '/tmp/stats_test_result_log'])
        values = []
        for line in result.stdout.splitlines():
            fields = line.split(' ')
            if 'Total' in line and len(fields) >= 9:
                values.append(fields[8])
        time.sleep(2)
        return '\n'.join(values).strip()

    def remove_timetxt(self):
        self.run_host_container(['rm', '-f', '/tmp/stats_test_result_log'])
        time.sleep(2)

    def _report_counter_perf(self, port_count, sai_time):
        """Return average counter operation latency in milliseconds."""
        latency_ms = (sai_time / port_count * 1000) if port_count > 0 else 0.0
        print(f"   Overall performance: {latency_ms:.5f} ms")
        return latency_ms

    def print_time_result(self, result, title="Performance Test Results"):
        """Print performance test result summary

        Args:
            results: Test result dictionary
            title: Test title
        """
        print(f"\n{'='*80}")
        print(f"{title:^80}")
        print(f"{'='*80}")


        print(f"{'Count':<12} {'sai_real_time(s)':<15} {'ptf_time(s)':<15} {'perf(s/)':<15}")
        print(f"{'-'*57}")

        # Display performance data

        count = result.get('count', 0)
        sai_real_time = result.get('sai_real_time', 0)
        ptf_time = result.get('ptf_time', 0)
        perf = result.get('perf', 0)

        print(f"{count:<12} {sai_real_time:<15.4f} {ptf_time:<15.4f} {perf:<15.5f}")

        print(f"{'-'*57}")
        # Performance baseline validation section

        expected_perf = getattr(self, 'expected_perf', None)
        if expected_perf:
            print(f"\n{'Performance Validation':^80}")
            print(f"{'Expected Performance: ' + str(expected_perf) + ' s':^80}")
            print(f"{'-'*80}")

            print(f"Average Performance:")
            if sai_real_time > 0:
                status = "PASS" if expected_perf >= sai_real_time else "WARNING"
                print(f"get stats: {sai_real_time:.2f} s - {status}")

        print(f"{'='*80}")

    def _prepare_nh_list(self, route_list):
        """Prepare next hop mappings for route entries"""
        nh_list = []
        for route in route_list:
            prefix = self.get_route_prefix(route)
            route_info = self.route_nh_map.get(prefix)

            if route_info is None:
                raise ValueError(f"Route mapping not found for {prefix}")

            nh_list.append(route_info['nh'])
        return nh_list

    def generate_ipv4_prefixes(self, prefix_len, start_ip="0.0.0.0", step=1, count=None):
        """Generate IPv4 prefix sequence with specified single mask

        Generate prefix sequence using ipaddress library for more efficient
        and readable IP address generation. Excludes 127.*.*.* prefixes as
        they are reserved for loopback.

        Args:
            prefix_len (int): Network mask length (16, 24, 26, 32, etc.)
            start_ip (str): Starting IP address (default: "0.0.0.0")
            step (int): Address increment between routes (default: 1)
            count (int): Number of prefixes to generate (default: self.total_routes)

        Returns:
            list: List of prefix strings in CIDR notation

        Examples:
            # Generate /16 prefixes: ["0.0.0.0/16", "0.1.0.0/16", "0.2.0.0/16", ...]
            generate_ipv4_prefixes(16, "0.0.0.0", 1)

            # Generate /24 prefixes: ["100.0.0.0/24", "100.0.1.0/24", "100.0.2.0/24", ...]
            generate_ipv4_prefixes(24, "100.0.0.0", 1)

            # Generate /32 prefixes: ["100.0.0.1/32", "100.0.0.2/32", "100.0.0.3/32", ...]
            generate_ipv4_prefixes(32, "100.0.0.1", 1)
        """
        if count is None:
            count = getattr(self, 'total_routes', 1000)

        print(f"\nGenerating {count} IPv4 /{prefix_len} prefixes (start: {start_ip}, step: {step})")

        prefix_list = []

        # Convert base IP to integer for calculation
        base_addr_int = ipaddress.IPv4Address(start_ip)._ip

        # Calculate address increment based on mask length
        if prefix_len == 32:
            # For /32 routes, each route is a single host address
            addr_increment = step
        else:
            # For network routes, calculate the address span of each network
            host_bits = 32 - prefix_len
            net_size = 2 ** host_bits  # Number of addresses in each network
            addr_increment = net_size * step

        # Generate prefixes
        gen_count = 0
        attempt = 0
        max_attempts = count * 10  # Prevent infinite loop

        while gen_count < count and attempt < max_attempts:
            # Calculate current address
            curr_addr_int = base_addr_int + (attempt * addr_increment)

            # Check if address is valid (not exceeding IPv4 range)
            if curr_addr_int > 0xFFFFFFFF:  # 255.255.255.255
                break

            curr_addr = ipaddress.IPv4Address(curr_addr_int)

            # Skip 127.*.*.* addresses (loopback range)
            if curr_addr._ip >> 24 == 127:  # Check if first octet is 127
                attempt += 1
                continue

            # Create network with specified mask
            network = ipaddress.IPv4Network(f"{curr_addr}/{prefix_len}", strict=False)
            prefix = str(network)

            prefix_list.append(prefix)
            gen_count += 1
            attempt += 1

        # Calculate end address for display
        if prefix_list:
            end_addr_int = base_addr_int + ((attempt - 1) * addr_increment)
            if end_addr_int <= 0xFFFFFFFF:
                end_addr = ipaddress.IPv4Address(end_addr_int)
                print(f"Generated {len(prefix_list)} IPv4 /{prefix_len} prefixes (range: {start_ip} - {end_addr})")
            else:
                print(f"Generated {len(prefix_list)} IPv4 /{prefix_len} prefixes (start: {start_ip})")
        else:
            print(f"Generated {len(prefix_list)} IPv4 /{prefix_len} prefixes")

        return prefix_list

    def generate_ipv6_prefixes(self, prefix_len, start_ip="1000::", step=1, count=None):
        """Generate IPv6 prefix sequence with specified single mask

        Generate prefix sequence using ipaddress library for more efficient
        and readable IPv6 address generation.

        Args:
            prefix_len (int): Network mask length (48, 56, 64, 128, etc.)
            start_ip (str): Starting IPv6 address (default: "1000::")
            step (int): Address increment between routes (default: 1)
            count (int): Number of prefixes to generate (default: self.total_routes)

        Returns:
            list: List of prefix strings in CIDR notation

        Examples:
            # Generate /48 prefixes: ["1000::/48", "1000:0:1::/48", "1000:0:2::/48", ...]
            generate_ipv6_prefixes(48, "1000::", 1)

            # Generate /56 prefixes: ["1000::/56", "1000:0:0:100::/56", "1000:0:0:200::/56", ...]
            generate_ipv6_prefixes(56, "1000::", 1)

            # Generate /64 prefixes: ["1000::/64", "1000:0:0:1::/64", "1000:0:0:2::/64", ...]
            generate_ipv6_prefixes(64, "1000::", 1)
        """
        if count is None:
            count = getattr(self, 'total_routes', 1000)

        print(f"\nGenerating {count} IPv6 /{prefix_len} prefixes (start: {start_ip}, step: {step})")

        prefix_list = []

        # Convert base IP to integer for calculation
        base_addr_int = ipaddress.IPv6Address(start_ip)._ip

        # Calculate address increment based on mask length
        if prefix_len == 128:
            # For /128 routes, each route is a single host address
            addr_increment = step
        else:
            # For network routes, calculate the address span of each network
            host_bits = 128 - prefix_len
            net_size = 2 ** host_bits  # Number of addresses in each network
            addr_increment = net_size * step

        # Generate prefixes
        for i in range(count):
            # Calculate current address
            curr_addr_int = base_addr_int + (i * addr_increment)
            curr_addr = ipaddress.IPv6Address(curr_addr_int)

            # Create network with specified mask
            network = ipaddress.IPv6Network(f"{curr_addr}/{prefix_len}", strict=False)
            prefix = str(network)

            prefix_list.append(prefix)

        # Calculate end address for display
        end_addr_int = base_addr_int + ((count - 1) * addr_increment)
        end_addr = ipaddress.IPv6Address(end_addr_int)

        print(f"Generated {len(prefix_list)} IPv6 /{prefix_len} prefixes (range: {start_ip} - {end_addr})")
        return prefix_list


    def create_routes_from_prefixes(self, prefix_list):
        """Create SAI route entries from mixed IPv4/IPv6 prefix list and build route-nexthop mapping

        Takes a list of IPv4 and/or IPv6 prefixes and creates corresponding SAI route entries.
        Automatically detects IP version for each prefix and uses appropriate next hop dictionary.
        Each route is assigned a randomly selected next hop from the corresponding IP version pool,
        and the mapping relationship is stored in route_nh_map for later use.

        Args:
            prefix_list (list): List of mixed prefix strings in CIDR notation
                               e.g., ["10.0.0.0/24", "2001:db8::/48", "10.0.1.0/24", "2001:db8:1::/48"]

        Returns:
            list: List of SAI route entry objects

        Side Effects:
            Updates self.route_nh_map with prefix -> next hop mappings

        Raises:
            ValueError: If no prefixes provided or required next hops are not available
        """
        if not prefix_list:
            print("Empty prefix list provided")
            return []

        # Check availability of next hop dictionaries
        has_ipv4_nh = hasattr(self, 'nh_v4_dict') and self.nh_v4_dict
        has_ipv6_nh = hasattr(self, 'nh_v6_dict') and self.nh_v6_dict

        if not has_ipv4_nh and not has_ipv6_nh:
            raise ValueError("No IPv4 or IPv6 next hops available. Please ensure topology is created first.")

        # Separate prefixes by IP version and validate availability
        ipv4_prefixes = []
        ipv6_prefixes = []

        for prefix in prefix_list:
            is_ipv6 = ':' in prefix
            if is_ipv6:
                if not has_ipv6_nh:
                    raise ValueError(f"IPv6 prefix '{prefix}' found but no IPv6 next hops available. Please ensure IPv6 topology is created.")
                ipv6_prefixes.append(prefix)
            else:
                if not has_ipv4_nh:
                    raise ValueError(f"IPv4 prefix '{prefix}' found but no IPv4 next hops available. Please ensure IPv4 topology is created.")
                ipv4_prefixes.append(prefix)

        # Initialize next hop indices
        ipv4_nh_indices = list(self.nh_v4_dict.keys()) if has_ipv4_nh else []
        ipv6_nh_indices = list(self.nh_v6_dict.keys()) if has_ipv6_nh else []

        print(f"\nCreating {len(prefix_list)} SAI route entries from mixed prefix list:")
        if ipv4_prefixes:
            print(f"  - IPv4 routes: {len(ipv4_prefixes)}")
        if ipv6_prefixes:
            print(f"  - IPv6 routes: {len(ipv6_prefixes)}")

        route_list = []

        # Process each prefix individually
        for prefix in prefix_list:
            is_ipv6 = ':' in prefix

            if is_ipv6:
                # Handle IPv6 prefix
                nh_idx = random.choice(ipv6_nh_indices)
                nh = self.nh_v6_dict[nh_idx]['nh']
                ip_version = "IPv6"
            else:
                # Handle IPv4 prefix
                nh_idx = random.choice(ipv4_nh_indices)
                nh = self.nh_v4_dict[nh_idx]['nh']
                ip_version = "IPv4"

            # Debug: print route generation info (commented out for performance)
            #print(f"Creating route {prefix} -> nh_idx {nh_idx} -> port {self.nh_v4_dict[nh_idx]['port']} mac {self.nh_v4_dict[nh_idx]['mac']} vlan {self.nh_v4_dict[nh_idx]['vlan']}")

            # Store route-to-nexthop mapping
            self.route_nh_map[prefix] = {
                'nh': nh,
                'nh_idx': nh_idx
            }

            # Create SAI route entry
            route_entry = sai_thrift_route_entry_t(
                vr_id=self.default_vrf,
                destination=sai_ipprefix(prefix))
            route_list.append(route_entry)

        print(f"Created {len(route_list)} SAI route entries with random next hop assignments")
        return route_list


    def get_route_prefix(self, route):
        """Extract prefix string from route.destination

        Convert route destination to prefix string format for use as dictionary key.
        Supports both IPv4 and IPv6 route entries created via sai_ipprefix().

        Input format examples:
            IPv4: sai_thrift_route_entry_t(
                switch_id=None,
                vr_id=216172782113783808,
                destination=sai_thrift_ip_prefix_t(
                    addr_family=0,
                    addr=sai_thrift_ip_addr_t(ip4='0.66.0.0', ip6=None),
                    mask=sai_thrift_ip_addr_t(ip4='255.255.0.0', ip6=None)
                )
            )

            IPv6: sai_thrift_route_entry_t(
                switch_id=None,
                vr_id=216172782113783808,
                destination=sai_thrift_ip_prefix_t(
                    addr_family=1,
                    addr=sai_thrift_ip_addr_t(ip4=None, ip6='1000::'),
                    mask=sai_thrift_ip_addr_t(ip4=None, ip6='ffff:ffff:ffff:0000:0000:0000:0000:0000')
                )
            )

        Output format examples:
            IPv4: '0.66.0.0/16'
            IPv6: '1000::/48'

        Args:
            route: Route entry object with destination attribute

        Returns:
            str: Prefix string in CIDR notation
        """
        destination = route.destination

        # Handle IPv4 (addr_family=0)
        if destination.addr_family == 0:
            addr = destination.addr.ip4
            mask = destination.mask.ip4
            # Convert IPv4 mask to prefix length using ipaddress
            mask_int = int(ipaddress.IPv4Address(mask))
            prefix_len = bin(mask_int).count('1')
            return f"{addr}/{prefix_len}"
        # Handle IPv6 (addr_family=1)
        elif destination.addr_family == 1:
            addr = destination.addr.ip6
            mask = destination.mask.ip6
            # Convert IPv6 mask to prefix length using ipaddress
            mask_int = int(ipaddress.IPv6Address(mask))
            prefix_len = bin(mask_int).count('1')
            return f"{addr}/{prefix_len}"
        # Fallback for unexpected format
        return str(destination)

    def bulk_create_routes(self, route_list, bulk_size):
        """Bulk route creation method focused on performance testing

        Args:
            route_list: List of routes to create
            bulk_size: Size of bulk operation

        Returns:
            tuple: (perf, success_route_cnt) - Performance metrics and number of successfully created routes
        """
        total_count = len(route_list)
        if total_count == 0:
            return 0.0, 0

        print(f"\n[BULK CREATE - Performance Test]")

        # Prepare next hop mappings
        try:
            nh_list = self._prepare_nh_list(route_list)
        except ValueError as e:
            print(f"ERROR: {e}")
            return 0.0, 0

        # Initialize tracking variables
        if self.get_timetxt() :
            time1 = int(self.get_timetxt())
        else:
            time1 = 0.0
        sai_api_time = 0.0

        start_time = time.perf_counter()
        sai_time = 0.0
        batch_attrs = [1] * bulk_size
        success_route_cnt = 0
        fail_route_cnt = 0

        # Process routes in batches
        for i in range(0, total_count, bulk_size):
            curr_batch_size = min(bulk_size, total_count - i)

            try:
                # Record SAI call time
                batch_start = time.perf_counter()
                status = sai_thrift_bulk_create_route_entry(
                    self.client,
                    route_list[i:i + curr_batch_size],
                    batch_attrs[:curr_batch_size],
                    SAI_BULK_OP_ERROR_MODE_IGNORE_ERROR,
                    next_hop_id=nh_list[i:i + curr_batch_size])
                batch_end = time.perf_counter()
                sai_time += (batch_end - batch_start)

                # Count successful and failed routes
                if self.status() == SAI_STATUS_SUCCESS:
                    success_route_cnt += curr_batch_size
                    for j in range(curr_batch_size):
                        self.created_route_entries.append(route_list[i + j])
                else:
                    for j in range(curr_batch_size):
                        if status[j] == SAI_STATUS_SUCCESS:
                            success_route_cnt += 1
                            self.created_route_entries.append(route_list[i + j])
                        else:
                            fail_route_cnt += 1

            except Exception:
                fail_route_cnt += curr_batch_size

        # Calculate and return performance results
        total_time = time.perf_counter() - start_time

        # Get sai api time
        time2 = int(self.get_timetxt())
        sai_api_time = (time2 - time1)/1000000

        """
            sai_time       :time take in python
            sai_api_time   :time take in C
        """
        perf = self._calc_and_report_perf(
            "created", total_count, success_route_cnt, fail_route_cnt, total_time, sai_api_time)
        self.record_spec(self._spec_name, "create", count=success_route_cnt,
                         actual_value=round(perf, 2),
                         duration=round(total_time, 3),
                         extra={"total_count": total_count,
                                "fail_count": fail_route_cnt,
                                "bulk_size": bulk_size})
        return perf, success_route_cnt

    def bulk_create_routes_load_factor(self, route_list, bulk_size):
        """Bulk route creation method focused on load factor testing

        Args:
            route_list: List of routes to create
            bulk_size: Size of bulk operation

        Returns:
            tuple: (load_factor_pass, success_route_cnt) - Whether load factor passes and number of successfully created routes

        Raises:
            AttributeError: If self.expected_load_factor is not set
        """
        if not hasattr(self, 'expected_load_factor'):
            raise AttributeError("expected_load_factor must be set before calling this method")

        total_count = len(route_list)
        if total_count == 0:
            return False, 0

        # Count IPv4 and IPv6 routes
        v4_total_count = 0
        v6_total_count = 0
        for route in route_list:
            if hasattr(route.destination, 'addr_family') and route.destination.addr_family == 1:
                v6_total_count += 1
            else:
                v4_total_count += 1

        # Prepare next hop mappings
        try:
            nh_list = self._prepare_nh_list(route_list)
        except ValueError as e:
            print(f"ERROR: {e}")
            return False, 0

        # Initialize counters
        batch_attrs = [1] * bulk_size
        success_route_cnt = 0
        v4_success_cnt = 0
        v6_success_cnt = 0
        v4_fail_cnt = 0
        v6_fail_cnt = 0

        # Process routes in batches
        for i in range(0, total_count, bulk_size):
            curr_batch_size = min(bulk_size, total_count - i)

            try:
                status = sai_thrift_bulk_create_route_entry(
                    self.client,
                    route_list[i:i + curr_batch_size],
                    batch_attrs[:curr_batch_size],
                    SAI_BULK_OP_ERROR_MODE_IGNORE_ERROR,
                    next_hop_id=nh_list[i:i + curr_batch_size])

                # Count results for each route
                if self.status() == SAI_STATUS_SUCCESS:
                    for j in range(curr_batch_size):
                        route = route_list[i + j]
                        self.created_route_entries.append(route)
                        if hasattr(route.destination, 'addr_family') and route.destination.addr_family == 1:
                            v6_success_cnt += 1
                        else:
                            v4_success_cnt += 1
                    success_route_cnt += curr_batch_size
                else:
                    for j in range(curr_batch_size):
                        route = route_list[i + j]
                        if status[j] == SAI_STATUS_SUCCESS:
                            self.created_route_entries.append(route)
                            if hasattr(route.destination, 'addr_family') and route.destination.addr_family == 1:
                                v6_success_cnt += 1
                            else:
                                v4_success_cnt += 1
                            success_route_cnt += 1
                        else:
                            if hasattr(route.destination, 'addr_family') and route.destination.addr_family == 1:
                                v6_fail_cnt += 1
                            else:
                                v4_fail_cnt += 1

            except Exception:
                for j in range(curr_batch_size):
                    route = route_list[i + j]
                    if hasattr(route.destination, 'addr_family') and route.destination.addr_family == 1:
                        v6_fail_cnt += 1
                    else:
                        v4_fail_cnt += 1

        # Calculate load factors
        v4_load_factor = (v4_success_cnt / v4_total_count) if v4_total_count > 0 else 0.0
        v6_load_factor = (v6_success_cnt / v6_total_count) if v6_total_count > 0 else 0.0
        # If both v4 and v6 exist, use the average as total_load_factor; otherwise, use the original algorithm
        if v4_total_count > 0 and v6_total_count > 0:
            total_load_factor = (v4_load_factor + v6_load_factor) / 2
        else:
            total_load_factor = (success_route_cnt / total_count) if total_count > 0 else 0.0

        # Determine whether load factor passes
        load_factor_pass = total_load_factor >= self.expected_load_factor

        # Print load factor comparison results
        print(f"\nLoad Factor Results: expected_load_factor: {self.expected_load_factor*100}%")
        if v4_total_count > 0:
            status = "PASS" if v4_load_factor >= self.expected_load_factor else "WARNING"
            print(f"IPv4 load factor: {v4_load_factor*100:.2f}% - {status} v4_total_count: {v4_total_count}, v4_success_cnt: {v4_success_cnt}")

        if v6_total_count > 0:
            status = "PASS" if v6_load_factor >= self.expected_load_factor else "WARNING"
            print(f"IPv6 load factor: {v6_load_factor*100:.2f}% - {status} v6_total_count: {v6_total_count}, v6_success_cnt: {v6_success_cnt}")

        status = "PASS" if total_load_factor >= self.expected_load_factor else "WARNING"
        print(f"Total load factor: {total_load_factor*100:.2f}% - {status} total_count: {total_count}, success_route_cnt: {success_route_cnt}")

        return load_factor_pass, success_route_cnt

    def loop_create_routes_load_factor(self, route_list):
        """Loop-based route creation method focused on load factor testing

        Args:
            route_list: List of routes to create

        Returns:
            tuple: (load_factor_pass, success_route_cnt) - Whether load factor passes and number of successfully created routes

        Raises:
            AttributeError: If self.expected_load_factor is not set
        """
        if not hasattr(self, 'expected_load_factor'):
            raise AttributeError("expected_load_factor must be set before calling this method")

        total_count = len(route_list)
        if total_count == 0:
            return False, 0

        # Automatically prepare nh_list, keep consistent with bulk_create_routes_load_factor
        try:
            nh_list = self._prepare_nh_list(route_list)
        except ValueError as e:
            print(f"ERROR: {e}")
            return False, 0

        v4_total_count = 0
        v6_total_count = 0
        for route in route_list:
            if hasattr(route.destination, 'addr_family') and route.destination.addr_family == 1:
                v6_total_count += 1
            else:
                v4_total_count += 1

        success_route_cnt = 0
        v4_success_cnt = 0
        v6_success_cnt = 0
        v4_fail_cnt = 0
        v6_fail_cnt = 0

        for i in range(total_count):
            route = route_list[i]
            nh_id = nh_list[i]
            is_ipv6 = hasattr(route.destination, 'addr_family') and route.destination.addr_family == 1

            try:
                status = sai_thrift_create_route_entry(self.client, route, next_hop_id=nh_id)

                if status == SAI_STATUS_SUCCESS:
                    self.created_route_entries.append(route)
                    success_route_cnt += 1
                    if is_ipv6:
                        v6_success_cnt += 1
                    else:
                        v4_success_cnt += 1
                else:
                    if is_ipv6:
                        v6_fail_cnt += 1
                    else:
                        v4_fail_cnt += 1
            except Exception:
                if is_ipv6:
                    v6_fail_cnt += 1
                else:
                    v4_fail_cnt += 1

        v4_load_factor = (v4_success_cnt / v4_total_count) if v4_total_count > 0 else 0.0
        v6_load_factor = (v6_success_cnt / v6_total_count) if v6_total_count > 0 else 0.0
        # If both v4 and v6 exist, use the average as total_load_factor; otherwise, use the original algorithm
        if v4_total_count > 0 and v6_total_count > 0:
            total_load_factor = (v4_load_factor + v6_load_factor) / 2
        else:
            total_load_factor = (success_route_cnt / total_count) if total_count > 0 else 0.0

        # Determine whether load factor passes
        load_factor_pass = total_load_factor >= self.expected_load_factor

        print(f"\nLoad Factor Results (Loop): expected_load_factor: {self.expected_load_factor}")
        if v4_total_count > 0:
            status = "PASS" if v4_load_factor >= self.expected_load_factor else "WARNING"
            print(f"IPv4 load factor: {v4_load_factor*100:.2f}% - {status} v4_total_count: {v4_total_count}, v4_success_cnt: {v4_success_cnt}")

        if v6_total_count > 0:
            status = "PASS" if v6_load_factor >= self.expected_load_factor else "WARNING"
            print(f"IPv6 load factor: {v6_load_factor*100:.2f}% - {status} v6_total_count: {v6_total_count}, v6_success_cnt: {v6_success_cnt}")

        status = "PASS" if total_load_factor >= self.expected_load_factor else "WARNING"
        print(f"Total load factor: {total_load_factor*100:.2f}% - {status} total_count: {total_count}, success_route_cnt: {success_route_cnt}")

        return load_factor_pass, success_route_cnt

    def loop_create_routes(self, route_list):
        """Create routes one by one using a loop and measure performance
        Args:
            route_list: List of routes to create
        Returns:
            tuple: (perf, success_count) - Performance metrics and number of successfully created routes
        """
        print(f"\nCreating {len(route_list)} routes (loop)...")
        if not route_list:
            return 0.0, 0

        # Automatically prepare nh_list, keep consistent with bulk_create_routes
        try:
            nh_list = self._prepare_nh_list(route_list)
        except ValueError as e:
            print(f"ERROR: {e}")
            return 0.0, 0

        # Initialize tracking variables
        if self.get_timetxt() :
            time1 = int(self.get_timetxt())
        else:
            time1 = 0.0
        sai_api_time = 0.0

        total_count = len(route_list)
        success_count = 0
        fail_count = 0
        start_time = time.perf_counter()
        sai_api_total_time = 0

        for i in range(total_count):
            route_entry = route_list[i]
            nh_id = nh_list[i]
            sai_api_start_time = time.perf_counter()
            status = sai_thrift_create_route_entry(self.client, route_entry, next_hop_id=nh_id)
            sai_api_total_time += (time.perf_counter() - sai_api_start_time)

            if status == SAI_STATUS_SUCCESS:
                success_count += 1
                self.created_route_entries.append(route_entry)
            else:
                fail_count += 1
                print(f"   [FAIL] Failed to create route {self.get_route_prefix(route_entry)}, status: {status}")
        total_time = time.perf_counter() - start_time

        # Get sai api time
        time2 = int(self.get_timetxt())
        sai_api_time = (time2 - time1)/1000000

        """
            sai_api_total_time :time used in python
            sai_api_time       :time used in C
        """
        perf = self._calc_and_report_perf("created", total_count, success_count, fail_count, total_time, sai_api_time)
        self.record_spec(self._spec_name, "create", count=success_count,
                         actual_value=round(perf, 2),
                         duration=round(total_time, 3),
                         extra={"total_count": total_count,
                                "fail_count": fail_count,
                                "mode": "loop"})
        return perf, success_count

    def bulk_get_routes(self, route_list, bulk_size):
        """Bulk get routes and verify next hop information

        Randomly select 1000 routes from the input route_list, get their attributes and verify next hop information.

        Args:
            route_list: List of route entries to verify
            bulk_size: Bulk operation size (not used in this implementation)
        """
        print(f"\n[BULK GET] - Verifying next hop information")

        # Randomly select 1000 routes for verification
        test_count = min(1000, len(route_list))
        test_routes = random.sample(route_list, test_count)
        print(f"Selected {len(test_routes)} routes for verification")

        # Prepare query parameters
        get_status = [SAI_STATUS_SUCCESS] * len(test_routes)
        attr_count = [1] * len(test_routes)
        nh_get = [True] * len(test_routes)
        get_pass = True

        try:
            # Get route attributes
            attrs = sai_thrift_bulk_get_route_entry_attribute(
                self.client,
                test_routes,
                attr_count,
                SAI_BULK_OP_ERROR_MODE_IGNORE_ERROR,
                get_status,
                next_hop_id=nh_get)

            # Verify results
            success_count = 0
            failed_routes = []

            for i, route in enumerate(test_routes):
                route_prefix = self.get_route_prefix(route)
                # Check if attribute retrieval was successful
                if get_status[i] != SAI_STATUS_SUCCESS:
                    failed_routes.append((route_prefix, f"Failed to get attributes: {get_status[i]}"))
                    continue

                # Check if route exists in mapping table
                if route_prefix not in self.route_nh_map:
                    failed_routes.append((route_prefix, "Not found in route_nh_map"))
                    continue

                # Verify next hop information
                recorded_nh = self.route_nh_map[route_prefix]['nh']
                actual_nh = attrs[i]['next_hop_id']

                if recorded_nh == actual_nh:
                    success_count += 1
                else:
                    failed_routes.append((route_prefix, f"Next hop mismatch: recorded={recorded_nh}, actual={actual_nh}"))

            # Print verification results
            print(f"   [INFO] Next hop verification summary:")
            print(f"      Total routes verified: {len(test_routes)}")
            print(f"      Successfully verified: {success_count}")

            if failed_routes:
                get_pass = False
                print(f"      Failed routes: {len(failed_routes)}")
                for route, reason in failed_routes[:5]:  # Show first 5 failures
                    print(f"         Failed route: {route} -> {reason}")
                if len(failed_routes) > 5:
                    print(f"         ... and {len(failed_routes) - 5} more failures")

            # Verify all routes were successfully verified
            self.assertEqual(success_count, len(test_routes),
                           f"Not all routes were verified successfully: {success_count}/{len(test_routes)}")
        except Exception as e:
            print(f"   [ERROR] Bulk get operation failed: {str(e)}")
            get_pass = False
            raise
        return get_pass

    def loop_get_routes(self, route_list):
        """Get routes one by one using a loop and verify next hop information

        Randomly select 1000 routes from the input route_list, get their attributes and verify next hop information.

        Args:
            route_list: List of route entries to verify
        """
        print(f"\n[LOOP GET] - Verifying next hop information")

        # Randomly select 1000 routes for verification
        test_count = min(1000, len(route_list))
        test_routes = random.sample(route_list, test_count)
        print(f"Selected {len(test_routes)} routes for verification")

        success_count = 0
        failed_routes = []
        get_pass = True

        for i, route in enumerate(test_routes):
            route_prefix = self.get_route_prefix(route)
            try:
                attrs = sai_thrift_get_route_entry_attribute(self.client, route, next_hop_id=True)
                if not attrs:
                    failed_routes.append((route_prefix, "Failed to get attributes"))
                    continue
                if route_prefix not in self.route_nh_map:
                    failed_routes.append((route_prefix, "Not found in route_nh_map"))
                    continue
                recorded_nh = self.route_nh_map[route_prefix]['nh']
                actual_nh = attrs['next_hop_id']
                if recorded_nh == actual_nh:
                    success_count += 1
                else:
                    failed_routes.append((route_prefix, f"Next hop mismatch: recorded={recorded_nh}, actual={actual_nh}"))
            except Exception as e:
                get_pass = False
                failed_routes.append((route_prefix, f"Exception: {str(e)}"))

        # Print verification results
        print(f"   [INFO] Next hop verification summary:")
        print(f"      Total routes verified: {len(test_routes)}")
        print(f"      Successfully verified: {success_count}")

        if failed_routes:
            get_pass = False
            print(f"      Failed routes: {len(failed_routes)}")
            for route, reason in failed_routes[:5]:  # Show first 5 failures
                print(f"         Failed route: {route} -> {reason}")
            if len(failed_routes) > 5:
                print(f"         ... and {len(failed_routes) - 5} more failures")

        # Verify all routes were successfully verified
        self.assertEqual(success_count, len(test_routes),
                         f"Not all routes were verified successfully: {success_count}/{len(test_routes)}")
        return get_pass

    def bulk_remove_routes(self, route_list, bulk_size):
        """Bulk remove routes and measure performance"""

        if self.created_route_entries:
            to_remove_route_entries = self.created_route_entries
        else:
            to_remove_route_entries = route_list
        total_count = len(to_remove_route_entries)
        if total_count == 0:
            return 0.0

        print(f"\n[BULK REMOVE]")

        # Initialize tracking
        if self.get_timetxt() :
            time1 = int(self.get_timetxt())
        else:
            time1 = 0.0
        sai_api_time = 0.0

        start_time = time.perf_counter()
        success_count = 0
        fail_count = 0
        sai_time = 0.0

        # Track indices of successfully deleted routes to remove from self.created_route_entries
        deleted_indices = set()

        # Process routes in batches
        for i in range(0, total_count, bulk_size):
            curr_batch_size = min(bulk_size, total_count - i)

            try:
                batch_start = time.perf_counter()
                status = sai_thrift_bulk_remove_route_entry(
                    self.client,
                    to_remove_route_entries[i:i + curr_batch_size],
                    SAI_BULK_OP_ERROR_MODE_IGNORE_ERROR)
                batch_end = time.perf_counter()

                sai_time += (batch_end - batch_start)

                if self.status() == SAI_STATUS_SUCCESS:
                    success_count += curr_batch_size
                    for idx in range(i, i + curr_batch_size):
                        deleted_indices.add(idx)
                else:
                    for j in range(0, curr_batch_size):
                        if status[j] != SAI_STATUS_SUCCESS:
                            fail_count += 1
                        else:
                            success_count += 1
                            deleted_indices.add(i + j)
                    batch_num = (i // bulk_size) + 1
                    total_batches = (total_count + bulk_size - 1) // bulk_size
                    print(f"   ERROR: Batch {batch_num}/{total_batches} failed with status: {self.status()}")

            except Exception as e:
                fail_count += curr_batch_size
                batch_num = (i // bulk_size) + 1
                total_batches = (total_count + bulk_size - 1) // bulk_size
                print(f"   ERROR: Batch {batch_num}/{total_batches} - {e}")

        if self.created_route_entries and deleted_indices:
            self.created_route_entries[:] = [
                route for idx, route in enumerate(self.created_route_entries)
                if idx not in deleted_indices
            ]

        # Get sai api time
        time2 = int(self.get_timetxt())
        sai_api_time = (time2 - time1)/1000000

        # Calculate and report results
        total_time = time.perf_counter() - start_time
        perf = self._calc_and_report_perf(
            "removed", total_count, success_count, fail_count, total_time, sai_api_time)
        self.record_spec(self._spec_name, "remove", count=success_count,
                         actual_value=round(perf, 2),
                         duration=round(total_time, 3),
                         extra={"total_count": total_count,
                                "fail_count": fail_count,
                                "bulk_size": bulk_size})
        return perf

    def loop_remove_routes(self, route_list):
        """Remove routes one by one using a loop and measure performance
        Args:
            route_list: List of routes to remove
        Returns:
            Performance metrics (routes per second)
        """
        print(f"\n[LOOP REMOVE]")
        if self.created_route_entries:
            to_remove_route_entries = self.created_route_entries
        else:
            to_remove_route_entries = route_list
        total_count = len(to_remove_route_entries)
        if total_count == 0:
            return 0.0

        if self.get_timetxt() :
            time1 = int(self.get_timetxt())
        else:
            time1 = 0.0
        sai_api_time = 0.0

        success_count = 0
        fail_count = 0
        start_time = time.perf_counter()
        sai_api_total_time = 0

        deleted_indices = set()

        for i in range(total_count):
            route_entry = to_remove_route_entries[i]
            sai_api_start_time = time.perf_counter()
            status = sai_thrift_remove_route_entry(self.client, route_entry)
            sai_api_total_time += (time.perf_counter() - sai_api_start_time)

            if status == SAI_STATUS_SUCCESS:
                success_count += 1
                deleted_indices.add(i)
            else:
                fail_count += 1

        if self.created_route_entries and deleted_indices:
            self.created_route_entries[:] = [
                route for idx, route in enumerate(self.created_route_entries)
                if idx not in deleted_indices
            ]

        total_time = time.perf_counter() - start_time

        # Get sai api time
        time2 = int(self.get_timetxt())
        sai_api_time = (time2 - time1)/1000000

        """
            sai_api_total_time :time used in python
            sai_api_time       :time used in C
        """

        perf = self._calc_and_report_perf("removed", total_count, success_count, fail_count, total_time, sai_api_time)
        self.record_spec(self._spec_name, "remove", count=success_count,
                         actual_value=round(perf, 2),
                         duration=round(total_time, 3),
                         extra={"total_count": total_count,
                                "fail_count": fail_count,
                                "mode": "loop"})
        return perf

    def bulk_set_routes(self, route_list, bulk_size):
        """Bulk set route attributes and measure performance"""
        total_count = len(route_list)
        if total_count == 0:
            return 0.0

        print(f"\n[BULK SET]")

        # Prepare next hop mappings
        try:
            nh_list = self._prepare_nh_list(route_list)
        except ValueError as e:
            print(f"ERROR: {e}")
            return 0.0

        # Initialize tracking
        if self.get_timetxt() :
            time1 = int(self.get_timetxt())
        else:
            time1 = 0.0
        sai_api_time = 0.0

        start_time = time.perf_counter()
        success_count = 0
        fail_count = 0
        sai_time = 0.0

        # Process routes in batches
        for i in range(0, total_count, bulk_size):
            curr_batch_size = min(bulk_size, total_count - i)

            try:
                batch_start = time.perf_counter()
                status = sai_thrift_bulk_set_route_entry_attribute(
                    self.client,
                    route_list[i:i + curr_batch_size],
                    SAI_BULK_OP_ERROR_MODE_IGNORE_ERROR,
                    next_hop_id=nh_list[i:i + curr_batch_size])
                batch_end = time.perf_counter()

                sai_time += (batch_end - batch_start)

                if all(x == SAI_STATUS_SUCCESS for x in self.status()):
                    success_count += curr_batch_size
                else:
                    fail_count += curr_batch_size
                    batch_num = (i // bulk_size) + 1
                    total_batches = (total_count + bulk_size - 1) // bulk_size
                    print(f"   ERROR: Batch {batch_num}/{total_batches} failed with status:{status}, self.status():{self.status()}")

            except Exception as e:
                fail_count += curr_batch_size
                batch_num = (i // bulk_size) + 1
                total_batches = (total_count + bulk_size - 1) // bulk_size
                print(f"   ERROR: Batch {batch_num}/{total_batches} - {e}")

        # Get sai api time
        time2 = int(self.get_timetxt())
        sai_api_time = (time2 - time1)/1000000

        """
            sai_time         :time used in python
            sai_api_time     :time used in C
        """

        # Calculate and report results
        total_time = time.perf_counter() - start_time
        perf = self._calc_and_report_perf(
            "updated", total_count, success_count, fail_count, total_time, sai_api_time)
        self.record_spec(self._spec_name, "set", count=success_count,
                         actual_value=round(perf, 2),
                         duration=round(total_time, 3),
                         extra={"total_count": total_count,
                                "fail_count": fail_count,
                                "bulk_size": bulk_size})
        return perf

    def loop_set_routes(self, route_list):
        """Set routes one by one using a loop and measure performance
        Args:
            route_list: List of routes to update
        Returns:
            Performance metrics (routes per second)
        """
        print(f"\nUpdating {len(route_list)} routes (loop)...")
        if not route_list:
            return 0.0

        # Automatically prepare nh_list, keep consistent with bulk_set_routes
        try:
            nh_list = self._prepare_nh_list(route_list)
        except ValueError as e:
            print(f"ERROR: {e}")
            return 0.0

        total_count = len(route_list)
        success_count = 0
        fail_count = 0

        if self.get_timetxt() :
            time1 = int(self.get_timetxt())
        else:
            time1 = 0.0
        sai_api_time = 0.0

        start_time = time.perf_counter()
        sai_api_total_time = 0
        for i in range(total_count):
            route_entry = route_list[i]
            new_nh = nh_list[i]
            sai_api_start_time = time.perf_counter()
            status = sai_thrift_set_route_entry_attribute(self.client, route_entry, next_hop_id=new_nh)
            sai_api_total_time += (time.perf_counter() - sai_api_start_time)

            if status == SAI_STATUS_SUCCESS:
                success_count += 1
            else:
                fail_count += 1
                print(f"   [FAIL] Failed to update route {self.get_route_prefix(route_entry)}, status: {status}")
        total_time = time.perf_counter() - start_time

        # Get sai api time
        time2 = int(self.get_timetxt())
        sai_api_time = (time2 - time1)/1000000

        """
            sai_api_total_time :time used in python
            sai_api_time       :time used in C
        """

        perf = self._calc_and_report_perf("updated", total_count, success_count, fail_count, total_time, sai_api_time)
        self.record_spec(self._spec_name, "set", count=success_count,
                         actual_value=round(perf, 2),
                         duration=round(total_time, 3),
                         extra={"total_count": total_count,
                                "fail_count": fail_count,
                                "mode": "loop"})
        return perf

    def create_routes(self, route_list, bulk_size):
        if self.support_route_bulk_api:
            return self.bulk_create_routes(route_list, bulk_size)
        else:
            return self.loop_create_routes(route_list)

    def remove_routes(self, route_list, bulk_size):
        if self.support_route_bulk_api:
            return self.bulk_remove_routes(route_list, bulk_size)
        else:
            return self.loop_remove_routes(route_list)

    def set_routes(self, route_list, bulk_size):
        if self.support_route_bulk_api:
            return self.bulk_set_routes(route_list, bulk_size)
        else:
            return self.loop_set_routes(route_list)

    def get_routes(self, route_list, bulk_size):
        if self.support_route_bulk_api:
            return self.bulk_get_routes(route_list, bulk_size)
        else:
            return self.loop_get_routes(route_list)

    def create_routes_load_factor(self, route_list, bulk_size):
        if self.support_route_bulk_api:
            return self.bulk_create_routes_load_factor(route_list, bulk_size)
        else:
            return self.loop_create_routes_load_factor(route_list)

    def find_longest_prefix_match(self, route_str):
        """
        Find the longest prefix match for a given route string (e.g. '100.0.0.0/24' or '1000::/48').

        Args:
            route_str (str): Route prefix in CIDR notation.

        Returns:
            tuple: (matched_route, prefix_len, nh_idx) or (None, 0, None)
        """
        try:
            network = ipaddress.ip_network(route_str, strict=False)
            prefix = str(network.network_address)
            prefix_len = network.prefixlen
            is_ipv6 = isinstance(network, ipaddress.IPv6Network)
            route_dict = self.route_nh_map

            if not is_ipv6:
                # IPv4: from /32 down to prefix_len
                for plen in range(32, prefix_len - 1, -1):
                    prefix_str = f"{prefix}/{plen}"
                    if prefix_str in route_dict:
                        nh_idx = route_dict[prefix_str]['nh_idx']
                        return prefix_str, plen, nh_idx
            else:
                # IPv6: from /128 down to prefix_len
                for plen in range(128, prefix_len - 1, -1):
                    prefix_str = f"{prefix}/{plen}"
                    if prefix_str in route_dict:
                        nh_idx = route_dict[prefix_str]['nh_idx']
                        return prefix_str, plen, nh_idx
            return None, 0, None

        except Exception:
            return None, 0, None

    def verify_traffic(self):
        """Verify route forwarding correctness by sending test packets."""
        print(f"\n[TRAFFIC VERIFICATION]")
        verify_pass = True
        test_count = min(100, len(self.route_nh_map))
        if test_count == 0:
            print("No routes to verify.")
            return verify_pass

        sampled_routes = random.sample(list(self.route_nh_map.keys()), test_count)
        print(f"Selected {test_count} routes for testing:")

        success_count = 0
        failed_routes = []
        ipv4_tested = 0
        ipv6_tested = 0
        dev_port16 = getattr(self, "dev_port16")
        nh_v4_dict = self.nh_v4_dict
        nh_v6_dict = self.nh_v6_dict

        def build_ipv4_pkt(prefix, mac, vlan):
            pkt = simple_tcp_packet(
                eth_dst=ROUTER_MAC,
                eth_src='00:22:22:22:22:22',
                ip_dst=prefix,
                ip_src='192.168.0.1',
                ip_id=105,
                ip_ttl=64,
                pktlen=100)
            exp_pkt = simple_tcp_packet(
                eth_dst=mac,
                eth_src=ROUTER_MAC,
                dl_vlan_enable=True,
                vlan_vid=vlan,
                ip_dst=prefix,
                ip_src='192.168.0.1',
                ip_id=105,
                ip_ttl=63,
                pktlen=104)
            return pkt, exp_pkt

        def build_ipv6_pkt(prefix, mac, vlan):
            pkt = simple_tcpv6_packet(
                eth_dst=ROUTER_MAC,
                eth_src='00:22:22:22:22:22',
                ipv6_dst=prefix,
                ipv6_src='2001:db8::1',
                ipv6_hlim=64,
                pktlen=100)
            exp_pkt = simple_tcpv6_packet(
                eth_dst=mac,
                eth_src=ROUTER_MAC,
                dl_vlan_enable=True,
                vlan_vid=vlan,
                ipv6_dst=prefix,
                ipv6_src='2001:db8::1',
                ipv6_hlim=63,
                pktlen=104)
            return pkt, exp_pkt

        for route_str in sampled_routes:
            try:
                network = ipaddress.ip_network(route_str, strict=False)
                prefix = str(network.network_address)
                original_prefix_len = network.prefixlen
                is_ipv6 = isinstance(network, ipaddress.IPv6Network)

                matched_route, matched_prefix_len, nh_idx = self.find_longest_prefix_match(route_str)
                nh_dict = nh_v6_dict if is_ipv6 else nh_v4_dict
                if nh_idx not in nh_dict:
                    print(f"   [SKIP] Route: {route_str} -> Next hop {nh_idx} not found")
                    continue

                port_index = nh_dict[nh_idx]['port']
                port = getattr(self, f"dev_port{port_index}")
                mac = nh_dict[nh_idx]['mac']
                vlan = nh_dict[nh_idx]['vlan']

                if original_prefix_len != matched_prefix_len:
                    print(f"   [TEST] Route: {route_str} -> Matched: {matched_route} -> Forwarding: port{port_index} (MAC: {mac}, VLAN: {vlan})")

                if is_ipv6:
                    pkt, exp_pkt = build_ipv6_pkt(prefix, mac, vlan)
                    ipv6_tested += 1
                else:
                    pkt, exp_pkt = build_ipv4_pkt(prefix, mac, vlan)
                    ipv4_tested += 1

                send_packet(self, dev_port16, pkt)
                verify_packet(self, exp_pkt, port)
                success_count += 1

            except Exception as e:
                verify_pass = False
                route_type = "IPv6" if 'is_ipv6' in locals() and is_ipv6 else "IPv4"
                print(f"   [Error] Route: {route_str} -> Exception: {type(e).__name__}: {e}")
                failed_routes.append({
                    'route': route_str,
                    'route_type': route_type,
                    'reason': f'{type(e).__name__}: {e}'
                })

        print(f"   [INFO] Traffic verification summary: IPv4: {ipv4_tested}, IPv6: {ipv6_tested}, Total: {ipv4_tested + ipv6_tested}")

        if failed_routes:
            print(f"   [FAIL] Result: {success_count}/{test_count} passed ({len(failed_routes)} failed)")
            for failed in failed_routes[:5]:
                print(f"      Failed {failed['route_type']} route: {failed['route']} - {failed['reason']}")
            if len(failed_routes) > 5:
                print(f"      ... and {len(failed_routes) - 5} more failures")
        else:
            print(f"   [PASS] Result: {success_count}/{test_count} passed")

        if success_count != test_count:
            verify_pass = False
            print(f"Not all routes were verified successfully: {success_count}/{test_count}")
        return verify_pass

    def update_routes_nexthop(self, route_list):
        """
        For each route in route_list, assign a new random next hop and update self.route_nh_map.
        This is useful for testing route attribute update (set) operations.

        Args:
            route_list (list): List of SAI route entry objects
        """
        if not route_list:
            print("Empty route list provided")
            return

        # Check next hop dictionaries
        has_ipv4_nh = hasattr(self, 'nh_v4_dict') and self.nh_v4_dict
        has_ipv6_nh = hasattr(self, 'nh_v6_dict') and self.nh_v6_dict

        if not has_ipv4_nh and not has_ipv6_nh:
            raise ValueError("No IPv4 or IPv6 next hops available. Please ensure topology is created first.")

        ipv4_nh_indices = list(self.nh_v4_dict.keys()) if has_ipv4_nh else []
        ipv6_nh_indices = list(self.nh_v6_dict.keys()) if has_ipv6_nh else []

        for route in route_list:
            prefix = self.get_route_prefix(route)
            # Determine if the route is IPv6
            is_ipv6 = False
            if hasattr(route.destination, 'addr_family') and route.destination.addr_family == 1:
                is_ipv6 = True

            if is_ipv6:
                if not ipv6_nh_indices:
                    raise ValueError(f"IPv6 route {prefix} but no IPv6 next hops available.")
                nh_idx = random.choice(ipv6_nh_indices)
                nh = self.nh_v6_dict[nh_idx]['nh']
            else:
                if not ipv4_nh_indices:
                    raise ValueError(f"IPv4 route {prefix} but no IPv4 next hops available.")
                nh_idx = random.choice(ipv4_nh_indices)
                nh = self.nh_v4_dict[nh_idx]['nh']

            # Update route_nh_map
            self.route_nh_map[prefix] = {
                'nh': nh,
                'nh_idx': nh_idx
            }
        print(f"Updated nexthop for {len(route_list)} routes in route_nh_map.")

    def print_performance_results(self, results, title="Performance Test Results"):
        """Print performance test result summary for a single result dict.

        Args:
            results: dict with keys 'create', 'remove', and optionally 'set'.
            title: Test title.
        Returns:
            bool: True if all performance items PASS, else False.
        """
        print(f"\n{'='*80}")
        print(f"{title:^80}")
        print(f"{'='*80}")
        has_set = 'set' in results
        # Print table header
        if has_set:
            print(f"{'Create(r/s)':<20}{'Set(r/s)':<20}{'Remove(r/s)':<20}")
            print(f"{'-'*60}")
            print(f"{results.get('create', 0):<20.2f}{results.get('set', 0):<20.2f}{results.get('remove', 0):<20.2f}")
            print(f"{'-'*60}")
        else:
            print(f"{'Create(r/s)':<20}{'Remove(r/s)':<20}")
            print(f"{'-'*40}")
            print(f"{results.get('create', 0):<20.2f}{results.get('remove', 0):<20.2f}")
            print(f"{'-'*40}")
        # Performance baseline validation
        expected_perf = getattr(self, 'expected_perf', None)
        all_pass = True
        if expected_perf:
            print(f"\n{'Performance Validation':^80}")
            print(f"{'Expected Performance: ' + str(expected_perf) + ' r/s':^80}")
            print(f"{'-'*80}")
            print(f"Average Performance:")
            if results.get('create', 0) > 0:
                status = "PASS" if results.get('create', 0) >= expected_perf else "WARNING"
                print(f"Create: {results.get('create', 0):.2f} r/s - {status}")
                if status != "PASS":
                    all_pass = False
            if results.get('remove', 0) > 0:
                status = "PASS" if results.get('remove', 0) >= expected_perf else "WARNING"
                print(f"Remove: {results.get('remove', 0):.2f} r/s - {status}")
                if status != "PASS":
                    all_pass = False
            if has_set and results.get('set', 0) > 0:
                status = "PASS" if results.get('set', 0) >= expected_perf else "WARNING"
                print(f"Set: {results.get('set', 0):.2f} r/s - {status}")
                if status != "PASS":
                    all_pass = False
        print(f"{'='*80}")
        return all_pass

class L3RouteScaleTestBase(SaiHelperScaleL3):
    """Route scale test base class

    Provides common functionality for large-scale route testing including:
    - Bulk route operations (create, get, set, remove)
    - Performance measurement and validation
    - Traffic forwarding verification
    - Test result reporting
    """

    def setUp(self):
        super(L3RouteScaleTestBase, self).setUp()
        cls_name = self.__class__.__name__
        has_v4 = 'IPv4' in cls_name
        has_v6 = 'IPv6' in cls_name
        if has_v4 and has_v6:
            self._spec_name = "ipv4_ipv6_route_scale"
        elif has_v6:
            self._spec_name = "ipv6_route_scale"
        else:
            self._spec_name = "ipv4_route_scale"

    def _verify_route_resource_recovery(self, init_v4_count, init_v6_count):
        """Verify route capacity after cleanup."""
        timeout = float(
            self.test_params.get("route_resource_recovery_timeout", 300)
        )
        poll_interval = float(
            self.test_params.get("route_resource_recovery_poll_interval", 2)
        )
        deadline = time.monotonic() + timeout
        poll_count = 0

        while True:
            attrs = sai_thrift_get_switch_attribute(
                self.client,
                available_ipv4_route_entry=True,
                available_ipv6_route_entry=True)
            final_v4_count = attrs['available_ipv4_route_entry']
            final_v6_count = attrs['available_ipv6_route_entry']

            if get_platform() != 'mlnx':
                self.assertEqual(
                    final_v4_count,
                    init_v4_count,
                    f"IPv4 route count not restored: initial "
                    f"{init_v4_count} != final {final_v4_count}")
                self.assertEqual(
                    final_v6_count,
                    init_v6_count,
                    f"IPv6 route count not restored: initial "
                    f"{init_v6_count} != final {final_v6_count}")
                return

            # MLNX route resource availability may update after bulk removal;
            # poll for recovery.
            if (final_v4_count >= init_v4_count and
                    final_v6_count >= init_v6_count):
                print(
                    "Route resources recovered after "
                    f"{poll_count} poll(s): "
                    f"IPv4 {final_v4_count}/{init_v4_count}, "
                    f"IPv6 {final_v6_count}/{init_v6_count}")
                return

            if time.monotonic() >= deadline:
                self.fail(
                    f"Route resources did not recover within {timeout}s: "
                    f"IPv4 initial {init_v4_count}, final {final_v4_count}; "
                    f"IPv6 initial {init_v6_count}, final {final_v6_count}")

            poll_count += 1
            print(
                f"Waiting for MLNX route resource recovery "
                f"(poll {poll_count}): "
                f"IPv4 {final_v4_count}/{init_v4_count}, "
                f"IPv6 {final_v6_count}/{init_v6_count}")
            time.sleep(poll_interval)

    def execute_crud_test(self, route_entries):
        """Execute complete CRUD operation test, supporting both bulk and loop modes.

        Args:
            route_entries: List of route entries to test.

        Returns:
            tuple: (average create performance, average remove performance, get_pass and verify_pass)
        """
        print(f"\n{'='*60}")
        print(f"  CRUD TEST")
        print(f"{'='*60}")

        # Record initial route count for later verification
        init_v4_count = sai_thrift_get_switch_attribute(
            self.client, available_ipv4_route_entry=True)['available_ipv4_route_entry']
        init_v6_count = sai_thrift_get_switch_attribute(
            self.client, available_ipv6_route_entry=True)['available_ipv6_route_entry']

        curd_pass = True
        if self.support_route_bulk_api:
            # Bulk branch: iterate over self.bulk_sizes
            perf_table = {}  # Store {bulk_size: {'create': ..., 'remove': ...}}
            for bulk_size in self.bulk_sizes:
                print(f"\n{'-'*40}\n[Bulk Size: {bulk_size}]")
                try:
                    # 1. Create
                    create_perf, success_route_cnt = self.bulk_create_routes(route_entries, bulk_size)
                    # 2. Get
                    get_pass = self.bulk_get_routes(route_entries, bulk_size)
                    # 3. Verify traffic
                    verify_pass = self.verify_traffic()
                    # 4. Remove
                    remove_perf = self.bulk_remove_routes(route_entries, bulk_size)
                    perf_table[bulk_size] = {'create': create_perf, 'remove': remove_perf}
                    # 5. Verify both IPv4 and IPv6 route count is restored
                    final_v4_count = sai_thrift_get_switch_attribute(
                        self.client, available_ipv4_route_entry=True)['available_ipv4_route_entry']
                    final_v6_count = sai_thrift_get_switch_attribute(
                        self.client, available_ipv6_route_entry=True)['available_ipv6_route_entry']
                    self.assertEqual(final_v4_count, init_v4_count,
                        f"IPv4 route count not restored: initial {init_v4_count} != final {final_v4_count}")
                    self.assertEqual(final_v6_count, init_v6_count,
                        f"IPv6 route count not restored: initial {init_v6_count} != final {final_v6_count}")
                    print(f"curd_pass: {curd_pass}, get_pass: {get_pass}, verify_pass: {verify_pass}")
                    curd_pass =  curd_pass and get_pass and verify_pass
                except Exception as e:
                    print(f"[ERROR] Exception during bulk size {bulk_size} test: {e}")
                    curd_pass = False
                    continue

            # Print performance table
            print("\n" + "="*80)
            print(f"{'Bulk CRUD Performance Test Results':^80}")
            print("="*80)
            print(f"{'Bulk Size':<12}{'Create(r/s)':<16}{'Remove(r/s)':<16}")
            print("-"*44)
            for bulk_size in perf_table:
                print(f"{bulk_size:<12}{perf_table[bulk_size]['create']:<16.2f}{perf_table[bulk_size]['remove']:<16.2f}")
            print("-"*44)

            avg_create_perf = sum(item['create'] for item in perf_table.values()) / len(perf_table) if perf_table else 0
            avg_remove_perf = sum(item['remove'] for item in perf_table.values()) / len(perf_table) if perf_table else 0
        else:
            # Loop branch: only run once
            try:
                # 1. Create
                create_perf, success_route_cnt = self.loop_create_routes(route_entries)
                # 2. Get
                get_pass = self.loop_get_routes(route_entries)
                # 3. Verify traffic
                verify_pass = self.verify_traffic()
                # 4. Remove
                remove_perf = self.loop_remove_routes(route_entries)
                # 5. Verify both IPv4 and IPv6 route count is restored
                final_v4_count = sai_thrift_get_switch_attribute(
                    self.client, available_ipv4_route_entry=True)['available_ipv4_route_entry']
                final_v6_count = sai_thrift_get_switch_attribute(
                    self.client, available_ipv6_route_entry=True)['available_ipv6_route_entry']
                self.assertEqual(final_v4_count, init_v4_count,
                    f"IPv4 route count not restored: initial {init_v4_count} != final {final_v4_count}")
                self.assertEqual(final_v6_count, init_v6_count,
                    f"IPv6 route count not restored: initial {init_v6_count} != final {final_v6_count}")
                avg_create_perf = create_perf
                avg_remove_perf = remove_perf
                curd_pass =  curd_pass and get_pass and verify_pass
            except Exception as e:
                print(f"[ERROR] Exception during loop mode test: {e}")
                avg_create_perf = 0
                avg_remove_perf = 0
                curd_pass = False

        return avg_create_perf, avg_remove_perf, curd_pass

    def execute_set_test(self, route_entries):
        """Execute complete set operation test, supporting both bulk and loop modes.

        Args:
            route_entries: List of route entries to test.

        Returns:
            tuple: (average create performance, average set performance, average remove performance)
        """
        print(f"\n{'='*60}")
        print(f"  SET TEST")
        print(f"{'='*60}")
        set_pass = True

        # Record initial route count for later verification
        init_v4_count = sai_thrift_get_switch_attribute(
            self.client, available_ipv4_route_entry=True)['available_ipv4_route_entry']
        init_v6_count = sai_thrift_get_switch_attribute(
            self.client, available_ipv6_route_entry=True)['available_ipv6_route_entry']

        if self.support_route_bulk_api:
            # Bulk branch: iterate over self.bulk_sizes
            perf_table = {}  # Store {bulk_size: {'create': ..., 'remove': ..., 'set': ...}}
            for bulk_size in self.bulk_sizes:
                print(f"\n{'-'*40}\n[Bulk Size: {bulk_size}]")
                try:
                    # 1. Create
                    create_perf, success_route_cnt = self.bulk_create_routes(route_entries, bulk_size)
                    # update route_nh_map
                    self.update_routes_nexthop(route_entries)
                    # 2. Set
                    set_perf = self.bulk_set_routes(route_entries, bulk_size)
                    # 3. Get
                    get_pass = self.bulk_get_routes(route_entries, bulk_size)
                    # 3. Verify traffic
                    verify_pass = self.verify_traffic()
                    # 4. Remove
                    remove_perf = self.bulk_remove_routes(route_entries, bulk_size)
                    perf_table[bulk_size] = {'create': create_perf, 'set': set_perf, 'remove': remove_perf}
                    # 5. Verify both IPv4 and IPv6 route count is restored
                    final_v4_count = sai_thrift_get_switch_attribute(
                        self.client, available_ipv4_route_entry=True)['available_ipv4_route_entry']
                    final_v6_count = sai_thrift_get_switch_attribute(
                        self.client, available_ipv6_route_entry=True)['available_ipv6_route_entry']
                    self.assertEqual(final_v4_count, init_v4_count,
                        f"IPv4 route count not restored: initial {init_v4_count} != final {final_v4_count}")
                    self.assertEqual(final_v6_count, init_v6_count,
                        f"IPv6 route count not restored: initial {init_v6_count} != final {final_v6_count}")
                    print(f"set_pass: {set_pass}, get_pass: {get_pass}, verify_pass: {verify_pass}")
                    set_pass = set_pass and get_pass and verify_pass
                except Exception as e:
                    print(f"[ERROR] Exception during bulk size {bulk_size} set test: {e}")
                    set_pass = False
                    continue
            print(f"set_pass: {set_pass}")
            # Print performance table (Bulk Set)
            print("\n" + "="*80)
            print(f"{'Bulk Set Performance Test':^80}")
            print("="*80)
            print(f"{'Bulk Size':<12}{'Create(r/s)':<16}{'Remove(r/s)':<16}{'Set(r/s)':<16}")
            print("-"*54)
            for bulk_size in perf_table:
                print(f"{bulk_size:<12}{perf_table[bulk_size]['create']:<16.2f}{perf_table[bulk_size]['remove']:<16.2f}{perf_table[bulk_size]['set']:<16.2f}")
            print("-"*54)

            avg_create_perf = sum(item['create'] for item in perf_table.values()) / len(perf_table) if perf_table else 0
            avg_set_perf = sum(item['set'] for item in perf_table.values()) / len(perf_table) if perf_table else 0
            avg_remove_perf = sum(item['remove'] for item in perf_table.values()) / len(perf_table) if perf_table else 0
        else:
            # Loop branch: only run once
            try:
                # 1. Create
                create_perf, success_route_cnt = self.loop_create_routes(route_entries)
                # update route_nh_map
                self.update_routes_nexthop(route_entries)
                # 2. Set
                set_perf = self.loop_set_routes(route_entries)
                # 3. Get
                get_pass = self.loop_get_routes(route_entries)
                # 3. Verify traffic
                verify_pass = self.verify_traffic()
                # 4. Remove
                remove_perf = self.loop_remove_routes(route_entries)
                # 5. Verify both IPv4 and IPv6 route count is restored
                final_v4_count = sai_thrift_get_switch_attribute(
                    self.client, available_ipv4_route_entry=True)['available_ipv4_route_entry']
                final_v6_count = sai_thrift_get_switch_attribute(
                    self.client, available_ipv6_route_entry=True)['available_ipv6_route_entry']
                self.assertEqual(final_v4_count, init_v4_count,
                    f"IPv4 route count not restored: initial {init_v4_count} != final {final_v4_count}")
                self.assertEqual(final_v6_count, init_v6_count,
                    f"IPv6 route count not restored: initial {init_v6_count} != final {final_v6_count}")
                avg_create_perf = create_perf
                avg_set_perf = set_perf
                avg_remove_perf = remove_perf
                set_pass = set_pass and get_pass and verify_pass
            except Exception as e:
                print(f"[ERROR] Exception during loop mode set test: {e}")
                avg_create_perf = 0
                avg_set_perf = 0
                avg_remove_perf = 0
                set_pass = False

        print(f"avg_create_perf: {avg_create_perf}, avg_set_perf: {avg_set_perf}, avg_remove_perf: {avg_remove_perf}, set_pass: {set_pass}")
        return avg_create_perf, avg_set_perf, avg_remove_perf, set_pass

    def _record_route_fill_rate(self, route_entries, success_route_cnt,
                                order=None):
        """fill rate = successfully installed routes / attempted routes (percent).

        `order` tags which delivery round this is: a case runs the same routes
        sequentially and then shuffled, and the two fill rates can differ a lot.
        """
        total = len(route_entries)
        if total <= 0:
            return
        fill_pct = round(success_route_cnt / total * 100.0, 2)
        base = getattr(self, '_spec_name', 'ipv4_route_scale')
        fill_spec = base.replace('_route_scale', '_route_fill_rate')
        extra = {"success_route_cnt": success_route_cnt}
        if order:
            extra["order"] = order
        self.record_spec(fill_spec, "", count=total,
                         actual_value=fill_pct, extra=extra)

    def execute_load_factor_test(self, route_entries, order=None):
        """Execute load factor test, supporting both bulk and loop modes.

        Args:
            route_entries: List of route entries to test.
            order: delivery order tag ("sequential" / "random") recorded with
                the fill rate, so a case's two rounds stay distinguishable.

        Returns:
            tuple: (load_factor_pass, success_route_cnt)
                load_factor_pass: bool, whether load factor passes
                success_route_cnt: int, number of successfully created routes
        """
        print(f"\n{'='*60}")
        print(f"  LOAD FACTOR TEST")
        print(f"{'='*60}")

        # Record initial route count for later verification
        init_v4_count = sai_thrift_get_switch_attribute(
            self.client, available_ipv4_route_entry=True)['available_ipv4_route_entry']
        init_v6_count = sai_thrift_get_switch_attribute(
            self.client, available_ipv6_route_entry=True)['available_ipv6_route_entry']

        if self.support_route_bulk_api:
            try:
                # 1. Create (bulk)
                load_factor_pass, success_route_cnt = self.bulk_create_routes_load_factor(route_entries, self.load_factor_bulk_size)
                self._record_route_fill_rate(route_entries, success_route_cnt,
                                             order)
                # 2. Remove
                self.bulk_remove_routes(route_entries, self.load_factor_bulk_size)
                # 3. Verify both IPv4 and IPv6 route count is restored
                final_v4_count = sai_thrift_get_switch_attribute(
                    self.client, available_ipv4_route_entry=True)['available_ipv4_route_entry']
                final_v6_count = sai_thrift_get_switch_attribute(
                    self.client, available_ipv6_route_entry=True)['available_ipv6_route_entry']
                self.assertEqual(final_v4_count, init_v4_count,
                    f"IPv4 route count not restored: initial {init_v4_count} != final {final_v4_count}")
                self.assertEqual(final_v6_count, init_v6_count,
                    f"IPv6 route count not restored: initial {init_v6_count} != final {final_v6_count}")
                return load_factor_pass, success_route_cnt
            except Exception as e:
                print(f"[ERROR] Exception during bulk load factor test: {e}")
                return False, 0
        else:
            try:
                # 1. Create (loop)
                load_factor_pass, success_route_cnt = self.loop_create_routes_load_factor(route_entries)
                self._record_route_fill_rate(route_entries, success_route_cnt,
                                             order)
                # 2. Remove
                self.loop_remove_routes(route_entries)
                # 3. Verify both IPv4 and IPv6 route count is restored
                final_v4_count = sai_thrift_get_switch_attribute(
                    self.client, available_ipv4_route_entry=True)['available_ipv4_route_entry']
                final_v6_count = sai_thrift_get_switch_attribute(
                    self.client, available_ipv6_route_entry=True)['available_ipv6_route_entry']
                self.assertEqual(final_v4_count, init_v4_count,
                    f"IPv4 route count not restored: initial {init_v4_count} != final {final_v4_count}")
                self.assertEqual(final_v6_count, init_v6_count,
                    f"IPv6 route count not restored: initial {init_v6_count} != final {final_v6_count}")
                return load_factor_pass, success_route_cnt
            except Exception as e:
                print(f"[ERROR] Exception during loop load factor test: {e}")
                return False, 0

class L3VrfScaleTest(SaiHelperScaleL3):
    """
    VRF scale and resource recovery test (optimized, using SaiHelperScaleL3 methods)
    """
    def runTest(self):
        # Skip syslog verify for this test
        self.skip_syslog_verify = True

        print("\n==== L3VrfScaleTest Start ====")
        available_routes_before = sai_thrift_get_switch_attribute(
            self.client,
            available_ipv4_route_entry=True
        )["available_ipv4_route_entry"]

        # Route ops here only exercise multi-VRF install; report them as
        # incidental so they never overwrite the pure-route scale metric.
        self._spec_name = "vrf_route_scale"
        # 1. Get the maximum number of VRFs and define test parameters
        max_vrf = sai_thrift_get_switch_attribute(self.client, max_virtual_routers=True)["max_virtual_routers"]
        actual_test_vrf = max_vrf - 10
        ROUTES_PER_VRF = 32
        print(f"Max VRF number: {max_vrf}, testing with {actual_test_vrf} new VRFs + default VRF.")

        self.record_spec("vrf", "", count=0, actual_value=max_vrf)

        # 2. Create new VRFs for the test to increase readability
        self.vrf_list = []
        for _ in range(actual_test_vrf):
            vrf = sai_thrift_create_virtual_router(self.client)
            assert vrf != SAI_NULL_OBJECT_ID, "Failed to create VRF!"
            self.vrf_list.append(vrf)
        print(f"Created {len(self.vrf_list)} new VRFs.")

        # Combine new VRFs with the default VRF for a complete test set
        vrf_list_for_test = self.vrf_list + [self.default_vrf]

        # 3. Calculate total route count for the test
        route_count = len(vrf_list_for_test) * ROUTES_PER_VRF
        print(f"Total VRFs for testing: {len(vrf_list_for_test)}, test route count: {route_count}")

        # 4. Generate route_count /24 prefixes
        prefixes = self.generate_ipv4_prefixes(24, start_ip="100.0.0.0", step=1, count=route_count)
        print(f"Generated {len(prefixes)} prefixes.")

        # 5. Distribute routes evenly to each VRF and build route entry list
        route_entries = []
        prefix_idx = 0
        self.route_dict = {vrf: [] for vrf in vrf_list_for_test}
        for vrf in vrf_list_for_test:
            for _ in range(ROUTES_PER_VRF):
                if prefix_idx >= len(prefixes):
                    print(f"Warning: Not enough prefixes generated. Stopping route creation.")
                    break
                route_entry = sai_thrift_route_entry_t(
                    switch_id=self.switch_id,
                    vr_id=vrf,
                    destination=sai_ipprefix(prefixes[prefix_idx])
                )
                self.route_dict[vrf].append(route_entry)
                route_entries.append(route_entry)
                prefix_idx += 1
        print(f"Prepared {len(route_entries)} route entries.")

        # 6. Use base class method to assign next hops for all routes
        self.route_nh_map = {}
        _ = self.create_routes_from_prefixes(prefixes)

        # 7. Bulk create routes
        perf_create, _ = self.create_routes(route_entries, bulk_size=10000)
        print(f"Bulk created {len(route_entries)} routes.")

        # 8. (Optional) Traffic verification
        #self.verify_traffic()

        # 9. Bulk remove routes
        perf_remove = self.remove_routes(route_entries, bulk_size=10000)
        print(f"Bulk removed {len(route_entries)} routes.")

        # 10. Remove only the VRFs created in this test
        for vrf in self.vrf_list:
            sai_thrift_remove_virtual_router(self.client, vrf)
        print(f"Removed {len(self.vrf_list)} new VRFs.")

        # 11. Resource recovery verification
        max_vrf_after = sai_thrift_get_switch_attribute(self.client, max_virtual_routers=True)["max_virtual_routers"]
        available_routes_after = sai_thrift_get_switch_attribute(self.client, available_ipv4_route_entry=True)["available_ipv4_route_entry"]
        print(f"Max VRF number after test: {max_vrf_after}, Available IPv4 route entry: {available_routes_after}")
        assert max_vrf_after == max_vrf, f"VRF resource leak: {max_vrf_after} != {max_vrf}"
        assert available_routes_after == self.init_ipv4_route_count, f"Route resource leak: {available_routes_after} != {self.init_ipv4_route_count}"
        print("==== L3VrfScaleTest End ====")

    def tearDown(self):
        super(L3VrfScaleTest, self).tearDown()

class L3SubIntfScaleTest(PlatformSaiHelper):
    """
    Sub interface scale and resource recovery test (optimized)
    """
    def runTest(self):
        # Skip syslog verify for this test
        self.skip_syslog_verify = True

        print("==== L3SubIntfScaleTest Start ====")
        PORT_COUNT = 16
        OTHER_PORT_COUNT = PORT_COUNT - 1
        VLAN_COUNT = 10
        SAME_PORT_RIF_COUNT = 1000
        OTHER_PORT_RIF_COUNT = 3000
        VRF_COUNT = (OTHER_PORT_RIF_COUNT) // (OTHER_PORT_COUNT * VLAN_COUNT) + 1
        vlan_base = 1000

        rif_list = []
        vrf_list = []
        try:
            # 1. Create VRFs
            vrf_list = [sai_thrift_create_virtual_router(self.client) for _ in range(VRF_COUNT)]
            for vrf in vrf_list:
                assert vrf != SAI_NULL_OBJECT_ID, "Failed to create VRF!"
            print(f"Created {len(vrf_list)} VRFs.")

            # 2.1 Create 1000 sub interfaces on one port, same VRF
            for vlan in range(vlan_base, vlan_base + SAME_PORT_RIF_COUNT):
                try:
                    rif = sai_thrift_create_router_interface(
                        self.client,
                        type=SAI_ROUTER_INTERFACE_TYPE_SUB_PORT,
                        port_id=self.port_list[0],
                        virtual_router_id=vrf_list[0],
                        admin_v4_state=True,
                        admin_v6_state=True,
                        outer_vlan_id=vlan
                    )
                    assert rif != SAI_NULL_OBJECT_ID, "Failed to create sub intf!"
                    rif_list.append(rif)
                except Exception as e:
                    print(f"Failed to create sub intf: {e}")
                    continue
            print(f"Created {len(rif_list)} sub interfaces.")

            # 2.2 Create 3000 sub interfaces on other ports, round-robin VRF/VLAN
            for vrf_idx in range(1, VRF_COUNT):
                vrf_vlan_base = vlan_base + vrf_idx * VLAN_COUNT    # Each VRF uses independent VLAN range to avoid conflicts
                for port_idx in range(1, PORT_COUNT):
                    for vlan in range(vrf_vlan_base, vrf_vlan_base + VLAN_COUNT):
                        try:
                            rif = sai_thrift_create_router_interface(
                                self.client,
                                type=SAI_ROUTER_INTERFACE_TYPE_SUB_PORT,
                                port_id=self.port_list[port_idx],
                                virtual_router_id=vrf_list[vrf_idx],
                                admin_v4_state=True,
                                admin_v6_state=True,
                                outer_vlan_id=vlan
                            )
                            assert rif != SAI_NULL_OBJECT_ID, "Failed to create sub intf!"
                            rif_list.append(rif)
                        except Exception as e:
                            print(f"Failed to create sub intf: {e}")
                            continue
            print(f"Created {len(rif_list)} sub interfaces.")

            # 3. Set/Get MTU for all sub interfaces
            for mtu in [1000, 9000]:
                for rif in rif_list:
                    sai_thrift_set_router_interface_attribute(self.client, rif, mtu=mtu)
                    rif_attr = sai_thrift_get_router_interface_attribute(self.client, router_interface_oid=rif, mtu=True)
                    assert rif_attr['mtu'] == mtu, f"MTU set/get failed for RIF {rif}"
            print("MTU set/get verified for all sub interfaces.")

        finally:
            # 4. Remove all RIFs if rif_list is a valid non-empty list
            if isinstance(rif_list, list) and rif_list:
                for rif in rif_list:
                    sai_thrift_remove_router_interface(self.client, rif)
                print(f"Removed {len(rif_list)} sub interfaces.")

            # 5. Remove all VRFs if vrf_list is a valid non-empty list
            if isinstance(vrf_list, list) and vrf_list:
                for vrf in vrf_list:
                    sai_thrift_remove_virtual_router(self.client, vrf)
                print(f"Removed {len(vrf_list)} VRFs.")

            print("==== L3SubIntfScaleTest End ====")

    def tearDown(self):
        super(L3SubIntfScaleTest, self).tearDown()
