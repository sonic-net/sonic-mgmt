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


"""
SAI L3 ECMP Scale Test Module

Provides comprehensive large-scale ECMP test cases based on SaiHelperScaleL3 framework.
Tests ECMP group/member creation, deletion, and performance with IPv4/IPv6 support.

Architecture:
    - Base class: L3EcmpScaleTestBase (inherits SaiHelperScaleL3)
    - Performance baselines: 1000 groups/s, 5000 members/s, 20000 routes/s
    - Bulk size testing: Groups(100-500), Members(500-2000), Routes(1000-8000)
    - L3 integration: 128 ready-made next hops, 16×8 sub-interface topology
"""

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


class L3EcmpScaleTestBase(SaiHelperScaleL3):
    """ECMP scale test base class

    Provides common functionality for ECMP scale testing including:
    - ECMP group/member creation and cleanup
    - Performance measurement and reporting
    - Integration with SaiHelperScaleL3 infrastructure
    - Bulk operation testing with various sizes
    """

    def setUp(self):
        """Initialize ECMP test environment

        Sets up:
        - ECMP capability discovery (groups, members, max per group)
        - Performance baselines (aligned with route testing standards)
        - Test state tracking variables
        - Bulk API support detection
        """
        super(L3EcmpScaleTestBase, self).setUp()

        # Check bulk API support
        self.support_ecmp_member_bulk_api = True
        print(f"\n  Bulk ecmp member API support: {self.support_ecmp_member_bulk_api}\n")

        # Get ECMP capabilities - using safe method to get attributes
        self.init_group_count = sai_thrift_get_switch_attribute(
            self.client, available_next_hop_group_entry=True)['available_next_hop_group_entry']
        self.init_member_count = sai_thrift_get_switch_attribute(
            self.client, available_next_hop_group_member_entry=True)['available_next_hop_group_member_entry']
        self.max_members_per_ecmp = sai_thrift_get_switch_attribute(
            self.client, ecmp_members=True)['ecmp_members']

        self.record_spec("ecmp_group", "", count=0,
                         actual_value=self.init_group_count)
        self.record_spec("ecmp_member", "", count=0,
                         actual_value=self.init_member_count)

        sai_thrift_set_switch_attribute(self.client, ecmp_default_hash_algorithm=SAI_HASH_ALGORITHM_CRC_32LO)

        # Set performance baselines (aligned with route test)
        self.expected_group_perf = 1000   # ECMP group creation baseline: 1000 groups/s
        self.expected_member_create_perf = 800  # ECMP member creation baseline: 800 members/s
        self.expected_member_remove_perf = 400  # ECMP member remove baseline: 400 members/s
        self.expected_route_perf = 10000  # Route creation baseline: 10000 routes/s

        # bulk_size is fixed to 10k
        self.bulk_size = 10000

        print(f"ECMP capabilities at start:")
        print(f"  Available ECMP groups (G): {self.init_group_count}")
        print(f"  Available ECMP members (M): {self.init_member_count}")
        print(f"  Max members per group (K): {self.max_members_per_ecmp}")
        print(f"Performance baselines:")
        print(f"  ECMP group performance: {self.expected_group_perf} groups/s")
        print(f"  ECMP member creation performance: {self.expected_member_create_perf} members/s")
        print(f"  ECMP member removal performance: {self.expected_member_remove_perf} members/s")
        print(f"  Route performance: {self.expected_route_perf} routes/s")
        print(f"Network infrastructure:")
        print(f"  IPv4 next hops available: {len(self.nh_v4_dict)}")
        print(f"  IPv6 next hops available: {len(self.nh_v6_dict)}")

        # Test state tracking
        self.ecmp_groups = []
        self.ecmp_members = []
        self.test_routes = []

        # Route mapping for traffic verification
        self.route_nh_map = {}
        self.group_to_members = {}  # Mapping: group -> member list

    def _calc_and_report_perf(self, op_type, total_count, success_count,
                             fail_count, total_time, sai_time):
        """Calculate and report ECMP operation performance metrics

        Args:
            op_type (str): Operation type name for reporting
            total_count (int): Total number of operations attempted
            success_count (int): Number of successful operations
            fail_count (int): Number of failed operations
            total_time (float): Total test time in seconds
            sai_time (float): Pure SAI API time in seconds

        Returns:
            float: Overall performance in operations per second
        """
        if total_time <= 0:
            print(f"   [WARN] {op_type.capitalize()}: Total time is 0, cannot calculate performance")
            return 0.0

        overall_perf = success_count / total_time
        sai_perf = success_count / sai_time if sai_time > 0 else 0
        sai_ratio = (sai_time / total_time * 100) if total_time > 0 else 0

        if fail_count == 0:
            print(f"   [PASS] Result: {success_count} {op_type} created, time: {total_time:.3f}s")
        else:
            print(f"   [FAIL] Result: {success_count} {op_type} created, {fail_count} failed, time: {total_time:.3f}s")

        print(f"   Total performance: {overall_perf:.0f} {op_type}/s")
        print(f"   SAI performance: {sai_perf:.0f} {op_type}/s (ratio: {sai_ratio:.1f}%)")

        if fail_count > 0:
            self.assertEqual(fail_count, 0, f"{fail_count} {op_type} failed")

        return overall_perf

    def _cleanup_all_ecmp_resources(self):
        """Clean up all ECMP test resources

        Removes all created ECMP groups, members, and routes.
        Resets all tracking state variables.
        """
        print(f"\nCleaning up all ECMP resources...")

        # Clean up routes first
        self._cleanup_resource_list(
            self.test_routes,
            sai_thrift_remove_route_entry,
            "Route"
        )

        # Clean up ECMP members
        self._cleanup_resource_list(
            self.ecmp_members,
            sai_thrift_remove_next_hop_group_member,
            "ECMP member"
        )

        # Clean up ECMP groups
        self._cleanup_resource_list(
            self.ecmp_groups,
            sai_thrift_remove_next_hop_group,
            "ECMP group"
        )

        # Reset state
        self.ecmp_groups = []
        self.ecmp_members = []
        self.test_routes = []
        self.route_nh_map = {}
        self.group_to_members = {}

    def _cleanup_resource_list(self, resource_list, remove_func, resource_name):
        """Safely clean up a list of resources with error handling."""
        if not resource_list:
            return

        success_count = 0
        for resource in resource_list:
            try:
                remove_func(self.client, resource)
                success_count += 1
            except Exception:
                pass  # Silent error handling to avoid cleanup failures

        if len(resource_list) > 0:
            print(
                f"{resource_name} cleanup: {success_count}/{len(resource_list)} successful")

    def check_ecmp_resource_recovery(self):
        """Check if final ECMP state is properly restored

        Returns:
            bool: True if state is restored within acceptable tolerance
        """
        print(f"\nChecking final ECMP capabilities...")

        final_group_count = sai_thrift_get_switch_attribute(
            self.client, available_next_hop_group_entry=True)['available_next_hop_group_entry']
        final_member_count = sai_thrift_get_switch_attribute(
            self.client, available_next_hop_group_member_entry=True)['available_next_hop_group_member_entry']

        group_match = abs(final_group_count - self.init_group_count) <= 5
        member_match = abs(final_member_count - self.init_member_count) <= 10

        print(f"Final check:")
        print(f"  ECMP groups: {final_group_count} vs initial {self.init_group_count} - {'Passed' if group_match else 'Failed'}")
        print(f"  ECMP members: {final_member_count} vs initial {self.init_member_count} - {'Passed' if member_match else 'Failed'}")

        return group_match and member_match

    def tearDown(self):
        """Enhanced cleanup with complete error handling"""
        '''
        try:
            self._cleanup_all_ecmp_resources()
        except Exception as e:
            print(f"Error during cleanup: {e}")
        '''

        super(L3EcmpScaleTestBase, self).tearDown()

    def create_routes(self, route_list, group_list, measure_perf=False):
        """
        Creates routes in bulk, with an option to measure and report performance.
        Uses bulk API if self.support_route_bulk_api is True, otherwise uses single route creation.
        """
        if not route_list:
            return 0 if measure_perf else None

        if measure_perf:
            print(f"\nCreating {len(route_list)} routes...")

        start_time = time.perf_counter()

        total_count = len(route_list)
        if getattr(self, 'support_route_bulk_api', False):
            # Use bulk API
            for i in range(0, total_count, self.bulk_size):
                curr_batch_size = min(self.bulk_size, total_count - i)
                try:
                    sai_thrift_bulk_create_route_entry(
                        self.client,
                        route_list[i:i + curr_batch_size],
                        [1] * curr_batch_size,
                        SAI_BULK_OP_ERROR_MODE_IGNORE_ERROR,
                        next_hop_id=group_list[i:i + curr_batch_size]
                    )
                except Exception as e:
                    print(f"Bulk create ECMP group routes failed: {e}")
        else:
            # Use single API
            for route_entry, nh_id in zip(route_list, group_list):
                try:
                    status = sai_thrift_create_route_entry(self.client, route_entry, next_hop_id=nh_id)
                except Exception as e:
                    print(f"Create ECMP group route failed: {e}")

        total_time = time.perf_counter() - start_time

        self.test_routes.extend(route_list)

        if measure_perf:
            perf = self._calc_and_report_perf(
                "Routes", len(route_list), len(route_list), 0, total_time, total_time)
            return perf

        return None


    def create_and_install_ipv4_routes(self, ecmp_groups):
        """Create SAI route entries from generated prefix list, assign ECMP group as next hop, and install routes in bulk."""
        prefix_list = self.generate_ipv4_prefixes(
            prefix_len=24,
            start_ip="100.0.0.0",
            step=1,
            count=len(ecmp_groups)
        )
        route_list, group_list = self._prepare_route_and_group_lists(
            prefix_list, ecmp_groups, assignment_mode='sequential')
        self.create_routes(route_list, group_list)
        print(f"  Created {len(self.test_routes)} routes")

    def create_and_install_ipv6_routes(self, ecmp_groups):
        """
        Create and install IPv6 routes, one for each ECMP group provided.
        """
        prefix_list = self.generate_ipv6_prefixes(
            prefix_len=56, start_ip="1000::", step=1, count=len(ecmp_groups))

        route_list, group_list = self._prepare_route_and_group_lists(
            prefix_list, ecmp_groups, assignment_mode='random')

        self.create_routes(route_list, group_list)
        print(f"  Created {len(self.test_routes)} routes")

    def _prepare_route_and_group_lists(self, prefix_list, ecmp_groups, assignment_mode='sequential'):
        """Prepares lists of route entries and their corresponding ECMP group OIDs."""
        route_list = []
        group_list = []
        if not ecmp_groups:
            return route_list, group_list

        for idx, prefix in enumerate(prefix_list):
            if assignment_mode == 'random':
                group = random.choice(ecmp_groups)
            else:  # sequential by default
                group = ecmp_groups[idx % len(ecmp_groups)]

            route_entry = sai_thrift_route_entry_t(
                vr_id=self.default_vrf,
                destination=sai_ipprefix(prefix)
            )
            self.route_nh_map[prefix] = group
            route_list.append(route_entry)
            group_list.append(group)
        return route_list, group_list

    def verify_ecmp_traffic(self):
        """Verify ECMP route forwarding correctness by sending IPv4 test packets to random routes."""
        print(f"\n[ECMP TRAFFIC VERIFICATION]")
        test_count = min(100, len(self.route_nh_map))
        if test_count == 0:
            print("No routes to verify.")
            return False

        test_prefixes = random.sample(list(self.route_nh_map.keys()), test_count)
        success_count = 0
        failed_routes = []

        for prefix in test_prefixes:
            group = self.route_nh_map.get(prefix)
            member_list = self.group_to_members.get(group, [])

            # Collect all output ports for this ECMP group
            port_list = []
            mac = None
            vlan = None
            for member in member_list:
                for nh_info in self.nh_v4_dict.values():
                    if nh_info['nh'] == member:
                        port_list.append(getattr(self, f"dev_port{nh_info['port']}"))
                        if mac is None:
                            mac = nh_info['mac']
                            vlan = nh_info['vlan']
                        break

            if not port_list:
                failed_routes.append({'route': prefix, 'reason': 'No valid ports for group members'})
                continue

            ip_dst = prefix.split('/')[0]
            try:
                pkt = simple_tcp_packet(
                    eth_dst=ROUTER_MAC,
                    eth_src='00:22:22:22:22:22',
                    ip_dst=ip_dst,
                    ip_src='192.168.0.1',
                    ip_id=105,
                    ip_ttl=64,
                    pktlen=100)
                exp_pkt = simple_tcp_packet(
                    eth_dst=mac,
                    eth_src=ROUTER_MAC,
                    dl_vlan_enable=True,
                    vlan_vid=vlan,
                    ip_dst=ip_dst,
                    ip_src='192.168.0.1',
                    ip_id=105,
                    ip_ttl=63,
                    pktlen=104)
                exp_pkt.set_do_not_care_scapy(ptf.packet.Ether, 'vlan')
                send_packet(self, self.dev_port16, pkt)
                verify_packet_any_port(self, exp_pkt, port_list)
                success_count += 1
            except Exception as e:
                failed_routes.append({'route': prefix, 'reason': str(e)})

        print(f"   [INFO] ECMP traffic verification summary:")
        print(f"      Total routes tested: {test_count}")
        if failed_routes:
            print(f"   [FAIL] Result: {success_count}/{test_count} passed ({len(failed_routes)} failed)")
            for failed in failed_routes[:5]:
                print(f"      Failed route: {failed['route']} - {failed['reason']}")
            if len(failed_routes) > 5:
                print(f"      ... and {len(failed_routes) - 5} more failures")
        else:
            print(f"   [PASS] Result: {success_count}/{test_count} passed")
        return success_count == test_count

    def _verify_performance_results(self, results):
        """
        Verify and print performance test results based on the provided metrics.
        This method dynamically checks for keys in the results dictionary,
        allowing it to be used by different tests that measure different sets of metrics.
        """
        print("\n=== Performance Test Results ===")
        all_checks_passed = True

        # Group creation performance
        if 'group_create_perf' in results:
            group_create_perf = results['group_create_perf']
            group_create_met = group_create_perf >= self.expected_group_perf
            print(f"  ECMP Group Creation: {group_create_perf:.2f} groups/s (Baseline: {self.expected_group_perf} groups/s) - {'PASS' if group_create_met else 'FAIL'}")
            if not group_create_met:
                all_checks_passed = False
                print(f"    Warning: Group creation performance {group_create_perf:.2f} groups/s below baseline {self.expected_group_perf} groups/s")

        # Member creation performance
        if 'member_create_perf' in results:
            member_create_perf = results['member_create_perf']
            member_create_met = member_create_perf >= self.expected_member_create_perf
            print(f"  ECMP Member Creation: {member_create_perf:.2f} members/s (Baseline: {self.expected_member_create_perf} members/s) - {'PASS' if member_create_met else 'FAIL'}")
            if not member_create_met:
                all_checks_passed = False
                print(f"    Warning: Member creation performance {member_create_perf:.2f} members/s below baseline {self.expected_member_create_perf} members/s")

        # Member removal performance
        if 'member_remove_perf' in results:
            member_remove_perf = results['member_remove_perf']
            member_remove_met = member_remove_perf >= self.expected_member_remove_perf
            print(f"  ECMP Member Removal: {member_remove_perf:.2f} members/s (Baseline: {self.expected_member_remove_perf} members/s) - {'PASS' if member_remove_met else 'FAIL'}")
            if not member_remove_met:
                all_checks_passed = False
                print(f"    Warning: Member removal performance {member_remove_perf:.2f} members/s below baseline {self.expected_member_remove_perf} members/s")

        # Group removal performance
        if 'group_remove_perf' in results:
            group_remove_perf = results['group_remove_perf']
            group_remove_met = group_remove_perf >= self.expected_group_perf
            print(f"  ECMP Group Removal: {group_remove_perf:.2f} groups/s (Baseline: {self.expected_group_perf} groups/s) - {'PASS' if group_remove_met else 'FAIL'}")
            if not group_remove_met:
                all_checks_passed = False
                print(f"    Warning: Group removal performance {group_remove_perf:.2f} groups/s below baseline {self.expected_group_perf} groups/s")

        # Route creation performance
        if 'route_create_perf' in results:
            route_create_perf = results.get('route_create_perf', 0)
            route_create_met = route_create_perf >= self.expected_route_perf
            print(f"  Route Creation: {route_create_perf:.2f} routes/s (Baseline: {self.expected_route_perf} routes/s) - {'PASS' if route_create_met else 'FAIL'}")
            if not route_create_met:
                all_checks_passed = False
                print(f"    Warning: Route creation performance {route_create_perf:.2f} routes/s below baseline {self.expected_route_perf} routes/s")

        # Route removal performance
        if 'route_remove_perf' in results:
            route_remove_perf = results.get('route_remove_perf', 0)
            route_remove_met = route_remove_perf >= self.expected_route_perf
            print(f"  Route Removal: {route_remove_perf:.2f} routes/s (Baseline: {self.expected_route_perf} routes/s) - {'PASS' if route_remove_met else 'FAIL'}")
            if not route_remove_met:
                all_checks_passed = False
                print(f"    Warning: Route removal performance {route_remove_perf:.2f} routes/s below baseline {self.expected_route_perf} routes/s")

        # Resource recovery verification
        if 'final_verified' in results:
            final_verified = results['final_verified']
            print(f"  Resource Recovery: {'PASS' if final_verified else 'FAIL'}")
            if not final_verified:
                all_checks_passed = False
                print("    Warning: Resource recovery verification failed")

        return all_checks_passed

    def _run_generic_scale_test(self, nh_dict, install_routes_func):
        """
        Generic runner for ECMP group/member scale tests.
        Encapsulates the entire test flow, from resource creation to cleanup and verification.
        Executes 3 iterations and calculates average performance.
        """
        # Performance tracking for 3 iterations
        performance_results = {
            'group_create_perf': [],
            'member_create_perf': [],
            'member_remove_perf': [],
            'group_remove_perf': []
        }

        print(f"\n=== Starting 3-iteration ECMP Scale Test ===")
        # Route ops below go through the base bulk_/loop_ route helpers, which
        # record self._spec_name; retag them so they do not overwrite the
        # authoritative ipv4_route_scale numbers.
        self._spec_name = "ecmp_route_scale"
        try:
            for iteration in range(3):
                print(f"\n--- Iteration {iteration + 1}/3 ---")
                # 1. Create ECMP groups
                group_create_perf = self._create_ecmp_groups()
                performance_results['group_create_perf'].append(group_create_perf)
                self.record_spec("ecmp_group_scale", "create",
                                 count=len(self.ecmp_groups),
                                 actual_value=round(group_create_perf, 2))

                # 2. Create ECMP members
                self.group_to_members, member_create_perf = self._create_ecmp_members(
                    self.ecmp_groups, nh_dict)
                self.ecmp_members = [
                    m for members in self.group_to_members.values() for m in members]
                performance_results['member_create_perf'].append(member_create_perf)
                self.record_spec("ecmp_member_scale", "create",
                                 count=len(self.ecmp_members),
                                 actual_value=round(member_create_perf, 2))

                # 3. Create and install routes
                install_routes_func(self.ecmp_groups)

                # Capture counts before cleanup for summary report
                group_count = len(self.ecmp_groups)
                member_count = len(self.ecmp_members)
                route_count = len(self.test_routes)

                # 4. (Optional) Traffic verification
                # traffic_verified = self.verify_ecmp_traffic()

                # 5. Remove routes
                self.remove_routes(self.test_routes, self.bulk_size)
                self.test_routes = []

                # 6. Remove ECMP members
                member_remove_perf = self._remove_ecmp_members(self.group_to_members)
                performance_results['member_remove_perf'].append(member_remove_perf)
                self.record_spec("ecmp_member_scale", "remove",
                                 count=member_count,
                                 actual_value=round(member_remove_perf, 2))
                self.group_to_members = {}
                self.ecmp_members = []

                # 7. Remove ECMP groups
                group_remove_perf = self._remove_ecmp_groups(self.ecmp_groups)
                performance_results['group_remove_perf'].append(group_remove_perf)
                self.record_spec("ecmp_group_scale", "remove",
                                 count=group_count,
                                 actual_value=round(group_remove_perf, 2))
                self.ecmp_groups = []

                # 8. Verify resource recovery
                final_verified = self.check_ecmp_resource_recovery()
                self.assertTrue(final_verified, "ECMP resource recovery failed")

                # Output iteration summary
                print(f"  Iteration {iteration + 1} Summary: Groups={group_count}, Members={member_count}, Routes={route_count}, Recovery={'PASS' if final_verified else 'FAIL'}")

            # Calculate average performance across all iterations
            print(f"\n=== Performance Summary (3 iterations) ===")
            avg_results = {}
            for metric, values in performance_results.items():
                if values:
                    avg_value = sum(values) / len(values)
                    avg_results[metric] = avg_value
                    print(f"  {metric}: {avg_value:.2f} (values: {[f'{v:.2f}' for v in values]})")
                else:
                    avg_results[metric] = 0.0
                    print(f"  {metric}: No data available")

            # 9. Verify performance results using averages
            avg_results['final_verified'] = self.check_ecmp_resource_recovery()
            perf_pass = self._verify_performance_results(avg_results)
            print(f"  Performance pass: {perf_pass}")
            return perf_pass

        finally:
            # Clean up any remaining resources
            self._cleanup_all_ecmp_resources()

    def _create_ecmp_groups(self):
        """Create ECMP groups

        Returns:
            float: Performance in groups/s
        """
        start_time = time.perf_counter()
        groups = []

        for _ in range(self.groups_to_create):
            group = sai_thrift_create_next_hop_group(
                self.client,
                type=SAI_NEXT_HOP_GROUP_TYPE_ECMP
            )
            if group:
                groups.append(group)

        total_time = time.perf_counter() - start_time
        perf = len(groups) / total_time if total_time > 0 else 0

        print(f"  ECMP Groups: {len(groups)}/{self.groups_to_create} created, {total_time:.3f}s, {perf:.2f} groups/s")

        self.ecmp_groups = groups
        return perf

    def _create_ecmp_members(self, ecmp_groups, nh_dict):
        """Create ECMP group members

        Args:
            ecmp_groups: List of ECMP groups
            nh_dict: Next hop dictionary

        Returns:
            tuple: (member_map, create_perf)
        """
        start_time = time.perf_counter()

        # Prepare next hop list
        nh_list = [v['nh'] for v in nh_dict.values()]
        if not nh_list:
            raise ValueError("No available next hops")

        # Randomly select members for each group
        group_nh_lists = [
            random.sample(nh_list, self.members_per_group)
            for _ in range(len(ecmp_groups))
        ]

        # Create members
        group_to_members = {}
        total_members = 0
        failed_members = 0

        for group, nhs in zip(ecmp_groups, group_nh_lists):
            if self.support_ecmp_member_bulk_api:
                # Use bulk API
                attr_counts = [2] * len(nhs)
                next_hop_group_ids = [group] * len(nhs)
                object_statuses = []
                members = sai_thrift_bulk_create_next_hop_group_member(
                    self.client,
                    attr_counts,
                    SAI_BULK_OP_ERROR_MODE_IGNORE_ERROR,
                    object_statuses,
                    next_hop_group_id=next_hop_group_ids,
                    next_hop_id=nhs
                )
                # Check bulk operation status
                if self.status() != SAI_STATUS_SUCCESS:
                    print(f"  Warning: Bulk member creation failed with status {self.status()}")
                    failed_members += len(nhs)
                    members = []
                else:
                    # Check individual member statuses
                    for member in members:
                        self.assertNotEqual(member, SAI_NULL_OBJECT_ID)
            else:
                # Create individually
                members = []
                for nh in nhs:
                    member = sai_thrift_create_next_hop_group_member(
                        self.client,
                        next_hop_group_id=group,
                        next_hop_id=nh
                    )
                    if member != SAI_NULL_OBJECT_ID:
                        members.append(member)
                    else:
                        print(f"  Warning: Member creation returned NULL object ID")
                        failed_members += 1

            group_to_members[group] = members
            total_members += len(members)

        total_time = time.perf_counter() - start_time
        perf = total_members / total_time if total_time > 0 else 0

        if failed_members > 0:
            print(f"  ECMP Members: {total_members}/{len(ecmp_groups)*self.members_per_group} created, {failed_members} failed, {total_time:.3f}s, {perf:.2f} members/s")
        else:
            print(f"  ECMP Members: {total_members}/{len(ecmp_groups)*self.members_per_group} created, {total_time:.3f}s, {perf:.2f} members/s")

        return group_to_members, perf

    def _remove_ecmp_members(self, group_to_members):
        """Remove ECMP group members

        Args:
            group_to_members: Member mapping dictionary

        Returns:
            float: Performance in members/s
        """
        start_time = time.perf_counter()

        member_count = 0

        for group, members in group_to_members.items():
            if self.support_ecmp_member_bulk_api:
                object_statuses = []
                sai_thrift_bulk_remove_next_hop_group_member(
                    self.client,
                    members,
                    SAI_BULK_OP_ERROR_MODE_IGNORE_ERROR
                )
                self.assertEqual(self.status(), SAI_STATUS_SUCCESS)
                for status in object_statuses:
                    self.assertEqual(status, SAI_STATUS_SUCCESS)
            else:
                for member in members:
                    status = sai_thrift_remove_next_hop_group_member(self.client, member)
                    self.assertEqual(status, SAI_STATUS_SUCCESS)
            member_count += len(members)

        total_time = time.perf_counter() - start_time
        perf = member_count / total_time if total_time > 0 else 0

        print(f"  ECMP Members: {member_count} removed, {total_time:.3f}s, {perf:.2f} members/s")

        return perf

    def _remove_ecmp_groups(self, ecmp_groups):
        """Remove ECMP groups

        Args:
            ecmp_groups: List of ECMP groups

        Returns:
            float: Performance in groups/s
        """
        start_time = time.perf_counter()

        failed_count = 0
        for group in ecmp_groups:
            status = sai_thrift_remove_next_hop_group(self.client, group)
            if status != SAI_STATUS_SUCCESS:
                failed_count += 1

        total_time = time.perf_counter() - start_time
        perf = len(ecmp_groups) / total_time if total_time > 0 else 0

        if failed_count > 0:
            print(f"  ECMP Groups: {len(ecmp_groups)} removed, {failed_count} failed, {total_time:.3f}s, {perf:.2f} groups/s")
        else:
            print(f"  ECMP Groups: {len(ecmp_groups)} removed, {total_time:.3f}s, {perf:.2f} groups/s")

        return perf

    def _measure_member_add_performance(self, ecmp_group, nh_list):
        """Measures performance of adding ECMP members one by one.

        Args:
            ecmp_group: ECMP group OID
            nh_list: List of next hop OIDs to add

        Returns:
            list: List of created member OIDs
        """
        print(f"\n[Step] Adding {len(nh_list)} members one by one")
        members = []
        add_times = []
        for i, nh in enumerate(nh_list):
            start = time.perf_counter()
            member = sai_thrift_create_next_hop_group_member(
                self.client,
                next_hop_group_id=ecmp_group,
                next_hop_id=nh
            )
            elapsed = (time.perf_counter() - start) * 1000  # ms
            print(
                f"    Add member {i+1}/{len(nh_list)}: {member}, time: {elapsed:.2f} ms")
            self.assertIsNotNone(member, f"Failed to add member {i+1}")
            add_times.append(elapsed)
            members.append(member)

        if not add_times:
            print("  No members were added, skipping performance check.")
            return members

        avg_add_time = statistics.mean(add_times)
        print(
            f"  All members added. Max time: {max(add_times):.2f} ms, Min time: {min(add_times):.2f} ms, Avg time: {avg_add_time:.2f} ms")

        self.record_spec("ecmp_member_op_latency", "add",
                         count=len(add_times),
                         actual_value=round(avg_add_time, 3))

        if avg_add_time < self.max_op_time_ms:
            perf_pass = True
            print(f"  [PASS] Average member add time {avg_add_time:.2f} ms < {self.max_op_time_ms} ms")
        else:
            perf_pass = False
            print(f"  [WARN] Average member add time {avg_add_time:.2f} ms >= {self.max_op_time_ms} ms")

        return members, perf_pass

    def _measure_member_remove_performance(self, members):
        """Measures performance of removing ECMP members one by one.

        Args:
            members: List of member OIDs to remove
        """
        print(f"\n[Step] Removing {len(members)} members one by one")
        remove_times = []
        for i, member in enumerate(members):
            start = time.perf_counter()
            status = sai_thrift_remove_next_hop_group_member(
                self.client, member)
            elapsed = (time.perf_counter() - start) * 1000  # ms
            print(
                f"    Remove member {i+1}/{len(members)}: status={status}, time: {elapsed:.2f} ms")
            self.assertEqual(
                status, SAI_STATUS_SUCCESS, f"Failed to remove member {i+1}")
            remove_times.append(elapsed)

        if not remove_times:
            print("  No members were removed, skipping performance check.")
            return

        avg_remove_time = statistics.mean(remove_times)
        print(
            f"  All members removed. Max time: {max(remove_times):.2f} ms, Min time: {min(remove_times):.2f} ms, Avg time: {avg_remove_time:.2f} ms")

        self.record_spec("ecmp_member_op_latency", "remove",
                         count=len(remove_times),
                         actual_value=round(avg_remove_time, 3))

        if avg_remove_time < self.max_op_time_ms:
            perf_pass = True
            print(f"  [PASS] Average member remove time {avg_remove_time:.2f} ms < {self.max_op_time_ms} ms")
        else:
            perf_pass = False
            print(f"  [WARN] Average member remove time {avg_remove_time:.2f} ms >= {self.max_op_time_ms} ms")

        return perf_pass


class L3IPv4MaxEcmpGroupScaleTest(L3EcmpScaleTestBase):
    """IPv4 ECMP Maximum Group Count Scale Test

    Test Objectives:
    1. Verify IPv4 ECMP maximum group count creation
    2. Test ECMP group creation performance
    3. Test ECMP member creation/removal performance
    4. Verify resource cleanup and recovery

    Test Number: 3.1.1
    """

    def setUp(self):
        """Initialize test environment

        Sets up:
        - Test parameters for maximum group count test
        - Performance expectations
        - Resource tracking variables
        """
        super(L3IPv4MaxEcmpGroupScaleTest, self).setUp()

        # Test parameters
        self.members_per_group = min(self.init_member_count // self.init_group_count, 64)
        self.groups_to_create = self.init_group_count

        # Resource tracking (inherited from base class)
        # self.ecmp_groups = []
        # self.group_to_members = {}
        # self.ecmp_members = []
        # self.test_routes = []
        # self.route_nh_map = {}

    def runTest(self):
        """Execute test"""
        print("\n=== Starting IPv4 ECMP Maximum Group Count Test ===")
        perf_pass = self._run_generic_scale_test(
            nh_dict=self.nh_v4_dict,
            install_routes_func=self.create_and_install_ipv4_routes
        )
        self.assertTrue(perf_pass, "IPv4 ECMP Maximum Group Count Test failed")

    def tearDown(self):
        super(L3IPv4MaxEcmpGroupScaleTest, self).tearDown()

class L3IPv4MaxEcmpMemberPerGroupScaleTest(L3EcmpScaleTestBase):
    """IPv4 ECMP Maximum Members Per Group Scale Test

    Test Objectives:
    1. Verify IPv4 ECMP group creation with maximum member count per group
    2. Test group creation performance at maximum member scale
    3. Validate final state restoration after test completion

    Test Number: 3.1.2
    """

    def setUp(self):
        """Initialize test environment

        Sets up:
        - Test parameters for maximum members per group test
        - Performance expectations
        - Resource tracking variables
        """
        super(L3IPv4MaxEcmpMemberPerGroupScaleTest, self).setUp()

        # Directly calculate groups_to_create, remove groups_full_members
        self.groups_to_create = int(self.init_member_count // self.max_members_per_ecmp) // 10 * 10
        self.members_per_group = self.max_members_per_ecmp

        print(f"[ECMP MaxMemberPerGroup] groups: {self.groups_to_create}")

    def runTest(self):
        """Execute test"""
        print("\n=== Starting IPv4 ECMP Maximum Members Per Group Test ===")
        perf_pass = self._run_generic_scale_test(
            nh_dict=self.nh_v4_dict,
            install_routes_func=self.create_and_install_ipv4_routes
        )
        self.assertTrue(perf_pass, "IPv4 ECMP Maximum Members Per Group Test failed")

    def tearDown(self):
        super(L3IPv4MaxEcmpMemberPerGroupScaleTest, self).tearDown()

class L3IPv6MaxEcmpGroupScaleTest(L3EcmpScaleTestBase):
    """IPv6 ECMP Maximum Group Count Scale Test

    Test Objectives:
    1. Verify IPv6 ECMP maximum group count creation
    2. Test ECMP group creation performance
    3. Test ECMP member creation/removal performance
    4. Verify resource cleanup and recovery

    Test Number: 3.1.3
    """

    def setUp(self):
        """Initialize test environment

        Sets up:
        - Test parameters for maximum group count test
        - Performance expectations
        - Resource tracking variables
        """
        super(L3IPv6MaxEcmpGroupScaleTest, self).setUp()

        # Test parameters
        self.members_per_group = min(self.init_member_count // self.init_group_count, 64)
        self.groups_to_create = self.init_group_count

        print(
            f"[ECMP MaxGroupScale] members/group: {self.members_per_group}, groups: {self.groups_to_create}")

    def runTest(self):
        """Execute test"""
        print("\n=== Starting IPv6 ECMP Maximum Group Count Test ===")
        perf_pass = self._run_generic_scale_test(
            nh_dict=self.nh_v6_dict,
            install_routes_func=self.create_and_install_ipv6_routes
        )
        self.assertTrue(perf_pass, "IPv6 ECMP Maximum Group Count Test failed")

    def tearDown(self):
        super(L3IPv6MaxEcmpGroupScaleTest, self).tearDown()

class L3IPv6MaxEcmpMemberPerGroupScaleTest(L3EcmpScaleTestBase):
    """IPv6 ECMP Maximum Members Per Group Scale Test

    Test Objectives:
    1. Verify IPv6 ECMP group creation with maximum member count per group
    2. Test group creation performance at maximum member scale
    3. Validate final state restoration after test completion

    Test Number: 3.1.4
    """

    def setUp(self):
        """Initialize test environment

        Sets up:
        - Test parameters for maximum members per group test
        - Performance expectations
        - Resource tracking variables
        """
        super(L3IPv6MaxEcmpMemberPerGroupScaleTest, self).setUp()

        # Test parameters
        # Directly calculate groups_to_create, remove groups_full_members and groups_4_members
        self.groups_to_create = int(self.init_member_count // self.max_members_per_ecmp) // 10 * 10
        self.members_per_group = self.max_members_per_ecmp

        print(f"[ECMP MaxMemberPerGroup] groups: {self.groups_to_create}")

    def runTest(self):
        """Execute test"""
        print("\n=== Starting IPv6 ECMP Maximum Members Per Group Test ===")
        perf_pass = self._run_generic_scale_test(
            nh_dict=self.nh_v6_dict,
            install_routes_func=self.create_and_install_ipv6_routes
        )
        self.assertTrue(perf_pass, "IPv6 ECMP Maximum Members Per Group Test failed")

    def tearDown(self):
        super(L3IPv6MaxEcmpMemberPerGroupScaleTest, self).tearDown()

class L3IPv4EcmpMemberOperPerformanceTest(L3EcmpScaleTestBase):
    """IPv4 ECMP Member Operation Performance Test

    Test Objectives:
    1. Establish performance baseline for IPv4 ECMP group operations
    2. Verify group creation performance meets expected thresholds
    3. Validate performance consistency across different test runs

    Test Number: 3.1.5
    """

    def setUp(self):
        """Initialize test environment

        Sets up:
        - Test parameters for member operation performance test
        - Performance expectations
        - Resource tracking variables
        """
        super(L3IPv4EcmpMemberOperPerformanceTest, self).setUp()

        # Performance requirements
        self.max_op_time_ms = 5.0  # 5ms performance limit

    def runTest(self):
        """Execute test"""
        print("\n=== Starting IPv4 ECMP Member Operation Performance Test (Single ECMP, step-by-step member add/remove) ===")

        try:
            # 1. Create an ECMP group
            print("\n[Step 1] Creating ECMP Group")
            ecmp_group = sai_thrift_create_next_hop_group(
                self.client, type=SAI_NEXT_HOP_GROUP_TYPE_ECMP)
            self.assertIsNotNone(ecmp_group, "ECMP group creation failed")
            self.ecmp_groups.append(ecmp_group)
            print(f"  ECMP group created: {ecmp_group}")

            # 2. Add members and measure performance
            nh_list = [v['nh'] for v in self.nh_v4_dict.values()]
            self.assertGreaterEqual(len(
                nh_list), self.max_members_per_ecmp, "Not enough next hops for test")

            members_to_test = nh_list[:self.max_members_per_ecmp]
            self.ecmp_members, add_perf_pass = self._measure_member_add_performance(ecmp_group, members_to_test)

            # 3. Remove members and measure performance
            remove_perf_pass = self._measure_member_remove_performance(self.ecmp_members)
            self.ecmp_members = []

            sai_thrift_remove_next_hop_group(self.client, ecmp_group)
            self.ecmp_groups = []

            self.assertTrue(add_perf_pass and remove_perf_pass, "IPv4 ECMP Member Operation Performance Test failed")

        finally:
            # Use unified cleanup
            self._cleanup_all_ecmp_resources()

    def tearDown(self):
        super(L3IPv4EcmpMemberOperPerformanceTest, self).tearDown()

class L3IPv6EcmpMemberOperPerformanceTest(L3EcmpScaleTestBase):
    """IPv6 ECMP Member Operation Performance Test

    Test Objectives:
    1. Establish performance baseline for IPv6 ECMP group operations
    2. Verify group creation performance meets expected thresholds with IPv6
    3. Compare IPv6 vs IPv4 performance characteristics

    Test Number: 3.1.6
    """

    def setUp(self):
        """Initialize test environment

        Sets up:
        - Test parameters for member operation performance test
        - Performance expectations
        - Resource tracking variables
        """
        super(L3IPv6EcmpMemberOperPerformanceTest, self).setUp()

        # Performance requirements
        self.max_op_time_ms = 5.0  # 5ms performance limit

    def runTest(self):
        """Execute test"""
        print("\n=== Starting IPv6 ECMP Member Operation Performance Test (Single ECMP, step-by-step member add/remove) ===")

        try:
            # 1. Create an ECMP group
            print("\n[Step 1] Creating ECMP Group")
            ecmp_group = sai_thrift_create_next_hop_group(
                self.client, type=SAI_NEXT_HOP_GROUP_TYPE_ECMP)
            self.assertIsNotNone(ecmp_group, "ECMP group creation failed")
            self.ecmp_groups.append(ecmp_group)
            print(f"  ECMP group created: {ecmp_group}")

            # 2. Add members and measure performance
            nh_list = [v['nh'] for v in self.nh_v6_dict.values()]
            self.assertGreaterEqual(len(
                nh_list), self.max_members_per_ecmp, "Not enough next hops for test")

            members_to_test = nh_list[:self.max_members_per_ecmp]
            self.ecmp_members, add_perf_pass = self._measure_member_add_performance(ecmp_group, members_to_test)

            # 3. Remove members and measure performance
            remove_perf_pass = self._measure_member_remove_performance(self.ecmp_members)
            self.ecmp_members = []

            sai_thrift_remove_next_hop_group(self.client, ecmp_group)
            self.ecmp_groups = []

            self.assertTrue(add_perf_pass and remove_perf_pass, "IPv6 ECMP Member Operation Performance Test failed")

        finally:
            # Use unified cleanup
            self._cleanup_all_ecmp_resources()

    def tearDown(self):
        super(L3IPv6EcmpMemberOperPerformanceTest, self).tearDown()


class L3IPv4MaxRouteEcmpScaleTest(L3EcmpScaleTestBase):
    """IPv4 Maximum Route ECMP Scale Test

    Test Objectives:
    1. Verify maximum route count with ECMP support for IPv4
    2. Test route creation and removal performance
    3. Validate resource cleanup and recovery

    Test Number: 3.1.7
    """

    def setUp(self):
        """Initialize test environment

        Sets up:
        - Test parameters for maximum route scale test
        - Performance expectations
        - Resource tracking variables
        """
        super(L3IPv4MaxRouteEcmpScaleTest, self).setUp()

        # Test parameters
        self.routes_to_create = int(self.init_ipv4_route_count * 0.85)  # Maximum routes to test
        self.route16_count = int(self.routes_to_create * 0.10)
        self.route24_count = int(self.routes_to_create * 0.30)
        self.route28_count = int(self.routes_to_create * 0.40)
        self.route32_count = self.routes_to_create - self.route16_count - self.route24_count - self.route28_count

        self.members_per_group = min(self.init_member_count // self.init_group_count, 64)
        self.groups_to_create = self.init_group_count


    def runTest(self):
        """Execute test"""
        print("\n=== Starting IPv4 Maximum Route ECMP Scale Test (3 iterations) ===")

        # Performance tracking for 3 iterations
        performance_results = {
            'group_create_perf': [],
            'member_create_perf': [],
            'member_remove_perf': [],
            'group_remove_perf': [],
            'route_create_perf': [],
            'route_remove_perf': []
        }

        # Generate routes outside the loop
        prefix16 = self.generate_ipv4_prefixes(prefix_len=16, start_ip="10.0.0.0", step=1, count=self.route16_count)
        prefix24 = self.generate_ipv4_prefixes(prefix_len=24, start_ip="20.0.0.0", step=1, count=self.route24_count)
        prefix28 = self.generate_ipv4_prefixes(prefix_len=28, start_ip="30.0.0.0", step=1, count=self.route28_count)
        prefix32 = self.generate_ipv4_prefixes(prefix_len=32, start_ip="40.0.0.0", step=1, count=self.route32_count)
        prefix_list = prefix16 + prefix24 + prefix28 + prefix32

        # remove_routes() below records self._spec_name internally; retag so the
        # ECMP route throughput does not overwrite ipv4_route_scale.
        self._spec_name = "ecmp_route_scale"

        try:
            for iteration in range(3):
                print(f"\n--- Iteration {iteration + 1}/3 ---")

                # 1. Create ECMP groups
                group_create_perf = self._create_ecmp_groups()
                performance_results['group_create_perf'].append(group_create_perf)
                self.record_spec("ecmp_group_scale", "create",
                                 count=len(self.ecmp_groups),
                                 actual_value=round(group_create_perf, 2))

                # 2. Create ECMP members
                self.group_to_members, member_create_perf = self._create_ecmp_members(
                    self.ecmp_groups, self.nh_v4_dict)
                self.ecmp_members = [
                    m for members in self.group_to_members.values() for m in members]
                performance_results['member_create_perf'].append(member_create_perf)
                self.record_spec("ecmp_member_scale", "create",
                                 count=len(self.ecmp_members),
                                 actual_value=round(member_create_perf, 2))

                # 3. Create and install routes
                route_list = []
                group_list = []
                for prefix in prefix_list:
                    group = random.choice(self.ecmp_groups)
                    route_entry = sai_thrift_route_entry_t(
                        vr_id=self.default_vrf, destination=sai_ipprefix(prefix))
                    self.route_nh_map[prefix] = group
                    route_list.append(route_entry)
                    group_list.append(group)

                route_create_perf = self.create_routes(
                    route_list, group_list, measure_perf=True)
                if route_create_perf:
                    performance_results['route_create_perf'].append(route_create_perf)
                    self.record_spec("ecmp_route_scale", "create",
                                     count=len(route_list),
                                     actual_value=round(route_create_perf, 2))

                # Capture counts before cleanup for summary
                group_count = len(self.ecmp_groups)
                member_count = len(self.ecmp_members)
                route_count = len(self.test_routes)

                # 4. (Optional) Traffic verification
                # traffic_verified = self.verify_ecmp_traffic()

                # 5. Remove routes and measure performance
                route_remove_perf = self.remove_routes(self.test_routes, self.bulk_size)
                if route_remove_perf:
                    performance_results['route_remove_perf'].append(route_remove_perf)
                self.test_routes = []

                # 6. Remove ECMP members and measure performance
                member_remove_perf = self._remove_ecmp_members(self.group_to_members)
                performance_results['member_remove_perf'].append(member_remove_perf)
                self.record_spec("ecmp_member_scale", "remove",
                                 count=member_count,
                                 actual_value=round(member_remove_perf, 2))
                self.group_to_members = {}
                self.ecmp_members = []

                # 7. Remove ECMP groups and measure performance
                group_remove_perf = self._remove_ecmp_groups(self.ecmp_groups)
                performance_results['group_remove_perf'].append(group_remove_perf)
                self.record_spec("ecmp_group_scale", "remove",
                                 count=group_count,
                                 actual_value=round(group_remove_perf, 2))
                self.ecmp_groups = []

                # 8. Resource recovery verification
                final_verified = self.check_ecmp_resource_recovery()

                # Output iteration summary
                print(f"  Iteration {iteration + 1} Summary: Groups={group_count}, Members={member_count}, Routes={route_count}, Recovery={'PASS' if final_verified else 'FAIL'}")

            # Calculate average performance across all iterations
            print(f"\n=== Performance Summary (3 iterations) ===")
            avg_results = {}
            for metric, values in performance_results.items():
                if values:
                    avg_value = sum(values) / len(values)
                    avg_results[metric] = avg_value
                    print(f"  {metric}: {avg_value:.2f} (values: {[f'{v:.2f}' for v in values]})")
                else:
                    avg_results[metric] = 0.0
                    print(f"  {metric}: No data available")

            # 9. Performance result verification using averages
            avg_results['final_verified'] = self.check_ecmp_resource_recovery()
            perf_pass = self._verify_performance_results(avg_results)
            print(f"  Performance pass: {perf_pass}")
            self.assertTrue(perf_pass, "IPv4 Maximum Route ECMP Scale Test failed")

        finally:
            # Ensure resource cleanup
            self._cleanup_all_ecmp_resources()


class L3IPv6MaxRouteEcmpScaleTest(L3EcmpScaleTestBase):
    """IPv6 Maximum Route ECMP Scale Test

    Test Objectives:
    1. Verify maximum route count with ECMP support for IPv6
    2. Test route creation and removal performance
    3. Validate resource cleanup and recovery

    Test Number: 3.1.8
    """

    def setUp(self):
        """Initialize test environment

        Sets up:
        - Test parameters for maximum route scale test
        - Performance expectations
        - Resource tracking variables
        """
        super(L3IPv6MaxRouteEcmpScaleTest, self).setUp()

        # Test parameters
        self.groups_to_create = self.init_group_count
        self.routes_to_create = int(self.init_ipv6_route_count * 0.85)
        self.route48_count = int(self.routes_to_create * 0.30)
        self.route56_count = int(self.routes_to_create * 0.30)
        self.route64_count = self.routes_to_create - self.route48_count - self.route56_count

        self.members_per_group = min(self.init_member_count // self.init_group_count, 64)
        self.groups_to_create = self.init_group_count


    def runTest(self):
        """Execute test"""
        print("\n=== Starting IPv6 Maximum Route ECMP Scale Test (3 iterations) ===")

        # Performance tracking for 3 iterations
        performance_results = {
            'group_create_perf': [],
            'member_create_perf': [],
            'member_remove_perf': [],
            'group_remove_perf': [],
            'route_create_perf': [],
            'route_remove_perf': []
        }

        # Generate routes outside the loop
        prefix48 = self.generate_ipv6_prefixes(prefix_len=48, start_ip="2000::", step=1, count=self.route48_count)
        prefix56 = self.generate_ipv6_prefixes(prefix_len=56, start_ip="3000::", step=1, count=self.route56_count)
        prefix64 = self.generate_ipv6_prefixes(prefix_len=64, start_ip="4000::", step=1, count=self.route64_count)
        prefix_list = prefix48 + prefix56 + prefix64

        # remove_routes() below records self._spec_name internally; retag so the
        # ECMP route throughput does not overwrite ipv4_route_scale.
        self._spec_name = "ecmp_route_scale"

        try:
            for iteration in range(3):
                print(f"\n--- Iteration {iteration + 1}/3 ---")

                # 1. Create ECMP groups
                group_create_perf = self._create_ecmp_groups()
                performance_results['group_create_perf'].append(group_create_perf)
                self.record_spec("ecmp_group_scale", "create",
                                 count=len(self.ecmp_groups),
                                 actual_value=round(group_create_perf, 2))

                # 2. Create ECMP members
                self.group_to_members, member_create_perf = self._create_ecmp_members(
                    self.ecmp_groups, self.nh_v6_dict)
                self.ecmp_members = [
                    m for members in self.group_to_members.values() for m in members]
                performance_results['member_create_perf'].append(member_create_perf)
                self.record_spec("ecmp_member_scale", "create",
                                 count=len(self.ecmp_members),
                                 actual_value=round(member_create_perf, 2))

                # 3. Create and install routes by pattern and proportion
                route_list, group_list = self._prepare_route_and_group_lists(
                    prefix_list, self.ecmp_groups, assignment_mode='random')

                route_create_perf = self.create_routes(
                    route_list, group_list, measure_perf=True)
                if route_create_perf:
                    performance_results['route_create_perf'].append(route_create_perf)
                    self.record_spec("ecmp_route_scale", "create",
                                     count=len(route_list),
                                     actual_value=round(route_create_perf, 2))

                # Capture counts before cleanup for summary
                group_count = len(self.ecmp_groups)
                member_count = len(self.ecmp_members)
                route_count = len(self.test_routes)

                # 4. (Optional) Traffic verification
                # traffic_verified = self.verify_ecmp_traffic()

                # 5. Remove routes and measure performance
                route_remove_perf = self.remove_routes(self.test_routes, self.bulk_size)
                if route_remove_perf:
                    performance_results['route_remove_perf'].append(route_remove_perf)
                self.test_routes = []

                # 6. Remove ECMP members and measure performance
                member_remove_perf = self._remove_ecmp_members(self.group_to_members)
                performance_results['member_remove_perf'].append(member_remove_perf)
                self.record_spec("ecmp_member_scale", "remove",
                                 count=member_count,
                                 actual_value=round(member_remove_perf, 2))
                self.group_to_members = {}
                self.ecmp_members = []

                # 7. Remove ECMP groups and measure performance
                group_remove_perf = self._remove_ecmp_groups(self.ecmp_groups)
                performance_results['group_remove_perf'].append(group_remove_perf)
                self.record_spec("ecmp_group_scale", "remove",
                                 count=group_count,
                                 actual_value=round(group_remove_perf, 2))
                self.ecmp_groups = []

                # 8. Resource recovery verification
                final_verified = self.check_ecmp_resource_recovery()

                # Output iteration summary
                print(f"  Iteration {iteration + 1} Summary: Groups={group_count}, Members={member_count}, Routes={route_count}, Recovery={'PASS' if final_verified else 'FAIL'}")

            # Calculate average performance across all iterations
            print(f"\n=== Performance Summary (3 iterations) ===")
            avg_results = {}
            for metric, values in performance_results.items():
                if values:
                    avg_value = sum(values) / len(values)
                    avg_results[metric] = avg_value
                    print(f"  {metric}: {avg_value:.2f} (values: {[f'{v:.2f}' for v in values]})")
                else:
                    avg_results[metric] = 0.0
                    print(f"  {metric}: No data available")

            # 9. Performance result verification using averages
            avg_results['final_verified'] = self.check_ecmp_resource_recovery()
            perf_pass = self._verify_performance_results(avg_results)
            print(f"  Performance pass: {perf_pass}")
            self.assertTrue(perf_pass, "IPv6 Maximum Route ECMP Scale Test failed")

        finally:
            # Ensure resource cleanup
            self._cleanup_all_ecmp_resources()


class L3EcmpRouteFlapTestBase(L3EcmpScaleTestBase):
    """Shared route-flap scenario: foreground ECMP, simulated NH loss, restore, cleanup.

    IPv4/IPv6 subclasses supply foreground NH table, prefix generators, and background RIF/NH.
    """

    BG_VLANS = [100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 1100, 1200, 1300, 1400, 1500, 1600]
    FG_ROUTE_COUNT = 50000
    BG_ROUTE_COUNT = 50000

    # Baseline: logical_ecmp_group_index -> nh_topology_index_list (full membership). Do not mutate;
    # flap steps use a deep copy in self._fg_group_to_nh_indices.
    FG_ECMP_GROUP_TO_NH_INDICES = [
        (0, list(range(32))),
        (1, list(range(32, 64))),
        (2, list(range(16)) + list(range(64, 80))),
        (3, list(range(16, 32)) + list(range(32, 48)) + list(range(80, 96))),
    ]

    def setUp(self):
        super(L3EcmpRouteFlapTestBase, self).setUp()
        self.nh_2_list = []
        self.bg_rif_list = []
        self.bg_route_flap_aux_nh = {}
        self.bg_groups = []
        self.bg_members = []
        self.fg_route_entries = []
        self.fg_route_prefix_to_group_idx = {}
        self.bg_route_entries = []
        self.flap_group_times = []
        self.flap_member_times = []
        self.flap_group_remove_times = []
        self.flap_member_remove_times = []
        self._fg_group_to_nh_indices = {
            gidx: list(nh_list)
            for gidx, nh_list in self.FG_ECMP_GROUP_TO_NH_INDICES
        }

    def _report_route_flap_performance_summary(self):
        """Print summary after flap cleanup.

        Requires cleanup first so check_ecmp_resource_recovery() matches initial
        switch capacity like the generic scale test.
        """
        if (not self.flap_group_times
                and not self.flap_group_remove_times):
            return
        final_verified = self.check_ecmp_resource_recovery()
        results = {'final_verified': final_verified}
        if self.flap_group_times:
            results['group_create_perf'] = (
                sum(self.flap_group_times) / len(self.flap_group_times))
            self.record_spec("route_flap", "group_create",
                             count=len(self.flap_group_times),
                             actual_value=round(results['group_create_perf'], 2))
        if self.flap_member_times:
            results['member_create_perf'] = (
                sum(self.flap_member_times) / len(self.flap_member_times))
            self.record_spec("route_flap", "member_create",
                             count=len(self.flap_member_times),
                             actual_value=round(results['member_create_perf'], 2))
        if self.flap_group_remove_times:
            results['group_remove_perf'] = (
                sum(self.flap_group_remove_times)
                / len(self.flap_group_remove_times))
            self.record_spec("route_flap", "group_remove",
                             count=len(self.flap_group_remove_times),
                             actual_value=round(results['group_remove_perf'], 2))
        if self.flap_member_remove_times:
            results['member_remove_perf'] = (
                sum(self.flap_member_remove_times)
                / len(self.flap_member_remove_times))
            self.record_spec("route_flap", "member_remove",
                             count=len(self.flap_member_remove_times),
                             actual_value=round(results['member_remove_perf'], 2))
        perf_pass = self._verify_performance_results(results)
        print(f"  Performance pass: {perf_pass}")

    def _print_simulate_nh_down_intent(self, nh_indices_to_down, step_detail):
        """Log which NH are treated as down and which foreground groups must shrink."""
        nh_sorted = sorted(set(nh_indices_to_down))
        if not nh_sorted:
            return
        if nh_sorted[-1] - nh_sorted[0] == len(nh_sorted) - 1:
            span = f"NH{nh_sorted[0]}-NH{nh_sorted[-1]}"
        else:
            span = f"NH indices {nh_sorted}"
        if not step_detail:
            print(
                f"    simulate {span} down — no foreground ECMP group references "
                f"these NH; skip rebuild")
            return
        glist = ", ".join(str(g) for g, _ in step_detail)
        print(
            f"    simulate {span} down — rebuild foreground group(s) [{glist}] ")
        for gidx, removed_sorted in step_detail:
            print(f"      group{gidx}: remove NH {removed_sorted}")

    def _create_ecmp_members_for_pairs(self, group_nh_pairs, print_summary=True,
                                       expected_total_for_summary=None):
        """Create members for explicit (group_oid, nh_list) pairs.

        Same bulk/single-object path and status handling as _create_ecmp_members.
        Uses wall-clock only (no get_timetxt); for route-flap tests.
        """
        start_time = time.perf_counter()
        group_to_members = {}
        total_members = 0
        failed_members = 0

        for group, nhs in group_nh_pairs:
            if not nhs:
                group_to_members[group] = []
                continue
            if self.support_ecmp_member_bulk_api:
                attr_counts = [2] * len(nhs)
                next_hop_group_ids = [group] * len(nhs)
                object_statuses = []
                members = sai_thrift_bulk_create_next_hop_group_member(
                    self.client,
                    attr_counts,
                    SAI_BULK_OP_ERROR_MODE_IGNORE_ERROR,
                    object_statuses,
                    next_hop_group_id=next_hop_group_ids,
                    next_hop_id=nhs
                )
                if self.status() != SAI_STATUS_SUCCESS:
                    print(f"  Warning: Bulk member creation failed with status {self.status()}")
                    failed_members += len(nhs)
                    members = []
                else:
                    for member in members:
                        self.assertNotEqual(member, SAI_NULL_OBJECT_ID)
            else:
                members = []
                for nh in nhs:
                    member = sai_thrift_create_next_hop_group_member(
                        self.client,
                        next_hop_group_id=group,
                        next_hop_id=nh
                    )
                    if member != SAI_NULL_OBJECT_ID:
                        members.append(member)
                    else:
                        print(f"  Warning: Member creation returned NULL object ID")
                        failed_members += 1

            group_to_members[group] = members
            total_members += len(members)

        total_time = time.perf_counter() - start_time
        perf = total_members / total_time if total_time > 0 else 0

        if print_summary:
            denom = expected_total_for_summary
            if denom is None:
                denom = sum(len(nhs) for _, nhs in group_nh_pairs)
            if failed_members > 0:
                print(f"  ECMP Members: {total_members}/{denom} created, {failed_members} failed, {total_time:.3f}s, {perf:.2f} members/s")
            else:
                print(f"  ECMP Members: {total_members}/{denom} created, {total_time:.3f}s, {perf:.2f} members/s")

        return group_to_members, total_members, total_time, perf

    def _build_foreground_groups(self):
        """Create 4 ECMP groups with specified NH sets. Returns list of (group_oid, member_oids)."""
        nh = self._route_flap_fg_nh_dict
        group0_nhs = [nh[i]['nh'] for i in range(32)]
        group1_nhs = [nh[i]['nh'] for i in range(32, 64)]
        group2_nhs = [nh[i]['nh'] for i in list(range(16)) + list(range(64, 80))]
        group3_nhs = [nh[i]['nh'] for i in list(range(16, 32)) + list(range(32, 48)) + list(range(80, 96))]
        groups_config = [
            ("Group0", group0_nhs),
            ("Group1", group1_nhs),
            ("Group2", group2_nhs),
            ("Group3", group3_nhs),
        ]
        pairs = []
        meta = []
        for name, nhs in groups_config:
            grp = sai_thrift_create_next_hop_group(
                self.client, type=SAI_NEXT_HOP_GROUP_TYPE_ECMP)
            self.assertNotEqual(grp, SAI_NULL_OBJECT_ID)
            self.ecmp_groups.append(grp)
            pairs.append((grp, nhs))
            meta.append((name, grp))

        mem_map, _, _, _ = self._create_ecmp_members_for_pairs(
            pairs, print_summary=False)
        created = []
        for name, grp in meta:
            members = mem_map.get(grp, [])
            self.ecmp_members.extend(members)
            self.group_to_members[grp] = members
            created.append((grp, members))
            print(f"  {name}: group oid:0x{grp:016x} with {len(members)} members")
        return created

    def _create_background_ecmp(self, G_2, M_2):
        """Create G_2 ECMP groups with M_2 members each from NH_2."""
        if not self.nh_2_list or G_2 <= 0 or M_2 <= 0:
            return []
        nh_pool = list(self.nh_2_list)
        random.shuffle(nh_pool)
        groups = []
        for _ in range(G_2):
            grp = sai_thrift_create_next_hop_group(
                self.client, type=SAI_NEXT_HOP_GROUP_TYPE_ECMP)
            if grp == SAI_NULL_OBJECT_ID:
                continue
            self.bg_groups.append(grp)
            chosen = random.sample(nh_pool, min(M_2, len(nh_pool)))
            members = []
            for nh_oid in chosen:
                m = sai_thrift_create_next_hop_group_member(
                    self.client, next_hop_group_id=grp, next_hop_id=nh_oid)
                self.assertNotEqual(m, SAI_NULL_OBJECT_ID)
                members.append(m)
                self.bg_members.append(m)
            self.group_to_members[grp] = members
            groups.append(grp)
        print(f"  Background ECMP: {len(groups)} groups, {M_2} members per group")
        return groups

    def _create_foreground_routes(self, group_oids):
        """Create FG_ROUTE_COUNT routes, evenly assigned to the 4 groups."""
        prefix_list = self._generate_fg_route_prefixes()
        route_list = []
        group_list = []
        for idx, prefix in enumerate(prefix_list):
            route_entry = sai_thrift_route_entry_t(
                vr_id=self.default_vrf, destination=sai_ipprefix(prefix))
            gidx = idx % 4
            grp = group_oids[gidx]
            route_list.append(route_entry)
            group_list.append(grp)
            self.route_nh_map[prefix] = grp
            self.fg_route_prefix_to_group_idx[prefix] = gidx
        self.create_routes(route_list, group_list)
        for r, g in zip(route_list, group_list):
            self.fg_route_entries.append((r, g))
        print(f"  Foreground routes: {len(route_list)} created, assigned to 4 groups")

    def _create_background_routes(self, bg_group_oids):
        """Create BG_ROUTE_COUNT background routes and assign to background groups."""
        if not bg_group_oids:
            return
        prefix_list = self._generate_bg_route_prefixes()
        route_list = []
        group_list = []
        for idx, prefix in enumerate(prefix_list):
            route_entry = sai_thrift_route_entry_t(
                vr_id=self.default_vrf, destination=sai_ipprefix(prefix))
            grp = bg_group_oids[idx % len(bg_group_oids)]
            route_list.append(route_entry)
            group_list.append(grp)
            self.route_nh_map[prefix] = grp
        self.create_routes(route_list, group_list)
        for r in route_list:
            self.bg_route_entries.append(r)
        print(f"  Background routes: {len(route_list)} created")

    def _routes_pointing_to_group(self, group_oid):
        """Return list of (route_entry, prefix) for foreground routes that use this group."""
        out = []
        for prefix, gidx in self.fg_route_prefix_to_group_idx.items():
            if gidx is None:
                continue
            grp = self.fg_groups_current[gidx]
            if grp == group_oid:
                route_entry = sai_thrift_route_entry_t(
                    vr_id=self.default_vrf, destination=sai_ipprefix(prefix))
                out.append((route_entry, prefix))
        return out

    def _update_routes_to_new_group(self, route_entries_with_prefix, new_group_oid):
        """Update route next_hop to new_group_oid and refresh route_nh_map and fg_groups_current."""
        for route_entry, prefix in route_entries_with_prefix:
            sai_thrift_set_route_entry_attribute(
                self.client, route_entry, next_hop_id=new_group_oid)
            self.route_nh_map[prefix] = new_group_oid
            gidx = self.fg_route_prefix_to_group_idx.get(prefix)
            if gidx is not None:
                self.fg_groups_current[gidx] = new_group_oid

    def _delete_group_and_members(self, group_oid):
        """Remove all NHG members then the NHG; drop group_to_members entry.

        Thrift wall time is measured only around sai_thrift_remove_next_hop_group_member /
        sai_thrift_remove_next_hop_group (not list copy or dict delete).

        Returns:
            (member_count, member_thrift_seconds, group_thrift_seconds)
        """
        members = list(self.group_to_members.get(group_oid, []))
        member_thrift_seconds = 0.0
        for m in members:
            t0 = time.perf_counter()
            status = sai_thrift_remove_next_hop_group_member(self.client, m)
            member_thrift_seconds += time.perf_counter() - t0
            self.assertEqual(status, SAI_STATUS_SUCCESS)
        t0 = time.perf_counter()
        status = sai_thrift_remove_next_hop_group(self.client, group_oid)
        group_thrift_seconds = time.perf_counter() - t0
        self.assertEqual(status, SAI_STATUS_SUCCESS)
        if group_oid in self.group_to_members:
            del self.group_to_members[group_oid]
        return len(members), member_thrift_seconds, group_thrift_seconds

    def _simulate_nh_down(self, nh_indices_to_down):
        """Rebuild foreground ECMP for groups whose current NH index list intersects this down set.

        self._fg_group_to_nh_indices holds the running membership per logical group; it is updated
        after a successful step (same cumulative effect as a global accumulated-down set).
        """
        nh_down_index_set = set(nh_indices_to_down)
        nh_dict = self._route_flap_fg_nh_dict

        remaining_by_idx = {}
        affected = []
        new_index_lists = {}
        step_detail = []
        for gidx, cur_nh_indices in self._fg_group_to_nh_indices.items():
            cur_set = set(cur_nh_indices)
            hit = cur_set & nh_down_index_set
            if not hit:
                continue
            affected.append(gidx)
            removed_sorted = sorted(hit)
            new_list = [i for i in cur_nh_indices if i not in nh_down_index_set]
            new_index_lists[gidx] = new_list
            remaining_by_idx[gidx] = [nh_dict[i]['nh'] for i in new_list]
            step_detail.append((gidx, removed_sorted))

        self._print_simulate_nh_down_intent(nh_indices_to_down, step_detail)

        pending = []
        t0 = time.perf_counter()
        for gidx in affected:
            remain = remaining_by_idx.get(gidx, [])
            grp = sai_thrift_create_next_hop_group(
                self.client, type=SAI_NEXT_HOP_GROUP_TYPE_ECMP)
            if grp == SAI_NULL_OBJECT_ID:
                continue
            pending.append((gidx, grp, remain))
        t_grp = time.perf_counter() - t0
        n_groups_step = len(pending)
        grp_rate = (n_groups_step / t_grp) if t_grp > 0 else 0.0
        if t_grp > 0 and pending:
            self.flap_group_times.append(grp_rate)

        pairs = [(grp, rem) for _, grp, rem in pending if rem]
        mem_res, member_count, t_mem, _ = self._create_ecmp_members_for_pairs(
            pairs, print_summary=False)
        mem_rate = (member_count / t_mem) if t_mem > 0 else 0.0
        if member_count > 0 and t_mem > 0:
            self.flap_member_times.append(mem_rate)

        new_groups = {}
        for gidx, grp, remain in pending:
            members = mem_res.get(grp, []) if remain else []
            self.ecmp_members.extend(members)
            self.group_to_members[grp] = members
            new_groups[gidx] = grp

        old_grps_order = []
        for gidx, new_grp in new_groups.items():
            old_grp = self.fg_groups_current[gidx]
            old_grps_order.append(old_grp)
            route_pairs = self._routes_pointing_to_group(old_grp)
            self._update_routes_to_new_group(route_pairs, new_grp)
            self.fg_groups_current[gidx] = new_grp

        n_mem_del = 0
        t_mem_del = 0.0
        n_grps_del = 0
        t_grp_del = 0.0
        for old_grp in old_grps_order:
            n_m, t_m, t_g = self._delete_group_and_members(old_grp)
            n_mem_del += n_m
            t_mem_del += t_m
            t_grp_del += t_g
            n_grps_del += 1

        mem_rm_rate = (n_mem_del / t_mem_del) if t_mem_del > 0 else 0.0
        grp_rm_rate = (n_grps_del / t_grp_del) if t_grp_del > 0 else 0.0
        if t_mem_del > 0 and n_mem_del > 0:
            self.flap_member_remove_times.append(mem_rm_rate)
        if t_grp_del > 0 and n_grps_del > 0:
            self.flap_group_remove_times.append(grp_rm_rate)

        print(
            f"    this step — create {n_groups_step} ECMP group(s) "
            f"({grp_rate:.2f} groups/s), create {member_count} ECMP member(s) "
            f"({mem_rate:.2f} members/s)\n"
            f"    this step — remove {n_mem_del} ECMP member(s) "
            f"({mem_rm_rate:.2f} members/s), remove {n_grps_del} ECMP group(s) "
            f"({grp_rm_rate:.2f} groups/s)")

        for gidx in new_index_lists:
            self._fg_group_to_nh_indices[gidx] = new_index_lists[gidx]

    def _simulate_nh_up_restore_full(self):
        """Restore full 4 groups and point foreground routes back to them."""
        print("    restore all NH — rebuild 4 full foreground ECMP groups")
        self._fg_group_to_nh_indices = {
            gidx: list(nh_list)
            for gidx, nh_list in self.FG_ECMP_GROUP_TO_NH_INDICES
        }
        nh = self._route_flap_fg_nh_dict
        n_groups_step = 0
        t_grp_sum = 0.0
        member_count_step = 0
        t_mem_sum = 0.0
        t_mem_del_sum = 0.0
        n_mem_del = 0
        t_grp_del_sum = 0.0
        n_grps_del = 0
        for gidx, nh_indices in self._fg_group_to_nh_indices.items():
            nhs = [nh[i]['nh'] for i in nh_indices]
            t0g = time.perf_counter()
            grp = sai_thrift_create_next_hop_group(
                self.client, type=SAI_NEXT_HOP_GROUP_TYPE_ECMP)
            t_grp_sum += time.perf_counter() - t0g
            self.assertNotEqual(grp, SAI_NULL_OBJECT_ID)
            n_groups_step += 1
            mem_res, mc, tm, _ = self._create_ecmp_members_for_pairs(
                [(grp, nhs)], print_summary=False)
            member_count_step += mc
            t_mem_sum += tm
            members = mem_res.get(grp, [])
            self.group_to_members[grp] = members
            self.ecmp_groups.append(grp)
            self.ecmp_members.extend(members)
            old_grp = self.fg_groups_current[gidx]
            route_pairs = self._routes_pointing_to_group(old_grp)
            self._update_routes_to_new_group(route_pairs, grp)
            self.fg_groups_current[gidx] = grp
            n_m, t_m, t_g = self._delete_group_and_members(old_grp)
            n_mem_del += n_m
            t_mem_del_sum += t_m
            t_grp_del_sum += t_g
            n_grps_del += 1

        grp_rate = (n_groups_step / t_grp_sum) if t_grp_sum > 0 else 0.0
        mem_rate = (
            (member_count_step / t_mem_sum) if t_mem_sum > 0 else 0.0)
        mem_rm_rate = (
            (n_mem_del / t_mem_del_sum) if t_mem_del_sum > 0 else 0.0)
        grp_rm_rate = (
            (n_grps_del / t_grp_del_sum) if t_grp_del_sum > 0 else 0.0)
        if t_mem_del_sum > 0 and n_mem_del > 0:
            self.flap_member_remove_times.append(mem_rm_rate)
        if t_grp_del_sum > 0 and n_grps_del > 0:
            self.flap_group_remove_times.append(grp_rm_rate)

        print(
            f"    this step — create {n_groups_step} ECMP group(s) "
            f"({grp_rate:.2f} groups/s), create {member_count_step} ECMP member(s) "
            f"({mem_rate:.2f} members/s)\n"
            f"    this step — remove {n_mem_del} ECMP member(s) "
            f"({mem_rm_rate:.2f} members/s), remove {n_grps_del} ECMP group(s) "
            f"({grp_rm_rate:.2f} groups/s)")

    def _cleanup_flap_resources(self):
        """Clean background ECMP and topology; base cleanup handles foreground."""

        for route_entry in self.bg_route_entries:
            status = sai_thrift_remove_route_entry(self.client, route_entry)
            self.assertEqual(status, SAI_STATUS_SUCCESS)
        self.bg_route_entries = []

        for route_entry, _ in self.fg_route_entries:
            status = sai_thrift_remove_route_entry(self.client, route_entry)
            self.assertEqual(status, SAI_STATUS_SUCCESS)
        self.fg_route_entries = []

        for m in self.bg_members:
            status = sai_thrift_remove_next_hop_group_member(self.client, m)
            self.assertEqual(status, SAI_STATUS_SUCCESS)
        self.bg_members = []
        for grp in self.bg_groups:
            status = sai_thrift_remove_next_hop_group(self.client, grp)
            self.assertEqual(status, SAI_STATUS_SUCCESS)
        self.bg_groups = []
        self._cleanup_background_topology()
        self._cleanup_all_ecmp_resources()

    def tearDown(self):
        for route_entry in self.bg_route_entries:
            status = sai_thrift_remove_route_entry(self.client, route_entry)
            self.assertEqual(status, SAI_STATUS_SUCCESS)

        for route_entry, _ in self.fg_route_entries:
            status = sai_thrift_remove_route_entry(self.client, route_entry)
            self.assertEqual(status, SAI_STATUS_SUCCESS)

        if hasattr(self, 'bg_groups') and self.bg_groups:
            for g in self.bg_groups:
                status = sai_thrift_remove_next_hop_group(self.client, g)
                self.assertEqual(status, SAI_STATUS_SUCCESS)
        if hasattr(self, 'bg_members') and self.bg_members:
            for m in self.bg_members:
                status = sai_thrift_remove_next_hop_group_member(self.client, m)
                self.assertEqual(status, SAI_STATUS_SUCCESS)
        self._cleanup_background_topology()
        super(L3EcmpRouteFlapTestBase, self).tearDown()


class L3IPv4EcmpRouteFlapTest(L3EcmpRouteFlapTestBase):
    """IPv4 ECMP Route Flap Test

    Test Objectives:
    1. Verify dynamic withdraw/add of ECMP groups and members when simulating NH down/up
    2. Measure group and member creation performance during flap
    3. Validate load balance before and after flap

    Preconditions: SaiHelperScaleL3 topology; 4 foreground groups (Group0-3) with
    specified NH sets; 100K routes (first 50K to 4 groups, last 50K background).

    """

    def setUp(self):
        super(L3IPv4EcmpRouteFlapTest, self).setUp()
        # FG_ECMP_GROUP_TO_NH_INDICES keys into the scale L3 IPv4 next-hop table.
        self._route_flap_fg_nh_dict = self.nh_v4_dict

    def _generate_fg_route_prefixes(self):
        return self.generate_ipv4_prefixes(
            prefix_len=24, start_ip="100.0.0.0", step=1, count=self.FG_ROUTE_COUNT)

    def _generate_bg_route_prefixes(self):
        return self.generate_ipv4_prefixes(
            prefix_len=24, start_ip="200.0.0.0", step=1, count=self.BG_ROUTE_COUNT)

    def _create_background_topology(self):
        """Create 128 sub-interfaces on PORT16-PORT23 (16 VLANs per port) for background ECMP."""
        if len(self.port_list) < 24:
            print(f"  [SKIP] Background topology requires at least 24 ports (PORT16-PORT23)")
            return False
        nh_idx = 0
        for port_idx in range(16, 24):
            port = self.port_list[port_idx]
            for vlan in self.BG_VLANS:
                sub_port = sai_thrift_create_router_interface(
                    self.client,
                    type=SAI_ROUTER_INTERFACE_TYPE_SUB_PORT,
                    port_id=port,
                    virtual_router_id=self.default_vrf,
                    admin_v4_state=True,
                    admin_v6_state=True,
                    outer_vlan_id=vlan)
                if sub_port == SAI_NULL_OBJECT_ID:
                    return False
                self.bg_rif_list.append(sub_port)
                ipv4_addr = f"10.{port_idx}.{vlan // 100}.1"
                mac_addr = f"00:11:22:33:{port_idx:02x}:{vlan // 100:02x}"
                nbr_entry = sai_thrift_neighbor_entry_t(
                    rif_id=sub_port,
                    ip_address=sai_ipaddress(ipv4_addr))
                sai_thrift_create_neighbor_entry(
                    self.client, nbr_entry, dst_mac_address=mac_addr)
                nhop = sai_thrift_create_next_hop(
                    self.client,
                    type=SAI_NEXT_HOP_TYPE_IP,
                    router_interface_id=sub_port,
                    ip=sai_ipaddress(ipv4_addr))
                if nhop == SAI_NULL_OBJECT_ID:
                    return False
                self.bg_route_flap_aux_nh[nh_idx] = {
                    'nh': nhop, 'rif': sub_port, 'ip': ipv4_addr}
                self.nh_2_list.append(nhop)
                nh_idx += 1
        print("  Background topology: 128 NH_2 created (ports 16-23)")
        return True

    def _cleanup_background_topology(self):
        """Remove background neighbors, next hops and router interfaces."""
        for nh_idx, info in self.bg_route_flap_aux_nh.items():
            status = sai_thrift_remove_next_hop(self.client, info['nh'])
            self.assertEqual(status, SAI_STATUS_SUCCESS)
            nbr_entry = sai_thrift_neighbor_entry_t(
                rif_id=info['rif'],
                ip_address=sai_ipaddress(info['ip']))
            status = sai_thrift_remove_neighbor_entry(self.client, nbr_entry)
            self.assertEqual(status, SAI_STATUS_SUCCESS)
        for rif in self.bg_rif_list:
            status = sai_thrift_remove_router_interface(self.client, rif)
            self.assertEqual(status, SAI_STATUS_SUCCESS)
        self.bg_rif_list = []
        self.bg_route_flap_aux_nh = {}
        self.nh_2_list = []

    def runTest(self):
        print("\n=== Starting IPv4 ECMP Route Flap Test ===")

        G = self.init_group_count
        M = self.init_member_count
        G_2 = min(int(G * 2 / 3), max(0, G - 4))
        M_2 = min(M // G if G else 0, 64) if G else 0
        print(f"  G={G}, M={M}, G_2={G_2}, M_2={M_2}")

        try:
            # 1. Create background topology (PORT16-PORT23, 128 NH_2)
            print(f"\n  [Step 1] Create background topology")
            has_bg = self._create_background_topology()
            if has_bg and G_2 > 0 and M_2 > 0:
                bg_groups = self._create_background_ecmp(G_2, M_2)
            else:
                bg_groups = []

            # 2. Create 4 foreground groups and 50K foreground routes
            print(f"\n  [Step 2] Create 4 foreground groups and routes")
            group_oids = []
            for grp, _ in self._build_foreground_groups():
                group_oids.append(grp)
            self.fg_groups_current = list(group_oids)
            self._create_foreground_routes(group_oids)
            self._create_background_routes(bg_groups)

            # 3. Random load balance verification for group0-3 (fg routes only — bg NH not in nh_v4_dict)
            print(f"\n  [Step 3] Random load balance verification for group0-3")
            fg_prefixes = list(self.fg_route_prefix_to_group_idx.keys())
            lb_ok = self.verify_ecmp_traffic(candidate_prefixes=fg_prefixes)
            self.assertTrue(lb_ok, "Initial load balance verification failed")

            # 4. Simulate NH down (cumulative via self._fg_group_to_nh_indices; affected auto-derived)
            print(f"\n  [Step 4] Simulate NH0-NH7 down")
            self._simulate_nh_down(list(range(8)))
            print(f"\n  [Step 5] Simulate NH8-NH15 down")
            self._simulate_nh_down(list(range(8, 16)))
            print(f"\n  [Step 6] Simulate NH16-NH23 down")
            self._simulate_nh_down(list(range(16, 24)))
            print(f"\n  [Step 7] Simulate NH24-NH31 down")
            self._simulate_nh_down(list(range(24, 32)))
            print(f"\n  [Step 8] Simulate NH32-NH39 down")
            self._simulate_nh_down(list(range(32, 40)))

            # 5. Simulate NH up (restore full groups)
            print(f"\n  [Step 9] Simulate NH up (restore full groups)")
            self._simulate_nh_up_restore_full()

            # 6. Final load balance verification
            print(f"\n  [Step 10] Final load balance verification")
            lb_ok = self.verify_ecmp_traffic(candidate_prefixes=fg_prefixes)
            self.assertTrue(lb_ok, "Final load balance verification failed")

        finally:
            self._cleanup_flap_resources()
            self._report_route_flap_performance_summary()


class L3IPv6EcmpRouteFlapTest(L3EcmpRouteFlapTestBase):
    """IPv6 ECMP Route Flap Test

    Test Objectives:
    1. Verify dynamic withdraw/add of ECMP groups and members when simulating NH down/up
    2. Measure group and member creation performance during flap
    3. Validate load balance before and after flap

    Preconditions: SaiHelperScaleL3 topology; 4 foreground groups (Group0-3) with
    specified NH sets; 100K routes (first 50K to 4 groups, last 50K background).

    """

    def setUp(self):
        super(L3IPv6EcmpRouteFlapTest, self).setUp()
        # FG_ECMP_GROUP_TO_NH_INDICES keys into the scale L3 IPv6 next-hop table.
        self._route_flap_fg_nh_dict = self.nh_v6_dict

    def _generate_fg_route_prefixes(self):
        return self.generate_ipv6_prefixes(
            prefix_len=56, start_ip="1000::", step=1, count=self.FG_ROUTE_COUNT)

    def _generate_bg_route_prefixes(self):
        return self.generate_ipv6_prefixes(
            prefix_len=56, start_ip="2000::", step=1, count=self.BG_ROUTE_COUNT)

    def _create_background_topology(self):
        """Create 128 sub-interfaces on PORT16-PORT23 (16 VLANs per port) for background ECMP."""
        if len(self.port_list) < 24:
            print(f"  [SKIP] Background topology requires at least 24 ports (PORT16-PORT23)")
            return False
        nh_idx = 0
        for port_idx in range(16, 24):
            port = self.port_list[port_idx]
            for vlan in self.BG_VLANS:
                sub_port = sai_thrift_create_router_interface(
                    self.client,
                    type=SAI_ROUTER_INTERFACE_TYPE_SUB_PORT,
                    port_id=port,
                    virtual_router_id=self.default_vrf,
                    admin_v4_state=True,
                    admin_v6_state=True,
                    outer_vlan_id=vlan)
                if sub_port == SAI_NULL_OBJECT_ID:
                    return False
                self.bg_rif_list.append(sub_port)
                # IPv6 address format: 2001:port_idx:vlan_high:vlan_low::1
                ipv6_addr = f"2001:{port_idx:02x}:{vlan // 256:02x}:{vlan % 256:02x}::1"
                mac_addr = f"00:11:22:33:{port_idx:02x}:{vlan // 100:02x}"
                nbr_entry = sai_thrift_neighbor_entry_t(
                    rif_id=sub_port,
                    ip_address=sai_ipaddress(ipv6_addr))
                sai_thrift_create_neighbor_entry(
                    self.client, nbr_entry, dst_mac_address=mac_addr)
                nhop = sai_thrift_create_next_hop(
                    self.client,
                    type=SAI_NEXT_HOP_TYPE_IP,
                    router_interface_id=sub_port,
                    ip=sai_ipaddress(ipv6_addr))
                if nhop == SAI_NULL_OBJECT_ID:
                    return False
                self.bg_route_flap_aux_nh[nh_idx] = {
                    'nh': nhop, 'rif': sub_port, 'ip': ipv6_addr}
                self.nh_2_list.append(nhop)
                nh_idx += 1
        print("  Background topology: 128 NH_2 created (ports 16-23)")
        return True

    def _cleanup_background_topology(self):
        """Remove background neighbors, next hops and router interfaces."""
        for nh_idx, info in self.bg_route_flap_aux_nh.items():
            status = sai_thrift_remove_next_hop(self.client, info['nh'])
            self.assertEqual(status, SAI_STATUS_SUCCESS)
            nbr_entry = sai_thrift_neighbor_entry_t(
                rif_id=info['rif'],
                ip_address=sai_ipaddress(info['ip']))
            status = sai_thrift_remove_neighbor_entry(self.client, nbr_entry)
            self.assertEqual(status, SAI_STATUS_SUCCESS)
        for rif in self.bg_rif_list:
            status = sai_thrift_remove_router_interface(self.client, rif)
            self.assertEqual(status, SAI_STATUS_SUCCESS)
        self.bg_rif_list = []
        self.bg_route_flap_aux_nh = {}
        self.nh_2_list = []

    def runTest(self):
        """Execute test"""
        print("\n=== Starting IPv6 ECMP Route Flap Test (3.1.9) ===")

        G = self.init_group_count
        M = self.init_member_count
        G_2 = min(int(G * 2 / 3), max(0, G - 4))
        M_2 = min(M // G if G else 0, 64) if G else 0
        print(f"  G={G}, M={M}, G_2={G_2}, M_2={M_2}")

        try:
            # 1. Create background topology (PORT16-PORT23, 128 NH_2)
            has_bg = self._create_background_topology()
            if has_bg and G_2 > 0 and M_2 > 0:
                bg_groups = self._create_background_ecmp(G_2, M_2)
            else:
                bg_groups = []

            # 2. Create 4 foreground groups and 50K foreground routes
            group_oids = []
            for grp, _ in self._build_foreground_groups():
                group_oids.append(grp)
            self.fg_groups_current = list(group_oids)
            self._create_foreground_routes(group_oids)
            self._create_background_routes(bg_groups)

            fg_prefixes = list(self.fg_route_prefix_to_group_idx.keys())
            print(f"\n  [Step 6] Random load balance verification for group0-3 (IPv6)")
            lb_ok = self.verify_ecmp_traffic(candidate_prefixes=fg_prefixes)
            self.assertTrue(lb_ok, "Initial IPv6 load balance verification failed")

            # 4. Simulate NH down (cumulative via self._fg_group_to_nh_indices; affected auto-derived)
            print(f"\n  [Step 7] Simulate NH0-NH7 down")
            self._simulate_nh_down(list(range(8)))
            print(f"\n  [Step 8] Simulate NH8-NH15 down")
            self._simulate_nh_down(list(range(8, 16)))
            print(f"\n  [Step 9] Simulate NH16-NH23 down")
            self._simulate_nh_down(list(range(16, 24)))
            print(f"\n  [Step 10] Simulate NH24-NH31 down")
            self._simulate_nh_down(list(range(24, 32)))
            print(f"\n  [Step 11] Simulate NH32-NH39 down")
            self._simulate_nh_down(list(range(32, 40)))

            # 5. Simulate NH up (restore full groups)
            print(f"\n  [Step 12] Simulate NH up (restore full groups)")
            self._simulate_nh_up_restore_full()

            print(f"\n  [Step 13] Final load balance verification (IPv6)")
            lb_ok = self.verify_ecmp_traffic(candidate_prefixes=fg_prefixes)
            self.assertTrue(lb_ok, "Final IPv6 load balance verification failed")

        finally:
            self._cleanup_flap_resources()
            self._report_route_flap_performance_summary()
