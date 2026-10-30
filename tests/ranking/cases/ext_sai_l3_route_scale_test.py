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
SAI L3 Route Scale Test Module
Provides test cases for large-scale route testing with optimized performance

This module contains test classes for SAI L3 route scale testing including:
- IPv4 route scale tests with different mask lengths (/16, /24, /26, /32)
- IPv6 route scale tests with different mask lengths (/48, /56, /64, /127, /128)
- Mixed IPv4/IPv6 route tests
- Performance testing for large-scale route operations

Performance Optimizations:
- All generate_mixed* methods have been optimized to use a single create_routes_from_prefixes call
- Prefix generation is separated from route creation for better modularity
- Reduced method call overhead for improved performance
"""

from sai_thrift.sai_headers import *
from ptf.testutils import *
from sai_base_test import *
import time
import random
import ipaddress
from ext_sai_l3_scale_base import L3RouteScaleTestBase


# IPv4 routes with different mask lengths - split test classes
class L3IPv4SingleHopScaleMask16Test(L3RouteScaleTestBase):
    """
    Test large-scale IPv4 /16 mask route scale and performance.

    Objectives:
    1. Generate large-scale IPv4 routes with /16 mask.
    2. Measure load factor and CRUD performance for /16 mask.
    3. Verify route table recovery after all operations.
    """
    def setUp(self):
        """
        Set up test environment for /16 mask route scale test.
        """
        super(L3IPv4SingleHopScaleMask16Test, self).setUp()
        self.expected_perf = 10000  # Performance baseline 10k/s
        self.total_routes_16 = 40000  # Maximum 65536 routes for 16-bit mask

    def test_mask16_routes(self):
        """
        Test IPv4 /16 mask route scale and performance.
        Steps:
        1. Generate IPv4 /16 prefixes.
        2. Create SAI route objects from prefixes.
        3. Test CRUD operations and print performance results.
        """
        print("\n=== Testing IPv4 /16 Mask Routes ===")
        self.route_nh_map = {}
        try:
            prefix_list = self.generate_ipv4_prefixes(
                prefix_len=16,
                start_ip="0.0.0.1",
                step=1,
                count=self.total_routes_16
            )
            route_entries = self.create_routes_from_prefixes(prefix_list)
            try:
                create_perf, remove_perf, crud_pass = self.execute_crud_test(route_entries)
                results = {
                    'create': create_perf,
                    'remove': remove_perf
                }
            except Exception as e:
                print(f"Error testing bulk size: {str(e)}")
                results = {'error': str(e)}
            perf_pass = self.print_performance_results(results, "IPv4 /16 Scale Performance Test Results")
            return perf_pass and crud_pass
        except Exception as e:
            print(f"IPv4 /16 mask test failed: {e}")
            raise

    def runTest(self):
        """
        Run the /16 mask route scale test and assert the result.
        """
        mask16_pass = self.test_mask16_routes()
        self.assertTrue(mask16_pass, "IPv4 /16 mask test failed")

    def tearDown(self):
        """
        Clean up test environment after /16 mask route scale test.
        """
        super(L3IPv4SingleHopScaleMask16Test, self).tearDown()


class L3IPv4SingleHopScaleMask24Test(L3RouteScaleTestBase):
    """
    Test large-scale IPv4 /24 mask route scale and performance.

    Objectives:
    1. Generate large-scale IPv4 routes with /24 mask.
    2. Measure load factor and CRUD performance for /24 mask.
    3. Verify route table recovery after all operations.
    """
    def setUp(self):
        """
        Set up test environment for /24 mask route scale test.
        """
        super(L3IPv4SingleHopScaleMask24Test, self).setUp()
        self.expected_perf = 10000  # Performance baseline 10k/s
        self.total_routes_24 = 100000  # Maximum 256 routes for 24-bit mask

    def test_mask24_routes(self):
        """
        Test IPv4 /24 mask route scale and performance.
        Steps:
        1. Generate IPv4 /24 prefixes.
        2. Create SAI route objects from prefixes.
        3. Test CRUD operations and print performance results.
        4. Test load factor and print results.
        """
        print("\n=== Testing IPv4 /24 Mask Routes ===")
        self.route_nh_map = {}
        try:
            prefix_list = self.generate_ipv4_prefixes(
                prefix_len=24,
                start_ip="100.0.0.0",
                step=1,
                count=self.total_routes_24
            )
            route_entries = self.create_routes_from_prefixes(prefix_list)
            create_perf, remove_perf, crud_pass = self.execute_crud_test(route_entries)
            results = {
                'create': create_perf,
                'remove': remove_perf
            }
            perf_pass = self.print_performance_results(results, "IPv4 /24 Scale Performance Test Results")
            # Test load factor
            self.skip_syslog_verify = True
            self.total_routes_24 = self.init_ipv4_route_count
            prefix_list = self.generate_ipv4_prefixes(
                prefix_len=24,
                start_ip="100.0.0.0",
                step=1,
                count=self.total_routes_24
            )
            route_entries = self.create_routes_from_prefixes(prefix_list)
            load_factor_pass, success_route_cnt = self.execute_load_factor_test(route_entries)
            print(f"perf_pass: {perf_pass}, crud_pass: {crud_pass}, load_factor_pass: {load_factor_pass}, success_add_route: {success_route_cnt}")
            return (perf_pass and crud_pass) and load_factor_pass
        except Exception as e:
            print(f"IPv4 /24 mask test failed: {e}")
            raise

    def runTest(self):
        """
        Run the /24 mask route scale test and assert the result.
        """
        mask24_pass = self.test_mask24_routes()
        self.assertTrue(mask24_pass, "IPv4 /24 mask test failed")

    def tearDown(self):
        """
        Clean up test environment after /24 mask route scale test.
        """
        super(L3IPv4SingleHopScaleMask24Test, self).tearDown()


class L3IPv4SingleHopScaleMask26Test(L3RouteScaleTestBase):
    """
    Test large-scale IPv4 /26 mask route scale and performance.

    Objectives:
    1. Generate large-scale IPv4 routes with /26 mask.
    2. Measure load factor and CRUD performance for /26 mask.
    3. Verify route table recovery after all operations.
    """
    def setUp(self):
        """
        Set up test environment for /26 mask route scale test.
        """
        super(L3IPv4SingleHopScaleMask26Test, self).setUp()
        self.expected_perf = 10000  # Performance baseline 10k/s
        self.total_routes_26 = 100000  # Maximum 64 routes for 26-bit mask

    def test_mask26_routes(self):
        """
        Test IPv4 /26 mask route scale and performance.
        Steps:
        1. Generate IPv4 /26 prefixes.
        2. Create SAI route objects from prefixes.
        3. Test CRUD operations and print performance results.
        4. Test load factor and print results.
        """
        print("\n=== Testing IPv4 /26 Mask Routes ===")
        self.route_nh_map = {}
        try:
            prefix_list = self.generate_ipv4_prefixes(
                prefix_len=26,
                start_ip="100.0.0.0",
                step=1,
                count=self.total_routes_26
            )
            route_entries = self.create_routes_from_prefixes(prefix_list)
            create_perf, remove_perf, crud_pass = self.execute_crud_test(route_entries)
            results = {
                'create': create_perf,
                'remove': remove_perf
            }
            perf_pass = self.print_performance_results(results, "IPv4 /26 Scale Performance Test Results")
            # Test load factor
            self.skip_syslog_verify = True
            self.total_routes_26 = self.init_ipv4_route_count
            prefix_list = self.generate_ipv4_prefixes(
                prefix_len=26,
                start_ip="100.0.0.0",
                step=1,
                count=self.total_routes_26
            )
            route_entries = self.create_routes_from_prefixes(prefix_list)
            load_factor_pass, success_route_cnt = self.execute_load_factor_test(route_entries)
            print(f"perf_pass: {perf_pass}, crud_pass: {crud_pass}, load_factor_pass: {load_factor_pass}, success_add_route: {success_route_cnt}")
            return (perf_pass and crud_pass) and load_factor_pass
        except Exception as e:
            print(f"IPv4 /26 mask test failed: {e}")
            raise

    def runTest(self):
        """
        Run the /26 mask route scale test and assert the result.
        """
        mask26_pass = self.test_mask26_routes()
        self.assertTrue(mask26_pass, "IPv4 /26 mask test failed")

    def tearDown(self):
        """
        Clean up test environment after /26 mask route scale test.
        """
        super(L3IPv4SingleHopScaleMask26Test, self).tearDown()


class L3IPv4SingleHopScaleMask32Test(L3RouteScaleTestBase):
    """
    Test large-scale IPv4 /32 mask route scale and performance.

    Objectives:
    1. Generate large-scale IPv4 routes with /32 mask.
    2. Measure load factor and CRUD performance for /32 mask.
    3. Verify route table recovery after all operations.
    """
    def setUp(self):
        """
        Set up test environment for /32 mask route scale test.
        """
        super(L3IPv4SingleHopScaleMask32Test, self).setUp()
        self.expected_perf = 10000  # Performance baseline 10k/s
        self.total_routes_32 = 100000  # Total route count, minimum 100k

    def test_mask32_routes(self):
        """
        Test IPv4 /32 mask route scale and performance.
        Steps:
        1. Generate IPv4 /32 prefixes.
        2. Create SAI route objects from prefixes.
        3. Test CRUD operations and print performance results.
        4. Test load factor and print results.
        """
        print("\n=== Testing IPv4 /32 Mask Routes ===")
        self.route_nh_map = {}
        try:
            prefix_list = self.generate_ipv4_prefixes(
                prefix_len=32,
                start_ip="100.0.0.0",
                step=1,
                count=self.total_routes_32
            )
            route_entries = self.create_routes_from_prefixes(prefix_list)
            create_perf, remove_perf, crud_pass = self.execute_crud_test(route_entries)
            results = {
                'create': create_perf,
                'remove': remove_perf
            }
            perf_pass = self.print_performance_results(results, "IPv4 /32 Scale Performance Test Results")
            # Test load factor
            self.skip_syslog_verify = True
            self.total_routes_32 = self.init_ipv4_route_count
            prefix_list = self.generate_ipv4_prefixes(
                prefix_len=32,
                start_ip="100.0.0.0",
                step=1,
                count=self.total_routes_32
            )
            route_entries = self.create_routes_from_prefixes(prefix_list)
            load_factor_pass, success_route_cnt = self.execute_load_factor_test(route_entries)
            print(f"perf_pass: {perf_pass}, crud_pass: {crud_pass}, load_factor_pass: {load_factor_pass}, success_add_route: {success_route_cnt}")
            return (perf_pass and crud_pass) and load_factor_pass
        except Exception as e:
            print(f"IPv4 /32 mask test failed: {e}")
            raise

    def runTest(self):
        """
        Run the /32 mask route scale test and assert the result.
        """
        mask32_pass = self.test_mask32_routes()
        self.assertTrue(mask32_pass, "IPv4 /32 mask test failed")

    def tearDown(self):
        """
        Clean up test environment after /32 mask route scale test.
        """
        super(L3IPv4SingleHopScaleMask32Test, self).tearDown()


class L3IPv4SingleHopScaleSetTest(L3RouteScaleTestBase):
    """
    Test large-scale IPv4 /24 mask route set operation and performance.

    Objectives:
    1. Generate large-scale IPv4 routes with /24 mask.
    2. Test set operation performance for /24 mask.
    3. Verify route table recovery after all operations.
    """
    def setUp(self):
        """
        Set up test environment for /24 mask set operation test.
        """
        super(L3IPv4SingleHopScaleSetTest, self).setUp()
        self.expected_perf = 10000  # Performance baseline 10k/s
        self.total_routes_24_set = 100000  # For bulk set test

    def test_set_routes(self):
        """
        Test IPv4 /24 mask route set operation and performance.
        Steps:
        1. Generate IPv4 /24 prefixes.
        2. Create SAI route objects from prefixes.
        3. Test set operation and print performance results.
        """
        print("\n=== Testing IPv4 /24 Set Performance ===")
        self.route_nh_map = {}
        try:
            prefix_list = self.generate_ipv4_prefixes(
                prefix_len=24,
                start_ip="100.0.0.0",
                step=1,
                count=self.total_routes_24_set
            )
            route_entries = self.create_routes_from_prefixes(prefix_list)
            create_perf, set_perf, remove_perf, set_pass = self.execute_set_test(route_entries)
            results = {
                'create': create_perf,
                'set': set_perf,
                'remove': remove_perf
            }
            perf_pass = self.print_performance_results(results, "IPv4 /24 Set Performance Test Results")
            print(f"perf_pass: {perf_pass}, set_pass: {set_pass}")
            return perf_pass and set_pass
        except Exception as e:
            print(f"IPv4 set test failed: {e}")
            raise

    def runTest(self):
        """
        Run the /24 mask set operation test and assert the result.
        """
        set_pass = self.test_set_routes()
        self.assertTrue(set_pass, "IPv4 /24 set test failed")

    def tearDown(self):
        """
        Clean up test environment after /24 mask set operation test.
        """
        super(L3IPv4SingleHopScaleSetTest, self).tearDown()


class L3IPv4SingleHopMixScale1Test(L3RouteScaleTestBase):
    """
    Test large-scale IPv4 mixed mask route scale and measure load factor.

    Objectives:
    1. Generate mixed IPv4 routes with /16, /24, /26, /32 masks in specified proportions.
    2. Measure load factor and CRUD performance for mixed routes.
    3. Verify route table recovery after all operations.

    IPv4 route distribution:
    - 20% /16 routes (100.0.0.0/16)
    - 40% /24 routes (100.0.0.0/24, 110.0.0.0/24)
    - 20% /26 routes (100.0.0.0/26, 120.0.0.0/26)
    - 20% /32 routes (100.0.0.0/32, step 4)
    """

    def setUp(self):
        super(L3IPv4SingleHopMixScale1Test, self).setUp()
        self.total_routes = 100000  # Total route count
        self.expected_perf = 10000  # Performance baseline 10k/s

    def generate_mixed_routes_scale1(self):
        """Generate IPv4 test route entries with mixed masks

        Generate route entries with different mask distribution using hierarchical approach:
        - 20% /16 routes (starting from 100.0.0.0/16)
        - 40% /24 routes (20% from 100.0.0.0/24, 20% from 110.0.0.0/24)
        - 20% /26 routes (10% from 100.0.0.0/26, 10% from 120.0.0.0/26)
        - 20% /32 routes (starting from 100.0.0.0/32, step 4)

        Returns:
            list: Route entry list
        """
        print("\nGenerating mixed IPv4 hierarchical test routes with optimized single call...")

        # Calculate route count for each mask based on distribution
        routes_16 = int(self.total_routes * 0.20)  # 20% /16
        routes_24 = int(self.total_routes * 0.40)  # 40% /24
        routes_26 = int(self.total_routes * 0.20)  # 20% /26
        routes_32 = self.total_routes - routes_16 - routes_24 - routes_26  # 20% /32

        print(f"Generating {routes_16} /16 routes, {routes_24} /24 routes, {routes_26} /26 routes, {routes_32} /32 routes")

        # Calculate subdivisions for hierarchical distribution
        routes_24_part1 = routes_24 // 2  # Half of /24 routes
        routes_24_part2 = routes_24 - routes_24_part1  # Remaining /24 routes
        routes_26_part1 = routes_26 // 2  # Half of /26 routes
        routes_26_part2 = routes_26 - routes_26_part1  # Remaining /26 routes

        # Generate all prefix lists first
        all_prefixes = []

        # 1. Generate /16 routes starting from 100.0.0.0/16
        if routes_16 > 0:
            print("Generating /16 prefixes...")
            prefix_list_16 = self.generate_ipv4_prefixes(
                prefix_len=16,
                start_ip="100.0.0.0",
                step=1,
                count=routes_16
            )
            all_prefixes.extend(prefix_list_16)

        # 2. Generate /24 routes (split into two address spaces)
        if routes_24_part1 > 0:
            print("Generating /24 prefixes (first part)...")
            prefix_list_24_part1 = self.generate_ipv4_prefixes(
                prefix_len=24,
                start_ip="100.0.0.0",
                step=1,
                count=routes_24_part1
            )
            all_prefixes.extend(prefix_list_24_part1)

        if routes_24_part2 > 0:
            print("Generating /24 prefixes (second part)...")
            prefix_list_24_part2 = self.generate_ipv4_prefixes(
                prefix_len=24,
                start_ip="110.0.0.0",
                step=1,
                count=routes_24_part2
            )
            all_prefixes.extend(prefix_list_24_part2)

        # 3. Generate /26 routes (split into two address spaces)
        if routes_26_part1 > 0:
            print("Generating /26 prefixes (first part)...")
            prefix_list_26_part1 = self.generate_ipv4_prefixes(
                prefix_len=26,
                start_ip="100.0.0.0",
                step=1,
                count=routes_26_part1
            )
            all_prefixes.extend(prefix_list_26_part1)

        if routes_26_part2 > 0:
            print("Generating /26 prefixes (second part)...")
            prefix_list_26_part2 = self.generate_ipv4_prefixes(
                prefix_len=26,
                start_ip="120.0.0.0",
                step=1,
                count=routes_26_part2
            )
            all_prefixes.extend(prefix_list_26_part2)

        # 4. Generate /32 routes starting from 100.0.0.0/32
        if routes_32 > 0:
            print("Generating /32 prefixes...")
            prefix_list_32 = self.generate_ipv4_prefixes(
                prefix_len=32,
                start_ip="100.0.0.0",
                step=4,
                count=routes_32
            )
            all_prefixes.extend(prefix_list_32)

        # Create all SAI route objects from all prefixes in one call
        print(f"Creating {len(all_prefixes)} SAI route objects from all prefixes...")
        route_entries = self.create_routes_from_prefixes(all_prefixes)

        print(f"Generated {len(route_entries)} mixed IPv4 hierarchical routes with optimized single call:")
        print(f"  - {routes_16} /16 routes")
        print(f"  - {routes_24} /24 routes ({routes_24_part1} + {routes_24_part2})")
        print(f"  - {routes_26} /26 routes ({routes_26_part1} + {routes_26_part2})")
        print(f"  - {routes_32} /32 routes")
        return route_entries

    def runTest(self):
        """Execute test steps to generate routes and test bulk CRUD operations."""
        try:
            # 1. Generate test routes
            route_entries = self.generate_mixed_routes_scale1()

            # 2. Test CRUD operations
            create_perf, remove_perf, crud_pass = self.execute_crud_test(route_entries)
            results = {
                'create': create_perf,
                'remove': remove_perf
            }

            # 3. Output test result summary
            perf_pass = self.print_performance_results(results, "IPv4 Mixed Scale1 Performance Test Results")
            print(f"perf_pass: {perf_pass}, crud_pass: {crud_pass}")
            self.assertTrue(perf_pass and crud_pass, "IPv4 Mixed Scale1 Performance Test failed")

        except Exception as e:
            print(f"Test failed: {e}")
            raise

    def tearDown(self):
        super(L3IPv4SingleHopMixScale1Test, self).tearDown()

class L3IPv4SingleHopMixScale2Test(L3RouteScaleTestBase):
    """
    Test large-scale IPv4 mixed mask route scale and measure load factor.

    Objectives:
    1. Generate mixed IPv4 routes with /8, /16, /24, /32 masks in specified proportions.
    2. Measure load factor and CRUD performance for mixed routes.
    3. Verify route table recovery after all operations.

    IPv4 route distribution:
    - /8 routes (100.0.0.0/8 to 200.0.0.0/8)
    - 30% /16 routes (half in /8)
    - 50% /24 routes (half in /16)
    - Remaining /32 routes (all in /24, step 4)
    """

    def setUp(self):
        super(L3IPv4SingleHopMixScale2Test, self).setUp()
        self.total_routes = 100000  # Total route count, minimum 100k
        self.expected_perf = 10000  # Performance baseline 10k/s

    def generate_mixed_routes_scale2(self):
        """Generate IPv4 test route entries with mixed masks

        Generate IPv4 routes using optimized approach with single create_routes_from_prefixes call:
        - /8 routes from 100.0.0.0/8 to 200.0.0.0/8 (101 routes)
        - 30% /16 routes (half contained in /8)
        - 50% /24 routes (half contained in /16)
        - Remaining routes are /32 (all contained in /24, step 4)

        Optimization: First generates all prefix lists, then creates all SAI route objects
        in a single call to create_routes_from_prefixes() for better performance.

        Returns:
            list: IPv4 route entry list
        """
        print(f"\nGenerating IPv4 mixed mask test routes with optimized single call...")

        # Generate all /8 routes from 100.0.0.0/8 to 254.0.0.0/8 (155 routes)
        routes_8 = 101  # 200 - 100 + 1 = 101 routes

        # Calculate route count for other masks based on total_routes
        routes_16 = int(self.total_routes * 0.30)  # 30% /16
        routes_24 = int(self.total_routes * 0.50)  # 50% /24
        routes_32 = self.total_routes - routes_16 - routes_24 - routes_8 # remaining routes are /32

        print(f"Generating {routes_8} /8 routes (100.0.0.0/8 to 200.0.0.0/8), {routes_16} /16 routes, {routes_24} /24 routes, {routes_32} /32 routes")

        # Calculate subdivisions for hierarchical distribution
        routes_16_in_8 = routes_16 // 2  # Half of /16 routes contained in /8
        routes_16_out_8 = routes_16 - routes_16_in_8  # Remaining /16 routes
        routes_24_in_16 = routes_24 // 2  # Half of /24 routes contained in /16
        routes_24_out_16 = routes_24 - routes_24_in_16  # Remaining /24 routes

        # Generate all prefix lists first
        all_prefixes = []

        # 1. Generate /8 routes from 100.0.0.0/8 to 254.0.0.0/8
        print("Generating /8 prefixes from 100.0.0.0/8 to 200.0.0.0/8...")
        prefix_list_8 = self.generate_ipv4_prefixes(
            prefix_len=8,
            start_ip="100.0.0.0",
            step=1,
            count=routes_8
        )
        all_prefixes.extend(prefix_list_8)

        # 2. Generate /16 routes (half contained in /8: 100.0.0.0/16, half separate: 0.0.0.1/16)
        if routes_16_in_8 > 0:
            print("Generating /16 prefixes contained in /8...")
            prefix_list_16_in_8 = self.generate_ipv4_prefixes(
                prefix_len=16,
                start_ip="100.0.0.0",
                step=1,
                count=routes_16_in_8
            )
            all_prefixes.extend(prefix_list_16_in_8)

        if routes_16_out_8 > 0:
            print("Generating /16 prefixes outside /8...")
            prefix_list_16_out_8 = self.generate_ipv4_prefixes(
                prefix_len=16,
                start_ip="0.0.0.1",
                step=1,
                count=routes_16_out_8
            )
            all_prefixes.extend(prefix_list_16_out_8)

        # 3. Generate /24 routes (half contained in /16: 100.0.0.0/24, half separate: 200.0.0.0/24)
        if routes_24_in_16 > 0:
            print("Generating /24 prefixes contained in /16...")
            prefix_list_24_in_16 = self.generate_ipv4_prefixes(
                prefix_len=24,
                start_ip="100.1.0.0",
                step=1,
                count=routes_24_in_16
            )
            all_prefixes.extend(prefix_list_24_in_16)

        if routes_24_out_16 > 0:
            print("Generating /24 prefixes outside /16...")
            prefix_list_24_out_16 = self.generate_ipv4_prefixes(
                prefix_len=24,
                start_ip="200.0.0.0",
                step=1,
                count=routes_24_out_16
            )
            all_prefixes.extend(prefix_list_24_out_16)

        # 4. Generate /32 routes (all contained in /24, step 4)
        if routes_32 > 0:
            print("Generating /32 prefixes contained in /24 with step 4...")
            prefix_list_32 = self.generate_ipv4_prefixes(
                prefix_len=32,
                start_ip="100.1.0.0",
                step=4,
                count=routes_32
            )
            all_prefixes.extend(prefix_list_32)

        # Create all SAI route objects from all prefixes in one call
        print(f"Creating {len(all_prefixes)} SAI route objects from all prefixes...")
        route_entries = self.create_routes_from_prefixes(all_prefixes)

        print(f"Generated {len(route_entries)} IPv4 mixed routes with optimized single call:")
        print(f"  - {routes_8} /8 routes (100.0.0.0/8 to 200.0.0.0/8)")
        print(f"  - {routes_16} /16 routes ({routes_16_in_8} contained in /8, {routes_16_out_8} separate)")
        print(f"  - {routes_24} /24 routes ({routes_24_in_16} contained in /16, {routes_24_out_16} separate)")
        print(f"  - {routes_32} /32 routes (all contained in /24, step 4)")
        return route_entries

    def runTest(self):
        """Execute test steps"""
        try:
            # 1. Generate test routes
            route_entries = self.generate_mixed_routes_scale2()

            # 2. Test CRUD operations
            create_perf, remove_perf, crud_pass = self.execute_crud_test(route_entries)
            results = {
                'create': create_perf,
                'remove': remove_perf
            }

            # 3. Output test result summary
            perf_pass = self.print_performance_results(results, "IPv4 Mixed Scale2 Performance Test Results")
            print(f"perf_pass: {perf_pass}, crud_pass: {crud_pass}")
            self.assertTrue(perf_pass and crud_pass, "IPv4 Mixed Scale2 Performance Test failed")

        except Exception as e:
            print(f"Test failed: {e}")
            raise

    def tearDown(self):
        super(L3IPv4SingleHopMixScale2Test, self).tearDown()


class L3IPv4SingleHopScaleIterate1Test(L3RouteScaleTestBase):
    """
    Test maximum stress coverage and load factor for large-scale IPv4 /32 routes.

    Objectives:
    1. Generate large-scale IPv4 /32 routes.
    2. Measure load factor for sequential and random route creation.
    3. Verify route table recovery after all operations.

    IPv4 route pattern:
    - /32 routes (200.0.0.0/32, step 4)
    """

    def setUp(self):
        super(L3IPv4SingleHopScaleIterate1Test, self).setUp()
        self.skip_syslog_verify = True
        self.total_routes = self.init_ipv4_route_count

    def runTest(self):
        """Execute test steps"""
        try:
            # 1. Generate test routes
            print("\nGenerating IPv4 /32 test routes...")
            prefix_list = self.generate_ipv4_prefixes(
                prefix_len=32,
                start_ip="200.0.0.0",
                step=4,
                count=self.total_routes
            )

            # 2. Create SAI route objects from prefixes
            print(f"Creating {len(prefix_list)} SAI route objects from prefixes...")
            route_entries = self.create_routes_from_prefixes(prefix_list)

            # 3. Sequentially create
            sequential_load_factor_pass, sequential_success_route_cnt = self.execute_load_factor_test(
                route_entries, order="sequential")
            print(f"Sequential delivery load factor pass: {sequential_load_factor_pass}, success_add_route: {sequential_success_route_cnt}")

            # 4. Shuffle and create again
            print(f"\nShuffling and creating again...")
            random.shuffle(route_entries)
            shuffle_load_factor_pass, shuffle_success_route_cnt = self.execute_load_factor_test(
                route_entries, order="random")
            print(f"Random delivery load factor pass: {shuffle_load_factor_pass}, success_add_route: {shuffle_success_route_cnt}")
            self.assertTrue(sequential_load_factor_pass and shuffle_load_factor_pass, "IPv4 /32 Scale Iterate Test failed")

        except Exception as e:
            print(f"Test failed: {e}")
            raise

    def tearDown(self):
        super(L3IPv4SingleHopScaleIterate1Test, self).tearDown()


class L3IPv4SingleHopScaleIterate2Test(L3RouteScaleTestBase):
    """
    Test maximum stress coverage and load factor for large-scale IPv4 /24 and /32 mixed routes.

    Objectives:
    1. Generate large-scale mixed IPv4 /24 and /32 routes.
    2. Measure load factor for sequential and random route creation.
    3. Verify route table recovery after all operations.

    IPv4 route distribution:
    - 20% /24 routes (100.0.0.0/24)
    - 40% /32 routes within /24 (100.0.0.0/32, step 4)
    - 40% /32 routes in separate segments (200.0.0.0/32, step 4)
    """

    def setUp(self):
        super(L3IPv4SingleHopScaleIterate2Test, self).setUp()
        self.skip_syslog_verify = True
        self.total_routes = self.init_ipv4_route_count

    def generate_mixed_routes_iterate2(self):
        """Generate mixed routes with optimized single-call approach
        Returns:
            list: Route entry list
        """
        print(f"\nGenerating {self.total_routes} mixed /24 and /32 test routes with optimized single call...")

        # Calculate route counts for each type
        routes_24 = int(self.total_routes * 0.20)    # 20% /24 routes
        routes_32_in_24 = int(self.total_routes * 0.40)   # 40% /32 routes within /24
        routes_32_separate = self.total_routes - routes_24 - routes_32_in_24  # 40% /32 routes in separate segments

        print(f"Route distribution:")
        print(f"  - {routes_24} /24 routes starting from 100.0.0.0/24")
        print(f"  - {routes_32_in_24} /32 routes within /24 networks starting from 100.0.0.0/32")
        print(f"  - {routes_32_separate} /32 routes in separate segments starting from 200.0.0.0/32")

        # Generate all prefix lists first
        all_prefixes = []

        # 1. Generate /24 network routes starting from 100.0.0.0/24
        if routes_24 > 0:
            print("\nGenerating /24 prefixes...")
            prefix_list_24 = self.generate_ipv4_prefixes(
                prefix_len=24,
                start_ip="100.0.0.0",
                step=1,
                count=routes_24
            )
            all_prefixes.extend(prefix_list_24)

        # 2. Generate /32 routes within /24 networks starting from 100.0.0.0/32
        if routes_32_in_24 > 0:
            print("Generating /32 prefixes within /24 networks...")
            prefix_list_32_in_24 = self.generate_ipv4_prefixes(
                prefix_len=32,
                start_ip="100.0.0.0",
                step=4,
                count=routes_32_in_24
            )
            all_prefixes.extend(prefix_list_32_in_24)

        # 3. Generate /32 routes in separate segments starting from 200.0.0.0/32
        if routes_32_separate > 0:
            print("Generating /32 prefixes in separate segments...")
            prefix_list_32_separate = self.generate_ipv4_prefixes(
                prefix_len=32,
                start_ip="200.0.0.0",
                step=4,
                count=routes_32_separate
            )
            all_prefixes.extend(prefix_list_32_separate)

        # Create all SAI route objects from all prefixes in one call
        print(f"\nCreating {len(all_prefixes)} SAI route objects...")
        route_entries = self.create_routes_from_prefixes(all_prefixes)

        print(f"\nGenerated {len(route_entries)} mixed routes:")
        print(f"  - {routes_24} /24 routes starting from 100.0.0.0/24")
        print(f"  - {routes_32_in_24} /32 routes within /24 networks starting from 100.0.0.0/32")
        print(f"  - {routes_32_separate} /32 routes in separate segments starting from 200.0.0.0/32")
        return route_entries

    def runTest(self):
        """Execute test steps"""
        try:
            # 1. Generate test routes
            route_entries = self.generate_mixed_routes_iterate2()

            # 2. Sequentially create
            sequential_load_factor_pass, sequential_success_route_cnt = self.execute_load_factor_test(
                route_entries, order="sequential")
            print(f"Sequential delivery load factor pass: {sequential_load_factor_pass}, success_add_route: {sequential_success_route_cnt}")

            # 3. Shuffle create again
            print(f"\nShuffling and create again...")
            random.shuffle(route_entries)
            shuffle_load_factor_pass, shuffle_success_route_cnt = self.execute_load_factor_test(
                route_entries, order="random")
            print(f"Random delivery load factor pass: {shuffle_load_factor_pass}, success_add_route: {shuffle_success_route_cnt}")
            self.assertTrue(sequential_load_factor_pass and shuffle_load_factor_pass, "IPv4 Mixed Scale Iterate Test failed")

        except Exception as e:
            print(f"Test failed: {e}")
            raise

    def tearDown(self):
        super(L3IPv4SingleHopScaleIterate2Test, self).tearDown()


class L3IPv4SingleHopScaleIterate4Test(L3RouteScaleTestBase):
    """
    Test maximum stress coverage and load factor for large-scale hierarchical IPv4 routes.

    Objectives:
    1. Generate large-scale hierarchical IPv4 routes with /8, /16, /24, /32 masks.
    2. Measure load factor for sequential and random route creation.
    3. Verify route table recovery after all operations.

    IPv4 route distribution:
    - /8 routes (100.0.0.0/8 to 200.0.0.0/8)
    - 10% /16 routes (100.0.0.0/16, 0.0.0.1/16)
    - 25% /32 routes (100.0.0.0/32, step 4)
    - Remaining /24 routes (100.0.0.0/24, 200.0.0.0/24)
    """

    def setUp(self):
        super(L3IPv4SingleHopScaleIterate4Test, self).setUp()
        self.skip_syslog_verify = True
        self.total_routes = self.init_ipv4_route_count # Total route count, minimum 100k

    def generate_mixed_routes_iterate4(self):
        """Generate hierarchical mixed routes with optimized single-call approach

        Generate hierarchical routes with different distributions:
        - /8 routes from 100.0.0.0/8 to 200.0.0.0/8 (101 routes)
        - 10% /16 routes (split 50/50 between 100.0.0.0/16 space and 0.0.0.1/16 space)
        - 25% /32 routes (starting from 100.0.0.0/32, step 4)
        - Remaining routes are /24 (split 50/50 between 100.0.0.0/24 space and 200.0.0.0/24 space)

        Optimization: First generates all prefix lists, then creates all SAI route objects
        in a single call to create_routes_from_prefixes() for better performance.

        Returns:
            list: Route entry list
        """
        print(f"\nGenerating hierarchical mixed /8, /16, /24 and /32 test routes with optimized single call...")

        # Generate all /8 routes from 100.0.0.0/8 to 200.0.0.0/8 (101 routes)
        routes_8 = 101  # 200 - 100 + 1 = 101 routes

        # Calculate route count for other masks based on total_routes
        routes_16 = int(self.total_routes * 0.10)  # 10% /16
        routes_32 = int(self.total_routes * 0.25) # 25% /32
        routes_24 = self.total_routes - routes_8 - routes_16 - routes_32 # remaining routes are /24

        print(f"Generating {routes_8} /8 routes (100.0.0.0/8 to 200.0.0.0/8), {routes_16} /16 routes, {routes_24} /24 routes, {routes_32} /32 routes")

        # Calculate subdivisions for mixed distributions
        routes_16_part1 = routes_16 // 2  # Half of /16 routes (from 100.0.0.0/16)
        routes_16_part2 = routes_16 - routes_16_part1  # Remaining /16 routes (from 0.0.0.1/16)

        routes_24_part1 = routes_24 // 2  # Half of /24 routes (from 100.0.0.0/24)
        routes_24_part2 = routes_24 - routes_24_part1  # Remaining /24 routes (from 200.0.0.0/24)

        # Generate all prefix lists first
        all_prefixes = []

        # 1. Generate /8 routes from 100.0.0.0/8 to 200.0.0.0/8
        print("Generating /8 prefixes from 100.0.0.0/8 to 200.0.0.0/8...")
        prefix_list_8 = self.generate_ipv4_prefixes(
            prefix_len=8,
            start_ip="100.0.0.0",
            step=1,
            count=routes_8
        )
        all_prefixes.extend(prefix_list_8)

        # 2. Generate /16 routes (split 50/50 into two address spaces)
        if routes_16_part1 > 0:
            print("Generating /16 prefixes (first part from 100.0.0.0/16)...")
            prefix_list_16_part1 = self.generate_ipv4_prefixes(
                prefix_len=16,
                start_ip="100.0.0.0",
                step=1,
                count=routes_16_part1
            )
            all_prefixes.extend(prefix_list_16_part1)

        if routes_16_part2 > 0:
            print("Generating /16 prefixes (second part from 0.0.0.1/16)...")
            prefix_list_16_part2 = self.generate_ipv4_prefixes(
                prefix_len=16,
                start_ip="0.0.0.1",
                step=1,
                count=routes_16_part2
            )
            all_prefixes.extend(prefix_list_16_part2)

        # 3. Generate /24 routes (split 50/50 into two address spaces)
        if routes_24_part1 > 0:
            print("Generating /24 prefixes (first part from 100.0.0.0/24)...")
            prefix_list_24_part1 = self.generate_ipv4_prefixes(
                prefix_len=24,
                start_ip="100.0.0.0",
                step=1,
                count=routes_24_part1
            )
            all_prefixes.extend(prefix_list_24_part1)

        if routes_24_part2 > 0:
            print("Generating /24 prefixes (second part from 200.0.0.0/24)...")
            prefix_list_24_part2 = self.generate_ipv4_prefixes(
                prefix_len=24,
                start_ip="200.0.0.0",
                step=1,
                count=routes_24_part2
            )
            all_prefixes.extend(prefix_list_24_part2)

        # 4. Generate /32 routes starting from 100.0.0.0/32 (25% of total)
        if routes_32 > 0:
            print("Generating /32 prefixes from 100.0.0.0/32...")
            prefix_list_32 = self.generate_ipv4_prefixes(
                prefix_len=32,
                start_ip="100.0.0.0",
                step=4,
                count=routes_32
            )
            all_prefixes.extend(prefix_list_32)

        # Create all SAI route objects from all prefixes in one call
        print(f"Creating {len(all_prefixes)} SAI route objects from all prefixes...")
        route_entries = self.create_routes_from_prefixes(all_prefixes)

        print(f"Generated {len(route_entries)} hierarchical mixed routes with optimized single call:")
        print(f"  - {routes_8} /8 routes (100.0.0.0/8 to 200.0.0.0/8)")
        print(f"  - {routes_16} /16 routes ({routes_16_part1} from 100.0.0.0/16 + {routes_16_part2} from 0.0.0.1/16)")
        print(f"  - {routes_24} /24 routes ({routes_24_part1} from 100.0.0.0/24 + {routes_24_part2} from 200.0.0.0/24)")
        print(f"  - {routes_32} /32 routes (starting from 100.0.0.0/32, step 4)")
        return route_entries

    def runTest(self):
        """Execute test steps"""
        try:
            # 1. Generate test routes
            route_entries = self.generate_mixed_routes_iterate4()

            # 2. Sequentially create
            sequential_load_factor_pass, sequential_success_route_cnt = self.execute_load_factor_test(
                route_entries, order="sequential")
            print(f"Sequential delivery load factor pass: {sequential_load_factor_pass}, success_add_route: {sequential_success_route_cnt}")

            # 3. Shuffle create again
            print(f"\nShuffling and create again...")
            random.shuffle(route_entries)
            shuffle_load_factor_pass, shuffle_success_route_cnt = self.execute_load_factor_test(
                route_entries, order="random")
            print(f"Random delivery load factor pass: {shuffle_load_factor_pass}, success_add_route: {shuffle_success_route_cnt}")
            self.assertTrue(sequential_load_factor_pass and shuffle_load_factor_pass, "IPv4 Mixed Scale Iterate Test failed")

        except Exception as e:
            print(f"Test failed: {e}")
            raise

    def tearDown(self):
        """Clean up test environment"""
        super(L3IPv4SingleHopScaleIterate4Test, self).tearDown()


class L3IPv6SingleHopScaleMask48Test(L3RouteScaleTestBase):
    """
    Test large-scale IPv6 /48 mask route scale and performance.

    Objectives:
    1. Generate large-scale IPv6 routes with /48 mask.
    2. Measure load factor and CRUD performance for /48 mask.
    3. Verify route table recovery after all operations.
    """
    def setUp(self):
        """
        Set up test environment for /48 mask route scale test.
        """
        super(L3IPv6SingleHopScaleMask48Test, self).setUp()
        self.expected_perf = 10000  # Performance baseline 10k/s
        self.total_routes_48 = 100000  # Large IPv6 network segments

    def test_mask48_routes(self):
        """
        Test IPv6 /48 mask route scale and performance.
        Steps:
        1. Generate IPv6 /48 prefixes.
        2. Create SAI route objects from prefixes.
        3. Test CRUD operations and print performance results.
        4. Test load factor and print results.
        """
        print("\n=== Testing IPv6 /48 Mask Routes ===")
        self.route_nh_map = {}
        try:
            prefix_list = self.generate_ipv6_prefixes(
                prefix_len=48,
                start_ip="1000::",
                step=1,
                count=self.total_routes_48
            )
            route_entries = self.create_routes_from_prefixes(prefix_list)
            create_perf, remove_perf, crud_pass = self.execute_crud_test(route_entries)
            results = {
                'create': create_perf,
                'remove': remove_perf
            }
            perf_pass = self.print_performance_results(results, "IPv6 /48 Scale Performance Test Results")
            # Test load factor
            self.skip_syslog_verify = True
            self.total_routes_48 = self.init_ipv6_route_count
            prefix_list = self.generate_ipv6_prefixes(
                prefix_len=48,
                start_ip="1000::",
                step=1,
                count=self.total_routes_48
            )
            route_entries = self.create_routes_from_prefixes(prefix_list)
            load_factor_pass, success_route_cnt = self.execute_load_factor_test(route_entries)
            print(f"Load factor pass: {load_factor_pass}, crud_pass: {crud_pass}, success_add_route: {success_route_cnt}")
            return (perf_pass and crud_pass) and load_factor_pass
        except Exception as e:
            print(f"IPv6 /48 mask test failed: {e}")
            raise

    def runTest(self):
        """
        Run the /48 mask route scale test and assert the result.
        """
        mask48_pass = self.test_mask48_routes()
        self.assertTrue(mask48_pass, "IPv6 /48 mask test failed")

    def tearDown(self):
        """
        Clean up test environment after /48 mask route scale test.
        """
        super(L3IPv6SingleHopScaleMask48Test, self).tearDown()


class L3IPv6SingleHopScaleMask56Test(L3RouteScaleTestBase):
    """
    Test large-scale IPv6 /56 mask route scale and performance.

    Objectives:
    1. Generate large-scale IPv6 routes with /56 mask.
    2. Measure load factor and CRUD performance for /56 mask.
    3. Verify route table recovery after all operations.
    """
    def setUp(self):
        """
        Set up test environment for /56 mask route scale test.
        """
        super(L3IPv6SingleHopScaleMask56Test, self).setUp()
        self.expected_perf = 10000  # Performance baseline 10k/s
        self.total_routes_56 = 100000  # Medium IPv6 network segments

    def test_mask56_routes(self):
        """
        Test IPv6 /56 mask route scale and performance.
        Steps:
        1. Generate IPv6 /56 prefixes.
        2. Create SAI route objects from prefixes.
        3. Test CRUD operations and print performance results.
        4. Test load factor and print results.
        """
        print("\n=== Testing IPv6 /56 Mask Routes ===")
        self.route_nh_map = {}
        try:
            prefix_list = self.generate_ipv6_prefixes(
                prefix_len=56,
                start_ip="1000::",
                step=1,
                count=self.total_routes_56
            )
            route_entries = self.create_routes_from_prefixes(prefix_list)
            create_perf, remove_perf, crud_pass = self.execute_crud_test(route_entries)
            results = {
                'create': create_perf,
                'remove': remove_perf
            }
            perf_pass = self.print_performance_results(results, "IPv6 /56 Scale Performance Test Results")
            # Test load factor
            self.skip_syslog_verify = True
            self.total_routes_56 = self.init_ipv6_route_count
            prefix_list = self.generate_ipv6_prefixes(
                prefix_len=56,
                start_ip="1000::",
                step=1,
                count=self.total_routes_56
            )
            route_entries = self.create_routes_from_prefixes(prefix_list)
            load_factor_pass, success_route_cnt = self.execute_load_factor_test(route_entries)
            print(f"Load factor pass: {load_factor_pass}, crud_pass: {crud_pass}, success_add_route: {success_route_cnt}")
            return (perf_pass and crud_pass) and load_factor_pass
        except Exception as e:
            print(f"IPv6 /56 mask test failed: {e}")
            raise

    def runTest(self):
        """
        Run the /56 mask route scale test and assert the result.
        """
        mask56_pass = self.test_mask56_routes()
        self.assertTrue(mask56_pass, "IPv6 /56 mask test failed")

    def tearDown(self):
        """
        Clean up test environment after /56 mask route scale test.
        """
        super(L3IPv6SingleHopScaleMask56Test, self).tearDown()


class L3IPv6SingleHopScaleMask64Test(L3RouteScaleTestBase):
    """
    Test large-scale IPv6 /64 mask route scale and performance.

    Objectives:
    1. Generate large-scale IPv6 routes with /64 mask.
    2. Measure load factor and CRUD performance for /64 mask.
    3. Verify route table recovery after all operations.
    """
    def setUp(self):
        """
        Set up test environment for /64 mask route scale test.
        """
        super(L3IPv6SingleHopScaleMask64Test, self).setUp()
        self.expected_perf = 10000  # Performance baseline 10k/s
        self.total_routes_64 = 100000  # Standard IPv6 network segments

    def test_mask64_routes(self):
        """
        Test IPv6 /64 mask route scale and performance.
        Steps:
        1. Generate IPv6 /64 prefixes.
        2. Create SAI route objects from prefixes.
        3. Test CRUD operations and print performance results.
        4. Test load factor and print results.
        """
        print("\n=== Testing IPv6 /64 Mask Routes ===")
        self.route_nh_map = {}
        try:
            prefix_list = self.generate_ipv6_prefixes(
                prefix_len=64,
                start_ip="1000::",
                step=1,
                count=self.total_routes_64
            )
            route_entries = self.create_routes_from_prefixes(prefix_list)
            create_perf, remove_perf, crud_pass = self.execute_crud_test(route_entries)
            results = {
                'create': create_perf,
                'remove': remove_perf
            }
            perf_pass = self.print_performance_results(results, "IPv6 /64 Scale Performance Test Results")
            # Test load factor
            self.skip_syslog_verify = True
            self.total_routes_64 = self.init_ipv6_route_count
            prefix_list = self.generate_ipv6_prefixes(
                prefix_len=64,
                start_ip="1000::",
                step=1,
                count=self.total_routes_64
            )
            route_entries = self.create_routes_from_prefixes(prefix_list)
            load_factor_pass, success_route_cnt = self.execute_load_factor_test(route_entries)
            print(f"Load factor pass: {load_factor_pass}, crud_pass: {crud_pass}, success_add_route: {success_route_cnt}")
            return (perf_pass and crud_pass) and load_factor_pass
        except Exception as e:
            print(f"IPv6 /64 mask test failed: {e}")
            raise

    def runTest(self):
        """
        Run the /64 mask route scale test and assert the result.
        """
        mask64_pass = self.test_mask64_routes()
        self.assertTrue(mask64_pass, "IPv6 /64 mask test failed")

    def tearDown(self):
        """
        Clean up test environment after /64 mask route scale test.
        """
        super(L3IPv6SingleHopScaleMask64Test, self).tearDown()


class L3IPv6SingleHopScaleSetTest(L3RouteScaleTestBase):
    """
    Test large-scale IPv6 /48 mask route set operation and performance.

    Objectives:
    1. Generate large-scale IPv6 routes with /48 mask.
    2. Test set operation performance for /48 mask.
    3. Verify route table recovery after all operations.
    """
    def setUp(self):
        """
        Set up test environment for /48 mask set operation test.
        """
        super(L3IPv6SingleHopScaleSetTest, self).setUp()
        self.expected_perf = 10000  # Performance baseline 10k/s
        self.total_routes_48_set = 100000  # For bulk set test

    def test_set_routes(self):
        """
        Test IPv6 /48 mask route set operation and performance.
        Steps:
        1. Generate IPv6 /48 prefixes.
        2. Create SAI route objects from prefixes.
        3. Test set operation and print performance results.
        """
        print("\n=== Testing IPv6 /48 Set Performance ===")
        self.route_nh_map = {}
        try:
            prefix_list = self.generate_ipv6_prefixes(
                prefix_len=48,
                start_ip="1000::",
                step=1,
                count=self.total_routes_48_set
            )
            route_entries = self.create_routes_from_prefixes(prefix_list)
            create_perf, set_perf, remove_perf, set_pass = self.execute_set_test(route_entries)
            results = {
                'create': create_perf,
                'set': set_perf,
                'remove': remove_perf
            }
            perf_pass = self.print_performance_results(results, "IPv6 /48 Set Performance Test Results")
            print(f"perf_pass: {perf_pass}, set_pass: {set_pass}")
            return perf_pass and set_pass
        except Exception as e:
            print(f"IPv6 set test failed: {e}")
            raise

    def runTest(self):
        """
        Run the /48 mask set operation test and assert the result.
        """
        set_pass = self.test_set_routes()
        self.assertTrue(set_pass, "IPv6 /48 set test failed")

    def tearDown(self):
        """
        Clean up test environment after /48 mask set operation test.
        """
        super(L3IPv6SingleHopScaleSetTest, self).tearDown()


class L3IPv6SingleHopMixScale1Test(L3RouteScaleTestBase):
    """
    Test large-scale IPv6 mixed mask route scale and measure load factor.

    Objectives:
    1. Generate mixed IPv6 routes with /48, /56, /64 masks in specified proportions.
    2. Measure load factor and CRUD performance for mixed routes.
    3. Verify route table recovery after all operations.

    IPv6 route distribution:
    - 30% /48 routes (1000::/48)
    - 30% /56 routes (1000::/56, 2000::/56)
    - 40% /64 routes (1000::/64, 3000::/64)
    """

    def setUp(self):
        super(L3IPv6SingleHopMixScale1Test, self).setUp()
        self.total_routes = 100000  # Total route count, minimum 100k
        self.expected_perf = 10000  # Performance baseline 10k/s

    def generate_mixed_ipv6_routes_scale1(self):
        """Generate IPv6 mixed mask test route entries

        Generate mixed mask routes with different distributions using optimized approach:
        - 30% /48 routes (starting from 1000::/48)
        - 30% /56 routes (half contained in /48)
        - 40% /64 routes (all contained in /56)

        Optimization: First generates all prefix lists, then creates all SAI route objects
        in a single call to create_routes_from_prefixes() for better performance.

        Returns:
            list: Route entry list
        """
        print(f"\nGenerating {self.total_routes} mixed IPv6 /48, /56, /64 test routes with optimized single call...")

        # Calculate route count for each type
        routes_48 = int(self.total_routes * 0.3)  # 30% /48 routes
        routes_56 = int(self.total_routes * 0.3)  # 30% /56 routes
        routes_64 = self.total_routes - routes_48 - routes_56  # 40% /64 routes

        print(f"Generating {routes_48} /48 routes, {routes_56} /56 routes, {routes_64} /64 routes")

        # Calculate subdivisions for hierarchical distribution
        routes_56_in_48 = routes_56 // 2  # Half of /56 routes contained in /48
        routes_56_out_48 = routes_56 - routes_56_in_48  # Remaining /56 routes
        routes_64_in_56 = routes_64 // 2  # Half of /64 routes contained in /56
        routes_64_out_56 = routes_64 - routes_64_in_56  # Remaining /64 routes

        # Generate all prefix lists first
        all_prefixes = []

        # 1. Generate /48 routes starting from 1000::/48
        if routes_48 > 0:
            print("Generating /48 prefixes...")
            prefix_list_48 = self.generate_ipv6_prefixes(
                prefix_len=48,
                start_ip="1000::",
                step=1,
                count=routes_48
            )
            all_prefixes.extend(prefix_list_48)

        # 2. Generate /56 routes (half contained in /48: 1000::/56, half separate: 2000::/56)
        if routes_56_in_48 > 0:
            print("Generating /56 prefixes contained in /48...")
            prefix_list_56_in_48 = self.generate_ipv6_prefixes(
                prefix_len=56,
                start_ip="1000::",
                step=1,
                count=routes_56_in_48
            )
            all_prefixes.extend(prefix_list_56_in_48)

        if routes_56_out_48 > 0:
            print("Generating /56 prefixes outside /48...")
            prefix_list_56_out_48 = self.generate_ipv6_prefixes(
                prefix_len=56,
                start_ip="2000::",
                step=1,
                count=routes_56_out_48
            )
            all_prefixes.extend(prefix_list_56_out_48)

        # 3. Generate /64 routes (half contained in /56: 1000::/64, half separate: 3000::/64)
        if routes_64_in_56 > 0:
            print("Generating /64 prefixes contained in /56...")
            prefix_list_64_in_56 = self.generate_ipv6_prefixes(
                prefix_len=64,
                start_ip="1000::",
                step=1,
                count=routes_64_in_56
            )
            all_prefixes.extend(prefix_list_64_in_56)

        if routes_64_out_56 > 0:
            print("Generating /64 prefixes outside /56...")
            prefix_list_64_out_56 = self.generate_ipv6_prefixes(
                prefix_len=64,
                start_ip="3000::",
                step=1,
                count=routes_64_out_56
            )
            all_prefixes.extend(prefix_list_64_out_56)

        # Create all SAI route objects from all prefixes in one call
        print(f"Creating {len(all_prefixes)} SAI route objects from all prefixes...")
        route_entries = self.create_routes_from_prefixes(all_prefixes)

        print(f"Generated {len(route_entries)} mixed IPv6 routes with optimized single call:")
        print(f"  - {routes_48} /48 routes")
        print(f"  - {routes_56} /56 routes ({routes_56_in_48} contained in /48, {routes_56_out_48} separate)")
        print(f"  - {routes_64} /64 routes ({routes_64_in_56} contained in /56, {routes_64_out_56} separate)")
        return route_entries

    def runTest(self):
        """Execute test steps"""
        try:
            # 1. Generate test routes
            route_entries = self.generate_mixed_ipv6_routes_scale1()

            # 2. Test CRUD operations
            create_perf, remove_perf, crud_pass = self.execute_crud_test(route_entries)
            results = {
                'create': create_perf,
                'remove': remove_perf
            }

            # 3. Output test result summary
            perf_pass = self.print_performance_results(results, "IPv6 Mixed Scale Performance Test Results")
            print(f"perf_pass: {perf_pass}, crud_pass: {crud_pass}")
            self.assertTrue(perf_pass and crud_pass, "IPv6 Mixed Scale Performance Test failed")
        except Exception as e:
            print(f"Test failed: {e}")
            raise

    def tearDown(self):
        super(L3IPv6SingleHopMixScale1Test, self).tearDown()


class L3IPv6SingleHopScaleIterate1Test(L3RouteScaleTestBase):
    """
    Test maximum stress coverage and load factor for large-scale IPv6 /64 routes.

    Objectives:
    1. Generate large-scale IPv6 /64 routes.
    2. Measure load factor for sequential and random route creation.
    3. Verify route table recovery after all operations.

    IPv6 route pattern:
    - /64 routes (1000::/64)
    """

    def setUp(self):
        super(L3IPv6SingleHopScaleIterate1Test, self).setUp()
        self.skip_syslog_verify = True
        self.total_routes = self.init_ipv6_route_count

    def runTest(self):
        """Execute test steps"""
        try:
            # 1. Generate test routes
            print("\nGenerating IPv6 /64 test routes...")
            prefix_list = self.generate_ipv6_prefixes(
                prefix_len=64,
                start_ip="1000::",
                step=1,
                count=self.total_routes
            )

            # 2. Create SAI route objects from prefixes
            print(f"Creating {len(prefix_list)} SAI route objects from prefixes...")
            route_entries = self.create_routes_from_prefixes(prefix_list)

            # 3. Sequentially create
            sequential_load_factor_pass, sequential_success_route_cnt = self.execute_load_factor_test(
                route_entries, order="sequential")
            print(f"Sequential delivery load factor pass: {sequential_load_factor_pass}, success_add_route: {sequential_success_route_cnt}")

            # 4. Shuffle and create again
            print(f"\nShuffling and creating again...")
            random.shuffle(route_entries)
            shuffle_load_factor_pass, shuffle_success_route_cnt = self.execute_load_factor_test(
                route_entries, order="random")
            print(f"Random delivery load factor pass: {shuffle_load_factor_pass}, success_add_route: {shuffle_success_route_cnt}")
            self.assertTrue(sequential_load_factor_pass and shuffle_load_factor_pass, "IPv6 /64 Scale Iterate Test failed")

        except Exception as e:
            print(f"Test failed: {e}")
            raise

    def tearDown(self):
        super(L3IPv6SingleHopScaleIterate1Test, self).tearDown()


class L3IPv6SingleHopScaleIterate2Test(L3RouteScaleTestBase):
    """
    Test maximum stress coverage and load factor for large-scale IPv6 /56 and /64 mixed routes.

    Objectives:
    1. Generate large-scale mixed IPv6 /56 and /64 routes.
    2. Measure load factor for sequential and random route creation.
    3. Verify route table recovery after all operations.

    IPv6 route distribution:
    - 20% /56 routes (1000::/56)
    - 40% /64 routes within /56 (1000::/64)
    - 40% /64 routes in separate segments (1100::/64)
    """

    def setUp(self):
        super(L3IPv6SingleHopScaleIterate2Test, self).setUp()
        self.skip_syslog_verify = True
        self.total_routes = self.init_ipv6_route_count

    def generate_mixed_ipv6_routes_iterate2(self):
        """Generate mixed routes with optimized single-call approach

        Generate mixed routes with different distributions using optimized approach:
        - 20% /56 routes starting from 1000::/56
        - 40% /64 routes within /56 networks starting from 1000::/64
        - 40% /64 routes in separate segments starting from 1100::/64

        Optimization: First generates all prefix lists, then creates all SAI route objects
        in a single call to create_routes_from_prefixes() for better performance.

        Returns:
            list: Route entry list
        """
        print(f"\nGenerating {self.total_routes} mixed /56 and /64 test routes with optimized single call...")

        # Calculate route counts for each type
        routes_56 = int(self.total_routes * 0.20)    # 20% /56 routes
        routes_64_in_56 = int(self.total_routes * 0.40)   # 40% /64 routes within /56
        routes_64_separate = self.total_routes - routes_56 - routes_64_in_56  # 40% /64 routes in separate segments

        print(f"Route distribution:")
        print(f"  - {routes_56} /56 routes starting from 1000::/56")
        print(f"  - {routes_64_in_56} /64 routes within /56 networks starting from 1000::/64")
        print(f"  - {routes_64_separate} /64 routes in separate segments starting from 1100::/64")

        # Generate all prefix lists first
        all_prefixes = []

        # 1. Generate /56 routes starting from 1000::/56
        if routes_56 > 0:
            print("\nGenerating /56 prefixes...")
            prefix_list_56 = self.generate_ipv6_prefixes(
                prefix_len=56,
                start_ip="1000::",
                step=1,
                count=routes_56
            )
            all_prefixes.extend(prefix_list_56)

        # 2. Generate /64 routes within /56 networks starting from 1000::/64
        if routes_64_in_56 > 0:
            print("Generating /64 prefixes within /56 networks...")
            prefix_list_64_in_56 = self.generate_ipv6_prefixes(
                prefix_len=64,
                start_ip="1000::",
                step=1,
                count=routes_64_in_56
            )
            all_prefixes.extend(prefix_list_64_in_56)

        # 3. Generate /64 routes in separate segments starting from 1100::/64
        if routes_64_separate > 0:
            print("Generating /64 prefixes in separate segments...")
            prefix_list_64_separate = self.generate_ipv6_prefixes(
                prefix_len=64,
                start_ip="1100::",
                step=1,
                count=routes_64_separate
            )
            all_prefixes.extend(prefix_list_64_separate)

        # Create all SAI route objects from all prefixes in one call
        print(f"\nCreating {len(all_prefixes)} SAI route objects...")
        route_entries = self.create_routes_from_prefixes(all_prefixes)

        print(f"\nGenerated {len(route_entries)} mixed routes:")
        print(f"  - {routes_56} /56 routes starting from 1000::/56")
        print(f"  - {routes_64_in_56} /64 routes within /56 networks starting from 1000::/64")
        print(f"  - {routes_64_separate} /64 routes in separate segments starting from 1100::/64")
        return route_entries

    def runTest(self):
        """Execute test steps"""
        try:
            # 1. Generate test routes
            route_entries = self.generate_mixed_ipv6_routes_iterate2()

            # 2. Sequentially create
            sequential_load_factor_pass, sequential_success_route_cnt = self.execute_load_factor_test(
                route_entries, order="sequential")
            print(f"Sequential delivery load factor pass: {sequential_load_factor_pass}, success_add_route: {sequential_success_route_cnt}")

            # 3. Shuffle create again
            print(f"\nShuffling and create again...")
            random.shuffle(route_entries)
            shuffle_load_factor_pass, shuffle_success_route_cnt = self.execute_load_factor_test(
                route_entries, order="random")
            print(f"Random delivery load factor pass: {shuffle_load_factor_pass}, success_add_route: {shuffle_success_route_cnt}")
            self.assertTrue(sequential_load_factor_pass and shuffle_load_factor_pass, "IPv6 /64 Scale Iterate Test failed")

        except Exception as e:
            print(f"Test failed: {e}")
            raise

    def tearDown(self):
        super(L3IPv6SingleHopScaleIterate2Test, self).tearDown()


class L3IPv6SingleHopScaleIterate4Test(L3RouteScaleTestBase):
    """
    Test maximum stress coverage and load factor for large-scale hierarchical IPv6 routes.

    Objectives:
    1. Generate large-scale hierarchical IPv6 routes with /48, /56, /64 masks.
    2. Measure load factor for sequential and random route creation.
    3. Verify route table recovery after all operations.

    IPv6 route distribution:
    - 20% /48 routes (1000::/48)
    - 40% /56 routes (1000::/56, 2000::/56)
    - 40% /64 routes (1000::/64)
    """

    def setUp(self):
        super(L3IPv6SingleHopScaleIterate4Test, self).setUp()
        self.skip_syslog_verify = True
        self.total_routes = self.init_ipv6_route_count  # Total route count, minimum 100k

    def generate_mixed_ipv6_routes_iterate4(self):
        """Generate IPv6 hierarchical /48, /56 and /64 mask test route entries

        Generate hierarchical routes using optimized approach:
        - 20% /48 routes starting from 1000::/48
        - 40% /56 routes (half from 1000::/56, half from 2000::/56)
        - 40% /64 routes starting from 1000::/64

        Optimization: First generates all prefix lists, then creates all SAI route objects
        in a single call to create_routes_from_prefixes() for better performance.

        Returns:
            list: Route entry list
        """
        print(f"\nGenerating IPv6 hierarchical /48, /56 and /64 test routes with optimized single call...")

        total_routes = self.total_routes
        routes_48 = int(total_routes * 0.2)    # 20% /48 routes
        routes_56 = int(total_routes * 0.4)    # 40% /56 routes
        routes_64 = total_routes - routes_48 - routes_56  # 40% /64 routes

        print(f"Generating {routes_48} /48 routes, {routes_56} /56 routes, {routes_64} /64 routes")

        # Calculate subdivisions for /56 routes
        routes_56_part1 = routes_56 // 2
        routes_56_part2 = routes_56 - routes_56_part1

        # Generate all prefix lists first
        all_prefixes = []

        # 1. Generate /48 routes starting from 1000::/48
        if routes_48 > 0:
            print("Generating /48 prefixes...")
            prefix_list_48 = self.generate_ipv6_prefixes(
                prefix_len=48,
                start_ip="1000::",
                step=1,
                count=routes_48
            )
            all_prefixes.extend(prefix_list_48)

        # 2. Generate /56 routes (split into two address spaces)
        if routes_56_part1 > 0:
            print("Generating /56 prefixes (first part from 1000::)...")
            prefix_list_56_part1 = self.generate_ipv6_prefixes(
                prefix_len=56,
                start_ip="1000::",
                step=1,
                count=routes_56_part1
            )
            all_prefixes.extend(prefix_list_56_part1)

        if routes_56_part2 > 0:
            print("Generating /56 prefixes (second part from 2000::)...")
            prefix_list_56_part2 = self.generate_ipv6_prefixes(
                prefix_len=56,
                start_ip="2000::",
                step=1,
                count=routes_56_part2
            )
            all_prefixes.extend(prefix_list_56_part2)

        # 3. Generate /64 routes starting from 1000::/64
        if routes_64 > 0:
            print("Generating /64 prefixes...")
            prefix_list_64 = self.generate_ipv6_prefixes(
                prefix_len=64,
                start_ip="1000::",
                step=1,
                count=routes_64
            )
            all_prefixes.extend(prefix_list_64)

        # Create all SAI route objects from all prefixes in one call
        print(f"Creating {len(all_prefixes)} SAI route objects from all prefixes...")
        route_entries = self.create_routes_from_prefixes(all_prefixes)

        print(f"Generated {len(route_entries)} hierarchical IPv6 routes with optimized single call:")
        print(f"  - {routes_48} /48 routes")
        print(f"  - {routes_56} /56 routes ({routes_56_part1} from 1000::, {routes_56_part2} from 2000::)")
        print(f"  - {routes_64} /64 routes")
        return route_entries

    def runTest(self):
        """Execute hierarchical route scale test with performance monitoring"""
        try:
            # 1. Generate hierarchical route structure
            route_entries = self.generate_mixed_ipv6_routes_iterate4()

            # 2. Sequentially create
            sequential_load_factor_pass, sequential_success_route_cnt = self.execute_load_factor_test(
                route_entries, order="sequential")
            print(f"Sequential delivery load factor pass: {sequential_load_factor_pass}, success_add_route: {sequential_success_route_cnt}")

            # 3. Shuffle create again
            print(f"\nShuffling and create again...")
            random.shuffle(route_entries)
            shuffle_load_factor_pass, shuffle_success_route_cnt = self.execute_load_factor_test(
                route_entries, order="random")
            print(f"Random delivery load factor pass: {shuffle_load_factor_pass}, success_add_route: {shuffle_success_route_cnt}")
            self.assertTrue(sequential_load_factor_pass and shuffle_load_factor_pass, "IPv6 /64 Scale Iterate Test failed")
        except Exception as e:
            print(f"Test failed: {e}")
            raise

    def tearDown(self):
        """Clean up test environment"""
        super(L3IPv6SingleHopScaleIterate4Test, self).tearDown()


class L3IPv4IPv6MixSingleHopScale1Test(L3RouteScaleTestBase):
    """
    Test large-scale mixed IPv4 and IPv6 route scale and measure load factor.

    Objectives:
    1. Generate large-scale mixed IPv4 and IPv6 routes according to specified distributions.
    2. Measure load factor for sequential and random route creation.
    3. Verify route table recovery after all operations.

    IPv4 route distribution:
    - 25% /26 routes (100.0.0.0/26)
    - 50% /28 routes (100.0.0.0/28)
    - 25% /32 routes (100.0.0.0/32, step 4)

    IPv6 route distribution:
    - 45% /56 routes (1000::/56)
    - 50% /64 routes (1000::/64)
    - 2.5% /127 routes (1000::/127)
    - 2.5% /128 routes (1000::/128)
    """

    def setUp(self):
        super(L3IPv4IPv6MixSingleHopScale1Test, self).setUp()

        self.skip_syslog_verify = True

        self.ipv4_routes = self.init_ipv4_route_count // 2  # M IPv4 routes
        self.ipv6_routes = self.init_ipv6_route_count // 2  # N IPv6 routes
        self.total_routes = self.ipv4_routes + self.ipv6_routes
        self.expected_perf = 10000  # Performance baseline 10k/s
        self.support_bulk_api = True
        self.ipv4_route_nh_map = {}
        self.ipv6_route_nh_map = {}

    def generate_ipv4ipv6_mixed_ipv4_routes_scale1(self):
        """Generate IPv4 test route entries with mixed masks

        Generate IPv4 routes using optimized approach:
        - 25% /26 routes starting from 100.0.0.0/26
        - 50% /28 routes starting from 100.0.0.0/28
        - 25% /32 routes starting from 100.0.0.0/32 (step 4)

        Optimization: First generates all prefix lists, then creates all SAI route objects
        in a single call to create_routes_from_prefixes() for better performance.

        Returns:
            list: IPv4 route entry list
        """
        print(f"\nGenerating {self.ipv4_routes} IPv4 mixed mask test routes with optimized single call...")

        # Calculate route count for each mask
        routes_26 = int(self.ipv4_routes * 0.25)  # 25% /26
        routes_28 = int(self.ipv4_routes * 0.50)  # 50% /28
        routes_32 = self.ipv4_routes - routes_26 - routes_28  # 25% /32

        print(f"Generating {routes_26} /26 routes, {routes_28} /28 routes, {routes_32} /32 routes")

        # Generate all prefix lists first
        all_prefixes = []

        # 1. Generate /28 routes starting from 100.0.0.0/28
        if routes_28 > 0:
            print("Generating /28 prefixes...")
            prefix_list_28 = self.generate_ipv4_prefixes(
                prefix_len=28,
                start_ip="100.0.0.0",
                step=1,
                count=routes_28
            )
            all_prefixes.extend(prefix_list_28)

        # 2. Generate /26 routes starting from 100.0.0.0/26
        if routes_26 > 0:
            print("Generating /26 prefixes...")
            prefix_list_26 = self.generate_ipv4_prefixes(
                prefix_len=26,
                start_ip="100.0.0.0",
                step=1,
                count=routes_26
            )
            all_prefixes.extend(prefix_list_26)

        # 3. Generate /32 routes starting from 100.0.0.0/32 (step 4)
        if routes_32 > 0:
            print("Generating /32 prefixes...")
            prefix_list_32 = self.generate_ipv4_prefixes(
                prefix_len=32,
                start_ip="100.0.0.0",
                step=4,
                count=routes_32
            )
            all_prefixes.extend(prefix_list_32)

        # Create all SAI route objects from all prefixes in one call
        print(f"Creating {len(all_prefixes)} SAI route objects from all prefixes...")
        route_entries = self.create_routes_from_prefixes(all_prefixes)

        print(f"Generated {len(route_entries)} IPv4 mixed routes with optimized single call:")
        print(f"  - {routes_26} /26 routes")
        print(f"  - {routes_28} /28 routes")
        print(f"  - {routes_32} /32 routes")
        return route_entries

    def generate_ipv4ipv6_mixed_ipv6_routes_scale1(self):
        """Generate IPv6 test route entries with mixed masks

        Generate IPv6 routes using optimized approach:
        - 45% /56 routes starting from 1000::/56
        - 50% /64 routes starting from 1000::/64
        - 2.5% /127 routes starting from 1000::/127
        - 2.5% /128 routes starting from 1000::/128

        Optimization: First generates all prefix lists, then creates all SAI route objects
        in a single call to create_routes_from_prefixes() for better performance.

        Returns:
            list: IPv6 route entry list
        """
        print(f"\nGenerating {self.ipv6_routes} IPv6 mixed mask test routes with optimized single call...")

        # Calculate route count for each mask
        routes_56 = int(self.ipv6_routes * 0.45)   # 45% /56
        routes_64 = int(self.ipv6_routes * 0.50)   # 50% /64
        routes_127 = int(self.ipv6_routes * 0.025)  # 2.5% /127
        routes_128 = self.ipv6_routes - routes_56 - routes_64 - routes_127  # 2.5% /128

        print(f"Generating {routes_56} /56 routes, {routes_64} /64 routes, {routes_127} /127 routes, {routes_128} /128 routes")

        # Generate all prefix lists first
        all_prefixes = []

        # 1. Generate /56 routes starting from 1000::/56
        if routes_56 > 0:
            print("Generating /56 prefixes...")
            prefix_list_56 = self.generate_ipv6_prefixes(
                prefix_len=56,
                start_ip="1000::",
                step=1,
                count=routes_56
            )
            all_prefixes.extend(prefix_list_56)

        # 2. Generate /64 routes starting from 1000::/64
        if routes_64 > 0:
            print("Generating /64 prefixes...")
            prefix_list_64 = self.generate_ipv6_prefixes(
                prefix_len=64,
                start_ip="1000::",
                step=1,
                count=routes_64
            )
            all_prefixes.extend(prefix_list_64)

        # 3. Generate /127 routes starting from 1000::/127
        if routes_127 > 0:
            print("Generating /127 prefixes...")
            prefix_list_127 = self.generate_ipv6_prefixes(
                prefix_len=127,
                start_ip="1000::",
                step=1,
                count=routes_127
            )
            all_prefixes.extend(prefix_list_127)

        # 4. Generate /128 routes starting from 1000::/128
        if routes_128 > 0:
            print("Generating /128 prefixes...")
            prefix_list_128 = self.generate_ipv6_prefixes(
                prefix_len=128,
                start_ip="1000::",
                step=1,
                count=routes_128
            )
            all_prefixes.extend(prefix_list_128)

        # Create all SAI route objects from all prefixes in one call
        print(f"Creating {len(all_prefixes)} SAI route objects from all prefixes...")
        route_entries = self.create_routes_from_prefixes(all_prefixes)

        print(f"Generated {len(route_entries)} IPv6 mixed routes with optimized single call:")
        print(f"  - {routes_56} /56 routes")
        print(f"  - {routes_64} /64 routes")
        print(f"  - {routes_127} /127 routes")
        print(f"  - {routes_128} /128 routes")
        return route_entries

    def runTest(self):
        """Execute test steps

        Steps:
        1. Generate IPv4 and IPv6 routes
        2. Sequentially route load factor test
        3. Shuffle route entries
        4. Shuffle route load factor test
        """
        try:
            # 1. Generate IPv4 and IPv6 routes
            ipv4_route_entries = self.generate_ipv4ipv6_mixed_ipv4_routes_scale1()
            ipv6_route_entries = self.generate_ipv4ipv6_mixed_ipv6_routes_scale1()

            # Merge all routes
            route_entries = ipv6_route_entries + ipv4_route_entries

            # 2. Sequentially route load factor test
            sequential_load_factor_pass, sequential_success_route_cnt = self.execute_load_factor_test(
                route_entries, order="sequential")
            print(f"Sequential delivery load factor pass: {sequential_load_factor_pass}, success_add_route: {sequential_success_route_cnt}")

            # 3. Shuffle route entries
            print(f"\nShuffling and create again...")
            random.shuffle(route_entries)

            # 4. Shuffle route load factor test
            shuffle_load_factor_pass, shuffle_success_route_cnt = self.execute_load_factor_test(
                route_entries, order="random")
            print(f"Random delivery load factor pass: {shuffle_load_factor_pass}, success_add_route: {shuffle_success_route_cnt}")

            self.assertTrue(sequential_load_factor_pass and shuffle_load_factor_pass, "IPv4 Mixed Scale Iterate Test failed")

        except Exception as e:
            print(f"Test failed: {e}")
            raise

    def tearDown(self):
        super(L3IPv4IPv6MixSingleHopScale1Test, self).tearDown()


class L3IPv4IPv6MixSingleHopScale2Test(L3RouteScaleTestBase):
    """Test IPv4 and IPv6 mixed route scale and performance

    Test objectives:
    1. Test maximum stress coverage of IPv4 and IPv6 mixed single-hop routes with different distribution
    2. Measure mixed route delivery performance
    3. Verify bulk operation performance with different bulk sizes

    IPv4 route distribution:
    - 20% /26 routes (100.0.0.0/26)
    - 15% /27 routes (100.0.0.0/27)
    - 50% /28 routes (100.0.0.0/28)
    - 15% /32 routes (100.0.0.0/32, step 4)

    IPv6 route distribution:
    - 20% /48 routes (1000::/48)
    - 40% /56 routes (1000::/56)
    - 40% /64 routes (1000::/64)

    """

    def setUp(self):
        super(L3IPv4IPv6MixSingleHopScale2Test, self).setUp()

        self.skip_syslog_verify = True

        # Set route scales based on available counts (use conservative values)
        self.ipv4_routes = self.init_ipv4_route_count // 2  # M IPv4 routes
        self.ipv6_routes = self.init_ipv6_route_count // 2  # N IPv6 routes
        self.total_routes = self.ipv4_routes + self.ipv6_routes

        self.bulk_size = 20000  # Bulk size list to test

        # Separate route-NH mappings for IPv4 and IPv6
        self.ipv4_route_nh_map = {}
        self.ipv6_route_nh_map = {}

    def generate_ipv4ipv6_mixed_ipv4_routes_scale2(self):
        """Generate IPv4 test route entries with mixed masks

        Generate IPv4 routes using optimized approach:
        - 20% /26 routes starting from 100.0.0.0/26
        - 15% /27 routes starting from 100.0.0.0/27
        - 50% /28 routes starting from 100.0.0.0/28
        - 15% /32 routes starting from 100.0.0.0/32 (step 4)

        Optimization: First generates all prefix lists, then creates all SAI route objects
        in a single call to create_routes_from_prefixes() for better performance.

        Returns:
            list: IPv4 route entry list
        """
        print(f"\nGenerating {self.ipv4_routes} IPv4 mixed mask test routes.")

        # Calculate route count for each mask
        routes_26 = int(self.ipv4_routes * 0.20)  # 20% /26
        routes_27 = int(self.ipv4_routes * 0.15)  # 15% /27
        routes_28 = int(self.ipv4_routes * 0.50)  # 50% /28
        routes_32 = self.ipv4_routes - routes_26 - routes_27 - routes_28  # 15% /32

        print(f"Generating {routes_26} /26 routes, {routes_27} /27 routes, {routes_28} /28 routes, {routes_32} /32 routes")

        # Generate all prefix lists first
        all_prefixes = []

        # 1. Generate /28 routes starting from 100.0.0.0/28
        if routes_28 > 0:
            print("Generating /28 prefixes...")
            prefix_list_28 = self.generate_ipv4_prefixes(
                prefix_len=28,
                start_ip="100.0.0.0",
                step=1,
                count=routes_28
            )
            all_prefixes.extend(prefix_list_28)

        # 2. Generate /27 routes starting from 100.0.0.0/27
        if routes_27 > 0:
            print("Generating /27 prefixes...")
            prefix_list_27 = self.generate_ipv4_prefixes(
                prefix_len=27,
                start_ip="100.0.0.0",
                step=1,
                count=routes_27
            )
            all_prefixes.extend(prefix_list_27)

        # 3. Generate /26 routes starting from 100.0.0.0/26
        if routes_26 > 0:
            print("Generating /26 prefixes...")
            prefix_list_26 = self.generate_ipv4_prefixes(
                prefix_len=26,
                start_ip="100.0.0.0",
                step=1,
                count=routes_26
            )
            all_prefixes.extend(prefix_list_26)

        # 4. Generate /32 routes (all contained in /24, step 4)
        if routes_32 > 0:
            print("Generating /32 prefixes contained in /24...")
            prefix_list_32 = self.generate_ipv4_prefixes(
                prefix_len=32,
                start_ip="100.0.0.0",
                step=4,
                count=routes_32
            )
            all_prefixes.extend(prefix_list_32)

        # Create all SAI route objects from all prefixes in one call
        print(f"Creating {len(all_prefixes)} SAI route objects from all prefixes...")
        route_entries = self.create_routes_from_prefixes(all_prefixes)

        print(f"Generated {len(route_entries)} IPv4 mixed routes with optimized single call:")
        print(f"  - {routes_26} /26 routes")
        print(f"  - {routes_27} /27 routes")
        print(f"  - {routes_28} /28 routes")
        print(f"  - {routes_32} /32 routes")
        return route_entries


    def generate_ipv4ipv6_mixed_ipv6_routes_scale2(self):
        """Generate IPv6 test route entries with mixed masks

        Generate IPv6 routes using optimized approach:
        - 20% /48 routes starting from 1000::/48
        - 40% /56 routes starting from 1000::/56
        - 40% /64 routes starting from 1000::/64

        Optimization: First generates all prefix lists, then creates all SAI route objects
        in a single call to create_routes_from_prefixes() for better performance.

        Returns:
            list: IPv6 route entry list
        """
        print(f"\nGenerating {self.ipv6_routes} IPv6 mixed mask test routes with optimized single call...")

        # Calculate route count for each mask
        routes_48 = int(self.ipv6_routes * 0.20)   # 20% /48
        routes_56 = int(self.ipv6_routes * 0.40)   # 40% /56
        routes_64 = int(self.ipv6_routes * 0.40)   # 40% /64

        print(f"Generating {routes_48} /48 routes, {routes_56} /56 routes, {routes_64} /64 routes")

        # Generate all prefix lists first
        all_prefixes = []

        # 1. Generate /48 routes starting from 1000::/48
        if routes_48 > 0:
            print("Generating /48 prefixes...")
            prefix_list_48 = self.generate_ipv6_prefixes(
                prefix_len=48,
                start_ip="1000::",
                step=1,
                count=routes_48
            )
            all_prefixes.extend(prefix_list_48)

        # 2. Generate /56 routes starting from 1000::/56
        if routes_56 > 0:
            print("Generating /56 prefixes...")
            prefix_list_56 = self.generate_ipv6_prefixes(
                prefix_len=56,
                start_ip="1000::",
                step=1,
                count=routes_56
            )
            all_prefixes.extend(prefix_list_56)

        # 3. Generate /64 routes starting from 1000::/64
        if routes_64 > 0:
            print("Generating /64 prefixes...")
            prefix_list_64 = self.generate_ipv6_prefixes(
                prefix_len=64,
                start_ip="1000::",
                step=1,
                count=routes_64
            )
            all_prefixes.extend(prefix_list_64)


        # Create all SAI route objects from all prefixes in one call
        print(f"Creating {len(all_prefixes)} SAI route objects from all prefixes...")
        route_entries = self.create_routes_from_prefixes(all_prefixes)

        print(f"Generated {len(route_entries)} IPv6 mixed routes with optimized single call:")
        print(f"  - {routes_48} /48 routes")
        print(f"  - {routes_56} /56 routes")
        print(f"  - {routes_64} /64 routes")
        return route_entries


    def runTest(self):
        """Execute test steps

        Steps:
        1. Generate IPv4 and IPv6 routes
        2. Sequentially route load factor test
        3. Shuffle route entries
        4. Shuffle route load factor test
        """
        try:
            # 1. Generate IPv4 and IPv6 routes
            ipv4_route_entries = self.generate_ipv4ipv6_mixed_ipv4_routes_scale2()
            ipv6_route_entries = self.generate_ipv4ipv6_mixed_ipv6_routes_scale2()

            # Merge all routes
            route_entries = ipv6_route_entries + ipv4_route_entries

            # 2. Sequentially route load factor test
            sequential_load_factor_pass, sequential_success_route_cnt = self.execute_load_factor_test(
                route_entries, order="sequential")
            print(f"Sequential delivery load factor pass: {sequential_load_factor_pass}, success_add_route: {sequential_success_route_cnt}")

            # 3. Shuffle route entries
            print(f"\nShuffling and create again...")
            random.shuffle(route_entries)

            # 4. Shuffle route load factor test
            shuffle_load_factor_pass, shuffle_success_route_cnt = self.execute_load_factor_test(
                route_entries, order="random")
            print(f"Random delivery load factor pass: {shuffle_load_factor_pass}, success_add_route: {shuffle_success_route_cnt}")

            self.assertTrue(sequential_load_factor_pass and shuffle_load_factor_pass, "IPv4 Mixed Scale Iterate Test failed")

        except Exception as e:
            print(f"Test failed: {e}")
            raise

    def tearDown(self):
        super(L3IPv4IPv6MixSingleHopScale2Test, self).tearDown()
