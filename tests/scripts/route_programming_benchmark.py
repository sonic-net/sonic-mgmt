#!/usr/bin/env python3
"""
Route Programming Performance Benchmark Script

Measures the time it takes for routes to be programmed through the SONiC pipeline:
1. Zebra -> fpmsyncd
2. fpmsyncd -> Redis APPL_DB
3. APPL_DB -> ASIC_DB
4. ASIC_DB -> Hardware

Usage:
    ./route_programming_benchmark.py [--routes 30000] [--prefix 192.168.0.0/16] [--nexthop 10.0.0.1]
"""

import argparse
import ipaddress
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Tuple


class RouteStatistics:
    """Store route statistics"""

    def __init__(self, frr_sharp: int, frr_fib: int, appl_db: int, asic_db: int, hardware: int):
        self.count = {
            "FRR SHARP": frr_sharp,
            "FRR FIB": frr_fib,
            "APPL_DB": appl_db,
            "ASIC_DB": asic_db,
            "Hardware": hardware,
        }

    def __getitem__(self, key):
        return self.count[key]

    def print(self):
        """Print formatted statistics"""
        for stage, count in self.count.items():
            print(f"{stage}: {count}")

    def print_with_target(self, target_stats: "RouteStatistics"):
        """Print formatted statistics for target stats"""
        for stage, count in self.count.items():
            target_count = target_stats.count.get(stage, 0)
            print(f"{stage}: {count} / {target_count}")

    def reached_target(self, target_stats: "RouteStatistics", stage_name: str) -> bool:
        """Check if target stats are reached for a specific stage"""
        # Define the pipeline stages in order (matching the dict keys)
        stage_order = ["FRR SHARP", "FRR FIB", "APPL_DB", "ASIC_DB", "Hardware"]

        # Get the index of the target stage
        try:
            target_stage_idx = stage_order.index(stage_name)
        except ValueError:
            # Unknown stage, check all stages
            target_stage_idx = len(stage_order) - 1

        # Check all stages up to and including the target stage
        for i in range(target_stage_idx + 1):
            stage = stage_order[i]
            current_count = self.count.get(stage, 0)
            target_count = target_stats.count.get(stage, 0)

            if current_count < target_count:
                return False

        return True

    def percentage_change(self, baseline_stats: "RouteStatistics", stage_name: str) -> float:
        """Calculate percentage change from baseline for a specific stage"""
        # Get current and baseline counts for the specified stage
        current_count = self.count.get(stage_name, 0)
        baseline_count = baseline_stats.count.get(stage_name, 0)

        # Calculate percentage change
        if baseline_count > 0:
            return (current_count - baseline_count) / baseline_count * 100
        elif current_count > 0:
            return float("inf")  # Infinite increase from zero baseline
        else:
            return 0.0  # No change (both zero)


@dataclass
class BenchmarkResults:
    """Store benchmark timing results"""

    total_routes: int
    pretty_start_time: str
    asic_db_to_hardware_time: Optional[float]
    total_time: float
    fpmsyncd_timing: Optional[Tuple[str, str, float]] = None
    orchagent_timing: Optional[Tuple[str, str, float]] = None

    def print_results(self):
        """Print formatted benchmark results"""
        print("\n" + "=" * 60)
        print("ROUTE PROGRAMMING BENCHMARK RESULTS")
        print("=" * 60)
        print(f"Total routes injected: {self.total_routes:,}")
        print(f"Total benchmark time: {self.total_time:.3f}s")
        print()
        print("Stage timings:")
        print(f"  Start time: {self.pretty_start_time}")
        if self.asic_db_to_hardware_time is not None:
            print(f"  ASIC_DB to Hardware: {self.asic_db_to_hardware_time:.3f}s")
        else:
            print("  ASIC_DB to Hardware: N/A (Virtual Switch)")

        if self.fpmsyncd_timing:
            first_new_timestamp, last_qualifying_timestamp, time_diff = self.fpmsyncd_timing
            print(f"  fpmsyncd processing: {time_diff:.3f}s")
            print(f"     first activity time: {first_new_timestamp}")
            print(f"     last activity time: {last_qualifying_timestamp}")
        else:
            print("  fpmsyncd processing: Not measured")

        if self.orchagent_timing:
            first_new_timestamp, last_qualifying_timestamp, time_diff = self.orchagent_timing
            print(f"  Orchagent processing: {time_diff:.3f}s")
            print(f"     first activity time: {first_new_timestamp}")
            print(f"     last activity time: {last_qualifying_timestamp}")
        else:
            print("  Orchagent processing: Not measured")


class RouteProgrammingBenchmark:
    """Main benchmark class for measuring route programming performance"""

    def __init__(
        self,
        num_routes: int = 30000,
        prefix: str = "192.168.0.0/16",
        num_hops: int = 1,
        nexthop: str = "10.0.0.1",
    ):
        self.num_routes = num_routes
        self.prefix = prefix
        self.num_hops = num_hops
        self.nexthop = nexthop
        self.start_time = None
        self.zmq_enabled = None
        self.is_vs = self.check_if_vs()

        # Parse base prefix to generate route prefixes
        self.base_ip, self.base_mask = prefix.split("/")
        self.base_mask = int(self.base_mask)
        self.is_vs = self.run_command("show version | grep -oP x86_64-kvm") == "x86_64-kvm"

    def check_if_vs(self) -> bool:
        """Check if running on Virtual Switch"""
        try:
            result = subprocess.run(["docker", "ps"], capture_output=True, text=True)
            return "syncd-vs" in result.stdout
        except Exception:
            return False

    def is_root(self) -> bool:
        """Check if running as root user"""
        return os.geteuid() == 0

    def needs_sudo(self, cmd: str) -> bool:
        """Check if command needs sudo privileges"""
        # No need for sudo if running as root
        if self.is_root():
            return False
        # Check if command needs sudo privileges
        return "syslog" in cmd or "bcmcmd" in cmd

    def run_command(self, cmd: str, container: Optional[str] = None) -> str:
        """Execute command and return output"""
        if container:
            cmd = f"docker exec -i {container} {cmd}"
        elif self.needs_sudo(cmd):
            cmd = f"sudo {cmd}"

        # Use longer timeout for bcmcmd which can be slow with many routes
        timeout = 60 if "bcmcmd" in cmd else 30

        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            if result.returncode != 0:
                print(f"Command failed (rc={result.returncode}): {cmd}")
                print(f"Stdout: {result.stdout}")
                print(f"Stderr: {result.stderr}")
                return ""
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            print(f"Command timed out after {timeout}s: {cmd}")
            return ""

    def get_last_routecounter_timestamp(self, count_pattern) -> Optional[Tuple[str, int]]:
        """Get timestamp and route count of the last RouteCounter message before benchmark starts"""
        try:
            cmd = "tail -n 10000 /var/log/syslog"
            syslog_output = self.run_command(cmd)

            if not syslog_output:
                return None

            last_timestamp = None
            last_count = 0

            for line in syslog_output.split("\n"):
                match = re.search(count_pattern, line)
                if match:
                    last_timestamp = match.group(1)
                    last_count = int(match.group(2))

            if last_timestamp:
                return (last_timestamp, last_count)
            return None

        except Exception as e:
            print(f"Error getting last RouteCounter timestamp: {e}")
            return None

    def check_zmq_enabled(self) -> bool:
        """Check if ZMQ is enabled for route programming"""
        if self.zmq_enabled is not None:
            return self.zmq_enabled

        cmd = 'redis-cli -n 4 HGET "DEVICE_METADATA|localhost" "orch_northbond_route_zmq_enabled"'
        result = self.run_command(cmd)
        self.zmq_enabled = result.strip('"') == "true"
        return self.zmq_enabled

    def get_redis_route_count(self, db_name: str) -> int:
        """Get number of routes in Redis database"""
        if db_name == "APPL_DB":
            cmd = "redis-cli -n 0 eval \"return #redis.call('keys', 'ROUTE_TABLE:*')\" 0"
        elif db_name == "ASIC_DB":
            cmd = "redis-cli -n 1 eval \"return #redis.call('keys', 'ASIC_STATE:SAI_OBJECT_TYPE_ROUTE_ENTRY:*')\" 0"
        else:
            return 0

        result = self.run_command(cmd)
        return int(result) if result.isdigit() else 0

    def get_frr_fib_route_count(self) -> int:
        """Get number of FIB routes in FRR using route summary"""
        cmd = "vtysh -c 'show ip route summary json'"
        result = self.run_command(cmd)
        if not result:
            return 0
        try:
            data = json.loads(result)
            if not isinstance(data, dict):
                return 0
            # Return total FIB routes
            if "routesTotalFib" in data:
                return int(data["routesTotalFib"])
            return 0
        except Exception as e:
            print(f"Error parsing FRR route summary JSON: {e}")
            return 0

    def get_frr_sharp_route_count(self) -> int:
        """Get number of SHARP routes in FRR"""
        cmd = "vtysh -c 'show ip route summary json'"
        result = self.run_command(cmd, "bgp")
        if not result:
            return 0
        try:
            data = json.loads(result)
            if isinstance(data, dict) and "routes" in data:
                for route_type in data["routes"]:
                    if route_type.get("type") == "sharp" and "fib" in route_type:
                        return int(route_type["fib"])
        except Exception as e:
            print(f"Error parsing FRR route summary JSON: {e}")
        return 0

    def get_hardware_route_count(self) -> int:
        """Get number of routes programmed in hardware using bcmcmd"""
        if self.is_vs:
            return 0

        # Try different bcmcmd commands to determine hardwre route count for different platforms
        # Format 1: "l3 route show"
        cmd = 'bash -c \'bcmcmd "l3 route show" 2>/dev/null | grep -c "^[0-9]" || true\''
        result = self.run_command(cmd)
        if result and result.isdigit() and int(result) > 0:
            return int(result)

        # Format 2: "l3 defip show"
        cmd = 'bash -c \'bcmcmd "l3 defip show" 2>/dev/null | grep -c "^[0-9]" || true\''
        result = self.run_command(cmd)
        if result and result.isdigit() and int(result) > 0:
            return int(result)

        # Format 3: "MDB LPM DuMP TaBLe=LPM_A2"
        cmd = 'bash -c \'bcmcmd "MDB LPM DuMP TaBLe=LPM_A2" 2>/dev/null | grep -c "^| [0-9]" || true\''
        result = self.run_command(cmd)
        if result and result.isdigit() and int(result) > 0:
            return int(result)

        return 0

        # COMMENTED OUT: Original fibOffLoaded logic
        # cmd = "vtysh -c 'show ip route summary json'"
        # result = self.run_command(cmd, "bgp")
        # if result:
        #     try:
        #         data = json.loads(result)
        #         if isinstance(data, dict) and 'routes' in data:
        #             # Sum up all fibOffLoaded routes from all types
        #             total_offloaded = 0
        #             for route_type in data['routes']:
        #                 if 'fibOffLoaded' in route_type:
        #                     total_offloaded += int(route_type['fibOffLoaded'])
        #             return total_offloaded
        #         elif isinstance(data, dict) and 'routesTotalFib' in data:
        #             # Alternative: use total FIB routes
        #             return int(data['routesTotalFib'])
        #     except Exception as e:
        #         print(f"Error parsing route summary JSON: {e}")
        #         pass
        #
        # # Fallback: Count routes in kernel
        # cmd = "ip route show | grep -v 'linkdown\\|unreachable' | wc -l"
        # result = self.run_command(cmd)
        # if result.isdigit():
        #     return int(result)

    def get_hardware_route_count_non_local(self) -> int:
        """Get number of non-local routes programmed in hardware"""
        # Use bcmcmd to get hardware routes (includes all routes)
        return self.get_hardware_route_count()  # Use bcmcmd route count

    def parse_syslog_timing(
        self, target_routes: int, count_pattern: str, feature: str, baseline_info: Optional[Tuple[str, int]] = None
    ) -> Optional[Tuple[str, str, float]]:
        """
        Parse syslog messages and calculate timing.

        Args:
            baseline_info: Tuple of (timestamp, route_count) to use as baseline
        """
        print(f"\nParsing syslog for {feature} timing (target: {target_routes} routes)...")

        baseline_timestamp = None
        baseline_count = 0

        if baseline_info:
            baseline_timestamp, baseline_count = baseline_info
            print(f"Baseline: {baseline_count} routes at {baseline_timestamp}")
            print(f"Looking for {target_routes} additional routes")

        try:
            cmd = "tail -n 10000 /var/log/syslog"
            syslog_output = self.run_command(cmd)

            if not syslog_output:
                print("Warning: Could not read syslog")
                return None

            # Parse cutoff timestamp if provided
            cutoff_dt = None
            if baseline_timestamp:
                try:
                    cutoff_dt = datetime.strptime(baseline_timestamp, "%Y %b %d %H:%M:%S.%f")
                except ValueError:
                    print(f"Warning: Could not parse baseline timestamp: {baseline_timestamp}")

            first_new_timestamp = None
            last_qualifying_timestamp = None
            last_qualifying_count = baseline_count

            # Parse syslog lines
            for line in syslog_output.split("\n"):
                # Skip lines before cutoff timestamp
                if cutoff_dt:
                    line_match = re.search(r"(\d{4} \w+ \d+ \d{2}:\d{2}:\d{2}\.\d+)", line)
                    if line_match:
                        try:
                            line_dt = datetime.strptime(line_match.group(1), "%Y %b %d %H:%M:%S.%f")
                            if line_dt <= cutoff_dt:
                                continue
                        except ValueError:
                            continue

                # Check for count messages
                count_match = re.search(count_pattern, line)
                if count_match:
                    timestamp = count_match.group(1)
                    route_count = int(count_match.group(2))

                    # Record first new message after baseline
                    if first_new_timestamp is None and route_count > baseline_count:
                        first_new_timestamp = timestamp
                        print(f"Found first new message: {route_count} routes at {timestamp}")

                    # Update if this count meets target and is the latest
                    if route_count >= baseline_count + target_routes and route_count >= last_qualifying_count:
                        last_qualifying_timestamp = timestamp
                        last_qualifying_count = route_count
                        print(f"Found qualifying message: {route_count} routes at {timestamp}")

            # Calculate time difference if both timestamps found
            if first_new_timestamp and last_qualifying_timestamp:
                try:
                    first_dt = datetime.strptime(first_new_timestamp, "%Y %b %d %H:%M:%S.%f")
                    last_dt = datetime.strptime(last_qualifying_timestamp, "%Y %b %d %H:%M:%S.%f")

                    time_diff = (last_dt - first_dt).total_seconds()
                    actual_new_routes = last_qualifying_count - baseline_count

                    print(f"✓ {feature} timing: {time_diff:.3f}s for {actual_new_routes} new routes")
                    return (first_new_timestamp, last_qualifying_timestamp, time_diff)

                except ValueError as e:
                    print(f"Error parsing timestamps: {e}")
                    return None
            else:
                if not first_new_timestamp:
                    print(f"Warning: Could not find new RouteCounter messages after baseline ({baseline_count} routes)")
                if not last_qualifying_timestamp:
                    expected_total = baseline_count + target_routes
                    print(f"Warning: Could not find message with >= {expected_total} total routes")
                return None

        except Exception as e:
            print(f"Error parsing syslog: {e}")
            return None

    def clear_injected_routes(self):
        """Clear the routes that were injected during this test run"""
        print("Clearing injected test routes...")

        # Use the first IP from the base prefix that was actually programmed
        ip_parts = self.base_ip.split('.')
        ip_parts[-1] = '1'
        start_ip = '.'.join(ip_parts)

        # Clear SHARP routes using the actual prefix and count
        cmd = f"vtysh -c 'sharp remove routes {start_ip} {self.num_routes}'"
        self.run_command(cmd, "bgp")

        # Clear nexthop group
        self.run_command("vtysh -c 'configure terminal' -c 'no nexthop-group nhg1'")

        # Wait for cleanup
        time.sleep(2)

    def wait_for_bgp_ready(self, timeout: int = 60) -> bool:
        """Wait for BGP/SHARP to be ready by checking if sharpd daemon is running"""
        print("Waiting for BGP/SHARP to be ready...")
        start_time = time.time()

        while time.time() - start_time < timeout:
            # Check if sharpd process is running in the BGP container
            cmd = "ps aux | grep sharpd | grep -v grep"
            result = self.run_command(cmd, "bgp")

            if result and "sharpd" in result:
                # sharpd is running, wait a bit for it to fully initialize
                print("  sharpd is running, waiting for initialization...")
                time.sleep(5)
                print(f"BGP/SHARP is ready (took {time.time() - start_time:.1f}s)")
                return True

            print(f"  sharpd daemon not running yet (elapsed: {time.time() - start_time:.1f}s)")
            time.sleep(5)

        print(f"WARNING: BGP/SHARP not ready after {timeout}s")
        return False

    def generate_nexthop_group(self) -> str:
        """Generate nexthop group and return group name"""
        print("Generating nexthop group...")
        start_nh = ipaddress.ip_address(self.nexthop)
        nh_list = ["-c 'nexthop " + str(start_nh + i) + "'" for i in range(self.num_hops)]
        nh_group_name = "nhg1"
        cmd = f"vtysh -c 'configure terminal' -c 'nexthop-group {nh_group_name}' {' '.join(nh_list)}"
        self.run_command(cmd)
        return nh_group_name

    def inject_routes_with_sharp(self) -> float:
        """Inject routes using SHARP and return time taken"""
        print(f"Injecting {self.num_routes} routes using SHARP...")

        # Check if SHARP is available
        print("Checking if SHARP daemon is available...")
        check_cmd = "pgrep sharpd"
        sharp_check = self.run_command(check_cmd, "bgp")

        if not sharp_check or "sharpd" not in sharp_check:
            error_msg = (
                "ERROR: SHARP daemon (sharpd) is not running in the BGP container.\n"
                "SHARP is required for route injection in this benchmark.\n"
                "Please ensure FRR is compiled with SHARP support and sharpd is enabled.\n"
                "To enable SHARP:\n"
                "  1. Check if sharpd is available: docker exec bgp which sharpd\n"
                "  2. Enable it in BGP container's supervisord.conf\n"
                "  3. If not available, FRR needs to be rebuilt with --enable-sharpd"
            )
            print(error_msg)
            sys.exit(1)

        print("  SHARP daemon is available")

        # Wait for BGP/SHARP to be ready (important after container restarts)
        if not self.wait_for_bgp_ready():
            print("ERROR: BGP/SHARP not ready, route injection may fail")
            sys.exit(1)

        # Use the first IP from the provided prefix
        ip_parts = self.base_ip.split('.')
        ip_parts[-1] = '1'  # Start from .1
        start_ip = '.'.join(ip_parts)

        start_time = time.time()

        # Inject routes using SHARP with correct syntax
        nh_group_name = self.generate_nexthop_group()
        cmd = f"vtysh -c 'sharp install routes {start_ip} nexthop-group {nh_group_name} {self.num_routes}'"
        result = self.run_command(cmd, "bgp")

        injection_time = time.time() - start_time
        print(f"Route injection completed in {injection_time:.3f} seconds")

        if result:
            print(f"SHARP output: {result}")

        return injection_time

    def wait_for_routes_in_stage(
        self, stage_name: str, is_vs: bool, target_stats: RouteStatistics, baseline: RouteStatistics, timeout: int = 120
    ) -> float:
        """Wait for routes to appear in a specific stage and return time taken"""
        print(f"Waiting for {stage_name}...")

        start_time = time.time()
        previous = baseline
        current = baseline
        last_update_time = start_time

        while time.time() - start_time < timeout:
            current = RouteStatistics(
                frr_sharp=self.get_frr_sharp_route_count(),
                frr_fib=self.get_frr_fib_route_count(),
                appl_db=self.get_redis_route_count("APPL_DB"),
                asic_db=self.get_redis_route_count("ASIC_DB"),
                hardware=0 if is_vs else self.get_hardware_route_count(),
            )

            current_time = time.time()
            if current.reached_target(target_stats, stage_name):
                elapsed = current_time - start_time
                print(f"✓ Finished reaching target for {stage_name} in {elapsed:.3f}s")
                return elapsed

            # Update progress every 2 seconds or when percentage change is at least 1%
            if (current_time - last_update_time > 2) or (current.percentage_change(previous, stage_name) > 1):
                elapsed = current_time - start_time
                print(f"● Progress for {stage_name}, {elapsed:.3f}s elapsed:")
                current.print_with_target(target_stats)
                previous = current
                last_update_time = current_time

            time.sleep(0.5)

        elapsed = time.time() - start_time
        print(f"✗ Timeout: Failed to reach target {stage_name} after {elapsed:.3f}s")
        return elapsed

    def run_benchmark(self) -> BenchmarkResults:
        """Run the complete benchmark and return results"""
        print("\nStarting Route Programming Benchmark")
        print(f"Target routes: {self.num_routes}")
        print(f"Prefix: {self.prefix}")
        print(f"Nexthop: {self.nexthop}")
        print(f"Platform: {'Virtual Switch' if self.is_vs else 'Hardware'}")
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        # Check if we need sudo for syslog access
        if not self.is_root():
            print("Note: Running as non-root user. Will use sudo for syslog access if needed.")

        # Check ZMQ configuration
        zmq_enabled = self.check_zmq_enabled()
        print(f"ZMQ Route Programming: {'Enabled' if zmq_enabled else 'Disabled'}")

        # Clear existing injected routes incase they were left over from last run
        self.clear_injected_routes()

        # Get baseline counts
        initial_stats = RouteStatistics(
            frr_sharp=self.get_frr_sharp_route_count(),
            frr_fib=self.get_frr_fib_route_count(),
            appl_db=self.get_redis_route_count("APPL_DB"),
            asic_db=self.get_redis_route_count("ASIC_DB"),
            hardware=self.get_hardware_route_count(),
        )
        print("\nBaseline counts:")
        initial_stats.print()

        # Parse syslog for fpmsyncd timing after routes are in hardware
        # Default patterns for fpmsyncd RouteCounter messages
        # Looks for messages like:
        # Example: bgp#fpmsyncd: :- ~RouteCounter: Processed 10000 RTM_NEWROUTE messages
        fpmsyncd_count_pattern = (r"(\d{4} \w+ \d+ \d{2}:\d{2}:\d{2}\.\d+) .* bgp#fpmsyncd: :- ~RouteCounter: "
                                  r"Processed (\d+) RTM_NEWROUTE messages")
        fpmsyncd_baseline_info = self.get_last_routecounter_timestamp(fpmsyncd_count_pattern)
        if fpmsyncd_baseline_info:
            baseline_timestamp, baseline_count = fpmsyncd_baseline_info
            print(f"Baseline fpmsyncd: {baseline_count} routes at {baseline_timestamp}")

        # Example: swss#orchagent: :- flush_creating_entries: RouteOrch: 110000 routes added to SAI (bulk)
        orchagent_count_pattern = (r"(\d{4} \w+ \d+ \d{2}:\d{2}:\d{2}\.\d+) .* swss#orchagent: :- "
                                   r"flush_creating_entries: RouteOrch: (\d+)")
        orchagent_baseline_info = self.get_last_routecounter_timestamp(orchagent_count_pattern)
        if orchagent_baseline_info:
            baseline_timestamp, baseline_count = orchagent_baseline_info
            print(f"Baseline orchagent: {baseline_count} routes at {baseline_timestamp}")

        # Start benchmark
        total_start_time = time.time()
        dt_object = datetime.fromtimestamp(total_start_time)
        pretty_start_time = dt_object.strftime("%Y-%m-%d %H:%M:%S.%f")

        # Inject routes with SHARP (Zebra receives them)
        injection_time = self.inject_routes_with_sharp()
        print(f"Route injection time: {injection_time:.3f}s")

        # Wait for routes in FRR
        target_stats = RouteStatistics(
            frr_sharp=initial_stats["FRR SHARP"] + self.num_routes,
            frr_fib=initial_stats["FRR FIB"] + self.num_routes,
            appl_db=initial_stats["APPL_DB"] + self.num_routes,
            asic_db=initial_stats["APPL_DB"] + self.num_routes,
            hardware=initial_stats["Hardware"] if self.is_vs else initial_stats["Hardware"] + self.num_routes,
        )

        # Dynamic timeout based on route count: ~1500 routes/sec observed throughput
        # with 120s minimum for small route counts
        hw_timeout = max(120, self.num_routes // 1500)

        # Wait for routes in Hardware (using bcmcmd)
        # This measures routes actually programmed and available for forwarding
        asic_to_hw_time = self.wait_for_routes_in_stage(
            "Hardware", self.is_vs, target_stats, initial_stats, timeout=hw_timeout
        )

        total_time = time.time() - total_start_time

        feature = "fpmsyncd RouteCounter"
        cnt = 30
        fpmsyncd_timing = None
        while not fpmsyncd_timing and cnt > 0:
            fpmsyncd_timing = self.parse_syslog_timing(self.num_routes, fpmsyncd_count_pattern, feature,
                                                       fpmsyncd_baseline_info)
            if not fpmsyncd_timing:
                cnt -= 1
                if cnt:
                    time.sleep(1)
            else:
                break

        # Parse syslog for Orchagent timing
        orchagent_timing = None
        feature = "orchagent RouteCounter"
        cnt = 30
        orchagent_timing = None
        while not orchagent_timing and cnt > 0:
            orchagent_timing = self.parse_syslog_timing(self.num_routes, orchagent_count_pattern, feature,
                                                        orchagent_baseline_info)
            if not orchagent_timing:
                cnt -= 1
                if cnt:
                    time.sleep(1)
            else:
                break

        # Clean up test routes
        print("\nCleaning up test routes...")
        self.clear_injected_routes()

        return BenchmarkResults(
            total_routes=self.num_routes,
            pretty_start_time=pretty_start_time,
            asic_db_to_hardware_time=asic_to_hw_time,
            total_time=total_time,
            fpmsyncd_timing=fpmsyncd_timing,
            orchagent_timing=orchagent_timing,
        )


def main():
    parser = argparse.ArgumentParser(description="Benchmark route programming performance in SONiC")
    parser.add_argument("--routes", type=int, default=30000, help="Number of routes to inject (default: 30000)")
    parser.add_argument("--prefix", type=str, default="192.168.0.0/16", help="Base prefix for route generation")
    parser.add_argument("--num-hops", type=int, default=1, help="Number of hops in the route")
    parser.add_argument("--nexthop", type=str, default="10.0.0.1", help="Nexthop IP address")

    args = parser.parse_args()

    # Validate arguments
    if args.routes <= 0:
        print("Error: Number of routes must be positive")
        sys.exit(1)

    try:
        benchmark = RouteProgrammingBenchmark(args.routes, args.prefix, args.num_hops, args.nexthop)
        results = benchmark.run_benchmark()
        results.print_results()

        # Save results to file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"route_benchmark_{timestamp}.json"

        with open(filename, "w") as f:
            json.dump(
                {
                    "timestamp": timestamp,
                    "total_routes": results.total_routes,
                    "asic_db_to_hardware_time": results.asic_db_to_hardware_time,
                    "total_time": results.total_time,
                    "fpmsyncd_timing": results.fpmsyncd_timing,
                    "orchagent_timing": results.orchagent_timing,
                },
                f,
                indent=2,
            )

        print(f"\nResults saved to: {filename}")

    except KeyboardInterrupt:
        print("\nBenchmark interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error running benchmark: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
