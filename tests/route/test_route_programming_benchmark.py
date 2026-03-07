"""
Route Programming Performance Benchmark Test

This test measures route programming performance through the SONiC pipeline
and supports YAML-based performance policies for optimization.

Usage:
  # Basic test (default: 100,000 routes)
  pytest tests/route/test_route_programming_benchmark.py::test_route_programming_performance -v

  # Custom route scale
  pytest --route_scale 50000 tests/route/test_route_programming_benchmark.py::test_route_programming_performance -v

  # Using performance policies
  pytest --perf_policy "northbound_zmq" \\
         tests/route/test_route_programming_benchmark.py::test_route_programming_performance -v
  # Use custom policy (create your_policy.yaml in tests/route/policies/ first)
  pytest --perf_policy "your_policy" \\
         tests/route/test_route_programming_benchmark.py::test_route_programming_performance -v

Available policies: non_zmq_optimized, northbound_zmq
Policy files are located in tests/route/policies/
To see available policies: ls tests/route/policies/

Custom Policy Creation:
  1. Create your policy file: tests/route/policies/my_custom_policy.yaml
  2. Use it by name: --perf_policy "my_custom_policy"

Metrics Output:
  The test outputs structured metrics in JSON format that can be consumed by external tools
  for publishing to monitoring systems.

  Schema:
    Measurement: route_benchmark_metrics
    Tags: dut, route_count, branch (auto-detected), policy (optional)
    Fields: total_time, hardware_time, fpmsyncd_time (optional), orchagent_time (optional)

  Note: The branch tag is automatically detected from the DUT's SONiC build version
        (e.g., "master.487-a98cf221", "202505.123-e0c38ec4d") for tracking performance
        across different builds and branches.
"""

import json
import logging
import os
import pytest
import time
import yaml
from dataclasses import dataclass
from typing import Dict, List, Optional, Any
from tests.common.config_reload import config_reload
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

pytestmark = [
    pytest.mark.topology("t0", "t1", "any"),
]

# Default test parameters
DEFAULT_ROUTE_COUNT = 100000
DEFAULT_PREFIX = "192.168.0.0/16"
DEFAULT_NEXTHOP = "10.0.0.1"


def get_bgp_neighbors_from_config_facts(duthost, config_facts, vrf_name="default"):
    nbrs_in_cfg_facts = config_facts.get('BGP_NEIGHBOR', {})
    bgp_neighbors = {}
    # When FRR management framework is enabled,
    # there's an additional level of nesting with vrf name as the key
    if duthost.get_frr_mgmt_framework_config() and vrf_name in nbrs_in_cfg_facts:
        bgp_neighbors = nbrs_in_cfg_facts[vrf_name]
    else:
        bgp_neighbors = nbrs_in_cfg_facts

    return bgp_neighbors


def build_metric_tags(dut_name, route_count, knob_config=None, extra_tags=None, branch_name=None):
    """
    Build base tags for metrics including DUT, route count, branch, policy, and knob settings.

    Args:
        dut_name: Name of the DUT
        route_count: Number of routes in the test
        knob_config: Optional policy configuration with knob settings
        extra_tags: Optional additional tags to include
        branch_name: Optional SONiC build version/branch name

    Returns:
        Dictionary of tags to be used for metrics
    """
    base_tags = {"dut": dut_name, "route_count": str(route_count)}

    # Add branch name if provided
    if branch_name:
        base_tags["branch"] = branch_name
        logger.info(f"Branch: {branch_name}")

    # Add policy information if available
    if knob_config and knob_config.get("policy_applied"):
        policy_info = knob_config["policy_applied"]
        base_tags["policy"] = policy_info["name"]
        logger.info(f"Policy: {policy_info['name']}")

        # Extract individual knob settings from the nested config structure
        # Config structure: {table_name: {key: {field: value}}}
        if "config" in policy_info:
            for table_name, table_config in policy_info["config"].items():
                for key, key_config in table_config.items():
                    for field_name, field_value in key_config.items():
                        # Add each knob setting as a tag
                        base_tags[field_name] = str(field_value)
                        logger.info(f"Added knob tag: {field_name}={field_value}")

    # Add extra tags if provided
    if extra_tags:
        base_tags.update(extra_tags)

    return base_tags


@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exceptions(duthost, loganalyzer):
    """
    Ignore expected failures logs during test execution.

    Route programming tests can trigger various expected errors,
    especially during config reload and container restarts.

    Args:
        duthost: DUT host object
        loganalyzer: Loganalyzer utility fixture
    """
    if loganalyzer:
        ignoreRegex = [
            # Syncd plugin registration errors
            r".* ERR syncd\d*#syncd: :- addPlugins: Plugin .* already registered",

            # DHCP DOS logger errors for missing interfaces
            r".* ERR dhcp_dos_logger.py: TC command failed for Ethernet\d+: Cannot find device \"Ethernet\d+\"",

            # Orchagent timeout errors during heavy route programming
            r".* ERR swss\d*#orchagent: :- wait: SELECT operation result: TIMEOUT on .*",
            r".* ERR swss\d*#orchagent: :- wait: failed to get response for .*",

            # Priority group initialization errors for virtual interfaces
            r".* ERR swss\d*#orchagent: :- initializePriorityGroups: Failed to get number of priority groups "
            r"for port .* rv:-1",

            # Common config reload related errors
            r".* ERR swss\d*#orchagent: :- getPort: Failed to get cached bridge port ID.*",

            # Route already exists errors - race condition during bulk route programming
            # These can be ignored as the focus of this test is to just measure route programming rate
            # and not do any scale route correctness testing.
            r".* ERR swss\d*#orchagent: :- meta_sai_validate_route_entry: object key "
            r"SAI_OBJECT_TYPE_ROUTE_ENTRY:.*already exists",
            r".* ERR swss\d*#orchagent: :- meta_generic_validation_create: object key "
            r"SAI_OBJECT_TYPE_ROUTE_ENTRY:.*already exists",
            r".* ERR syncd\d*#syncd:.*SAI_API_ROUTE:_brcm_sai_l3_route_config:\d+ L3 route add failed with error "
            r"Entry exists.*",
            r".* ERR syncd\d*#syncd:.*SAI_API_ROUTE:brcm_sai_xgs_route_create:\d+ L3 route add failed with error -6\.?",
            r".* ERR syncd\d*#syncd:.*SAI_API_ROUTE:_?brcm_sai_create_route_entry:\d+ pd route create failed "
            r"failed with error -6\.?",
            r".* ERR syncd\d*#syncd: :- sendApiResponse: api SAI_COMMON_API_BULK_CREATE failed in syncd mode: "
            r"SAI_STATUS_FAILURE",
            r".* ERR swss\d*#orchagent: :- flush_creating_entries: EntityBulker.flush create entries failed, "
            r"number of entries to create: \d+, status: SAI_STATUS_FAILURE",
            r".* ERR swss\d*#orchagent: :- addRoutePost: Failed to create route .* with next hop\(s\) .*",
            r".* ERR swss\d*#orchagent: :- flush_creating_entries: EntityBulker.flush create entries failed, "
            r"number of entries to create: \d+, status: SAI_STATUS_ITEM_ALREADY_EXISTS",
            r".* ERR swss\d*#orchagent: :- handleSaiFailure: Encountered failure in create operation, "
            r"SAI API: SAI_API_ROUTE, status: SAI_STATUS_NOT_EXECUTED",
        ]
        loganalyzer[duthost.hostname].ignore_regex.extend(ignoreRegex)

    yield


@dataclass
class PerformancePolicy:
    """Represents a performance policy loaded from YAML"""
    name: str
    description: str
    config: Dict[str, Any]
    containers_to_restart: List[str]

    @classmethod
    def from_yaml_file(cls, file_path: str) -> 'PerformancePolicy':
        """Load policy from YAML file"""
        with open(file_path, 'r') as f:
            data = yaml.safe_load(f)

        return cls(
            name=data['name'],
            description=data['description'],
            config=data['config'],
            containers_to_restart=data['containers_to_restart']
        )


class PolicyManager:
    """Manages performance policies"""

    def __init__(self, policy_dir: Optional[str] = None):
        if policy_dir is None:
            # Default to policies directory relative to this file
            current_dir = os.path.dirname(os.path.abspath(__file__))
            self.policy_dir = os.path.join(current_dir, "policies")
        else:
            self.policy_dir = policy_dir

    def list_available_policies(self) -> List[str]:
        """List all available policy names"""
        if not os.path.exists(self.policy_dir):
            return []

        policies = []
        for filename in os.listdir(self.policy_dir):
            if filename.endswith('.yaml') or filename.endswith('.yml'):
                policy_name = os.path.splitext(filename)[0]
                policies.append(policy_name)

        return sorted(policies)

    def load_policy(self, policy_name: str) -> PerformancePolicy:
        """
        Load a policy by name from the policies directory

        Args:
            policy_name: Policy name (e.g., 'basic_performance', 'my_custom_policy')

        Returns:
            PerformancePolicy object
        """
        # Check if it's a policy name in the policies directory
        policy_file = os.path.join(self.policy_dir, f"{policy_name}.yaml")
        if os.path.exists(policy_file):
            return PerformancePolicy.from_yaml_file(policy_file)

        # Try .yml extension
        policy_file = os.path.join(self.policy_dir, f"{policy_name}.yml")
        if os.path.exists(policy_file):
            return PerformancePolicy.from_yaml_file(policy_file)

        available = self.list_available_policies()
        raise FileNotFoundError(f"Policy '{policy_name}' not found. Available policies: {available}")

    def validate_policy(self, policy: PerformancePolicy) -> List[str]:
        """
        Validate a policy and return list of warnings/errors

        Returns:
            List of validation messages (empty if valid)
        """
        issues = []

        # Check required fields
        if not policy.name:
            issues.append("Policy name is required")

        if not policy.config:
            issues.append("Policy config is required")

        if not policy.containers_to_restart:
            issues.append("At least one container to restart should be specified")

        # Validate config structure
        if 'DEVICE_METADATA' not in policy.config:
            issues.append("Policy config must contain DEVICE_METADATA section")
        elif 'localhost' not in policy.config['DEVICE_METADATA']:
            issues.append("Policy config DEVICE_METADATA must contain localhost section")

        # Check for conflicting configurations
        device_config = policy.config.get('DEVICE_METADATA', {}).get('localhost', {})

        # ZMQ conflicts
        zmq_enabled = device_config.get('orch_northbond_route_zmq_enabled') == 'true'
        flush_pub_enabled = device_config.get('producerstate_flush_pub_enabled') == 'true'

        if zmq_enabled and flush_pub_enabled:
            issues.append("ZMQ and flushPub cannot be enabled simultaneously")

        # ZMQ dependency checks
        zmq_db_persistence_disabled = device_config.get('zmq_db_persistence_enabled') == 'false'
        if zmq_db_persistence_disabled and not zmq_enabled:
            issues.append("zmq_db_persistence_enabled=false requires orch_northbond_route_zmq_enabled=true")

        return issues


class PerformanceKnobManager:
    """Manages performance optimization knobs for route programming benchmarks"""

    def __init__(self, duthost):
        self.duthost = duthost
        self.policy_manager = PolicyManager()
        self.applied_policy: Optional[PerformancePolicy] = None

    def _restart_container(self, container_name: str) -> None:
        """Restart a specific container"""
        logger.info(f"Restarting {container_name} service...")
        restart_result = self.duthost.shell(f"sudo systemctl restart {container_name}", module_ignore_errors=True)
        if restart_result["rc"] != 0:
            error_msg = restart_result.get('stderr', 'Unknown error')
            raise RuntimeError(f"Failed to restart {container_name} service: {error_msg}")
        logger.info(f"Successfully restarted {container_name} service")

    def _wait_for_containers_ready(self, containers: List[str], timeout: int = 120) -> None:
        """Wait for containers to be ready using systemctl is-active"""
        logger.info(f"Waiting for services to be active: {containers}")
        start_time = time.time()

        while time.time() - start_time < timeout:
            all_ready = True
            for container in containers:
                # Check if service is active using systemctl
                result = self.duthost.shell(f"systemctl is-active {container}", module_ignore_errors=True)
                if result["rc"] != 0 or result.get("stdout", "").strip() != "active":
                    all_ready = False
                    logger.debug(f"Service {container} not active yet: {result.get('stdout', 'unknown')}")
                    break
                else:
                    logger.debug(f"Service {container} is active")

            if all_ready:
                logger.info("All services are active and ready")
                return
            time.sleep(5)

        raise RuntimeError(f"Services not ready after {timeout} seconds: {containers}")

    def _wait_for_bgp_sessions(self, timeout: int = 300) -> None:
        """
        Wait for BGP sessions to be established after container restart

        Args:
            timeout: Maximum time to wait in seconds (default: 300)
        """
        logger.info(f"Waiting for BGP sessions to be established (timeout: {timeout}s)...")

        # Get all BGP neighbors from config
        config_facts = self.duthost.config_facts(host=self.duthost.hostname, source="running")['ansible_facts']
        bgp_neighbors = get_bgp_neighbors_from_config_facts(self.duthost, config_facts)

        if not bgp_neighbors:
            logger.warning("No BGP neighbors found in config")
            return

        # Use the standard wait_until helper with check_bgp_session_state
        if not wait_until(timeout, 10, 0, self.duthost.check_bgp_session_state, bgp_neighbors):
            raise RuntimeError(f"BGP sessions not established after {timeout} seconds")

        logger.info("All BGP sessions established")

    def apply_policy(self, policy_name: str) -> Dict[str, Any]:
        """
        Apply a performance policy from YAML file

        Args:
            policy_name: Policy name (e.g., 'basic_performance', 'my_custom_policy')

        Returns:
            Dictionary with policy application results
        """
        logger.info(f"Loading performance policy: {policy_name}")

        # Load the policy
        try:
            policy = self.policy_manager.load_policy(policy_name)
        except FileNotFoundError as e:
            available_policies = self.policy_manager.list_available_policies()
            raise ValueError(f"Policy not found: {e}. Available policies: {available_policies}")

        # Validate the policy
        validation_issues = self.policy_manager.validate_policy(policy)
        if validation_issues:
            raise ValueError(f"Policy validation failed: {validation_issues}")

        logger.info(f"Applying policy '{policy.name}': {policy.description}")

        # Apply the policy configuration
        containers_to_restart = set()
        applied_config = {}

        for table_name, table_config in policy.config.items():
            for key, key_config in table_config.items():
                config_key = f"{table_name}|{key}"

                # Store what we're applying for results
                if table_name not in applied_config:
                    applied_config[table_name] = {}
                applied_config[table_name][key] = key_config

                # Apply each configuration value
                for config_field, config_value in key_config.items():
                    cmd = f"sonic-db-cli CONFIG_DB hset '{config_key}' {config_field} {config_value}"
                    result = self.duthost.shell(cmd)

                    if result["rc"] != 0:
                        error_msg = result.get('stderr', 'Unknown error')
                        raise RuntimeError(f"Failed to apply policy config {config_field}={config_value}: {error_msg}")

                    logger.info(f"Applied: {config_key} {config_field}={config_value}")

        # Track containers that need restart
        containers_to_restart.update(policy.containers_to_restart)

        # Restart required containers
        containers_restarted = []
        if containers_to_restart:
            logger.info(f"Restarting containers: {list(containers_to_restart)}")
            for container in containers_to_restart:
                self._restart_container(container)
                containers_restarted.append(container)

            # Wait for containers to be ready
            self._wait_for_containers_ready(containers_restarted)
            logger.info("Containers restarted and ready.")

            # If BGP container was restarted, wait for BGP sessions to be established
            if "bgp" in containers_restarted:
                self._wait_for_bgp_sessions(timeout=300)

        # Verify policy was applied
        self._verify_policy_applied(policy)

        # Store the applied policy
        self.applied_policy = policy

        return {
            "policy_applied": {
                "name": policy.name,
                "description": policy.description,
                "config": applied_config
            },
            "containers_restarted": containers_restarted
        }

    def _verify_policy_applied(self, policy: PerformancePolicy) -> None:
        """Verify that policy was applied correctly"""
        logger.info("Verifying policy was applied correctly...")

        for table_name, table_config in policy.config.items():
            for key, key_config in table_config.items():
                config_key = f"{table_name}|{key}"

                for config_field, expected_value in key_config.items():
                    cmd = f"sonic-db-cli CONFIG_DB hget '{config_key}' {config_field}"
                    result = self.duthost.shell(cmd)

                    if result["rc"] != 0:
                        error_msg = result.get('stderr', 'Unknown error')
                        logger.warning(f"Could not verify {config_key} {config_field}: {error_msg}")
                    else:
                        actual_value = result["stdout"].strip()

                        if actual_value == str(expected_value):
                            logger.info(f"Policy config verified: {config_key} {config_field}={actual_value}")
                        else:
                            logger.warning(
                                f"Policy config mismatch: {config_key} {config_field} - "
                                f"expected: {expected_value}, actual: {actual_value}"
                            )


def output_structured_metrics(
    dut_name, route_count, benchmark_results, extra_tags=None, knob_config=None, branch_name=None
):
    """Output structured metrics in JSON format for external consumption"""
    logger.info(f"Outputting structured metrics for {route_count} routes...")

    # Build base tags using helper function
    base_tags = build_metric_tags(
        dut_name, route_count, knob_config, extra_tags, branch_name=branch_name
    )

    metrics = []

    # Total time metric
    if benchmark_results.get("total_time"):
        total_tags = base_tags.copy()
        total_tags["stage"] = "total"
        metrics.append(
            {
                "tags": total_tags,
                "fields": {"time": benchmark_results["total_time"]},
            }
        )
        logger.info(f"Added total time metric: {benchmark_results['total_time']}s")

    # ASIC DB to Hardware programming time (syncd)
    if benchmark_results.get("asic_db_to_hardware_time"):
        hardware_tags = base_tags.copy()
        hardware_tags["stage"] = "hardware"
        metrics.append(
            {
                "tags": hardware_tags,
                "fields": {"time": benchmark_results["asic_db_to_hardware_time"]},
            }
        )
        logger.info(f"Added hardware time metric: {benchmark_results['asic_db_to_hardware_time']}s")

    # FPMsyncd timing
    if benchmark_results.get("fpmsyncd_timing") and len(benchmark_results["fpmsyncd_timing"]) >= 3:
        fpmsyncd_time = benchmark_results["fpmsyncd_timing"][2]  # time_diff
        fpmsyncd_tags = base_tags.copy()
        fpmsyncd_tags["stage"] = "fpmsyncd"
        metrics.append(
            {
                "tags": fpmsyncd_tags,
                "fields": {"time": fpmsyncd_time},
            }
        )
        logger.info(f"Added fpmsyncd time metric: {fpmsyncd_time}s")

    # Orchagent timing
    if benchmark_results.get("orchagent_timing") and len(benchmark_results["orchagent_timing"]) >= 3:
        orchagent_time = benchmark_results["orchagent_timing"][2]  # time_diff
        orchagent_tags = base_tags.copy()
        orchagent_tags["stage"] = "orchagent"
        metrics.append(
            {
                "tags": orchagent_tags,
                "fields": {"time": orchagent_time},
            }
        )
        logger.info(f"Added orchagent time metric: {orchagent_time}s")

    # Output metrics in a structured format that can be parsed by external tools
    metrics_output = {"metrics": metrics, "raw_results": benchmark_results}

    # Add policy configuration details if provided
    if knob_config:
        metrics_output["policy_configuration"] = knob_config

    # Output as JSON with a special marker for easy parsing
    logger.info("=== ROUTE_METRICS_START ===")
    logger.info(json.dumps(metrics_output, indent=2))
    logger.info("=== ROUTE_METRICS_END ===")

    # Also print to stdout for external parsing
    print("=== ROUTE_METRICS_START ===")
    print(json.dumps(metrics_output, indent=2))
    print("=== ROUTE_METRICS_END ===")

    logger.info(f"Successfully output {len(metrics)} structured metrics for {route_count} routes")


def publish_metrics(
    dut_name, route_count, benchmark_results, extra_tags=None, knob_config=None, branch_name=None
):
    """Output structured route programming metrics"""

    logger.info(f"Publishing metrics for DUT: {dut_name}, Routes: {route_count}")
    output_structured_metrics(
        dut_name, route_count, benchmark_results, extra_tags, knob_config, branch_name=branch_name
    )


@pytest.fixture(scope="function", autouse=True)
def restore_dut(duthosts, enum_rand_one_per_hwsku_frontend_hostname, request):
    """Restore DUT configuration after test to clean up routes"""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    yield
    if request.node.rep_call.failed:
        # Issue a config_reload to clear statically added route table
        logging.info("Restoring config after test failure...")
        config_reload(duthost)


def cleanup_old_benchmark_files(duthost):
    """Clean up any old benchmark result files from previous test runs"""
    logger.info("Cleaning up old benchmark result files...")

    # Clean up files in both /home/admin and /tmp directories
    for directory in ["/home/admin", "/tmp"]:
        cleanup_result = duthost.shell(f"rm -f {directory}/route_benchmark_*.json", module_ignore_errors=True)
        if cleanup_result["rc"] == 0:
            if cleanup_result.get("stdout"):
                logger.info(f"Cleaned up old files in {directory}")
        else:
            logger.debug(f"No old files to clean up in {directory} (or cleanup failed)")


def run_benchmark_script(duthost, route_count, prefix=DEFAULT_PREFIX, nexthop=DEFAULT_NEXTHOP):
    """
    Run the route programming benchmark script on the DUT

    Args:
        duthost: DUT host object
        route_count: Number of routes to program
        prefix: Base prefix for route generation
        nexthop: Nexthop IP address

    Returns:
        dict: Benchmark results
    """
    # Clean up any old benchmark files first
    cleanup_old_benchmark_files(duthost)

    # Copy the benchmark script to the DUT
    script_path = "/tmp/route_programming_benchmark.py"
    local_script = "scripts/route_programming_benchmark.py"

    # Copy script to DUT
    duthost.copy(src=local_script, dest=script_path)

    # Make script executable
    duthost.shell(f"chmod +x {script_path}")

    # Run the benchmark from the admin home directory to ensure results file is saved there
    cmd = f"cd /home/admin && python3 {script_path} --routes {route_count} --prefix {prefix} --nexthop {nexthop}"
    logger.info(f"Running benchmark: {cmd}")

    result = duthost.shell(cmd, module_ignore_errors=True)

    # Log the benchmark script output for debugging
    logger.info(f"Benchmark script stdout: {result.get('stdout', 'No stdout')}")
    if result.get("stderr"):
        logger.warning(f"Benchmark script stderr: {result['stderr']}")

    if result["rc"] != 0:
        pytest.fail(f"Benchmark script failed with rc={result['rc']}: {result.get('stderr', 'No stderr')}")

    # Parse the JSON output file
    # The script saves results to a timestamped JSON file in the current directory (/home/admin)
    # First, let's check if any benchmark files exist in /home/admin
    find_result = duthost.shell("find /home/admin -name 'route_benchmark_*.json' -type f")

    # Check if find command succeeded
    if find_result["rc"] != 0:
        pytest.fail(f"Find command failed with rc={find_result['rc']}: {find_result.get('stderr', 'No stderr')}")

    # Check if we found any files
    if not find_result["stdout"].strip():
        # Try looking in /tmp directory as fallback
        find_result_tmp = duthost.shell("find /tmp -name 'route_benchmark_*.json' -type f")

        if find_result_tmp["rc"] == 0 and find_result_tmp["stdout"].strip():
            find_result = find_result_tmp
        else:
            # Debug: List all files in both directories to see what's there
            admin_files = duthost.shell(
                "ls -la /home/admin/route_benchmark_*.json 2>/dev/null || echo 'No files found in /home/admin'"
            )
            tmp_files = duthost.shell("ls -la /tmp/route_benchmark_*.json 2>/dev/null || echo 'No files found in /tmp'")
            logger.error(f"Debug - Admin directory: {admin_files.get('stdout', 'No output')}")
            logger.error(f"Debug - Tmp directory: {tmp_files.get('stdout', 'No output')}")

            # Also check what files were actually created
            all_admin_files = duthost.shell("ls -la /home/admin/")
            all_tmp_files = duthost.shell("ls -la /tmp/ | grep route")
            logger.error(f"All admin files: {all_admin_files.get('stdout', 'No output')}")
            logger.error(f"All tmp route files: {all_tmp_files.get('stdout', 'No output')}")

            pytest.fail("Could not find benchmark results file")

    # Get the most recent file (if multiple exist)
    files = [f.strip() for f in find_result["stdout"].strip().split("\n") if f.strip()]
    if len(files) > 1:
        # Get the most recent file by modification time
        get_newest_result = duthost.shell("ls -t " + " ".join(files) + " | head -1")
        if get_newest_result["rc"] == 0 and get_newest_result["stdout"].strip():
            results_file = get_newest_result["stdout"].strip()
        else:
            results_file = files[0]  # fallback to first file
    else:
        results_file = files[0]

    logger.info(f"Reading results from: {results_file}")

    # Read the results file
    cat_result = duthost.shell(f"cat {results_file}")
    if cat_result["rc"] != 0:
        pytest.fail(f"Could not read results file: {cat_result.get('stderr', 'No stderr')}")

    try:
        results = json.loads(cat_result["stdout"])
        logger.info(f"Benchmark results: {json.dumps(results, indent=2)}")

        # Clean up the results file after successful parsing
        cleanup_result = duthost.shell(f"rm -f {results_file}")
        if cleanup_result["rc"] == 0:
            logger.info(f"Successfully cleaned up results file: {results_file}")
        else:
            logger.warning(
                f"Failed to clean up results file {results_file}: {cleanup_result.get('stderr', 'No stderr')}"
            )

        return results
    except json.JSONDecodeError as e:
        logger.error(f"Raw results file content: {cat_result['stdout']}")
        pytest.fail(f"Could not parse benchmark results JSON: {e}")


def test_route_programming_performance(duthosts, enum_rand_one_per_hwsku_frontend_hostname, request):
    """Test route programming performance with configurable optimization policies"""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    dut_name = duthost.hostname

    # Get parameters from command line arguments
    route_scale = request.config.getoption("--route_scale")
    perf_policy_str = request.config.getoption("--perf_policy")

    # Auto-detect SONiC build version from DUT (includes branch, build number, and commit hash)
    try:
        branch_name = duthost.os_version
        # os_version will be like "master.487-a98cf221", "202505.123-e0c38ec4d", etc.
        logger.info(f"Auto-detected SONiC build version: {branch_name}")
    except Exception as e:
        logger.warning(f"Failed to detect SONiC build version: {e}, using 'unknown'")
        branch_name = "unknown"

    logger.info(f"Starting route programming benchmark for {route_scale} routes on {dut_name}")

    if perf_policy_str:
        logger.info(f"Performance policy requested: {perf_policy_str}")

    # Initialize policy manager
    policy_manager = PerformanceKnobManager(duthost)
    policy_config = None

    try:
        # Apply performance configuration
        if perf_policy_str:
            # Apply policy-based configuration
            logger.info(f"Applying performance policy: {perf_policy_str}")
            policy_config = policy_manager.apply_policy(perf_policy_str)
            policy_info = policy_config["policy_applied"]
            logger.info(f"Applied policy: {policy_info['name']} - {policy_info['description']}")
            logger.info(f"Restarted containers: {policy_config['containers_restarted']}")

        # Run the benchmark
        results = run_benchmark_script(duthost, route_scale)

        # Validate results
        pytest_assert(
            results.get("total_routes") == route_scale,
            f"Expected {route_scale} routes, got {results.get('total_routes')}"
        )

        pytest_assert(
            results.get("total_time") is not None and results.get("total_time") > 0, "Total time should be positive"
        )

        # Log key metrics
        logger.info("Route programming completed:")
        logger.info(f"  Routes: {results.get('total_routes', 'N/A')}")
        logger.info(f"  Total time: {results.get('total_time', 'N/A')}s")

        if results.get("asic_db_to_hardware_time"):
            logger.info(f"  ASIC DB → Hardware (syncd): {results['asic_db_to_hardware_time']}s")

        if results.get("fpmsyncd_timing") and len(results["fpmsyncd_timing"]) >= 3:
            logger.info(f"  FPMsyncd processing: {results['fpmsyncd_timing'][2]}s")

        if results.get("orchagent_timing") and len(results["orchagent_timing"]) >= 3:
            logger.info(f"  Orchagent processing: {results['orchagent_timing'][2]}s")

        # Log policy configuration if applied
        if policy_config and policy_config.get("policy_applied"):
            policy_info = policy_config["policy_applied"]
            logger.info(f"Performance policy applied: {policy_info['name']} - {policy_info['description']}")

        # Publish metrics with policy configuration and branch name
        publish_metrics(dut_name, route_scale, results, knob_config=policy_config, branch_name=branch_name)

        logger.info(f"Route programming benchmark completed successfully for {route_scale} routes")

    finally:
        # Always restore original configuration using config reload
        if policy_manager.applied_policy:
            logger.info("Restoring original configuration using config reload...")
            try:
                config_reload(duthost, safe_reload=True, check_intf_up_ports=True)
                logger.info("Configuration restored successfully via config reload")
            except Exception as e:
                logger.error(f"Config reload failed: {e}")
                logger.error("Manual intervention may be required to restore DUT state")
        else:
            logger.info("No policy configuration to restore")
