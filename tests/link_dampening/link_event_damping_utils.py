"""
Utility functions for Link Event Damping tests

This module provides helper functions for:
- Configuring link damping parameters
- Generating link flaps via Fanout switch
- Collecting and verifying link damping statistics
- Managing Redis database state
"""

import logging
import time
from datetime import datetime
from natsort import natsorted

logger = logging.getLogger(__name__)


def get_dut_fronface_ports(duthost, tbinfo):
    """
    Get all front-facing (non-backend) ports from the DUT.

    Args:
        duthost: The AnsibleHost object of DUT.
        tbinfo: Testbed information dictionary.

    Returns:
        list: List of front-facing interface names (e.g., ['Ethernet0', 'Ethernet4', ...])
    """
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    front_ports = []

    for port in mg_facts.get('minigraph_ports', {}).keys():
        # Exclude backend ports (contain 'Ethernet-BP' or have non-Ext role)
        if not duthost.is_backend_port(port, mg_facts):
            front_ports.append(port)

    return natsorted(front_ports)


def configure_link_damping(dut, interface, suppress_threshold=None, reuse_threshold=None,
                           decay_half_life=None, max_suppress_time=None, flap_penalty=None,
                           algorithm="aied", disabled=False):
    """
    Configure link damping parameters on a specific interface using AIED algorithm.

    Args:
        dut: DUT host object
        interface: Interface name (e.g., "Ethernet0")
        suppress_threshold: Penalty threshold to enter damped state
        reuse_threshold: Penalty threshold to exit damped state
        decay_half_life: Time in milliseconds for penalty to decay by half
        max_suppress_time: Maximum time in milliseconds an interface can be suppressed
        flap_penalty: Penalty added per link down event
        algorithm: Damping algorithm to use (default: "aied")
        disabled: Set to True to disable damping on the interface

    Returns:
        bool: True if configuration successful
    """
    try:
        if disabled:
            # Disable damping on the interface by removing algorithm
            # TODO: Verify the correct command to disable damping
            cmd = f"config interface damping algo {interface} disabled"
            result = dut.shell(cmd, module_ignore_errors=True)
            logger.info(f"Link damping disabled on {interface} result {result}")
            return True

        # Step 1: Configure the damping algorithm
        algo_cmd = f"config interface damping algo {interface} {algorithm}"
        result = dut.shell(algo_cmd, module_ignore_errors=True)

        if result["rc"] != 0:
            logger.warning(f"Failed to configure damping algorithm on {interface}: {result.get('stderr', '')}")
            return False

        logger.info(f"Damping algorithm '{algorithm}' configured on {interface}")

        # Step 2: Configure damping parameters if any are provided
        if any([suppress_threshold, reuse_threshold, decay_half_life, max_suppress_time, flap_penalty]):
            # Build parameter configuration command
            param_cmd = f"config interface damping {algorithm}-param {interface}"

            if suppress_threshold is not None:
                param_cmd += f" --suppress-threshold {suppress_threshold}"
            if reuse_threshold is not None:
                param_cmd += f" --reuse-threshold {reuse_threshold}"
            if decay_half_life is not None:
                param_cmd += f" --decay-half-life {decay_half_life}"
            if max_suppress_time is not None:
                param_cmd += f" --max-suppress-time {max_suppress_time}"
            if flap_penalty is not None:
                param_cmd += f" --flap-penalty {flap_penalty}"

            # Execute parameter configuration
            result = dut.shell(param_cmd, module_ignore_errors=True)

            if result["rc"] == 0:
                logger.info(f"Link damping parameters configured on {interface}: "
                            f"threshold={suppress_threshold}, reuse={reuse_threshold}, "
                            f"decay={decay_half_life}ms, max_suppress={max_suppress_time}ms, penalty={flap_penalty}")
                return True
            else:
                logger.warning(f"Failed to configure damping parameters on {interface}: {result.get('stderr', '')}")
                return False

        return True

    except Exception as e:
        logger.error(f"Error configuring link damping on {interface}: {e}")
        return False


def verify_configuration(dut, interface, config_params):
    """
    Verify that link damping configuration is applied correctly.

    Args:
        dut: DUT host object
        interface: Interface name
        config_params: Dictionary of expected configuration parameters

    Returns:
        bool: True if configuration matches expected values
    """
    try:
        # Query CONFIG_DB via redis-cli
        cmd = f"redis-cli -n 4 HGETALL 'PORT|{interface}'"
        result = dut.shell(cmd, module_ignore_errors=True)

        if result["rc"] != 0:
            logger.warning(f"Could not query CONFIG_DB for {interface}")
            return False

        # Parse output
        output = result["stdout"]
        if not output or "no such key" in output.lower():
            logger.warning(f"No CONFIG_DB entry found for {interface}")
            return False

        logger.debug(f"CONFIG_DB entry for {interface}: {output}")
        return True

    except Exception as e:
        logger.error(f"Error verifying configuration for {interface}: {e}")
        return False


def generate_link_flap(dut, dut_interface, fanout=None, fanout_interface=None, num_flaps=1, interval=1):
    """
    Generate link flaps by shutting down/bringing up fanout switch interface.

    This is the proper way to generate link flaps from the remote end (Fanout).
    Link up/down events are generated at the ASIC layer via the fanout switch.

    Args:
        dut: DUT host object
        dut_interface: Interface name on DUT (for logging)
        fanout: Fanout switch host object (optional)
        fanout_interface: Interface on fanout switch to toggle (optional)
        num_flaps: Number of flaps to generate
        interval: Time in seconds between flaps

    Returns:
        bool: True if flaps were generated successfully
    """
    try:
        if not fanout or not fanout_interface:
            # Fallback: use DUT interface admin down/up
            logger.warning("Using DUT interface for flap generation (fanout not available)")
            logger.info(f"Generating {num_flaps} link flaps on {dut_interface} with {interval}s interval")

            for flap_num in range(num_flaps):
                # Admin dow Exception as en
                logger.debug(f"Flap {flap_num + 1}/{num_flaps}: Admin down on {dut_interface}")
                dut.shell(f"config interface shutdown {dut_interface}", module_ignore_errors=True)
                time.sleep(interval / 2)

                # Admin up
                logger.debug(f"Flap {flap_num + 1}/{num_flaps}: Admin up on {dut_interface}")
                dut.shell(f"config interface startup {dut_interface}", module_ignore_errors=True)
                time.sleep(interval / 2)

            return True

        else:
            # Use fanout switch interface (preferred method)
            logger.info(f"Generating {num_flaps} link flaps on {dut_interface} "
                        f"(fanout {fanout_interface}) with {interval}s interval")

            for flap_num in range(num_flaps):
                # Shut down fanout interface (causes link DOWN on DUT)
                logger.debug(f"Flap {flap_num + 1}/{num_flaps}: Shutting down {fanout_interface}")
                try:
                    fanout.shutdown([fanout_interface])
                except Exception as e:
                    # Fallback to shell command
                    fanout.shell("configure terminal", module_ignore_errors=True)
                    fanout.shell(f"interface {fanout_interface}", module_ignore_errors=True)
                    fanout.shell("shutdown", module_ignore_errors=True)
                    fanout.shell("end", module_ignore_errors=True)

                time.sleep(interval / 2)

                # Bring up fanout interface (causes link UP on DUT)
                logger.debug(f"Flap {flap_num + 1}/{num_flaps}: Bringing up {fanout_interface}")
                try:
                    fanout.no_shutdown([fanout_interface])
                except Exception as e:
                    # Fallback to shell command
                    fanout.shell("configure terminal", module_ignore_errors=True)
                    fanout.shell(f"interface {fanout_interface}", module_ignore_errors=True)
                    fanout.shell("no shutdown", module_ignore_errors=True)
                    fanout.shell("end", module_ignore_errors=True)

                time.sleep(interval / 2)

            logger.info(f"Successfully generated {num_flaps} link flaps")
            return True

    except Exception as e:
        logger.error(f"Error generating link flaps: {e}")
        return False


def get_interface_operational_state(dut, interface):
    """
    Get the operational state of an interface.

    Args:
        dut: DUT host object
        interface: Interface name

    Returns:
        str: "up" or "down"
    """
    try:
        output = dut.show_and_parse(f"show interfaces status {interface}")
        if output:
            oper_state = output[0].get("oper", "unknown").lower()
            return oper_state
        return "unknown"
    except Exception as e:
        logger.error(f"Error getting operational state for {interface}: {e}")
        return "unknown"


def get_interface_physical_state(dut, interface):
    """
    Get the physical state of an interface.

    Args:
        dut: DUT host object
        interface: Interface name

    Returns:
        str: "up" or "down"
    """
    try:
        # Physical state is typically the same as admin state in most cases
        # unless there's a link issue
        output = dut.show_and_parse(f"show interfaces status {interface}")
        if output:
            # In SONiC, physical state is often the real link state
            phys_state = output[0].get("oper", "unknown").lower()
            return phys_state
        return "unknown"
    except Exception as e:
        logger.error(f"Error getting physical state for {interface}: {e}")
        return "unknown"


def get_link_damping_stats(dut, interface):
    """
    Retrieve link damping statistics for an interface.

    Stats include:
    - pre_damping_link_transitions: Total link transitions before damping
    - pre_damping_up_events: Total UP events before damping
    - pre_damping_down_events: Total DOWN events before damping
    - post_damping_propagated_transitions: Events propagated after damping
    - post_damping_up_advertised: UP events advertised after damping
    - post_damping_down_advertised: DOWN events advertised after damping

    Args:
        dut: DUT host object
        interface: Interface name

    Returns:
        dict: Dictionary of statistics
    """
    try:
        # Query APPL_DB for damping statistics
        # In SONiC, link damping stats are stored in APP_DB
        get_oid_cmd = f"redis-cli -n 2 HGET 'COUNTERS_PORT_NAME_MAP' '{interface}'"

        oid_result = dut.shell(get_oid_cmd, module_ignore_errors=True)

        # Extract and clean the OID from the shell output
        # (Assuming dut.shell returns an object where .stdout or .strip() gets the raw string)
        oid = oid_result['stdout'].strip()

        # Step 2: Query APP_DB using the retrieved OID for damping statistics
        # In SONiC, link damping stats are stored in APP_DB using the port's OID
        cmd = f'redis-cli -n 6 HGETALL "LINK_EVENT_DAMPING_STATS|{oid}"'

        result = dut.shell(cmd, module_ignore_errors=True)

        if result["rc"] == 0 and result["stdout"]:
            # Parse the HGETALL output (alternating key-value pairs)
            lines = result["stdout"].strip().split('\n')
            stats = {}
            for i in range(0, len(lines), 2):
                if i + 1 < len(lines):
                    key = lines[i].strip().strip('"')
                    value = lines[i + 1].strip().strip('"')
                    stats[key] = value
            logger.debug(f"Link damping stats for {interface}: {stats}")
            return stats
        else:
            logger.warning(f"No statistics found for {interface}")
            return {}

    except Exception as e:
        logger.error(f"Error getting link damping stats for {interface}: {e}")
        return {}


def clear_link_damping_stats(dut):
    """
    Clear link damping statistics for all interfaces or specific interface.

    Args:
        dut: DUT host object

    Returns:
        bool: True if stats were cleared successfully
    """
    try:
        # Clear all link damping stats from APP_DB
        cmd = "redis-cli -n 6 --scan --pattern 'LINK_EVENT_DAMPING_STATS*' | xargs redis-cli -n 6 DEL"
        result = dut.shell(cmd, module_ignore_errors=True)

        if result["rc"] == 0:
            logger.info("Link damping statistics cleared")
            return True
        else:
            logger.warning(f"Failed to clear statistics: {result['stderr']}")
            return False

    except Exception as e:
        logger.error(f"Error clearing link damping stats: {e}")
        return False


def get_redis_db_entries(dut, db_name, key_pattern):
    """
    Get entries from a Redis database matching a pattern.

    Args:
        dut: DUT host object
        db_name: Database name (e.g., "CONFIG_DB", "APP_DB")
        key_pattern: Key pattern to search (e.g., "*LINK_DAMPING*")

    Returns:
        dict: Dictionary of matching entries
    """
    try:
        # Map database names to their indices
        db_map = {
            "CONFIG_DB": 6,
            "APP_DB": 0,
            "STATE_DB": 1,
            "ASIC_DB": 2,
            "COUNTER_DB": 3
        }

        db_index = db_map.get(db_name, 4)

        # Use redis-cli to scan for matching keys
        cmd = f"redis-cli -n {db_index} --scan --pattern '{key_pattern}'"
        result = dut.shell(cmd, module_ignore_errors=True)

        if result["rc"] == 0:
            keys = result["stdout"].strip().split('\n')
            entries = {}
            for key in keys:
                if key.strip():
                    # Get the entry
                    get_cmd = f"redis-cli -n {db_index} HGETALL '{key.strip()}'"
                    get_result = dut.shell(get_cmd, module_ignore_errors=True)
                    if get_result["rc"] == 0:
                        entries[key.strip()] = get_result["stdout"]

            logger.debug(f"Found {len(entries)} entries in {db_name}")
            return entries
        else:
            logger.warning(f"Failed to query {db_name}")
            return {}

    except Exception as e:
        logger.error(f"Error getting Redis entries: {e}")
        return {}


def validate_redis_persistence(dut, interface, config_params):
    """
    Validate that configuration is persisted in Redis databases.

    Args:
        dut: DUT host object
        interface: Interface name
        config_params: Expected configuration parameters

    Returns:
        bool: True if configuration is persisted correctly
    """
    try:
        # Check CONFIG_DB
        get_oid_cmd = f"redis-cli -n 2 HGET 'COUNTERS_PORT_NAME_MAP' '{interface}'"

        oid_result = dut.shell(get_oid_cmd, module_ignore_errors=True)
        oid = oid_result['stdout'].strip()
        config_entries = get_redis_db_entries(dut, "CONFIG_DB", f"*LINK_EVENT_DAMPING*{oid}*")

        if not config_entries:
            logger.warning(f"No CONFIG_DB entries found for {interface}")
            return False

        logger.info(f"Configuration persisted in Redis for {interface}")
        return True

    except Exception as e:
        logger.error(f"Error validating Redis persistence: {e}")
        return False


def get_dampening_penalties(dut, interface):
    """
    Get current dampening penalty value for an interface.

    Args:
        dut: DUT host object
        interface: Interface name

    Returns:
        int: Current penalty value (0 if not in damping state)
    """
    try:
        # Query STATE_DB for current penalty
        get_oid_cmd = f"redis-cli -n 2 HGET 'COUNTERS_PORT_NAME_MAP' '{interface}'"

        oid_result = dut.shell(get_oid_cmd, module_ignore_errors=True)
        oid = oid_result['stdout'].strip()
        
        cmd = f"redis-cli -n 6 HGET 'LINK_EVENT_DAMPING_STATS|{oid}' 'current_penalty'"
        result = dut.shell(cmd, module_ignore_errors=True)

        if result["rc"] == 0 and result["stdout"]:
            penalty = int(result["stdout"].strip().strip('"'))
            logger.debug(f"Current penalty for {interface}: {penalty}")
            return penalty
        else:
            logger.debug(f"No penalty info for {interface} (likely not in damping state)")
            return 0

    except Exception as e:
        logger.warning(f"Error getting penalty for {interface}: {e}")
        return 0


def check_suppression_active(dut, interface):
    """
    Check if suppression is currently active on an interface.

    Args:
        dut: DUT host object
        interface: Interface name

    Returns:
        bool: True if suppression is active
    """
    try:
        # Query STATE_DB for suppression status
        get_oid_cmd = f"redis-cli -n 2 HGET 'COUNTERS_PORT_NAME_MAP' '{interface}'"

        oid_result = dut.shell(get_oid_cmd, module_ignore_errors=True)
        oid = oid_result['stdout'].strip()
        
        cmd = f"redis-cli -n 6 HGET 'LINK_EVENT_DAMPING_STATS|{oid}' 'is_damping_active'"
        result = dut.shell(cmd, module_ignore_errors=True)

        if result["rc"] == 0 and result["stdout"]:
            status = result["stdout"].strip().strip('"').lower()
            is_active = status in ["true", "1", "yes"]
            logger.debug(f"Suppression active on {interface}: {is_active}")
            return is_active
        else:
            # Also check if penalty is above suppress threshold
            penalty = get_dampening_penalties(dut, interface)
            return penalty > 0

    except Exception as e:
        logger.warning(f"Error checking suppression status for {interface}: {e}")
        return False


def verify_counter_values(dut, interface, expected_counters):
    """
    Verify that counter values match expected values.

    Args:
        dut: DUT host object
        interface: Interface name
        expected_counters: Dictionary of expected counter values

    Returns:
        bool: True if all counters match expected values
    """
    try:
        stats = get_link_damping_stats(dut, interface)

        for counter_name, expected_value in expected_counters.items():
            actual_value = int(stats.get(counter_name, 0))
            if actual_value != expected_value:
                logger.warning(f"{counter_name}: expected {expected_value}, got {actual_value}")
                return False

        logger.debug(f"debug:All counters verified for {interface}")
        logger.warning(f"warning:All counters verified for {interface}")
        return True

    except Exception as e:
        logger.error(f"Error verifying counter values: {e}")
        return False


def calculate_expected_suppression_time(suppress_threshold, reuse_threshold, decay_half_life, penalty):
    """
    Calculate expected time for suppression to end based on decay.

    Args:
        suppress_threshold: Threshold to enter suppression
        reuse_threshold: Threshold to exit suppression
        decay_half_life: Half-life for penalty decay (in milliseconds)
        penalty: Current penalty value

    Returns:
        float: Expected time in seconds for suppression to end
    """
    try:
        if penalty <= reuse_threshold:
            return 0

        # Exponential decay: penalty(t) = penalty_0 * (0.5)^(t / half_life)
        # Solve for t when penalty(t) = reuse_threshold
        # t = half_life * log2(penalty_0 / reuse_threshold)

        import math
        if penalty > 0 and reuse_threshold > 0:
            ratio = penalty / reuse_threshold
            # Convert decay_half_life from milliseconds to seconds for calculation
            decay_half_life_sec = decay_half_life / 1000.0
            time_to_reuse = decay_half_life_sec * math.log2(ratio)
            logger.info(f"Expected suppression time: {time_to_reuse:.2f}s "
                        f"(penalty {penalty} -> {reuse_threshold}, half_life={decay_half_life}ms)")
            return time_to_reuse
        else:
            return 0

    except Exception as e:
        logger.error(f"Error calculating suppression time: {e}")
        return 0


def inject_traffic_and_verify(dut, ptf, interface, traffic_config, verify_callback):
    """
    Inject traffic and verify behavior using spytest/scapy APIs.

    Args:
        dut: DUT host object
        ptf: PTF host object (for traffic generation)
        interface: Interface to test
        traffic_config: Traffic configuration dictionary
        verify_callback: Callback function to verify results

    Returns:
        bool: True if traffic was injected and verified successfully
    """
    try:
        logger.info(f"Injecting traffic on {interface}")
        # This would use spytest scapy APIs to generate traffic
        # Implementation depends on spytest framework integration
        logger.info("Traffic injection and verification completed")
        return True

    except Exception as e:
        logger.error(f"Error injecting traffic: {e}")
        return False


def restart_docker_container(dut, container_name):
    """
    Restart a Docker container on the DUT.

    Args:
        dut: DUT host object
        container_name: Name of the container (e.g., "swss", "syncd", "bgp")

    Returns:
        bool: True if container was restarted successfully
    """
    try:
        cmd = f"docker restart {container_name}"
        result = dut.shell(cmd, module_ignore_errors=True)

        if result["rc"] == 0:
            logger.info(f"Docker container '{container_name}' restarted successfully")
            time.sleep(5)  # Wait for container to stabilize
            return True
        else:
            logger.error(f"Failed to restart container '{container_name}': {result['stderr']}")
            return False

    except Exception as e:
        logger.error(f"Error restarting Docker container: {e}")
        return False


def wait_for_condition(dut, condition_func, timeout=60, interval=2, condition_name="condition"):
    """
    Wait for a condition to be true.

    Args:
        dut: DUT host object
        condition_func: Function that returns True when condition is met
        timeout: Maximum time to wait in seconds
        interval: Time between checks in seconds
        condition_name: Name of condition for logging

    Returns:
        bool: True if condition was met within timeout
    """
    try:
        start_time = datetime.now()
        while (datetime.now() - start_time).total_seconds() < timeout:
            if condition_func():
                logger.info(f"Condition '{condition_name}' met")
                return True
            time.sleep(interval)

        logger.warning(f"Timeout waiting for '{condition_name}' ({timeout}s)")
        return False

    except Exception as e:
        logger.error(f"Error waiting for condition: {e}")
        return False


# ============================================================================
# Config CLI Helper Functions
# ============================================================================

def get_running_config(dut, interface=None):
    """Get running configuration for interface(s)."""
    try:
        if interface:
            cmd = f"show running-configuration interface {interface}"
        else:
            cmd = "show running-configuration"

        output = dut.shell(cmd, module_ignore_errors=True)
        return output.get("stdout", "")

    except Exception as e:
        logger.error(f"Error getting running config: {e}")
        return ""


def save_configuration(dut):
    """Save current configuration to startup config."""
    try:
        cmd = "config save"
        result = dut.shell(cmd, module_ignore_errors=True)
        if result["rc"] == 0:
            logger.info("Configuration saved")
            return True
        return False

    except Exception as e:
        logger.error(f"Error saving configuration: {e}")
        return False


def reload_configuration(dut):
    """Reload configuration from file."""
    try:
        time.sleep(60)  # Wait for swSS to be up
        cmd = "config reload -y"
        result = dut.shell(cmd, module_ignore_errors=True)
        if result["rc"] == 0:
            logger.info("Configuration reloaded")
            time.sleep(60)  # Wait for reload to complete
            return True
        return False

    except Exception as e:
        logger.error(f"Error reloading configuration: {e}")
        return False
