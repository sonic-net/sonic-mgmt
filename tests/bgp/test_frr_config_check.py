import logging
import pytest
import re
from tests.common import config_reload
from tests.common.platform.processes_utils import wait_critical_processes

pytestmark = [
    pytest.mark.topology('t0', 't1'),
    pytest.mark.disable_loganalyzer,
]

logger = logging.getLogger(__name__)

# Global skip list for FRR commands that may not appear in 'show running-config' output
# These commands are hidden when their values match FRR defaults
SKIP_CONFIG_COMMANDS = [
    'zebra nexthop kernel enable'
]


def parse_frr_config_file(duthost, config_file):
    """
    Parse FRR configuration file and extract meaningful configuration lines
    """
    config_lines = []
    try:
        # Read the configuration file
        cmd = "sudo cat /etc/sonic/frr/{}".format(config_file)
        result = duthost.shell(cmd)

        for line in result['stdout_lines']:
            line = line.strip()
            # Skip empty lines and comments
            if (line and not line.startswith('!')):
                config_lines.append(line)

    except Exception as e:
        logger.warning("Failed to read config file {}: {}".format(config_file, str(e)))

    return config_lines


def parse_vtysh_running_config(duthost):
    """
    Get running configuration from vtysh and parse it
    """
    try:
        result = duthost.shell('vtysh -c "show running-config"')
        running_config = result['stdout']
        return running_config
    except Exception as e:
        logger.error("Failed to get running configuration: {}".format(str(e)))
        return ""


def normalize_config_line(line):
    """
    Normalize configuration line for comparison
    Remove extra spaces and standardize format
    """
    # Remove extra whitespace
    line = re.sub(r'\s+', ' ', line.strip())
    return line


def is_config_in_running(config_line, running_config):
    """
    Check if a configuration line exists in running configuration
    """
    normalized_config = normalize_config_line(config_line)
    normalized_running = normalize_config_line(running_config)

    # Direct match
    if normalized_config in normalized_running:
        return True

    # Check for partial matches for complex configurations
    # Split the config line into words for more flexible matching
    config_words = normalized_config.split()
    if len(config_words) > 1:
        # Check if all words in config line appear in the same context in running config
        lines = normalized_running.split('\n')
        for line in lines:
            if all(word in line for word in config_words):
                return True

    return False


def verify_frr_config_in_running(duthost, config_file, running_config):
    """
    Verify that configurations in config file are present in running configuration
    """
    logger.info("Verifying FRR config file: {}".format(config_file))

    # Get configuration lines from file
    config_lines = parse_frr_config_file(duthost, config_file)
    logger.info("Parsed {} lines from config file {}".format(len(config_lines), config_file))
    logger.debug("Configuration lines: {}".format(config_lines))

    if not running_config:
        pytest.fail("Failed to get running configuration from vtysh")

    missing_configs = []

    # Check each configuration line
    for config_line in config_lines:
        # Skip certain lines that are not expected in running config (regex patterns)
        skip_patterns = [
            r'password\s+',           # password lines are security-related and not shown
            r'^interface\s+',
            r'^link-detect$',
            r'^network\s+',
            r'^maximum-paths\s+',
        ]

        should_skip = False

        # Check against regex patterns
        for pattern in skip_patterns:
            # re.IGNORECASE makes the pattern matching case-insensitive
            # This means 'HOSTNAME', 'hostname', 'Hostname' will all match r'hostname\s+'
            if re.match(pattern, config_line, re.IGNORECASE):
                should_skip = True
                logger.debug("Skipping config line '{}' (matched pattern: {})".format(config_line, pattern))
                break

        # Check against global skip command list (commands that may be hidden when matching defaults)
        if not should_skip:
            for skip_cmd in SKIP_CONFIG_COMMANDS:
                if config_line.lower().startswith(skip_cmd.lower()):
                    should_skip = True
                    logger.debug("Skipping config line '{}' (matched skip command: {})".format(
                        config_line, skip_cmd))
                    break

        if should_skip:
            continue

        if not is_config_in_running(config_line, running_config):
            missing_configs.append(config_line)
            logger.warning("Configuration '{}' from {} not found in running config".format(
                config_line, config_file))

    return missing_configs


def get_frr_config_files(duthost):
    """
    Get list of FRR config files from /etc/sonic/frr directory
    """
    config_files = []
    try:
        result = duthost.shell("ls /etc/sonic/frr")
        for file in result['stdout_lines']:
            file = file.strip()
            # Only include .conf files
            if file.endswith('.conf'):
                config_files.append(file)
        logger.info("Found FRR config files: {}".format(config_files))
        return config_files
    except Exception as e:
        logger.error("Failed to get FRR config files: {}".format(str(e)))
        return config_files


# Add iteration level mapping similar to bgp_stress_link_flap
ITERATION_LEVEL_MAP = {
    'debug': 1,
    'basic': 3,
    'confident': 10,
    'thorough': 50
}


def test_frr_config_check(duthosts, enum_rand_one_per_hwsku_frontend_hostname, get_function_completeness_level):
    """
    Test FRR configuration consistency
    1. Get current FRR running configuration using 'vtysh -c "show running"'
    2. Read config files and get configurations
    3. Compare config file contents with FRR running configuration
    4. Perform config reload
    5. Repeat the comparison after config reload
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    logger.info("Starting FRR configuration check test on {}".format(duthost.hostname))

    # Get completeness level and set number of iterations
    normalized_level = get_function_completeness_level
    if normalized_level is None:
        normalized_level = 'debug'
    num_iterations = ITERATION_LEVEL_MAP[normalized_level]
    logger.info('Completeness level: {}, setting iterations to: {}'.format(normalized_level, num_iterations))

    # FRR config files to check - ['bgpd.conf', 'staticd.conf', 'zebra.conf', 'vtysh.conf']
    frr_config_files = get_frr_config_files(duthost)
    logger.info("FRR config files to check: {}".format(frr_config_files))

    # Get current FRR running configuration (once)
    logger.info("Getting FRR running configuration")
    running_config = parse_vtysh_running_config(duthost)
    # logger.debug("Running configuration: {}".format(running_config))

    # Initial configuration verification
    logger.info("Verifying initial FRR configuration consistency")
    initial_missing_configs = {}

    for config_file in frr_config_files:
        missing_configs = verify_frr_config_in_running(duthost, config_file, running_config)
        logger.info("Missing configurations in {}: {}".format(config_file, missing_configs))
        if missing_configs:
            initial_missing_configs[config_file] = missing_configs

    # Log initial results
    if initial_missing_configs:
        logger.warning("Initial check - Found missing configurations:")
        for config_file, missing in initial_missing_configs.items():
            logger.warning("File {}: {}".format(config_file, missing))
    else:
        logger.info("Initial check - All configurations are present in running config")

    # Loop for repeated config reload and verification
    logger.info("Starting {} iterations of config reload and verification".format(num_iterations))

    for iteration in range(1, num_iterations + 1):
        logger.info("ITERATION {}/{}".format(iteration, num_iterations))

        # Perform config reload
        logger.info("Iteration {}: Performing config reload".format(iteration))
        try:
            config_reload(duthost, safe_reload=True, check_intf_up_ports=True)
            wait_critical_processes(duthost)
            logger.info("Iteration {}: Config reload completed successfully".format(iteration))
        except Exception as e:
            pytest.fail("Iteration {}: Config reload failed: {}".format(iteration, str(e)))

        # Get running configuration again after reload
        logger.info("Iteration {}: Getting FRR running configuration after reload".format(iteration))
        post_reload_running_config = parse_vtysh_running_config(duthost)

        # Verify configuration after reload
        logger.info("Iteration {}: Verifying FRR configuration after config reload".format(iteration))
        post_reload_missing_configs = {}

        for config_file in frr_config_files:
            missing_configs = verify_frr_config_in_running(duthost, config_file, post_reload_running_config)
            if missing_configs:
                post_reload_missing_configs[config_file] = missing_configs
                logger.warning("Iteration {}: Missing configs in {}: {}".format(
                    iteration, config_file, missing_configs))

        # Compare with initial results
        logger.info("Iteration {}: Comparing with initial configuration check".format(iteration))
        if initial_missing_configs == post_reload_missing_configs:
            logger.info("Iteration {}: Configuration consistency maintained".format(iteration))
        else:
            logger.warning("Iteration {}: Configuration consistency changed".format(iteration))
            logger.warning("Initial missing: {}".format(initial_missing_configs))
            logger.warning("Current missing: {}".format(post_reload_missing_configs))

        # Final verification for this iteration
        if post_reload_missing_configs:
            logger.error("Iteration {}: Found missing configurations:".format(iteration))
            for config_file, missing in post_reload_missing_configs.items():
                logger.error("Iteration {}: File {}: {}".format(iteration, config_file, missing))

            # Fail immediately when configuration inconsistency is detected
            pytest.fail("Iteration {}: FRR configuration inconsistency detected after config reload".format(iteration))
        else:
            logger.info("Iteration {}: All configurations are present in running config".format(iteration))

    logger.info("Completed {} iterations of config reload and verification".format(num_iterations))
