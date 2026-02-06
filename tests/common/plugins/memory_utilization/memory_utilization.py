import logging
import re
import json
from os.path import join, split

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

MEMORY_UTILIZATION_COMMON_JSON_FILE = join(split(__file__)[0], "memory_utilization_common.json")
MEMORY_UTILIZATION_DEPENDENCE_JSON_FILE = join(split(__file__)[0], "memory_utilization_dependence.json")


class MemoryMonitor:
    def __init__(self, ansible_host):
        logger.debug("Initializing MemoryMonitor for host: {}".format(ansible_host.hostname))
        self.ansible_host = ansible_host
        self.commands = []
        self.memory_values = {}
        self.memory_errors = []

    def register_command(self, name, cmd, memory_params, memory_check_fn):
        """Register a command with its associated memory parameters and check function."""
        logger.info(
            "Registering command: name={}, cmd={}, memory_params={}, "
            "memory_check={}".format(name, cmd, memory_params, memory_check_fn)
        )
        self.commands.append((name, cmd, memory_params, memory_check_fn))
        self.memory_values[name] = {}

    def execute_command(self, cmd):
        """Execute a shell command and return its output."""
        logger.debug("Executing command: {}".format(cmd))
        try:
            response = self.ansible_host.command(cmd, module_ignore_errors=True)
            stdout = response.get('stdout', '')
            if stdout:
                logger.debug("Command output length: {} bytes".format(len(stdout)))
            else:
                logger.warning("Command '{}' returned no output".format(cmd))
            return stdout or ""  # Ensure we always return at least an empty string
        except Exception as e:
            logger.warning("Error executing command '{}': {}".format(cmd, str(e)))
            return ""  # Return empty string on error

    def check_memory_thresholds(self, current_values, previous_values):
        """Check memory usage against thresholds. """
        logger.debug("Starting memory threshold check")
        logger.debug("Previous values: {}".format(previous_values))
        logger.debug("Current values: {}".format(current_values))

        for name, cmd, memory_params, memory_check_fn in self.commands:
            for mem_item, thresholds in memory_params.items():
                logger.info("Checking thresholds for command: {}-{}".format(name, mem_item))

                # Convert thresholds to structured format for consistency
                logger.debug("Original thresholds: {}".format(thresholds))
                normalized_thresholds = self._normalize_thresholds(thresholds)
                logger.debug("Normalized thresholds: {}".format(normalized_thresholds))

                current_value = round(float(current_values.get(name, {}).get(mem_item, 0)), 1)
                previous_value = round(float(previous_values.get(name, {}).get(mem_item, 0)), 1)

                if current_value == 0 or previous_value == 0:
                    logger.warning("Skipping memory check for {}-{} due to zero value".format(name, mem_item))
                    continue

                logger.debug("Processing thresholds for {}:{} - previous: {}, current: {}".format(
                    name, mem_item, previous_value, current_value))

                # Skip high threshold check if explicitly set to null
                high_threshold_raw = normalized_thresholds.get("memory_high_threshold", None)
                if high_threshold_raw is not None:
                    logger.debug("Raw high threshold for {}:{}: {}".format(name, mem_item, high_threshold_raw))
                    high_threshold = self._parse_threshold(high_threshold_raw, previous_value)
                    logger.info("Calculated high threshold for {}:{}: {}".format(name, mem_item, high_threshold))

                    if previous_value > high_threshold:
                        self._handle_memory_threshold_exceeded(
                            name, mem_item, previous_value, high_threshold_raw,
                            previous_values, current_values, is_current=False
                        )

                    if current_value > high_threshold:
                        self._handle_memory_threshold_exceeded(
                            name, mem_item, current_value, high_threshold_raw,
                            previous_values, current_values, is_current=True
                        )

                # Get increase threshold and determine if it's a percentage or absolute value
                increase_threshold_raw = normalized_thresholds.get("memory_increase_threshold", float('inf'))
                logger.debug("Raw increase threshold for {}:{}: {}".format(name, mem_item, increase_threshold_raw))
                increase_threshold = self._parse_threshold(increase_threshold_raw, previous_value)
                logger.info("Calculated increase threshold for {}:{}: {}".format(name, mem_item, increase_threshold))

                increase = current_value - previous_value
                if increase > increase_threshold:
                    self._handle_memory_threshold_exceeded(
                        name, mem_item, increase, increase_threshold_raw,
                        previous_values, current_values, is_increase=True
                    )

    def _normalize_thresholds(self, thresholds):
        """
        Convert legacy or shorthand threshold formats into a consistent structured format.

        Purpose:
        - Ensures all threshold values are represented as dictionaries with explicit "type" and "value" fields.
        - Converts simple numeric values to {"type": "value", "value": ...}
        - Converts percentage strings (like "10%") to {"type": "percentage", "value": ...}
        - Leaves already-structured or list values unchanged.

        This normalization allows the rest of the code to process thresholds in a uniform way.
        """
        normalized = {}

        for key, value in thresholds.items():
            if isinstance(value, (int, float)):
                logger.warning("Legacy threshold format detected: {}={}. Please use structured format.".format(
                    key, value))
                normalized[key] = {"type": "value", "value": value}
                logger.debug("Converted simple value {} to structured format: {}".format(
                             value, normalized[key]))
            elif isinstance(value, str) and value.endswith('%'):
                logger.warning("Legacy threshold format detected: {}={}. Please use structured format.".format(
                    key, value))
                normalized[key] = {"type": "percentage", "value": value}
                logger.debug("Converted percentage string {} to structured format: {}".format(
                             value, normalized[key]))
            else:
                normalized[key] = value

        return normalized

    def _parse_threshold(self, threshold, base_value):
        """
        Parse threshold value which can be either:
        1. A dict with type and value fields
        2. A list of dicts for multiple threshold types,
        possibly including a {"type": "comparison", "value": "min"/"max"}
        Returns the selected calculated threshold value.
        """
        logger.debug("Parsing threshold: {} (type: {}) with base value: {}".format(
                     threshold, type(threshold).__name__, base_value))

        # Handle structured format
        if isinstance(threshold, dict) and 'type' in threshold and 'value' in threshold:
            threshold_type = threshold['type']
            threshold_value = threshold['value']
            logger.debug("Structured threshold - type: {}, value: {}".format(threshold_type, threshold_value))

            if threshold_type == 'percentage':
                try:
                    # Strip % if present
                    if isinstance(threshold_value, str) and threshold_value.endswith('%'):
                        percentage = float(threshold_value.rstrip('%'))
                    else:
                        percentage = float(threshold_value)

                    # Validate percentage is in reasonable range
                    if percentage < 0 or percentage > 100:
                        logger.warning("Percentage threshold outside normal range (0-100): {}%".format(percentage))

                    calculated = round((percentage / 100.0) * base_value, 1)
                    logger.debug("Calculated percentage threshold: {}% of {} = {}".format(
                        percentage, base_value, calculated))
                    return calculated
                except (ValueError, TypeError) as e:
                    logger.error("Failed to process percentage threshold: {}".format(str(e)), exc_info=True)
                    return float('inf')
            elif threshold_type == 'value':
                try:
                    value = round(float(threshold_value), 1)
                    if value < 0:
                        logger.warning("Negative threshold value: {}".format(value))
                    logger.debug("Using absolute value: {}".format(value))
                    return value
                except (ValueError, TypeError) as e:
                    logger.error("Failed to process value threshold: {}".format(str(e)), exc_info=True)
                    return float('inf')
            elif threshold_type == 'percentage_points':
                try:
                    value = round(float(threshold_value), 1)
                    if value < 0:
                        logger.warning("Negative threshold value: {}".format(value))
                    logger.debug("Using absolute percentage points value: {}".format(value))
                    return value
                except (ValueError, TypeError) as e:
                    logger.error("Failed to process percentage_points threshold: {}".format(str(e)), exc_info=True)
                    return float('inf')
            else:
                logger.error("Unknown threshold type: {}".format(threshold_type))
                return float('inf')

        # Handle list format (multiple threshold types)
        elif isinstance(threshold, list):
            logger.debug("Processing a list of {} thresholds".format(len(threshold)))
            thresholds = []
            comparison = None
            for t in threshold:
                if isinstance(t, dict) and t.get("type") == "comparison":
                    # Accepts "min" or "max"
                    comparison = t.get("value", None)
                elif isinstance(t, dict) and 'type' in t and 'value' in t:
                    parsed = self._parse_threshold(t, base_value)
                    logger.debug("List item: parsed value = {}".format(parsed))
                    thresholds.append(parsed)
                else:
                    logger.warning("Skipping invalid threshold list item: {}".format(t))
            if not thresholds:
                return float('inf')
            if comparison == "max":
                selected = round(max(thresholds), 1)
            else:
                # Default to min if no comparison specified
                selected = round(min(thresholds), 1)
            logger.info("Selected {} threshold from list: {} (from values: {})".format(
                         comparison if comparison else "min", selected, thresholds))
            return selected

        # Handle deprecated formats with warning
        elif isinstance(threshold, (int, float, str)):
            logger.warning(
                "Using deprecated threshold format: {}. Please update to structured format.".format(threshold))

            # For backward compatibility
            if isinstance(threshold, str) and threshold.endswith('%'):
                try:
                    percentage = float(threshold.rstrip('%'))
                    calculated = round((percentage / 100.0) * base_value, 1)
                    logger.debug("Calculated legacy percentage threshold: {}% of {} = {}".format(
                        percentage, base_value, calculated))
                    return calculated
                except (ValueError, TypeError) as e:
                    logger.error("Invalid percentage threshold string: {} - Error: {}".format(threshold, e))
                    return float('inf')
            else:
                # Simple value
                try:
                    value = round(float(threshold), 1)
                    logger.debug("Using legacy absolute threshold: {}".format(value))
                    return value
                except (ValueError, TypeError) as e:
                    logger.error("Invalid threshold value: {} - Error: {}".format(threshold, e))
                    return float('inf')
        else:
            logger.warning("Unsupported threshold format: {}".format(threshold))
            return float('inf')

    def _handle_memory_threshold_exceeded(self, name, mem_item, value, threshold,
                                          previous_values, current_values, is_current=False, is_increase=False):
        """Handle memory threshold or increase exceeded."""
        logger.info("{}:{}, previous_values: {}".format(name, mem_item, previous_values))
        logger.info("{}:{}, current_values: {}".format(name, mem_item, current_values))

        def fmt(val, threshold_type="value"):
            """Format value with appropriate unit based on threshold type"""
            if threshold_type == "percentage_points":
                return f"{val:.1f}%"
            else:
                return f"{val:.1f} MB"

        def format_threshold_and_value(threshold, value):
            if isinstance(threshold, dict) and 'type' in threshold:
                threshold_type = threshold['type']
                if threshold_type == 'percentage':
                    return f"{value:.1f}%", f"{threshold['value']}%"
                elif threshold_type == 'percentage_points':
                    return f"{value:.1f}%", f"{threshold['value']}%"
                else:  # 'value' type
                    return fmt(value), fmt(float(threshold['value']))
            elif isinstance(threshold, list):
                for t in threshold:
                    if isinstance(t, dict) and 'type' in t:
                        return format_threshold_and_value(t, value)
                return str(value), str(threshold)
            else:
                return fmt(value), str(threshold)

        threshold_str = self._format_threshold_for_display(threshold)
        logger.debug("Threshold exceeded - measured value: {}, formatted threshold: {}".format(
            value, threshold_str))

        prev_val = previous_values.get(name, {}).get(mem_item, 0)
        curr_val = current_values.get(name, {}).get(mem_item, 0)

        threshold_type = "value"  # default
        if isinstance(threshold, dict) and 'type' in threshold:
            threshold_type = threshold['type']
        elif isinstance(threshold, list):
            for t in threshold:
                if isinstance(t, dict) and 'type' in t:
                    threshold_type = t['type']
                    break

        if is_increase:
            val_str, th_str = format_threshold_and_value(threshold, value)
            message = (
                "[ALARM]: {}:{} memory usage increased by {}, exceeds increase threshold {} (previous: {}, current: {})"
                .format(name, mem_item, val_str, th_str, fmt(prev_val, threshold_type), fmt(curr_val, threshold_type))
            )
        else:
            which = "Current" if is_current else "Previous"
            val_str, th_str = format_threshold_and_value(threshold, value)
            message = (
                "[ALARM]: {}:{}, {} memory usage {} exceeds high threshold {} (previous: {}, current: {})"
                .format(name, mem_item, which, val_str, th_str, fmt(prev_val, threshold_type), fmt(curr_val, threshold_type))  # noqa: E501
            )

        asic_type = self.ansible_host.facts['asic_type']
        if asic_type == "vs":
            logger.warning(message)
        else:
            logger.error(message)
            # Store error instead of failing immediately
            self.memory_errors.append(message)
            logger.debug("Stored memory error: {}".format(message))

    def get_memory_errors(self):
        return self.memory_errors

    def has_memory_errors(self):
        return len(self.memory_errors) > 0

    def clear_memory_errors(self):
        self.memory_errors = []

    def _format_threshold_for_display(self, threshold):
        """Format a threshold value for better readability in messages."""
        logger.debug("Formatting threshold for display: {} (type: {})".format(threshold, type(threshold).__name__))

        if isinstance(threshold, dict) and 'type' in threshold and 'value' in threshold:
            if threshold['type'] == 'percentage':
                value = threshold['value']
                if isinstance(value, str) and value.endswith('%'):
                    formatted = value
                else:
                    formatted = "{}%".format(value)
                logger.debug("Formatted percentage threshold as: {}".format(formatted))
                return formatted
            elif threshold['type'] == 'percentage_points':
                formatted = "{}%".format(threshold['value'])
                logger.debug("Formatted percentage_points threshold as: {}".format(formatted))
                return formatted
            else:
                formatted = str(threshold['value'])
                logger.debug("Formatted value threshold as: {}".format(formatted))
                return formatted
        elif isinstance(threshold, list):
            logger.debug("Formatting list of {} thresholds".format(len(threshold)))
            formatted = []
            for t in threshold:
                item_format = self._format_threshold_for_display(t)
                logger.debug("Formatted list item as: {}".format(item_format))
                formatted.append(item_format)
            result = ", ".join(formatted)
            logger.debug("Joined list thresholds as: {}".format(result))
            return result
        else:
            result = str(threshold)
            logger.debug("Formatted simple threshold as: {}".format(result))
            return result

    def parse_and_register_commands(self, hwsku=None):
        """Initialize the MemoryMonitor by reading commands from JSON files and registering them."""
        logger.info("Loading memory monitoring commands for hwsku: {}".format(hwsku))

        parameter_dict = {}
        with open(MEMORY_UTILIZATION_COMMON_JSON_FILE, 'r') as file:
            data = json.load(file)
            memory_items = data.get("COMMON", [])
            for item in memory_items:
                name = item["name"]
                command = item["cmd"]
                memory_params = item["memory_params"]
                memory_check_fn = item["memory_check"]
                parameter_dict[name] = {
                    'name': name,
                    'cmd': command,
                    'memory_params': memory_params,
                    'memory_check_fn': memory_check_fn
                }

        with open(MEMORY_UTILIZATION_DEPENDENCE_JSON_FILE, 'r') as file:
            data = json.load(file)
            memory_items = data.get("COMMON", [])
            for item in memory_items:
                name = item["name"]
                command = item["cmd"]
                memory_params = item["memory_params"]
                memory_check_fn = item["memory_check"]
                parameter_dict[name] = {
                    'name': name,
                    'cmd': command,
                    'memory_params': memory_params,
                    'memory_check_fn': memory_check_fn
                }

            if hwsku:
                hwsku_found = any(hwsku in sku_list for sku_list in data.get("HWSKU", {}).values())
                if hwsku_found:
                    for key, value in data["HWSKU"].items():
                        if hwsku in value:
                            for item in data[key]:
                                name = item["name"]
                                command = item["cmd"]
                                memory_params = item["memory_params"]
                                memory_check_fn = item["memory_check"]

                                # Check if this command already exists (from common config)
                                if name in parameter_dict:
                                    logger.info("Merging hwsku-specific config for command: {}".format(name))
                                    # Merge memory_params instead of overwriting
                                    existing_params = parameter_dict[name]['memory_params']
                                    for mem_item, thresholds in memory_params.items():
                                        logger.debug("Overriding memory params for {}:{}".format(name, mem_item))
                                        existing_params[mem_item] = thresholds
                                    # Update cmd and memory_check_fn if needed
                                    parameter_dict[name]['cmd'] = command
                                    parameter_dict[name]['memory_check_fn'] = memory_check_fn
                                else:
                                    # New command specific to this hwsku
                                    logger.info("Adding new hwsku-specific command: {}".format(name))
                                    parameter_dict[name] = {
                                        'name': name,
                                        'cmd': command,
                                        'memory_params': memory_params,
                                        'memory_check_fn': memory_check_fn
                                    }

        for param in parameter_dict.values():
            # Normalize thresholds in memory_params to ensure consistent behavior
            for mem_item, thresholds in param['memory_params'].items():
                param['memory_params'][mem_item] = self._normalize_thresholds(thresholds)

            self.register_command(param['name'], param['cmd'], param['memory_params'], eval(param['memory_check_fn']))


def parse_top_output(output, memory_params):
    """Parse the 'top' command output to extract memory usage information."""
    memory_values = {}

    if not output:
        logger.warning("Empty output for top command, returning empty values")
        return memory_values

    headers = []
    length = 0
    for line in output.split('\n'):
        if "PID" in line and "USER" in line and "RES" in line and "COMMAND" in line:
            headers = line.split()
            length = len(headers)
            continue

        parts = line.split()
        if length != 0 and len(parts) == length:
            process_info = {headers[i]: parts[i] for i in range(length)}

            for mem_item, thresholds in memory_params.items():
                if mem_item in process_info["COMMAND"]:
                    if mem_item in memory_values:
                        memory_values[mem_item] = round(
                            memory_values[mem_item] + float(int(process_info["RES"]) / 1024), 1
                        )
                    else:
                        memory_values[mem_item] = round(float(int(process_info["RES"]) / 1024), 1)

    logger.debug("Parsed memory values: {}".format(memory_values))
    return memory_values


def parse_free_output(output, memory_params):
    """Parse the 'free' command output to extract memory usage information."""
    memory_values = {}

    if not output:
        logger.warning("Empty output for free command, returning empty values")
        return memory_values

    headers, Mem, Swap = [], [], []
    for line in output.split('\n'):
        if "total" in line:
            headers = line.split()
        if "Mem:" in line:
            Mem = line.split()[1:]
        if "Swap:" in line:
            Swap = line.split()[1:]

    mem_info = {headers[i]: int(Mem[i]) for i in range(len(Mem))}
    swap_info = {headers[i]: int(Swap[i]) for i in range(len(Swap))}

    for mem_item, _ in memory_params.items():
        memory_values[mem_item] = round(mem_info.get(mem_item, 0) + swap_info.get(mem_item, 0), 1)

    logger.debug("Parsed memory values: {}".format(memory_values))
    return memory_values


def parse_monit_validate_output(output, memory_params):
    """Parse the 'monit validate' command output to extract memory usage information."""
    memory_values = {}

    if not output:
        logger.warning("Empty output for monit validate command, returning empty values")
        return memory_values

    memory_pattern = r"memory usage\s+([\d\.]+ \w+)\s+\[(\d+\.\d+)%\]"
    swap_pattern = r"swap usage\s+([\d\.]+ \w+)\s+\[(\d+\.\d+)%\]"

    for line in output.split('\n'):
        if "memory usage" in line:
            match = re.search(memory_pattern, line)
            if match:
                used_memory = match.group(1)         # noqa: F841
                memory_percentage = match.group(2)
                memory_values['memory_usage'] = round(float(memory_percentage), 1)
            else:
                logger.error("Failed to parse memory usage from line: {}".format(line))
        if "swap usage" in line:
            match = re.search(swap_pattern, line)
            if match:
                used_swap = match.group(1)            # noqa: F841
                swap_percentage = match.group(2)      # noqa: F841
            else:
                logger.debug("Failed to parse swap usage from line: {}".format(line))

    logger.debug("Parsed memory values: {}".format(memory_values))
    return memory_values


def parse_docker_stats_output(output, memory_params):
    """Parse the 'docker stats' command output to extract memory usage information."""
    memory_values = {}

    if not output:
        logger.warning("Empty output for docker stats command, returning empty values")
        return memory_values

    length = 0
    pattern = r"(\d+\.\d+)%.*?(\d+\.\d+)%"

    for line in output.split('\n'):
        if "NAME" in line and "CPU" in line and "MEM" in line:
            headers = line.split()
            length = len(headers)
            continue

        if length != 0:
            for mem_item, thresholds in memory_params.items():
                if mem_item in line:
                    match = re.search(pattern, line)
                    if match:
                        mem_usage = match.group(2)
                        memory_values[mem_item] = round(float(mem_usage), 1)
                    else:
                        logger.error("Failed to parse memory usage from line: {}".format(line))
                else:
                    continue

    logger.debug("Parsed memory values: {}".format(memory_values))
    return memory_values


def parse_frr_memory_output(output, memory_params):
    """Parse the 'vtysh -c "show memory bgp/zebra"' output to extract FRR daemon memory usage."""
    memory_values = {}

    if not output:
        logger.warning("Empty output for FRR memory command, returning empty values")
        return memory_values

    unit_multipliers = {
        'bytes': 1,
        'KiB': 1024,
        'MiB': 1024 * 1024,
        'GiB': 1024 * 1024 * 1024
    }

    # Initialize values for the three lines
    holding_block_headers = 0.0
    used_small_blocks = 0.0
    used_ordinary_blocks = 0.0

    for line in output.split('\n'):
        line = line.strip()
        if "Holding block headers:" in line:
            parts = line.split()
            if len(parts) >= 4:
                try:
                    value = float(parts[3])
                    unit = parts[4] if len(parts) > 4 else 'bytes'
                    logger.debug(f"Parsed 'Holding block headers': {value} {unit}")
                    if unit in unit_multipliers:
                        holding_block_headers = value * unit_multipliers[unit]
                    else:
                        logger.warning(f"Unknown memory unit in 'Holding block headers': {unit}, treating as bytes")
                        holding_block_headers = value
                except (ValueError, TypeError) as e:
                    logger.error(f"Failed to parse 'Holding block headers' value: {e}")
        elif "Used small blocks:" in line:
            parts = line.split()
            if len(parts) >= 4:
                try:
                    value = float(parts[3])
                    unit = parts[4] if len(parts) > 4 else 'bytes'
                    logger.debug(f"Parsed 'Used small blocks': {value} {unit}")
                    if unit in unit_multipliers:
                        used_small_blocks = value * unit_multipliers[unit]
                    else:
                        logger.warning(f"Unknown memory unit in 'Used small blocks': {unit}, treating as bytes")
                        used_small_blocks = value
                except (ValueError, TypeError) as e:
                    logger.error(f"Failed to parse 'Used small blocks' value: {e}")
        elif "Used ordinary blocks:" in line:
            parts = line.split()
            if len(parts) >= 4:
                try:
                    value = float(parts[3])
                    unit = parts[4] if len(parts) > 4 else 'bytes'
                    logger.debug(f"Parsed 'Used ordinary blocks': {value} {unit}")
                    if unit in unit_multipliers:
                        used_ordinary_blocks = value * unit_multipliers[unit]
                    else:
                        logger.warning(f"Unknown memory unit in 'Used ordinary blocks': {unit}, treating as bytes")
                        used_ordinary_blocks = value
                except (ValueError, TypeError) as e:
                    logger.error(f"Failed to parse 'Used ordinary blocks' value: {e}")

    # Sum the three values and convert to MB
    total_bytes = holding_block_headers + used_small_blocks + used_ordinary_blocks
    memory_values['used'] = round(total_bytes / (1024 * 1024), 1)
    logger.info(f"Total FRR memory used: {memory_values['used']} MB, "
                f"holding: {holding_block_headers} bytes, "
                f"small: {used_small_blocks} bytes, "
                f"ordinary: {used_ordinary_blocks} bytes")

    logger.debug("Parsed FRR memory values: {}".format(memory_values))
    return memory_values
