import logging
import re
import json
from os.path import join, split
import pytest

logger = logging.getLogger(__name__)

MEMORY_UTILIZATION_COMMON_JSON_FILE = join(split(__file__)[0], "memory_utilization_common.json")
MEMORY_UTILIZATION_DEPENDENCE_JSON_FILE = join(split(__file__)[0], "memory_utilization_dependence.json")


class MemoryMonitor:
    def __init__(self, ansible_host):
        self.ansible_host = ansible_host
        self.commands = []
        self.memory_values = {}

    def register_command(self, name, cmd, memory_params, memory_check_fn):
        """Register a command with its associated memory parameters and check function."""
        self.commands.append((name, cmd, memory_params, memory_check_fn))
        self.memory_values[name] = {}

    def execute_command(self, cmd):
        """Execute a shell command and return its output."""
        response = self.ansible_host.command(cmd, module_ignore_errors=True)
        stdout = response.get('stdout', None)
        # logger.debug("Command '{}' response: {}".format(cmd, stdout))
        return stdout

    def check_memory_thresholds(self, current_values, previous_values):
        """Check memory usage against thresholds. """
        logger.debug("Previous values: {}".format(previous_values))
        logger.debug("Current values: {}".format(current_values))

        for name, cmd, memory_params, memory_check_fn in self.commands:
            for mem_item, thresholds in memory_params.items():
                current_value = float(current_values.get(name, {}).get(mem_item, 0))
                previous_value = float(previous_values.get(name, {}).get(mem_item, 0))

                if current_value == 0 or previous_value == 0:
                    logger.warning("Skipping memory check for {}-{} due to zero value".format(name, mem_item))
                    continue

                high_threshold = float(thresholds.get("memory_high_threshold", float('inf')))
                increase_threshold = float(thresholds.get("memory_increase_threshold", float('inf')))

                if previous_value > high_threshold:
                    self.handle_memory_threshold_exceeded(
                        name, mem_item, previous_value, high_threshold,
                        previous_values, current_values, is_current=False
                    )

                if current_value > high_threshold:
                    self.handle_memory_threshold_exceeded(
                        name, mem_item, current_value, high_threshold,
                        previous_values, current_values, is_current=True
                    )

                increase = current_value - previous_value
                if increase > increase_threshold:
                    self.handle_memory_threshold_exceeded(
                        name, mem_item, increase, increase_threshold,
                        previous_values, current_values, is_increase=True
                    )

    def handle_memory_threshold_exceeded(self, name, mem_item, value, threshold,
                                         previous_values, current_values, is_current=False, is_increase=False):

        """Handle memory threshold or increase exceeded."""
        logger.info("{}:{}, previous_values: {}".format(name, mem_item, previous_values))
        logger.info("{}:{}, current_values: {}".format(name, mem_item, current_values))

        if is_increase:
            message = (
                "[ALARM]: {}:{} memory usage increased by {}, "
                "exceeds increase threshold {}".format(
                    name, mem_item, value, threshold
                )
            )
        else:
            message = (
                "[ALARM]: {}:{}, {} memory usage {} exceeds "
                "high threshold {}".format(
                    name, mem_item, "Current" if is_current else "Previous", value, threshold
                )
            )

        logger.warning(message)
        pytest.fail(message)

    def parse_and_register_commands(self, hwsku=None):
        """Initialize the MemoryMonitor by reading commands from JSON files and registering them."""

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
                                logger.info("#### CMD {} ".format(item))
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

        for param in parameter_dict.values():
            logger.debug(
                "Registering command: name={}, cmd={}, memory_params={}, "
                "memory_check={}".format(
                    param['name'], param['cmd'], param['memory_params'], param['memory_check_fn']
                )
            )
            self.register_command(param['name'], param['cmd'], param['memory_params'], eval(param['memory_check_fn']))


def parse_top_output(output, memory_params):
    """Parse the 'top' command output to extract memory usage information."""
    memory_values = {}
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
                        memory_values[mem_item] += int(process_info["RES"])
                    else:
                        memory_values[mem_item] = int(process_info["RES"])

    logger.debug("Parsed memory values: {}".format(memory_values))
    return memory_values


def parse_free_output(output, memory_params):
    """Parse the 'free' command output to extract memory usage information."""
    memory_values = {}
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
        memory_values[mem_item] = mem_info.get(mem_item, 0) + swap_info.get(mem_item, 0)

    logger.debug("Parsed memory values: {}".format(memory_values))
    return memory_values


def parse_monit_status_output(output, memory_params):
    """Parse the 'monit status' command output to extract memory usage information."""
    memory_values = {}
    memory_pattern = r"memory usage\s+([\d\.]+ \w+)\s+\[(\d+\.\d+)%\]"
    swap_pattern = r"swap usage\s+([\d\.]+ \w+)\s+\[(\d+\.\d+)%\]"

    for line in output.split('\n'):
        if "memory usage" in line:
            match = re.search(memory_pattern, line)
            if match:
                used_memory = match.group(1)         # noqa F841
                memory_percentage = match.group(2)
                memory_values['memory_usage'] = float(memory_percentage)
            else:
                logger.error("Failed to parse memory usage from line: {}".format(line))
        if "swap usage" in line:
            match = re.search(swap_pattern, line)
            if match:
                used_swap = match.group(1)            # noqa F841
                swap_percentage = match.group(2)      # noqa F841
            else:
                logger.debug("Failed to parse swap usage from line: {}".format(line))

    logger.debug("Parsed memory values: {}".format(memory_values))
    return memory_values


def parse_docker_stats_output(output, memory_params):
    memory_values = {}
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
                        memory_values[mem_item] = mem_usage
                    else:
                        logger.error("Failed to parse memory usage from line: {}".format(line))
                else:
                    continue

    logger.debug("Parsed memory values: {}".format(memory_values))
    return memory_values
