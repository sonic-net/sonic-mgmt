"""
Cross-feature helpers and constants for packet-trimming-related scheduler /
queue-counter manipulation.

Originally defined inside tests/packet_trimming/ — moved here so other features
(e.g. tests/tam/) can reuse them without violating the
tests/common/plugins/dependency_check cross-feature import rule.
"""

import ipaddress
import json
import logging

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until


logger = logging.getLogger(__name__)


# --- Scheduler / trimming constants ---------------------------------------

BLOCK_DATA_PLANE_SCHEDULER_NAME = "SCHEDULER_BLOCK_DATA_PLANE"
SCHEDULER_TYPE = "DWRR"
SCHEDULER_WEIGHT = 15
SCHEDULER_PIR = 1
SCHEDULER_CIR = 1
SCHEDULER_METER_TYPE = 'packets'

DEFAULT_QUEUE_SCHEDULER_CONFIG = {
    "0": "scheduler.0",
    "1": "scheduler.0",
    "2": "scheduler.0",
    "3": "scheduler.1",
    "4": "scheduler.1",
    "5": "scheduler.0",
    "6": "scheduler.0",
}

DEFAULT_DSCP = 1  # Map to queue1


# --- Scheduler ASIC_DB inspection -----------------------------------------

def get_scheduler_oid_by_attributes(duthost, **kwargs):
    """
    Find scheduler OID in ASIC_DB by matching its attributes.

    Returns:
        str: OID of the matched scheduler, or None if not found
    """
    param_to_sai_attr = {
        'type': 'SAI_SCHEDULER_ATTR_SCHEDULING_TYPE',
        'weight': 'SAI_SCHEDULER_ATTR_SCHEDULING_WEIGHT',
        'pir': 'SAI_SCHEDULER_ATTR_MAX_BANDWIDTH_RATE',
        'cir': 'SAI_SCHEDULER_ATTR_MIN_BANDWIDTH_RATE'
    }

    type_value_mapping = {
        'DWRR': 'SAI_SCHEDULING_TYPE_DWRR',
        'STRICT': 'SAI_SCHEDULING_TYPE_STRICT'
    }

    expected_attrs = {}
    for param, value in kwargs.items():
        if param not in param_to_sai_attr:
            logger.warning(f"Unknown scheduler parameter: {param}")
            continue

        sai_attr = param_to_sai_attr[param]

        if param == 'type':
            if value in type_value_mapping:
                expected_attrs[sai_attr] = type_value_mapping[value]
            else:
                logger.warning(f"Unknown scheduler type: {value}")
                continue
        else:
            expected_attrs[sai_attr] = str(value)

    logger.info(f"Looking for scheduler with attributes: {expected_attrs}")

    cmd_get_oids = 'redis-cli -n 1 keys "ASIC_STATE:SAI_OBJECT_TYPE_SCHEDULER:oid*"'
    result = duthost.shell(cmd_get_oids)

    if not result["stdout"].strip():
        logger.warning("No schedulers found in ASIC_DB")
        return None

    oid_keys = result["stdout"].strip().split('\n')
    logger.info(f"Found {len(oid_keys)} schedulers in ASIC_DB")

    for oid_key in oid_keys:
        cmd_get_attrs = f'redis-cli -n 1 hgetall "{oid_key}"'
        result = duthost.shell(cmd_get_attrs)

        if not result["stdout"].strip():
            continue

        lines = result["stdout"].strip().split('\n')
        scheduler_attrs = {}
        for i in range(0, len(lines), 2):
            if i + 1 < len(lines):
                scheduler_attrs[lines[i]] = lines[i + 1]

        is_match = True
        for attr_name, expected_value in expected_attrs.items():
            actual_value = scheduler_attrs.get(attr_name)
            if actual_value != expected_value:
                is_match = False
                break

        if is_match:
            oid_value = oid_key.split(':')[-1]
            logger.info(f"Found matching scheduler OID: {oid_value}")
            logger.debug(f"Scheduler attributes: {scheduler_attrs}")
            return oid_value

    logger.warning(f"No scheduler found matching attributes: {expected_attrs}")
    return None


def validate_scheduler_configuration(duthost, dut_port, queue, expected_scheduler):
    """
    Validate that the scheduler configuration is applied correctly for a specific queue.
    """
    cmd_verify_scheduler = f"sonic-db-cli CONFIG_DB hget 'QUEUE|{dut_port}|{queue}' scheduler"
    verify_result = duthost.shell(cmd_verify_scheduler)
    current_scheduler = verify_result["stdout"].strip()

    if current_scheduler == expected_scheduler:
        logger.debug(f"Scheduler validation successful for port {dut_port} queue {queue}: {current_scheduler}")
        return True
    else:
        logger.debug(f"Scheduler validation failed for port {dut_port} queue {queue}. "
                     f"Expected: {expected_scheduler}, Got: {current_scheduler}")
        return False


def get_scheduler_usage_count(duthost, scheduler_oid):
    """
    Get the count of scheduler groups using the specified scheduler in ASIC_DB.
    """
    tmp_file = "/tmp/asic_db_scheduler_check.json"
    dump_cmd = f"sonic-db-dump -n ASIC_DB -y > {tmp_file}"
    duthost.shell(dump_cmd)

    cmd_grep_oid = f'grep "SAI_SCHEDULER_GROUP_ATTR_SCHEDULER_PROFILE_ID" {tmp_file} | grep -c "{scheduler_oid}"'
    result = duthost.shell(cmd_grep_oid, module_ignore_errors=True)

    duthost.shell(f"rm -f {tmp_file}")

    count = int(result["stdout"].strip()) if result["stdout"].strip() else 0
    return count


def validate_scheduler_apply_to_queue_in_asic_db(duthost, scheduler_oid, expected_count=1):
    """
    Validate that the scheduler is applied to queue in ASIC_DB.
    """
    logger.debug(f"Validating scheduler OID {scheduler_oid} in ASIC_DB (expected_count={expected_count})")

    count = get_scheduler_usage_count(duthost, scheduler_oid)

    if count == expected_count:
        logger.debug(f"ASIC_DB scheduler validation successful: "
                     f"OID {scheduler_oid} found in {count} scheduler groups (matches expected)")
        return True
    else:
        logger.debug(f"ASIC_DB scheduler validation failed: "
                     f"OID {scheduler_oid} found in {count} scheduler groups (expected {expected_count})")
        return False


# --- Blocking-scheduler create / apply ------------------------------------

def create_blocking_scheduler(duthost):
    """
    Create a blocking scheduler for limiting egress traffic.
    """
    logger.info(f"Creating blocking scheduler: {BLOCK_DATA_PLANE_SCHEDULER_NAME}")

    cmd_check = f"sonic-db-cli CONFIG_DB exists 'SCHEDULER|{BLOCK_DATA_PLANE_SCHEDULER_NAME}'"
    result = duthost.shell(cmd_check)

    if result["stdout"].strip() == "1":
        logger.info(f"Blocking scheduler {BLOCK_DATA_PLANE_SCHEDULER_NAME} already exists")
    else:
        cmd_create = (
            f'sonic-db-cli CONFIG_DB hset "SCHEDULER|{BLOCK_DATA_PLANE_SCHEDULER_NAME}" '
            f'"type" {SCHEDULER_TYPE} "weight" {SCHEDULER_WEIGHT} "pir" {SCHEDULER_PIR} "cir" {SCHEDULER_CIR}'
        )
        if duthost.get_asic_name() == 'th5':
            cmd_create += f' "meter_type" {SCHEDULER_METER_TYPE}'

        duthost.shell(cmd_create)
        logger.info(f"Successfully created blocking scheduler: {BLOCK_DATA_PLANE_SCHEDULER_NAME}")


def disable_egress_data_plane(duthost, dut_port, queue):
    """
    Disable egress data plane for a specific queue on a specific port.

    Returns:
        str: Original scheduler name for later restoration
    """
    queue = str(queue)

    logger.info(f"Disabling egress data plane for port: {dut_port}, queue: {queue}")

    cmd_get_scheduler = f"sonic-db-cli CONFIG_DB hget 'QUEUE|{dut_port}|{queue}' scheduler"
    result = duthost.shell(cmd_get_scheduler)

    original_scheduler = result["stdout"].strip()

    scheduler_oid = get_scheduler_oid_by_attributes(duthost, type=SCHEDULER_TYPE,
                                                    weight=SCHEDULER_WEIGHT, pir=SCHEDULER_PIR)
    pytest_assert(scheduler_oid, "Failed to find blocking scheduler OID in ASIC_DB")

    current_count = get_scheduler_usage_count(duthost, scheduler_oid)
    logger.info(f"Scheduler OID {scheduler_oid} current usage count before applying: {current_count}")

    cmd_block_q = f"sonic-db-cli CONFIG_DB hset 'QUEUE|{dut_port}|{queue}' scheduler {BLOCK_DATA_PLANE_SCHEDULER_NAME}"
    duthost.shell(cmd_block_q)

    pytest_assert(wait_until(60, 5, 0, validate_scheduler_configuration,
                             duthost, dut_port, queue, BLOCK_DATA_PLANE_SCHEDULER_NAME),
                  f"Blocking scheduler configuration failed for port {dut_port} queue {queue}")

    expected_count = current_count + 1
    pytest_assert(wait_until(60, 5, 0, validate_scheduler_apply_to_queue_in_asic_db, duthost, scheduler_oid,
                             expected_count),
                  f"Scheduler OID {scheduler_oid} validation in ASIC_DB failed for port {dut_port} "
                  f"queue {queue} (expected count: {expected_count})")

    logger.info(f"Successfully applied blocking scheduler to port {dut_port} queue {queue}")

    return original_scheduler


def enable_egress_data_plane(duthost, dut_port, queue, original_scheduler=None):
    """
    Restore egress data plane for a specific queue on a specific port.
    """
    queue = str(queue)

    logger.info(f"Enabling egress data plane for port: {dut_port}, queue: {queue}")

    if original_scheduler is None:
        original_scheduler = DEFAULT_QUEUE_SCHEDULER_CONFIG.get(queue)

    if original_scheduler:
        cmd = f"sonic-db-cli CONFIG_DB hset 'QUEUE|{dut_port}|{queue}' scheduler {original_scheduler}"
        duthost.shell(cmd)
        logger.info(f"Restored scheduler '{original_scheduler}' for port {dut_port} queue {queue}")
    else:
        cmd = f"sonic-db-cli CONFIG_DB hdel 'QUEUE|{dut_port}|{queue}' scheduler"
        duthost.shell(cmd)
        logger.info(f"Removed scheduler for port {dut_port} queue {queue}")


# --- ConfigTrimming context manager ---------------------------------------

class ConfigTrimming:
    """
    Context manager for blocking and restoring multiple egress ports.
    This is used to trigger packet trimming by blocking the egress queues.
    """

    def __init__(self, duthost, ports, queue):
        """
        Args:
            duthost: DUT host object
            ports (list or str): List of port names or single port name
                               (e.g., ["Ethernet0", "Ethernet4"] or "Ethernet0")
            queue (int): Queue index
        """
        self.duthost = duthost
        self.ports = [ports] if isinstance(ports, str) else ports
        self.queue = queue
        self.original_schedulers = {}

    def __enter__(self):
        try:
            for port in self.ports:
                logger.info(f"Blocking egress port {port} queue {self.queue}")
                original_scheduler = disable_egress_data_plane(self.duthost, port, self.queue)

                if not original_scheduler:
                    raise Exception(f"Failed to block egress port {port} queue {self.queue}")

                self.original_schedulers[port] = original_scheduler
                logger.info(f"Successfully blocked port {port} (original scheduler: {original_scheduler})")

            return self

        except Exception as e:
            logger.error(f"Failed to block egress ports: {e}")
            self.__exit__(None, None, None)
            raise

    def __exit__(self, exc_type, exc_val, exc_tb):
        restore_errors = []

        for port, original_scheduler in self.original_schedulers.items():
            try:
                if original_scheduler:
                    logger.info(f"Restoring original scheduler for port {port} queue {self.queue}")
                    enable_egress_data_plane(self.duthost, port, self.queue, original_scheduler)
                    logger.info(f"Successfully restored scheduler for port {port}")

            except Exception as e:
                error_msg = f"Exception while restoring port {port}: {str(e)}"
                logger.error(error_msg)
                restore_errors.append(error_msg)

        if restore_errors:
            raise Exception(f"Failed to restore some ports: {'; '.join(restore_errors)}")


# --- Interface / queue counter helpers ------------------------------------

def get_interface_peer_addresses(mg_facts, interface_name):
    """
    Get IPv4 and IPv6 peer addresses of a specified interface from minigraph facts.

    Returns:
        tuple: (ipv4_peer_addr, ipv6_peer_addr)
              May return (None, None) if no peer addresses are found for the interface
    """
    ipv4_peer_addr = None
    ipv6_peer_addr = None

    if "PortChannel" in interface_name:
        interface_list_key = 'minigraph_portchannel_interfaces'
        logger.info(f"Searching for PortChannel interface {interface_name} in {interface_list_key}")
    else:
        interface_list_key = 'minigraph_interfaces'
        logger.info(f"Searching for regular interface {interface_name} in {interface_list_key}")

    if interface_list_key not in mg_facts:
        logger.warning(f"Interface list '{interface_list_key}' not found in minigraph facts")
        return ipv4_peer_addr, ipv6_peer_addr

    for interface in mg_facts[interface_list_key]:
        if interface.get('attachto') == interface_name:
            if 'peer_addr' in interface:
                ip = ipaddress.ip_address(interface['peer_addr'])

                if ip.version == 4:
                    ipv4_peer_addr = interface['peer_addr']
                    logger.info(f"Found IPv4 peer address for {interface_name}: {ipv4_peer_addr}")
                elif ip.version == 6:
                    ipv6_peer_addr = interface['peer_addr']
                    logger.info(f"Found IPv6 peer address for {interface_name}: {ipv6_peer_addr}")

    if not ipv4_peer_addr and not ipv6_peer_addr:
        logger.warning(f"No peer addresses found for interface {interface_name}")

    return ipv4_peer_addr, ipv6_peer_addr


def convert_all_counter_values(data):
    """
    Convert all counter values in a dictionary, handling 'N/A' and comma-separated numbers.
    """
    for field, value in data.items():
        if isinstance(value, str):
            if value == 'N/A':
                data[field] = 0
            else:
                data[field] = int(value.replace(',', ''))
    return data


def get_queue_trim_counters_json(duthost, port):
    """
    Get specified port queue level trim counter using JSON format.

    Returns:
        dict: Queue trim counters with all values converted to integers.
              'N/A' values are converted to 0, comma-separated numbers are handled.
              'time' field is excluded from the returned data.
    """
    result = duthost.shell(f"show queue counters {port} --all --json")
    stdout = result['stdout'].strip()
    pytest_assert(stdout, "Command returned empty output.")

    json_data = json.loads(stdout)
    port_data = json_data.get(port, {})
    pytest_assert(port_data, f"No queue data found for port {port} in JSON output")

    if "time" in port_data:
        del port_data["time"]

    for queue_id, queue_data in port_data.items():
        if isinstance(queue_data, dict):
            convert_all_counter_values(queue_data)

    logger.info(f"Queue trim counters for port {port} (JSON): {port_data}")
    return port_data
