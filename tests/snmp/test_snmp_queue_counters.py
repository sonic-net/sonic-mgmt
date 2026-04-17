"""
Validates SNMP queue counter behavior with create_only_config_db_buffers
optimization: that SNMP correctly exposes queue counters and that removing
buffer queue configuration properly reduces the counter count.

N.B.: The SNMP agent reads queue information from COUNTERS_QUEUE_NAME_MAP
in Redis which contains ALL SAI queue objects. SNMP exposes all queue
objects that exist in the hardware/SAI layer.
"""

import pytest
import json
import re
import logging
from tests.common import config_reload
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

CFG_DB_PATH = "/etc/sonic/config_db.json"
ORIG_CFG_DB = "/etc/sonic/orig_config_db.json"
UNICAST_CTRS = 4
MULTICAST_CTRS = 4

pytestmark = [
    pytest.mark.disable_route_check,
    pytest.mark.topology('any', 't1-multi-asic'),
    pytest.mark.device_type('vs')
]


def load_new_cfg(duthost, data, loganalyzer):
    duthost.copy(content=json.dumps(data, indent=4), dest=CFG_DB_PATH)
    config_reload(
        duthost, config_source='config_db', safe_reload=True,
        check_intf_up_ports=True, wait_for_bgp=True,
        ignore_loganalyzer=loganalyzer)


def get_queue_ctrs(duthost, cmd):
    """Get the count of SNMP queue counter entries returned by snmpwalk."""
    return len(duthost.shell(cmd)["stdout_lines"])


def get_redis_queue_count_with_types(duthost, interface, asic=None):
    """
    Get the count of UC and MC queues for an interface from Redis.

    Queries both COUNTERS_QUEUE_NAME_MAP and COUNTERS_QUEUE_TYPE_MAP to
    determine the breakdown of unicast vs multicast queues.

    Args:
        duthost: The DUT host object
        interface: Interface name (e.g., "Ethernet0")
        asic: ASIC instance for multi-ASIC systems, or None for single-ASIC

    Returns:
        Dictionary with 'total', 'unicast', and 'multicast' queue counts
    """
    # Build the redis-cli commands with namespace support for multi-ASIC
    if asic is not None and duthost.sonichost.is_multi_asic:
        name_map_cmd = (
            "sonic-db-cli -n {} COUNTERS_DB HGETALL COUNTERS_QUEUE_NAME_MAP"
            .format(asic.namespace))
        type_map_cmd = (
            "sonic-db-cli -n {} COUNTERS_DB HGETALL COUNTERS_QUEUE_TYPE_MAP"
            .format(asic.namespace))
    else:
        name_map_cmd = "redis-cli -n 2 HGETALL COUNTERS_QUEUE_NAME_MAP"
        type_map_cmd = "redis-cli -n 2 HGETALL COUNTERS_QUEUE_TYPE_MAP"

    # Get queue name map (interface:queue -> SAI OID)
    name_map_result = duthost.shell(name_map_cmd)['stdout_lines']

    # Get queue type map (SAI OID -> queue type)
    type_map_result = duthost.shell(type_map_cmd)['stdout_lines']

    # Build type map dictionary (SAI OID -> type string)
    type_map = {}
    for i in range(0, len(type_map_result), 2):
        if i + 1 < len(type_map_result):
            sai_oid = type_map_result[i]
            queue_type = type_map_result[i + 1]
            type_map[sai_oid] = queue_type

    # Count queues for the interface
    queue_count = {'total': 0, 'unicast': 0, 'multicast': 0}

    for i in range(0, len(name_map_result), 2):
        if i + 1 < len(name_map_result):
            key = name_map_result[i]
            sai_oid = name_map_result[i + 1]
            if key.startswith("{}:".format(interface)):
                queue_count['total'] += 1
                queue_type = type_map.get(sai_oid, "")
                if queue_type == "SAI_QUEUE_TYPE_UNICAST":
                    queue_count['unicast'] += 1
                elif queue_type == "SAI_QUEUE_TYPE_MULTICAST":
                    queue_count['multicast'] += 1

    return queue_count


def calculate_expected_snmp_counters(queue_counts):
    """
    Calculate expected SNMP counter count based on queue counts.

    Each queue type has specific counter types:
    - Unicast queues: 4 counters
    - Multicast queues: 4 counters

    Args:
        queue_counts: Dictionary with 'unicast' and 'multicast' counts

    Returns:
        Expected total number of SNMP counter entries
    """
    return ((queue_counts['unicast'] * UNICAST_CTRS) +
            (queue_counts['multicast'] * MULTICAST_CTRS))


def check_snmp_cmd_output(duthost, cmd, count):
    out_len = len(duthost.shell(cmd)["stdout_lines"])
    if out_len >= count:
        return True
    else:
        return False


def get_queue_cntrs_oid(interface):
    """
    Return queue_cntrs_oid value based on the interface chosen.

    Args:
        interface: Asic interface selected
    Returns:
        queue_cntrs_oid
    """
    intf_num = interface.split('Ethernet')[1]
    queue_cntrs_oid = '1.3.6.1.4.1.9.9.580.1.5.5.1.4.{}'.format(
        int(intf_num) + 1)
    return queue_cntrs_oid


def get_dpu_npu_port_list(duthost):
    dpu_npu_port_list = []

    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    if config_facts is None:
        return dpu_npu_port_list
    if 'PORT' not in config_facts:
        return dpu_npu_port_list
    dpu_npu_port_list = [p for p, v in list(config_facts['PORT'].items()) if v.get('role', None) == 'Dpc']

    logger.info(f"dpu npu port list: {dpu_npu_port_list}")
    return dpu_npu_port_list


def get_asic_interface(inter_facts, duthost):
    """
    Return interface dynamically based on the asic chosen.

    Works for single/multi-asic sonic host.
    """
    ansible_inter_facts = inter_facts['ansible_interface_facts']
    interface = None
    internal_port_list = get_dpu_npu_port_list(duthost)
    for key, v in ansible_inter_facts.items():
        # Exclude internal interfaces
        if 'IB' in key or 'Rec' in key or 'BP' in key:
            continue
        if key in internal_port_list:
            continue
        if 'Ether' in key and v['active']:
            interface = key
            break

    return interface


def test_snmp_queue_counters(duthosts,
                             enum_rand_one_per_hwsku_frontend_hostname,
                             enum_frontend_asic_index,
                             creds_all_duts, loganalyzer):
    """
    Test SNMP queue counters with create_only_config_db_buffers optimization.

    This test validates that:
    1. SNMP correctly exposes queue counters based on COUNTERS_QUEUE_NAME_MAP
    2. Removing BUFFER_QUEUE entries reduces the SNMP counter count

    The SNMP agent exposes counters for all queues in COUNTERS_QUEUE_NAME_MAP.
    This includes both unicast and multicast queues created by SAI, regardless
    of BUFFER_QUEUE config.

    Test Steps:
        1. Enable create_only_config_db_buffers in DEVICE_METADATA
        2. Query COUNTERS_QUEUE_NAME_MAP to get expected queue count
        3. Verify SNMP returns the expected number of counters
        4. Remove a buffer queue entry and reload config
        5. Verify SNMP counter count decreases by the expected amount

    This test covers issue:
    https://github.com/sonic-net/sonic-buildimage/issues/17448
    """

    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    """
     Ignore expected error logs related to memory checker and orchagent
     that may occur during config reload and do not impact the test outcome.
    """
    if loganalyzer:
        ignore_regex_list = [
            r".* ERR memory_checker: \[memory_checker\] "
            r"Failed to get container ID of.*",
            r".* ERR memory_checker: \[memory_checker\] "
            r"cgroup memory usage file.*"
        ]
        if duthost.sonichost.facts['platform_asic'] == 'broadcom':
            ignore_regex_list.append(
                r".* ERR swss#orchagent:\s*.*\s*"
                r"queryAattributeEnumValuesCapability:\s*"
                r"returned value \d+ is not allowed on "
                r"SAI_SWITCH_ATTR_(?:ECMP|LAG)_DEFAULT_HASH_ALGORITHM.*")
        loganalyzer[duthost.hostname].ignore_regex.extend(ignore_regex_list)
    global ORIG_CFG_DB, CFG_DB_PATH
    hostip = duthost.host.options['inventory_manager'].get_host(
        duthost.hostname).vars['ansible_host']
    asic = duthost.asic_instance(enum_frontend_asic_index)
    int_facts = asic.interface_facts()['ansible_facts']
    interface = get_asic_interface(int_facts, duthost)
    if interface is None:
        pytest.skip("No active interface present on the asic {}".format(asic))
    queue_cntrs_oid = get_queue_cntrs_oid(interface)

    get_bfr_queue_cntrs_cmd = (
        "docker exec snmp snmpwalk -v2c -c {} {} {}"
        .format(
            creds_all_duts[duthost.hostname]['snmp_rocommunity'], hostip,
            queue_cntrs_oid))
    # Generate sonic-cfggen commands for multi-asic and single-asic duts
    if duthost.sonichost.is_multi_asic and asic is not None:
        ORIG_CFG_DB = "/etc/sonic/orig_config_db{}.json".format(
            asic.asic_index)
        CFG_DB_PATH = "/etc/sonic/config_db{}.json".format(asic.asic_index)
        cmd = "sonic-cfggen -n {} -d --print-data > {}".format(
            asic.namespace, ORIG_CFG_DB)
    else:
        cmd = "sonic-cfggen -d --print-data > {}".format(ORIG_CFG_DB)

    duthost.shell(cmd)
    data = json.loads(duthost.shell("cat {}".format(ORIG_CFG_DB),
                                    verbose=False)['stdout'])
    buffer_queue_to_del = None

    # Get appropriate buffer queue value to delete
    buffer_queues = list(data['BUFFER_QUEUE'].keys())
    iface_buffer_queues = [
        bq for bq in buffer_queues
        if any(val == interface for val in bq.split('|'))]
    if iface_buffer_queues:
        buffer_queue_to_del = iface_buffer_queues[0]
    else:
        pytest_assert(
            False,
            "Buffer Queue list can't be empty if valid interface is selected.")

    if len(iface_buffer_queues) == 1:
        # We are about to delete the config for all buffer queues
        # This test has been written with the assumption that only a subset
        # of the buffer queues will be deleted
        # Modify the key to avoid deleting all buffer queues on config reload
        match = re.search(
            rf"^{interface}\|(?P<low>[0-9]+)-(?P<high>[0-9]+)$",
            buffer_queue_to_del)
        pytest_assert(match, "Unknown key format in BUFFER_QUEUE config.")
        buffer_queue_cfg = data['BUFFER_QUEUE'][buffer_queue_to_del]
        del data['BUFFER_QUEUE'][buffer_queue_to_del]
        queue_num_low = match.group("low")
        queue_num_high = match.group("high")
        buffer_queue_to_del = "{}|{}-{}".format(
            interface, queue_num_low, int(queue_num_high) - 1)
        buffer_queue_to_remain = "{}|{}".format(interface, queue_num_high)
        data['BUFFER_QUEUE'][buffer_queue_to_del] = buffer_queue_cfg
        data['BUFFER_QUEUE'][buffer_queue_to_remain] = buffer_queue_cfg

    # Add create_only_config_db_buffers entry to device metadata to enable
    # counters optimization and get number of queue counters of Ethernet0
    # prior to removing buffer queues
    data['DEVICE_METADATA']["localhost"]["create_only_config_db_buffers"] = \
        "true"
    load_new_cfg(duthost, data, loganalyzer)

    # Query COUNTERS_QUEUE_NAME_MAP to get the accurate queue count that
    # SNMP will expose. This is the authoritative source because the SNMP
    # agent reads queue information from COUNTERS_QUEUE_NAME_MAP, not from
    # flex counter registrations or BUFFER_QUEUE config.
    # The map contains ALL SAI queue objects (both UC and MC) regardless
    # of buffer configuration.
    queue_counts_pre = get_redis_queue_count_with_types(
        duthost, interface, asic)
    expected_snmp_cnt_pre = calculate_expected_snmp_counters(queue_counts_pre)

    # Config reload may make SNMP agent restart, 60s wait may be insufficient
    wait_until(120, 15, 0, check_snmp_cmd_output, duthost,
               get_bfr_queue_cntrs_cmd, expected_snmp_cnt_pre)
    queue_counters_cnt_pre = get_queue_ctrs(duthost, get_bfr_queue_cntrs_cmd)

    # Verify SNMP returns the expected number of counters based on
    # COUNTERS_QUEUE_NAME_MAP
    pytest_assert(
        (queue_counters_cnt_pre == expected_snmp_cnt_pre),
        "Snmpwalk Queue counters actual count {} differs from expected "
        "count {} (UC queues: {}, MC queues: {})".format(
            queue_counters_cnt_pre, expected_snmp_cnt_pre,
            queue_counts_pre['unicast'], queue_counts_pre['multicast']))

    # Remove buffer queue and reload and get number of queue counters
    # of selected interface
    del data['BUFFER_QUEUE'][buffer_queue_to_del]
    load_new_cfg(duthost, data, loganalyzer)

    # Re-query COUNTERS_QUEUE_NAME_MAP after config reload
    queue_counts_post = get_redis_queue_count_with_types(
        duthost, interface, asic)
    expected_snmp_cnt_post = calculate_expected_snmp_counters(
        queue_counts_post)

    wait_until(60, 20, 0, check_snmp_cmd_output, duthost,
               get_bfr_queue_cntrs_cmd, expected_snmp_cnt_post)
    queue_counters_cnt_post = get_queue_ctrs(duthost, get_bfr_queue_cntrs_cmd)

    pytest_assert(
        (queue_counters_cnt_post == expected_snmp_cnt_post),
        "Snmpwalk Queue counters actual count {} differs from expected "
        "count {} (UC queues: {}, MC queues: {})".format(
            queue_counters_cnt_post, expected_snmp_cnt_post,
            queue_counts_post['unicast'], queue_counts_post['multicast']))

    # For broadcom-dnx voq chassis, number of voq are fixed (static), which
    # cannot be modified dynamically. Hence, make sure the queue counters
    # before deletion and after deletion are same for broadcom-dnx voq chassis
    platform_asic = duthost.facts.get("platform_asic")
    if platform_asic == "broadcom-dnx" and duthost.sonichost.is_multi_asic:
        pytest_assert(
            (queue_counters_cnt_pre == queue_counters_cnt_post),
            "Queue counters actual count {} differs from expected values {}"
            .format(queue_counters_cnt_post, queue_counters_cnt_pre))
    # For other platforms, verify that removing a BUFFER_QUEUE entry reduces
    # the counter count.
    # The reduction depends on whether the removed queues were unicast-only
    # or included multicast:
    # - UC only: removed_queues * 4 (statsTypes 1,2,5,6)
    # - UC + MC: removed_queues * 8 (statsTypes 1-8)

    else:
        range_str = str(buffer_queue_to_del.split('|')[-1])
        if '-' in range_str:
            low = int(range_str.split('-')[0])
            high = int(range_str.split('-')[1])
            buffer_queues_removed = high - low + 1
        else:
            buffer_queues_removed = 1
        unicast_expected_diff = buffer_queues_removed * UNICAST_CTRS
        multicast_expected_diff = (
            unicast_expected_diff + (buffer_queues_removed * MULTICAST_CTRS))
        actual_diff = queue_counters_cnt_pre - queue_counters_cnt_post
        pytest_assert(
            actual_diff in [unicast_expected_diff, multicast_expected_diff],
            "Queue counter reduction {} does not match expected UC-only "
            "diff {} or UC+MC diff {}. Pre: {}, Post: {}".format(
                actual_diff, unicast_expected_diff, multicast_expected_diff,
                queue_counters_cnt_pre, queue_counters_cnt_post))


@pytest.fixture(autouse=True, scope="module")
def teardown(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """
    Teardown procedure for all test function.

    param duthosts: duthosts object
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    yield
    # Cleanup
    duthost.copy(src=ORIG_CFG_DB, dest=CFG_DB_PATH, remote_src=True)
    config_reload(duthost, config_source='config_db', safe_reload=True)
