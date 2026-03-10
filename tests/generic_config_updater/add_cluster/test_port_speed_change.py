import logging
import random
import re
import pytest
from tests.generic_config_updater.add_cluster.helpers import get_cfg_info_from_dut
from tests.generic_config_updater.add_cluster.helpers import acl_asic_shell_wrappper
from .platform_constants import PLATFORM_SUPPORTED_SPEEDS_MAP, PLATFORM_SPEED_LANES_MAP, SPEED_FEC_MAP
from tests.generic_config_updater.add_cluster.test_add_cluster import format_sonic_interface_dict
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until, is_ipv4_address, is_ipv6_address
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.common.platform.interface_utils import check_interface_status_of_up_ports
from tests.common.config_reload import config_reload
from tests.common.gu_utils import delete_tmpfile, expect_op_success, generate_tmpfile, apply_patch
from tests.generic_config_updater.add_cluster.helpers import get_active_interfaces, \
    remove_dataacl_table_single_dut, send_and_verify_traffic

pytestmark = [
    pytest.mark.topology("t2")
]

logger = logging.getLogger(__name__)
allure.logger = logger


# -----------------------------
# Attributes used by test for acl config
# -----------------------------
ACL_TABLE_NAME = "L3_TRANSPORT_TEST"
ACL_TABLE_STAGE_EGRESS = "egress"
ACL_TABLE_TYPE_L3 = "L3"
ACL_RULE_FILE_PATH = "generic_config_updater/add_cluster/acl/acl_rule_src_dst_port.json"
ACL_RULE_DST_FILE = "/tmp/test_add_cluster_acl_rule.json"
ACL_RULE_SKIP_VERIFICATION_LIST = [""]


# -----------------------------
# Fixtures
# -----------------------------
@pytest.fixture(scope="module")
def selected_random_port(config_facts):
    """Fixture that selects a random port"""
    active_ports = get_active_interfaces(config_facts)
    port_name = ""
    port_channel_members = []
    if 'PORTCHANNEL_MEMBER' not in config_facts:
        if len(active_ports) > 0:
            port_name = active_ports[0]
        logging.info(f"Selected random active port {port_name} to use for testing.")
        return port_name
    port_channel_member_facts = config_facts['PORTCHANNEL_MEMBER']
    for port_channel in list(port_channel_member_facts.keys()):
        for member in list(port_channel_member_facts[port_channel].keys()):
            port_channel_members.append(member)
    for port in active_ports:
        if port not in port_channel_members:
            port_role = config_facts['PORT'][port].get('role')
            if port_role and port_role != 'Ext':    # ensure port is front-panel port
                continue
            port_name = port
            break
    logging.info(f"Selected random active port {port_name} to use for testing.")
    return str(port_name)


@pytest.fixture(scope="module")
def selected_random_port_alias(mg_facts, selected_random_port):
    return mg_facts['minigraph_port_name_to_alias_map'].get(selected_random_port, selected_random_port)


@pytest.fixture(autouse=True)
def ignore_port_speed_loganalyzer_exceptions(duthosts, enum_downstream_dut_hostname, loganalyzer):
    """
       Ignore expected yang validation failure during port speed change
    """
    duthost = duthosts[enum_downstream_dut_hostname]
    if loganalyzer:
        ignoreRegex = [
            ".*ERR swss[0-9]*#orchagent.*doPortTask: Unsupported port.*speed",
        ]
        loganalyzer[duthost.hostname].ignore_regex.extend(ignoreRegex)

# -----------------------------
# Helper functions
# -----------------------------


def move_key_first(d, key):
    if key not in d:
        return d.copy()
    new = {key: d[key]}
    for k, v in d.items():
        if k != key:
            new[k] = v
    return new


def move_key_last(d, key):
    if key not in d:
        return d.copy()
    new = d.copy()
    val = new.pop(key)
    new[key] = val
    return new


def get_port_speed(duthost, cli_namespace_prefix, selected_random_port):
    cmd = 'sonic-db-cli {} CONFIG_DB hget \'PORT|{}\' speed'.format(cli_namespace_prefix, selected_random_port)
    return duthost.shell(cmd, module_ignore_errors=True)['stdout']


def get_port_fec(duthost, cli_namespace_prefix, selected_random_port):
    cmd = 'sonic-db-cli {} CONFIG_DB hget \'PORT|{}\' fec'.format(cli_namespace_prefix, selected_random_port)
    return duthost.shell(cmd, module_ignore_errors=True)['stdout']


def get_port_lanes(duthost, cli_namespace_prefix, selected_random_port):
    out = duthost.shell('sonic-db-cli {} CONFIG_DB hget \'PORT|{}\' lanes'.format(
        cli_namespace_prefix, selected_random_port))
    return out["stdout_lines"][0].split(',')


def get_target_speed(duthost, cli_namespace_prefix, selected_random_port):
    """
    Function that determines the target speed for a given port.
    Prints current speed, supported speeds, and selects a target speed to change to.
    Reads the supported speeds from the STATE_DB and picks a target speed other than the current one.

    Due to chip limitation (open ticket CS00012433083),
    as a workaround the target speed is selecting based on a platform mapping that provides the supported speeds.
    """

    current_speed = get_port_speed(duthost, cli_namespace_prefix, selected_random_port)
    logger.info(f"Current speed is {current_speed}")
    supported_statedb_speeds = get_supported_port_speeds(duthost, cli_namespace_prefix, selected_random_port)
    logger.info(f"Supported valid speeds for port based on STATE_DB: {supported_statedb_speeds}")
    supported_test_speeds = get_test_speeds(duthost)
    logger.info(f"Supported test speeds for port based on platform and test definition: {supported_test_speeds}")
    other_speeds = [s for s in supported_test_speeds if int(s) != int(current_speed)]
    target_speed = random.choice(other_speeds)
    pytest_assert(target_speed, "Failed to find any speed to change to.")

    return target_speed


def get_target_fec(duthost, cli_namespace_prefix, selected_random_port, target_speed):
    """
    Function that determines the target FEC for a given port and target speed.
    Prints current fec, supported fecs, and selects a target fec.
    Purpose is to identify proper fec value when we change speed and apply accordingly.
    For port proper function opposite end point (fanout) need to have fec set accordingly.
    For example:
        400G speeds might support rs fec while 100G speeds might support fc fec.
    """
    current_fec = get_port_fec(duthost, cli_namespace_prefix, selected_random_port)
    logger.info(f"Current fec for port: {current_fec}")
    target_fec = None
    supported_statedb_fecs = get_supported_port_fecs(duthost, cli_namespace_prefix, selected_random_port)
    logger.info(f"Supported valid fecs for port based on STATE_DB: {supported_statedb_fecs}")
    supported_fecs_per_speed = get_fec_for_speed(duthost, target_speed)
    pytest_assert(supported_fecs_per_speed, f"Failed to find any fec for speed {target_speed}.")
    logger.info(f"Supported test fecs for port based on targeted speed: {supported_fecs_per_speed}")
    for fec in supported_fecs_per_speed:
        if fec in supported_statedb_fecs:
            target_fec = fec
            break
    logger.info(f"Target fec is: {target_fec}")
    return target_fec


def get_supported_port_speeds(duthost, cli_namespace_prefix, selected_random_port):
    cmd = "sonic-db-cli {} STATE_DB HGET \"PORT_TABLE|{}\" \"supported_speeds\"".format(
        cli_namespace_prefix, selected_random_port)
    output = duthost.shell(cmd, module_ignore_errors=True)['stdout']
    valid_speeds = output.split(',')
    pytest_assert(valid_speeds, "Failed to get any valid port speed to change to.")
    return valid_speeds


def get_supported_port_fecs(duthost, cli_namespace_prefix, selected_random_port):
    cmd = "sonic-db-cli {} STATE_DB HGET \"PORT_TABLE|{}\" \"supported_fecs\"".format(
        cli_namespace_prefix, selected_random_port)
    output = duthost.shell(cmd, module_ignore_errors=True)['stdout']
    valid_fecs = output.split(',')
    pytest_assert(valid_fecs, "Failed to get any valid port fec to change to.")
    return valid_fecs


def verify_port_speed_in_dbs(duthost, enum_rand_one_frontend_asic_index, cli_namespace_prefix, selected_random_port,
                             verify=True):
    port_speed_config_db = ""
    port_speed_appl_db = ""
    port_speed_asic = "N/A"

    cmd = "sonic-db-cli {} CONFIG_DB HGET \"PORT|{}\" \"speed\"".format(cli_namespace_prefix, selected_random_port)
    port_speed_config_db = duthost.shell(cmd, module_ignore_errors=True)['stdout']

    cmd = "sonic-db-cli {} APPL_DB HGET \"PORT_TABLE:{}\" \"speed\"".format(cli_namespace_prefix, selected_random_port)
    port_speed_appl_db = duthost.shell(cmd, module_ignore_errors=True)['stdout']

    cmd = "sonic-db-cli {} APPL_DB HGET \"PORT_TABLE:{}\" \"core_port_id\"".format(
        cli_namespace_prefix, selected_random_port)
    core_port_id = duthost.shell(cmd, module_ignore_errors=True)['stdout']
    asic_type = duthost.facts['asic_type']
    if asic_type == "broadcom":
        cmd = "bcmcmd -n {} \"port status {}\"".format(enum_rand_one_frontend_asic_index, core_port_id)
        output = duthost.shell(cmd, module_ignore_errors=True)['stdout']
        m = re.search(r'\b\d+G\b', output)
        port_speed_asic = m.group(0) if m else None
        port_speed_asic = port_speed_asic.replace("G", "000")
    logger.info("Port speed values: CONFIG_DB={} APPL_DB={} ASIC-{}={}".format(
        port_speed_config_db, port_speed_appl_db, asic_type, port_speed_asic))
    pytest_assert(port_speed_config_db == port_speed_appl_db, "Speeds in CONFIG_DB and APPL_DB do not match!")
    if verify:
        pytest_assert(port_speed_config_db == port_speed_asic, "Speed in ASIC SAI does not match CONFIG_DB/APPL_DB!")


def get_interface_neighbor_and_intfs(mg_facts, selected_random_port):
    vm_neighbors = mg_facts['minigraph_neighbors']
    dut_interface = selected_random_port
    # if the interface is a portchannel member, resolve to actual member
    if (port_channel := mg_facts.get('minigraph_portchannels', {}).get(dut_interface)) is not None:
        dut_interface = port_channel['members'][0]
    neighbor_name = vm_neighbors[dut_interface]['name']
    neighbor_info = mg_facts['minigraph_bgp']
    neighbor_addr = []
    neighbor_ipv4_addr = ""
    neighbor_ipv6_addr = ""
    for neigh in neighbor_info:
        if neigh['name'] == neighbor_name:
            neighbor_addr.append(neigh['addr'])
            if is_ipv4_address(neigh['addr']):
                neighbor_ipv4_addr = neigh['addr']
            elif is_ipv6_address(neigh['addr']):
                neighbor_ipv6_addr = neigh['addr']
    neighbor_addr = list(set(neighbor_addr))
    logger.info(
        "Found neighbor {} with interfaces {} for duthost port {}. "
        "IPV4 interface: {} IPV6 interface: {}".format(
            neighbor_name, neighbor_addr, selected_random_port, neighbor_ipv4_addr, neighbor_ipv6_addr)
    )
    return neighbor_name, neighbor_addr, neighbor_ipv4_addr, neighbor_ipv6_addr


def get_num_lanes_per_speed(duthost, speed):
    return PLATFORM_SPEED_LANES_MAP.get(duthost.facts['platform']).get(speed, None)


def get_test_speeds(duthost):
    return PLATFORM_SUPPORTED_SPEEDS_MAP.get(duthost.facts['platform'], None)


def get_fec_for_speed(duthost, speed):
    return SPEED_FEC_MAP.get(speed, None)


def get_port_index_in_acl_table(duthost, enum_rand_one_asic_namespace, acl_table, port):

    cmd = "sudo sonic-db-cli -n {} CONFIG_DB HGET \"ACL_TABLE|{}\" ports@".format(enum_rand_one_asic_namespace,
                                                                                  acl_table)
    output = duthost.shell(cmd, module_ignore_errors=True)['stdout']
    ports_in_acl_table = output.split(',')
    pytest_assert(ports_in_acl_table, f"Failed to get any ports in acl table {acl_table}.")
    for index, p in enumerate(ports_in_acl_table):
        if p == port:
            return index
    return None


def apply_patch_change_port_cluster(config_facts,
                                    config_facts_localhost,
                                    mg_facts,
                                    duthost,
                                    enum_rand_one_asic_namespace,
                                    selected_random_port,
                                    selected_random_port_alias,
                                    cli_namespace_prefix,
                                    target_speed,
                                    operation=None,
                                    dry_run=False):
    """
    Apply patch to change cluster information for a port.
    """

    logger.info("Changing cluster information via apply-patch for interface {} of {} .".format(
        selected_random_port, enum_rand_one_asic_namespace))
    json_namespace = '' if enum_rand_one_asic_namespace is None else '/' + enum_rand_one_asic_namespace

    ##############
    # Patch Operation No.1
    ##############
    json_patch = []

    # ACL
    json_patch_acl = []
    for acl_table in ["DATAACL", "EVERFLOW", "EVERFLOWV6"]:
        if operation == "add":
            json_patch_acl.append({
                "op": "add",
                "path": "{}/ACL_TABLE/{}/ports/-".format(json_namespace, acl_table),
                "value": selected_random_port
            })
        elif operation == "remove":
            if acl_table not in config_facts["ACL_TABLE"]:
                continue
            port_index = get_port_index_in_acl_table(
                duthost, enum_rand_one_asic_namespace, acl_table, selected_random_port)
            if port_index is not None:
                json_patch_acl.append({
                    "op": "remove",
                    "path": "{}/ACL_TABLE/{}/ports/{}".format(json_namespace, acl_table, port_index)
                })

    # BGP_NEIGHBOR, DEVICE_NEIGHBOR, DEVICE_NEIGHBOR_METADATA
    bgp_neigh_name, bgp_neigh_intfs, bgp_neigh_ipv4, bgp_neigh_ipv6 = get_interface_neighbor_and_intfs(
        mg_facts, selected_random_port)
    for bgp_neigh_intf in bgp_neigh_intfs:
        bgp_neigh_intf = bgp_neigh_intf.lower()
        if operation == "add":
            json_patch.append({
                "op": "add",
                "path": "/localhost/BGP_NEIGHBOR/{}".format(bgp_neigh_intf),
                "value": config_facts_localhost["BGP_NEIGHBOR"][bgp_neigh_intf]
            })
        elif operation == "remove":
            json_patch.append({
                "op": "remove",
                "path": "/localhost/BGP_NEIGHBOR/{}".format(bgp_neigh_intf)
            })
    if operation == "add":
        json_patch.append({
            "op": "add",
            "path": "/localhost/DEVICE_NEIGHBOR/{}".format(selected_random_port_alias.replace("/", "~1")),
            "value": config_facts_localhost["DEVICE_NEIGHBOR"][selected_random_port_alias]
        })
        json_patch.append({
            "op": "add",
            "path": "/localhost/DEVICE_NEIGHBOR_METADATA/{}".format(bgp_neigh_name),
            "value": config_facts_localhost["DEVICE_NEIGHBOR_METADATA"][bgp_neigh_name]
        })
    elif operation == "remove":
        json_patch.append({
            "op": "remove",
            "path": "/localhost/DEVICE_NEIGHBOR_METADATA/{}".format(bgp_neigh_name)
        })
        json_patch.append({
            "op": "remove",
            "path": "/localhost/DEVICE_NEIGHBOR/{}".format(selected_random_port_alias.replace("/", "~1"))
        })
    for bgp_neigh_intf in bgp_neigh_intfs:
        bgp_neigh_intf = bgp_neigh_intf.lower()
        if operation == "add":
            json_patch.append({
                "op": "add",
                "path": "{}/BGP_NEIGHBOR/{}".format(json_namespace, bgp_neigh_intf),
                "value": config_facts["BGP_NEIGHBOR"][bgp_neigh_intf]
            })
        elif operation == "remove":
            json_patch.append({
                "op": "remove",
                "path": "{}/BGP_NEIGHBOR/{}".format(json_namespace, bgp_neigh_intf)
            })
    if operation == "add":
        json_patch.append({
            "op": "add",
            "path": "{}/DEVICE_NEIGHBOR/{}".format(json_namespace, selected_random_port),
            "value": config_facts["DEVICE_NEIGHBOR"][selected_random_port]
        })
        json_patch.append({
            "op": "add",
            "path": "{}/DEVICE_NEIGHBOR_METADATA/{}".format(json_namespace, bgp_neigh_name),
            "value": config_facts["DEVICE_NEIGHBOR_METADATA"][bgp_neigh_name]
        })
    elif operation == "remove":
        json_patch.append({
            "op": "remove",
            "path": "{}/DEVICE_NEIGHBOR/{}".format(json_namespace, selected_random_port)
        })
        json_patch.append({
            "op": "remove",
            "path": "{}/DEVICE_NEIGHBOR_METADATA/{}".format(json_namespace, bgp_neigh_name)
        })

    # INTERFACE
    interface_dict = {}
    all_int_dict = format_sonic_interface_dict(config_facts["INTERFACE"])
    for key, value in all_int_dict.items():
        updated_key = key
        if key.startswith(selected_random_port):
            updated_key = updated_key.replace("/", "~1")
            interface_dict[updated_key] = value
        else:
            continue
    if operation == "add":
        interface_dict = move_key_first(interface_dict, selected_random_port)
    elif operation == "remove":
        interface_dict = move_key_last(interface_dict, selected_random_port)
    localhost_interface_dict = {}
    for key, value in interface_dict.items():
        parts = key.split('|')
        updated_key = key
        if len(parts) == 2:
            port = parts[0]
            alias = mg_facts['minigraph_port_name_to_alias_map'].get(port, port)
            updated_key = "{}|{}".format(alias, parts[1])
        else:
            updated_key = mg_facts['minigraph_port_name_to_alias_map'].get(key, key)
        updated_key = updated_key.replace("/", "~1")
        localhost_interface_dict[updated_key] = value
    intf_paths_list = []
    intf_values_list = []
    for key, value in interface_dict.items():
        intf_paths_list.append(f"{json_namespace}/INTERFACE/{key}")
        intf_values_list.append(value)
    for key, value in localhost_interface_dict.items():
        intf_paths_list.append(f"/localhost/INTERFACE/{key}")
        intf_values_list.append(value)
    for path, value in zip(intf_paths_list, intf_values_list):
        if operation == "add":
            json_patch.append({
                "op": "add",
                "path": path,
                "value": value
            })
        elif operation == "remove":
            json_patch.append({
                "op": "remove",
                "path": path
            })

    # CABLE_LENGTH
    initial_cable_length_table = config_facts["CABLE_LENGTH"]["AZURE"]
    cable_length_values = [int(v.rstrip("m")) for v in initial_cable_length_table.values()]
    highest = max(cable_length_values)
    lowest = min(cable_length_values)
    if operation == "add":
        json_patch.append({
            "op": "add",
            "path": "{}/CABLE_LENGTH/AZURE/{}".format(json_namespace, selected_random_port),
            "value": f"{highest}m"
        })
    elif operation == "remove":
        json_patch.append({
            "op": "add",
            "path": "{}/CABLE_LENGTH/AZURE/{}".format(json_namespace, selected_random_port),
            "value": f"{lowest}m"
        })

    # PFC_WD
    if 'PFC_WD' in config_facts:
        if operation == "add":
            json_patch.append({
                "op": "add",
                "path": f"{json_namespace}/PFC_WD/{selected_random_port}",
                "value": config_facts["PFC_WD"][selected_random_port]
            })
        elif operation == "remove":
            json_patch.append({
                "op": "remove",
                "path": f"{json_namespace}/PFC_WD/{selected_random_port}"
            })

    # QUEUE
    cmd = f"sudo sonic-db-cli {cli_namespace_prefix} CONFIG_DB keys \
        'QUEUE|{duthost.hostname}|{enum_rand_one_asic_namespace}|{selected_random_port}*'"
    output = duthost.shell(cmd, module_ignore_errors=True)['stdout']
    queue_keys = [k.strip() for k in output.splitlines() if k.strip()]
    pytest_assert(queue_keys, f"No QUEUE keys found for port {selected_random_port}")
    for key in queue_keys:
        json_patch.append({
            "op": "remove",
            "path": f"{json_namespace}/{key.replace('QUEUE|', 'QUEUE/')}"
        })

    # PORT
    json_patch.append({
        "op": "add",
        "path": f"{json_namespace}/PORT/{selected_random_port}/admin_status",
        "value": "down"
    })
    current_lanes = get_port_lanes(duthost, cli_namespace_prefix, selected_random_port)
    start_lane = int(current_lanes[0])
    target_num_lanes = get_num_lanes_per_speed(duthost, target_speed)
    pytest_assert(target_num_lanes is not None, f"Could not determine num lanes for speed {target_speed}")
    new_lanes = ",".join(str(i) for i in range(start_lane, start_lane + target_num_lanes))
    json_patch.append({
        "op": "add",
        "path": f"{json_namespace}/PORT/{selected_random_port}/lanes",
        "value": new_lanes
    })
    json_patch.append({
        "op": "add",
        "path": f"{json_namespace}/PORT/{selected_random_port}/speed",
        "value": target_speed
    })
    current_fec = get_port_fec(duthost, cli_namespace_prefix, selected_random_port)
    # target_fec = get_target_fec(duthost, cli_namespace_prefix, selected_random_port, target_speed)
    target_fec = None
    if operation == "add":
        target_fec = config_facts["PORT"][selected_random_port].get("fec", None)
    elif operation == "remove":
        fec_values = get_fec_for_speed(duthost, target_speed)
        if fec_values:
            target_fec = random.choice(get_fec_for_speed(duthost, target_speed))
    if target_fec == "N/A":
        if current_fec:
            json_patch.append({
                "op": "remove",
                "path": f"{json_namespace}/PORT/{selected_random_port}/fec"
            })
    elif target_fec:
        json_patch.append({
            "op": "add",
            "path": f"{json_namespace}/PORT/{selected_random_port}/fec",
            "value": target_fec
        })

    # BUFFER_PG
    if operation == "add":
        json_patch.append({
            "op": "add",
            "path": f"{json_namespace}/BUFFER_PG/{selected_random_port}|0",
            "value": config_facts["BUFFER_PG"][selected_random_port]["0"]
        })
    if operation == "remove":
        cmd = f"sudo sonic-db-cli -n {enum_rand_one_asic_namespace} CONFIG_DB keys \
        'BUFFER_PG|{selected_random_port}|*'"
        output = duthost.shell(cmd, module_ignore_errors=True)['stdout']
        keys = [k.strip() for k in output.splitlines() if k.strip()]
        pytest_assert(output, f"No BUFFER_PG keys found for port {selected_random_port}")
        logger.info(f"BUFFER_PG keys for port {selected_random_port}: {keys}")
        for key in keys:
            json_patch.append({
                "op": "remove",
                "path": f"{json_namespace}/{key.replace('BUFFER_PG|', 'BUFFER_PG/')}"
                })

    # PORT_QOS_MAP
    if operation == "add":
        json_patch.append({
            "op": "add",
            "path": f"{json_namespace}/PORT_QOS_MAP/{selected_random_port}",
            "value": config_facts["PORT_QOS_MAP"][selected_random_port]
            })
    elif operation == "remove":
        json_patch.append({
            "op": "remove",
            "path": f"{json_namespace}/PORT_QOS_MAP/{selected_random_port}"
            })
    if operation == "add":
        json_patch = json_patch + json_patch_acl
        json_patch.append({
            "op": "add",
            "path": f"{json_namespace}/PORT/{selected_random_port}/admin_status",
            "value": "up"
            })
    elif operation == "remove":
        json_patch = json_patch_acl + json_patch

    # APPLY PATCH NO.1
    tmpfile = generate_tmpfile(duthost)
    try:
        logger.info(f"Applying patch to change port cluster info. Operation {operation}. Dry-run {dry_run}")
        logger.info(f"Patch content: {json_patch}")
        if not dry_run:
            output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
            expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile)

    ##############
    # Patch Operation No.2: QUEUE
    ##############

    # QUEUE
    json_patch_queues = []
    for key in queue_keys:
        json_patch_queues.append({
            "op": "add",
            "path": f"{json_namespace}/{key.replace('QUEUE|', 'QUEUE/')}",
            "value": config_facts["QUEUE"][duthost.hostname][key.replace(f'QUEUE|{duthost.hostname}|', '')]
        })

    # APPLY PATCH NO.2
    tmpfile = generate_tmpfile(duthost)
    try:
        logger.info(f"Applying patch to add queues info. Dry-run {dry_run}")
        logger.info(f"Patch content: {json_patch_queues}")
        if not dry_run:
            output = apply_patch(duthost, json_data=json_patch_queues, dest_file=tmpfile)
            expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile)


# -----------------------------
# Setup Fixtures/functions
# -----------------------------
def setup_acl_config(duthost, ip_netns_namespace_prefix):
    logger.info("Adding acl config.")
    remove_dataacl_table_single_dut("DATAACL", duthost)
    duthost.copy(src=ACL_RULE_FILE_PATH, dest=ACL_RULE_DST_FILE)
    cmds = [
            "config acl add table {} {} -s {}".format(ACL_TABLE_NAME, ACL_TABLE_TYPE_L3, ACL_TABLE_STAGE_EGRESS),
            "acl-loader update full --table_name {} {}".format(ACL_TABLE_NAME, ACL_RULE_DST_FILE)
        ]
    acl_asic_shell_wrappper(duthost, cmds)
    acl_tables = duthost.command("{} show acl table".format(ip_netns_namespace_prefix))["stdout_lines"]
    acl_rules = duthost.command("{} show acl rule".format(ip_netns_namespace_prefix))["stdout_lines"]
    logging.info(('\n'.join(acl_tables)))
    logging.info(('\n'.join(acl_rules)))


@pytest.fixture(scope="function")
def initialize_random_variables(enum_downstream_dut_hostname,
                                enum_upstream_dut_hostname,
                                enum_rand_one_frontend_asic_index,
                                enum_rand_one_asic_namespace,
                                ip_netns_namespace_prefix,
                                cli_namespace_prefix,
                                selected_random_port,
                                selected_random_port_alias):
    return enum_downstream_dut_hostname, enum_upstream_dut_hostname, enum_rand_one_frontend_asic_index, \
        enum_rand_one_asic_namespace, ip_netns_namespace_prefix, cli_namespace_prefix, \
        selected_random_port, selected_random_port_alias


@pytest.fixture(scope="function")
def initialize_facts(mg_facts,
                     config_facts,
                     config_facts_localhost):
    return mg_facts, config_facts, config_facts_localhost


@pytest.fixture(scope="function")
def setup_port_speed_change(duthosts,
                            loganalyzer,
                            initialize_random_variables,
                            initialize_facts):
    """
    Setup fixture to change port speed
    """

    # initial test env
    enum_downstream_dut_hostname, enum_upstream_dut_hostname, enum_rand_one_frontend_asic_index, \
        enum_rand_one_asic_namespace, ip_netns_namespace_prefix, cli_namespace_prefix, \
        selected_random_port, selected_random_port_alias = initialize_random_variables
    mg_facts, config_facts, config_facts_localhost = initialize_facts

    duthost = duthosts[enum_downstream_dut_hostname]

    speed_a = get_port_speed(duthost, cli_namespace_prefix, selected_random_port)
    speed_b = get_target_speed(duthost, cli_namespace_prefix, selected_random_port)

    if int(speed_b) < int(speed_a):
        logger.warning(f"Intermediate Speed B is {speed_b}. \
                       Main scenario will do speed upgrade ({speed_b} -> {speed_a})")
    else:
        logger.info(f"Intermediate Speed B is {speed_b}. \
                    Main scenario will do speed downgrade ({speed_b} -> {speed_a})")

    with allure.step("Disabling loganalyzer before removing cluster - changing speeds."):
        if loganalyzer and loganalyzer[duthost.hostname]:
            loganalyzer[duthost.hostname].add_start_ignore_mark()

    with allure.step("Changing speed to invalid speed (B). Removing cluster info. \
                     Expecting success operation AND ports down."):
        apply_patch_change_port_cluster(config_facts,
                                        config_facts_localhost,
                                        mg_facts,
                                        duthost,
                                        enum_rand_one_asic_namespace,
                                        selected_random_port,
                                        selected_random_port_alias,
                                        cli_namespace_prefix,
                                        speed_b,
                                        operation='remove',
                                        dry_run=False)

    with allure.step("Re-enabling loganalyzer before removing cluster - changing speeds."):
        if loganalyzer and loganalyzer[duthost.hostname]:
            loganalyzer[duthost.hostname].add_end_ignore_mark()

    with allure.step("Reload the system with config reload so as to simulate that we start with speed B"):
        duthost.shell("config save -y")
        config_reload(duthost, config_source='config_db', safe_reload=True)
        pytest_assert(wait_until(300, 20, 0, duthost.critical_services_fully_started),
                      "All critical services should be fully started!")

    with allure.step("Verify no config failures after reload by applying an empty patch."):
        tmpfile = generate_tmpfile(duthost)
        output = apply_patch(duthost, json_data=[], dest_file=tmpfile)
        expect_op_success(duthost, output)

    with allure.step("Verify speed B updated in DBs"):
        verify_port_speed_in_dbs(duthost, enum_rand_one_frontend_asic_index, cli_namespace_prefix,
                                 selected_random_port, verify=False)
        current_status_speed = get_port_speed(duthost, cli_namespace_prefix, selected_random_port)
        pytest_assert(current_status_speed == speed_b,
                      "Failed to properly configure interface speed to requested value {}".format(speed_b))
    yield

    # revert the config via minigraph as we have previously performed config save with invalid speed
    config_reload(duthost, config_source="minigraph", safe_reload=True)


# -----------------------------
# Test Definitions
# -----------------------------
def test_port_speed_change(tbinfo,
                           duthosts,
                           initialize_random_variables,
                           initialize_facts,
                           ptfadapter,
                           setup_port_speed_change):
    """
    Validates port speed change functionality via Generic Config Updater (GCU).
    This test verifies that port speed changes are correctly applied, including updates to
    the configuration database, buffer profiles, and hardware state. It also performs
    traffic scenarios with and without ACL rules to ensure successful data transmission,
    correct queue counters, and accurate ACL rule match counters.
    """

    # initial test env
    enum_downstream_dut_hostname, enum_upstream_dut_hostname, enum_rand_one_frontend_asic_index, \
        enum_rand_one_asic_namespace, ip_netns_namespace_prefix, cli_namespace_prefix, \
        selected_random_port, selected_random_port_alias = initialize_random_variables
    mg_facts, config_facts, config_facts_localhost = initialize_facts
    bgp_neigh_name, bgp_neigh_intfs, bgp_neigh_ipv4, bgp_neigh_ipv6 = get_interface_neighbor_and_intfs(
        mg_facts, selected_random_port)
    duthost = duthosts[enum_downstream_dut_hostname]
    duthost_up = duthosts[enum_upstream_dut_hostname]
    asic_id = enum_rand_one_frontend_asic_index
    asic_id_src = None
    asic_id_src_up = None
    for asic in duthost.get_asic_ids():
        if asic == asic_id:
            continue
        asic_id_src = asic
        break
    for asic in duthost_up.get_asic_ids():
        asic_id_src_up = asic
        break

    pytest_assert(
        asic_id_src is not None, "Couldn't find an asic id to be used for sending traffic. \
            Reserved asic id: {}. All available asic ids: {}".format(
            asic_id, duthost.get_asic_ids()
        )
    )
    pytest_assert(
        asic_id_src_up is not None, "Couldn't find an asic id to be used for sending traffic from upstream. \
            All available asic ids: {}".format(
            duthost_up.get_asic_ids()
        )
    )

    initial_speed = config_facts["PORT"][selected_random_port]["speed"]
    initial_cable_length = config_facts["CABLE_LENGTH"]["AZURE"][selected_random_port]
    initial_pg_lossless_profile_name = 'pg_lossless_{}_{}_profile'.format(initial_speed, initial_cable_length)

    with allure.step("Changing speed to initial speed (A) [{}]. Adding cluster info. \
                     Expecting success operation AND ports up.".format(initial_speed)):
        apply_patch_change_port_cluster(config_facts,
                                        config_facts_localhost,
                                        mg_facts,
                                        duthost,
                                        enum_rand_one_asic_namespace,
                                        selected_random_port,
                                        selected_random_port_alias,
                                        cli_namespace_prefix,
                                        initial_speed,
                                        operation='add',
                                        dry_run=False)

    with allure.step("Verify speed A updated in DBs - ports should be up"):
        verify_port_speed_in_dbs(duthost, enum_rand_one_frontend_asic_index, cli_namespace_prefix,
                                 selected_random_port, verify=True)
        current_status_speed = get_port_speed(duthost, cli_namespace_prefix, selected_random_port)
        pytest_assert(current_status_speed == initial_speed,
                      "Failed to properly configure interface back speed to requested value {}".format(initial_speed))
        pytest_assert(wait_until(300, 20, 0, check_interface_status_of_up_ports, duthost),
                      "Not all ports that are admin up on are operationally up")

    with allure.step("Verify new pg lossless profile created and assign to port"):
        # verify CONFIG_DB:BUFFER_PROFILE:BUFFER_PG
        current_buffer_profile_info = get_cfg_info_from_dut(duthost, 'BUFFER_PROFILE', enum_rand_one_asic_namespace)
        # current_buffer_pg_info = get_cfg_info_from_dut(duthost, 'BUFFER_PG', enum_rand_one_asic_namespace)
        pytest_assert(initial_pg_lossless_profile_name in current_buffer_profile_info,
                      "Expected buffer profile {} was not created in CONFIG_DB.".format(
                          initial_pg_lossless_profile_name))
        cmd = "sonic-db-cli -n {} APPL_DB keys BUFFER_PROFILE_TABLE:*".format(enum_rand_one_asic_namespace)
        current_buffer_profile_info_appl_db = duthost.shell(cmd)["stdout"]
        pytest_assert(initial_pg_lossless_profile_name in current_buffer_profile_info_appl_db,
                      "Expected buffer profile {} was not created in APPL_DB.".format(
                          initial_pg_lossless_profile_name))

    # add acl config
    setup_acl_config(duthost, ip_netns_namespace_prefix)

    # Traffic scenarios applied
    traffic_scenarios = [
        {"direction": "upstream->downstream", "dst_ip": bgp_neigh_ipv4, "count": 1000, "dscp": 3,
         "sport": 5000, "dport": 50, "verify": True, "expect_error": False, "match_rule": "RULE_100"},
        {"direction": "upstream->downstream", "dst_ip": bgp_neigh_ipv4, "count": 1000, "dscp": 3,
         "sport": 1234, "dport": 8080, "verify": True, "expect_error": True, "match_rule": "RULE_200"},
        {"direction": "upstream->downstream", "dst_ip": bgp_neigh_ipv4, "count": 1000, "dscp": 3,
         "sport": 1234, "dport": 50, "verify": True, "expect_error": False, "match_rule": None},
        {"direction": "downstream->downstream", "dst_ip": bgp_neigh_ipv4, "count": 1000, "dscp": 3,
         "sport": 5000, "dport": 50, "verify": True, "expect_error": False, "match_rule": "RULE_100"},
        {"direction": "downstream->downstream", "dst_ip": bgp_neigh_ipv4, "count": 1000, "dscp": 3,
         "sport": 1234, "dport": 8080, "verify": True, "expect_error": True, "match_rule": "RULE_200"},
        {"direction": "downstream->downstream", "dst_ip": bgp_neigh_ipv4, "count": 1000, "dscp": 3,
         "sport": 1234, "dport": 50, "verify": True, "expect_error": False, "match_rule": None}
    ]

    for traffic_scenario in traffic_scenarios:
        logger.info("Starting Data Traffic Scenario: {}".format(traffic_scenario))
        if traffic_scenario["direction"] == "upstream->downstream":
            src_duthost = duthost_up
            src_asic_index = asic_id_src_up
        elif traffic_scenario["direction"] == "downstream->downstream":
            src_duthost = duthost
            src_asic_index = asic_id_src
        else:
            pytest.fail("Unsupported direction for traffic scenario {}.".format(traffic_scenario["direction"]))

        duthost.shell('{} aclshow -c'.format(ip_netns_namespace_prefix))
        # send traffic
        send_and_verify_traffic(tbinfo, src_duthost, duthost, src_asic_index, asic_id,
                                ptfadapter,
                                dst_ip=traffic_scenario["dst_ip"],
                                dscp=traffic_scenario["dscp"],
                                count=traffic_scenario["count"],
                                sport=traffic_scenario["sport"],
                                dport=traffic_scenario["dport"],
                                verify=traffic_scenario["verify"],
                                expect_error=traffic_scenario["expect_error"])
        # verify acl counters
        acl_counters = duthost.show_and_parse('{} aclshow -a'.format(ip_netns_namespace_prefix))
        for acl_counter in acl_counters:
            if acl_counter["rule name"] in ACL_RULE_SKIP_VERIFICATION_LIST:
                continue
            pytest_assert(acl_counter["packets count"] == str(traffic_scenario["count"])
                          if acl_counter["rule name"] == traffic_scenario.get("match_rule")
                          else acl_counter["packets count"] == '0',
                          "Acl rule {} statistics are not as expected. Found value {}"
                          .format(acl_counter["rule name"], acl_counter["packets count"]))
