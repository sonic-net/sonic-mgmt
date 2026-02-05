import logging
import pytest
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.common.platform.interface_utils import check_interface_status_of_up_ports
from tests.common.config_reload import config_reload
from tests.common.gu_utils import delete_tmpfile, expect_op_success, generate_tmpfile
from tests.common.gu_utils import apply_patch
from tests.generic_config_updater.add_cluster.helpers import add_static_route, \
    clear_static_route, get_active_interfaces, get_cfg_info_from_dut, \
    get_exabgp_port_for_neighbor, remove_dataacl_table_single_dut, remove_static_route, \
    send_and_verify_traffic, verify_routev4_existence

pytestmark = [
        pytest.mark.topology("t2")
        ]

logger = logging.getLogger(__name__)
allure.logger = logger


# -----------------------------
# Attributes used by test for static route, acl config
# -----------------------------

EXABGP_BASE_PORT = 5000
NHIPV4 = '10.10.246.254'
STATIC_DST_IP = '1.1.1.1'

ACL_TABLE_NAME = "L3_TRANSPORT_TEST"
ACL_TABLE_STAGE_EGRESS = "egress"
ACL_TABLE_TYPE_L3 = "L3"
ACL_RULE_FILE_PATH = "generic_config_updater/add_cluster/acl/acl_rule_src_dst_port.json"
ACL_RULE_DST_FILE = "/tmp/test_add_cluster_acl_rule.json"
ACL_RULE_SKIP_VERIFICATION_LIST = [""]

# -----------------------------
# Helper functions that validate apply-patch changes
# -----------------------------


def verify_bgp_peers_removed_from_asic(duthost, namespace):
    logger.info("{}: Verifying bgp_neighbors info is removed.".format(duthost.hostname))
    cur_bgp_neighbors = get_cfg_info_from_dut(duthost, "BGP_NEIGHBOR", namespace)
    cur_device_neighbor = get_cfg_info_from_dut(duthost, "DEVICE_NEIGHBOR", namespace)
    cur_device_neighbor_metadata = get_cfg_info_from_dut(duthost, "DEVICE_NEIGHBOR_METADATA", namespace)
    pytest_assert(not cur_bgp_neighbors,
                  "Bgp neighbors info removal via apply-patch failed."
                  )
    pytest_assert(not cur_device_neighbor,
                  "Device neighbor info removal via apply-patch failed."
                  )
    pytest_assert(not cur_device_neighbor_metadata,
                  "Device neighbor metadata info removal via apply-patch failed."
                  )


# -----------------------------
# Helper functions that modify configuration via apply-patch
# -----------------------------


def remove_external_portchannels_for_chassis_packet(config_facts,
                                                    duthost,
                                                    json_namespace,
                                                    cli_namespace_prefix,
                                                    run_and_check):
    """
    Remove external PortChannels (non-BP) for chassis-packet switches.
    For chassis-packet switches, we need to preserve internal PortChannels with BP members.
    """
    # Identify external PortChannels (those without internal ports as members)
    # Internal ports: "Ethernet-BP*" (backplane)
    external_portchannels = set()
    for pc_name, members in config_facts.get("PORTCHANNEL_MEMBER", {}).items():
        has_internal_port = False
        for member_port in members.keys():
            # BP ports are internal
            if member_port.startswith("Ethernet-BP"):
                has_internal_port = True
                break
        # If no internal ports, it's an external PortChannel
        if not has_internal_port:
            external_portchannels.add(pc_name)

    logger.info(f"External PortChannels to remove: {external_portchannels}")
    internal_pcs = set(config_facts.get('PORTCHANNEL', {}).keys()) - external_portchannels
    logger.info(f"Internal PortChannels to preserve: {internal_pcs}")

    # PORTCHANNEL_INTERFACE - Remove only external PortChannel interfaces
    # Handle both base entry (PortChannel150) and IP prefix entries (PortChannel150|10.0.0.128/31)
    pc_if_entries_to_delete = []
    for pc_if_key, pc_if_value in config_facts.get("PORTCHANNEL_INTERFACE", {}).items():
        pc_name = pc_if_key.split('|')[0] if '|' in pc_if_key else pc_if_key
        if pc_name in external_portchannels:
            # Add base PortChannel entry to delete list
            pc_if_entries_to_delete.append(pc_if_key)

            # If value is a dict with IP prefixes, add those to delete list too
            if isinstance(pc_if_value, dict) and pc_if_value:
                for ip_prefix in pc_if_value.keys():
                    pc_if_ip_key = f"{pc_if_key}|{ip_prefix}"
                    pc_if_entries_to_delete.append(pc_if_ip_key)
        else:
            logger.info(f"Preserving internal PORTCHANNEL_INTERFACE: {pc_if_key}")

    # Now delete all collected entries
    logger.info(f"PORTCHANNEL_INTERFACE entries to delete: {pc_if_entries_to_delete}")
    for entry_key in pc_if_entries_to_delete:
        cmd = f"sudo sonic-db-cli {cli_namespace_prefix} CONFIG_DB del 'PORTCHANNEL_INTERFACE|{entry_key}'"
        run_and_check(json_namespace, cmd, f"Deleting external PORTCHANNEL_INTERFACE {entry_key}")

    # PORTCHANNEL_MEMBER - Remove only external PortChannel members
    for pc_name in config_facts.get("PORTCHANNEL_MEMBER", {}).keys():
        if pc_name in external_portchannels:
            for member in config_facts["PORTCHANNEL_MEMBER"][pc_name].keys():
                cmd = f"sudo sonic-db-cli {cli_namespace_prefix} CONFIG_DB del 'PORTCHANNEL_MEMBER|{pc_name}|{member}'"
                run_and_check(json_namespace, cmd, f"Deleting external PORTCHANNEL_MEMBER {pc_name}|{member}")
        else:
            logger.info(f"Preserving internal PORTCHANNEL_MEMBER: {pc_name}")

    # PORTCHANNEL - Remove only external PortChannels
    for pc_name in config_facts.get("PORTCHANNEL", {}).keys():
        if pc_name in external_portchannels:
            cmd = f"sudo sonic-db-cli {cli_namespace_prefix} CONFIG_DB del 'PORTCHANNEL|{pc_name}'"
            run_and_check(json_namespace, cmd, f"Deleting external PORTCHANNEL {pc_name}")
        else:
            logger.info(f"Preserving internal PORTCHANNEL: {pc_name}")

    return external_portchannels


def remove_cluster_via_sonic_db_cli_chassis_packet(config_facts,
                                                   config_facts_localhost,
                                                   mg_facts,
                                                   duthost,
                                                   enum_rand_one_asic_namespace,
                                                   cli_namespace_prefix):
    """
    Remove cluster information directly from CONFIG_DB using sonic-db-cli commands,
    bypassing YANG validation but safely and persistently.

    Performs same cleanup as apply_patch_remove_cluster:
    - ACL_TABLE
    - BGP_NEIGHBOR
    - DEVICE_NEIGHBOR
    - DEVICE_NEIGHBOR_METADATA
    - PORTCHANNEL
    - PORTCHANNEL_INTERFACE
    - PORTCHANNEL_MEMBER
    - INTERFACE
    - BUFFER_PG
    - CABLE_LENGTH
    - PORT_QOS_MAP
    - PORT
    """

    json_namespace = '' if enum_rand_one_asic_namespace is None else enum_rand_one_asic_namespace
    logger.info(f"Starting cluster removal for ASIC namespace: {json_namespace} (chassis-packet mode)")

    active_interfaces = get_active_interfaces(config_facts, duthost)

    def run_and_check(ns, cmd, desc):
        """Run a shell command on DUT and check for success."""
        logger.info(f"[{ns}] {desc}: {cmd}")
        res = duthost.shell(cmd, module_ignore_errors=True)
        if res["rc"] != 0:
            logger.warning(f"[WARN] Command failed: {cmd}\nstdout: {res['stdout']}\nstderr: {res['stderr']}")
            return False
        return True

    ######################
    # ASIC NAMESPACE
    ######################
    if json_namespace:
        logger.info(f"Cleaning up ASIC namespace: {json_namespace}")

        # BGP_NEIGHBOR, DEVICE_NEIGHBOR, DEVICE_NEIGHBOR_METADATA
        for table in ["BGP_NEIGHBOR", "DEVICE_NEIGHBOR", "DEVICE_NEIGHBOR_METADATA"]:
            cmd = f"sudo sonic-db-cli {cli_namespace_prefix} CONFIG_DB keys '{table}*' \
                | xargs -r -n1 sudo sonic-db-cli {cli_namespace_prefix} CONFIG_DB del"
            run_and_check(json_namespace, cmd, f"Clearing table {table}")

        # INTERFACE
        asic_interface_keys = []
        if "INTERFACE" in config_facts:
            for interface_key in config_facts["INTERFACE"].keys():
                # Skip Rec and BP interfaces
                if (interface_key.startswith("Ethernet-Rec") or
                        interface_key.startswith("Ethernet-BP")):
                    continue
                for key, _value in config_facts["INTERFACE"][interface_key].items():
                    asic_interface_keys.append(interface_key + '|' + key)
                asic_interface_keys.append(interface_key)
            for iface in asic_interface_keys:
                run_and_check(json_namespace,
                              f"sudo sonic-db-cli {cli_namespace_prefix} CONFIG_DB del 'INTERFACE|{iface}'",
                              f"Deleting INTERFACE {iface}")

        # ACL
        for acl_table in ["DATAACL", "EVERFLOW", "EVERFLOWV6"]:
            cmd = f"sudo sonic-db-cli {cli_namespace_prefix} CONFIG_DB hdel 'ACL_TABLE|{acl_table}' ports@"
            run_and_check(json_namespace, cmd, f"Removing ACL_TABLE {acl_table} ports")

        # PortChannel handling: Selective removal (preserving internal BP PortChannels)
        external_portchannels = remove_external_portchannels_for_chassis_packet(
            config_facts, duthost, json_namespace, cli_namespace_prefix, run_and_check
        )

        # CABLE_LENGTH - Skip BP interfaces for chassis-packet
        initial = config_facts["CABLE_LENGTH"]["AZURE"]
        lowest = min(int(v.rstrip("m")) for v in initial.values())
        for iface in active_interfaces:
            # Never modify BP interfaces for chassis-packet switches
            if iface.startswith("Ethernet-BP"):
                logger.info(f"Skipping cable length change for BP interface: {iface}")
                continue
            run_and_check(json_namespace,
                          f"sudo sonic-db-cli {cli_namespace_prefix} CONFIG_DB hset \
                            'CABLE_LENGTH|AZURE' {iface} '{lowest}m'",
                          f"Set cable length for {iface}"
                          )
        # PORT - Set admin status to down, but skip BP interfaces for chassis-packet
        for iface in active_interfaces:
            # Extra safety check: Never set BP interfaces to down for chassis-packet switches
            if iface.startswith("Ethernet-BP"):
                logger.info(f"Skipping admin down for BP interface: {iface}")
                continue
            run_and_check(json_namespace,
                          f"sudo sonic-db-cli {cli_namespace_prefix} CONFIG_DB hset 'PORT|{iface}' admin_status down",
                          f"Set {iface} admin down")

        # BUFFER_PG handling: Selective removal (preserving BP interfaces)
        buffer_pg_keys = config_facts.get("BUFFER_PG", {}).keys()
        for bp_key in buffer_pg_keys:
            interface = bp_key.split('|')[0]
            exclusion_prefixes = ["Ethernet-IB", "Ethernet-Rec", "Ethernet-BP"]
            if not any(interface.startswith(prefix) for prefix in exclusion_prefixes):
                run_and_check(json_namespace,
                              f"sudo sonic-db-cli {cli_namespace_prefix} CONFIG_DB del 'BUFFER_PG|{bp_key}'",
                              f"Deleting BUFFER_PG {bp_key}")

        # PORT_QOS_MAP - only for external interfaces (BP check only for chassis-packet)
        for iface in active_interfaces:
            if not iface.startswith("Ethernet-BP"):
                run_and_check(json_namespace,
                              f"sudo sonic-db-cli {cli_namespace_prefix} CONFIG_DB del 'PORT_QOS_MAP|{iface}'",
                              f"Deleting PORT_QOS_MAP for {iface}")

    ######################
    # LOCALHOST NAMESPACE
    ######################
    logger.info("Cleaning up localhost namespace")
    # BGP_NEIGHBOR
    for entry in config_facts["BGP_NEIGHBOR"].keys():
        run_and_check("localhost",
                      f"sudo sonic-db-cli CONFIG_DB del 'BGP_NEIGHBOR|{entry}'",
                      f"Deleting localhost BGP_NEIGHBOR {entry}")
    # DEVICE_NEIGHBOR_METADATA
    for entry in config_facts["DEVICE_NEIGHBOR_METADATA"].keys():
        run_and_check("localhost",
                      f"sudo sonic-db-cli CONFIG_DB del 'DEVICE_NEIGHBOR_METADATA|{entry}'",
                      f"Deleting localhost DEVICE_NEIGHBOR_METADATA {entry}")
    # INTERFACE
    localhost_interface_keys = []
    for key in asic_interface_keys:
        if key.startswith('Ethernet-Rec'):
            continue
        parts = key.split('|')
        key_to_remove = key
        if len(parts) == 2:
            port = parts[0]
            alias = mg_facts['minigraph_port_name_to_alias_map'].get(port, port)
            key_to_remove = "{}|{}".format(alias, parts[1])
        else:
            key_to_remove = mg_facts['minigraph_port_name_to_alias_map'].get(key, key)
        localhost_interface_keys.append(key_to_remove)
    for iface in localhost_interface_keys:
        run_and_check("localhost",
                      f"sudo sonic-db-cli CONFIG_DB del 'INTERFACE|{iface}'",
                      f"Deleting localhost INTERFACE {iface}")
    # PORTCHANNEL_INTERFACE - Remove only external PortChannels
    # Handle both base entry and IP prefix entries
    localhost_pc_if_entries_to_delete = []
    for entry, entry_value in config_facts.get("PORTCHANNEL_INTERFACE", {}).items():
        pc_name = entry.split('|')[0] if '|' in entry else entry
        if pc_name in external_portchannels:
            # Add base PortChannel entry to delete list
            localhost_pc_if_entries_to_delete.append(entry)

            # If value is a dict with IP prefixes, add those to delete list too
            if isinstance(entry_value, dict) and entry_value:
                for ip_prefix in entry_value.keys():
                    pc_if_ip_key = f"{entry}|{ip_prefix}"
                    localhost_pc_if_entries_to_delete.append(pc_if_ip_key)
        else:
            logger.info(f"Preserving localhost internal PORTCHANNEL_INTERFACE: {entry}")

    # Now delete all collected localhost entries
    logger.info(f"Localhost PORTCHANNEL_INTERFACE entries to delete: {localhost_pc_if_entries_to_delete}")
    for entry_key in localhost_pc_if_entries_to_delete:
        run_and_check("localhost",
                      f"sudo sonic-db-cli CONFIG_DB del 'PORTCHANNEL_INTERFACE|{entry_key}'",
                      f"Deleting localhost PORTCHANNEL_INTERFACE {entry_key}")

    # PORTCHANNEL_MEMBER - Remove only external PortChannels
    localhost_pc_member_dict = config_facts_localhost.get("PORTCHANNEL_MEMBER", {})
    for pc_key in config_facts.get("PORTCHANNEL", {}).keys():
        if pc_key in external_portchannels and pc_key in localhost_pc_member_dict:
            for member_key, _value in localhost_pc_member_dict[pc_key].items():
                key_to_remove = pc_key + '|' + member_key
                run_and_check("localhost",
                              f"sudo sonic-db-cli CONFIG_DB del 'PORTCHANNEL_MEMBER|{key_to_remove}'",
                              f"Deleting localhost PORTCHANNEL_MEMBER {key_to_remove}")
        elif pc_key not in external_portchannels:
            logger.info(f"Preserving localhost internal PORTCHANNEL_MEMBER: {pc_key}")

    # ACL localhost - need to remove only the entries from asic namespace
    for acl_table in ["DATAACL", "EVERFLOW", "EVERFLOWV6"]:
        run_and_check("localhost",
                      f"sudo sonic-db-cli CONFIG_DB hdel 'ACL_TABLE|{acl_table}' ports@",
                      f"Removing localhost ACL_TABLE {acl_table} ports")

    # PORTCHANNEL - Remove only external PortChannels
    for entry in config_facts.get("PORTCHANNEL", {}).keys():
        if entry in external_portchannels:
            run_and_check("localhost",
                          f"sudo sonic-db-cli CONFIG_DB del 'PORTCHANNEL|{entry}'",
                          f"Deleting localhost PORTCHANNEL {entry}")
        else:
            logger.info(f"Preserving localhost internal PORTCHANNEL: {entry}")


def apply_patch_remove_cluster_chassis_packet(config_facts,
                                              config_facts_localhost,
                                              mg_facts,
                                              duthost,
                                              enum_rand_one_asic_namespace,
                                              cli_namespace_prefix):
    """
    Apply patch to remove cluster information for chassis-packet switches.

    For chassis-packet switches, we preserve internal BP (backplane) interfaces and PortChannels.
    Only external PortChannels and non-BP interfaces are removed.

    Changes are perfomed to below tables:
    ACL_TABLE, BGP_NEIGHBOR, DEVICE_NEIGHBOR, DEVICE_NEIGHBOR_METADATA,
    PORTCHANNEL, PORTCHANNEL_INTERFACE, PORTCHANNEL_MEMBER,
    INTERFACE, BUFFER_PG, CABLE_LENGTH, PORT, PORT_QOS_MAP
    """

    logger.info("Removing cluster for namespace {} via apply-patch (chassis-packet mode)."
                .format(enum_rand_one_asic_namespace))

    json_patch_asic = []
    json_namespace = '' if enum_rand_one_asic_namespace is None else '/' + enum_rand_one_asic_namespace

    # find active ports
    active_interfaces = get_active_interfaces(config_facts, duthost)

    # Identify external PortChannels (those without BP members)
    external_portchannels = set()
    for pc_name, members in config_facts.get("PORTCHANNEL_MEMBER", {}).items():
        has_internal_port = False
        for member_port in members.keys():
            if (member_port.startswith("Ethernet-IB") or
                    member_port.startswith("Ethernet-Rec") or
                    member_port.startswith("Ethernet-BP")):
                has_internal_port = True
                break
        if not has_internal_port:
            external_portchannels.add(pc_name)
    logger.info(f"External PortChannels to remove: {external_portchannels}")
    internal_pcs = set(config_facts.get('PORTCHANNEL', {}).keys()) - external_portchannels
    logger.info(f"Internal PortChannels to preserve: {internal_pcs}")

    # W/A: TABLE:ACL_TABLE removing whole table instead of detaching ports
    json_patch_asic = [
        {
            "op": "remove",
            "path": f"{json_namespace}/ACL_TABLE/DATAACL"
        },
        {
            "op": "remove",
            "path": f"{json_namespace}/ACL_TABLE/EVERFLOW"
        },
        {
            "op": "remove",
            "path": f"{json_namespace}/ACL_TABLE/EVERFLOWV6"
        },
        {
            "op": "remove",
            "path": f"{json_namespace}/BGP_NEIGHBOR"
        },
        {
            "op": "remove",
            "path": f"{json_namespace}/DEVICE_NEIGHBOR"
        },
        {
            "op": "remove",
            "path": f"{json_namespace}/DEVICE_NEIGHBOR_METADATA"
        }
    ]

    # Remove PORTCHANNEL_MEMBER - only for external PortChannels
    portchannel_member_dict = config_facts.get("PORTCHANNEL_MEMBER", {})
    for pc_name in portchannel_member_dict.keys():
        if pc_name in external_portchannels:
            for member_port in portchannel_member_dict[pc_name].keys():
                json_patch_asic.append({
                    "op": "remove",
                    "path": f"{json_namespace}/PORTCHANNEL_MEMBER/{pc_name}|{member_port}"
                })

    # Remove PORTCHANNEL_INTERFACE - only for external PortChannels
    portchannel_interface_dict = config_facts.get("PORTCHANNEL_INTERFACE", {})
    for pc_if_key in portchannel_interface_dict.keys():
        pc_name = pc_if_key.split('|')[0] if '|' in pc_if_key else pc_if_key
        if pc_name in external_portchannels:
            json_patch_asic.append({
                "op": "remove",
                "path": f"{json_namespace}/PORTCHANNEL_INTERFACE/{pc_if_key.replace('/', '~1')}"
            })

    # Remove BUFFER_PG - only for non-BP interfaces (preserve BP, IB, Rec)
    buffer_pg_dict = config_facts.get("BUFFER_PG", {})
    for buffer_pg_key in buffer_pg_dict.keys():
        interface = buffer_pg_key.split('|')[0]
        if not any(interface.startswith(prefix) for prefix in ["Ethernet-IB", "Ethernet-Rec", "Ethernet-BP"]):
            json_patch_asic.append({
                "op": "remove",
                "path": f"{json_namespace}/BUFFER_PG/{buffer_pg_key.replace('/', '~1')}"
            })

    # table INTERFACE - Skip BP and Rec interfaces (chassis-packet specific)
    if 'INTERFACE' in config_facts:
        asic_interface_dict = config_facts["INTERFACE"]
        asic_interface_keys = []
        asic_interface_ip_prefix_keys = []
        for interface_key in asic_interface_dict.keys():
            if interface_key.startswith("Ethernet-Rec") or interface_key.startswith("Ethernet-BP"):
                continue
            for key, _value in asic_interface_dict[interface_key].items():
                key_to_remove = interface_key + '|' + key.replace("/", "~1")
                asic_interface_ip_prefix_keys.append(key_to_remove)
            asic_interface_keys.append(interface_key)

        for key in asic_interface_ip_prefix_keys:
            json_patch_asic.append({
                "op": "remove",
                "path": f"{json_namespace}/INTERFACE/{key}"
            })

    # table PORT_QOS_MAP changes - skip BP interfaces
    for interface in active_interfaces:
        if not any(interface.startswith(prefix) for prefix in ["Ethernet-IB", "Ethernet-Rec", "Ethernet-BP"]):
            json_patch_asic.append({
                "op": "remove",
                "path": "{}/PORT_QOS_MAP/{}".format(json_namespace, interface)
            })

    # table PORT changes - Set admin status to down, but skip BP interfaces
    for interface in active_interfaces:
        if not interface.startswith("Ethernet-BP"):
            json_patch_asic.append({
                "op": "add",
                "path": "{}/PORT/{}/admin_status".format(json_namespace, interface),
                "value": "down"
            })

    # table CABLE_LENGTH changes - Skip BP interfaces
    initial_cable_length_table = config_facts["CABLE_LENGTH"]["AZURE"]
    cable_length_values = [int(v.rstrip("m")) for v in initial_cable_length_table.values()]
    lowest = min(cable_length_values)
    for interface in active_interfaces:
        if not interface.startswith("Ethernet-BP"):
            json_patch_asic.append({
                "op": "add",
                "path": "{}/CABLE_LENGTH/AZURE/{}".format(json_namespace, interface),
                "value": f"{lowest}m"
            })

    # Apply ASIC namespace patch
    json_patch = json_patch_asic
    tmpfile = generate_tmpfile(duthost)
    try:
        logger.info("Applying patch (1/2) to remove cluster info (all except PORTCHANNEL, INTERFACE name) - "
                    "chassis-packet mode.")
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
        verify_bgp_peers_removed_from_asic(duthost, enum_rand_one_asic_namespace)
    finally:
        delete_tmpfile(duthost, tmpfile)

    # W/A TABLE:PORTCHANNEL, INTERFACE names needs to be removed in separate gcu apply operation
    json_patch_extra = []

    # Remove PORTCHANNEL - only external ones
    for pc_name in config_facts["PORTCHANNEL"].keys():
        if pc_name in external_portchannels:
            json_patch_extra.append({
                "op": "remove",
                "path": f"{json_namespace}/PORTCHANNEL/{pc_name}"
            })

    # Remove INTERFACE names
    interface_paths_to_remove = [f"{json_namespace}/INTERFACE/"]
    interface_keys_to_remove = [asic_interface_keys]
    for path, keys in zip(interface_paths_to_remove, interface_keys_to_remove):
        for k in keys:
            json_patch_extra.append({
                "op": "remove",
                "path": path + k
            })

    tmpfile_pc = generate_tmpfile(duthost)
    try:
        logger.info("Applying patch (2/2) to remove cluster info (PORTCHANNEL, INTERFACE name) - chassis-packet mode.")
        output = apply_patch(duthost, json_data=json_patch_extra, dest_file=tmpfile_pc)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile_pc)


def remove_cluster_via_sonic_db_cli(config_facts,
                                    config_facts_localhost,
                                    mg_facts,
                                    duthost,
                                    enum_rand_one_asic_namespace,
                                    cli_namespace_prefix):
    """
    Remove cluster information directly from CONFIG_DB using sonic-db-cli commands,
    bypassing YANG validation but safely and persistently.

    Performs same cleanup as apply_patch_remove_cluster:
    - ACL_TABLE
    - BGP_NEIGHBOR
    - DEVICE_NEIGHBOR
    - DEVICE_NEIGHBOR_METADATA
    - PORTCHANNEL
    - PORTCHANNEL_INTERFACE
    - PORTCHANNEL_MEMBER
    - INTERFACE
    - BUFFER_PG
    - CABLE_LENGTH
    - PORT_QOS_MAP
    - PORT
    """

    json_namespace = '' if enum_rand_one_asic_namespace is None else enum_rand_one_asic_namespace
    logger.info(f"Starting cluster removal for ASIC namespace: {json_namespace}")

    active_interfaces = get_active_interfaces(config_facts)
    success = True

    def run_and_check(ns, cmd, desc):
        """Run a shell command on DUT and check for success."""
        logger.info(f"[{ns}] {desc}: {cmd}")
        res = duthost.shell(cmd, module_ignore_errors=True)
        if res["rc"] != 0:
            logger.warning(f"[WARN] Command failed: {cmd}\nstdout: {res['stdout']}\nstderr: {res['stderr']}")
            return False
        return True

    ######################
    # ASIC NAMESPACE
    ######################
    if json_namespace:
        logger.info(f"Cleaning up ASIC namespace: {json_namespace}")

        # BGP_NEIGHBOR, DEVICE_NEIGHBOR, DEVICE_NEIGHBOR_METADATA
        for table in ["BGP_NEIGHBOR", "DEVICE_NEIGHBOR", "DEVICE_NEIGHBOR_METADATA"]:
            cmd = f"sudo sonic-db-cli {cli_namespace_prefix} CONFIG_DB keys '{table}*' \
                | xargs -r -n1 sudo sonic-db-cli {cli_namespace_prefix} CONFIG_DB del"
            run_and_check(json_namespace, cmd, f"Clearing table {table}")

        # INTERFACE
        asic_interface_keys = []
        for interface_key in config_facts["INTERFACE"].keys():
            if interface_key.startswith("Ethernet-Rec"):
                continue
            for key, _value in config_facts["INTERFACE"][interface_key].items():
                asic_interface_keys.append(interface_key + '|' + key)
            asic_interface_keys.append(interface_key)
        for iface in asic_interface_keys:
            run_and_check(json_namespace,
                          f"sudo sonic-db-cli {cli_namespace_prefix} CONFIG_DB del 'INTERFACE|{iface}'",
                          f"Deleting INTERFACE {iface}")

        # PORTCHANNEL_INTERFACE, PORTCHANNEL_MEMBER
        for table in ["PORTCHANNEL_INTERFACE", "PORTCHANNEL_MEMBER"]:
            cmd = f"sudo sonic-db-cli {cli_namespace_prefix} CONFIG_DB keys '{table}*' \
                | xargs -r -n1 sudo sonic-db-cli {cli_namespace_prefix} CONFIG_DB del"
            run_and_check(json_namespace, cmd, f"Clearing table {table}")

        # ACL
        for acl_table in ["DATAACL", "EVERFLOW", "EVERFLOWV6"]:
            cmd = f"sudo sonic-db-cli {cli_namespace_prefix} CONFIG_DB hdel 'ACL_TABLE|{acl_table}' ports@"
            run_and_check(json_namespace, cmd, f"Removing ACL_TABLE {acl_table} ports")

        # PORTCHANNEL
        cmd = f"sudo sonic-db-cli {cli_namespace_prefix} CONFIG_DB keys 'PORTCHANNEL*' \
            | xargs -r -n1 sudo sonic-db-cli {cli_namespace_prefix} CONFIG_DB del"
        run_and_check(json_namespace, cmd, "Clearing table PORTCHANNEL")

        # CABLE_LENGTH
        initial = config_facts["CABLE_LENGTH"]["AZURE"]
        lowest = min(int(v.rstrip("m")) for v in initial.values())
        for iface in active_interfaces:
            run_and_check(json_namespace,
                          f"sudo sonic-db-cli {cli_namespace_prefix} CONFIG_DB hset \
                            'CABLE_LENGTH|AZURE' {iface} '{lowest}m'",
                          f"Set cable length for {iface}"
                          )
        # PORT
        for iface in active_interfaces:
            run_and_check(json_namespace,
                          f"sudo sonic-db-cli {cli_namespace_prefix} CONFIG_DB hset 'PORT|{iface}' admin_status down",
                          f"Set {iface} admin down")
        # BUFFER_PG
        cmd = f"sudo sonic-db-cli {cli_namespace_prefix} CONFIG_DB keys 'BUFFER_PG*' \
            | xargs -r -n1 sudo sonic-db-cli {cli_namespace_prefix} CONFIG_DB del"
        run_and_check(json_namespace, cmd, "Clearing table BUFFER_PG")

        # PORT_QOS_MAP
        for iface in active_interfaces:
            run_and_check(json_namespace,
                          f"sudo sonic-db-cli {cli_namespace_prefix} CONFIG_DB del 'PORT_QOS_MAP|{iface}'",
                          f"Deleting PORT_QOS_MAP for {iface}")

    ######################
    # LOCALHOST NAMESPACE
    ######################
    logger.info("Cleaning up localhost namespace")
    # BGP_NEIGHBOR
    for entry in config_facts["BGP_NEIGHBOR"].keys():
        run_and_check("localhost",
                      f"sudo sonic-db-cli CONFIG_DB del 'BGP_NEIGHBOR|{entry}'",
                      f"Deleting localhost BGP_NEIGHBOR {entry}")
    # DEVICE_NEIGHBOR_METADATA
    for entry in config_facts["DEVICE_NEIGHBOR_METADATA"].keys():
        run_and_check("localhost",
                      f"sudo sonic-db-cli CONFIG_DB del 'DEVICE_NEIGHBOR_METADATA|{entry}'",
                      f"Deleting localhost DEVICE_NEIGHBOR_METADATA {entry}")
    # INTERFACE
    localhost_interface_keys = []
    for key in asic_interface_keys:
        if key.startswith('Ethernet-Rec'):
            continue
        parts = key.split('|')
        key_to_remove = key
        if len(parts) == 2:
            port = parts[0]
            alias = mg_facts['minigraph_port_name_to_alias_map'].get(port, port)
            key_to_remove = "{}|{}".format(alias, parts[1])
        else:
            key_to_remove = mg_facts['minigraph_port_name_to_alias_map'].get(key, key)
        localhost_interface_keys.append(key_to_remove)
    for iface in localhost_interface_keys:
        run_and_check("localhost",
                      f"sudo sonic-db-cli CONFIG_DB del 'INTERFACE|{iface}'",
                      f"Deleting localhost INTERFACE {iface}")
    # PORTCHANNEL_INTERFACE
    for entry in config_facts.get("PORTCHANNEL_INTERFACE", {}).keys():
        run_and_check("localhost",
                      f"sudo sonic-db-cli CONFIG_DB del 'PORTCHANNEL_INTERFACE|{entry}'",
                      f"Deleting localhost PORTCHANNEL_INTERFACE {entry}")
    # PORTCHANNEL_MEMBER
    pc_keys = config_facts.get("PORTCHANNEL", {}).keys()
    localhost_pc_member_dict = config_facts_localhost.get("PORTCHANNEL_MEMBER", {})
    localhost_pc_member_keys = []
    for pc_key in pc_keys:
        if pc_key in localhost_pc_member_dict:
            for key, _value in localhost_pc_member_dict[pc_key].items():
                key_to_remove = pc_key + '|' + key
                localhost_pc_member_keys.append(key_to_remove)
    for entry in localhost_pc_member_keys:
        run_and_check("localhost",
                      f"sudo sonic-db-cli CONFIG_DB del 'PORTCHANNEL_MEMBER|{entry}'",
                      f"Deleting localhost PORTCHANNEL_MEMBER {entry}")
    # ACL localhost - need to remove only the entries from asic namespace
    for acl_table in ["DATAACL", "EVERFLOW", "EVERFLOWV6"]:
        run_and_check("localhost",
                      f"sudo sonic-db-cli CONFIG_DB hdel 'ACL_TABLE|{acl_table}' ports@",
                      f"Removing localhost ACL_TABLE {acl_table} ports")
    # PORTCHANNEL
    for entry in config_facts("PORTCHANNEL", {}).keys():
        run_and_check("localhost",
                      f"sudo sonic-db-cli CONFIG_DB del 'PORTCHANNEL|{entry}'",
                      f"Deleting localhost PORTCHANNEL {entry}")

    # Partial Verification
    logger.info("Verifying that asic tables were cleared...")
    tables_to_check = [
        "BGP_NEIGHBOR", "DEVICE_NEIGHBOR", "DEVICE_NEIGHBOR_METADATA",
        "PORTCHANNEL_INTERFACE", "PORTCHANNEL_MEMBER", "PORTCHANNEL"
    ]
    for table in tables_to_check:
        cmd = f"sudo sonic-db-cli {cli_namespace_prefix} CONFIG_DB keys '{table}*'"
        res = duthost.shell(cmd, module_ignore_errors=True)
        if res["stdout"].strip():
            logger.warning(f"{table} still contains entries: {res['stdout']}")
            success = False
        else:
            logger.info(f"{table} is empty")

    if success:
        logger.info("Cluster removal completed successfully.")
    else:
        logger.warning("Cluster removal incomplete — verification failure.")


def apply_patch_remove_cluster(config_facts,
                               config_facts_localhost,
                               mg_facts,
                               duthost,
                               enum_rand_one_asic_namespace,
                               cli_namespace_prefix):
    """
    Apply patch to remove cluster information for a given ASIC namespace.

    Changes are perfomed to below tables:

    ACL_TABLE
    BGP_NEIGHBOR
    DEVICE_NEIGHBOR
    DEVICE_NEIGHBOR_METADATA
    PORTCHANNEL
    PORTCHANNEL_INTERFACE
    PORTCHANNEL_MEMBER
    INTERFACE
    BUFFER_PG
    CABLE_LENGTH
    PORT
    PORT_QOS_MAP

    """

    logger.info("Removing cluster for namespace {} via apply-patch.".format(enum_rand_one_asic_namespace))

    ######################
    # ASIC NAMESPACE
    ######################
    json_patch_asic = []
    logger.info("{}: Removing cluster info for namespace {}".format(duthost.hostname, enum_rand_one_asic_namespace))
    json_namespace = '' if enum_rand_one_asic_namespace is None else '/' + enum_rand_one_asic_namespace

    asic_paths_list = []

    # find active ports
    active_interfaces = get_active_interfaces(config_facts)

    # W/A: TABLE:ACL_TABLE removing whole table instead of detaching ports
    # https://github.com/sonic-net/sonic-buildimage/issues/24295

    # op: remove
    json_patch_asic = [
        {
            "op": "remove",
            "path": f"{json_namespace}/ACL_TABLE/DATAACL"
        },
        {
            "op": "remove",
            "path": f"{json_namespace}/ACL_TABLE/EVERFLOW"
        },
        {
            "op": "remove",
            "path": f"{json_namespace}/ACL_TABLE/EVERFLOWV6"
        },
        {
            "op": "remove",
            "path": f"{json_namespace}/BGP_NEIGHBOR"
        },
        {
            "op": "remove",
            "path": f"{json_namespace}/DEVICE_NEIGHBOR"
        },
        {
            "op": "remove",
            "path": f"{json_namespace}/DEVICE_NEIGHBOR_METADATA"
        },
        {
            "op": "remove",
            "path": f"{json_namespace}/BUFFER_PG"
        }
    ]

    if 'PORTCHANNEL' in config_facts:
        json_patch_asic.append(
            {
                "op": "remove",
                "path": f"{json_namespace}/PORTCHANNEL_MEMBER"
            }
        )
        json_patch_asic.append(
            {
                "op": "remove",
                "path": f"{json_namespace}/PORTCHANNEL_INTERFACE"
            }
        )

    # table INTERFACE
    if 'INTERFACE' in config_facts:
        asic_interface_dict = config_facts["INTERFACE"]
        asic_interface_keys = []
        asic_interface_ip_prefix_keys = []
        for interface_key in asic_interface_dict.keys():
            if interface_key.startswith("Ethernet-Rec"):
                continue
            for key, _value in asic_interface_dict[interface_key].items():
                key_to_remove = interface_key + '|' + key.replace("/", "~1")
                asic_interface_ip_prefix_keys.append(key_to_remove)
            asic_interface_keys.append(interface_key)

        for key in asic_interface_ip_prefix_keys:
            asic_paths_list.append(f"{json_namespace}/INTERFACE/" + key)

        for path in asic_paths_list:
            json_patch_asic.append({
                "op": "remove",
                "path": path
            })

    # table PORT_QOS_MAP changes
    for interface in active_interfaces:
        json_patch_asic.append({
            "op": "remove",
            "path": "{}/PORT_QOS_MAP/{}".format(json_namespace, interface)
        })

    # table PORT changes
    for interface in active_interfaces:
        json_patch_asic.append({
            "op": "add",
            "path": "{}/PORT/{}/admin_status".format(json_namespace, interface),
            "value": "down"
        })

    # table CABLE_LENGTH changes
    initial_cable_length_table = config_facts["CABLE_LENGTH"]["AZURE"]
    cable_length_values = [int(v.rstrip("m")) for v in initial_cable_length_table.values()]
    lowest = min(cable_length_values)
    for interface in active_interfaces:
        json_patch_asic.append({
            "op": "add",
            "path": "{}/CABLE_LENGTH/AZURE/{}".format(json_namespace, interface),
            "value": f"{lowest}m"
        })
    ######################
    # LOCALHOST NAMESPACE
    ######################
    json_patch_localhost = []
    logger.info("{}: Removing cluster info for namespace localhost".format(duthost.hostname))

    # INTERFACE TABLE: in localhost replace the interface name with the interface alias
    # INTERFACE ip-prefix
    if 'INTERFACE' in config_facts:
        localhost_ip_prefix_interface_keys = []
        for key in asic_interface_ip_prefix_keys:
            parts = key.split('|')
            port = parts[0]
            alias = mg_facts['minigraph_port_name_to_alias_map'].get(port, port)
            key_to_remove = "{}|{}".format(alias, parts[1])
            key_to_remove = key_to_remove.replace("/", "~1")
            localhost_ip_prefix_interface_keys.append(key_to_remove)
        # INTERFACE name
        localhost_interface_keys = []
        for key in asic_interface_keys:
            key_to_remove = mg_facts['minigraph_port_name_to_alias_map'].get(key, key)
            key_to_remove = key_to_remove.replace("/", "~1")
            localhost_interface_keys.append(key_to_remove)

    # PORTCHANNEL_MEMBER keys
    if 'PORTCHANNEL' in config_facts:
        pc_keys = config_facts.get("PORTCHANNEL", {}).keys()

        localhost_pc_member_dict = config_facts_localhost.get("PORTCHANNEL_MEMBER", {})
        localhost_pc_member_keys = []
        for pc_key in pc_keys:
            if pc_key in localhost_pc_member_dict:
                for key, _value in localhost_pc_member_dict[pc_key].items():
                    key_to_remove = pc_key + '|' + key.replace("/", "~1")
                    localhost_pc_member_keys.append(key_to_remove)
        # PORTCHANNEL_INTERFACE keys
        localhost_pc_interface_dict = config_facts_localhost.get("PORTCHANNEL_INTERFACE", {})
        localhost_pc_interface_keys = []
        for pc_key in pc_keys:
            if pc_key in localhost_pc_interface_dict:
                for key, _value in localhost_pc_interface_dict[pc_key].items():
                    key_to_remove = pc_key + '|' + key.replace("/", "~1")
                    localhost_pc_interface_keys.append(key_to_remove)
                localhost_pc_interface_keys.append(pc_key)

    # ACL TABLE
    acl_ports_localhost = config_facts_localhost["ACL_TABLE"]["DATAACL"]["ports"]
    acl_ports_asic = config_facts["ACL_TABLE"]["DATAACL"]["ports"]
    acl_ports_localhost_post_removal = [p for p in acl_ports_localhost if p not in acl_ports_asic]
    if acl_ports_localhost_post_removal:
        json_patch_localhost = [
            {
                "op": "add",
                "path": "/localhost/ACL_TABLE/DATAACL/ports",
                "value": acl_ports_localhost_post_removal
            },
            {
                "op": "add",
                "path": "/localhost/ACL_TABLE/EVERFLOW/ports",
                "value": acl_ports_localhost_post_removal
            },
            {
                "op": "add",
                "path": "/localhost/ACL_TABLE/EVERFLOWV6/ports",
                "value": acl_ports_localhost_post_removal
            }
        ]
    localhost_paths_list = []
    localhost_paths_to_remove = ["/localhost/BGP_NEIGHBOR/",
                                 "/localhost/DEVICE_NEIGHBOR_METADATA/"
                                 ]
    localhost_keys_to_remove = [
        config_facts["BGP_NEIGHBOR"].keys() if config_facts.get("BGP_NEIGHBOR") else [],
        config_facts["DEVICE_NEIGHBOR_METADATA"].keys() if config_facts.get("DEVICE_NEIGHBOR_METADATA") else [],
    ]
    if 'INTERFACE' in config_facts:
        localhost_paths_to_remove.append("/localhost/INTERFACE/")
        localhost_keys_to_remove.append(localhost_ip_prefix_interface_keys)
    if 'PORTCHANNEL' in config_facts:
        localhost_paths_to_remove.append("/localhost/PORTCHANNEL_MEMBER/")
        localhost_paths_to_remove.append("/localhost/PORTCHANNEL_INTERFACE/")
        localhost_keys_to_remove.append(localhost_pc_member_keys)
        localhost_keys_to_remove.append(localhost_pc_interface_keys)

    for path, keys in zip(localhost_paths_to_remove, localhost_keys_to_remove):
        for k in keys:
            localhost_paths_list.append(path + k)
    for path in localhost_paths_list:
        json_patch_localhost.append({
            "op": "remove",
            "path": path
        })

    #####################################
    # combine localhost and ASIC patch data
    #####################################
    json_patch = json_patch_localhost + json_patch_asic
    tmpfile = generate_tmpfile(duthost)
    try:
        logger.info("Applying patch (1/2) to remove cluster info (all except PORTCHANNEL, INTERFACE name).")
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
        verify_bgp_peers_removed_from_asic(duthost, enum_rand_one_asic_namespace)
    finally:
        delete_tmpfile(duthost, tmpfile)

    # W/A TABLE:PORTCHANNEL, INTERFACE names needs to be removed in separate gcu apply operation
    # https://github.com/sonic-net/sonic-buildimage/issues/24338
    json_patch_extra = []
    if 'PORTCHANNEL' in config_facts:
        json_patch_extra = [
            {
                "op": "remove",
                "path": f"{json_namespace}/PORTCHANNEL"
            }
        ]
        for key, _value in config_facts.get("PORTCHANNEL", {}).items():
            json_patch_extra.append({
                "op": "remove",
                "path": "/localhost/PORTCHANNEL/{}".format(key),
            })
    interface_paths_list = []
    interface_paths_to_remove = [f"{json_namespace}/INTERFACE/", "/localhost/INTERFACE/"]
    interface_keys_to_remove = [asic_interface_keys, localhost_interface_keys]
    for path, keys in zip(interface_paths_to_remove, interface_keys_to_remove):
        for k in keys:
            interface_paths_list.append(path + k)
    for path in interface_paths_list:
        json_patch_extra.append({
            "op": "remove",
            "path": path
        })

    tmpfile_pc = generate_tmpfile(duthost)
    try:
        logger.info("Applying patch (2/2) to remove cluster info (PORTCHANNEL, INTERFACE name).")
        output = apply_patch(duthost, json_data=json_patch_extra, dest_file=tmpfile_pc)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile_pc)


def apply_patch_add_cluster(config_facts,
                            config_facts_localhost,
                            mg_facts,
                            duthost,
                            enum_rand_one_asic_namespace):
    """
    Apply patch to add cluster information for a given ASIC namespace.

    Changes are perfomed to below tables:

    ACL_TABLE
    BGP_NEIGHBOR
    DEVICE_NEIGHBOR
    DEVICE_NEIGHBOR_METADATA
    PORTCHANNEL
    PORTCHANNEL_INTERFACE
    PORTCHANNEL_MEMBER
    INTERFACE
    BUFFER_PG
    CABLE_LENGTH
    PORT
    PORT_QOS_MAP
    """

    logger.info("Adding cluster for namespace {} via apply-patch.".format(enum_rand_one_asic_namespace))

    ######################
    # ASIC NAMESPACE
    ######################
    json_patch_asic = []
    json_namespace = '' if enum_rand_one_asic_namespace is None else '/' + enum_rand_one_asic_namespace
    pc_dict = {}
    interface_dict = format_sonic_interface_dict(config_facts.get("INTERFACE", {}))
    portchannel_interface_dict = format_sonic_interface_dict(config_facts.get("PORTCHANNEL_INTERFACE", {}))
    portchannel_member_dict = format_sonic_interface_dict(config_facts.get("PORTCHANNEL_MEMBER", {}),
                                                          single_entry=False)
    buffer_pg_dict = format_sonic_buffer_pg_dict(config_facts.get("BUFFER_PG", {}))
    pc_dict = {
        k: {ik: iv for ik, iv in v.items() if ik != "members"}
        for k, v in config_facts.get("PORTCHANNEL", {}).items()
    }

    # find active ports
    active_interfaces = get_active_interfaces(config_facts)

    # PORTCHANNEL info needs to be added in separate gcu apply operation
    # https://github.com/sonic-net/sonic-buildimage/issues/24338
    if pc_dict:
        json_patch_pc = [
            {
                "op": "add",
                "path": f"{json_namespace}/PORTCHANNEL",
                "value": pc_dict
            }
        ]
        for pc_key, pc_value in pc_dict.items():
            json_patch_pc.append({
                "op": "add",
                "path": "/localhost/PORTCHANNEL/{}".format(pc_key),
                "value": pc_value
            })
        tmpfile_pc = generate_tmpfile(duthost)
        try:
            logger.info("Applying patch (1/2) to add cluster info (PORTCHANNEL).")
            output = apply_patch(duthost, json_data=json_patch_pc, dest_file=tmpfile_pc)
            expect_op_success(duthost, output)
        finally:
            delete_tmpfile(duthost, tmpfile_pc)

    # op: add
    json_patch_asic = [
        {
            "op": "add",
            "path": f"{json_namespace}/BGP_NEIGHBOR",
            "value": config_facts["BGP_NEIGHBOR"]
        },
        {
            "op": "add",
            "path": f"{json_namespace}/DEVICE_NEIGHBOR",
            "value": config_facts["DEVICE_NEIGHBOR"]
        },
        {
            "op": "add",
            "path": f"{json_namespace}/DEVICE_NEIGHBOR_METADATA",
            "value": config_facts["DEVICE_NEIGHBOR_METADATA"]
        },
        {
            "op": "add",
            "path": f"{json_namespace}/INTERFACE",
            "value": interface_dict
        },
        {
            "op": "add",
            "path": f"{json_namespace}/BUFFER_PG",
            "value": buffer_pg_dict
        },
        {
            "op": "add",
            "path": f"{json_namespace}/PORT_QOS_MAP",
            "value": config_facts["PORT_QOS_MAP"]
        }
    ]

    if 'PORTCHANNEL' in config_facts:
        json_patch_asic.append({
            "op": "add",
            "path": f"{json_namespace}/PORTCHANNEL_MEMBER",
            "value": portchannel_member_dict
        })
        json_patch_asic.append({
            "op": "add",
            "path": f"{json_namespace}/PORTCHANNEL_INTERFACE",
            "value": portchannel_interface_dict
        })

    # table PORT changes
    for interface in active_interfaces:
        json_patch_asic.append({
            "op": "add",
            "path": "{}/PORT/{}/admin_status".format(json_namespace, interface),
            "value": "up"
        })

    # table CABLE_LENGTH changes
    initial_cable_length_table = config_facts["CABLE_LENGTH"]["AZURE"]
    cable_length_values = [int(v.rstrip("m")) for v in initial_cable_length_table.values()]
    highest = max(cable_length_values)
    for interface in active_interfaces:
        json_patch_asic.append({
            "op": "add",
            "path": "{}/CABLE_LENGTH/AZURE/{}".format(json_namespace, interface),
            "value": f"{highest}m"
        })

    # table ACL_TABLE changes
    json_patch_asic.append({
        "op": "add",
        "path": f"{json_namespace}/ACL_TABLE/DATAACL",
        "value": config_facts["ACL_TABLE"]["DATAACL"]
    })
    json_patch_asic.append({
        "op": "add",
        "path": f"{json_namespace}/ACL_TABLE/EVERFLOW",
        "value": config_facts["ACL_TABLE"]["EVERFLOW"]
    })
    json_patch_asic.append({
        "op": "add",
        "path": f"{json_namespace}/ACL_TABLE/EVERFLOWV6",
        "value": config_facts["ACL_TABLE"]["EVERFLOWV6"]
    })

    ######################
    # LOCALHOST NAMESPACE
    ######################

    json_patch_localhost = []

    # INTERFACE keys: in localhost replace the interface name with the interface alias
    localhost_interface_dict = {}
    for key, value in interface_dict.items():
        if key.startswith('Ethernet-Rec'):
            continue
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

    # identify the keys to add
    localhost_add_paths_list = []
    localhost_add_values_list = []
    for k, v in list(config_facts["BGP_NEIGHBOR"].items()):
        localhost_add_paths_list.append('/localhost/BGP_NEIGHBOR/{}'.format(k))
        localhost_add_values_list.append(v)
    for k, v in list(config_facts["DEVICE_NEIGHBOR"].items()):
        localhost_add_paths_list.append('/localhost/DEVICE_NEIGHBOR/{}'.format(k))
        localhost_add_values_list.append(v)
    for k, v in list(config_facts["DEVICE_NEIGHBOR_METADATA"].items()):
        localhost_add_paths_list.append('/localhost/DEVICE_NEIGHBOR_METADATA/{}'.format(k))
        localhost_add_values_list.append(v)
    for k, v in list(localhost_interface_dict.items()):
        localhost_add_paths_list.append("/localhost/INTERFACE/{}".format(k))
        localhost_add_values_list.append(v)

    if 'PORTCHANNEL' in config_facts:
        # PORTCHANNEL INTERFACE
        localhost_pc_interface_dict = {}
        for key, value in portchannel_interface_dict.items():
            updated_key = key.replace('/', '~1')
            localhost_pc_interface_dict[updated_key] = value
        # PORTCHANNEL_MEMBER keys
        localhost_pc_member_dict = {}
        for key, value in portchannel_member_dict.items():
            parts = key.split('|')
            updated_key = key
            if len(parts) == 2:
                port = parts[1]
                alias = mg_facts['minigraph_port_name_to_alias_map'].get(port, port)
                updated_key = "{}|{}".format(parts[0], alias)
            updated_key = updated_key.replace("/", "~1")
            localhost_pc_member_dict[updated_key] = value
        # for k, v in list(pc_dict.items()):
        #     localhost_add_paths_list.append("/localhost/PORTCHANNEL/{}".format(k))
        #     localhost_add_values_list.append(v)
        for k, v in list(localhost_pc_interface_dict.items()):
            localhost_add_paths_list.append("/localhost/PORTCHANNEL_INTERFACE/{}".format(k))
            localhost_add_values_list.append(v)
        for k, v in list(localhost_pc_member_dict.items()):
            localhost_add_paths_list.append("/localhost/PORTCHANNEL_MEMBER/{}".format(k))
            localhost_add_values_list.append(v)

    for path, value in zip(localhost_add_paths_list, localhost_add_values_list):
        json_patch_localhost.append({
            "op": "add",
            "path": path,
            "value": value
        })

    json_patch_localhost.append({
        "op": "add",
        "path": "/localhost/ACL_TABLE/DATAACL/ports",
        "value": config_facts_localhost["ACL_TABLE"]["DATAACL"]["ports"]
    })
    json_patch_localhost.append({
        "op": "add",
        "path": "/localhost/ACL_TABLE/EVERFLOW/ports",
        "value": config_facts_localhost["ACL_TABLE"]["EVERFLOW"]["ports"]
    })
    json_patch_localhost.append({
        "op": "add",
        "path": "/localhost/ACL_TABLE/EVERFLOWV6/ports",
        "value": config_facts_localhost["ACL_TABLE"]["EVERFLOWV6"]["ports"]
    })

    #####################################
    # combine localhost and ASIC patch data
    #####################################
    json_patch = json_patch_localhost + json_patch_asic
    tmpfile = generate_tmpfile(duthost)
    try:
        logger.info("Applying patch (2/2) to add cluster info (all except PORTCHANNEL).")
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile)


def apply_patch_add_cluster_chassis_packet(config_facts,
                                           config_facts_localhost,
                                           mg_facts,
                                           duthost,
                                           enum_rand_one_asic_namespace):
    """
    Apply patch to add cluster information for chassis-packet switches.

    For chassis-packet switches:
    - Excludes BP (backplane) interfaces
    - Only adds external PortChannels (those without BP members)
    - Skips localhost namespace patches

    Changes are perfomed to below tables:

    ACL_TABLE
    BGP_NEIGHBOR
    DEVICE_NEIGHBOR
    DEVICE_NEIGHBOR_METADATA
    PORTCHANNEL
    PORTCHANNEL_INTERFACE
    PORTCHANNEL_MEMBER
    INTERFACE
    BUFFER_PG
    CABLE_LENGTH
    PORT
    PORT_QOS_MAP
    """
    logger.info("Adding cluster for namespace {} via apply-patch (chassis-packet mode).".format(
        enum_rand_one_asic_namespace))

    ######################
    # ASIC NAMESPACE
    ######################
    json_namespace = '' if enum_rand_one_asic_namespace is None else '/' + enum_rand_one_asic_namespace

    # Identify external PortChannels (those without BP members)
    # Exclude PortChannels with BP (backplane) members - these are internal
    external_portchannels = set()
    for pc_name, members in config_facts.get("PORTCHANNEL_MEMBER", {}).items():
        has_internal_port = False
        for member_port in members.keys():
            # BP ports are internal for chassis-packet
            if member_port.startswith("Ethernet-BP"):
                has_internal_port = True
                break
        # If no internal ports, it's an external PortChannel
        if not has_internal_port:
            external_portchannels.add(pc_name)

    logger.info(f"External PortChannels to add back: {external_portchannels}")
    internal_pcs = set(config_facts.get('PORTCHANNEL', {}).keys()) - external_portchannels
    logger.info(f"Internal PortChannels to skip: {internal_pcs}")

    # Filter config_facts to only include external interfaces and PortChannels
    # Filter INTERFACE - exclude BP interfaces
    filtered_interface = {k: v for k, v in config_facts.get("INTERFACE", {}).items()
                          if not k.split('|')[0].startswith("Ethernet-BP")}

    # Filter PORTCHANNEL_INTERFACE - only external PortChannels
    filtered_pc_interface = {k: v for k, v in config_facts.get("PORTCHANNEL_INTERFACE", {}).items()
                             if (k.split('|')[0] if '|' in k else k) in external_portchannels}

    # Filter PORTCHANNEL_MEMBER - only external PortChannels
    filtered_pc_member = {k: v for k, v in config_facts.get("PORTCHANNEL_MEMBER", {}).items()
                          if k in external_portchannels}

    # Filter BUFFER_PG - exclude BP interfaces
    filtered_buffer_pg = {k: v for k, v in config_facts.get("BUFFER_PG", {}).items()
                          if not k.split('|')[0].startswith("Ethernet-BP")}

    # Filter PORTCHANNEL - only external PortChannels
    filtered_portchannel = {k: v for k, v in config_facts.get("PORTCHANNEL", {}).items()
                            if k in external_portchannels}

    # Now build the dictionaries from filtered data
    interface_dict = format_sonic_interface_dict(filtered_interface)
    portchannel_interface_dict = format_sonic_interface_dict(filtered_pc_interface)
    portchannel_member_dict = format_sonic_interface_dict(filtered_pc_member, single_entry=False)
    buffer_pg_dict = format_sonic_buffer_pg_dict(filtered_buffer_pg)
    pc_dict = {k: {ik: iv for ik, iv in v.items() if ik != "members"} for k, v in filtered_portchannel.items()}

    # find active ports
    active_interfaces = get_active_interfaces(config_facts, duthost)

    # Build single patch with correct operation order
    # Order is critical for YANG validation:
    # 1. PORTCHANNEL_MEMBER
    # 2. PORTCHANNEL_INTERFACE base entries
    # 3. PORTCHANNEL_INTERFACE IP entries
    # 4. PORTCHANNEL base (comes LAST!)

    #####################################
    # Single combined patch for PortChannel configuration
    #####################################
    json_patch_asic_pc = []

    # STEP 1: Add PORTCHANNEL_MEMBER entries
    for pc_member_key, pc_member_value in portchannel_member_dict.items():
        json_patch_asic_pc.append({
            "op": "add",
            "path": f"{json_namespace}/PORTCHANNEL_MEMBER/{pc_member_key}",
            "value": pc_member_value
        })

    # STEP 2: Add PORTCHANNEL_INTERFACE base entries (no IP addresses)
    for pc_if_key, pc_if_value in portchannel_interface_dict.items():
        if '|' not in pc_if_key:  # Base entries only
            json_patch_asic_pc.append({
                "op": "add",
                "path": f"{json_namespace}/PORTCHANNEL_INTERFACE/{pc_if_key}",
                "value": pc_if_value
            })

    # STEP 3: Add PORTCHANNEL_INTERFACE IP entries with proper JSON Pointer escaping
    for pc_if_key, pc_if_value in portchannel_interface_dict.items():
        if '|' in pc_if_key:  # IP address entries
            # Escape '/' as '~1' in the JSON Pointer path per RFC 6901
            escaped_key = pc_if_key.replace('/', '~1')
            json_patch_asic_pc.append({
                "op": "add",
                "path": f"{json_namespace}/PORTCHANNEL_INTERFACE/{escaped_key}",
                "value": pc_if_value
            })

    # STEP 4: Add PORTCHANNEL base entries (comes LAST!)
    for pc_key, pc_value in pc_dict.items():
        json_patch_asic_pc.append({
            "op": "add",
            "path": f"{json_namespace}/PORTCHANNEL/{pc_key}",
            "value": pc_value
        })

    #####################################
    # Second patch: BGP_NEIGHBOR and everything else
    #####################################
    json_patch_asic_rest = []

    # STEP 5: Add BGP_NEIGHBOR (can now validate against committed PORTCHANNEL_INTERFACE)
    for bgp_key, bgp_value in config_facts["BGP_NEIGHBOR"].items():
        json_patch_asic_rest.append({
            "op": "add",
            "path": f"{json_namespace}/BGP_NEIGHBOR/{bgp_key}",
            "value": bgp_value
        })

    # STEP 6: Add DEVICE_NEIGHBOR and DEVICE_NEIGHBOR_METADATA
    for dev_key, dev_value in config_facts["DEVICE_NEIGHBOR"].items():
        json_patch_asic_rest.append({
            "op": "add",
            "path": f"{json_namespace}/DEVICE_NEIGHBOR/{dev_key}",
            "value": dev_value
        })

    for dev_meta_key, dev_meta_value in config_facts["DEVICE_NEIGHBOR_METADATA"].items():
        json_patch_asic_rest.append({
            "op": "add",
            "path": f"{json_namespace}/DEVICE_NEIGHBOR_METADATA/{dev_meta_key}",
            "value": dev_meta_value
        })

    # STEP 7: Add INTERFACE entries (skip BP interfaces) with proper JSON Pointer escaping
    for iface_key, iface_value in interface_dict.items():
        # Escape '/' as '~1' in the JSON Pointer path per RFC 6901
        escaped_iface_key = iface_key.replace('/', '~1')
        json_patch_asic_rest.append({
            "op": "add",
            "path": f"{json_namespace}/INTERFACE/{escaped_iface_key}",
            "value": iface_value
        })

    # STEP 8: Add BUFFER_PG entries (skip BP interfaces and pg_lossless profiles)
    # Filter out pg_lossless profiles (e.g., pg_lossless_100000_300m_profile) as they are
    # automatically created by orchagent on DUT. Include other BUFFER_PG entries.
    for bp_key, bp_value in buffer_pg_dict.items():
        # Skip if profile contains "pg_lossless" - orchagent will create these
        if isinstance(bp_value, dict) and 'profile' in bp_value:
            if 'pg_lossless' in bp_value['profile']:
                logger.debug(f"Skipping BUFFER_PG {bp_key} with pg_lossless profile: {bp_value['profile']}")
                continue

        json_patch_asic_rest.append({
            "op": "add",
            "path": f"{json_namespace}/BUFFER_PG/{bp_key}",
            "value": bp_value
        })

    # STEP 9: Add PORT_QOS_MAP entries (skip BP interfaces)
    for port_qos_key, port_qos_value in config_facts.get("PORT_QOS_MAP", {}).items():
        if port_qos_key.startswith("Ethernet-BP"):
            continue
        json_patch_asic_rest.append({
            "op": "add",
            "path": f"{json_namespace}/PORT_QOS_MAP/{port_qos_key}",
            "value": port_qos_value
        })

    # STEP 10: Set PORT admin status to up (skip BP interfaces)
    for interface in active_interfaces:
        if interface.startswith("Ethernet-BP"):
            continue
        json_patch_asic_rest.append({
            "op": "add",
            "path": "{}/PORT/{}/admin_status".format(json_namespace, interface),
            "value": "up"
        })

    # STEP 11: Set CABLE_LENGTH (skip BP interfaces)
    initial_cable_length_table = config_facts["CABLE_LENGTH"]["AZURE"]
    cable_length_values = [int(v.rstrip("m")) for v in initial_cable_length_table.values()]
    highest = max(cable_length_values)
    for interface in active_interfaces:
        if interface.startswith("Ethernet-BP"):
            continue
        json_patch_asic_rest.append({
            "op": "add",
            "path": "{}/CABLE_LENGTH/AZURE/{}".format(json_namespace, interface),
            "value": f"{highest}m"
        })

    # STEP 12: Add/Replace ACL_TABLE changes
    for acl_table_name in ["DATAACL", "EVERFLOW", "EVERFLOWV6"]:
        if acl_table_name in config_facts.get("ACL_TABLE", {}):
            json_patch_asic_rest.append({
                "op": "add",
                "path": f"{json_namespace}/ACL_TABLE/{acl_table_name}/ports",
                "value": config_facts["ACL_TABLE"][acl_table_name]["ports"]
            })

    #####################################
    # Apply patches in correct order
    #####################################
    tmpfile_pc = generate_tmpfile(duthost)
    try:
        logger.info("Applying patch (1/2) to add cluster info (PortChannel configuration - ASIC namespace).")
        output = apply_patch(duthost, json_data=json_patch_asic_pc, dest_file=tmpfile_pc)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile_pc)

    tmpfile_rest = generate_tmpfile(duthost)
    try:
        logger.info("Applying patch (2/2) to add cluster info (BGP_NEIGHBOR and remaining config - ASIC namespace).")
        output = apply_patch(duthost, json_data=json_patch_asic_rest, dest_file=tmpfile_rest)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile_rest)


def format_sonic_interface_dict(interface_dict, single_entry=True):
    """
    Converts a SONiC interface dictionary into the correct format so the formatted value can be used
    as the 'value' in a JSON patch.

    - Ensures interfaces exist as standalone keys.
    - Converts IP addresses into the "Interface|IP" format.
    """
    formatted_interface_dict = {}

    for key, values in interface_dict.items():
        if isinstance(values, dict):  # if IPs are defined under the interface
            if single_entry:
                formatted_interface_dict[key] = {}
            for ip in values.keys():
                formatted_interface_dict[f"{key}|{ip}"] = {}
        else:
            if single_entry:
                formatted_interface_dict[key] = {}

    return formatted_interface_dict


def format_sonic_buffer_pg_dict(buffer_pg_dict):
    """
    Converts a SONiC interface dictionary into the correct format so the formatted value can be used
    as the 'value' in a JSON patch.
    """
    formatted_dict = {}
    for key, values in buffer_pg_dict.items():
        if isinstance(values, dict):
            for pg_num_key, value in values.items():
                formatted_dict[f"{key}|{pg_num_key}"] = value
    return formatted_dict


# -----------------------------
# Setup Fixtures/functions
# -----------------------------

@pytest.fixture(scope="module", params=[False, True])
def acl_config_scenario(request):
    return request.param


# Setting to false due to kvm data traffic issue failing the test case. Need to be enabled after investigation.
# Issue: https://github.com/sonic-net/sonic-mgmt/issues/21775
@pytest.fixture(scope="module", params=[False])
def data_traffic_scenario(request):
    return request.param


def setup_acl_config(duthost, ip_netns_namespace_prefix):
    logger.info("Adding acl config.")
    remove_dataacl_table_single_dut("DATAACL", duthost)
    duthost.command("{} config acl add table {} {} -s {}".format(
        ip_netns_namespace_prefix, ACL_TABLE_NAME, ACL_TABLE_TYPE_L3, ACL_TABLE_STAGE_EGRESS))
    duthost.copy(src=ACL_RULE_FILE_PATH, dest=ACL_RULE_DST_FILE)
    duthost.shell("{} acl-loader update full --table_name {} {}".format(
        ip_netns_namespace_prefix, ACL_TABLE_NAME, ACL_RULE_DST_FILE))
    acl_tables = duthost.command("{} show acl table".format(ip_netns_namespace_prefix))["stdout_lines"]
    acl_rules = duthost.command("{} show acl rule".format(ip_netns_namespace_prefix))["stdout_lines"]
    logging.info(('\n'.join(acl_tables)))
    logging.info(('\n'.join(acl_rules)))


def remove_acl_config(duthost, ip_netns_namespace_prefix):
    logger.info("Removing acl config.")
    config_reload(duthost, config_source="minigraph", safe_reload=True)
    acl_tables = duthost.command("{} show acl table".format(ip_netns_namespace_prefix))["stdout_lines"]
    acl_rules = duthost.command("{} show acl rule".format(ip_netns_namespace_prefix))["stdout_lines"]
    logging.info(('\n'.join(acl_tables)))
    logging.info(('\n'.join(acl_rules)))


@pytest.fixture(scope="module")
def setup_static_route(tbinfo, duthosts, enum_downstream_dut_hostname,
                       enum_rand_one_frontend_asic_index,
                       rand_bgp_neigh_ip_name):
    duthost = duthosts[enum_downstream_dut_hostname]
    bgp_neigh_ip, bgp_neigh_name = rand_bgp_neigh_ip_name
    logger.info("Adding static route {} to be routed via bgp neigh {}.".format(STATIC_DST_IP, bgp_neigh_ip))
    exabgp_port = get_exabgp_port_for_neighbor(tbinfo, bgp_neigh_name, EXABGP_BASE_PORT)
    route_exists = verify_routev4_existence(duthost, enum_rand_one_frontend_asic_index,
                                            STATIC_DST_IP, should_exist=True)
    if route_exists:
        logger.warning("Route exists already - will try to clear")
        clear_static_route(tbinfo, duthost, STATIC_DST_IP)
    add_static_route(tbinfo, bgp_neigh_ip, exabgp_port, ip=STATIC_DST_IP, nhipv4=NHIPV4)
    wait_until(10, 1, 0, verify_routev4_existence, duthost,
               enum_rand_one_frontend_asic_index, STATIC_DST_IP, should_exist=True)

    yield

    logger.info("Removing static route {} .".format(STATIC_DST_IP))
    remove_static_route(tbinfo, bgp_neigh_ip, exabgp_port, ip=STATIC_DST_IP, nhipv4=NHIPV4)
    wait_until(10, 1, 0, verify_routev4_existence, duthost,
               enum_rand_one_frontend_asic_index, STATIC_DST_IP, should_exist=False)


@pytest.fixture(scope="function")
def initialize_random_variables(enum_downstream_dut_hostname,
                                enum_upstream_dut_hostname,
                                enum_rand_one_frontend_asic_index,
                                enum_rand_one_asic_namespace,
                                ip_netns_namespace_prefix,
                                cli_namespace_prefix,
                                rand_bgp_neigh_ip_name):
    return enum_downstream_dut_hostname, enum_upstream_dut_hostname, enum_rand_one_frontend_asic_index, \
        enum_rand_one_asic_namespace, ip_netns_namespace_prefix, cli_namespace_prefix, rand_bgp_neigh_ip_name


@pytest.fixture(scope="function")
def initialize_facts(mg_facts,
                     config_facts,
                     config_facts_localhost):
    return mg_facts, config_facts, config_facts_localhost


@pytest.fixture(scope="function")
def setup_add_cluster(tbinfo,
                      duthosts,
                      localhost,
                      initialize_random_variables,
                      initialize_facts,
                      ptfadapter,
                      loganalyzer,
                      acl_config_scenario,
                      setup_static_route,
                      data_traffic_scenario):
    """
    This setup fixture prepares the Downstream LC by applying a patch to remove
    and then re-add the cluster configuration.

    The purpose is to prepare the DUT host for test cases that validate functionality
    after adding a cluster via apply-patch.
    The fixture reads the running configuration and constructs patches to remove
    the current config from a running namespace.
    After verifying successful removal, it re-adds the configuration and validates that it was successfully restored.

    **Setup steps - applied to the Downstream LC:**
    1. Save the original configuration.
    2. Remove the cluster from a randomly selected namespace.
    3. Verify BGP information, route table, and interface details to ensure everything has been removed as expected.
    4. Perform data verification in the upstream → downlink direction, targeting a static route, which should now fail.
    5. Save the configuration and reboot the system so that it initializes clear from cluster information
    6. Re-add the cluster to the randomly selected namespace.
    7. Verify BGP information, route table, and interface details to ensure everything is restored as expected.
    8. Add ACL configuration based on the test parameter value.

    **Teardown steps:**
    The setup logic already re-applies the initial cluster configuration for the namespace.
    The only recovery needed during teardown is for the ACL configuration:
    1. Restore the ACL configuration to its initial values.
    """

    # initial test env
    enum_downstream_dut_hostname, enum_upstream_dut_hostname, enum_rand_one_frontend_asic_index, \
        enum_rand_one_asic_namespace, ip_netns_namespace_prefix, cli_namespace_prefix, \
        rand_bgp_neigh_ip_name = initialize_random_variables
    mg_facts, config_facts, config_facts_localhost = initialize_facts
    duthost = duthosts[enum_downstream_dut_hostname]
    # Check if the device is a modular chassis and the topology is T2
    is_chassis = duthost.get_facts().get("modular_chassis")
    if not (is_chassis and tbinfo['topo']['type'] == 't2' and
            (duthost.facts['switch_type'] == "voq" or
             duthost.facts['switch_type'] == "chassis-packet")):
        pytest.skip("Test is Applicable for T2 VOQ or Chassis-Packet Chassis Setup")
    duthost_src = duthosts[enum_upstream_dut_hostname]
    asic_id = enum_rand_one_frontend_asic_index
    asic_id_src = None
    all_asic_ids = duthost_src.get_asic_ids()
    for asic in all_asic_ids:
        if duthost_src == duthost and asic == asic_id:
            continue
        asic_id_src = asic
        break
    bgp_neigh_ip, _bgp_neigh_name = rand_bgp_neigh_ip_name
    pytest_assert(
        asic_id_src is not None, "Couldn't find an asic id to be used for sending traffic. \
            Reserved asic id: {}. All available asic ids: {}".format(
            asic_id, all_asic_ids
        )
    )
    initial_buffer_pg_info = get_cfg_info_from_dut(duthost, 'BUFFER_PG', enum_rand_one_asic_namespace)
    with allure.step("Verification before removing cluster"):
        for host_device in duthosts:
            if host_device.is_supervisor_node():
                continue
            logger.info(host_device.shell('show ip bgp summary -d all'))
            logger.info(host_device.shell('show ipv6 bgp summary -d all'))
        route_exists = verify_routev4_existence(duthost, asic_id, STATIC_DST_IP, should_exist=True)
        route_exists_src = verify_routev4_existence(duthost_src, asic_id_src, STATIC_DST_IP, should_exist=True)
        pytest_assert(route_exists, "Static route {} doesn't exist on downstream DUT before cluster removal."
                      .format(STATIC_DST_IP))
        pytest_assert(route_exists_src, "Static route {} doesn't exist on upstream DUT before cluster removal."
                      .format(STATIC_DST_IP))
        if data_traffic_scenario:
            logger.info("Sending traffic from upstream DUT to downstream DUT before cluster removal.")
            send_and_verify_traffic(tbinfo, duthost_src, duthost, asic_id_src, asic_id,
                                    ptfadapter, dst_ip=STATIC_DST_IP, count=10, expect_error=False)

    with allure.step("Removing cluster info for namespace"):
        # disable loganalyzer during cluster removal
        logger.info("Disabling loganalyzer before starting cluster removal.")
        if loganalyzer and loganalyzer[duthost.hostname]:
            loganalyzer[duthost.hostname].add_start_ignore_mark()

        # Check switch type to determine which removal functions to use
        is_chassis_packet = duthost.facts.get('switch_type') == 'chassis-packet'
        logger.info(f"Switch type: {duthost.facts.get('switch_type')} - "
                    f"Using chassis-packet functions: {is_chassis_packet}")

        if len(config_facts["BUFFER_PG"]) <= 6:  # num of active interfaces = num of pg lossless profiles
            if is_chassis_packet:
                logger.info("Removal method gcu - min setup (chassis-packet).")
                apply_patch_remove_cluster_chassis_packet(config_facts,
                                                          config_facts_localhost,
                                                          mg_facts,
                                                          duthost,
                                                          enum_rand_one_asic_namespace,
                                                          cli_namespace_prefix)
            else:
                logger.info("Removal method gcu - min setup (non-chassis-packet).")
                apply_patch_remove_cluster(config_facts,
                                           config_facts_localhost,
                                           mg_facts,
                                           duthost,
                                           enum_rand_one_asic_namespace,
                                           cli_namespace_prefix)
        else:
            if is_chassis_packet:
                logger.info("Removal method sonic-db-cli - mid-max setup (chassis-packet).")
                remove_cluster_via_sonic_db_cli_chassis_packet(config_facts,
                                                               config_facts_localhost,
                                                               mg_facts,
                                                               duthost,
                                                               enum_rand_one_asic_namespace,
                                                               cli_namespace_prefix)
            else:
                logger.info("Removal method sonic-db-cli - mid-max setup (non-chassis-packet).")
                remove_cluster_via_sonic_db_cli(config_facts,
                                                config_facts_localhost,
                                                mg_facts,
                                                duthost,
                                                enum_rand_one_asic_namespace,
                                                cli_namespace_prefix)

        # Verify routes removed
        wait_until(5, 1, 0, verify_routev4_existence, duthost,
                   enum_rand_one_frontend_asic_index, bgp_neigh_ip, should_exist=False)
        wait_until(5, 1, 0, verify_routev4_existence, duthost,
                   enum_rand_one_frontend_asic_index, STATIC_DST_IP, should_exist=False)

        # re-enabling loganalyzer during cluster removal
        logger.info("Re-enabling loganalyzer after cluster removal.")
        if loganalyzer and loganalyzer[duthost.hostname]:
            loganalyzer[duthost.hostname].add_end_ignore_mark()
    with allure.step("Reload the system with config reload"):
        duthost.shell("config save -y")
        config_reload(duthost, config_source='config_db', safe_reload=True)
        pytest_assert(wait_until(300, 20, 0, duthost.critical_services_fully_started),
                      "All critical services should be fully started!")
        pytest_assert(wait_until(1200, 20, 0, check_interface_status_of_up_ports, duthost),
                      "Not all ports that are admin up on are operationally up")

    with allure.step("Verify config after reload"):
        tmpfile = generate_tmpfile(duthost)
        output = apply_patch(duthost, json_data=[], dest_file=tmpfile)
        expect_op_success(duthost, output)

    with allure.step("Adding cluster info for namespace"):
        # Check switch type to determine which add function to use
        is_chassis_packet = duthost.facts.get('switch_type') == 'chassis-packet'
        if is_chassis_packet:
            apply_patch_add_cluster_chassis_packet(config_facts,
                                                   config_facts_localhost,
                                                   mg_facts,
                                                   duthost,
                                                   enum_rand_one_asic_namespace)
        else:
            apply_patch_add_cluster(config_facts,
                                    config_facts_localhost,
                                    mg_facts,
                                    duthost,
                                    enum_rand_one_asic_namespace)
        # Verify routes added
        wait_until(5, 1, 0, verify_routev4_existence,
                   duthost, enum_rand_one_frontend_asic_index, bgp_neigh_ip, should_exist=True)
        wait_until(5, 1, 0, verify_routev4_existence,
                   duthost, enum_rand_one_frontend_asic_index, STATIC_DST_IP, should_exist=True)
        # Verify buffer pg
        buffer_pg_info_add_interfaces = get_cfg_info_from_dut(duthost, 'BUFFER_PG', enum_rand_one_asic_namespace)
        pytest_assert(buffer_pg_info_add_interfaces == initial_buffer_pg_info,
                      "Didn't find expected BUFFER_PG info in CONFIG_DB after adding back the interfaces.")

    if acl_config_scenario:
        setup_acl_config(duthost, ip_netns_namespace_prefix)

    yield

    if acl_config_scenario:
        remove_acl_config(duthost, ip_netns_namespace_prefix)


# -----------------------------
# Test Definitions
# -----------------------------

def test_add_cluster(tbinfo,
                     duthosts,
                     initialize_random_variables,
                     ptfadapter,
                     loganalyzer,
                     acl_config_scenario,
                     cli_namespace_prefix,
                     setup_add_cluster,
                     data_traffic_scenario):
    """
    Validates the functionality of the Downstream Linecard after adding a cluster.

    Performs lossless data traffic scenarios for both ACL and non-ACL cases.
    Verifies successful data transmission, queue counters, and ACL rule match counters.
    """

    # initial test env
    enum_downstream_dut_hostname, enum_upstream_dut_hostname, enum_rand_one_frontend_asic_index, \
        enum_rand_one_asic_namespace, ip_netns_namespace_prefix, cli_namespace_prefix, \
        rand_bgp_neigh_ip_name = initialize_random_variables
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
        asic_id_src is not None, "Couldn't find an asic id to be used for sending traffic from upstream. \
            All available asic ids: {}".format(
            duthost_up.get_asic_ids()
        )
    )

    if data_traffic_scenario:
        # Traffic scenarios applied in non-acl, acl scenario
        traffic_scenarios = [
            {"direction": "upstream->downstream", "dst_ip": STATIC_DST_IP, "count": 1000, "dscp": 3,
             "sport": 1234, "dport": 50, "verify": True, "expect_error": False},
            {"direction": "downstream->downstream", "dst_ip": STATIC_DST_IP, "count": 1000, "dscp": 3,
             "sport": 1234, "dport": 50, "verify": True, "expect_error": False}
        ]
        if acl_config_scenario:
            traffic_scenarios = [
                {"direction": "upstream->downstream", "dst_ip": STATIC_DST_IP, "count": 1000, "dscp": 3,
                 "sport": 5000, "dport": 50, "verify": True, "expect_error": False, "match_rule": "RULE_100"},
                {"direction": "upstream->downstream", "dst_ip": STATIC_DST_IP, "count": 1000, "dscp": 3,
                 "sport": 1234, "dport": 8080, "verify": True, "expect_error": True, "match_rule": "RULE_200"},
                {"direction": "upstream->downstream", "dst_ip": STATIC_DST_IP, "count": 1000, "dscp": 3,
                 "sport": 1234, "dport": 50, "verify": True, "expect_error": False, "match_rule": None},
                {"direction": "downstream->downstream", "dst_ip": STATIC_DST_IP, "count": 1000, "dscp": 3,
                 "sport": 5000, "dport": 50, "verify": True, "expect_error": False, "match_rule": "RULE_100"},
                {"direction": "downstream->downstream", "dst_ip": STATIC_DST_IP, "count": 1000, "dscp": 3,
                 "sport": 1234, "dport": 8080, "verify": True, "expect_error": True, "match_rule": "RULE_200"},
                {"direction": "downstream->downstream", "dst_ip": STATIC_DST_IP, "count": 1000, "dscp": 3,
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
                pytest_assert("Unsupported direction for traffic scenario {}.".format(traffic_scenario["direction"]))

            if acl_config_scenario:
                duthost.shell('{} aclshow -c'.format(ip_netns_namespace_prefix))

            send_and_verify_traffic(tbinfo, src_duthost, duthost, src_asic_index, asic_id,
                                    ptfadapter,
                                    dst_ip=traffic_scenario["dst_ip"],
                                    dscp=traffic_scenario["dscp"],
                                    count=traffic_scenario["count"],
                                    sport=traffic_scenario["sport"],
                                    dport=traffic_scenario["dport"],
                                    verify=traffic_scenario["verify"],
                                    expect_error=traffic_scenario["expect_error"])

            if acl_config_scenario:
                acl_counters = duthost.show_and_parse('{} aclshow -a'.format(ip_netns_namespace_prefix))
                for acl_counter in acl_counters:
                    if acl_counter["rule name"] in ACL_RULE_SKIP_VERIFICATION_LIST:
                        continue
                    pytest_assert(acl_counter["packets count"] == str(traffic_scenario["count"])
                                  if acl_counter["rule name"] == traffic_scenario["match_rule"]
                                  else acl_counter["packets count"] == '0',
                                  "Acl rule {} statistics are not as expected. Found value {}"
                                  .format(acl_counter["rule name"], acl_counter["packets count"]))
