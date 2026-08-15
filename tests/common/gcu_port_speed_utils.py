"""
Common helpers for GCU port speed conversion tests.
"""

import logging

from tests.common.gu_utils import (
    ASIC_PREFIX,
    apply_patch,
    delete_tmpfile,
    expect_op_success,
    generate_tmpfile,
)
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import is_ipv4_address, is_ipv6_address, wait_until

logger = logging.getLogger(__name__)


def _format_sonic_interface_dict(interface_dict, single_entry=True):
    """
    Convert a SONiC interface-style dictionary into JSON patch key/value form.
    """
    formatted_interface_dict = {}

    for key, values in interface_dict.items():
        if isinstance(values, dict):
            if single_entry:
                formatted_interface_dict[key] = {}
            for ip_addr in values:
                formatted_interface_dict["{}|{}".format(key, ip_addr)] = {}
        elif single_entry:
            formatted_interface_dict[key] = {}

    return formatted_interface_dict


def _format_sonic_buffer_pg_dict(buffer_pg_dict):
    """
    Convert a SONiC BUFFER_PG dictionary into JSON patch key/value form.
    """
    formatted_dict = {}
    for key, values in buffer_pg_dict.items():
        if isinstance(values, dict):
            for pg_num_key, value in values.items():
                formatted_dict["{}|{}".format(key, pg_num_key)] = value
    return formatted_dict


def _format_sonic_queue_dict(queue_dict):
    """
    Convert a SONiC QUEUE dictionary into JSON patch key/value form.
    """
    formatted_dict = {}
    for key, value in queue_dict.items():
        if '|' in key:
            formatted_dict[key] = value
            continue
        if isinstance(value, dict):
            for queue_key, queue_value in value.items():
                formatted_dict["{}|{}".format(key, queue_key)] = queue_value
    return formatted_dict


def _escape_json_pointer_key(key):
    """
    Escape a CONFIG_DB key segment for use in a JSON patch path.
    """
    return key.replace('/', '~1')


def _iter_portchannel_members(config_facts):
    """
    Iterate PORTCHANNEL_MEMBER entries as (portchannel, member_port, value).
    """
    for key, value in config_facts.get("PORTCHANNEL_MEMBER", {}).items():
        if '|' in key:
            portchannel, member_port = key.split('|', 1)
            yield portchannel, member_port, value
        else:
            for member_port, member_value in value.items():
                yield key, member_port, member_value


def _get_portchannel_for_member(config_facts, port):
    """
    Return the PortChannel containing a member port, if any.
    """
    for portchannel, member_port, _ in _iter_portchannel_members(config_facts):
        if member_port == port:
            return portchannel
    return None


def _get_portchannel_member_value(config_facts, portchannel, port):
    """
    Return the PORTCHANNEL_MEMBER value for a selected member port.
    """
    portchannel_members = config_facts.get("PORTCHANNEL_MEMBER", {})
    if portchannel in portchannel_members:
        return portchannel_members.get(portchannel, {}).get(port, {})
    return portchannel_members.get("{}|{}".format(portchannel, port), {})


def _append_portchannel_add_ops(
        json_patch, json_namespace, config_facts, port):
    """
    Append PortChannel add operations for the selected port.
    """
    portchannel = _get_portchannel_for_member(config_facts, port)
    if not portchannel:
        return

    pc_member_key = "{}|{}".format(portchannel, port)
    pc_member_value = _get_portchannel_member_value(
        config_facts, portchannel, port
    )

    json_patch.append({
        "op": "add",
        "path": "{}/PORTCHANNEL_MEMBER/{}".format(
            json_namespace, _escape_json_pointer_key(pc_member_key)
        ),
        "value": pc_member_value,
    })


def get_interface_neighbor_and_intfs(mg_facts, selected_random_port):
    """
    Resolve BGP neighbor name and addresses for a port or its portchannel.
    """
    vm_neighbors = mg_facts['minigraph_neighbors']
    dut_interface = selected_random_port
    port_channel = mg_facts.get('minigraph_portchannels', {}).get(
        dut_interface
    )
    if port_channel is not None:
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
        "Found neighbor %s with interfaces %s for duthost port %s. "
        "IPv4 interface: %s IPv6 interface: %s",
        neighbor_name,
        neighbor_addr,
        selected_random_port,
        neighbor_ipv4_addr,
        neighbor_ipv6_addr,
    )
    return neighbor_name, neighbor_addr, neighbor_ipv4_addr, neighbor_ipv6_addr


def build_cluster_port_restore_ops(
        config_facts, mg_facts, json_namespace, port):
    """
    Build add operations that restore cluster config for a selected port.
    """
    json_patch = []
    _append_portchannel_add_ops(
        json_patch, json_namespace, config_facts, port
    )

    bgp_neigh_name, bgp_neigh_intfs, _, _ = get_interface_neighbor_and_intfs(
        mg_facts, port
    )

    for bgp_neigh_intf in bgp_neigh_intfs:
        bgp_neigh_intf = bgp_neigh_intf.lower()
        if bgp_neigh_intf in config_facts.get("BGP_NEIGHBOR", {}):
            json_patch.append({
                "op": "add",
                "path": "{}/BGP_NEIGHBOR/{}".format(
                    json_namespace, bgp_neigh_intf
                ),
                "value": config_facts["BGP_NEIGHBOR"][bgp_neigh_intf],
            })

    if port in config_facts.get("DEVICE_NEIGHBOR", {}):
        json_patch.append({
            "op": "add",
            "path": "{}/DEVICE_NEIGHBOR/{}".format(json_namespace, port),
            "value": config_facts["DEVICE_NEIGHBOR"][port],
        })

    if bgp_neigh_name in config_facts.get("DEVICE_NEIGHBOR_METADATA", {}):
        json_patch.append({
            "op": "add",
            "path": "{}/DEVICE_NEIGHBOR_METADATA/{}".format(
                json_namespace, bgp_neigh_name
            ),
            "value": config_facts["DEVICE_NEIGHBOR_METADATA"][bgp_neigh_name],
        })

    interface_dict = {
        _escape_json_pointer_key(key): value
        for key, value in _format_sonic_interface_dict(
            config_facts.get("INTERFACE", {})
        ).items()
        if key == port or key.startswith("{}|".format(port))
    }
    for iface_key, iface_value in interface_dict.items():
        json_patch.append({
            "op": "add",
            "path": "{}/INTERFACE/{}".format(json_namespace, iface_key),
            "value": iface_value,
        })

    buffer_pg_dict = {
        key: value
        for key, value in _format_sonic_buffer_pg_dict(
            config_facts.get("BUFFER_PG", {})
        ).items()
        if key == port or key.startswith("{}|".format(port))
    }
    for bp_key, bp_value in buffer_pg_dict.items():
        if (
            isinstance(bp_value, dict)
            and 'pg_lossless' in bp_value.get('profile', '')
        ):
            continue
        json_patch.append({
            "op": "add",
            "path": "{}/BUFFER_PG/{}".format(json_namespace, bp_key),
            "value": bp_value,
        })

    queue_dict = {
        _escape_json_pointer_key(key): value
        for key, value in _format_sonic_queue_dict(
            config_facts.get("QUEUE", {})
        ).items()
        if key == port or key.startswith("{}|".format(port))
    }
    for queue_key, queue_value in queue_dict.items():
        json_patch.append({
            "op": "add",
            "path": "{}/QUEUE/{}".format(json_namespace, queue_key),
            "value": queue_value,
        })

    if port in config_facts.get("PORT_QOS_MAP", {}):
        json_patch.append({
            "op": "add",
            "path": "{}/PORT_QOS_MAP/{}".format(json_namespace, port),
            "value": config_facts["PORT_QOS_MAP"][port],
        })

    if port in config_facts.get("PFC_WD", {}):
        json_patch.append({
            "op": "add",
            "path": "{}/PFC_WD/{}".format(json_namespace, port),
            "value": config_facts["PFC_WD"][port],
        })

    cable_length = config_facts.get("CABLE_LENGTH", {}).get("AZURE", {}).get(
        port
    )
    if cable_length is not None:
        json_patch.append({
            "op": "add",
            "path": "{}/CABLE_LENGTH/AZURE/{}".format(json_namespace, port),
            "value": cable_length,
        })

    return json_patch


def _dedupe_patch_ops(json_patch):
    """
    Return patch operations with duplicate paths removed.
    """
    deduped = []
    seen_paths = set()
    for operation in json_patch:
        path = operation.get("path")
        if path in seen_paths:
            continue
        deduped.append(operation)
        seen_paths.add(path)
    return deduped


def build_cluster_ports_restore_ops(config_facts, mg_facts, json_namespace,
                                    ports):
    """
    Build restore operations for the selected port(s).
    """
    json_patch = []
    for port in ports:
        json_patch.extend(
            build_cluster_port_restore_ops(
                config_facts, mg_facts, json_namespace, port
            )
        )
    return _dedupe_patch_ops(json_patch)


def validate_patch_scoped_to_ports(json_patch, ports, mg_facts=None):
    """
    Assert selected-port table operations do not target unrelated ports.
    """
    allowed_ports = set(ports)
    allowed_bgp_neighbors = set()
    allowed_neighbor_metadata = set()
    if mg_facts is not None:
        for port in ports:
            neighbor_name, neighbor_addrs, _, _ = \
                get_interface_neighbor_and_intfs(mg_facts, port)
            allowed_neighbor_metadata.add(neighbor_name)
            allowed_bgp_neighbors.update(
                addr.lower() for addr in neighbor_addrs
            )

    selected_port_tables = [
        "PORT",
        "INTERFACE",
        "BUFFER_PG",
        "QUEUE",
        "PORT_QOS_MAP",
        "PFC_WD",
        "DEVICE_NEIGHBOR",
        "PORTCHANNEL_MEMBER",
    ]
    for operation in json_patch:
        path = operation.get("path", "")
        path_parts = path.strip('/').split('/')
        if len(path_parts) < 2:
            continue

        table_index = 1 if path_parts[0].startswith(ASIC_PREFIX) else 0
        if table_index >= len(path_parts):
            continue
        table_name = path_parts[table_index]
        if table_name == "BGP_NEIGHBOR":
            if table_index + 1 >= len(path_parts):
                continue
            neighbor_key = path_parts[
                table_index + 1
            ].replace('~1', '/').lower()
            pytest_assert(
                mg_facts is not None,
                "BGP_NEIGHBOR patch op requires mg_facts for validation: "
                "{}".format(operation),
            )
            pytest_assert(
                neighbor_key in allowed_bgp_neighbors,
                "Patch operation {} targets BGP neighbor {}, expected one "
                "of {}".format(
                    operation, neighbor_key, sorted(allowed_bgp_neighbors)
                ),
            )
            continue
        if table_name == "DEVICE_NEIGHBOR_METADATA":
            if table_index + 1 >= len(path_parts):
                continue
            metadata_key = path_parts[table_index + 1].replace('~1', '/')
            pytest_assert(
                mg_facts is not None,
                "DEVICE_NEIGHBOR_METADATA patch op requires mg_facts for "
                "validation: {}".format(operation),
            )
            pytest_assert(
                metadata_key in allowed_neighbor_metadata,
                "Patch operation {} targets neighbor metadata {}, expected "
                "one of {}".format(
                    operation, metadata_key, sorted(allowed_neighbor_metadata)
                ),
            )
            continue
        if table_name == "CABLE_LENGTH":
            if len(path_parts) <= table_index + 2:
                continue
            target_port = path_parts[table_index + 2]
            pytest_assert(
                target_port in allowed_ports,
                "Patch operation {} targets {}, expected one of selected "
                "ports {}".format(
                    operation, target_port, sorted(allowed_ports)
                )
            )
            continue
        if path_parts[table_index] not in selected_port_tables:
            continue
        if table_index + 1 >= len(path_parts):
            continue

        key = path_parts[table_index + 1].replace('~1', '/')
        if path_parts[table_index] == "PORTCHANNEL_MEMBER":
            target_port = key.split('|', 1)[1] if '|' in key else key
        else:
            target_port = key.split('|', 1)[0]
        pytest_assert(
            target_port in allowed_ports,
            "Patch operation {} targets {}, expected one of selected ports "
            "{}".format(operation, target_port, sorted(allowed_ports))
        )


def get_port_show_interface_status(duthost, port, asic_namespace=None):
    """
    Return the parsed show interface status row for a single port.
    """
    if asic_namespace:
        cmd = "show interface status {} -n {}".format(port, asic_namespace)
    else:
        cmd = "show interface status {}".format(port)
    result = duthost.show_and_parse(cmd)
    pytest_assert(
        result, "No show interface status output for port {}".format(port)
    )
    return result[0]


def _is_port_oper_up(duthost, port, asic_namespace=None):
    """
    Check whether a port is admin up and oper up.
    """
    status = get_port_show_interface_status(duthost, port, asic_namespace)
    return (
        status.get('oper', '').lower() == 'up'
        and status.get('admin', '').lower() == 'up'
    )


def apply_patch_port_configs(duthost, enum_rand_one_asic_namespace,
                             port_configs, config_facts=None, mg_facts=None,
                             dry_run=False):
    """
    Apply a GCU patch that updates one or more member port speeds.
    """
    ports = list(port_configs.keys())
    if enum_rand_one_asic_namespace is None:
        json_namespace = ''
    else:
        json_namespace = '/' + enum_rand_one_asic_namespace
    json_patch = []
    if config_facts is not None and mg_facts is not None:
        json_patch.extend(
            build_cluster_ports_restore_ops(
                config_facts, mg_facts, json_namespace, ports
            )
        )

    for port, port_config in port_configs.items():
        json_patch.append({
            "op": "add",
            "path": "{}/PORT/{}".format(json_namespace, port),
            "value": port_config,
        })
    validate_patch_scoped_to_ports(json_patch, ports, mg_facts=mg_facts)

    tmpfile = generate_tmpfile(duthost)
    try:
        logger.info(
            "Applying port speed patch for %s. Dry-run %s", ports, dry_run
        )
        logger.info("Patch content: %s", json_patch)
        if not dry_run:
            output = apply_patch(
                duthost, json_data=json_patch, dest_file=tmpfile
            )
            expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile)


def verify_port_show_interface_status(duthost, port, asic_namespace,
                                      expected_speed, expected_lanes,
                                      expected_fec, require_oper_up=False):
    """
    Verify speed, lanes, and FEC from show interface status.
    """
    if require_oper_up:
        pytest_assert(
            wait_until(
                300, 20, 0,
                lambda: _is_port_oper_up(duthost, port, asic_namespace)
            ),
            "Port {} not oper up".format(port)
        )

    status = get_port_show_interface_status(duthost, port, asic_namespace)
    displayed_speed = status.get(
        'speed', ''
    ).replace('G', '000').replace('M', '')
    pytest_assert(
        displayed_speed == expected_speed,
        "Port {} speed mismatch: expected {}, got {}".format(
            port, expected_speed, status.get('speed')
        )
    )
    pytest_assert(
        status.get('lanes') == expected_lanes,
        "Port {} lanes mismatch: expected {}, got {}".format(
            port, expected_lanes, status.get('lanes')
        )
    )
    expected_fec_display = (expected_fec or 'N/A').upper()
    actual_fec = status.get('fec', 'N/A').upper()
    pytest_assert(
        actual_fec == expected_fec_display,
        "Port {} fec mismatch: expected {}, got {}".format(
            port, expected_fec_display, actual_fec
        )
    )
    if require_oper_up:
        pytest_assert(
            status.get('oper', '').lower() == 'up',
            "Port {} oper state is not up: {}".format(
                port, status.get('oper')
            )
        )
    logger.info(
        "show interface status for %s: speed=%s lanes=%s fec=%s oper=%s",
        port,
        status.get('speed'),
        status.get('lanes'),
        status.get('fec'),
        status.get('oper'),
    )
