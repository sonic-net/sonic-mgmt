#!/usr/bin/env python3
"""
Generate buffer and QoS tables for golden_config_db.json.

Produces all buffer-related config_db tables for a given PORT table so that
a DUT can perform a full ``config reload`` without crashing due to missing
buffer configuration.

Tables generated:
    BUFFER_POOL, BUFFER_PROFILE, BUFFER_PG, BUFFER_QUEUE,
    QUEUE, PORT_QOS_MAP, CABLE_LENGTH, SCHEDULER, WRED_PROFILE
"""

import re

PORT_NAME_RE = re.compile(r"^Ethernet(\d+)$")

# Default pool sizes (from reference config_db_moby.json)
DEFAULT_INGRESS_POOL_SIZE = "164075364"
DEFAULT_EGRESS_POOL_SIZE = "164075364"

# Default management port indices — these get reduced QoS (no PFC)
DEFAULT_MGMT_PORT_INDICES = [512, 513]

# Queue-to-scheduler mapping (queue_id -> scheduler name)
QUEUE_SCHEDULER_MAP = {
    0: "SCHEDULER_DEFAULT",
    1: "SCHEDULER_Q1",
    2: "SCHEDULER_DEFAULT",
    3: "SCHEDULER_Q3",
    4: "SCHEDULER_Q4",
    5: "SCHEDULER_DEFAULT",
    6: "SCHEDULER_Q6",
    7: "SCHEDULER_DEFAULT",
}

# Lossless queues that also get a WRED profile
QUEUE_WRED_MAP = {
    3: "WRED_LOSSLESS_Q3",
    4: "WRED_LOSSLESS_Q4",
}


# ---------------------------------------------------------------------------
# Placeholder functions — the user will supply real formulas later
# ---------------------------------------------------------------------------

def compute_xoff(speed, cable_length):
    """Compute xoff value for a lossless BUFFER_PROFILE entry.

    Args:
        speed: port speed as string (e.g. "400000")
        cable_length: cable length as string (e.g. "40m")

    Returns:
        xoff value as a string
    """
    # TODO: replace with real formula
    return "0"


def compute_static_th(speed, cable_length):
    """Compute static_th value for a lossless BUFFER_PROFILE entry.

    Args:
        speed: port speed as string (e.g. "400000")
        cable_length: cable length as string (e.g. "40m")

    Returns:
        static_th value as a string
    """
    # TODO: replace with real formula
    return "0"


def compute_pool_xoff(port_speeds, cable_lengths):
    """Compute xoff value for the ingress_lossless_pool.

    Args:
        port_speeds: list of speed strings for all ports
        cable_lengths: list of cable length strings for all ports

    Returns:
        pool xoff value as a string
    """
    # TODO: replace with real formula
    return "0"


# ---------------------------------------------------------------------------
# Table generators
# ---------------------------------------------------------------------------

def _parse_port_index(port_name):
    """Extract the numeric index from an Ethernet port name."""
    m = PORT_NAME_RE.match(port_name)
    return int(m.group(1)) if m else None


def _sort_port_names(port_names):
    """Sort port names numerically by Ethernet index."""
    def _key(name):
        idx = _parse_port_index(name)
        return (idx is None, idx if idx is not None else 0, name)
    return sorted(port_names, key=_key)


def _is_mgmt_port(port_name, mgmt_port_indices):
    """Check if a port is a management port based on its index."""
    idx = _parse_port_index(port_name)
    if idx is None:
        return False
    return idx in mgmt_port_indices


def generate_buffer_pool(ingress_pool_size=DEFAULT_INGRESS_POOL_SIZE,
                         egress_pool_size=DEFAULT_EGRESS_POOL_SIZE,
                         pool_xoff="0"):
    """Generate the BUFFER_POOL table.

    Pool sizes are kept as-is (passed in, not computed).
    The xoff for ingress_lossless_pool comes from the placeholder function.
    """
    return {
        "egress_lossless_pool": {
            "mode": "static",
            "size": egress_pool_size,
            "type": "egress",
        },
        "ingress_lossless_pool": {
            "mode": "dynamic",
            "size": ingress_pool_size,
            "type": "ingress",
            "xoff": pool_xoff,
        },
    }


def generate_buffer_profiles(speed_cable_pairs):
    """Generate the BUFFER_PROFILE table.

    Creates a pg_lossless profile for each unique (speed, cable_length) pair
    and three static profiles that don't vary by speed.

    Args:
        speed_cable_pairs: set of (speed_str, cable_length_str) tuples

    Returns:
        dict of profile_name -> profile_fields
    """
    profiles = {
        "egress_lossless_profile": {
            "pool": "egress_lossless_pool",
            "size": "0",
            "static_th": "165364160",
        },
        "egress_lossy_profile": {
            "dynamic_th": "0",
            "pool": "egress_lossless_pool",
            "size": "1778",
        },
        "ingress_lossy_profile": {
            "pool": "ingress_lossless_pool",
            "size": "0",
            "static_th": "165364160",
        },
    }

    for speed, cable in sorted(speed_cable_pairs):
        name = "pg_lossless_{}_{}_profile".format(speed, cable)
        profiles[name] = {
            "dynamic_th": "0",
            "pool": "ingress_lossless_pool",
            "size": "18796",
            "xoff": compute_xoff(speed, cable),
            "xon": "0",
            "xon_offset": "3556",
        }

    return profiles


def generate_buffer_pg(port_names, speed_cable_map, mgmt_port_indices=None):
    """Generate the BUFFER_PG table.

    Each port gets:
        PG 0       -> ingress_lossy_profile
        PG 3-4     -> pg_lossless_{speed}_{cable}_profile  (data ports only)

    Management ports only get PG 0 (no lossless PG).

    Args:
        port_names: list of port name strings
        speed_cable_map: dict of port_name -> (speed_str, cable_length_str)
        mgmt_port_indices: list of integer port indices for management ports

    Returns:
        dict of "port|pg" -> {"profile": profile_name}
    """
    if mgmt_port_indices is None:
        mgmt_port_indices = list(DEFAULT_MGMT_PORT_INDICES)

    buffer_pg = {}
    for port in _sort_port_names(port_names):
        buffer_pg["{}|0".format(port)] = {
            "profile": "ingress_lossy_profile",
        }
        if not _is_mgmt_port(port, mgmt_port_indices):
            speed, cable = speed_cable_map[port]
            profile_name = "pg_lossless_{}_{}_profile".format(speed, cable)
            buffer_pg["{}|3-4".format(port)] = {
                "profile": profile_name,
            }
    return buffer_pg


def generate_buffer_queue(port_names):
    """Generate the BUFFER_QUEUE table.

    Each port gets three queue range entries:
        0-2  -> egress_lossy_profile
        3-4  -> egress_lossless_profile
        5-6  -> egress_lossy_profile

    Args:
        port_names: list of port name strings

    Returns:
        dict of "port|queue_range" -> {"profile": profile_name}
    """
    buffer_queue = {}
    for port in _sort_port_names(port_names):
        buffer_queue["{}|0-2".format(port)] = {
            "profile": "egress_lossy_profile",
        }
        buffer_queue["{}|3-4".format(port)] = {
            "profile": "egress_lossless_profile",
        }
        buffer_queue["{}|5-6".format(port)] = {
            "profile": "egress_lossy_profile",
        }
    return buffer_queue


def generate_queue_table(port_names):
    """Generate the QUEUE table.

    Each port gets 8 queue entries (0-7) with scheduler assignments.
    Lossless queues (3, 4) also get WRED profiles.

    Args:
        port_names: list of port name strings

    Returns:
        dict of "port|queue_id" -> {scheduler, [wred_profile]}
    """
    queue_table = {}
    for port in _sort_port_names(port_names):
        for qid in range(8):
            entry = {"scheduler": QUEUE_SCHEDULER_MAP[qid]}
            if qid in QUEUE_WRED_MAP:
                entry["wred_profile"] = QUEUE_WRED_MAP[qid]
            queue_table["{}|{}".format(port, qid)] = entry
    return queue_table


def generate_port_qos_map(port_names, mgmt_port_indices=None):
    """Generate the PORT_QOS_MAP table.

    Normal data ports get the full 6-field QoS config (with PFC).
    Management ports get a reduced 3-field config (no PFC).
    A ``global`` entry is always included.

    Args:
        port_names: list of port name strings
        mgmt_port_indices: list of integer port indices that are management
            ports (default: [512, 513])

    Returns:
        dict of port_name_or_global -> qos_fields
    """
    if mgmt_port_indices is None:
        mgmt_port_indices = list(DEFAULT_MGMT_PORT_INDICES)

    qos_map = {}
    for port in _sort_port_names(port_names):
        if _is_mgmt_port(port, mgmt_port_indices):
            qos_map[port] = {
                "dscp_to_tc_map": "AZURE",
                "tc_to_pg_map": "AZURE",
                "tc_to_queue_map": "AZURE",
            }
        else:
            qos_map[port] = {
                "dscp_to_tc_map": "AZURE",
                "pfc_enable": "3,4",
                "pfc_to_queue_map": "AZURE",
                "pfcwd_sw_enable": "3,4",
                "tc_to_pg_map": "AZURE",
                "tc_to_queue_map": "AZURE",
            }

    qos_map["global"] = {
        "dscp_to_tc_map": "AZURE",
    }
    return qos_map


def generate_cable_length(port_names, cable_length_default="40m",
                         port_cable_lengths=None):
    """Generate the CABLE_LENGTH table.

    Uses per-port cable lengths when available, otherwise falls back to
    the default for all ports.

    Args:
        port_names: list of port name strings
        cable_length_default: fallback cable length string (e.g. "40m")
        port_cable_lengths: optional dict of port_name -> cable_length.
            Ports not in this dict get ``cable_length_default``.

    Returns:
        dict with single key "AZURE" mapping port names to lengths
    """
    azure = {}
    for port in _sort_port_names(port_names):
        if port_cable_lengths and port in port_cable_lengths:
            azure[port] = port_cable_lengths[port]
        else:
            azure[port] = cable_length_default
    return {"AZURE": azure}


def generate_scheduler_and_wred():
    """Generate constant SCHEDULER and WRED_PROFILE tables.

    These tables have no per-port variation; values match the reference
    config_db_moby.json.

    Returns:
        tuple of (scheduler_dict, wred_profile_dict)
    """
    scheduler = {
        "SCHEDULER_DEFAULT": {"type": "DWRR", "weight": "10"},
        "SCHEDULER_Q1": {"type": "DWRR", "weight": "10"},
        "SCHEDULER_Q3": {"type": "DWRR", "weight": "20"},
        "SCHEDULER_Q4": {"type": "DWRR", "weight": "10"},
        "SCHEDULER_Q6": {"type": "DWRR", "weight": "70"},
    }

    wred_entry = {
        "ecn": "ecn_all",
        "green_drop_probability": "5",
        "green_max_threshold": "262144",
        "green_min_threshold": "131072",
        "red_drop_probability": "5",
        "red_max_threshold": "262144",
        "red_min_threshold": "131072",
        "wred_green_enable": "true",
        "wred_red_enable": "true",
        "wred_yellow_enable": "true",
        "yellow_drop_probability": "5",
        "yellow_max_threshold": "262144",
        "yellow_min_threshold": "131072",
    }

    wred_profile = {
        "WRED_LOSSLESS_Q3": dict(wred_entry),
        "WRED_LOSSLESS_Q4": dict(wred_entry),
    }

    return scheduler, wred_profile


def generate_all_buffer_tables(port_table,
                               cable_length_default="40m",
                               mgmt_port_indices=None,
                               ingress_pool_size=DEFAULT_INGRESS_POOL_SIZE,
                               egress_pool_size=DEFAULT_EGRESS_POOL_SIZE,
                               port_cable_lengths=None):
    """Generate all buffer and QoS tables for a golden config.

    This is the main entry point. Given a PORT table (as produced by
    ``generate_port_table_from_platform`` or minigraph), it produces all
    8 buffer/QoS tables ready to be merged into the golden config JSON.

    Args:
        port_table: dict of port_name -> port_entry (must have "speed" field)
        cable_length_default: default cable length string (e.g. "40m")
        mgmt_port_indices: list of int port indices for management ports
            (default: [512, 513])
        ingress_pool_size: pool size string for ingress_lossless_pool
        egress_pool_size: pool size string for egress_lossless_pool
        port_cable_lengths: optional dict of port_name -> cable_length.
            When provided, each port uses its own cable length for
            profile selection. Ports not in this dict fall back to
            ``cable_length_default``.

    Returns:
        dict with keys: BUFFER_POOL, BUFFER_PROFILE, BUFFER_PG,
            BUFFER_QUEUE, QUEUE, PORT_QOS_MAP, CABLE_LENGTH,
            SCHEDULER, WRED_PROFILE
    """
    if mgmt_port_indices is None:
        mgmt_port_indices = list(DEFAULT_MGMT_PORT_INDICES)

    port_names = list(port_table.keys())

    # Build per-port (speed, cable_length) mapping
    speed_cable_map = {}
    port_speeds_list = []
    cable_lengths_list = []
    for port in port_names:
        speed = port_table[port].get("speed", "0")
        if port_cable_lengths and port in port_cable_lengths:
            cable = port_cable_lengths[port]
        else:
            cable = cable_length_default
        speed_cable_map[port] = (speed, cable)
        port_speeds_list.append(speed)
        cable_lengths_list.append(cable)

    # Unique (speed, cable) pairs for profile generation
    speed_cable_pairs = set(speed_cable_map.values())

    # Pool xoff from placeholder
    pool_xoff = compute_pool_xoff(port_speeds_list, cable_lengths_list)

    # Generate all tables
    scheduler, wred_profile = generate_scheduler_and_wred()

    result = {
        "BUFFER_POOL": generate_buffer_pool(
            ingress_pool_size, egress_pool_size, pool_xoff),
        "BUFFER_PROFILE": generate_buffer_profiles(speed_cable_pairs),
        "BUFFER_PG": generate_buffer_pg(
            port_names, speed_cable_map, mgmt_port_indices),
        "BUFFER_QUEUE": generate_buffer_queue(port_names),
        "QUEUE": generate_queue_table(port_names),
        "PORT_QOS_MAP": generate_port_qos_map(port_names, mgmt_port_indices),
        "CABLE_LENGTH": generate_cable_length(
            port_names, cable_length_default, port_cable_lengths),
        "SCHEDULER": scheduler,
        "WRED_PROFILE": wred_profile,
    }

    return result
