"""
Helper module for the SRv6 max throughput minimum packet size test.
"""
import os
import yaml
import logging
import time

from tests.common.helpers.srv6_helper import (
    create_srv6_locator,
    create_srv6_sid,
    del_srv6_locator,
    del_srv6_sid,
    SRv6,
)

logger = logging.getLogger(__name__)

CONFIG_FILE = os.path.join(os.path.dirname(__file__), "max_throughput_config.yaml")


def load_max_throughput_config():
    """Load the YAML config for the max throughput test."""
    with open(CONFIG_FILE, "r") as f:
        return yaml.safe_load(f)


def get_platform_thresholds(duthost, config):
    """Look up min-packet-size thresholds for the DUT's platform. Returns None if unknown."""
    platform = duthost.facts.get("hwsku", "")
    thresholds = config.get("platform_thresholds", {})

    if platform in thresholds:
        return thresholds[platform]

    # Try partial match (e.g. "Nvidia 5640" in "Nvidia-5640-O28")
    for key in thresholds:
        if key.lower().replace(" ", "") in platform.lower().replace("-", "").replace(" ", ""):
            return thresholds[key]

    return None


# ---------------------------------------------------------------------------
# Feature toggle helpers
# ---------------------------------------------------------------------------

def _get_front_panel_ports(duthost):
    """Return list of admin-up front-panel Ethernet ports on the DUT."""
    import json as _json
    result = duthost.shell("portstat -j")["stdout"]
    port_data = _json.loads(result)
    # STATE: U=Up, D=Down, X=Disabled (admin-down)
    return sorted(
        [port for port, stats in port_data.items() if stats.get("STATE") != "X"],
        key=lambda p: (len(p), p),
    )


def _dataacl_exists(duthost):
    """Check if DATAACL table exists."""
    lines = duthost.shell(cmd="show acl table DATAACL")["stdout_lines"]
    return any("DATAACL" in line for line in lines)


def _verify_acl_table_ports(duthost, table_name, expected_ports):
    """Verify that the ACL table is bound to the expected ports."""
    output = duthost.shell("show acl table {}".format(table_name))["stdout"]
    for port in expected_ports:
        if port not in output:
            logger.warning("ACL table %s not attached to port %s", table_name, port)
            return False
    logger.info("ACL table %s verified on all %d ports", table_name, len(expected_ports))
    return True


def _verify_acl_table_removed(duthost, table_name):
    """Verify that the ACL table no longer exists."""
    output = duthost.shell("show acl table {}".format(table_name))["stdout"]
    if table_name in output:
        logger.warning("ACL table %s still exists after removal", table_name)
        return False
    logger.info("ACL table %s confirmed removed", table_name)
    return True


# --- DataACL ---

def enable_dataacl(duthost):
    """Add DATAACL L3 table bound to all front-panel ports."""
    if _dataacl_exists(duthost):
        logger.info("DATAACL already exists on %s, skipping", duthost.hostname)
        return
    ports = _get_front_panel_ports(duthost)
    cmd = "config acl add table DATAACL L3 -p {}".format(",".join(ports))
    logger.info("Enabling DATAACL on %s", duthost.hostname)
    duthost.shell(cmd)
    duthost.shell("config save -y")
    if not _verify_acl_table_ports(duthost, "DATAACL", ports):
        raise RuntimeError("DATAACL not attached to all ports on {}".format(duthost.hostname))


def disable_dataacl(duthost):
    """Remove DATAACL table if it exists."""
    if not _dataacl_exists(duthost):
        logger.info("DATAACL does not exist on %s, skipping removal", duthost.hostname)
        return
    logger.info("Removing DATAACL on %s", duthost.hostname)
    duthost.shell("config acl remove table DATAACL")
    duthost.shell("config save -y")
    if not _verify_acl_table_removed(duthost, "DATAACL"):
        raise RuntimeError("DATAACL not fully removed on {}".format(duthost.hostname))


# --- Everflow (IPv4 mirror) ---

EVERFLOW_SESSION = "max_tput_ev4_session"
EVERFLOW_TABLE = "EVERFLOW"
MIRROR_SRC_IP = "10.10.10.1"
MIRROR_DST_IP = "10.10.10.2"
MIRROR_DSCP = "8"
MIRROR_TTL = "64"


def _mirror_session_exists(duthost, session_name):
    output = duthost.shell("show mirror_session {}".format(session_name))["stdout"]
    return session_name in output


def enable_everflow(duthost):
    """Create ERSPAN mirror session and EVERFLOW ACL table."""
    if not _mirror_session_exists(duthost, EVERFLOW_SESSION):
        logger.info("Creating Everflow mirror session on %s", duthost.hostname)
        duthost.shell(
            "config mirror_session add {} {} {} {} {}".format(
                EVERFLOW_SESSION, MIRROR_SRC_IP, MIRROR_DST_IP, MIRROR_DSCP, MIRROR_TTL
            )
        )

    lines = duthost.shell("show acl table EVERFLOW")["stdout_lines"]
    if not any("EVERFLOW" in line for line in lines):
        ports = _get_front_panel_ports(duthost)
        duthost.shell(
            "config acl add table EVERFLOW MIRROR -p {}".format(",".join(ports))
        )
        if not _verify_acl_table_ports(duthost, "EVERFLOW", ports):
            raise RuntimeError("EVERFLOW not attached to all ports on {}".format(duthost.hostname))
    duthost.shell("config save -y")


def disable_everflow(duthost):
    """Remove EVERFLOW ACL table and mirror session."""
    lines = duthost.shell("show acl table EVERFLOW")["stdout_lines"]
    if any("EVERFLOW" in line for line in lines):
        duthost.shell("config acl remove table EVERFLOW")
        if not _verify_acl_table_removed(duthost, "EVERFLOW"):
            raise RuntimeError("EVERFLOW not fully removed on {}".format(duthost.hostname))

    if _mirror_session_exists(duthost, EVERFLOW_SESSION):
        duthost.shell("config mirror_session remove {}".format(EVERFLOW_SESSION))
    duthost.shell("config save -y")


# --- EverflowV6 (IPv6 mirror) ---

EVERFLOWV6_SESSION = "max_tput_ev6_session"
EVERFLOWV6_TABLE = "EVERFLOWV6"
MIRROR_SRC_IPV6 = "fc00::1"
MIRROR_DST_IPV6 = "fc00::2"


def enable_everflowv6(duthost):
    """Create ERSPANv6 mirror session and EVERFLOWV6 ACL table."""
    if not _mirror_session_exists(duthost, EVERFLOWV6_SESSION):
        duthost.shell(
            "config mirror_session add {} {} {} {} {}".format(
                EVERFLOWV6_SESSION, MIRROR_SRC_IPV6, MIRROR_DST_IPV6, MIRROR_DSCP, MIRROR_TTL
            )
        )

    lines = duthost.shell("show acl table EVERFLOWV6")["stdout_lines"]
    if not any("EVERFLOWV6" in line for line in lines):
        ports = _get_front_panel_ports(duthost)
        duthost.shell(
            "config acl add table EVERFLOWV6 MIRRORV6 -p {}".format(",".join(ports))
        )
        if not _verify_acl_table_ports(duthost, "EVERFLOWV6", ports):
            raise RuntimeError("EVERFLOWV6 not attached to all ports on {}".format(duthost.hostname))
    duthost.shell("config save -y")


def disable_everflowv6(duthost):
    """Remove EVERFLOWV6 ACL table and mirror session."""
    lines = duthost.shell("show acl table EVERFLOWV6")["stdout_lines"]
    if any("EVERFLOWV6" in line for line in lines):
        duthost.shell("config acl remove table EVERFLOWV6")
        if not _verify_acl_table_removed(duthost, "EVERFLOWV6"):
            raise RuntimeError("EVERFLOWV6 not fully removed on {}".format(duthost.hostname))

    if _mirror_session_exists(duthost, EVERFLOWV6_SESSION):
        duthost.shell("config mirror_session remove {}".format(EVERFLOWV6_SESSION))
    duthost.shell("config save -y")


# --- IPinIP Decap ---

IPINIP_DECAP_CONF_TEMPLATE = """[
    {{
        "TUNNEL_DECAP_TERM_TABLE:IPINIP_TUNNEL:{loopback_ip}": {{
            "term_type": "P2MP"
        }},
        "OP": "{op}"
    }},
    {{
        "TUNNEL_DECAP_TABLE:IPINIP_TUNNEL": {{
            "tunnel_type": "IPINIP",
            "dscp_mode": "pipe",
            "ecn_mode": "copy_from_outer",
            "ttl_mode": "pipe"
        }},
        "OP": "{op}"
    }}
]"""


def _get_loopback_ip(duthost):
    """Return the first Loopback0 IPv4 address."""
    result = duthost.shell(
        "sonic-db-cli CONFIG_DB keys 'LOOPBACK_INTERFACE|Loopback0|*'"
    )["stdout"].strip()
    for line in result.splitlines():
        parts = line.split("|")
        if len(parts) >= 3:
            ip = parts[2].split("/")[0]
            if "." in ip:
                return ip
    return "10.1.0.32"


def enable_ipinip_decap(duthost):
    """Configure IPINIP decap tunnel via swssconfig."""
    loopback_ip = _get_loopback_ip(duthost)
    conf = IPINIP_DECAP_CONF_TEMPLATE.format(loopback_ip=loopback_ip, op="SET")
    logger.info("Enabling IPinIP decap on %s (loopback=%s)", duthost.hostname, loopback_ip)

    duthost.copy(content=conf, dest="/tmp/ipinip_decap_set.json")
    for asic_id in duthost.get_frontend_asic_ids():
        swss = "swss{}".format(asic_id if asic_id is not None else "")
        cmds = [
            "docker cp /tmp/ipinip_decap_set.json {}:/ipinip_decap_set.json".format(swss),
            "docker exec {} swssconfig /ipinip_decap_set.json".format(swss),
            "docker exec {} rm /ipinip_decap_set.json".format(swss),
        ]
        duthost.shell_cmds(cmds=cmds)


def _verify_ipinip_decap_removed(duthost):
    """Verify that all IPINIP decap tunnel entries are removed from APP_DB."""
    result = duthost.shell(
        'sonic-db-cli APPL_DB KEYS "TUNNEL_DECAP_TABLE:IPINIP_TUNNEL*"',
        module_ignore_errors=True,
    )["stdout"].strip()
    if result:
        logger.warning("IPinIP decap entries still present in APPL_DB: %s", result)
        return False

    term_result = duthost.shell(
        'sonic-db-cli APPL_DB KEYS "TUNNEL_DECAP_TERM_TABLE:IPINIP_TUNNEL*"',
        module_ignore_errors=True,
    )["stdout"].strip()
    if term_result:
        logger.warning("IPinIP decap term entries still present in APPL_DB: %s", term_result)
        return False

    logger.info("All IPinIP decap entries successfully removed from APPL_DB")
    return True


def disable_ipinip_decap(duthost):
    """Remove IPINIP decap tunnel via swssconfig."""
    loopback_ip = _get_loopback_ip(duthost)
    conf = IPINIP_DECAP_CONF_TEMPLATE.format(loopback_ip=loopback_ip, op="DEL")
    logger.info("Disabling IPinIP decap on %s", duthost.hostname)

    duthost.copy(content=conf, dest="/tmp/ipinip_decap_del.json")
    for asic_id in duthost.get_frontend_asic_ids():
        swss = "swss{}".format(asic_id if asic_id is not None else "")
        cmds = [
            "docker cp /tmp/ipinip_decap_del.json {}:/ipinip_decap_del.json".format(swss),
            "docker exec {} swssconfig /ipinip_decap_del.json".format(swss),
            "docker exec {} rm /ipinip_decap_del.json".format(swss),
        ]
        duthost.shell_cmds(cmds=cmds)

    if not _verify_ipinip_decap_removed(duthost):
        raise RuntimeError("IPinIP decap entries were not fully removed on {}".format(duthost.hostname))


def enable_usid_decap(duthost, config):
    """Create SRv6 locator and SID for uSID shift-and-forward."""
    srv6_cfg = config.get("srv6", {})
    locator_name = srv6_cfg.get("locator_name", "loc1")
    locator_prefix = srv6_cfg.get("locator_prefix", "fcbb:bbbb:1::")
    sid_ip = srv6_cfg.get("sid_ip", "fcbb:bbbb:1::")
    action = srv6_cfg.get("sid_action", SRv6.uN)
    decap_vrf = srv6_cfg.get("decap_vrf", "default")
    dscp_mode = srv6_cfg.get("decap_dscp_mode", SRv6.pipe_mode)

    logger.info("Enabling uSID decap on %s (locator=%s)", duthost.hostname, locator_name)
    create_srv6_locator(
        duthost,
        locator_name,
        locator_prefix,
        block_len=srv6_cfg.get("block_len", 32),
        node_len=srv6_cfg.get("node_len", 16),
        func_len=srv6_cfg.get("func_len", 0),
        arg_len=srv6_cfg.get("arg_len", 0),
    )
    create_srv6_sid(
        duthost,
        locator_name,
        sid_ip,
        action=action,
        decap_vrf=decap_vrf,
        decap_dscp_mode=dscp_mode,
    )
    duthost.shell("config save -y")


def disable_usid_decap(duthost, config):
    """Remove SRv6 locator and SID."""
    srv6_cfg = config.get("srv6", {})
    locator_name = srv6_cfg.get("locator_name", "loc1")
    sid_ip = srv6_cfg.get("sid_ip", "fcbb:bbbb:1::")

    logger.info("Disabling uSID decap on %s", duthost.hostname)
    del_srv6_sid(duthost, locator_name, sid_ip)
    del_srv6_locator(duthost, locator_name)
    duthost.shell("config save -y")


# ---------------------------------------------------------------------------
# DUT config backup/restore
# ---------------------------------------------------------------------------

CONFIG_DB_PATH = "/etc/sonic/config_db.json"
CONFIG_DB_BACKUP_PATH = "/host/config_db.json.before_max_throughput_test"


def backup_dut_config(duthost):
    """Save running config and back up config_db.json for later restoration."""
    logger.info("Backing up DUT config on %s", duthost.hostname)
    # Persist current running config to config_db.json
    duthost.shell("config save -y")
    # Copy config_db.json to a backup location
    duthost.shell("cp {} {}".format(CONFIG_DB_PATH, CONFIG_DB_BACKUP_PATH))
    logger.info("Config backed up to %s", CONFIG_DB_BACKUP_PATH)


def restore_dut_config(duthost):
    """Restore config_db.json from backup and reload."""
    logger.info("Restoring DUT config on %s", duthost.hostname)
    result = duthost.shell("test -f {}".format(CONFIG_DB_BACKUP_PATH), module_ignore_errors=True)
    if result["rc"] != 0:
        logger.warning("Backup file %s not found, skipping restore", CONFIG_DB_BACKUP_PATH)
        return

    duthost.shell("cp {} {}".format(CONFIG_DB_BACKUP_PATH, CONFIG_DB_PATH))
    duthost.shell("config reload -y", module_ignore_errors=True)
    time.sleep(60)
    duthost.shell("rm -f {}".format(CONFIG_DB_BACKUP_PATH))


# ---------------------------------------------------------------------------
# Scenario orchestration
# ---------------------------------------------------------------------------

# Map feature keys to (enable_fn, disable_fn) pairs.
FEATURE_TOGGLE_MAP = {
    "dataacl": (enable_dataacl, disable_dataacl),
    "everflow": (enable_everflow, disable_everflow),
    "everflowv6": (enable_everflowv6, disable_everflowv6),
    "ipinip_decap": (enable_ipinip_decap, disable_ipinip_decap),
    "usid_decap": (enable_usid_decap, disable_usid_decap),
}


def _call_feature_fn(fn, duthost, feature_key, config):
    """Call a feature toggle function, passing config if needed."""
    if feature_key in ("usid_decap",):
        fn(duthost, config)
    else:
        fn(duthost)


def cleanup_all_features(duthost, config):
    """Disable all features to reach a clean baseline."""
    logger.info("Cleaning all features on %s to reach baseline", duthost.hostname)
    for feature_key, (_, disable_fn) in FEATURE_TOGGLE_MAP.items():
        try:
            _call_feature_fn(disable_fn, duthost, feature_key, config)
        except Exception as e:
            logger.warning("Failed to disable %s on %s: %s", feature_key, duthost.hostname, e)


def configure_scenario(duthost, scenario_name, config):
    """Configure DUT for a scenario: clean baseline then enable required features."""
    scenario = config["scenarios"][scenario_name]
    logger.info(
        "Configuring scenario '%s' (%s) on %s",
        scenario_name, scenario.get("description", ""), duthost.hostname,
    )

    cleanup_all_features(duthost, config)
    time.sleep(5)

    enabled_features = []
    for feature_key, (enable_fn, _) in FEATURE_TOGGLE_MAP.items():
        if scenario.get(feature_key, False):
            logger.info("Enabling feature: %s", feature_key)
            _call_feature_fn(enable_fn, duthost, feature_key, config)
            enabled_features.append(feature_key)

    # Allow configs to settle
    time.sleep(10)
    return enabled_features
