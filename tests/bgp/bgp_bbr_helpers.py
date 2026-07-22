"""This script is to define helpers for BGP Bounce Back Routing (BBR) related features of SONiC."""

import logging
import time
import yaml

from tests.common.gcu_utils import apply_gcu_patch

CONSTANTS_FILE = "/etc/sonic/constants.yml"
logger = logging.getLogger(__name__)


def get_bbr_default_state(duthost):
    bbr_supported = False
    bbr_default_state = "disabled"

    # Check BBR configuration from config_db first
    bbr_config_db_exist = int(duthost.shell('redis-cli -n 4 HEXISTS "BGP_BBR|all" "status"')["stdout"])
    if bbr_config_db_exist:
        # key exist, BBR is supported
        bbr_supported = True
        bbr_default_state = duthost.shell('redis-cli -n 4 HGET "BGP_BBR|all" "status"')["stdout"]
    else:
        # Check BBR configuration from constants.yml
        constants = yaml.safe_load(duthost.shell("cat {}".format(CONSTANTS_FILE))["stdout"])
        try:
            bbr_supported = constants["constants"]["bgp"]["bbr"]["enabled"]
            if not bbr_supported:
                return bbr_supported, bbr_default_state
            bbr_default_state = constants["constants"]["bgp"]["bbr"]["default_state"]
        except KeyError:
            return bbr_supported, bbr_default_state

    return bbr_supported, bbr_default_state


def program_bbr_for_mode(duthost, enabled):
    """Make BBR take effect regardless of FRR config mode.

    In traditional (bgpcfgd) mode the BGP_BBR table is consumed by bgpcfgd, which
    applies ``allowas-in 1`` to the BBR-enabled peer-groups -- nothing extra is
    needed here. In frr_mgmt_framework mode frrcfgd does not consume BGP_BBR, but it
    *does* support allowas-in natively (BGP_PEER_GROUP_AF ``allow_as_in``), so program
    the equivalent directly on every peer-group address-family. Callers still set the
    BGP_BBR table (so its value is asserted / persisted); this just adds the frr-native
    realization. frrcfgd not consuming BGP_BBR is by design -- it uses the native
    allowas-in schema rather than the bgpcfgd convenience table.
    """
    if not duthost.get_frr_mgmt_framework_config():
        return
    pg_af_keys = [k for k in duthost.shell(
        'sonic-db-cli CONFIG_DB KEYS "BGP_PEER_GROUP_AF|*"')["stdout"].splitlines() if k.strip()]
    peer_groups = set()
    for key in pg_af_keys:
        fields = key.split("|")            # BGP_PEER_GROUP_AF|<vrf>|<pg>|<afi_safi>
        if len(fields) >= 4:
            peer_groups.add(fields[2])
        if enabled:
            duthost.shell("sonic-db-cli CONFIG_DB hset '{}' allow_as_in true allow_as_count 1".format(key))
        else:
            duthost.shell("sonic-db-cli CONFIG_DB hdel '{}' allow_as_in allow_as_count".format(key))
    time.sleep(3)
    # Re-evaluate already-received routes so allowas-in takes effect on live sessions,
    # mirroring bgpcfgd's BBRMgr restart_peer_groups (clear bgp peer-group <pg> soft in).
    for pg in sorted(peer_groups):
        duthost.shell('sudo vtysh -c "clear bgp peer-group {} soft in"'.format(pg),
                      module_ignore_errors=True)
    time.sleep(3)


def is_bbr_enabled(duthost):
    bbr_supported, bbr_default_state = get_bbr_default_state(duthost)
    if bbr_supported and bbr_default_state == "enabled":
        return True

    return False


def config_bbr_by_gcu(duthost, status):
    logger.info("Config BGP_BBR to '%s' by GCU cmd", status)

    # Check both key existence and field existence to pick the right JSON patch op
    bbr_key_exists = int(duthost.shell(
        'redis-cli -n 4 EXISTS "BGP_BBR|all"', module_ignore_errors=True
    )["stdout"])
    bbr_field_exists = int(duthost.shell(
        'redis-cli -n 4 HEXISTS "BGP_BBR|all" "status"', module_ignore_errors=True
    )["stdout"])

    logger.info("BGP_BBR|all key exists: %d, status field exists: %d", bbr_key_exists, bbr_field_exists)

    if bbr_field_exists:
        # Field exists — replace the value
        json_patch = [{"op": "replace", "path": "/BGP_BBR/all/status", "value": "{}".format(status)}]
    elif bbr_key_exists:
        # Key exists but no status field — add the field
        json_patch = [{"op": "add", "path": "/BGP_BBR/all/status", "value": "{}".format(status)}]
    else:
        # Neither exists — add the whole entry
        json_patch = [{"op": "add", "path": "/BGP_BBR/all", "value": {"status": "{}".format(status)}}]

    logger.info("Applying GCU patch: %s", json_patch)
    try:
        apply_gcu_patch(duthost, json_patch)
    except Exception as e:
        # The redis-cli fallback bypasses GCU schema validation.  If the GCU
        # failure is due to a schema violation this could put CONFIG_DB into an
        # inconsistent state, so log at error level for post-run diagnosis.
        logger.error(
            "GCU patch for BGP_BBR failed (possible schema drift): %s. "
            "Falling back to direct redis-cli HSET — CONFIG_DB may be inconsistent.",
            e,
        )
        duthost.shell(
            'redis-cli -n 4 HSET "BGP_BBR|all" "status" "{}"'.format(status),
            module_ignore_errors=True,
        )
        # Allow bgpcfgd to pick up the CONFIG_DB change
        time.sleep(3)
        # Verify the fallback took effect
        actual = duthost.shell(
            'redis-cli -n 4 HGET "BGP_BBR|all" "status"', module_ignore_errors=True
        )["stdout"].strip()
        if actual != status:
            raise RuntimeError(
                "Failed to set BGP_BBR status to '{}' via both GCU and redis-cli fallback. "
                "Current value: '{}'".format(status, actual)
            )
