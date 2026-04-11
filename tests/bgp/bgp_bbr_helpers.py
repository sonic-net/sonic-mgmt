"""This script is to define helpers for BGP Bounce Back Routing (BBR) related features of SONiC."""

import logging
import time
import yaml

from tests.common.gu_utils import apply_patch, expect_op_success
from tests.common.gu_utils import generate_tmpfile, delete_tmpfile

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
        # Field exists - replace the value
        json_patch = [{"op": "replace", "path": "/BGP_BBR/all/status", "value": "{}".format(status)}]
    elif bbr_key_exists:
        # Key exists but no status field - add the field
        json_patch = [{"op": "add", "path": "/BGP_BBR/all/status", "value": "{}".format(status)}]
    else:
        # Neither exists - add the whole entry
        json_patch = [{"op": "add", "path": "/BGP_BBR/all", "value": {"status": "{}".format(status)}}]

    logger.info("Applying GCU patch: %s", json_patch)
    tmpfile = generate_tmpfile(duthost)
    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
    except Exception as e:
        logger.error(
            "GCU patch for BGP_BBR failed (possible schema drift): %s. "
            "Falling back to direct redis-cli HSET.",
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
    finally:
        delete_tmpfile(duthost, tmpfile)
