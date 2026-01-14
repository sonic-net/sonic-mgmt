"""This script is to define helpers for BGP Bounce Back Routing (BBR) related features of SONiC."""

import logging
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


def is_bbr_enabled(duthost):
    bbr_supported, bbr_default_state = get_bbr_default_state(duthost)
    if bbr_supported and bbr_default_state == "enabled":
        return True

    return False


def config_bbr_by_gcu(duthost, status):
    logger.info("Config BGP_BBR by GCU cmd")

    # Check BBR configuration from config_db first
    bbr_config_db_exist = int(duthost.shell('redis-cli -n 4 HEXISTS "BGP_BBR|all" "status"')["stdout"])
    if bbr_config_db_exist:
        json_patch = [{"op": "replace", "path": "/BGP_BBR/all/status", "value": "{}".format(status)}]
    else:
        json_patch = [{"op": "add", "path": "/BGP_BBR/all", "value": {"status": "{}".format(status)}}]

    apply_gcu_patch(duthost, json_patch)
