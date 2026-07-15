import logging
import re
import time

from tests.common.helpers.constants import DEFAULT_NAMESPACE

logger = logging.getLogger(__name__)

TOPO_FILENAME_TEMPLATE = 'topo_{}.yml'
SHOW_BGP_SUMMARY_CMD = "show ip bgp summary"
LOOP_TIMES_LEVEL_MAP = {
    'debug': 1,
    'basic': 10,
    'confident': 50,
    'thorough': 100,
    'diagnose': 200
}


def get_crm_resource_status(duthost, resource, status, namespace=DEFAULT_NAMESPACE):
    crm_resources = duthost.get_crm_resources(namespace)
    main_resources = crm_resources.get("main_resources") if crm_resources else None
    if not main_resources:
        # CRM can read back empty/incomplete right after a `config reload` (e.g. the
        # frr_config_mode restore reload at module teardown) before crmconfig repopulates
        # STATE_DB. Log the raw payload so the next run shows whether this is a readiness
        # race (empty dict) vs a structural change, rather than an opaque AttributeError
        # on None. Behavior is otherwise unchanged (the deref below still raises).
        logger.warning("get_crm_resource_status(%s/%s, ns=%s): 'main_resources' missing/empty; "
                       "raw get_crm_resources() -> %r", resource, status, namespace, crm_resources)
    return main_resources.get(resource).get(status)


def check_queue_status(duthost, queue):
    bgp_neighbors = duthost.show_and_parse(SHOW_BGP_SUMMARY_CMD)
    bgp_neighbor_addr_regex = re.compile(r"^([0-9]{1,3}\.){3}[0-9]{1,3}")
    for neighbor in bgp_neighbors:
        if "neighbhor" in neighbor:
            neigh = neighbor["neighbhor"]
        else:
            neigh = neighbor["neighbor"]
        if bgp_neighbor_addr_regex.match(neigh) and int(neighbor[queue]) != 0:
            return False
    return True


def sleep_to_wait(seconds):
    if seconds > 300:
        seconds = 300
    time.sleep(seconds)
