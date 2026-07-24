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


CRM_READY_RETRIES = 3
CRM_READY_RETRY_INTERVAL = 3


def get_crm_resource_status(duthost, resource, status, namespace=DEFAULT_NAMESPACE):
    # After a `config reload` (e.g. the frr_config_mode mode switch) CRM counters are wiped
    # AND the polling interval reverts to the 300s default, so `crm show resources all` reads
    # back an empty main-resources table until the next poll -- up to a full ~300s cycle, not
    # a brief race. In this module the reads that feed assertions/logic run mid-test with CRM
    # populated; only the informational teardown log lines hit the post-reload empty window.
    # So retry briefly (to absorb any genuine sub-poll race), then return None with a clear
    # warning rather than raising -- an informational read must not fail the run while CRM is
    # merely repopulating. Real callers run when CRM is populated and get their value.
    crm_resources = None
    main_resources = None
    for attempt in range(CRM_READY_RETRIES):
        crm_resources = duthost.get_crm_resources(namespace)
        main_resources = crm_resources.get("main_resources") if crm_resources else None
        if main_resources:
            break
        if attempt < CRM_READY_RETRIES - 1:
            time.sleep(CRM_READY_RETRY_INTERVAL)
    if not main_resources:
        logger.warning("get_crm_resource_status(%s/%s, ns=%s): CRM main_resources empty after "
                       "%d attempts (CRM repopulating after a config reload); returning None. "
                       "Raw get_crm_resources() -> %r", resource, status, namespace,
                       CRM_READY_RETRIES, crm_resources)
        return None
    resource_entry = main_resources.get(resource)
    if resource_entry is None:
        logger.warning("get_crm_resource_status(%s/%s, ns=%s): resource %r absent from CRM "
                       "main_resources; returning None. Available: %s",
                       resource, status, namespace, resource, sorted(main_resources))
        return None
    return resource_entry.get(status)


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
