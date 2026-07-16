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


CRM_READY_RETRIES = 6
CRM_READY_RETRY_INTERVAL = 5


def get_crm_resource_status(duthost, resource, status, namespace=DEFAULT_NAMESPACE):
    # `crm show resources all` can transiently read back an empty main-resources table:
    # CRM counters are wiped and only repopulated on the next polling cycle after a
    # `config reload` (e.g. the frr_config_mode mode switch reverts the short polling
    # interval set_polling_interval installs back to the 300s default), and the show
    # command itself can race a poll refresh. Retry briefly to absorb that readiness gap
    # before dereferencing, and if it never populates raise a clear error naming the
    # resource instead of an opaque AttributeError on None.
    crm_resources = None
    main_resources = None
    for attempt in range(CRM_READY_RETRIES):
        crm_resources = duthost.get_crm_resources(namespace)
        main_resources = crm_resources.get("main_resources") if crm_resources else None
        if main_resources:
            break
        logger.warning("get_crm_resource_status(%s/%s, ns=%s): 'main_resources' missing/empty "
                       "(attempt %d/%d); raw get_crm_resources() -> %r",
                       resource, status, namespace, attempt + 1, CRM_READY_RETRIES, crm_resources)
        if attempt < CRM_READY_RETRIES - 1:
            time.sleep(CRM_READY_RETRY_INTERVAL)
    if not main_resources:
        raise RuntimeError(
            "CRM main_resources never populated for {}/{} (ns={}) after {} attempts; "
            "last raw get_crm_resources() -> {!r}".format(
                resource, status, namespace, CRM_READY_RETRIES, crm_resources))
    resource_entry = main_resources.get(resource)
    if resource_entry is None:
        raise RuntimeError(
            "CRM resource {!r} not present in main_resources (ns={}); available: {}".format(
                resource, namespace, sorted(main_resources)))
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
