import concurrent.futures
from tests.common.config_reload import config_reload
from tests.common.helpers.assertions import pytest_assert
import logging
logger = logging.getLogger(__name__)


def validate_status(status):
    pytest_assert(status in ["enabled", "disabled"], "Invalid tunnel_qos_remap status {}".format(status))


def bool_to_status(is_enabled : bool):
    return "enabled" if is_enabled else "disabled"


def validate_pfc_buffer_pg_synced(duthost):
    """
    Assert that the running config DB has PFC enabled on a port/priority if-and-only-if
    there's a lossless buffer profile on the corresponding PG. Assumes a 1-1 lossless
    relationship between PGs and priorities.
    """
    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    pfc_enabled_locs = set()
    for port in config_facts['PORT_QOS_MAP']:
        port_qos = config_facts['PORT_QOS_MAP'][port]
        if 'pfc_enable' in port_qos:
            enabled_prios = port_qos['pfc_enable'].split(',')
            for prio in enabled_prios:
                pfc_enabled_locs.add((port, prio))
    buffer_pg_lossless_locs = set()
    for port in config_facts['BUFFER_PG']:
        for prio_range in config_facts['BUFFER_PG'][port]:
            if 'lossless' not in config_facts['BUFFER_PG'][port][prio_range]['profile']:
                # Skip non-lossless profiles
                continue
            # Supports 'a-b' and 'c' syntax
            prios = []
            if '-' in prio_range:
                lhs_prio, rhs_prio = prio_range.split('-')
                pytest_assert(int(lhs_prio) < int(rhs_prio), "Invalid priority range in config DB {}".format(prio_range))
                for prio in range(int(lhs_prio), int(rhs_prio) + 1):
                    prios.append(str(prio))
            else:
                prios.append(prio_range)
            for prio in prios:
                buffer_pg_lossless_locs.add((port, prio))
    missing_buffer_pg = pfc_enabled_locs - buffer_pg_lossless_locs
    pytest_assert(len(missing_buffer_pg) == 0, "Missing lossless buffer profile at {}".format(missing_buffer_pg))
    extra_buffer_pg = buffer_pg_lossless_locs - pfc_enabled_locs
    pytest_assert(len(extra_buffer_pg) == 0, "Extra lossless buffer profile at {}".format(extra_buffer_pg))

def get_tunnel_qos_remap(duthost):
    rv = duthost.shell('redis-cli -n 4 HGET "SYSTEM_DEFAULTS|tunnel_qos_remap" "status"')
    pytest_assert(rv['rc'] == 0, "Failed to get tunnel_qos_remap state")
    status = rv['stdout'].strip()
    validate_status(status)
    return status


def set_tunnel_qos_remap(duthost, is_enabled : bool):
    old_status = get_tunnel_qos_remap(duthost)
    new_status = bool_to_status(is_enabled)
    if old_status != new_status:
        logger.info("Changing duthost {} tunnel_qos_remap from {} to {}".format(duthost.hostname, old_status, new_status))
        rv = duthost.shell('redis-cli -n 4 HSET "SYSTEM_DEFAULTS|tunnel_qos_remap" "status" {}'.format(new_status))
        pytest_assert(rv['rc'] == 0, "Failed to set tunnel_qos_remap state")
        modified_status = get_tunnel_qos_remap(duthost)
        pytest_assert(modified_status == new_status, "Failed to change duthost {} status to the target status {}, got {}".format(
            duthost.hostname, new_status, modified_status))

        # Regenerate QOS config with new setting
        rv = duthost.shell('config qos reload')
        pytest_assert(rv['rc'] == 0, "Failed to perform qos reload, stdout: {}, stderr: {}".format(rv['stdout'], rv['stderr']))

        # Save config
        rv = duthost.shell('config save -y')
        pytest_assert(rv['rc'] == 0, "Failed to config save, stdout: {}, stderr: {}".format(rv['stdout'], rv['stderr']))

        # Reload config since the buffer config manager may not detect the lossless buffer profile changes
        config_reload(duthost, yang_validate=False)

        # Validate buffer config manager has populated the lossless BUFFER_PG profiles
        validate_pfc_buffer_pg_synced(duthost)

        # Save config again with lossless profiles applied by the buffer config manager
        rv = duthost.shell('config save -y')
        pytest_assert(rv['rc'] == 0, "Failed to config save after reload, stdout: {}, stderr: {}".format(rv['stdout'], rv['stderr']))


def set_tunnel_qos_remap_multidut(duthosts, is_enabled : bool, is_parallel=True):
    """
    Perform set_tunnel_qos_remap in parallel over all duthosts.
    """
    if is_parallel:
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(duthosts)) as executor:
            # Submit tasks to the thread pool in a list comprehension
            futures = [executor.submit(set_tunnel_qos_remap, duthost, is_enabled) for duthost in duthosts]
            # Process results as they are completed
            for future in concurrent.futures.as_completed(futures):
                # Any assertion exceptions should be rethrown from here
                future.result()
    else:
        for duthost in duthosts:
            set_tunnel_qos_remap(duthost, is_enabled)
