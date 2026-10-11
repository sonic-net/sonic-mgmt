import logging
import os
from shlex import quote
from enum import Enum
from collections import namedtuple

from tests.common.helpers.multi_thread_utils import SafeThreadPoolExecutor

logger = logging.getLogger(__name__)


# Parametrization for the NASA CLI helper commands
NASA_DEBUG_ENTITY_CONTENT = namedtuple("NASA_DEBUG_ENTITY_CONTENT", ["title", "nasa_helper_key", "config_key"])
NASA_DEBUG_DUMP_DIR = "/var/log/bluefield/sdk-dumps"
NASA_CT_DUMP_SENTINEL = "/var/run/sonic-platform-nvidia-bluefield/techsupport-sdk-ct-dump.enabled"
NASA_CT_DUMP_FILES = [
    "stats.log.gz",
    "stats_query.log.gz",
    "general.log.gz",
    "routing.log.gz",
    "vnets.dump.gz",
    "counters.dump.gz",
    "enis.log.gz",
    "acls.log.gz",
    "meter_policies.log.gz",
    "crm.log.gz",
    "ct_table_log.bin.gz",
    "ct_table_log_ipvx.bin.gz",
]
NASA_FLOW_DUMP_PATTERN = "flow_dump_*.jsonl.gz"
NASA_MST_DUMP_PATTERNS = [
    "mstdump_full_*_iter1of3.log.gz",
    "mstdump_full_*_iter2of3.log.gz",
    "mstdump_full_*_iter3of3.log.gz",
]


class NASA_DEBUG_ENTITY(Enum):
    CONFIG_RECORD = NASA_DEBUG_ENTITY_CONTENT(title="Configuration Record",
                                              nasa_helper_key="get_sai_debug_mode",
                                              config_key="config-record")
    PACKET_DROP = NASA_DEBUG_ENTITY_CONTENT(title="Packet Drop",
                                            nasa_helper_key="get_packet_debug_mode",
                                            config_key="packet-drop")


def get_nasa_entity_debug_enabled(dpuhost, entity):
    """Check if a NASA debug entity is enabled on a DPU.

    Args:
        dpuhost: DPU host object
        entity: NASA_DEBUG_ENTITY enum member

    Returns:
        bool: True if enabled, False if disabled

    Raises:
        ValueError: If the status is neither 'enabled' nor 'disabled'
    """
    result = dpuhost.shell(f"nasa-cli-helper.py {entity.value.nasa_helper_key}")['stdout'].strip()
    if result == "disabled":
        return False
    if result == "enabled":
        return True

    raise ValueError(f"Unexpected {entity.value.title} status: {result}")


def get_nasa_entity_debug_file(dpuhost, entity):
    """Get the current debug file path for a NASA debug entity.

    Args:
        dpuhost: DPU host object
        entity: NASA_DEBUG_ENTITY enum member

    Returns:
        str or None: File path if debug is active and file exists, None otherwise
    """
    result = dpuhost.shell(f"nasa-cli-helper.py {entity.value.nasa_helper_key} -f")
    debug_file = result['stdout'].rstrip('\x00').strip()
    # check if the file exists
    if debug_file != "None" and dpuhost.shell(f"stat {quote(debug_file)}")['rc'] == 0:
        return debug_file
    return None


def nasa_entity_debug_set(dpuhost, entity, enable):
    """Enable or disable a NASA debug entity on a DPU.

    Args:
        dpuhost: DPU host object
        entity: NASA_DEBUG_ENTITY enum member
        enable: bool - True to enable, False to disable
    """
    logger.info(f"{'Enabling' if enable else 'Disabling'} NASA {entity.value.title} on {dpuhost.hostname}")
    dpuhost.shell(f"sudo config platform nvidia-bluefield sdk "
                  f"{entity.value.config_key} {'enabled' if enable else 'disabled'}")


def nasa_debuggability_enable(dpuhost):
    """Enable all NASA debug entities on a single DPU."""
    for entity in NASA_DEBUG_ENTITY:
        nasa_entity_debug_set(dpuhost, entity, True)


def nasa_debuggability_enable_all(dpuhosts):
    """Enable all NASA debug entities on all DPUs in parallel."""
    with SafeThreadPoolExecutor(max_workers=len(dpuhosts)) as executor:
        for temp_dpuhost in dpuhosts:
            executor.submit(nasa_debuggability_enable, temp_dpuhost)


def nasa_debuggability_disable(dpuhost):
    """Disable all NASA debug entities on a single DPU."""
    for entity in NASA_DEBUG_ENTITY:
        nasa_entity_debug_set(dpuhost, entity, False)


def nasa_debuggability_disable_all(dpuhosts):
    """Disable all NASA debug entities on all DPUs in parallel."""
    with SafeThreadPoolExecutor(max_workers=len(dpuhosts)) as executor:
        for temp_dpuhost in dpuhosts:
            executor.submit(nasa_debuggability_disable, temp_dpuhost)


def get_file_size(dpuhost, file_path):
    """Get file size in bytes using stat command.

    Args:
        dpuhost: DPU host object
        file_path: Path to the file on the DPU

    Returns:
        int: File size in bytes
    """
    result = dpuhost.shell(f"stat -c %s {file_path}")
    return int(result['stdout'].strip())


def nasa_ct_dump_set(dpuhost, enable):
    """Enable or disable NASA CT dump inclusion in techsupport.

    Uses the platform CLI command to create or remove the sentinel file
    inside the syncd container.

    Args:
        dpuhost: DPU host object
        enable: bool - True to enable, False to disable
    """
    state = "enabled" if enable else "disabled"
    logger.info(f"{'Enabling' if enable else 'Disabling'} NASA CT dump in techsupport on {dpuhost.hostname}")
    dpuhost.shell(f"sudo config platform nvidia-bluefield sdk techsupport-ct-dump {state}")


def get_nasa_ct_dump_enabled(dpuhost):
    """Check if NASA CT dump is enabled (sentinel file exists in syncd container).

    Args:
        dpuhost: DPU host object

    Returns:
        bool: True if enabled, False if disabled
    """
    rc = dpuhost.shell(
        f"docker exec syncd test -f {NASA_CT_DUMP_SENTINEL}",
        module_ignore_errors=True
    )['rc']
    return rc == 0


def get_techsupport_file_list(dpuhost, tech_support_file):
    """List all files inside a techsupport tarball with the top-level prefix stripped.

    Args:
        dpuhost: DPU host object
        tech_support_file: Full path to the techsupport .tar.gz file on the DPU

    Returns:
        list[str]: List of file paths inside the tarball (prefix stripped)
    """
    result = dpuhost.shell(f"tar tzf {quote(tech_support_file)}")
    basename = os.path.basename(tech_support_file)
    prefix = basename.replace(".tar.gz", "") + "/"
    files = []
    for line in result['stdout_lines']:
        line = line.strip()
        if line.startswith(prefix):
            stripped = line[len(prefix):]
            if stripped:
                files.append(stripped)
        elif line:
            files.append(line)
    return files
