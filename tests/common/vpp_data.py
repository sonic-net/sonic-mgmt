"""
Helpers for interacting with the VPP dataplane on sonic-vpp DUTs.
"""

import logging

logger = logging.getLogger(__name__)


def vpp_bds_with_uu_flood(duthost):
    """
    Collect the VPP bridge domain ids that currently have unknown unicast flooding enabled

    Args:
        duthost(AnsibleHost) : dut instance

    Returns:
        list: bridge domain ids whose 'UU-Flood' column is not 'drop'
    """
    result = duthost.shell("docker exec syncd vppctl show bridge-domain", module_ignore_errors=True)
    if result['rc'] != 0:
        logger.warning("Unable to read VPP bridge domains: %s", result['stderr'])
        return []

    bd_ids = []
    uu_flood_idx = None
    for line in result['stdout_lines']:
        fields = line.split()
        if not fields:
            continue
        if 'UU-Flood' in fields:
            uu_flood_idx = fields.index('UU-Flood')
            continue
        if uu_flood_idx is None or len(fields) <= uu_flood_idx:
            continue
        # BD 0 is the VPP "no bridging" domain and has no flood state to tweak
        if not fields[0].isdigit() or fields[0] == '0':
            continue
        if fields[uu_flood_idx].lower() != 'drop':
            bd_ids.append(fields[0])
    return bd_ids


def set_vpp_bd_uu_flood(duthost, bd_id, enable):
    """
    Enable or disable unknown unicast flooding on a VPP bridge domain

    Args:
        duthost(AnsibleHost) : dut instance
        bd_id(string) : VPP bridge domain id
        enable(bool) : True to enable unknown unicast flooding, False to disable it
    """
    duthost.shell("docker exec syncd vppctl set bridge-domain uu-flood {}{}"
                  .format(bd_id, "" if enable else " disable"))
