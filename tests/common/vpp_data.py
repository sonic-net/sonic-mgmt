"""
Helpers for interacting with the VPP dataplane on sonic-vpp DUTs.
"""

import logging

logger = logging.getLogger(__name__)

# Printed by 'show bridge-domain' when the dataplane has no bridge domain configured at all
NO_BRIDGE_DOMAINS_MSG = "no bridge-domains in use"


def vpp_bd_uu_flood_states(duthost):
    """
    Collect the unknown unicast flood state of every VPP bridge domain

    Args:
        duthost(AnsibleHost) : dut instance

    Returns:
        dict: bridge domain id to the lowercased value of its 'UU-Flood' column, empty only when
              the dataplane reports that no bridge domain is in use

    Raises:
        RuntimeError: if the query fails or its output cannot be parsed. Returning an empty result
                      in that case would look identical to "nothing is flooding" and would turn a
                      setup problem into a misleading traffic failure.
    """
    cmd = "docker exec syncd vppctl show bridge-domain"
    result = duthost.shell(cmd, module_ignore_errors=True)
    if result['rc'] != 0:
        raise RuntimeError("Unable to read VPP bridge domains, '{}' failed with rc {}: {}"
                           .format(cmd, result['rc'], result['stderr']))

    states = {}
    uu_flood_idx = None
    for line in result['stdout_lines']:
        if NO_BRIDGE_DOMAINS_MSG in line.lower():
            return {}
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
        states[fields[0]] = fields[uu_flood_idx].lower()

    if uu_flood_idx is None:
        raise RuntimeError("Unable to parse VPP bridge domains, no 'UU-Flood' column in '{}' output: {}"
                           .format(cmd, result['stdout']))
    return states


def vpp_bds_with_uu_flood(duthost):
    """
    Collect the VPP bridge domain ids that currently have unknown unicast flooding enabled

    Args:
        duthost(AnsibleHost) : dut instance

    Returns:
        list: bridge domain ids whose 'UU-Flood' column is not 'drop'
    """
    return [bd_id for bd_id, state in vpp_bd_uu_flood_states(duthost).items() if state != 'drop']


def set_vpp_bd_uu_flood(duthost, bd_id, enable):
    """
    Enable or disable unknown unicast flooding on a VPP bridge domain

    Args:
        duthost(AnsibleHost) : dut instance
        bd_id(string) : VPP bridge domain id
        enable(bool) : True to enable unknown unicast flooding, False to disable it

    Returns:
        bool: True if the bridge domain ended up in the requested state, False otherwise
    """
    result = duthost.shell("docker exec syncd vppctl set bridge-domain uu-flood {}{}"
                           .format(bd_id, "" if enable else " disable"), module_ignore_errors=True)
    if result['rc'] != 0:
        logger.warning("Failed to set unknown unicast flood on bridge domain %s: %s", bd_id, result['stderr'])
        return False

    state = vpp_bd_uu_flood_states(duthost).get(bd_id)
    if state is None:
        logger.warning("Bridge domain %s not found while verifying its unknown unicast flood state", bd_id)
        return False

    is_enabled = state != 'drop'
    if is_enabled != enable:
        logger.warning("Bridge domain %s unknown unicast flood is '%s', expected it to be %s",
                       bd_id, state, "enabled" if enable else "disabled")
    return is_enabled == enable
