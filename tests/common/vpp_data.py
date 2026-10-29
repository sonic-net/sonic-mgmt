"""
Helpers for interacting with the VPP dataplane on sonic-vpp DUTs.
"""

import logging

from tests.common.config_reload import config_reload

logger = logging.getLogger(__name__)

# Environment file sourced by the syncd container when VPP is started
VPP_SYNCD_ENV_PATH = "/etc/sonic/vpp/syncd_vpp_env"

# Startup config for the VPP ip-validate plugin, link-local drop is enabled by default
IP_VALIDATE_CONFIG_VAR = "IP_VALIDATE_CONFIG"
IP_VALIDATE_LINK_LOCAL_DROP_OFF = "{}=link-local-drop=off".format(IP_VALIDATE_CONFIG_VAR)


def set_vpp_link_local_drop(duthost, enable):
    """
    Enable or disable dropping of link-local sourced/destined packets by the VPP ip-validate plugin

    The setting is a startup config of the plugin, so it only takes effect after VPP is restarted
    by a config reload. Dropping is enabled by default, which is why disabling it is expressed as
    an explicit IP_VALIDATE_CONFIG entry and restoring the default is done by removing that entry.

    Args:
        duthost(AnsibleHost) : dut instance
        enable(bool) : True to restore the default link-local drop, False to disable it
    """
    duthost.shell("sed -i '/^{}=/d' {}".format(IP_VALIDATE_CONFIG_VAR, VPP_SYNCD_ENV_PATH))
    if not enable:
        duthost.shell("echo '{}' >> {}".format(IP_VALIDATE_LINK_LOCAL_DROP_OFF, VPP_SYNCD_ENV_PATH))

    logger.info("%s VPP link-local drop, reloading config to restart VPP",
                "Enabled" if enable else "Disabled")
    config_reload(duthost, safe_reload=True, check_intf_up_ports=True)


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
