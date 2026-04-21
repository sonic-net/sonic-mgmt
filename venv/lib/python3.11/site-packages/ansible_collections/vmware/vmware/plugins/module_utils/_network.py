# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Ansible Cloud Team (@ansible-collections)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later
#

# Note: This utility is considered private, and can only be referenced from inside the vmware.vmware collection.
#       It may be made public at a later date

try:
    from pyVmomi import vim
except ImportError:
    pass


def get_standard_portgroup_vlan_vswitch(portgroup, pg_name):
    ret_pg = {'name': pg_name}
    for host in portgroup.host:
        pgs = host.config.network.portgroup
        for pg in pgs:
            if pg.spec.name == pg_name:
                ret_pg['vlan_id'] = str(pg.spec.vlanId)
                ret_pg['vswitch_name'] = str(pg.spec.vswitchName)
                return ret_pg


def get_teaming_policy(uplink_teaming_policy):
    return dict(
        policy=uplink_teaming_policy.policy.value,
        inbound_policy=uplink_teaming_policy.reversePolicy.value,
        notify_switches=uplink_teaming_policy.notifySwitches.value,
        rolling_order=uplink_teaming_policy.rollingOrder.value,
    )


def get_port_policy(config_policy):
    return dict(
        block_override=config_policy.blockOverrideAllowed,
        ipfix_override=config_policy.ipfixOverrideAllowed,
        live_port_move=config_policy.livePortMovingAllowed,
        network_rp_override=config_policy.networkResourcePoolOverrideAllowed,
        port_config_reset_at_disconnect=config_policy.portConfigResetAtDisconnect,
        security_override=config_policy.macManagementOverrideAllowed,
        shaping_override=config_policy.shapingOverrideAllowed,
        traffic_filter_override=config_policy.trafficFilterOverrideAllowed,
        uplink_teaming_override=config_policy.uplinkTeamingOverrideAllowed,
        vendor_config_override=config_policy.vendorConfigOverrideAllowed,
        vlan_override=config_policy.vlanOverrideAllowed
    )


def get_dvs_mac_learning(mac_learning_policy):
    return dict(
        allow_unicast_flooding=mac_learning_policy.allowUnicastFlooding,
        enabled=mac_learning_policy.enabled,
        limit=mac_learning_policy.limit,
        limit_policy=mac_learning_policy.limitPolicy
    )


def get_dvs_network_policy(mac_management_policy):
    return dict(
        forged_transmits=mac_management_policy.forgedTransmits,
        promiscuous=mac_management_policy.allowPromiscuous,
        mac_changes=mac_management_policy.macChanges
    )


def get_vlan_info(vlan_obj):
    if isinstance(vlan_obj, vim.dvs.VmwareDistributedVirtualSwitch.TrunkVlanSpec):
        vlan_id_list = []
        for vli in vlan_obj.vlanId:
            if vli.start == vli.end:
                vlan_id_list.append(str(vli.start))
            else:
                vlan_id_list.append('{}-{}'.format(vli.start, vli.end))
        return dict(trunk=True, pvlan=False, vlan_id=vlan_id_list)
    elif isinstance(vlan_obj, vim.dvs.VmwareDistributedVirtualSwitch.PvlanSpec):
        return dict(trunk=False, pvlan=True, vlan_id=str(vlan_obj.pvlanId))
    else:
        return dict(trunk=False, pvlan=False, vlan_id=str(vlan_obj.vlanId))


def get_dvs_port_allocation(config_type):
    if config_type == 'ephemeral':
        return 'ephemeral'
    else:
        return 'static'


def get_dvs_auto_expand(config_auto_expand):
    return 'elastic' if config_auto_expand else 'fixed'
