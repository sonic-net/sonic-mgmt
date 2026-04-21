# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Utility functions for Intersight vHBA-related modules.

This module contains common functions used by both intersight_san_connectivity_policy
and intersight_vhba_template modules to prevent code duplication.
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import re


def validate_wwn_address(wwn_address, address_type='WWPN'):
    """
    Validate WWN (WWNN or WWPN) address format and range.
    """
    wwn_pattern = r'^([0-9a-fA-F]{2}:){7}[0-9a-fA-F]{2}$'
    if not re.match(wwn_pattern, wwn_address):
        raise ValueError(f"Invalid {address_type} format '{wwn_address}'. Expected format: XX:XX:XX:XX:XX:XX:XX:XX (hex values)")
    first_octet = int(wwn_address.split(':')[0], 16)
    if not ((0x20 <= first_octet <= 0x2F) or (0x50 <= first_octet <= 0x5F)):
        raise ValueError(f"Invalid {address_type} address range. First octet must be 20-2F or 50-5F")
    return True


def get_policy_moid_with_org(intersight, policy_cache, module, resource_path, policy_name, organization_name, policy_type="Policy"):
    """
    Get policy MOID with caching and organization scoping to avoid redundant API calls.
    """
    if not policy_name:
        return None

    cache_key = f"{resource_path}:{policy_name}"
    if cache_key in policy_cache:
        return policy_cache[cache_key]

    policy_moid = intersight.get_moid_by_name_and_org(
        resource_path=resource_path,
        resource_name=policy_name,
        organization_name=organization_name
    )
    if not policy_moid:
        module.fail_json(msg=f"{policy_type} '{policy_name}' not found in organization '{organization_name}'")

    policy_cache[cache_key] = policy_moid
    return policy_moid


def get_common_fc_policy_mappings():
    """
    Get common Fibre Channel policy mappings shared between vHBA template and SAN connectivity policy.
    """
    return {
        'fibre_channel_network_policy_name': ('/vnic/FcNetworkPolicies', 'FcNetworkPolicy', 'Fibre Channel Network Policy'),
        'fibre_channel_qos_policy_name': ('/vnic/FcQosPolicies', 'FcQosPolicy', 'Fibre Channel QoS Policy'),
        'fibre_channel_adapter_policy_name': ('/vnic/FcAdapterPolicies', 'FcAdapterPolicy', 'Fibre Channel Adapter Policy')
    }


def get_wwpn_pool_policy_mapping():
    """
    Get WWPN pool policy mapping.
    """
    return {
        'wwpn_pool_name': ('/fcpool/Pools', 'WwpnPool', 'WWPN Pool')
    }


def get_fc_zone_policy_mapping():
    """
    Get Fibre Channel Zone policy mapping (optional policy).
    """
    return {
        'fibre_channel_zone_policy_names': ('/fabric/FcZonePolicies', 'FcZonePolicies', 'Fibre Channel Zone Policy')
    }


def validate_wwpn_address_config(module, config, config_name='vHBA'):
    """
    Validate WWPN address configuration.
    """
    wwpn_address_type = config.get('wwpn_address_type', 'pool')
    wwpn_pool = config.get('wwpn_pool') or config.get('wwpn_pool_name')
    static_wwpn_address = config.get('static_wwpn_address')

    if wwpn_address_type == 'pool' and not wwpn_pool:
        module.fail_json(msg=f"wwpn_pool_name is required when wwpn_address_type is 'pool' for {config_name}")

    if wwpn_address_type == 'static' and not static_wwpn_address:
        module.fail_json(msg=f"static_wwpn_address is required when wwpn_address_type is 'static' for {config_name}")

    if wwpn_address_type != 'pool' and wwpn_pool:
        module.fail_json(msg=f"wwpn_pool_name should only be specified when wwpn_address_type is 'pool' for {config_name}")

    if wwpn_address_type != 'static' and static_wwpn_address:
        module.fail_json(msg=f"static_wwpn_address should only be specified when wwpn_address_type is 'static' for {config_name}")

    # Validate static WWPN address format if provided
    if static_wwpn_address:
        try:
            validate_wwn_address(static_wwpn_address, 'WWPN')
        except ValueError as e:
            module.fail_json(msg=f"{config_name}: {str(e)}")


def validate_wwnn_address_config(module, policy_params):
    """
    Validate WWNN address configuration for SAN Connectivity Policy.
    """
    wwnn_address_type = policy_params.get('wwnn_address_type')
    static_wwnn_address = policy_params.get('static_wwnn_address')
    wwnn_pool = policy_params.get('wwnn_pool')

    if wwnn_address_type == 'static' and not static_wwnn_address:
        module.fail_json(msg="static_wwnn_address is required when wwnn_address_type is 'static'")

    if wwnn_address_type == 'pool' and not wwnn_pool:
        module.fail_json(msg="wwnn_pool is required when wwnn_address_type is 'pool'")

    if wwnn_address_type != 'static' and static_wwnn_address:
        module.fail_json(msg="static_wwnn_address should only be specified when wwnn_address_type is 'static'")

    if wwnn_address_type != 'pool' and wwnn_pool:
        module.fail_json(msg="wwnn_pool should only be specified when wwnn_address_type is 'pool'")

    if static_wwnn_address:
        try:
            validate_wwn_address(static_wwnn_address, 'WWNN')
        except ValueError as e:
            module.fail_json(msg=str(e))


def validate_fi_attached_placement_config(module, vhba_config):
    """
    Validate FIAttached placement configuration for vHBA.
    """
    vhba_name = vhba_config.get('name', 'unknown')
    auto_slot_id = vhba_config.get('auto_slot_id', True)
    slot_id = vhba_config.get('slot_id')
    auto_pci_link = vhba_config.get('auto_pci_link', True)
    pci_link_assignment_mode = vhba_config.get('pci_link_assignment_mode')
    pci_link = vhba_config.get('pci_link')

    if not auto_slot_id and not slot_id:
        module.fail_json(msg=f"slot_id is required when auto_slot_id is false for vHBA '{vhba_name}'")

    if auto_slot_id and slot_id:
        module.fail_json(msg=f"slot_id should not be specified when auto_slot_id is true for vHBA '{vhba_name}'")

    if not auto_pci_link and not pci_link_assignment_mode:
        module.fail_json(msg=f"pci_link_assignment_mode is required when auto_pci_link is false for vHBA '{vhba_name}'")

    if auto_pci_link and pci_link_assignment_mode:
        module.fail_json(msg=f"pci_link_assignment_mode should not be specified when auto_pci_link is true for vHBA '{vhba_name}'")

    if pci_link_assignment_mode == 'custom' and pci_link is None:
        module.fail_json(msg=f"pci_link is required when pci_link_assignment_mode is 'custom' for vHBA '{vhba_name}'")

    if pci_link_assignment_mode != 'custom' and pci_link is not None and pci_link != 0:
        module.fail_json(msg=f"pci_link should only be specified when pci_link_assignment_mode is 'custom' for vHBA '{vhba_name}'")


def validate_standalone_vhba_config(module, vhba_config):
    """
    Validate Standalone specific vHBA configuration.
    """
    vhba_name = vhba_config.get('name', 'unknown')
    slot_id = vhba_config.get('slot_id')

    if not slot_id:
        module.fail_json(msg=f"slot_id is required for standalone vHBA '{vhba_name}'")


def resolve_policy_moids_from_mappings(intersight, policy_cache, module, config_source, policy_mappings, organization_name):
    """
    Resolve policy MOIDs from configuration using provided policy mappings.
    """
    policy_moids = {}

    for param_name, (resource_path, api_field, policy_type) in policy_mappings.items():
        policy_name = config_source.get(param_name)
        if policy_name:
            policy_moid = get_policy_moid_with_org(
                intersight, policy_cache, module, resource_path, policy_name, organization_name, policy_type
            )
            policy_moids[api_field] = policy_moid

    return policy_moids


def resolve_fc_zone_policies(intersight, policy_cache, module, zone_policy_names, organization_name):
    """
    Resolve Fibre Channel Zone Policy MOIDs from list of policy names.
    """
    fc_zone_policy_moids = []

    if zone_policy_names:
        for fc_zone_policy_name in zone_policy_names:
            fc_zone_policy_moid = get_policy_moid_with_org(
                intersight, policy_cache, module, '/fabric/FcZonePolicies',
                fc_zone_policy_name, organization_name, 'Fibre Channel Zone Policy'
            )
            fc_zone_policy_moids.append(fc_zone_policy_moid)

    return fc_zone_policy_moids


def build_wwpn_address_config(vhba_config, intersight, policy_cache, module, organization_name):
    """
    Build WWPN address configuration for API body.
    """
    wwpn_address_type = vhba_config.get('wwpn_address_type', 'pool')
    wwpn_address_type_map = {'pool': 'POOL', 'static': 'STATIC'}
    api_wwpn_address_type = wwpn_address_type_map[wwpn_address_type]

    wwpn_config = {
        'WwpnAddressType': api_wwpn_address_type
    }

    if wwpn_address_type == 'pool':
        wwpn_pool_name = vhba_config.get('wwpn_pool') or vhba_config.get('wwpn_pool_name')
        wwpn_pool_moid = get_policy_moid_with_org(
            intersight, policy_cache, module, '/fcpool/Pools',
            wwpn_pool_name, organization_name, 'WWPN Pool'
        )
        wwpn_config['WwpnPool'] = wwpn_pool_moid
        wwpn_config['StaticWwpnAddress'] = ''
    else:
        wwpn_config['StaticWwpnAddress'] = vhba_config['static_wwpn_address']
        wwpn_config['WwpnPool'] = ''

    return wwpn_config


def build_fi_attached_placement(vhba_config):
    """
    Build FI-Attached placement configuration for API body.
    """
    auto_slot_id = vhba_config.get('auto_slot_id', True)
    auto_pci_link = vhba_config.get('auto_pci_link', True)
    switch_id = vhba_config.get('switch_id', 'a')
    api_switch_id = switch_id.upper()

    placement = {
        'SwitchId': api_switch_id,
        'AutoSlotId': auto_slot_id,
        'AutoPciLink': auto_pci_link
    }

    if not auto_slot_id:
        placement['Id'] = vhba_config['slot_id']

    if not auto_pci_link:
        pci_link_mode = vhba_config['pci_link_assignment_mode']
        pci_link_mode_map = {'custom': 'Custom', 'load-balanced': 'Load-Balanced'}
        api_pci_link_mode = pci_link_mode_map[pci_link_mode]
        placement['PciLinkAssignmentMode'] = api_pci_link_mode
        if pci_link_mode == 'custom':
            placement['PciLink'] = vhba_config.get('pci_link', 0)

    return placement


def build_standalone_placement(vhba_config):
    """
    Build Standalone placement configuration for API body.
    """
    return {
        'Id': vhba_config['slot_id'],
        'Uplink': vhba_config.get('uplink_port', 0),
        'PciLink': vhba_config.get('pci_link', 0)
    }


def get_vhba_template_policy_mappings():
    """
    Get policy mappings for vHBA Template configuration.
    """
    policy_mappings = get_common_fc_policy_mappings()
    policy_mappings.update(get_wwpn_pool_policy_mapping())
    return policy_mappings


def get_san_connectivity_vhba_policy_mappings(target_platform):
    """
    Get policy mappings for vHBA in SAN Connectivity Policy based on target platform.
    """
    policy_mappings = {
        'fibre_channel_network_policy': ('/vnic/FcNetworkPolicies', 'FcNetworkPolicy', 'Fibre Channel Network Policy'),
        'fibre_channel_qos_policy': ('/vnic/FcQosPolicies', 'FcQosPolicy', 'Fibre Channel QoS Policy'),
        'fibre_channel_adapter_policy': ('/vnic/FcAdapterPolicies', 'FcAdapterPolicy', 'Fibre Channel Adapter Policy')
    }

    # WWPN pool only for FI-Attached
    if target_platform == 'fiattached':
        policy_mappings['wwpn_pool'] = ('/fcpool/Pools', 'WwpnPool', 'WWPN Pool')

    return policy_mappings
