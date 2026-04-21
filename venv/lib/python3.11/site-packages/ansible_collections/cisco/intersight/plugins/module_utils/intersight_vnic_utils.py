# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Utility functions for Intersight vNIC-related modules.

This module contains common functions used by both intersight_lan_connectivity_policy
and intersight_vnic_template modules to prevent code duplication.
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type


def get_policy_moid_with_org(intersight, policy_cache, module, resource_path, policy_name, organization_name, policy_type="Policy"):
    """
    Get policy MOID with caching and organization scoping to avoid redundant API calls.

    This function scopes the policy lookup to a specific organization, preventing
    conflicts when multiple organizations have policies with the same name.

    Args:
        intersight: IntersightModule instance
        policy_cache: Dictionary for caching policy MOIDs
        module: AnsibleModule instance
        resource_path: API resource path for the policy
        policy_name: Name of the policy to resolve
        organization_name: Name of the organization to scope the search to
        policy_type: Type of policy for error messages (default: "Policy")

    Returns:
        MOID of the policy or fails with error message if not found
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


def validate_cdn_config(module, vnic_config):
    """
    Validate CDN (Consistent Device Naming) configuration.
    """
    cdn_source = vnic_config.get('cdn_source', 'vnic')
    cdn_value = vnic_config.get('cdn_value')
    vnic_name = vnic_config.get('name', 'unknown')

    if cdn_source == 'user' and not cdn_value:
        module.fail_json(msg=f"cdn_value is required when cdn_source is set to 'user' for {vnic_name}")

    if cdn_source == 'vnic' and cdn_value:
        module.fail_json(msg=f"cdn_value should not be provided when cdn_source is set to 'vnic' for {vnic_name}")


def validate_usnic_settings(module, usnic_settings, name=None):
    """
    Validate USNIC connection type settings.
    """
    error_suffix = f" for {name}" if name else ""

    if not usnic_settings:
        module.fail_json(msg=f"usnic_settings is required when connection_type is 'usnic'{error_suffix}")

    usnic_adapter_policy_name = usnic_settings.get('usnic_adapter_policy_name')
    if not usnic_adapter_policy_name:
        module.fail_json(msg=f"usnic_adapter_policy_name is required in usnic_settings{error_suffix}")

    count = usnic_settings.get('count', 0)
    cos = usnic_settings.get('cos', 5)

    if count < 0 or count > 225:
        module.fail_json(msg=f"USNIC count must be between 0 and 225{error_suffix}")
    if cos < 0 or cos > 6:
        module.fail_json(msg=f"USNIC CoS must be between 0 and 6{error_suffix}")


def validate_vmq_settings(module, vmq_settings, name=None):
    """
    Validate VMQ connection type settings.
    """
    error_suffix = f" for {name}" if name else ""
    multi_queue_support = vmq_settings.get('multi_queue_support', False)

    if not multi_queue_support:
        num_interrupts = vmq_settings.get('num_interrupts', 16)
        num_vmqs = vmq_settings.get('num_vmqs', 4)

        if num_interrupts < 1 or num_interrupts > 514:
            module.fail_json(msg=f"VMQ num_interrupts must be between 1 and 514{error_suffix}")
        if num_vmqs < 1 or num_vmqs > 128:
            module.fail_json(msg=f"VMQ num_vmqs must be between 1 and 128{error_suffix}")
    else:
        num_sub_vnics = vmq_settings.get('num_sub_vnics', 64)
        if num_sub_vnics < 0 or num_sub_vnics > 64:
            module.fail_json(msg=f"VMQ num_sub_vnics must be between 0 and 64{error_suffix}")

        if not vmq_settings.get('vmmq_adapter_policy_name'):
            module.fail_json(msg=f"vmmq_adapter_policy_name is required when multi_queue_support is true{error_suffix}")


def validate_sriov_settings(module, sriov_settings, name=None):
    """
    Validate SR-IOV connection type settings.
    """
    error_suffix = f" for {name}" if name else ""
    vf_count = sriov_settings.get('vf_count', 64)
    rx_count_per_vf = sriov_settings.get('rx_count_per_vf', 4)
    tx_count_per_vf = sriov_settings.get('tx_count_per_vf', 1)
    comp_count_per_vf = sriov_settings.get('comp_count_per_vf', 5)
    int_count_per_vf = sriov_settings.get('int_count_per_vf', 8)

    if vf_count < 1 or vf_count > 64:
        module.fail_json(msg=f"SR-IOV vf_count must be between 1 and 64{error_suffix}")
    if rx_count_per_vf < 1 or rx_count_per_vf > 8:
        module.fail_json(msg=f"SR-IOV rx_count_per_vf must be between 1 and 8{error_suffix}")
    if tx_count_per_vf < 1 or tx_count_per_vf > 8:
        module.fail_json(msg=f"SR-IOV tx_count_per_vf must be between 1 and 8{error_suffix}")
    if comp_count_per_vf < 1 or comp_count_per_vf > 16:
        module.fail_json(msg=f"SR-IOV comp_count_per_vf must be between 1 and 16{error_suffix}")
    if int_count_per_vf < 1 or int_count_per_vf > 16:
        module.fail_json(msg=f"SR-IOV int_count_per_vf must be between 1 and 16{error_suffix}")


def build_usnic_settings(intersight, policy_cache, module, usnic_settings, organization_name):
    """
    Build USNIC settings for API body.
    """
    usnic_adapter_policy_name = usnic_settings.get('usnic_adapter_policy_name')
    usnic_adapter_policy_moid = get_policy_moid_with_org(
        intersight, policy_cache, module, '/vnic/EthAdapterPolicies',
        usnic_adapter_policy_name, organization_name, 'USNIC Adapter Policy'
    )

    return {
        'Count': usnic_settings.get('count', 0),
        'UsnicAdapterPolicy': usnic_adapter_policy_moid,
        'Cos': usnic_settings.get('cos', 5)
    }


def build_vmq_settings(intersight, policy_cache, module, vmq_settings, organization_name):
    """
    Build VMQ settings for API body.
    """
    multi_queue_support = vmq_settings.get('multi_queue_support', False)

    if multi_queue_support:
        vmmq_adapter_policy_name = vmq_settings.get('vmmq_adapter_policy_name')
        vmmq_adapter_policy_moid = get_policy_moid_with_org(
            intersight, policy_cache, module, '/vnic/EthAdapterPolicies',
            vmmq_adapter_policy_name, organization_name, 'VMMQ Adapter Policy'
        )

        return {
            'Enabled': vmq_settings.get('enabled', True),
            'MultiQueueSupport': True,
            'NumSubVnics': vmq_settings.get('num_sub_vnics', 64),
            'VmmqAdapterPolicy': vmmq_adapter_policy_moid
        }
    else:
        return {
            'Enabled': vmq_settings.get('enabled', True),
            'MultiQueueSupport': False,
            'NumInterrupts': vmq_settings.get('num_interrupts', 16),
            'NumVmqs': vmq_settings.get('num_vmqs', 4)
        }


def build_sriov_settings(sriov_settings):
    """
    Build SR-IOV settings for API body.
    """
    return {
        'VfCount': sriov_settings.get('vf_count', 64),
        'RxCountPerVf': sriov_settings.get('rx_count_per_vf', 4),
        'TxCountPerVf': sriov_settings.get('tx_count_per_vf', 1),
        'CompCountPerVf': sriov_settings.get('comp_count_per_vf', 5),
        'IntCountPerVf': sriov_settings.get('int_count_per_vf', 8),
        'Enabled': sriov_settings.get('enabled', True)
    }


def build_cdn_config(config_source):
    """
    Build CDN configuration for API body.
    """
    cdn_config = {
        'Source': config_source.get('cdn_source', 'vnic')
    }

    # Add CDN value if specified
    if config_source.get('cdn_value'):
        cdn_config['Value'] = config_source['cdn_value']

    return cdn_config


def get_common_policy_mappings():
    """
    Get common policy mappings shared between vNIC template and LAN connectivity policy.
    """
    return {
        'eth_qos_policy_name': ('/vnic/EthQosPolicies', 'EthQosPolicy', 'Ethernet QoS Policy'),
        'eth_adapter_policy_name': ('/vnic/EthAdapterPolicies', 'EthAdapterPolicy', 'Ethernet Adapter Policy')
    }


def get_iscsi_boot_policy_mapping():
    """
    Get iSCSI boot policy mapping (optional policy).
    """
    return {
        'iscsi_boot_policy_name': ('/vnic/IscsiBootPolicies', 'IscsiBootPolicy', 'iSCSI Boot Policy')
    }


def get_fabric_network_policy_mappings():
    """
    Get fabric network policy mappings for FI-attached configurations.
    """
    return {
        'fabric_eth_network_group_policy_name': (
            '/fabric/EthNetworkGroupPolicies', 'FabricEthNetworkGroupPolicy', 'Fabric Ethernet Network Group Policy'
        ),
        'fabric_eth_network_control_policy_name': (
            '/fabric/EthNetworkControlPolicies', 'FabricEthNetworkControlPolicy', 'Fabric Ethernet Network Control Policy'
        )
    }


def get_mac_pool_policy_mapping():
    """
    Get MAC pool policy mapping.
    """
    return {
        'mac_pool_name': ('/macpool/Pools', 'MacPool', 'MAC Pool')
    }


def get_common_settings_argument_spec():
    """
    Get common connection settings argument specifications.
    """
    return {
        'connection_type': dict(type='str', choices=['none', 'usnic', 'vmq', 'sriov'], default='none'),
        'iscsi_boot_policy_name': dict(type='str'),
        'fabric_eth_network_control_policy_name': dict(type='str'),
        'fabric_eth_network_group_policy_name': dict(type='str'),
        'failover_enabled': dict(type='bool', default=False),
        'switch_id': dict(type='str', choices=['A', 'B'], default='A'),
        'mac_pool_name': dict(type='str'),
        'cdn_value': dict(type='str'),
        'cdn_source': dict(type='str', choices=['vnic', 'user'], default='vnic'),
        'usnic_settings': dict(type='dict', options=dict(
            count=dict(type='int', default=0),
            cos=dict(type='int', choices=[0, 1, 2, 3, 4, 5, 6], default=5),
            usnic_adapter_policy_name=dict(type='str')
        )),
        'vmq_settings': dict(type='dict', options=dict(
            enabled=dict(type='bool', default=True),
            multi_queue_support=dict(type='bool', default=False),
            num_interrupts=dict(type='int', default=16),
            num_vmqs=dict(type='int', default=4),
            num_sub_vnics=dict(type='int', default=64),
            vmmq_adapter_policy_name=dict(type='str')
        )),
        'sriov_settings': dict(type='dict', options=dict(
            enabled=dict(type='bool', default=True),
            vf_count=dict(type='int', default=64),
            rx_count_per_vf=dict(type='int', default=4),
            tx_count_per_vf=dict(type='int', default=1),
            comp_count_per_vf=dict(type='int', default=5),
            int_count_per_vf=dict(type='int', default=8)
        ))
    }


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
            # Special handling for FabricEthNetworkGroupPolicy which needs to be an array for the API
            if api_field == 'FabricEthNetworkGroupPolicy':
                policy_moids[api_field] = [policy_moid]
            else:
                policy_moids[api_field] = policy_moid

    return policy_moids


def build_connection_settings(intersight, policy_cache, module, config_source, organization_name):
    """
    Build connection type specific settings for API body.
    """
    connection_settings = {}
    connection_type = config_source.get('connection_type', 'none')

    if connection_type == 'usnic':
        usnic_settings = config_source.get('usnic_settings', {})
        connection_settings['UsnicSettings'] = build_usnic_settings(intersight, policy_cache, module, usnic_settings, organization_name)
    elif connection_type == 'vmq':
        vmq_settings = config_source.get('vmq_settings', {})
        connection_settings['VmqSettings'] = build_vmq_settings(intersight, policy_cache, module, vmq_settings, organization_name)
    elif connection_type == 'sriov':
        sriov_settings = config_source.get('sriov_settings', {})
        connection_settings['SriovSettings'] = build_sriov_settings(sriov_settings)

    return connection_settings
