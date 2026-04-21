#!/usr/bin/python

# (c) 2020, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

""" NetApp StorageGRID Grid Info using REST APIs """


from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
module: na_sg_grid_info
author: NetApp Ansible Team (@jasonl4) <ng-ansibleteam@netapp.com>
extends_documentation_fragment:
    - netapp.storagegrid.netapp.sg
short_description: NetApp StorageGRID Grid information gatherer.
description:
    - This module allows you to gather various information about StorageGRID Grid configuration.
version_added: 20.11.0

options:
    gather_subset:
        type: list
        elements: str
        description:
            - When supplied, this argument will restrict the information collected to a given subset.
            - Either the info name or the REST API can be given.
            - Possible values for this argument include
            - C(grid_accounts_info) or C(grid/accounts)
            - C(grid_alarms_info) or C(grid/alarms)
            - C(grid_audit_info) or C(grid/audit)
            - C(grid_compliance_global_info) or C(grid/compliance-global)
            - C(grid_config_info) or C(grid/config)
            - C(grid_config_management_info) or C(grid/config/management)
            - C(grid_config_product_version_info) or C(grid/config/product-version)
            - C(grid_deactivated_features_info) or C(grid/deactivated-features)
            - C(grid_dns_servers_info) or C(grid/dns-servers)
            - C(grid_domain_names_info) or C(grid/domain-names)
            - C(grid_ec_profiles_info) or C(grid/ec-profiles)
            - C(grid_expansion_info) or C(grid/expansion)
            - C(grid_expansion_nodes_info) or C(grid/expansion/nodes)
            - C(grid_expansion_sites_info) or C(grid/expansion/sites)
            - C(grid_grid_networks_info) or C(grid/grid-networks)
            - C(grid_groups_info) or C(grid/groups)
            - C(grid_health_info) or C(grid/health)
            - C(grid_health_topology_info) or C(grid/health/topology)
            - C(grid_identity_source_info) or C(grid/identity-source)
            - C(grid_ilm_criteria_info) or C(grid/ilm-criteria)
            - C(grid_ilm_policies_info) or C(grid/ilm-policies)
            - C(grid_ilm_rules_info) or C(grid/ilm-rules)
            - C(grid_license_info) or C(grid/license)
            - C(grid_management_certificate_info) or C(grid/management-certificate)
            - C(grid_ntp_servers_info) or C(grid/ntp-servers)
            - C(grid_recovery_available_nodes_info) or C(grid/recovery/available-nodes)
            - C(grid_recovery_info) or C(grid/recovery)
            - C(grid_regions_info) or C(grid/regions)
            - C(grid_schemes_info) or C(grid/schemes)
            - C(grid_snmp_info) or C(grid/snmp)
            - C(grid_storage_api_certificate_info) or C(grid/storage-api-certificate)
            - C(grid_untrusted_client_network_info) or C(grid/untrusted-client-network)
            - C(grid_users_info) or C(grid/users)
            - C(grid_users_root_info) or C(grid/users/root)
            - C(versions_info) or C(versions)
            - C(grid_load_balancer_endpoints_config_info) or C(private/gateway-configs)
            - C(grid_ha_groups_info) or C(private/ha-groups)
            - Can specify a list of values to include a larger subset.
        default: all
    parameters:
        description:
        - Allows for any rest option to be passed in.
        type: dict
"""

EXAMPLES = """
- name: Gather StorageGRID Grid info
  netapp.storagegrid.na_sg_grid_info:
    api_url: "https://1.2.3.4/"
    auth_token: "storagegrid-auth-token"
    validate_certs: false
  register: sg_grid_info

- name: Gather StorageGRID Grid info for grid/accounts and grid/config subsets
  netapp.storagegrid.na_sg_grid_info:
    api_url: "https://1.2.3.4/"
    auth_token: "storagegrid-auth-token"
    validate_certs: false
    gather_subset:
      - grid_accounts_info
      - grid/config
  register: sg_grid_info

- name: Gather StorageGRID Grid info for all subsets
  netapp.storagegrid.na_sg_grid_info:
    api_url: "https://1.2.3.4/"
    auth_token: "storagegrid-auth-token"
    validate_certs: false
    gather_subset:
      - all
  register: sg_grid_info

- name: Gather StorageGRID Grid info for grid/accounts and grid/users subsets, limit to 5 results for each subset
  netapp.storagegrid.na_sg_grid_info:
    api_url: "https://1.2.3.4/"
    auth_token: "storagegrid-auth-token"
    validate_certs: false
    gather_subset:
      - grid/accounts
      - grid/users
    parameters:
      limit: 5
  register: sg_grid_info
"""

RETURN = """
sg_info:
    description: Returns various information about the StorageGRID Grid configuration.
    returned: always
    type: dict
    sample: {
        "grid/accounts": {...},
        "grid/alarms": {...},
        "grid/audit": {...},
        "grid/compliance-global": {...},
        "grid/config": {...},
        "grid/config/management": {...},
        "grid/config/product-version": {...},
        "grid/deactivated-features": {...},
        "grid/dns-servers": {...},
        "grid/domain-names": {...},
        "grid/ec-profiles": {...},
        "grid/expansion": {...},
        "grid/expansion/nodes": {...},
        "grid/expansion/sites": {...},
        "grid/networks": {...},
        "grid/groups": {...},
        "grid/health": {...},
        "grid/health/topology": {...},
        "grid/identity-source": {...},
        "grid/ilm-criteria": {...},
        "grid/ilm-policies": {...},
        "grid/ilm-rules": {...},
        "grid/license": {...},
        "grid/management-certificate": {...},
        "grid/ntp-servers": {...},
        "grid/recovery/available-nodes": {...},
        "grid/recovery": {...},
        "grid/regions": {...},
        "grid/schemes": {...},
        "grid/snmp": {...},
        "grid/storage-api-certificate": {...},
        "grid/untrusted-client-network": {...},
        "grid/users": {...},
        "grid/users/root": {...},
        "grid/versions": {...},
        "private/gateway-configs": {...},
        "private/ha-groups": {...},
    }
"""

from ansible.module_utils.basic import AnsibleModule
import ansible_collections.netapp.storagegrid.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp import SGRestAPI


class NetAppSgGatherInfo(object):
    """ Class with gather info methods """

    def __init__(self):
        """
        Parse arguments, setup variables, check parameters and ensure
        request module is installed.
        """
        self.argument_spec = netapp_utils.na_storagegrid_host_argument_spec()
        self.argument_spec.update(dict(
            gather_subset=dict(default=['all'], type='list', elements='str', required=False),
            parameters=dict(type='dict', required=False)
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )

        # set up variables
        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)
        self.rest_api = SGRestAPI(self.module)

    def get_subset_info(self, gather_subset_info):
        """
        Gather StorageGRID information for the given subset using REST APIs
        Input for REST APIs call : (api, data)
        return gathered_sg_info
        """

        api = gather_subset_info['api_call']
        data = {}
        # allow for passing in any additional rest api parameters
        if self.parameters.get('parameters'):
            for each in self.parameters['parameters']:
                data[each] = self.parameters['parameters'][each]

        gathered_sg_info, error = self.rest_api.get(api, data)

        if error:
            self.module.fail_json(msg=error)
        else:
            return gathered_sg_info

        return None

    def convert_subsets(self):
        """ Convert an info to the REST API """
        info_to_rest_mapping = {
            'grid_accounts_info': 'grid/accounts',
            'grid_alarms_info': 'grid/alarms',
            'grid_audit_info': 'grid/audit',
            'grid_compliance_global_info': 'grid/compliance-global',
            'grid_config_info': 'grid/config',
            'grid_config_management_info': 'grid/config/management',
            'grid_config_product_version_info': 'grid/config/product-version',
            'grid_deactivated_features_info': 'grid/deactivated-features',
            'grid_dns_servers_info': 'grid/dns-servers',
            'grid_domain_names_info': 'grid/domain-names',
            'grid_ec_profiles_info': 'grid/ec-profiles',
            'grid_expansion_info': 'grid/expansion',
            'grid_expansion_nodes_info': 'grid/expansion/nodes',
            'grid_expansion_sites_info': 'grid/expansion/sites',
            'grid_grid_networks_info': 'grid/grid-networks',
            'grid_groups_info': 'grid/groups',
            'grid_health_info': 'grid/health',
            'grid_health_topology_info': 'grid/health/topology',
            'grid_identity_source_info': 'grid/identity-source',
            'grid_ilm_criteria_info': 'grid/ilm-criteria',
            'grid_ilm_policies_info': 'grid/ilm-policies',
            'grid_ilm_rules_info': 'grid/ilm-rules',
            'grid_license_info': 'grid/license',
            'grid_management_certificate_info': 'grid/management-certificate',
            'grid_ntp_servers_info': 'grid/ntp-servers',
            'grid_recovery_available_nodes_info': 'grid/recovery/available-nodes',
            'grid_recovery_info': 'grid/recovery',
            'grid_regions_info': 'grid/regions',
            'grid_schemes_info': 'grid/schemes',
            'grid_snmp_info': 'grid/snmp',
            'grid_storage_api_certificate_info': 'grid/storage-api-certificate',
            'grid_untrusted_client_network_info': 'grid/untrusted-client-network',
            'grid_users_info': 'grid/users',
            'grid_users_root_info': 'grid/users/root',
            'versions_info': 'versions',
            'grid_load_balancer_endpoints_config_info': 'private/gateway-configs',
            'grid_ha_groups_info': 'private/ha-groups',
        }
        # Add rest API names as there info version, also make sure we don't add a duplicate.
        subsets = []
        for subset in self.parameters['gather_subset']:
            if subset in info_to_rest_mapping:
                if info_to_rest_mapping[subset] not in subsets:
                    subsets.append(info_to_rest_mapping[subset])
            else:
                if subset not in subsets:
                    subsets.append(subset)
        return subsets

    def apply(self):
        """ Perform pre-checks, call functions and exit """

        result_message = dict()

        # Defining gather_subset and appropriate api_call.
        get_sg_subset_info = {
            'grid/accounts': {
                'api_call': 'api/v3/grid/accounts',
            },
            'grid/alarms': {
                'api_call': 'api/v3/grid/alarms',
            },
            'grid/audit': {
                'api_call': 'api/v3/grid/audit',
            },
            'grid/compliance-global': {
                'api_call': 'api/v3/grid/compliance-global',
            },
            'grid/config': {
                'api_call': 'api/v3/grid/config',
            },
            'grid/config/management': {
                'api_call': 'api/v3/grid/config/management',
            },
            'grid/config/product-version': {
                'api_call': 'api/v3/grid/config/product-version',
            },
            'grid/deactivated-features': {
                'api_call': 'api/v3/grid/deactivated-features',
            },
            'grid/dns-servers': {
                'api_call': 'api/v3/grid/dns-servers',
            },
            'grid/domain-names': {
                'api_call': 'api/v3/grid/domain-names',
            },
            'grid/ec-profiles': {
                'api_call': 'api/v3/grid/ec-profiles',
            },
            'grid/expansion': {
                'api_call': 'api/v3/grid/expansion',
            },
            'grid/expansion/nodes': {
                'api_call': 'api/v3/grid/expansion/nodes',
            },
            'grid/expansion/sites': {
                'api_call': 'api/v3/grid/expansion/sites',
            },
            'grid/grid-networks': {
                'api_call': 'api/v3/grid/grid-networks',
            },
            'grid/groups': {
                'api_call': 'api/v3/grid/groups',
            },
            'grid/health': {
                'api_call': 'api/v3/grid/health',
            },
            'grid/health/topology': {
                'api_call': 'api/v3/grid/health/topology',
            },
            'grid/identity-source': {
                'api_call': 'api/v3/grid/identity-source',
            },
            'grid/ilm-criteria': {
                'api_call': 'api/v3/grid/ilm-criteria',
            },
            'grid/ilm-policies': {
                'api_call': 'api/v3/grid/ilm-policies',
            },
            'grid/ilm-rules': {
                'api_call': 'api/v3/grid/ilm-rules',
            },
            'grid/license': {
                'api_call': 'api/v3/grid/license',
            },
            'grid/management-certificate': {
                'api_call': 'api/v3/grid/management-certificate',
            },
            'grid/ntp-servers': {
                'api_call': 'api/v3/grid/ntp-servers',
            },
            'grid/recovery/available-nodes': {
                'api_call': 'api/v3/grid/recovery/available-nodes',
            },
            'grid/recovery': {
                'api_call': 'api/v3/grid/recovery',
            },
            'grid/regions': {
                'api_call': 'api/v3/grid/regions',
            },
            'grid/schemes': {
                'api_call': 'api/v3/grid/schemes',
            },
            'grid/snmp': {
                'api_call': 'api/v3/grid/snmp',
            },
            'grid/storage-api-certificate': {
                'api_call': 'api/v3/grid/storage-api-certificate',
            },
            'grid/untrusted-client-network': {
                'api_call': 'api/v3/grid/untrusted-client-network',
            },
            'grid/users': {
                'api_call': 'api/v3/grid/users',
            },
            'grid/users/root': {
                'api_call': 'api/v3/grid/users/root',
            },
            'versions': {
                'api_call': 'api/v3/versions',
            },
            'private/gateway-configs': {
                'api_call': 'api/v3/private/gateway-configs'
            },
            'private/ha-groups': {
                'api_call': 'api/v3/private/ha-groups'
            },
        }

        if 'all' in self.parameters['gather_subset']:
            # If all in subset list, get the information of all subsets.
            self.parameters['gather_subset'] = sorted(get_sg_subset_info.keys())

        converted_subsets = self.convert_subsets()

        for subset in converted_subsets:
            try:
                # Verify whether the supported subset passed.
                specified_subset = get_sg_subset_info[subset]
            except KeyError:
                self.module.fail_json(msg="Specified subset %s not found, supported subsets are %s" %
                                      (subset, list(get_sg_subset_info.keys())))

            result_message[subset] = self.get_subset_info(specified_subset)

        self.module.exit_json(changed='False', sg_info=result_message)


def main():
    """ Main function """
    obj = NetAppSgGatherInfo()
    obj.apply()


if __name__ == '__main__':
    main()
