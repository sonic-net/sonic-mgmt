#!/usr/bin/python

# (c) 2020, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

""" NetApp StorageGRID Org Info using REST APIs """


from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
module: na_sg_org_info
author: NetApp Ansible Team (@jasonl4) <ng-ansibleteam@netapp.com>
extends_documentation_fragment:
    - netapp.storagegrid.netapp.sg
short_description: NetApp StorageGRID Org information gatherer.
description:
    - This module allows you to gather various information about StorageGRID Org configuration.
version_added: 20.11.0

options:
    gather_subset:
        type: list
        elements: str
        description:
            - When supplied, this argument will restrict the information collected to a given subset.
            - Either the info name or the Rest API can be given.
            - Possible values for this argument include
            - C(org_compliance_global_info) or C(org/compliance-global)
            - C(org_config_info) or C(org/config)
            - C(org_config_product_version_info) or C(org/config/product-version)
            - C(org_containers_info) or C(org/containers)
            - C(org_deactivated_features_info) or C(org/deactivated-features)
            - C(org_endpoints_info) or C(org/endpoints)
            - C(org_groups_info) or C(org/groups)
            - C(org_identity_source_info) or C(org/identity-source)
            - C(org_regions_info) or C(org/regions)
            - C(org_users_current_user_s3_access_keys_info) or C(org/users/current-user/s3-access-keys)
            - C(org_usage_info) or C(org/usage)
            - C(org_users_info) or C(org/users)
            - C(org_users_root_info) or C(org/users/root)
            - C(versions_info) or C(versions)
            - Can specify a list of values to include a larger subset.
        default: "all"
    parameters:
        description:
        - Allows for any rest option to be passed in.
        type: dict
"""

EXAMPLES = """
- name: Gather StorageGRID Org info
  netapp.storagegrid.na_sg_org_info:
    api_url: "https://1.2.3.4/"
    auth_token: "storagegrid-auth-token"
    validate_certs: false
  register: sg_org_info

- name: Gather StorageGRID Org info for org/containers and org/config subsets
  netapp.storagegrid.na_sg_org_info:
    api_url: "https://1.2.3.4/"
    auth_token: "storagegrid-auth-token"
    validate_certs: false
    gather_subset:
      - org_containers_info
      - org/config
  register: sg_org_info

- name: Gather StorageGRID Org info for all subsets
  netapp.storagegrid.na_sg_org_info:
    api_url: "https://1.2.3.4/"
    auth_token: "storagegrid-auth-token"
    validate_certs: false
    gather_subset:
      - all
  register: sg_org_info

- name: Gather StorageGRID Org info for org/containers and org/users subsets, limit to 5 results for each subset
  netapp.storagegrid.na_sg_org_info:
    api_url: "https://1.2.3.4/"
    auth_token: "storagegrid-auth-token"
    validate_certs: false
    gather_subset:
      - org/containers
      - org/users
    parameters:
      limit: 5
  register: sg_org_info
"""

RETURN = """
sg_info:
    description: Returns various information about the StorageGRID Grid configuration.
    returned: always
    type: dict
    sample: {
        "org/compliance-global": {...},
        "org/config": {...},
        "org/config/product-version": {...},
        "org/containers": {...},
        "org/deactivated-features": {...},
        "org/endpoints": {...},
        "org/groups": {...},
        "org/identity-source": {...},
        "org/regions": {...},
        "org/users/current-user/s3-access-keys": {...},
        "org/usage": {...},
        "org/users": {...},
        "org/users/root": {...},
        "org/versions": {...}
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
            'org_compliance_global_info': 'org/compliance-global',
            'org_config_info': 'org/config',
            'org_config_product_version_info': 'org/config/product-version',
            'org_containers_info': 'org/containers',
            'org_deactivated_features_info': 'org/deactivated-features',
            'org_endpoints_info': 'org/endpoints',
            'org_groups_info': 'org/groups',
            'org_identity_source_info': 'org/identity-source',
            'org_regions_info': 'org/regions',
            'org_users_current_user_s3_access_keys_info': 'org/users/current-user/s3-access-keys',
            'org_usage_info': 'org/usage',
            'org_users_info': 'org/users',
            'org_users_root_info': 'org/users/root',
            'versions_info': 'versions'
        }
        # Add rest API names as there info version, also make sure we don't add a duplicate
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

        # Defining gather_subset and appropriate api_call
        get_sg_subset_info = {
            'org/compliance-global': {
                'api_call': 'api/v3/org/compliance-global',
            },
            'org/config': {
                'api_call': 'api/v3/org/config',
            },
            'org/config/product-version': {
                'api_call': 'api/v3/org/config/product-version',
            },
            'org/containers': {
                'api_call': 'api/v3/org/containers',
            },
            'org/deactivated-features': {
                'api_call': 'api/v3/org/deactivated-features',
            },
            'org/endpoints': {
                'api_call': 'api/v3/org/endpoints',
            },
            'org/groups': {
                'api_call': 'api/v3/org/groups',
            },
            'org/identity-source': {
                'api_call': 'api/v3/org/identity-source',
            },
            'org/regions': {
                'api_call': 'api/v3/org/regions',
            },
            'org/users/current-user/s3-access-keys': {
                'api_call': 'api/v3/org/users/current-user/s3-access-keys',
            },
            'org/usage': {
                'api_call': 'api/v3/org/usage',
            },
            'org/users': {
                'api_call': 'api/v3/org/users',
            },
            'org/users/root': {
                'api_call': 'api/v3/org/users/root',
            },
            'versions': {
                'api_call': 'api/v3/versions',
            },
        }

        if 'all' in self.parameters['gather_subset']:
            # If all in subset list, get the information of all subsets
            self.parameters['gather_subset'] = sorted(get_sg_subset_info.keys())

        converted_subsets = self.convert_subsets()

        for subset in converted_subsets:
            try:
                # Verify whether the supported subset passed
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
