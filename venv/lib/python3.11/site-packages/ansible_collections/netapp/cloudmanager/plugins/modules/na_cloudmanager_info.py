#!/usr/bin/python

# (c) 2021, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

'''
na_cloudmanager_info
'''

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''

module: na_cloudmanager_info
short_description: NetApp Cloud Manager info
extends_documentation_fragment:
  - netapp.cloudmanager.netapp.cloudmanager
version_added: '21.4.0'
author: NetApp Ansible Team (@carchi8py) <ng-ansibleteam@netapp.com>

description:
  - This module allows you to gather various information about cloudmanager using REST APIs.

options:
  client_id:
    required: true
    type: str
    description:
      - The connector ID of the Cloud Manager Connector.

  gather_subsets:
    type: list
    elements: str
    description:
      - When supplied, this argument will restrict the information collected to a given subset.
      - Possible values for this argument include
      - 'working_environments_info'
      - 'aggregates_info'
      - 'accounts_info'
      - 'account_info'
      - 'agents_info'
      - 'active_agents_info'
    default: 'all'

notes:
- Support check_mode
'''

EXAMPLES = """
- name: Get all available subsets
  netapp.cloudmanager.na_cloudmanager_info:
    client_id: "{{ client_id }}"
    refresh_token: "{{ refresh_token }}"
    gather_subsets:
      - all

- name: Collect data for cloud manager with indicated subsets
  netapp.cloudmanager.na_cloudmanager_info:
    client_id: "{{ client_id }}"
    refresh_token: "{{ refresh_token }}"
    gather_subsets:
      - aggregates_info
      - working_environments_info
"""

RETURN = """
info:
  description:
    - a dictionary of collected subsets
    - each subset if in JSON format
  returned: success
  type: dict
  sample: '{
    "info": {
      "working_environments_info": [
        {
          "azureVsaWorkingEnvironments": [],
          "gcpVsaWorkingEnvironments": [],
          "onPremWorkingEnvironments": [],
          "vsaWorkingEnvironments": [
            {
                "actionsRequired": null,
                "activeActions": null,
                "awsProperties": null,
                "capacityFeatures": null,
                "cbsProperties": null,
                "cloudProviderName": "Amazon",
                "cloudSyncProperties": null,
                "clusterProperties": null,
                "complianceProperties": null,
                "creatorUserEmail": "samlp|NetAppSAML|test_user",
                "cronJobSchedules": null,
                "encryptionProperties": null,
                "fpolicyProperties": null,
                "haProperties": null,
                "interClusterLifs": null,
                "isHA": false,
                "k8sProperties": null,
                "monitoringProperties": null,
                "name": "testAWS",
                "ontapClusterProperties": null,
                "publicId": "VsaWorkingEnvironment-3txYJOsX",
                "replicationProperties": null,
                "reservedSize": null,
                "saasProperties": null,
                "schedules": null,
                "snapshotPolicies": null,
                "status": null,
                "supportRegistrationInformation": [],
                "supportRegistrationProperties": null,
                "supportedFeatures": null,
                "svmName": "svm_testAWS",
                "svms": null,
                "tenantId": "Tenant-2345",
                "workingEnvironmentType": "VSA"
            }
          ]
        },
        null
      ]
    }
  }'
"""

from ansible.module_utils.basic import AnsibleModule
import ansible_collections.netapp.cloudmanager.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.cloudmanager.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.cloudmanager.plugins.module_utils.netapp import CloudManagerRestAPI


class NetAppCloudmanagerInfo(object):
    '''
    Contains methods to parse arguments,
    derive details of CloudmanagerInfo objects
    and send requests to CloudmanagerInfo via
    the restApi
    '''

    def __init__(self):
        self.argument_spec = netapp_utils.cloudmanager_host_argument_spec()
        self.argument_spec.update(dict(
            gather_subsets=dict(type='list', elements='str', default='all'),
            client_id=dict(required=True, type='str'),
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            required_one_of=[['refresh_token', 'sa_client_id']],
            required_together=[['sa_client_id', 'sa_secret_key']],
            supports_check_mode=True
        )

        self.na_helper = NetAppModule()
        # set up state variables
        self.parameters = self.na_helper.set_parameters(self.module.params)
        # Calling generic rest_api class
        self.rest_api = CloudManagerRestAPI(self.module)
        self.rest_api.url += self.rest_api.environment_data['CLOUD_MANAGER_HOST']
        self.rest_api.api_root_path = None
        self.methods = dict(
            working_environments_info=self.na_helper.get_working_environments_info,
            aggregates_info=self.get_aggregates_info,
            accounts_info=self.na_helper.get_accounts_info,
            account_info=self.na_helper.get_account_info,
            agents_info=self.na_helper.get_agents_info,
            active_agents_info=self.na_helper.get_active_agents_info,
        )
        self.headers = {}
        if 'client_id' in self.parameters:
            self.headers['X-Agent-Id'] = self.rest_api.format_client_id(self.parameters['client_id'])

    def get_aggregates_info(self, rest_api, headers):
        '''
        Get aggregates info: there are 4 types of working environments.
        Each of the aggregates will be categorized by working environment type and working environment id
        '''
        aggregates = {}
        # get list of working environments
        working_environments, error = self.na_helper.get_working_environments_info(rest_api, headers)
        if error is not None:
            self.module.fail_json(msg="Error: Failed to get working environments: %s" % str(error))
        # Four types of working environments:
        # azureVsaWorkingEnvironments, gcpVsaWorkingEnvironments, onPremWorkingEnvironments, vsaWorkingEnvironments
        for working_env_type in working_environments:
            we_aggregates = {}
            # get aggregates for each working environment
            for we in working_environments[working_env_type]:
                provider = we['cloudProviderName']
                working_environment_id = we['publicId']
                self.na_helper.set_api_root_path(we, rest_api)
                if provider != "Amazon":
                    api = '%s/aggregates/%s' % (rest_api.api_root_path, working_environment_id)
                else:
                    api = '%s/aggregates?workingEnvironmentId=%s' % (rest_api.api_root_path, working_environment_id)
                response, error, dummy = rest_api.get(api, None, header=headers)
                if error:
                    self.module.fail_json(msg="Error: Failed to get aggregate list: %s" % str(error))
                we_aggregates[working_environment_id] = response
            aggregates[working_env_type] = we_aggregates
        return aggregates

    def get_info(self, func, rest_api):
        '''
        Main get info function
        '''
        return self.methods[func](rest_api, self.headers)

    def apply(self):
        '''
        Apply action to the Cloud Manager
        :return: None
        '''
        info = {}
        if 'all' in self.parameters['gather_subsets']:
            self.parameters['gather_subsets'] = self.methods.keys()
        for func in self.parameters['gather_subsets']:
            if func in self.methods:
                info[func] = self.get_info(func, self.rest_api)
            else:
                msg = '%s is not a valid gather_subset. Only %s are allowed' % (func, self.methods.keys())
                self.module.fail_json(msg=msg)
        self.module.exit_json(changed=False, info=info)


def main():
    '''
    Main function
    '''
    na_cloudmanager_info = NetAppCloudmanagerInfo()
    na_cloudmanager_info.apply()


if __name__ == '__main__':
    main()
