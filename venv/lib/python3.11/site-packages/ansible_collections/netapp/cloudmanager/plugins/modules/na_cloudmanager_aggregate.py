#!/usr/bin/python

# (c) 2021, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

'''
na_cloudmanager_aggregate
'''

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = '''

module: na_cloudmanager_aggregate
short_description: NetApp Cloud Manager Aggregate
extends_documentation_fragment:
    - netapp.cloudmanager.netapp.cloudmanager
version_added: '21.3.0'
author: NetApp Ansible Team (@carchi8py) <ng-ansibleteam@netapp.com>

description:
- Create, Modify or Delete Aggregate on Cloud Manager.

options:
  state:
    description:
    - Whether the specified aggregate should exist or not.
    choices: ['present', 'absent']
    required: true
    type: str

  name:
    description:
    - The name of the new aggregate.
    required: true
    type: str

  working_environment_name:
    description:
    - The working environment name where the aggregate will be created.
    type: str

  working_environment_id:
    description:
    - The public ID of the working environment where the aggregate will be created.
    type: str

  client_id:
    description:
    - The connector ID of the Cloud Manager Connector.
    required: true
    type: str

  number_of_disks:
    description:
    - The required number of disks in the new aggregate.
    type: int

  disk_size_size:
    description:
    - The required size of the disks.
    type: int

  disk_size_unit:
    description:
    - The disk size unit ['GB' or 'TB']. The default is 'TB'.
    choices: ['GB', 'TB']
    default: 'TB'
    type: str

  home_node:
    description:
    - The home node that the new aggregate should belong to.
    type: str

  provider_volume_type:
    description:
    - The cloud provider volume type.
    type: str

  capacity_tier:
    description:
    - The aggregate's capacity tier for tiering cold data to object storage.
    - If the value is NONE, the capacity_tier will not be set on aggregate creation.
    choices: [ 'NONE', 'S3', 'Blob', 'cloudStorage']
    type: str

  iops:
    description:
    - Provisioned IOPS. Needed only when providerVolumeType is "io1".
    type: int

  throughput:
    description:
    - Unit is Mb/s. Valid range 125-1000.
    - Required only when provider_volume_type is 'gp3'.
    type: int

notes:
- Support check_mode.
'''

EXAMPLES = '''
- name: Create Aggregate
  netapp.cloudmanager.na_cloudmanager_aggregate:
    state: present
    name: AnsibleAggregate
    working_environment_name: testAWS
    client_id: "{{ client_id }}"
    number_of_disks: 2
    refresh_token: xxx

- name: Delete Volume
  netapp.cloudmanager.na_cloudmanager_aggregate:
    state: absent
    name: AnsibleAggregate
    working_environment_name: testAWS
    client_id: "{{ client_id }}"
    refresh_token: xxx
'''

RETURN = '''
msg:
    description: Success message.
    returned: success
    type: str
    sample: "Aggregate Created"
'''

from ansible.module_utils.basic import AnsibleModule
import ansible_collections.netapp.cloudmanager.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.cloudmanager.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.cloudmanager.plugins.module_utils.netapp import CloudManagerRestAPI


class NetAppCloudmanagerAggregate(object):
    '''
    Contains methods to parse arguments,
    derive details of CloudmanagerAggregate objects
    and send requests to CloudmanagerAggregate via
    the restApi
    '''

    def __init__(self):
        '''
        Parse arguments, setup state variables,
        check parameters and ensure request module is installed
        '''
        self.argument_spec = netapp_utils.cloudmanager_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=True, choices=['present', 'absent']),
            name=dict(required=True, type='str'),
            working_environment_id=dict(required=False, type='str'),
            working_environment_name=dict(required=False, type='str'),
            client_id=dict(required=True, type='str'),
            number_of_disks=dict(required=False, type='int'),
            disk_size_size=dict(required=False, type='int'),
            disk_size_unit=dict(required=False, choices=['GB', 'TB'], default='TB'),
            home_node=dict(required=False, type='str'),
            provider_volume_type=dict(required=False, type='str'),
            capacity_tier=dict(required=False, choices=['NONE', 'S3', 'Blob', 'cloudStorage'], type='str'),
            iops=dict(required=False, type='int'),
            throughput=dict(required=False, type='int'),
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            required_one_of=[
                ['refresh_token', 'sa_client_id'],
                ['working_environment_name', 'working_environment_id'],
            ],
            required_together=[['sa_client_id', 'sa_secret_key']],
            required_if=[
                ['provider_volume_type', 'gp3', ['iops', 'throughput']],
                ['provider_volume_type', 'io1', ['iops']],
            ],
            supports_check_mode=True
        )

        self.na_helper = NetAppModule()
        # set up state variables
        self.parameters = self.na_helper.set_parameters(self.module.params)
        # Calling generic rest_api class
        self.rest_api = CloudManagerRestAPI(self.module)
        self.rest_api.url += self.rest_api.environment_data['CLOUD_MANAGER_HOST']
        self.rest_api.api_root_path = None
        self.headers = {
            'X-Agent-Id': self.rest_api.format_client_id(self.parameters['client_id'])
        }

    def get_aggregate(self):
        '''
        Get aggregate details
        '''
        working_environment_detail = None
        if 'working_environment_id' in self.parameters:
            working_environment_detail, error = self.na_helper.get_working_environment_details(self.rest_api, self.headers)
            if error is not None:
                self.module.fail_json(msg="Error: Cannot find working environment: %s" % str(error))
        elif 'working_environment_name' in self.parameters:
            working_environment_detail, error = self.na_helper.get_working_environment_details_by_name(self.rest_api,
                                                                                                       self.headers,
                                                                                                       self.parameters['working_environment_name'])
            if error is not None:
                self.module.fail_json(msg="Error: Cannot find working environment: %s" % str(error))
        else:
            self.module.fail_json(msg="Error: Missing working environment information")
        if working_environment_detail is not None:
            self.parameters['working_environment_id'] = working_environment_detail['publicId']
        self.na_helper.set_api_root_path(working_environment_detail, self.rest_api)
        api_root_path = self.rest_api.api_root_path

        if working_environment_detail['cloudProviderName'] != "Amazon":
            api = '%s/aggregates/%s' % (api_root_path, working_environment_detail['publicId'])
        else:
            api = '%s/aggregates?workingEnvironmentId=%s' % (api_root_path, working_environment_detail['publicId'])
        response, error, dummy = self.rest_api.get(api, header=self.headers)
        if error:
            self.module.fail_json(msg="Error: Failed to get aggregate list: %s, %s" % (str(error), str(response)))
        for aggr in response:
            if aggr['name'] == self.parameters['name']:
                return aggr
        return None

    def create_aggregate(self):
        '''
        Create aggregate
        '''
        api = '%s/aggregates' % self.rest_api.api_root_path
        # check if all the required parameters exist
        body = {
            'name': self.parameters['name'],
            'workingEnvironmentId': self.parameters['working_environment_id'],
            'numberOfDisks': self.parameters['number_of_disks'],
            'diskSize': {'size': self.parameters['disk_size_size'],
                         'unit': self.parameters['disk_size_unit']},
        }
        # optional parameters
        if 'home_node' in self.parameters:
            body['homeNode'] = self.parameters['home_node']
        if 'provider_volume_type' in self.parameters:
            body['providerVolumeType'] = self.parameters['provider_volume_type']
        if 'capacity_tier' in self.parameters and self.parameters['capacity_tier'] != "NONE":
            body['capacityTier'] = self.parameters['capacity_tier']
        if 'iops' in self.parameters:
            body['iops'] = self.parameters['iops']
        if 'throughput' in self.parameters:
            body['throughput'] = self.parameters['throughput']
        response, error, dummy = self.rest_api.post(api, body, header=self.headers)
        if error is not None:
            self.module.fail_json(msg="Error: unexpected response on aggregate creation: %s, %s" % (str(error), str(response)))

    def update_aggregate(self, add_number_of_disks):
        '''
        Update aggregate with aggregate name and the parameters number_of_disks will be added
        '''
        api = '%s/aggregates/%s/%s/disks' % (self.rest_api.api_root_path, self.parameters['working_environment_id'],
                                             self.parameters['name'])
        body = {
            'aggregateName': self.parameters['name'],
            'workingEnvironmentId': self.parameters['working_environment_id'],
            'numberOfDisks': add_number_of_disks
        }
        response, error, dummy = self.rest_api.post(api, body, header=self.headers)
        if error is not None:
            self.module.fail_json(msg="Error: unexpected response on aggregate adding disks: %s, %s" % (str(error), str(response)))

    def delete_aggregate(self):
        '''
        Delete aggregate with aggregate name
        '''
        api = '%s/aggregates/%s/%s' % (self.rest_api.api_root_path, self.parameters['working_environment_id'],
                                       self.parameters['name'])
        body = {
            'aggregateName': self.parameters['name'],
            'workingEnvironmentId': self.parameters['working_environment_id'],
        }
        response, error, dummy = self.rest_api.delete(api, body, header=self.headers)
        if error is not None:
            self.module.fail_json(msg="Error: unexpected response on aggregate deletion: %s, %s" % (str(error), str(response)))

    def apply(self):
        '''
        Check, process and initiate aggregate operation
        '''
        # check if aggregate exists
        current = self.get_aggregate()
        # check the action
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if self.na_helper.changed:
            action = cd_action + "_aggregate"
            have_all_required, missed_params = self.na_helper.have_required_parameters(action)
            if not have_all_required:
                self.module.fail_json(msg="Error: Missing required parameters (%s) on %s" % (str(missed_params), action))
        add_disks = 0
        if current and self.parameters['state'] != 'absent':
            have_all_required, missed_params = self.na_helper.have_required_parameters("update_aggregate")
            if not have_all_required:
                self.module.fail_json(msg="Error: Missing required parameters (%s) on update_aggregate" % str(missed_params))
            if len(current['disks']) < self.parameters['number_of_disks']:
                add_disks = self.parameters['number_of_disks'] - len(current['disks'])
                self.na_helper.changed = True
            elif len(current['disks']) > self.parameters['number_of_disks']:
                self.module.fail_json(msg="Error: Only add disk support. number_of_disks cannot be reduced")

        result_message = ""
        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == "create":
                self.create_aggregate()
                result_message = "Aggregate Created"
            elif cd_action == "delete":
                self.delete_aggregate()
                result_message = "Aggregate Deleted"
            else:  # modify
                self.update_aggregate(add_disks)
                result_message = "Aggregate Updated"
        self.module.exit_json(changed=self.na_helper.changed, msg=result_message)


def main():
    '''
    Create NetAppCloudmanagerAggregate class instance and invoke apply
    :return: None
    '''
    na_cloudmanager_aggregate = NetAppCloudmanagerAggregate()
    na_cloudmanager_aggregate.apply()


if __name__ == '__main__':
    main()
