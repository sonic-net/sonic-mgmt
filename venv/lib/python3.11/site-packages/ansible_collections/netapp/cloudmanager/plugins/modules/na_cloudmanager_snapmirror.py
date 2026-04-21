#!/usr/bin/python

# (c) 2021, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

'''
na_cloudmanager_snapmirror
'''

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''

module: na_cloudmanager_snapmirror
short_description: NetApp Cloud Manager SnapMirror
extends_documentation_fragment:
    - netapp.cloudmanager.netapp.cloudmanager
version_added: '21.6.0'
author: NetApp Ansible Team (@carchi8py) <ng-ansibleteam@netapp.com>

description:
- Create or Delete SnapMirror relationship on Cloud Manager.

options:

  state:
    description:
    - Whether the specified snapmirror relationship should exist or not.
    choices: ['present', 'absent']
    default: 'present'
    type: str

  source_working_environment_name:
    description:
    - The working environment name of the source volume.
    type: str

  destination_working_environment_name:
    description:
    - The working environment name of the destination volume.
    type: str

  source_working_environment_id:
    description:
    - The public ID of the working environment of the source volume.
    type: str

  destination_working_environment_id:
    description:
    - The public ID of the working environment of the destination volume.
    type: str

  destination_aggregate_name:
    description:
    - The aggregate in which the volume will be created.
    - If not provided, Cloud Manager chooses the best aggregate for you.
    type: str

  policy:
    description:
    - The SnapMirror policy name.
    type: str
    default: 'MirrorAllSnapshots'

  max_transfer_rate:
    description:
    - Maximum transfer rate limit KB/s.
    - Use 0 for no limit, otherwise use number between 1024 and 2,147,482,624.
    type: int
    default: 100000

  source_svm_name:
    description:
    - The name of the source SVM.
    - The default SVM name is used, if a name is not provided.
    type: str

  destination_svm_name:
    description:
    - The name of the destination SVM.
    - The default SVM name is used, if a name is not provided.
    type: str

  source_volume_name:
    description:
    - The name of the source volume.
    required: true
    type: str

  destination_volume_name:
    description:
    - The name of the destination volume to be created for snapmirror relationship.
    required: true
    type: str

  schedule:
    description:
    - The name of the Schedule.
    type: str
    default: '1hour'

  provider_volume_type:
    description:
    - The underlying cloud provider volume type.
    - For AWS ['gp3', 'gp2', 'io1', 'st1', 'sc1'].
    - For Azure ['Premium_LRS','Standard_LRS','StandardSSD_LRS'].
    - For GCP ['pd-balanced','pd-ssd','pd-standard'].
    type: str

  capacity_tier:
    description:
    - The volume capacity tier for tiering cold data to object storage.
    - The default values for each cloud provider are as follows, Amazon 'S3', Azure 'Blob', GCP 'cloudStorage'.
    - If NONE, the capacity tier will not be set on volume creation.
    type: str
    choices: ['S3', 'Blob', 'cloudStorage', 'NONE']

  tenant_id:
    description:
    - The NetApp account ID that the Connector will be associated with. To be used only when using FSx.
    type: str
    version_added: 21.14.0

  client_id:
    description:
    - The connector ID of the Cloud Manager Connector.
    required: true
    type: str

notes:
- Support check_mode.
'''

EXAMPLES = '''
- name: Create snapmirror with working_environment_name
  netapp.cloudmanager.na_cloudmanager_snapmirror:
    state: present
    source_working_environment_name: source
    destination_working_environment_name: dest
    source_volume_name: source
    destination_volume_name: source_copy
    policy: MirrorAllSnapshots
    schedule: 5min
    max_transfer_rate: 102400
    client_id: client_id
    refresh_token: refresh_token

- name: Delete snapmirror
  netapp.cloudmanager.na_cloudmanager_snapmirror:
    state: absent
    source_working_environment_name: source
    destination_working_environment_name: dest
    source_volume_name: source
    destination_volume_name: source_copy
    client_id: client_id
    refresh_token: refresh_token
'''

RETURN = r''' # '''


from ansible.module_utils.basic import AnsibleModule
import ansible_collections.netapp.cloudmanager.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.cloudmanager.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.cloudmanager.plugins.module_utils.netapp import CloudManagerRestAPI


PROVIDER_TO_CAPACITY_TIER = {'amazon': 'S3', 'azure': 'Blob', 'gcp': 'cloudStorage'}


class NetAppCloudmanagerSnapmirror:

    def __init__(self):
        """
        Parse arguments, setup state variables,
        check parameters and ensure request module is installed
        """
        self.argument_spec = netapp_utils.cloudmanager_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, choices=['present', 'absent'], default='present'),
            source_working_environment_id=dict(required=False, type='str'),
            destination_working_environment_id=dict(required=False, type='str'),
            source_working_environment_name=dict(required=False, type='str'),
            destination_working_environment_name=dict(required=False, type='str'),
            destination_aggregate_name=dict(required=False, type='str'),
            policy=dict(required=False, type='str', default='MirrorAllSnapshots'),
            max_transfer_rate=dict(required=False, type='int', default='100000'),
            schedule=dict(required=False, type='str', default='1hour'),
            source_svm_name=dict(required=False, type='str'),
            destination_svm_name=dict(required=False, type='str'),
            source_volume_name=dict(required=True, type='str'),
            destination_volume_name=dict(required=True, type='str'),
            capacity_tier=dict(required=False, type='str', choices=['NONE', 'S3', 'Blob', 'cloudStorage']),
            provider_volume_type=dict(required=False, type='str'),
            tenant_id=dict(required=False, type='str'),
            client_id=dict(required=True, type='str'),
        ))
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            required_one_of=[
                ['source_working_environment_id', 'source_working_environment_name'],
                ['refresh_token', 'sa_client_id'],
            ],
            required_together=(['source_working_environment_id', 'destination_working_environment_id'],
                               ['source_working_environment_name', 'destination_working_environment_name'],
                               ['sa_client_id', 'sa_secret_key'],
                               ),
            supports_check_mode=True
        )

        self.na_helper = NetAppModule()
        # set up state variables
        self.parameters = self.na_helper.set_parameters(self.module.params)

        self.rest_api = CloudManagerRestAPI(self.module)
        self.rest_api.url += self.rest_api.environment_data['CLOUD_MANAGER_HOST']
        self.rest_api.api_root_path = None
        self.headers = {
            'X-Agent-Id': self.rest_api.format_client_id(self.parameters['client_id'])
        }
        if self.rest_api.simulator:
            self.headers.update({'x-simulator': 'true'})

    def get_snapmirror(self):
        source_we_info, dest_we_info, err = self.na_helper.get_working_environment_detail_for_snapmirror(self.rest_api, self.headers)
        if err is not None:
            self.module.fail_json(changed=False, msg=err)

        get_url = '/occm/api/replication/status/%s' % source_we_info['publicId']
        snapmirror_info, err, dummy = self.rest_api.send_request("GET", get_url, None, header=self.headers)
        if err is not None:
            self.module.fail_json(changed=False, msg='Error getting snapmirror relationship %s: %s.' % (err, snapmirror_info))
        sm_found = False
        snapmirror = None
        for sm in snapmirror_info:
            if sm['destination']['volumeName'] == self.parameters['destination_volume_name']:
                sm_found = True
                snapmirror = sm
                break

        if not sm_found:
            return None
        result = {
            'source_working_environment_id': source_we_info['publicId'],
            'destination_svm_name': snapmirror['destination']['svmName'],
            'destination_working_environment_id': dest_we_info['publicId'],
        }
        if not dest_we_info['publicId'].startswith('fs-'):
            result['cloud_provider_name'] = dest_we_info['cloudProviderName']
        return result

    def create_snapmirror(self):
        snapmirror_build_data = {}
        replication_request = {}
        replication_volume = {}
        source_we_info, dest_we_info, err = self.na_helper.get_working_environment_detail_for_snapmirror(self.rest_api, self.headers)
        if err is not None:
            self.module.fail_json(changed=False, msg=err)
        if self.parameters.get('capacity_tier') is not None:
            if self.parameters['capacity_tier'] == 'NONE':
                self.parameters.pop('capacity_tier')
        else:
            if dest_we_info.get('cloudProviderName'):
                self.parameters['capacity_tier'] = PROVIDER_TO_CAPACITY_TIER[dest_we_info['cloudProviderName'].lower()]

        interclusterlifs_info = self.get_interclusterlifs(source_we_info['publicId'], dest_we_info['publicId'])

        if source_we_info['workingEnvironmentType'] != 'ON_PREM':
            source_volumes = self.get_volumes(source_we_info, self.parameters['source_volume_name'])
        else:
            source_volumes = self.get_volumes_on_prem(source_we_info, self.parameters['source_volume_name'])

        if len(source_volumes) == 0:
            self.module.fail_json(changed=False, msg='source volume not found')

        vol_found = False
        vol_dest_quote = {}
        source_volume_resp = {}
        for vol in source_volumes:
            if vol['name'] == self.parameters['source_volume_name']:
                vol_found = True
                vol_dest_quote = vol
                source_volume_resp = vol
                if self.parameters.get('source_svm_name') is not None and vol['svmName'] != self.parameters['source_svm_name']:
                    vol_found = False
                if vol_found:
                    break

        if not vol_found:
            self.module.fail_json(changed=False, msg='source volume not found')

        if self.parameters.get('source_svm_name') is None:
            self.parameters['source_svm_name'] = source_volume_resp['svmName']

        if self.parameters.get('destination_svm_name') is None:
            if dest_we_info.get('svmName') is not None:
                self.parameters['destination_svm_name'] = dest_we_info['svmName']
            else:
                self.parameters['destination_working_environment_name'] = dest_we_info['name']
                dest_working_env_detail, err = self.na_helper.get_working_environment_details_by_name(self.rest_api,
                                                                                                      self.headers,
                                                                                                      self.parameters['destination_working_environment_name'])
                if err:
                    self.module.fail_json(changed=False, msg='Error getting destination info %s: %s.' % (err, dest_working_env_detail))
                self.parameters['destination_svm_name'] = dest_working_env_detail['svmName']

        if dest_we_info.get('workingEnvironmentType') and dest_we_info['workingEnvironmentType'] != 'ON_PREM'\
                and not dest_we_info['publicId'].startswith('fs-'):
            quote = self.build_quote_request(source_we_info, dest_we_info, vol_dest_quote)
            quote_response = self.quote_volume(quote)
            replication_volume['numOfDisksApprovedToAdd'] = int(quote_response['numOfDisks'])
            if 'iops' in quote:
                replication_volume['iops'] = quote['iops']
            if 'throughput' in quote:
                replication_volume['throughput'] = quote['throughput']
            if self.parameters.get('destination_aggregate_name') is not None:
                replication_volume['advancedMode'] = True
            else:
                replication_volume['advancedMode'] = False
                replication_volume['destinationAggregateName'] = quote_response['aggregateName']
        if self.parameters.get('provider_volume_type') is None:
            replication_volume['destinationProviderVolumeType'] = source_volume_resp['providerVolumeType']

        if self.parameters.get('capacity_tier') is not None:
            replication_volume['destinationCapacityTier'] = self.parameters['capacity_tier']
        replication_request['sourceWorkingEnvironmentId'] = source_we_info['publicId']
        if dest_we_info['publicId'].startswith('fs-'):
            replication_request['destinationFsxId'] = dest_we_info['publicId']
        else:
            replication_request['destinationWorkingEnvironmentId'] = dest_we_info['publicId']
        replication_volume['sourceVolumeName'] = self.parameters['source_volume_name']
        replication_volume['destinationVolumeName'] = self.parameters['destination_volume_name']
        replication_request['policyName'] = self.parameters['policy']
        replication_request['scheduleName'] = self.parameters['schedule']
        replication_request['maxTransferRate'] = self.parameters['max_transfer_rate']
        replication_volume['sourceSvmName'] = source_volume_resp['svmName']
        replication_volume['destinationSvmName'] = self.parameters['destination_svm_name']
        replication_request['sourceInterclusterLifIps'] = [interclusterlifs_info['interClusterLifs'][0]['address']]
        replication_request['destinationInterclusterLifIps'] = [interclusterlifs_info['peerInterClusterLifs'][0]['address']]

        snapmirror_build_data['replicationRequest'] = replication_request
        snapmirror_build_data['replicationVolume'] = replication_volume

        if dest_we_info['publicId'].startswith('fs-'):
            api = '/occm/api/replication/fsx'
        elif dest_we_info['workingEnvironmentType'] != 'ON_PREM':
            api = '/occm/api/replication/vsa'
        else:
            api = '/occm/api/replication/onprem'

        response, err, on_cloud_request_id = self.rest_api.send_request("POST", api, None, snapmirror_build_data, header=self.headers)
        if err is not None:
            self.module.fail_json(changed=False, msg='Error creating snapmirror relationship %s: %s.' % (err, response))
        wait_on_completion_api_url = '/occm/api/audit/activeTask/%s' % (str(on_cloud_request_id))
        err = self.rest_api.wait_on_completion(wait_on_completion_api_url, "snapmirror", "create", 20, 5)
        if err is not None:
            self.module.fail_json(changed=False, msg=err)

    def get_volumes(self, working_environment_detail, name):
        self.na_helper.set_api_root_path(working_environment_detail, self.rest_api)
        response, err, dummy = self.rest_api.send_request("GET", "%s/volumes?workingEnvironmentId=%s&name=%s" % (
            self.rest_api.api_root_path, working_environment_detail['publicId'], name), None, header=self.headers)
        if err is not None:
            self.module.fail_json(changed=False, msg='Error getting volume %s: %s.' % (err, response))
        return response

    def quote_volume(self, quote):
        response, err, on_cloud_request_id = self.rest_api.send_request("POST", '%s/volumes/quote' %
                                                                        self.rest_api.api_root_path, None, quote, header=self.headers)
        if err is not None:
            self.module.fail_json(changed=False, msg='Error quoting destination volume %s: %s.' % (err, response))
        wait_on_completion_api_url = '/occm/api/audit/activeTask/%s' % (str(on_cloud_request_id))
        err = self.rest_api.wait_on_completion(wait_on_completion_api_url, "volume", "quote", 20, 5)
        if err is not None:
            self.module.fail_json(changed=False, msg=err)
        return response

    def get_volumes_on_prem(self, working_environment_detail, name):
        response, err, dummy = self.rest_api.send_request("GET", "/occm/api/onprem/volumes?workingEnvironmentId=%s&name=%s" %
                                                          (working_environment_detail['publicId'], name), None, header=self.headers)
        if err is not None:
            self.module.fail_json(changed=False, msg='Error getting volume on prem %s: %s.' % (err, response))
        return response

    def get_aggregate_detail(self, working_environment_detail, aggregate_name):
        if working_environment_detail['workingEnvironmentType'] == 'ON_PREM':
            api = "/occm/api/onprem/aggregates?workingEnvironmentId=%s" % working_environment_detail['publicId']
        else:
            self.na_helper.set_api_root_path(working_environment_detail, self.rest_api)
            api_root_path = self.rest_api.api_root_path
            if working_environment_detail['cloudProviderName'] != "Amazon":
                api = '%s/aggregates/%s'
            else:
                api = '%s/aggregates?workingEnvironmentId=%s'
            api = api % (api_root_path, working_environment_detail['publicId'])
        response, error, dummy = self.rest_api.get(api, header=self.headers)
        if error:
            self.module.fail_json(msg="Error: Failed to get aggregate list: %s" % str(error))
        for aggr in response:
            if aggr['name'] == aggregate_name:
                return aggr
        return None

    def build_quote_request(self, source_we_info, dest_we_info, vol_dest_quote):
        quote = dict()
        quote['size'] = {'size': vol_dest_quote['size']['size'], 'unit': vol_dest_quote['size']['unit']}
        quote['name'] = self.parameters['destination_volume_name']
        quote['snapshotPolicyName'] = vol_dest_quote['snapshotPolicy']
        quote['enableDeduplication'] = vol_dest_quote['deduplication']
        quote['enableThinProvisioning'] = vol_dest_quote['thinProvisioning']
        quote['enableCompression'] = vol_dest_quote['compression']
        quote['verifyNameUniqueness'] = True
        quote['replicationFlow'] = True

        # Use source working environment to get physical properties info of volumes
        aggregate = self.get_aggregate_detail(source_we_info, vol_dest_quote['aggregateName'])
        if aggregate is None:
            self.module.fail_json(changed=False, msg='Error getting aggregate on source volume')
        # All the volumes in one aggregate have the same physical properties
        if source_we_info['workingEnvironmentType'] != 'ON_PREM':
            if aggregate['providerVolumes'][0]['diskType'] == 'gp3' or aggregate['providerVolumes'][0]['diskType'] == 'io1'\
                    or aggregate['providerVolumes'][0]['diskType'] == 'io2':
                quote['iops'] = aggregate['providerVolumes'][0]['iops']
            if aggregate['providerVolumes'][0]['diskType'] == 'gp3':
                quote['throughput'] = aggregate['providerVolumes'][0]['throughput']
            quote['workingEnvironmentId'] = dest_we_info['publicId']
            quote['svmName'] = self.parameters['destination_svm_name']
        if self.parameters.get('capacity_tier') is not None:
            quote['capacityTier'] = self.parameters['capacity_tier']

        if self.parameters.get('provider_volume_type') is None:
            quote['providerVolumeType'] = vol_dest_quote['providerVolumeType']
        else:
            quote['providerVolumeType'] = self.parameters['provider_volume_type']

        return quote

    def delete_snapmirror(self, sm_detail):
        api_delete = '/occm/api/replication/%s/%s/%s' %\
                     (sm_detail['destination_working_environment_id'], sm_detail['destination_svm_name'], self.parameters['destination_volume_name'])
        dummy, err, dummy_second = self.rest_api.send_request("DELETE", api_delete, None, None, header=self.headers)
        if err is not None:
            self.module.fail_json(changed=False, msg='Error deleting snapmirror relationship %s: %s.' % (err, dummy))

    def get_interclusterlifs(self, source_we_id, dest_we_id):
        api_get = '/occm/api/replication/intercluster-lifs?peerWorkingEnvironmentId=%s&workingEnvironmentId=%s' % (dest_we_id, source_we_id)
        response, err, dummy_second = self.rest_api.send_request("GET", api_get, None, header=self.headers)
        if err is not None:
            self.module.fail_json(changed=False, msg='Error getting interclusterlifs %s: %s.' % (err, response))
        return response

    def apply(self):
        current = self.get_snapmirror()
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                self.create_snapmirror()
            elif cd_action == 'delete':
                self.delete_snapmirror(current)
        self.module.exit_json(changed=self.na_helper.changed)


def main():
    '''Main Function'''
    volume = NetAppCloudmanagerSnapmirror()
    volume.apply()


if __name__ == '__main__':
    main()
