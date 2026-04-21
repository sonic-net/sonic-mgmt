#!/usr/bin/python

# (c) 2022, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

'''
na_cloudmanager_volume
'''

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = '''

module: na_cloudmanager_volume
short_description: NetApp Cloud Manager volume
extends_documentation_fragment:
    - netapp.cloudmanager.netapp.cloudmanager
version_added: '21.3.0'
author: NetApp Ansible Team (@carchi8py) <ng-ansibleteam@netapp.com>

description:
- Create, Modify or Delete volume on Cloud Manager.

options:
    state:
        description:
        - Whether the specified volume should exist or not.
        choices: ['present', 'absent']
        default: 'present'
        type: str

    name:
        description:
        - The name of the volume.
        required: true
        type: str

    working_environment_name:
        description:
        - The working environment name where the volume will be created.
        type: str

    working_environment_id:
        description:
        - The public ID of the working environment where the volume will be created.
        type: str

    client_id:
        description:
        - The connector ID of the Cloud Manager Connector.
        required: true
        type: str

    size:
        description:
        - The size of the volume.
        type: float

    size_unit:
        description:
        - The size unit of volume.
        choices: ['GB']
        default: 'GB'
        type: str

    snapshot_policy_name:
        description:
        - The snapshot policy name.
        type: str

    provider_volume_type:
        description:
        - The underlying cloud provider volume type.
        - For AWS is ["gp3", "gp2", "io1", "st1", "sc1"].
        - For Azure is ['Premium_LRS','Standard_LRS','StandardSSD_LRS'].
        - For GCP is ['pd-balanced','pd-ssd','pd-standard'].
        type: str

    enable_deduplication:
        description:
        - Enabling deduplication.
        - Default to true if not specified.
        type: bool

    enable_compression:
        description:
        - Enabling cpmpression.
        - Default to true if not specified.
        type: bool

    enable_thin_provisioning:
        description:
        - Enabling thin provisioning.
        - Default to true if not specified.
        type: bool

    svm_name:
        description:
        - The name of the SVM. The default SVM name is used, if a name is not provided.
        type: str

    aggregate_name:
        description:
        - The aggregate in which the volume will be created. If not provided, Cloud Manager chooses the best aggregate.
        type: str

    capacity_tier:
        description:
        - The volume's capacity tier for tiering cold data to object storage.
        - The default values for each cloud provider are as follows. Amazon as 'S3', Azure as 'Blob', GCP as 'cloudStorage'.
        - If 'NONE', the capacity tier will not be set on volume creation.
        choices: ['NONE', 'S3', 'Blob', 'cloudStorage']
        type: str

    tiering_policy:
        description:
        - The tiering policy.
        choices: ['none', 'snapshot_only', 'auto', 'all']
        type: str

    export_policy_type:
        description:
        - The export policy type (NFS protocol parameters).
        type: str

    export_policy_ip:
        description:
        - Custom export policy list of IPs (NFS protocol parameters).
        type: list
        elements: str

    export_policy_nfs_version:
        description:
        - Export policy protocol (NFS protocol parameters).
        type: list
        elements: str

    iops:
        description:
        - Provisioned IOPS. Needed only when provider_volume_type is "io1".
        type: int

    throughput:
        description:
        - Unit is Mb/s. Valid range 125-1000.
        - Required only when provider_volume_type is 'gp3'.
        type: int

    volume_protocol:
        description:
        - The protocol for the volume. This affects the provided parameters.
        choices: ['nfs', 'cifs', 'iscsi']
        type: str
        default: 'nfs'

    share_name:
        description:
        - Share name (CIFS protocol parameters).
        type: str

    permission:
        description:
        - CIFS share permission type (CIFS protocol parameters).
        type: str

    users:
        description:
        - List of users with the permission (CIFS protocol parameters).
        type: list
        elements: str

    igroups:
        description:
        - List of igroups (iSCSI protocol parameters).
        type: list
        elements: str

    os_name:
        description:
        - Operating system (iSCSI protocol parameters).
        type: str

    tenant_id:
        description:
        - The NetApp account ID that the Connector will be associated with. To be used only when using FSx.
        type: str
        version_added: 21.20.0

    initiators:
        description:
        - Set of attributes of Initiators (iSCSI protocol parameters).
        type: list
        elements: dict
        suboptions:
          iqn:
            description: The initiator node name.
            required: true
            type: str
          alias:
            description: The alias which associates with the node.
            required: true
            type: str

notes:
- Support check_mode.
'''

EXAMPLES = '''
- name: Create nfs volume with working_environment_name
  netapp.cloudmanager.na_cloudmanager_volume:
    state: present
    name: test_vol
    size: 15
    size_unit: GB
    working_environment_name: working_environment_1
    client_id: client_id
    refresh_token: refresh_token
    svm_name: svm_1
    snapshot_policy_name: default
    export_policy_type: custom
    export_policy_ip: ["10.0.0.1/16"]
    export_policy_nfs_version: ["nfs3","nfs4"]

- name: Delete volume
  netapp.cloudmanager.na_cloudmanager_volume:
    state: absent
    name: test_vol
    working_environment_name: working_environment_1
    client_id: client_id
    refresh_token: refresh_token
    svm_name: svm_1
'''

RETURN = r''' # '''

from ansible.module_utils.basic import AnsibleModule
import ansible_collections.netapp.cloudmanager.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.cloudmanager.plugins.module_utils.netapp_module import NetAppModule


class NetAppCloudmanagerVolume(object):

    def __init__(self):
        """
        Parse arguments, setup state variables,
        check parameters and ensure request module is installed
        """
        self.argument_spec = netapp_utils.cloudmanager_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, choices=['present', 'absent'], default='present'),
            name=dict(required=True, type='str'),
            working_environment_id=dict(required=False, type='str'),
            working_environment_name=dict(required=False, type='str'),
            client_id=dict(required=True, type='str'),
            size=dict(required=False, type='float'),
            size_unit=dict(required=False, choices=['GB'], default='GB'),
            snapshot_policy_name=dict(required=False, type='str'),
            provider_volume_type=dict(required=False, type='str'),
            enable_deduplication=dict(required=False, type='bool'),
            enable_thin_provisioning=dict(required=False, type='bool'),
            enable_compression=dict(required=False, type='bool'),
            svm_name=dict(required=False, type='str'),
            aggregate_name=dict(required=False, type='str'),
            capacity_tier=dict(required=False, type='str', choices=['NONE', 'S3', 'Blob', 'cloudStorage']),
            tiering_policy=dict(required=False, type='str', choices=['none', 'snapshot_only', 'auto', 'all']),
            export_policy_type=dict(required=False, type='str'),
            export_policy_ip=dict(required=False, type='list', elements='str'),
            export_policy_nfs_version=dict(required=False, type='list', elements='str'),
            iops=dict(required=False, type='int'),
            throughput=dict(required=False, type='int'),
            volume_protocol=dict(required=False, type='str', choices=['nfs', 'cifs', 'iscsi'], default='nfs'),
            share_name=dict(required=False, type='str'),
            permission=dict(required=False, type='str'),
            users=dict(required=False, type='list', elements='str'),
            igroups=dict(required=False, type='list', elements='str'),
            os_name=dict(required=False, type='str'),
            tenant_id=dict(required=False, type='str'),
            initiators=dict(required=False, type='list', elements='dict', options=dict(
                alias=dict(required=True, type='str'),
                iqn=dict(required=True, type='str'),)),

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
                ['capacity_tier', 'S3', ['tiering_policy']],
            ],
            # enable_thin_provisioning reflects storage efficiency.
            required_by={
                'capacity_tier': ('tiering_policy', 'enable_thin_provisioning'),
            },
            supports_check_mode=True
        )
        self.na_helper = NetAppModule()
        # set up state variables
        self.parameters = self.na_helper.set_parameters(self.module.params)
        # Calling generic rest_api class
        self.rest_api = netapp_utils.CloudManagerRestAPI(self.module)
        self.rest_api.token_type, self.rest_api.token = self.rest_api.get_token()
        self.rest_api.url += self.rest_api.environment_data['CLOUD_MANAGER_HOST']
        self.headers = {
            'X-Agent-Id': self.rest_api.format_client_id(self.parameters['client_id'])
        }
        if self.rest_api.simulator:
            self.headers.update({'x-simulator': 'true'})
        if self.parameters.get('tenant_id'):
            working_environment_detail, error = self.na_helper.get_aws_fsx_details(self.rest_api, self.headers, self.parameters['working_environment_name'])
        elif self.parameters.get('working_environment_id'):
            working_environment_detail, error = self.na_helper.get_working_environment_details(self.rest_api, self.headers)
        else:
            working_environment_detail, error = self.na_helper.get_working_environment_details_by_name(self.rest_api,
                                                                                                       self.headers,
                                                                                                       self.parameters['working_environment_name'])
        if working_environment_detail is None:
            self.module.fail_json(msg="Error: Cannot find working environment, if it is an AWS FSxN, please provide tenant_id: %s" % str(error))
        self.parameters['working_environment_id'] = working_environment_detail['publicId']\
            if working_environment_detail.get('publicId') else working_environment_detail['id']
        self.na_helper.set_api_root_path(working_environment_detail, self.rest_api)
        self.is_fsx = self.parameters['working_environment_id'].startswith('fs-')

        if self.parameters.get('svm_name') is None:
            fsx_path = ''
            if self.is_fsx:
                fsx_path = '/svms'
            response, err, dummy = self.rest_api.send_request("GET", "%s/working-environments/%s%s" % (
                self.rest_api.api_root_path, self.parameters['working_environment_id'], fsx_path), None, None, header=self.headers)
            if err is not None:
                self.module.fail_json(changed=False, msg="Error: unexpected response on getting svm: %s, %s" % (str(err), str(response)))
            if self.is_fsx:
                self.parameters['svm_name'] = response[0]['name']
            else:
                self.parameters['svm_name'] = response['svmName']

        if self.parameters['volume_protocol'] == 'nfs':
            extra_options = []
            for option in ['share_name', 'permission', 'users', 'igroups', 'os_name', 'initiator']:
                if self.parameters.get(option) is not None:
                    extra_options.append(option)
            if len(extra_options) > 0:
                self.module.fail_json(msg="Error: The following options are not allowed when volume_protocol is nfs: "
                                          " %s" % extra_options)
        elif self.parameters['volume_protocol'] == 'cifs':
            extra_options = []
            for option in ['export_policy_type', 'export_policy_ip', 'export_policy_nfs_version', 'igroups', 'os_name', 'initiator']:
                if self.parameters.get(option) is not None:
                    extra_options.append(option)
            if len(extra_options) > 0:
                self.module.fail_json(msg="Error: The following options are not allowed when volume_protocol is cifs: "
                                          "%s" % extra_options)
        else:
            extra_options = []
            for option in ['export_policy_type', 'export_policy_ip', 'export_policy_nfs_version', 'share_name', 'permission', 'users']:
                if self.parameters.get(option) is not None:
                    extra_options.append(option)
            if len(extra_options) > 0:
                self.module.fail_json(msg="Error: The following options are not allowed when volume_protocol is iscsi: "
                                          "%s" % extra_options)

        if self.parameters.get('igroups'):
            current_igroups = []
            for igroup in self.parameters['igroups']:
                current = self.get_igroup(igroup)
                current_igroups.append(current)
            if any(isinstance(x, dict) for x in current_igroups) and None in current_igroups:
                self.module.fail_json(changed=False, msg="Error: can not specify existing"
                                                         "igroup and new igroup together.")
            if len(current_igroups) > 1 and None in current_igroups:
                self.module.fail_json(changed=False, msg="Error: can not create more than one igroups.")
            if current_igroups[0] is None:
                if self.parameters.get('initiators') is None:
                    self.module.fail_json(changed=False, msg="Error: initiator is required when creating new igroup.")

        if self.parameters.get('users'):
            # When creating volume, 'Everyone' must have upper case E, 'everyone' will not work.
            # When modifying volume, 'everyone' is fine.
            new_users = []
            for user in self.parameters['users']:
                if user.lower() == 'everyone':
                    new_users.append('Everyone')
                else:
                    new_users.append(user)
            self.parameters['users'] = new_users

    def get_volume(self):
        if self.is_fsx:
            query_param = 'fileSystemId'
        else:
            query_param = 'workingEnvironmentId'
        response, err, dummy = self.rest_api.send_request("GET", "%s/volumes?%s=%s" % (
            self.rest_api.api_root_path, query_param, self.parameters['working_environment_id']), None, header=self.headers)
        if err is not None:
            self.module.fail_json(changed=False, msg="Error: unexpected response on getting volume: %s, %s" % (str(err), str(response)))
        target_vol = dict()
        if response is None:
            return None
        for volume in response:
            if volume['name'] == self.parameters['name']:
                target_vol['name'] = volume['name']
                target_vol['enable_deduplication'] = volume['deduplication']
                target_vol['enable_thin_provisioning'] = volume['thinProvisioning']
                target_vol['enable_compression'] = volume['compression']
                if self.parameters.get('size'):
                    target_vol['size'] = volume['size']['size']
                if self.parameters.get('size_unit'):
                    target_vol['size_unit'] = volume['size']['unit']
                if self.parameters.get('export_policy_nfs_version') and volume.get('exportPolicyInfo'):
                    target_vol['export_policy_nfs_version'] = volume['exportPolicyInfo']['nfsVersion']
                if self.parameters.get('export_policy_ip') and volume.get('exportPolicyInfo'):
                    target_vol['export_policy_ip'] = volume['exportPolicyInfo']['ips']
                if self.parameters.get('export_policy_type') and volume.get('exportPolicyInfo'):
                    target_vol['export_policy_type'] = volume['exportPolicyInfo']['policyType']
                if self.parameters.get('snapshot_policy'):
                    target_vol['snapshot_policy'] = volume['snapshotPolicy']
                if self.parameters.get('provider_volume_type'):
                    target_vol['provider_volume_type'] = volume['providerVolumeType']
                if self.parameters.get('capacity_tier') and self.parameters.get('capacity_tier') != 'NONE':
                    target_vol['capacity_tier'] = volume['capacityTier']
                if self.parameters.get('tiering_policy'):
                    target_vol['tiering_policy'] = volume['tieringPolicy']
                if self.parameters.get('share_name') and volume.get('shareInfo'):
                    target_vol['share_name'] = volume['shareInfo'][0]['shareName']
                if self.parameters.get('users') and volume.get('shareInfo'):
                    if len(volume['shareInfo'][0]['accessControlList']) > 0:
                        target_vol['users'] = volume['shareInfo'][0]['accessControlList'][0]['users']
                    else:
                        target_vol['users'] = []
                if self.parameters.get('users') and volume.get('shareInfo'):
                    if len(volume['shareInfo'][0]['accessControlList']) > 0:
                        target_vol['permission'] = volume['shareInfo'][0]['accessControlList'][0]['permission']
                    else:
                        target_vol['permission'] = []
                if self.parameters.get('os_name') and volume.get('iscsiInfo'):
                    target_vol['os_name'] = volume['iscsiInfo']['osName']
                if self.parameters.get('igroups') and volume.get('iscsiInfo'):
                    target_vol['igroups'] = volume['iscsiInfo']['igroups']
                return target_vol
        return None

    def create_volume(self):
        exclude_list = ['client_id', 'size_unit', 'export_policy_name', 'export_policy_type', 'export_policy_ip',
                        'export_policy_nfs_version', 'capacity_tier']
        quote = self.na_helper.convert_module_args_to_api(self.parameters, exclude_list)
        quote['verifyNameUniqueness'] = True  # Always hard coded to true.
        quote['unit'] = self.parameters['size_unit']
        quote['size'] = {'size': self.parameters['size'], 'unit': self.parameters['size_unit']}
        create_aggregate_if_not_exists = True
        if self.parameters.get('aggregate_name'):
            quote['aggregateName'] = self.parameters['aggregate_name']
            create_aggregate_if_not_exists = False

        if self.parameters.get('capacity_tier') and self.parameters['capacity_tier'] != "NONE":
            quote['capacityTier'] = self.parameters['capacity_tier']

        if self.parameters['volume_protocol'] == 'nfs':
            quote['exportPolicyInfo'] = dict()
            if self.parameters.get('export_policy_type'):
                quote['exportPolicyInfo']['policyType'] = self.parameters['export_policy_type']
            if self.parameters.get('export_policy_ip'):
                quote['exportPolicyInfo']['ips'] = self.parameters['export_policy_ip']
            if self.parameters.get('export_policy_nfs_version'):
                quote['exportPolicyInfo']['nfsVersion'] = self.parameters['export_policy_nfs_version']
        elif self.parameters['volume_protocol'] == 'iscsi':
            iscsi_info = self.iscsi_volume_helper()
            quote.update(iscsi_info)
        else:
            quote['shareInfo'] = dict()
            quote['shareInfo']['accessControl'] = dict()
            quote['shareInfo']['accessControl']['users'] = self.parameters['users']
            if self.parameters.get('permission'):
                quote['shareInfo']['accessControl']['permission'] = self.parameters['permission']
            if self.parameters.get('share_name'):
                quote['shareInfo']['shareName'] = self.parameters['share_name']
        if not self.is_fsx:
            response, err, dummy = self.rest_api.send_request("POST", "%s/volumes/quote" % self.rest_api.api_root_path,
                                                              None, quote, header=self.headers)
            if err is not None:
                self.module.fail_json(changed=False, msg="Error: unexpected response on quoting volume: %s, %s" % (str(err), str(response)))
            quote['newAggregate'] = response['newAggregate']
            quote['aggregateName'] = response['aggregateName']
            quote['maxNumOfDisksApprovedToAdd'] = response['numOfDisks']
        else:
            quote['fileSystemId'] = self.parameters['working_environment_id']
        if self.parameters.get('enable_deduplication'):
            quote['deduplication'] = self.parameters.get('enable_deduplication')
        if self.parameters.get('enable_thin_provisioning'):
            quote['thinProvisioning'] = self.parameters.get('enable_thin_provisioning')
        if self.parameters.get('enable_compression'):
            quote['compression'] = self.parameters.get('enable_compression')
        if self.parameters.get('snapshot_policy_name'):
            quote['snapshotPolicy'] = self.parameters['snapshot_policy_name']
        if self.parameters.get('capacity_tier') and self.parameters['capacity_tier'] != "NONE":
            quote['capacityTier'] = self.parameters['capacity_tier']
        if self.parameters.get('tiering_policy'):
            quote['tieringPolicy'] = self.parameters['tiering_policy']
        if self.parameters.get('provider_volume_type'):
            quote['providerVolumeType'] = self.parameters['provider_volume_type']
        if self.parameters.get('iops'):
            quote['iops'] = self.parameters.get('iops')
        if self.parameters.get('throughput'):
            quote['throughput'] = self.parameters.get('throughput')
        response, err, on_cloud_request_id = self.rest_api.send_request("POST", "%s/volumes?createAggregateIfNotFound=%s" % (
            self.rest_api.api_root_path, create_aggregate_if_not_exists), None, quote, header=self.headers)
        if err is not None:
            self.module.fail_json(changed=False, msg="Error: unexpected on creating volume: %s, %s" % (str(err), str(response)))
        wait_on_completion_api_url = '/occm/api/audit/activeTask/%s' % (str(on_cloud_request_id))
        err = self.rest_api.wait_on_completion(wait_on_completion_api_url, "volume", "create", 20, 5)
        if err is not None:
            self.module.fail_json(changed=False, msg="Error: unexpected response wait_on_completion for creating volume: %s, %s" % (str(err), str(response)))

    def modify_volume(self, modify):
        vol = dict()
        if self.parameters['volume_protocol'] == 'nfs':
            export_policy_info = dict()
            if self.parameters.get('export_policy_type'):
                export_policy_info['policyType'] = self.parameters['export_policy_type']
            if self.parameters.get('export_policy_ip'):
                export_policy_info['ips'] = self.parameters['export_policy_ip']
            if self.parameters.get('export_policy_nfs_version'):
                export_policy_info['nfsVersion'] = self.parameters['export_policy_nfs_version']
            vol['exportPolicyInfo'] = export_policy_info
        elif self.parameters['volume_protocol'] == 'cifs':
            vol['shareInfo'] = dict()
            vol['shareInfo']['accessControlList'] = []
            vol['shareInfo']['accessControlList'].append(dict())
            if self.parameters.get('users'):
                vol['shareInfo']['accessControlList'][0]['users'] = self.parameters['users']
            if self.parameters.get('permission'):
                vol['shareInfo']['accessControlList'][0]['permission'] = self.parameters['permission']
            if self.parameters.get('share_name'):
                vol['shareInfo']['shareName'] = self.parameters['share_name']
        if modify.get('snapshot_policy_name'):
            vol['snapshotPolicyName'] = self.parameters.get('snapshot_policy_name')
        if modify.get('tiering_policy'):
            vol['tieringPolicy'] = self.parameters.get('tiering_policy')
        response, err, dummy = self.rest_api.send_request("PUT", "%s/volumes/%s/%s/%s" % (
            self.rest_api.api_root_path, self.parameters['working_environment_id'], self.parameters['svm_name'],
            self.parameters['name']), None, vol, header=self.headers)
        if err is not None:
            self.module.fail_json(changed=False, msg="Error: unexpected response on modifying volume: %s, %s" % (str(err), str(response)))

    def delete_volume(self):
        response, err, dummy = self.rest_api.send_request("DELETE", "%s/volumes/%s/%s/%s" % (
            self.rest_api.api_root_path, self.parameters['working_environment_id'], self.parameters['svm_name'],
            self.parameters['name']), None, None, header=self.headers)
        if err is not None:
            self.module.fail_json(changed=False, msg="Error: unexpected response on deleting volume: %s, %s" % (str(err), str(response)))

    def get_initiator(self, alias_name):
        response, err, dummy = self.rest_api.send_request("GET", "%s/volumes/initiator" % (
            self.rest_api.api_root_path), None, header=self.headers)
        if err is not None:
            self.module.fail_json(changed=False, msg="Error: unexpected response on getting initiator: %s, %s" % (str(err), str(response)))
        result = dict()
        if response is None:
            return None
        for initiator in response:
            if initiator.get('aliasName') and initiator.get('aliasName') == alias_name:
                result['alias'] = initiator.get('aliasName')
                result['iqn'] = initiator.get('iqn')
                return result
        return None

    def create_initiator(self, initiator):
        ini = self.na_helper.convert_module_args_to_api(initiator)
        response, err, dummy = self.rest_api.send_request("POST", "%s/volumes/initiator" % (
            self.rest_api.api_root_path), None, ini, header=self.headers)
        if err is not None:
            self.module.fail_json(changed=False, msg="Error: unexpected response on creating initiator: %s, %s" % (str(err), str(response)))

    def get_igroup(self, igroup_name):
        response, err, dummy = self.rest_api.send_request("GET", "%s/volumes/igroups/%s/%s" % (
            self.rest_api.api_root_path, self.parameters['working_environment_id'], self.parameters['svm_name']),
            None, None, header=self.headers)
        if err is not None:
            self.module.fail_json(changed=False, msg="Error: unexpected response on getting igroup: %s, %s" % (str(err), str(response)))
        result = dict()
        if response is None:
            return None
        for igroup in response:
            if igroup['igroupName'] == igroup_name:
                result['igroup_name'] = igroup['igroupName']
                result['os_type'] = igroup['osType']
                result['portset_name'] = igroup['portsetName']
                result['igroup_type'] = igroup['igroupType']
                result['initiators'] = igroup['initiators']
                return result
        return None

    def iscsi_volume_helper(self):
        quote = dict()
        quote['iscsiInfo'] = dict()
        if self.parameters.get('igroups'):
            current_igroups = []
            for igroup in self.parameters['igroups']:
                current = self.get_igroup(igroup)
                current_igroups.append(current)
            for igroup in current_igroups:
                if igroup is None:
                    quote['iscsiInfo']['igroupCreationRequest'] = dict()
                    quote['iscsiInfo']['igroupCreationRequest']['igroupName'] = self.parameters['igroups'][0]
                    iqn_list = []
                    for initiator in self.parameters['initiators']:
                        if initiator.get('iqn'):
                            iqn_list.append(initiator['iqn'])
                            current_initiator = self.get_initiator(initiator['alias'])
                            if current_initiator is None:
                                initiator_request = dict()
                                if initiator.get('alias'):
                                    initiator_request['aliasName'] = initiator['alias']
                                if initiator.get('iqn'):
                                    initiator_request['iqn'] = initiator['iqn']
                                self.create_initiator(initiator_request)
                        quote['iscsiInfo']['igroupCreationRequest']['initiators'] = iqn_list
                        quote['iscsiInfo']['osName'] = self.parameters['os_name']

                else:
                    quote['iscsiInfo']['igroups'] = self.parameters['igroups']
                    quote['iscsiInfo']['osName'] = self.parameters['os_name']
        return quote

    def apply(self):
        current = self.get_volume()
        cd_action, modify = None, None
        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if cd_action is None:
            modify = self.na_helper.get_modified_attributes(current, self.parameters)
            unmodifiable = []
            for attr in modify:
                if attr not in ['export_policy_ip', 'export_policy_nfs_version', 'snapshot_policy_name', 'users',
                                'permission', 'tiering_policy', 'snapshot_policy_name']:
                    unmodifiable.append(attr)
            if len(unmodifiable) > 0:
                self.module.fail_json(changed=False, msg="%s cannot be modified." % str(unmodifiable))
        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                self.create_volume()
            elif cd_action == 'delete':
                self.delete_volume()
            elif modify:
                self.modify_volume(modify)
        self.module.exit_json(changed=self.na_helper.changed)


def main():
    '''Main Function'''
    volume = NetAppCloudmanagerVolume()
    volume.apply()


if __name__ == '__main__':
    main()
