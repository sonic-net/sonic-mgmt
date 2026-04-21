#!/usr/bin/python

# (c) 2022, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

'''
na_cloudmanager_cvo_azure
'''

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''

module: na_cloudmanager_cvo_azure
short_description: NetApp Cloud Manager CVO/working environment in single or HA mode for Azure.
extends_documentation_fragment:
    - netapp.cloudmanager.netapp.cloudmanager
version_added: '21.4.0'
author: NetApp Ansible Team (@carchi8py) <ng-ansibleteam@netapp.com>

description:
- Create, delete, or manage Cloud Manager CVO/working environment in single or HA mode for Azure.

options:

  state:
    description:
    - Whether the specified Cloud Manager CVO for AZURE should exist or not.
    choices: ['present', 'absent']
    default: 'present'
    type: str

  name:
    required: true
    description:
    - The name of the Cloud Manager CVO for AZURE to manage.
    type: str

  subscription_id:
    required: true
    description:
    - The ID of the Azure subscription.
    type: str

  instance_type:
    description:
    - The type of instance to use, which depends on the license type you chose.
    - Explore ['Standard_DS3_v2'].
    - Standard ['Standard_DS4_v2, Standard_DS13_v2, Standard_L8s_v2'].
    - Premium ['Standard_DS5_v2', 'Standard_DS14_v2'].
    - For more supported instance types, refer to Cloud Volumes ONTAP Release Notes.
    type: str
    default: Standard_DS4_v2

  license_type:
    description:
    - The type of license to use.
    - For single node by Capacity ['capacity-paygo'].
    - For single node by Node paygo ['azure-cot-explore-paygo', 'azure-cot-standard-paygo', 'azure-cot-premium-paygo'].
    - For single node by Node byol ['azure-cot-premium-byol'].
    - For HA by Capacity ['ha-capacity-paygo'].
    - For HA by Node paygo ['azure-ha-cot-standard-paygo', 'azure-ha-cot-premium-paygo'].
    - For HA by Node byol ['azure-ha-cot-premium-byol'].
    choices: ['azure-cot-standard-paygo', 'azure-cot-premium-paygo', 'azure-cot-premium-byol', \
     'azure-cot-explore-paygo', 'azure-ha-cot-standard-paygo', 'azure-ha-cot-premium-paygo', \
     'azure-ha-cot-premium-byol', 'capacity-paygo', 'ha-capacity-paygo']
    default: 'capacity-paygo'
    type: str

  provided_license:
    description:
    - Using a NLF license file for BYOL deployment.
    type: str

  capacity_package_name:
    description:
    - Capacity package name is required when selecting a capacity based license.
    - Essential only available with Bring Your Own License Capacity-Based.
    - Professional available as an annual contract from a cloud provider or Bring Your Own License Capacity-Based.
    choices: ['Professional', 'Essential', 'Freemium']
    default: 'Essential'
    type: str
    version_added: 21.12.0

  workspace_id:
    description:
    - The ID of the Cloud Manager workspace where you want to deploy Cloud Volumes ONTAP.
    - If not provided, Cloud Manager uses the first workspace.
    - You can find the ID from the Workspace tab on [https://cloudmanager.netapp.com].
    type: str

  subnet_id:
    required: true
    description:
    - The name of the subnet for the Cloud Volumes ONTAP system.
    type: str

  vnet_id:
    required: true
    description:
    - The name of the virtual network.
    type: str

  vnet_resource_group:
    description:
    - The resource group in Azure associated to the virtual network.
    type: str

  resource_group:
    description:
    - The resource_group where Cloud Volumes ONTAP will be created.
    - If not provided, Cloud Manager generates the resource group name (name of the working environment/CVO with suffix '-rg').
    - If the resource group does not exist, it is created.
    type: str

  allow_deploy_in_existing_rg:
    description:
    - Indicates if to allow creation in existing resource group.
    type: bool
    default: false

  cidr:
    required: true
    description:
    - The CIDR of the VNET. If not provided, resource needs az login to authorize and fetch the cidr details from Azure.
    type: str

  location:
    required: true
    description:
    - The location where the working environment will be created.
    type: str

  data_encryption_type:
    description:
    - The type of encryption to use for the working environment.
    choices: ['AZURE', 'NONE']
    default: 'AZURE'
    type: str

  azure_encryption_parameters:
    description:
    - AZURE encryption parameters. It is required if using AZURE encryption.
    type: str
    version_added: 21.10.0

  storage_type:
    description:
    - The type of storage for the first data aggregate.
    choices: ['Premium_LRS', 'Standard_LRS', 'StandardSSD_LRS', 'Premium_ZRS']
    default: 'Premium_LRS'
    type: str

  client_id:
    required: true
    description:
    - The connector ID of the Cloud Manager Connector.
    - You can find the ID from the Connector tab on [https://cloudmanager.netapp.com].
    type: str

  disk_size:
    description:
    - Azure volume size for the first data aggregate.
    - For GB, the value can be [100, 500].
    - For TB, the value can be [1,2,4,8,16].
    default: 1
    type: int

  disk_size_unit:
    description:
    - The unit for disk size.
    choices: ['GB', 'TB']
    default: 'TB'
    type: str

  security_group_id:
    description:
    - The ID of the security group for the working environment. If not provided, Cloud Manager creates the security group.
    type: str

  svm_password:
    required: true
    description:
    - The admin password for Cloud Volumes ONTAP.
    - It will be updated on each run.
    type: str

  svm_name:
    description:
      - The name of the SVM.
    type: str
    version_added: 21.22.0

  ontap_version:
    description:
    - The required ONTAP version. Ignored if 'use_latest_version' is set to true.
    type: str
    default: 'latest'

  use_latest_version:
    description:
    - Indicates whether to use the latest available ONTAP version.
    type: bool
    default: true

  serial_number:
    description:
    - The serial number for the cluster.
    - Required when using one of these, 'azure-cot-premium-byol' or 'azure-ha-cot-premium-byol'.
    type: str

  tier_level:
    description:
    - If capacity_tier is Blob, this argument indicates the tiering level.
    choices: ['normal', 'cool']
    default: 'normal'
    type: str

  nss_account:
    description:
    - The NetApp Support Site account ID to use with this Cloud Volumes ONTAP system.
    - If the license type is BYOL and an NSS account isn't provided, Cloud Manager tries to use the first existing NSS account.
    type: str

  writing_speed_state:
    description:
    - The write speed setting for Cloud Volumes ONTAP ['NORMAL','HIGH'].
    - This argument is not relevant for HA pairs.
    type: str

  capacity_tier:
    description:
    - Whether to enable data tiering for the first data aggregate.
    choices: ['Blob', 'NONE']
    default: 'Blob'
    type: str

  cloud_provider_account:
    description:
    - The cloud provider credentials id to use when deploying the Cloud Volumes ONTAP system.
    - You can find the ID in Cloud Manager from the Settings > Credentials page.
    - If not specified, Cloud Manager uses the instance profile of the Connector.
    type: str

  backup_volumes_to_cbs:
    description:
    - Automatically enable back up of all volumes to S3.
    default: false
    type: bool

  enable_compliance:
    description:
    - Enable the Cloud Compliance service on the working environment.
    default: false
    type: bool

  enable_monitoring:
    description:
    - Enable the Monitoring service on the working environment.
    default: false
    type: bool

  azure_tag:
    description:
    - Additional tags for the AZURE CVO working environment.
    type: list
    elements: dict
    suboptions:
      tag_key:
        description: The key of the tag.
        type: str
      tag_value:
        description: The tag value.
        type: str
  is_ha:
    description:
    - Indicate whether the working environment is an HA pair or not.
    type: bool
    default: false

  platform_serial_number_node1:
    description:
    - For HA BYOL, the serial number for the first node.
    type: str

  platform_serial_number_node2:
    description:
    - For HA BYOL, the serial number for the second node.
    type: str

  ha_enable_https:
    description:
    - For HA, enable the HTTPS connection from CVO to storage accounts. This can impact write performance. The default is false.
    type: bool
    version_added: 21.10.0

  upgrade_ontap_version:
    description:
    - Indicates whether to upgrade ONTAP image on the CVO.
    - If the current version already matches the desired version, no action is taken.
    type: bool
    default: false
    version_added: 21.13.0

  update_svm_password:
    description:
    - Indicates whether to update svm_password on the CVO.
    - When set to true, the module is not idempotent, as we cannot read the current password.
    type: bool
    default: false
    version_added: 21.13.0

  availability_zone:
    description:
    - The availability zone on the location configuration.
    type: int
    version_added: 21.20.0

  availability_zone_node1:
    description:
    - The node1 availability zone on the location configuration for HA.
    type: int
    version_added: 21.21.0

  availability_zone_node2:
    description:
    - The node2 availability zone on the location configuration for HA.
    type: int
    version_added: 21.21.0
'''

EXAMPLES = """
- name: create NetApp Cloud Manager CVO for Azure single
  netapp.cloudmanager.na_cloudmanager_cvo_azure:
    state: present
    refresh_token: "{{ xxxxxxxxxxxxxxx }}"
    name: AnsibleCVO
    location: westus
    subnet_id: subnet-xxxxxxx
    vnet_id: vnetxxxxxxxx
    svm_password: P@assword!
    client_id: "{{ xxxxxxxxxxxxxxx }}"
    writing_speed_state: NORMAL
    azure_tag: [
        {tag_key: abc,
        tag_value: a123}]

- name: create NetApp Cloud Manager CVO for Azure HA
  netapp.cloudmanager.na_cloudmanager_cvo_azure:
    state: present
    refresh_token: "{{ xxxxxxxxxxxxxxx }}"
    name: AnsibleCVO
    location: westus
    subnet_id: subnet-xxxxxxx
    vnet_id: vnetxxxxxxxx
    svm_password: P@assword!
    client_id: "{{ xxxxxxxxxxxxxxx }}"
    writing_speed_state: NORMAL
    azure_tag: [
        {tag_key: abc,
        tag_value: a123}]
    is_ha: true

- name: delete NetApp Cloud Manager cvo for Azure
  netapp.cloudmanager.na_cloudmanager_cvo_azure:
    state: absent
    name: ansible
    refresh_token: "{{ xxxxxxxxxxxxxxx }}"
    location: westus
    subnet_id: subnet-xxxxxxx
    vnet_id: vnetxxxxxxxx
    svm_password: P@assword!
    client_id: "{{ xxxxxxxxxxxxxxx }}"
"""

RETURN = '''
working_environment_id:
  description: Newly created AZURE CVO working_environment_id.
  type: str
  returned: success
'''

from ansible.module_utils.basic import AnsibleModule
import ansible_collections.netapp.cloudmanager.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.cloudmanager.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.cloudmanager.plugins.module_utils.netapp import CloudManagerRestAPI


AZURE_License_Types = ['azure-cot-standard-paygo', 'azure-cot-premium-paygo', 'azure-cot-premium-byol', 'azure-cot-explore-paygo',
                       'azure-ha-cot-standard-paygo', 'azure-ha-cot-premium-paygo', 'azure-ha-cot-premium-byol', 'capacity-paygo', 'ha-capacity-paygo']


class NetAppCloudManagerCVOAZURE:
    """ object initialize and class methods """

    def __init__(self):
        self.use_rest = False
        self.argument_spec = netapp_utils.cloudmanager_host_argument_spec()
        self.argument_spec.update(dict(
            name=dict(required=True, type='str'),
            state=dict(required=False, choices=['present', 'absent'], default='present'),
            instance_type=dict(required=False, type='str', default='Standard_DS4_v2'),
            license_type=dict(required=False, type='str', choices=AZURE_License_Types, default='capacity-paygo'),
            workspace_id=dict(required=False, type='str'),
            capacity_package_name=dict(required=False, type='str', choices=['Professional', 'Essential', 'Freemium'], default='Essential'),
            provided_license=dict(required=False, type='str'),
            subnet_id=dict(required=True, type='str'),
            vnet_id=dict(required=True, type='str'),
            vnet_resource_group=dict(required=False, type='str'),
            resource_group=dict(required=False, type='str'),
            cidr=dict(required=True, type='str'),
            location=dict(required=True, type='str'),
            subscription_id=dict(required=True, type='str'),
            data_encryption_type=dict(required=False, type='str', choices=['AZURE', 'NONE'], default='AZURE'),
            azure_encryption_parameters=dict(required=False, type='str', no_log=True),
            storage_type=dict(required=False, type='str', choices=['Premium_LRS', 'Standard_LRS', 'StandardSSD_LRS', 'Premium_ZRS'], default='Premium_LRS'),
            disk_size=dict(required=False, type='int', default=1),
            disk_size_unit=dict(required=False, type='str', choices=['GB', 'TB'], default='TB'),
            svm_password=dict(required=True, type='str', no_log=True),
            svm_name=dict(required=False, type='str'),
            ontap_version=dict(required=False, type='str', default='latest'),
            use_latest_version=dict(required=False, type='bool', default=True),
            tier_level=dict(required=False, type='str', choices=['normal', 'cool'], default='normal'),
            nss_account=dict(required=False, type='str'),
            writing_speed_state=dict(required=False, type='str'),
            capacity_tier=dict(required=False, type='str', choices=['Blob', 'NONE'], default='Blob'),
            security_group_id=dict(required=False, type='str'),
            cloud_provider_account=dict(required=False, type='str'),
            backup_volumes_to_cbs=dict(required=False, type='bool', default=False),
            enable_compliance=dict(required=False, type='bool', default=False),
            enable_monitoring=dict(required=False, type='bool', default=False),
            allow_deploy_in_existing_rg=dict(required=False, type='bool', default=False),
            client_id=dict(required=True, type='str'),
            azure_tag=dict(required=False, type='list', elements='dict', options=dict(
                tag_key=dict(type='str', no_log=False),
                tag_value=dict(type='str')
            )),
            serial_number=dict(required=False, type='str'),
            is_ha=dict(required=False, type='bool', default=False),
            platform_serial_number_node1=dict(required=False, type='str'),
            platform_serial_number_node2=dict(required=False, type='str'),
            ha_enable_https=dict(required=False, type='bool'),
            upgrade_ontap_version=dict(required=False, type='bool', default=False),
            update_svm_password=dict(required=False, type='bool', default=False),
            availability_zone=dict(required=False, type='int'),
            availability_zone_node1=dict(required=False, type='int'),
            availability_zone_node2=dict(required=False, type='int'),
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            required_one_of=[['refresh_token', 'sa_client_id']],
            required_together=[['sa_client_id', 'sa_secret_key']],
            required_if=[
                ['license_type', 'capacity-paygo', ['capacity_package_name']],
                ['license_type', 'ha-capacity-paygo', ['capacity_package_name']],
                ['license_type', 'azure-cot-premium-byol', ['serial_number']],
                ['license_type', 'azure-ha-cot-premium-byol', ['platform_serial_number_node1', 'platform_serial_number_node2']],
            ],
            supports_check_mode=True
        )

        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)
        self.changeable_params = ['svm_password', 'svm_name', 'azure_tag', 'tier_level', 'ontap_version',
                                  'instance_type', 'license_type', 'writing_speed_state']
        self.rest_api = CloudManagerRestAPI(self.module)
        self.rest_api.url += self.rest_api.environment_data['CLOUD_MANAGER_HOST']
        self.rest_api.api_root_path = '/occm/api/azure/%s' % ('ha' if self.parameters['is_ha'] else 'vsa')
        self.headers = {
            'X-Agent-Id': self.rest_api.format_client_id(self.parameters['client_id'])
        }

    def create_cvo_azure(self):
        """
        Create AZURE CVO
        """
        if self.parameters.get('workspace_id') is None:
            response, msg = self.na_helper.get_tenant(self.rest_api, self.headers)
            if response is None:
                self.module.fail_json(msg)
            self.parameters['workspace_id'] = response

        if self.parameters.get('nss_account') is None:
            if self.parameters.get('serial_number') is not None:
                if not self.parameters['serial_number'].startswith('Eval-') and self.parameters['license_type'] == 'azure-cot-premium-byol':
                    response, msg = self.na_helper.get_nss(self.rest_api, self.headers)
                    if response is None:
                        self.module.fail_json(msg)
                    self.parameters['nss_account'] = response
            elif self.parameters.get('platform_serial_number_node1') is not None and self.parameters.get('platform_serial_number_node2') is not None:
                if not self.parameters['platform_serial_number_node1'].startswith('Eval-')\
                        and not self.parameters['platform_serial_number_node2'].startswith('Eval-')\
                        and self.parameters['license_type'] == 'azure-ha-cot-premium-byol':
                    response, msg = self.na_helper.get_nss(self.rest_api, self.headers)
                    if response is None:
                        self.module.fail_json(msg)
                    self.parameters['nss_account'] = response

        json = {"name": self.parameters['name'],
                "region": self.parameters['location'],
                "subscriptionId": self.parameters['subscription_id'],
                "tenantId": self.parameters['workspace_id'],
                "storageType": self.parameters['storage_type'],
                "dataEncryptionType": self.parameters['data_encryption_type'],
                "optimizedNetworkUtilization": True,
                "diskSize": {
                    "size": self.parameters['disk_size'],
                    "unit": self.parameters['disk_size_unit']},
                "svmPassword": self.parameters['svm_password'],
                "backupVolumesToCbs": self.parameters['backup_volumes_to_cbs'],
                "enableCompliance": self.parameters['enable_compliance'],
                "enableMonitoring": self.parameters['enable_monitoring'],
                "vsaMetadata": {
                    "ontapVersion": self.parameters['ontap_version'],
                    "licenseType": self.parameters['license_type'],
                    "useLatestVersion": self.parameters['use_latest_version'],
                    "instanceType": self.parameters['instance_type']}
                }

        if self.parameters['capacity_tier'] == "Blob":
            json.update({"capacityTier": self.parameters['capacity_tier'],
                         "tierLevel": self.parameters['tier_level']})

        if self.parameters.get('provided_license') is not None:
            json['vsaMetadata'].update({"providedLicense": self.parameters['provided_license']})

        # clean default value if it is not by Capacity license
        if not self.parameters['license_type'].endswith('capacity-paygo'):
            json['vsaMetadata'].update({"capacityPackageName": ''})

        if self.parameters.get('capacity_package_name') is not None:
            json['vsaMetadata'].update({"capacityPackageName": self.parameters['capacity_package_name']})

        if self.parameters.get('cidr') is not None:
            json.update({"cidr": self.parameters['cidr']})

        if self.parameters.get('writing_speed_state') is not None:
            json.update({"writingSpeedState": self.parameters['writing_speed_state'].upper()})

        if self.parameters.get('resource_group') is not None:
            json.update({"resourceGroup": self.parameters['resource_group'],
                         "allowDeployInExistingRg": self.parameters['allow_deploy_in_existing_rg']})
        else:
            json.update({"resourceGroup": (self.parameters['name'] + '-rg')})

        if self.parameters.get('serial_number') is not None:
            json.update({"serialNumber": self.parameters['serial_number']})

        if self.parameters.get('security_group_id') is not None:
            json.update({"securityGroupId": self.parameters['security_group_id']})

        if self.parameters.get('cloud_provider_account') is not None:
            json.update({"cloudProviderAccount": self.parameters['cloud_provider_account']})

        if self.parameters.get('backup_volumes_to_cbs') is not None:
            json.update({"backupVolumesToCbs": self.parameters['backup_volumes_to_cbs']})

        if self.parameters.get('nss_account') is not None:
            json.update({"nssAccount": self.parameters['nss_account']})

        if self.parameters.get('availability_zone') is not None:
            json.update({"availabilityZone": self.parameters['availability_zone']})

        if self.parameters['data_encryption_type'] == "AZURE":
            if self.parameters.get('azure_encryption_parameters') is not None:
                json.update({"azureEncryptionParameters": {"key": self.parameters['azure_encryption_parameters']}})

        if self.parameters.get('svm_name') is not None:
            json.update({"svmName": self.parameters['svm_name']})

        if self.parameters.get('azure_tag') is not None:
            tags = []
            for each_tag in self.parameters['azure_tag']:
                tag = {
                    'tagKey': each_tag['tag_key'],
                    'tagValue': each_tag['tag_value']
                }

                tags.append(tag)
            json.update({"azureTags": tags})

        if self.parameters['is_ha']:
            ha_params = dict()

            if self.parameters.get('platform_serial_number_node1'):
                ha_params["platformSerialNumberNode1"] = self.parameters['platform_serial_number_node1']

            if self.parameters.get('platform_serial_number_node2'):
                ha_params["platformSerialNumberNode2"] = self.parameters['platform_serial_number_node2']

            if self.parameters.get('availability_zone_node1'):
                ha_params["availabilityZoneNode1"] = self.parameters['availability_zone_node1']

            if self.parameters.get('availability_zone_node2'):
                ha_params["availabilityZoneNode2"] = self.parameters['availability_zone_node2']

            if self.parameters.get('ha_enable_https') is not None:
                ha_params['enableHttps'] = self.parameters['ha_enable_https']

            json["haParams"] = ha_params

        resource_group = self.parameters['vnet_resource_group'] if self.parameters.get(
            'vnet_resource_group') is not None else self.parameters['resource_group']

        resource_group_path = 'subscriptions/%s/resourceGroups/%s' % (self.parameters['subscription_id'], resource_group)
        vnet_format = '%s/%s' if self.rest_api.simulator else '/%s/providers/Microsoft.Network/virtualNetworks/%s'
        vnet = vnet_format % (resource_group_path, self.parameters['vnet_id'])
        json.update({"vnetId": vnet})
        json.update({"subnetId": '%s/subnets/%s' % (vnet, self.parameters['subnet_id'])})

        api_url = '%s/working-environments' % self.rest_api.api_root_path
        response, error, on_cloud_request_id = self.rest_api.post(api_url, json, header=self.headers)
        if error is not None:
            self.module.fail_json(
                msg="Error: unexpected response on creating cvo azure: %s, %s" % (str(error), str(response)))
        working_environment_id = response['publicId']
        wait_on_completion_api_url = '/occm/api/audit/activeTask/%s' % str(on_cloud_request_id)
        err = self.rest_api.wait_on_completion(wait_on_completion_api_url, "CVO", "create", 60, 90)

        if err is not None:
            self.module.fail_json(msg="Error: unexpected response wait_on_completion for creating CVO AZURE: %s" % str(err))

        return working_environment_id

    def get_extra_azure_tags(self, rest_api, headers):
        # Get extra azure tag from current working environment
        # It is created automatically not from the user input
        we, err = self.na_helper.get_working_environment_details(rest_api, headers)
        if err is not None:
            self.module.fail_json(msg="Error: unexpected response to get CVO AZURE details: %s" % str(err))
        return [{'tag_key': 'DeployedByOccm', 'tag_value': we['userTags']['DeployedByOccm']}] if 'DeployedByOccm' in \
                                                                                                 we['userTags'] else []

    def update_cvo_azure(self, working_environment_id, modify):
        base_url = '%s/working-environments/%s/' % (self.rest_api.api_root_path, working_environment_id)
        for item in modify:
            if item == 'svm_password':
                response, error = self.na_helper.update_svm_password(base_url, self.rest_api, self.headers, self.parameters['svm_password'])
                if error is not None:
                    self.module.fail_json(changed=False, msg=error)
            if item == 'svm_name':
                response, error = self.na_helper.update_svm_name(base_url, self.rest_api, self.headers, self.parameters['svm_name'])
                if error is not None:
                    self.module.fail_json(changed=False, msg=error)
            if item == 'azure_tag':
                # default azure tag
                tag_list = self.get_extra_azure_tags(self.rest_api, self.headers)
                if 'azure_tag' in self.parameters:
                    tag_list.extend(self.parameters['azure_tag'])
                response, error = self.na_helper.update_cvo_tags(base_url, self.rest_api, self.headers, 'azure_tag', tag_list)
                if error is not None:
                    self.module.fail_json(changed=False, msg=error)
            if item == 'tier_level':
                response, error = self.na_helper.update_tier_level(base_url, self.rest_api, self.headers, self.parameters['tier_level'])
                if error is not None:
                    self.module.fail_json(changed=False, msg=error)
            if item == 'writing_speed_state':
                response, error = self.na_helper.update_writing_speed_state(base_url, self.rest_api, self.headers, self.parameters['writing_speed_state'])
                if error is not None:
                    self.module.fail_json(changed=False, msg=error)
            if item == 'ontap_version':
                response, error = self.na_helper.upgrade_ontap_image(self.rest_api, self.headers, self.parameters['ontap_version'])
                if error is not None:
                    self.module.fail_json(changed=False, msg=error)
            if item == 'instance_type' or item == 'license_type':
                response, error = self.na_helper.update_instance_license_type(base_url, self.rest_api, self.headers,
                                                                              self.parameters['instance_type'],
                                                                              self.parameters['license_type'])
                if error is not None:
                    self.module.fail_json(changed=False, msg=error)

    def delete_cvo_azure(self, we_id):
        """
        Delete AZURE CVO
        """

        api_url = '%s/working-environments/%s' % (self.rest_api.api_root_path, we_id)
        response, error, on_cloud_request_id = self.rest_api.delete(api_url, None, header=self.headers)
        if error is not None:
            self.module.fail_json(msg="Error: unexpected response on deleting cvo azure: %s, %s" % (str(error), str(response)))

        wait_on_completion_api_url = '/occm/api/audit/activeTask/%s' % str(on_cloud_request_id)
        err = self.rest_api.wait_on_completion(wait_on_completion_api_url, "CVO", "delete", 40, 60)

        if err is not None:
            self.module.fail_json(msg="Error: unexpected response wait_on_completion for deleting CVO AZURE: %s" % str(err))

    def validate_cvo_params(self):
        if self.parameters['use_latest_version'] is True and self.parameters['ontap_version'] != "latest":
            self.module.fail_json(msg="ontap_version parameter not required when having use_latest_version as true")

        if self.parameters.get('serial_number') is None and self.parameters['license_type'] == "azure-cot-premium-byol":
            self.module.fail_json(msg="serial_number parameter required when having license_type as azure-cot-premium-byol")

        if self.parameters['is_ha'] and self.parameters['license_type'] == "azure-ha-cot-premium-byol":
            if self.parameters.get('platform_serial_number_node1') is None or self.parameters.get('platform_serial_number_node2') is None:
                self.module.fail_json(msg="both platform_serial_number_node1 and platform_serial_number_node2 parameters are required"
                                          "when having ha type as true and license_type as azure-ha-cot-premium-byol")
        if self.parameters['is_ha'] is True and self.parameters['license_type'] == 'capacity-paygo':
            self.parameters['license_type'] == 'ha-capacity-paygo'

    def apply(self):
        """
        Apply action to the Cloud Manager CVO for AZURE
        :return: None
        """
        working_environment_id = None
        modify = None
        current, dummy = self.na_helper.get_working_environment_details_by_name(self.rest_api, self.headers,
                                                                                self.parameters['name'], "azure")
        if current:
            self.parameters['working_environment_id'] = current['publicId']
        # check the action whether to create, delete, or not
        cd_action = self.na_helper.get_cd_action(current, self.parameters)

        if current and self.parameters['state'] != 'absent':
            working_environment_id = current['publicId']
            modify, error = self.na_helper.is_cvo_update_needed(self.rest_api, self.headers, self.parameters, self.changeable_params, 'azure')
            if error is not None:
                self.module.fail_json(changed=False, msg=error)

        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == "create":
                self.validate_cvo_params()
                working_environment_id = self.create_cvo_azure()
            elif cd_action == "delete":
                self.delete_cvo_azure(current['publicId'])
            else:
                self.update_cvo_azure(current['publicId'], modify)

        self.module.exit_json(changed=self.na_helper.changed, working_environment_id=working_environment_id)


def main():
    """
    Create Cloud Manager CVO for AZURE class instance and invoke apply
    :return: None
    """
    obj_store = NetAppCloudManagerCVOAZURE()
    obj_store.apply()


if __name__ == '__main__':
    main()
