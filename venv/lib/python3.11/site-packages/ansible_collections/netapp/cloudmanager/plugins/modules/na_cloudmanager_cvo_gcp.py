#!/usr/bin/python

# (c) 2022, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

'''
na_cloudmanager_cvo_gcp
'''

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''

module: na_cloudmanager_cvo_gcp
short_description: NetApp Cloud Manager CVO for GCP
extends_documentation_fragment:
    - netapp.cloudmanager.netapp.cloudmanager
version_added: '21.4.0'
author: NetApp Ansible Team (@carchi8py) <ng-ansibleteam@netapp.com>

description:
  - Create, delete, or manage Cloud Manager CVO for GCP.

options:

  backup_volumes_to_cbs:
    description:
      - Automatically backup all volumes to cloud.
    default: false
    type: bool

  capacity_tier:
    description:
      - Whether to enable data tiering for the first data aggregate.
    choices: ['cloudStorage']
    type: str

  client_id:
    required: true
    description:
      - The connector ID of the Cloud Manager Connector.
      - You can find the ID from the Connector tab on U(https://cloudmanager.netapp.com).
    type: str

  data_encryption_type:
    description:
      - Type of encryption to use for this working environment.
    choices: ['GCP']
    type: str

  gcp_encryption_parameters:
    description:
      - The GCP encryption parameters.
    type: str
    version_added: 21.10.0

  enable_compliance:
    description:
      - Enable the Cloud Compliance service on the working environment.
    default: false
    type: bool

  firewall_rule:
    description:
      - Firewall name for a single node cluster.
    type: str

  gcp_labels:
    description:
      - Optionally provide up to four key-value pairs with which to all GCP entities created by Cloud Manager.
    type: list
    elements: dict
    suboptions:
      label_key:
        description: The key of the label.
        type: str
      label_value:
        description: The label value.
        type: str

  gcp_service_account:
    description:
      - The gcp_service_account email in order to enable tiering of cold data to Google Cloud Storage.
    required: true
    type: str

  gcp_volume_size:
    description:
      - GCP volume size.
    type: int

  gcp_volume_size_unit:
    description:
      - GCP volume size unit.
    choices: ['GB', 'TB']
    type: str

  gcp_volume_type:
    description:
      - GCP volume type.
    choices: ['pd-balanced', 'pd-standard', 'pd-ssd']
    type: str

  instance_type:
    description:
      - The type of instance to use, which depends on the license type you choose.
      - Explore ['custom-4-16384'].
      - Standard ['n1-standard-8'].
      - Premium ['n1-standard-32'].
      - BYOL all instance types defined for PayGo.
      - For more supported instance types, refer to Cloud Volumes ONTAP Release Notes.
    default: 'n1-standard-8'
    type: str

  is_ha:
    description:
      - Indicate whether the working environment is an HA pair or not.
    type: bool
    default: false

  license_type:
    description:
      - The type of license to use.
      - For single node by Capacity ['capacity-paygo'].
      - For single node by Node paygo ['gcp-cot-explore-paygo', 'gcp-cot-standard-paygo', 'gcp-cot-premium-paygo'].
      - For single node by Node byol ['gcp-cot-premium-byol'].
      - For HA by Capacity ['ha-capacity-paygo'].
      - For HA by Node paygo ['gcp-ha-cot-explore-paygo', 'gcp-ha-cot-standard-paygo', 'gcp-ha-cot-premium-paygo'].
      - For HA by Node byol ['gcp-cot-premium-byol'].
    choices: ['gcp-cot-standard-paygo', 'gcp-cot-explore-paygo', 'gcp-cot-premium-paygo', 'gcp-cot-premium-byol', \
     'gcp-ha-cot-standard-paygo', 'gcp-ha-cot-premium-paygo', 'gcp-ha-cot-explore-paygo', 'gcp-ha-cot-premium-byol', \
     'capacity-paygo', 'ha-capacity-paygo']
    type: str
    default: 'capacity-paygo'

  provided_license:
    description:
      - Using a NLF license file for BYOL deployment
    type: str

  capacity_package_name:
    description:
      - Capacity package name is required when selecting a capacity based license.
    choices: ['Professional', 'Essential', 'Freemium']
    default: 'Essential'
    type: str
    version_added: 21.12.0

  mediator_zone:
    description:
      - The zone for mediator.
      - Option for HA pair only.
    type: str

  name:
    description:
      - The name of the Cloud Manager CVO for GCP to manage.
    required: true
    type: str

  network_project_id:
    description:
      - The project id in GCP associated with the Subnet.
      - If not provided, it is assumed that the Subnet is within the previously specified project id.
    type: str

  node1_zone:
    description:
      - Zone for node 1.
      - Option for HA pair only.
    type: str

  node2_zone:
    description:
      - Zone for node 2.
      - Option for HA pair only.
    type: str

  nss_account:
    description:
      - The NetApp Support Site account ID to use with this Cloud Volumes ONTAP system.
      - If the license type is BYOL and an NSS account isn't provided, Cloud Manager tries to use the first existing NSS account.
    type: str

  ontap_version:
    description:
      - The required ONTAP version. Ignored if 'use_latest_version' is set to true.
    type: str
    default: 'latest'

  platform_serial_number_node1:
    description:
      - For HA BYOL, the serial number for the first node.
      - Option for HA pair only.
    type: str

  platform_serial_number_node2:
    description:
      - For HA BYOL, the serial number for the second node.
      - Option for HA pair only.
    type: str

  project_id:
    description:
      - The ID of the GCP project.
    required: true
    type: str

  platform_serial_number:
    description:
      - The serial number for the system. Required when using 'gcp-cot-premium-byol'.
    type: str

  state:
    description:
      - Whether the specified Cloud Manager CVO for GCP should exist or not.
    choices: ['present', 'absent']
    default: 'present'
    type: str

  subnet_id:
    description:
      - The name of the subnet for Cloud Volumes ONTAP.
    type: str

  subnet0_node_and_data_connectivity:
    description:
      - Subnet path for nic1, required for node and data connectivity.
      - If using shared VPC, network_project_id must be provided.
      - Option for HA pair only.
    type: str

  subnet1_cluster_connectivity:
    description:
      - Subnet path for nic2, required for cluster connectivity.
      - Option for HA pair only.
    type: str

  subnet2_ha_connectivity:
    description:
      - Subnet path for nic3, required for HA connectivity.
      - Option for HA pair only.
    type: str

  subnet3_data_replication:
    description:
      - Subnet path for nic4, required for HA connectivity.
      - Option for HA pair only.
    type: str

  svm_password:
    description:
      - The admin password for Cloud Volumes ONTAP.
      - It will be updated on each run.
    type: str

  svm_name:
    description:
      - The name of the SVM.
    type: str
    version_added: 21.22.0

  tier_level:
    description:
      - The tiering level when 'capacity_tier' is set to 'cloudStorage'.
    choices: ['standard', 'nearline', 'coldline']
    default: 'standard'
    type: str

  use_latest_version:
    description:
      - Indicates whether to use the latest available ONTAP version.
    type: bool
    default: true

  vpc_id:
    required: true
    description:
      - The name of the VPC.
    type: str

  vpc0_firewall_rule_name:
    description:
      - Firewall rule name for vpc1.
      - Option for HA pair only.
    type: str

  vpc0_node_and_data_connectivity:
    description:
      - VPC path for nic1, required for node and data connectivity.
      - If using shared VPC, network_project_id must be provided.
      - Option for HA pair only.
    type: str

  vpc1_cluster_connectivity:
    description:
      - VPC path for nic2, required for cluster connectivity.
      - Option for HA pair only.
    type: str

  vpc1_firewall_rule_name:
    description:
      - Firewall rule name for vpc2.
      - Option for HA pair only.
    type: str

  vpc2_ha_connectivity:
    description:
      - VPC path for nic3, required for HA connectivity.
      - Option for HA pair only.
    type: str

  vpc2_firewall_rule_name:
    description:
      - Firewall rule name for vpc3.
      - Option for HA pair only.
    type: str

  vpc3_data_replication:
    description:
      - VPC path for nic4, required for data replication.
      - Option for HA pair only.
    type: str

  vpc3_firewall_rule_name:
    description:
      - Firewall rule name for vpc4.
      - Option for HA pair only.
    type: str

  workspace_id:
    description:
      - The ID of the Cloud Manager workspace where you want to deploy Cloud Volumes ONTAP.
      - If not provided, Cloud Manager uses the first workspace.
      - You can find the ID from the Workspace tab on [https://cloudmanager.netapp.com].
    type: str

  writing_speed_state:
    description:
      - The write speed setting for Cloud Volumes ONTAP ['NORMAL','HIGH'].
      - Default value is 'NORMAL' for non-HA GCP CVO
      - This argument is not relevant for HA pairs.
    type: str

  zone:
    description:
      - The zone of the region where the working environment will be created.
    required: true
    type: str

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

  subnet_path:
    description:
      - Subnet path for a single node cluster.
    type: str
    version_added: 21.20.0

notes:
- Support check_mode.
'''

EXAMPLES = """

- name: Create NetApp Cloud Manager cvo for GCP
  netapp.cloudmanager.na_cloudmanager_cvo_gcp:
    state: present
    name: ansiblecvogcp
    project_id: default-project
    zone: us-east4-b
    subnet_path: projects/<project>/regions/<region>/subnetworks/<subnetwork>
    subnet_id: projects/<project>/regions/<region>/subnetworks/<subnetwork>
    gcp_volume_type: pd-ssd
    gcp_volume_size: 500
    gcp_volume_size_unit: GB
    gcp_service_account: "{{ xxxxxxxxxxxxxxx }}"
    data_encryption_type: GCP
    svm_password: "{{ xxxxxxxxxxxxxxx }}"
    ontap_version: latest
    use_latest_version: true
    license_type: capacity-paygo
    instance_type: n1-standard-8
    client_id: "{{ xxxxxxxxxxxxxxx }}"
    workspace_id: "{{ xxxxxxxxxxxxxxx }}"
    capacity_tier: cloudStorage
    writing_speed_state: NORMAL
    refresh_token: "{{ xxxxxxxxxxxxxxx }}"
    vpc_id: default
    gcp_labels:
      - label_key: key1
        label_value: value1
      - label_key: key2
        label_value: value2

- name: Create NetApp Cloud Manager cvo ha for GCP
  netapp.cloudmanager.na_cloudmanager_cvo_gcp:
    state: present
    name: ansiblecvogcpha
    project_id: "default-project"
    zone: us-east1-b
    gcp_volume_type: pd-ssd
    gcp_volume_size: 500
    gcp_volume_size_unit: GB
    gcp_service_account: "{{ xxxxxxxxxxxxxxx }}"
    data_encryption_type: GCP
    svm_password: "{{ xxxxxxxxxxxxxxx }}"
    ontap_version: ONTAP-9.9.0.T1.gcpha
    use_latest_version: false
    license_type: ha-capacity-paygo
    instance_type: custom-4-16384
    client_id: "{{ xxxxxxxxxxxxxxx }}"
    workspace_id:  "{{ xxxxxxxxxxxxxxx }}"
    capacity_tier: cloudStorage
    writing_speed_state: NORMAL
    refresh_token: "{{ xxxxxxxxxxxxxxx }}"
    is_ha: true
    mediator_zone: us-east1-b
    node1_zone: us-east1-b
    node2_zone: us-east1-b
    subnet0_node_and_data_connectivity: default
    subnet1_cluster_connectivity: subnet2
    subnet2_ha_connectivity: subnet3
    subnet3_data_replication: subnet1
    vpc0_node_and_data_connectivity: default
    vpc1_cluster_connectivity: vpc2
    vpc2_ha_connectivity: vpc3
    vpc3_data_replication: vpc1
    vpc_id: default
    subnet_id: default

"""

RETURN = '''
working_environment_id:
  description: Newly created GCP CVO working_environment_id.
  type: str
  returned: success
'''

from ansible.module_utils.basic import AnsibleModule
import ansible_collections.netapp.cloudmanager.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.cloudmanager.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.cloudmanager.plugins.module_utils.netapp import CloudManagerRestAPI


GCP_LICENSE_TYPES = ["gcp-cot-standard-paygo", "gcp-cot-explore-paygo", "gcp-cot-premium-paygo", "gcp-cot-premium-byol",
                     "gcp-ha-cot-standard-paygo", "gcp-ha-cot-premium-paygo", "gcp-ha-cot-explore-paygo",
                     "gcp-ha-cot-premium-byol", "capacity-paygo", "ha-capacity-paygo"]
GOOGLE_API_URL = "https://www.googleapis.com/compute/v1/projects"


class NetAppCloudManagerCVOGCP:
    ''' object initialize and class methods '''

    def __init__(self):
        self.use_rest = False
        self.argument_spec = netapp_utils.cloudmanager_host_argument_spec()
        self.argument_spec.update(dict(
            backup_volumes_to_cbs=dict(required=False, type='bool', default=False),
            capacity_tier=dict(required=False, type='str', choices=['cloudStorage']),
            client_id=dict(required=True, type='str'),
            data_encryption_type=dict(required=False, choices=['GCP'], type='str'),
            gcp_encryption_parameters=dict(required=False, type='str', no_log=True),
            enable_compliance=dict(required=False, type='bool', default=False),
            firewall_rule=dict(required=False, type='str'),
            gcp_labels=dict(required=False, type='list', elements='dict', options=dict(
                label_key=dict(type='str', no_log=False),
                label_value=dict(type='str')
            )),
            gcp_service_account=dict(required=True, type='str'),
            gcp_volume_size=dict(required=False, type='int'),
            gcp_volume_size_unit=dict(required=False, choices=['GB', 'TB'], type='str'),
            gcp_volume_type=dict(required=False, choices=['pd-balanced', 'pd-standard', 'pd-ssd'], type='str'),
            instance_type=dict(required=False, type='str', default='n1-standard-8'),
            is_ha=dict(required=False, type='bool', default=False),
            license_type=dict(required=False, type='str', choices=GCP_LICENSE_TYPES, default='capacity-paygo'),
            mediator_zone=dict(required=False, type='str'),
            name=dict(required=True, type='str'),
            network_project_id=dict(required=False, type='str'),
            node1_zone=dict(required=False, type='str'),
            node2_zone=dict(required=False, type='str'),
            nss_account=dict(required=False, type='str'),
            ontap_version=dict(required=False, type='str', default='latest'),
            platform_serial_number=dict(required=False, type='str'),
            platform_serial_number_node1=dict(required=False, type='str'),
            platform_serial_number_node2=dict(required=False, type='str'),
            project_id=dict(required=True, type='str'),
            state=dict(required=False, choices=['present', 'absent'], default='present'),
            subnet_id=dict(required=False, type='str'),
            subnet0_node_and_data_connectivity=dict(required=False, type='str'),
            subnet1_cluster_connectivity=dict(required=False, type='str'),
            subnet2_ha_connectivity=dict(required=False, type='str'),
            subnet3_data_replication=dict(required=False, type='str'),
            svm_password=dict(required=False, type='str', no_log=True),
            svm_name=dict(required=False, type='str'),
            tier_level=dict(required=False, type='str', choices=['standard', 'nearline', 'coldline'],
                            default='standard'),
            use_latest_version=dict(required=False, type='bool', default=True),
            capacity_package_name=dict(required=False, type='str', choices=['Professional', 'Essential', 'Freemium'], default='Essential'),
            provided_license=dict(required=False, type='str'),
            vpc_id=dict(required=True, type='str'),
            vpc0_firewall_rule_name=dict(required=False, type='str'),
            vpc0_node_and_data_connectivity=dict(required=False, type='str'),
            vpc1_cluster_connectivity=dict(required=False, type='str'),
            vpc1_firewall_rule_name=dict(required=False, type='str'),
            vpc2_firewall_rule_name=dict(required=False, type='str'),
            vpc2_ha_connectivity=dict(required=False, type='str'),
            vpc3_data_replication=dict(required=False, type='str'),
            vpc3_firewall_rule_name=dict(required=False, type='str'),
            workspace_id=dict(required=False, type='str'),
            writing_speed_state=dict(required=False, type='str'),
            zone=dict(required=True, type='str'),
            upgrade_ontap_version=dict(required=False, type='bool', default=False),
            update_svm_password=dict(required=False, type='bool', default=False),
            subnet_path=dict(required=False, type='str'),
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            required_one_of=[['refresh_token', 'sa_client_id']],
            required_together=[['sa_client_id', 'sa_secret_key']],
            required_if=[
                ['license_type', 'capacity-paygo', ['capacity_package_name']],
                ['license_type', 'ha-capacity-paygo', ['capacity_package_name']],
                ['license_type', 'gcp-cot-premium-byol', ['platform_serial_number']],
                ['license_type', 'gcp-ha-cot-premium-byol', ['platform_serial_number_node1', 'platform_serial_number_node2']],
            ],
            supports_check_mode=True
        )
        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)
        self.changeable_params = ['svm_password', 'svm_name', 'tier_level', 'gcp_labels', 'ontap_version',
                                  'instance_type', 'license_type', 'writing_speed_state']
        self.rest_api = CloudManagerRestAPI(self.module)
        self.rest_api.url += self.rest_api.environment_data['CLOUD_MANAGER_HOST']
        self.rest_api.api_root_path = '/occm/api/gcp/%s' % ('ha' if self.parameters['is_ha'] else 'vsa')
        self.headers = {
            'X-Agent-Id': self.rest_api.format_client_id(self.parameters['client_id'])
        }

    @staticmethod
    def has_self_link(param):
        return param.startswith(("https://www.googleapis.com/compute/", "projects/"))

    def create_cvo_gcp(self):

        if self.parameters.get('workspace_id') is None:
            response, msg = self.na_helper.get_tenant(self.rest_api, self.headers)
            if response is None:
                self.module.fail_json(msg)
            self.parameters['workspace_id'] = response

        if self.parameters.get('nss_account') is None:
            if self.parameters.get('platform_serial_number') is not None:
                if not self.parameters['platform_serial_number'].startswith('Eval-'):
                    if self.parameters['license_type'] == 'gcp-cot-premium-byol' or self.parameters['license_type'] == 'gcp-ha-cot-premium-byol':
                        response, msg = self.na_helper.get_nss(self.rest_api, self.headers)
                        if response is None:
                            self.module.fail_json(msg)
                        self.parameters['nss_account'] = response

        if self.parameters['is_ha'] is True and self.parameters['license_type'] == 'capacity-paygo':
            self.parameters['license_type'] == 'ha-capacity-paygo'

        json = {"name": self.parameters['name'],
                "region": self.parameters['zone'],
                "tenantId": self.parameters['workspace_id'],
                "vpcId": self.parameters['vpc_id'],
                "gcpServiceAccount": self.parameters['gcp_service_account'],
                "gcpVolumeSize": {
                    "size": self.parameters['gcp_volume_size'],
                    "unit": self.parameters['gcp_volume_size_unit']},
                "gcpVolumeType": self.parameters['gcp_volume_type'],
                "svmPassword": self.parameters['svm_password'],
                "backupVolumesToCbs": self.parameters['backup_volumes_to_cbs'],
                "enableCompliance": self.parameters['enable_compliance'],
                "vsaMetadata": {
                    "ontapVersion": self.parameters['ontap_version'],
                    "licenseType": self.parameters['license_type'],
                    "useLatestVersion": self.parameters['use_latest_version'],
                    "instanceType": self.parameters['instance_type']}
                }

        if self.parameters['is_ha'] is False:
            if self.parameters.get('writing_speed_state') is None:
                self.parameters['writing_speed_state'] = 'NORMAL'
            json.update({'writingSpeedState': self.parameters['writing_speed_state'].upper()})

        if self.parameters.get('data_encryption_type') is not None and self.parameters['data_encryption_type'] == "GCP":
            json.update({'dataEncryptionType': self.parameters['data_encryption_type']})
            if self.parameters.get('gcp_encryption_parameters') is not None:
                json.update({"gcpEncryptionParameters": {"key": self.parameters['gcp_encryption_parameters']}})

        if self.parameters.get('provided_license') is not None:
            json['vsaMetadata'].update({"providedLicense": self.parameters['provided_license']})

        # clean default value if it is not by Capacity license
        if not self.parameters['license_type'].endswith('capacity-paygo'):
            json['vsaMetadata'].update({"capacityPackageName": ''})

        if self.parameters.get('capacity_package_name') is not None:
            json['vsaMetadata'].update({"capacityPackageName": self.parameters['capacity_package_name']})

        if self.parameters.get('project_id'):
            json.update({'project': self.parameters['project_id']})

        if self.parameters.get('nss_account'):
            json.update({'nssAccount': self.parameters['nss_account']})

        if self.parameters.get('subnet_id'):
            json.update({'subnetId': self.parameters['subnet_id']})

        if self.parameters.get('subnet_path'):
            json.update({'subnetPath': self.parameters['subnet_path']})

        if self.parameters.get('platform_serial_number') is not None:
            json.update({"serialNumber": self.parameters['platform_serial_number']})

        if self.parameters.get('capacity_tier') is not None and self.parameters['capacity_tier'] == "cloudStorage":
            json.update({"capacityTier": self.parameters['capacity_tier'],
                         "tierLevel": self.parameters['tier_level']})

        if self.parameters.get('svm_name') is not None:
            json.update({"svmName": self.parameters['svm_name']})

        if self.parameters.get('gcp_labels') is not None:
            labels = []
            for each_label in self.parameters['gcp_labels']:
                label = {
                    'labelKey': each_label['label_key'],
                    'labelValue': each_label['label_value']
                }

                labels.append(label)
            json.update({"gcpLabels": labels})

        if self.parameters.get('firewall_rule'):
            json.update({'firewallRule': self.parameters['firewall_rule']})

        if self.parameters['is_ha'] is True:
            ha_params = dict()

            if self.parameters.get('network_project_id') is not None:
                network_project_id = self.parameters.get('network_project_id')
            else:
                network_project_id = self.parameters['project_id']

            if not self.has_self_link(self.parameters['subnet_id']):
                json.update({'subnetId': 'projects/%s/regions/%s/subnetworks/%s' % (network_project_id,
                                                                                    self.parameters['zone'][:-2],
                                                                                    self.parameters['subnet_id'])})

            if self.parameters.get('platform_serial_number_node1'):
                ha_params["platformSerialNumberNode1"] = self.parameters['platform_serial_number_node1']

            if self.parameters.get('platform_serial_number_node2'):
                ha_params["platformSerialNumberNode2"] = self.parameters['platform_serial_number_node2']

            if self.parameters.get('node1_zone'):
                ha_params["node1Zone"] = self.parameters['node1_zone']

            if self.parameters.get('node2_zone'):
                ha_params["node2Zone"] = self.parameters['node2_zone']

            if self.parameters.get('mediator_zone'):
                ha_params["mediatorZone"] = self.parameters['mediator_zone']

            if self.parameters.get('vpc0_node_and_data_connectivity'):
                if self.has_self_link(self.parameters['vpc0_node_and_data_connectivity']):
                    ha_params["vpc0NodeAndDataConnectivity"] = self.parameters['vpc0_node_and_data_connectivity']
                else:
                    ha_params["vpc0NodeAndDataConnectivity"] = GOOGLE_API_URL + "/{0}/global/networks/{1}".format(
                        network_project_id, self.parameters['vpc0_node_and_data_connectivity'])

            if self.parameters.get('vpc1_cluster_connectivity'):
                if self.has_self_link(self.parameters['vpc1_cluster_connectivity']):
                    ha_params["vpc1ClusterConnectivity"] = self.parameters['vpc1_cluster_connectivity']
                else:
                    ha_params["vpc1ClusterConnectivity"] = GOOGLE_API_URL + "/{0}/global/networks/{1}".format(
                        network_project_id, self.parameters['vpc1_cluster_connectivity'])

            if self.parameters.get('vpc2_ha_connectivity'):
                if self.has_self_link(self.parameters['vpc2_ha_connectivity']):
                    ha_params["vpc2HAConnectivity"] = self.parameters['vpc2_ha_connectivity']
                else:
                    ha_params["vpc2HAConnectivity"] = "https://www.googleapis.com/compute/v1/projects/{0}/global/networks" \
                        "/{1}".format(network_project_id, self.parameters['vpc2_ha_connectivity'])

            if self.parameters.get('vpc3_data_replication'):
                if self.has_self_link(self.parameters['vpc3_data_replication']):
                    ha_params["vpc3DataReplication"] = self.parameters['vpc3_data_replication']
                else:
                    ha_params["vpc3DataReplication"] = GOOGLE_API_URL + "/{0}/global/networks/{1}".format(
                        network_project_id, self.parameters['vpc3_data_replication'])

            if self.parameters.get('subnet0_node_and_data_connectivity'):
                if self.has_self_link(self.parameters['subnet0_node_and_data_connectivity']):
                    ha_params["subnet0NodeAndDataConnectivity"] = self.parameters['subnet0_node_and_data_connectivity']
                else:
                    ha_params["subnet0NodeAndDataConnectivity"] = GOOGLE_API_URL + "/{0}/regions/{1}/subnetworks/{2}".\
                        format(network_project_id, self.parameters['zone'][:-2], self.parameters['subnet0_node_and_data_connectivity'])

            if self.parameters.get('subnet1_cluster_connectivity'):
                if self.has_self_link(self.parameters['subnet1_cluster_connectivity']):
                    ha_params["subnet1ClusterConnectivity"] = self.parameters['subnet1_cluster_connectivity']
                else:
                    ha_params["subnet1ClusterConnectivity"] = GOOGLE_API_URL + "/{0}/regions/{1}/subnetworks/{2}".format(
                        network_project_id, self.parameters['zone'][:-2],
                        self.parameters['subnet1_cluster_connectivity'])

            if self.parameters.get('subnet2_ha_connectivity'):
                if self.has_self_link(self.parameters['subnet2_ha_connectivity']):
                    ha_params["subnet2HAConnectivity"] = self.parameters['subnet2_ha_connectivity']
                else:
                    ha_params["subnet2HAConnectivity"] = GOOGLE_API_URL + "/{0}/regions/{1}/subnetworks/{2}".format(
                        network_project_id, self.parameters['zone'][:-2],
                        self.parameters['subnet2_ha_connectivity'])

            if self.parameters.get('subnet3_data_replication'):
                if self.has_self_link(self.parameters['subnet3_data_replication']):
                    ha_params["subnet3DataReplication"] = self.parameters['subnet3_data_replication']
                else:
                    ha_params["subnet3DataReplication"] = GOOGLE_API_URL + "/{0}/regions/{1}/subnetworks/{2}". \
                        format(network_project_id, self.parameters['zone'][:-2],
                               self.parameters['subnet3_data_replication'])

            if self.parameters.get('vpc0_firewall_rule_name'):
                ha_params["vpc0FirewallRuleName"] = self.parameters['vpc0_firewall_ruleName']

            if self.parameters.get('vpc1_firewall_rule_name'):
                ha_params["vpc1FirewallRuleName"] = self.parameters['vpc1_firewall_rule_name']

            if self.parameters.get('vpc2_firewall_rule_name'):
                ha_params["vpc2FirewallRuleName"] = self.parameters['vpc2_firewall_rule_name']

            if self.parameters.get('vpc3_firewall_rule_name'):
                ha_params["vpc3FirewallRuleName"] = self.parameters['vpc3_firewall_rule_name']

            json["haParams"] = ha_params

        api_url = '%s/working-environments' % self.rest_api.api_root_path
        response, error, on_cloud_request_id = self.rest_api.post(api_url, json, header=self.headers)
        if error is not None:
            self.module.fail_json(
                msg="Error: unexpected response on creating cvo gcp: %s, %s" % (str(error), str(response)))
        working_environment_id = response['publicId']
        wait_on_completion_api_url = '/occm/api/audit/activeTask/%s' % str(on_cloud_request_id)
        err = self.rest_api.wait_on_completion(wait_on_completion_api_url, "CVO", "create", 60, 90)

        if err is not None:
            self.module.fail_json(msg="Error: unexpected response wait_on_completion for creating CVO GCP: %s" % str(err))
        return working_environment_id

    def update_cvo_gcp(self, working_environment_id, modify):
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
            if item == 'gcp_labels':
                tag_list = None
                if 'gcp_labels' in self.parameters:
                    tag_list = self.parameters['gcp_labels']
                response, error = self.na_helper.update_cvo_tags(base_url, self.rest_api, self.headers, 'gcp_labels', tag_list)
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

    def delete_cvo_gcp(self, we_id):
        """
        Delete GCP CVO
        """
        api_url = '%s/working-environments/%s' % (self.rest_api.api_root_path, we_id)
        response, error, on_cloud_request_id = self.rest_api.delete(api_url, None, header=self.headers)
        if error is not None:
            self.module.fail_json(msg="Error: unexpected response on deleting cvo gcp: %s, %s" % (str(error), str(response)))

        wait_on_completion_api_url = '/occm/api/audit/activeTask/%s' % str(on_cloud_request_id)
        err = self.rest_api.wait_on_completion(wait_on_completion_api_url, "CVO", "delete", 40, 60)
        if err is not None:
            self.module.fail_json(msg="Error: unexpected response wait_on_completion for deleting cvo gcp: %s" % str(err))

    def apply(self):
        working_environment_id = None
        modify = None

        current, dummy = self.na_helper.get_working_environment_details_by_name(self.rest_api, self.headers,
                                                                                self.parameters['name'], "gcp")
        if current:
            self.parameters['working_environment_id'] = current['publicId']
        # check the action
        cd_action = self.na_helper.get_cd_action(current, self.parameters)

        if current and self.parameters['state'] != 'absent':
            working_environment_id = current['publicId']
            modify, error = self.na_helper.is_cvo_update_needed(self.rest_api, self.headers, self.parameters, self.changeable_params, 'gcp')
            if error is not None:
                self.module.fail_json(changed=False, msg=error)

        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == "create":
                working_environment_id = self.create_cvo_gcp()
            elif cd_action == "delete":
                self.delete_cvo_gcp(current['publicId'])
            else:
                self.update_cvo_gcp(current['publicId'], modify)

        self.module.exit_json(changed=self.na_helper.changed, working_environment_id=working_environment_id)


def main():
    """
    Create Cloud Manager CVO for GCP class instance and invoke apply
    :return: None
    """
    obj_store = NetAppCloudManagerCVOGCP()
    obj_store.apply()


if __name__ == '__main__':
    main()
