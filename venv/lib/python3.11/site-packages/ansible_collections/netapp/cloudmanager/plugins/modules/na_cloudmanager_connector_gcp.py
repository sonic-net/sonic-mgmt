#!/usr/bin/python

# (c) 2021, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

'''
na_cloudmanager_connector_gcp
'''

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''

module: na_cloudmanager_connector_gcp
short_description: NetApp Cloud Manager connector for GCP.
extends_documentation_fragment:
  - netapp.cloudmanager.netapp.cloudmanager
version_added: '21.4.0'
author: NetApp Ansible Team (@carchi8py) <ng-ansibleteam@netapp.com>

description:
  - Create or delete Cloud Manager connector for GCP.

options:
  state:
    description:
    - Whether the specified Cloud Manager connector for GCP should exist or not.
    choices: ['present', 'absent']
    default: 'present'
    type: str

  name:
    required: true
    description:
    - The name of the Cloud Manager connector for GCP to manage.
    type: str

  project_id:
    description:
    - The GCP project_id where the connector will be created.
    required: true
    type: str

  zone:
    description:
    - The GCP zone where the Connector will be created.
    required: true
    type: str

  gcp_service_account_email:
    description:
    - The email of the service_account for the connector instance. This service account is used to allow the Connector to create Cloud Volume ONTAP.
    required: true
    type: str
    aliases: ['service_account_email']
    version_added: 21.7.0

  company:
    description:
    - The name of the company of the user.
    required: true
    type: str

  gcp_service_account_path:
    description:
    - The local path of the service_account JSON file for GCP authorization purposes. This service account is used to create the Connector in GCP.
    type: str
    aliases: ['service_account_path']
    version_added: 21.7.0

  subnet_id:
    description:
    - The name of the subnet for the virtual machine.
    type: str
    default: default

  network_project_id:
    description:
    - The project id in GCP associated with the Subnet. If not provided, it is assumed that the Subnet is within the previously specified project id.
    type: str

  machine_type:
    description:
    - The machine_type for the Connector VM.
    type: str
    default: n2-standard-4

  firewall_tags:
    description:
    - Indicates whether to add firewall_tags to the connector VM (HTTP and HTTP).
    type: bool
    default: true

  associate_public_ip:
    description:
    - Indicates whether to associate a public IP address to the virtual machine.
    type: bool
    default: true

  proxy_url:
    description:
    - The proxy URL, if using a proxy to connect to the internet.
    type: str

  proxy_user_name:
    description:
    - The proxy user name, if using a proxy to connect to the internet.
    type: str

  proxy_password:
    description:
    - The proxy password, if using a proxy to connect to the internet.
    type: str

  proxy_certificates:
    description:
    - The proxy certificates. A list of certificate file names.
    type: list
    elements: str

  account_id:
    description:
    - The NetApp account ID that the Connector will be associated with.
    - If not provided, Cloud Manager uses the first account. If no account exists, Cloud Manager creates a new account.
    - You can find the account ID in the account tab of Cloud Manager at [https://cloudmanager.netapp.com](https://cloudmanager.netapp.com).
    type: str

  client_id:
    description:
    - The client ID of the Cloud Manager Connector.
    - The connector ID.
    - If state is absent, the client id is used to identify the agent and delete it.
    - If state is absent and this parameter is not set, all agents associated with C(name) are deleted.
    - Ignored when state is present.
    type: str

'''

EXAMPLES = """
- name: Create NetApp Cloud Manager connector for GCP
  netapp.cloudmanager.na_cloudmanager_connector_gcp:
    state: present
    name: ansible-occm-gcp
    project_id: xxxxxxx-support
    zone: us-east4-b
    company: NetApp
    gcp_service_account_email: xxxxxxxx@xxxxxxx-support.iam.gserviceaccount.com
    gcp_service_account_path: gcp_creds.json
    proxy_user_name: test
    proxy_password: test
    proxy_url: http://abcdefg.com
    proxy_certificates: ["D-TRUST_Root_Class_3_CA_2_2009.crt", "DigiCertGlobalRootCA.crt", "DigiCertGlobalRootG2.crt"]
    account_id: account-xxxxXXXX
    refresh_token: "{{ xxxxxxxxxxxxxxx }}"

- name: Delete NetApp Cloud Manager connector for GCP
  netapp.cloudmanager.na_cloudmanager_connector_gcp:
    state: absent
    name: ansible-occm-gcp
    refresh_token: "{{ xxxxxxxxxxxxxxx }}"
    client_id: "{{ wwwwwwwwww }}"
    project_id: xxxxxxx-support
    zone: us-east4-b
    company: NetApp
    gcp_service_account_email: xxxxxxxx@xxxxxxx-support.iam.gserviceaccount.com
    gcp_service_account_path: gcp_creds.json
    account_id: account-xxxxXXXX
"""

RETURN = """
client_id:
  description: Newly created GCP connector id on cloud manager.
  type: str
  returned: success
  sample: 'FDQE8SwrbjVS6mqUgZoOHQmu2DvBNRRW'
client_ids:
  description:
    - a list of client ids matching the name and provider if the connector already exists.
    - ideally the list should be empty, or contain a single element matching client_id.
  type: list
  elements: str
  returned: success
  sample: ['FDQE8SwrbjVS6mqUgZoOHQmu2DvBNRRW']
"""
import uuid
import time
import base64
import json

from ansible.module_utils.basic import AnsibleModule
import ansible_collections.netapp.cloudmanager.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.cloudmanager.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.cloudmanager.plugins.module_utils.netapp import CloudManagerRestAPI

IMPORT_ERRORS = []
HAS_GCP_COLLECTION = False

try:
    import google.auth
    from google.auth.transport import requests
    from google.oauth2 import service_account
    import yaml
    HAS_GCP_COLLECTION = True
except ImportError as exc:
    IMPORT_ERRORS.append(str(exc))

GCP_DEPLOYMENT_MANAGER = "www.googleapis.com"
UUID = str(uuid.uuid4())


class NetAppCloudManagerConnectorGCP(object):
    ''' object initialize and class methods '''

    def __init__(self):
        self.argument_spec = netapp_utils.cloudmanager_host_argument_spec()
        self.argument_spec.update(dict(
            name=dict(required=True, type='str'),
            state=dict(required=False, choices=['present', 'absent'], default='present'),
            project_id=dict(required=True, type='str'),
            zone=dict(required=True, type='str'),
            company=dict(required=True, type='str'),
            gcp_service_account_email=dict(required=True, type='str', aliases=['service_account_email']),
            gcp_service_account_path=dict(required=False, type='str', aliases=['service_account_path']),
            subnet_id=dict(required=False, type='str', default='default'),
            network_project_id=dict(required=False, type='str'),
            machine_type=dict(required=False, type='str', default='n2-standard-4'),
            firewall_tags=dict(required=False, type='bool', default=True),
            associate_public_ip=dict(required=False, type='bool', default=True),
            proxy_url=dict(required=False, type='str'),
            proxy_user_name=dict(required=False, type='str'),
            proxy_password=dict(required=False, type='str', no_log=True),
            proxy_certificates=dict(required=False, type='list', elements='str'),
            account_id=dict(required=False, type='str'),
            client_id=dict(required=False, type='str'),
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            required_one_of=[['refresh_token', 'sa_client_id']],
            required_together=[['sa_client_id', 'sa_secret_key']],
            supports_check_mode=True
        )
        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)
        self.rest_api = CloudManagerRestAPI(self.module)
        self.gcp_common_suffix_name = "-vm-boot-deployment"
        self.fail_when_import_errors(IMPORT_ERRORS, HAS_GCP_COLLECTION)
        super(NetAppCloudManagerConnectorGCP, self).__init__()

        self.rest_api.gcp_token, error = self.get_gcp_token()
        if error:
            self.module.fail_json(msg='Error getting gcp token: %s' % repr(error))

    def get_gcp_token(self):
        '''
        get gcp token from gcp service account credential json file
        '''
        scopes = ["https://www.googleapis.com/auth/cloud-platform",
                  "https://www.googleapis.com/auth/compute",
                  "https://www.googleapis.com/auth/compute.readonly",
                  "https://www.googleapis.com/auth/ndev.cloudman",
                  "https://www.googleapis.com/auth/ndev.cloudman.readonly",
                  "https://www.googleapis.com/auth/devstorage.full_control",
                  "https://www.googleapis.com/auth/devstorage.read_write"]
        if 'gcp_service_account_path' in self.parameters:
            try:
                fh = open(self.parameters['gcp_service_account_path'])
            except (OSError, IOError) as error:
                return None, "opening %s: got: %s" % (self.parameters['gcp_service_account_path'], repr(error))
            with fh:
                key_bytes = json.load(fh)
                if key_bytes is None:
                    return None, "Error: gcp_service_account_path file is empty"
            credentials = service_account.Credentials.from_service_account_file(self.parameters['gcp_service_account_path'], scopes=scopes)
        else:
            credentials, project = google.auth.default(scopes=scopes)

        credentials.refresh(requests.Request())

        return credentials.token, None

    def fail_when_import_errors(self, import_errors, has_gcp_collection=True):
        if has_gcp_collection and not import_errors:
            return
        msg = ''
        if not has_gcp_collection:
            msg = 'The python google-auth package is required. '
        msg += 'Import errors: %s' % str(import_errors)
        self.module.fail_json(msg=msg)

    def get_deploy_vm(self):
        '''
        Get Cloud Manager connector for GCP
        :return:
            Dictionary of current details if Cloud Manager connector for GCP
            None if Cloud Manager connector for GCP is not found
        '''
        api_url = GCP_DEPLOYMENT_MANAGER + '/deploymentmanager/v2/projects/%s/global/deployments/%s%s' % (
            self.parameters['project_id'], self.parameters['name'], self.gcp_common_suffix_name)
        headers = {
            "X-User-Token": self.rest_api.token_type + " " + self.rest_api.token,
            'Authorization': self.rest_api.token_type + " " + self.rest_api.gcp_token,
        }

        occm_status, error, dummy = self.rest_api.get(api_url, header=headers)
        if error is not None:
            if error == '404' and b'is not found' in occm_status:
                return None
            self.module.fail_json(
                msg="Error: unexpected response on getting occm: %s, %s" % (str(error), str(occm_status)))

        return occm_status

    def get_custom_data_for_gcp(self, proxy_certificates):
        '''
        get custom data for GCP
        '''
        # get account ID
        if 'account_id' not in self.parameters:
            # get account ID
            response, error = self.na_helper.get_or_create_account(self.rest_api)
            if error is not None:
                self.module.fail_json(
                    msg="Error: unexpected response on getting account: %s, %s" % (str(error), str(response)))
            self.parameters['account_id'] = response
        # registerAgentTOServiceForGCP
        response, error = self.na_helper.register_agent_to_service(self.rest_api, "GCP", "")
        if error is not None:
            self.module.fail_json(
                msg="Error: register agent to service for gcp failed: %s, %s" % (str(error), str(response)))
        # add proxy_certificates as part of json data
        client_id = response['clientId']
        client_secret = response['clientSecret']
        u_data = {
            'instanceName': self.parameters['name'],
            'company': self.parameters['company'],
            'clientId': client_id,
            'clientSecret': client_secret,
            'systemId': UUID,
            'tenancyAccountId': self.parameters['account_id'],
            'proxySettings': {'proxyPassword': self.parameters.get('proxy_password'),
                              'proxyUserName': self.parameters.get('proxy_user_name'),
                              'proxyUrl': self.parameters.get('proxy_url'),
                              'proxyCertificates': proxy_certificates,
                              },
        }
        # convert response to json format
        user_data = json.dumps(u_data)
        return user_data, client_id, None

    def deploy_gcp_vm(self, proxy_certificates):
        '''
        deploy GCP VM
        '''
        # getCustomDataForGCP
        response, client_id, error = self.get_custom_data_for_gcp(proxy_certificates)
        if error is not None:
            self.module.fail_json(
                msg="Error: Not able to get user data for GCP: %s, %s" % (str(error), str(response)))
        # compose
        user_data = response
        gcp_custom_data = base64.b64encode(user_data.encode())
        gcp_sa_scopes = ["https://www.googleapis.com/auth/cloud-platform",
                         "https://www.googleapis.com/auth/compute",
                         "https://www.googleapis.com/auth/compute.readonly",
                         "https://www.googleapis.com/auth/ndev.cloudman",
                         "https://www.googleapis.com/auth/ndev.cloudman.readonly"]

        tags = []
        if self.parameters['firewall_tags'] is True:
            tags = {'items': ['firewall-tag-bvsu', 'http-server', 'https-server']}

        # first resource
        device_name = self.parameters['name'] + '-vm-disk-boot'
        t = {
            'name': self.parameters['name'] + '-vm',
            'properties': {
                'disks': [
                    {'autoDelete': True,
                     'boot': True,
                     'deviceName': device_name,
                     'name': device_name,
                     'source': "\\\"$(ref.%s.selfLink)\\\"" % device_name,
                     'type': "PERSISTENT",
                     },
                ],
                'machineType': "zones/%s/machineTypes/%s" % (self.parameters['zone'], self.parameters['machine_type']),
                'metadata': {
                    'items': [
                        {'key': 'serial-port-enable',
                         'value': 1},
                        {'key': 'customData',
                         'value': gcp_custom_data}
                    ]
                },
                'serviceAccounts': [{'email': self.parameters['gcp_service_account_email'],
                                     'scopes': gcp_sa_scopes, }],
                'tags': tags,
                'zone': self.parameters['zone']
            },
            'metadata': {'dependsOn': [device_name]},
            'type': 'compute.v1.instance',
        }

        access_configs = []
        if self.parameters['associate_public_ip'] is True:
            access_configs = [{'kind': 'compute#accessConfig',
                               'name': 'External NAT',
                               'type': 'ONE_TO_ONE_NAT',
                               'networkTier': 'PREMIUM'
                               }]
        project_id = self.parameters['project_id']
        if self.parameters.get('network_project_id'):
            project_id = self.parameters['network_project_id']

        t['properties']['networkInterfaces'] = [
            {'accessConfigs': access_configs,
             'kind': 'compute#networkInterface',
             'subnetwork': 'projects/%s/regions/%s/subnetworks/%s' % (
                 project_id, self.parameters['region'], self.parameters['subnet_id'])
             }]

        td = {
            'name': device_name,
            'properties': {'name': device_name,
                           'sizeGb': 100,
                           'sourceImage': 'projects/%s/global/images/family/%s' % (self.rest_api.environment_data['GCP_IMAGE_PROJECT'],
                                                                                   self.rest_api.environment_data['GCP_IMAGE_FAMILY']),
                           'type': 'zones/%s/diskTypes/pd-ssd' % (self.parameters['zone']),
                           'zone': self.parameters['zone']
                           },
            'type': 'compute.v1.disks',
        }
        content = {
            'resources': [t, td]
        }
        my_data = str(yaml.dump(content))
        # The template must be in this format:
        # {
        #   "name": "ansible-cycc-vm-boot-deployment",
        #   "target": {
        #   "config": {
        #   "content": "resources:
        # - name: xxxx
        #   properties:
        #         ...
        # "
        #  }
        # }
        # }
        gcp_deployment_template = '{\n  "name": "%s%s",\n  "target": {\n  "config": {\n  "content": "%s"\n  }\n}\n}' % (
            self.parameters['name'], '-vm-boot-deployment', my_data)

        # post
        api_url = GCP_DEPLOYMENT_MANAGER + '/deploymentmanager/v2/projects/%s/global/deployments' % (
            self.parameters['project_id'])

        headers = {
            'X-User-Token': self.rest_api.token_type + " " + self.rest_api.gcp_token,
            'X-Tenancy-Account-Id': self.parameters['account_id'],
            'Authorization': self.rest_api.token_type + " " + self.rest_api.gcp_token,
            'Content-type': "application/json",
            'Referer': "Ansible_NetApp",
            'X-Agent-Id': self.rest_api.format_client_id(client_id)
        }

        response, error, dummy = self.rest_api.post(api_url, data=gcp_deployment_template, header=headers,
                                                    gcp_type=True)
        if error is not None:
            return response, client_id, error

        # check occm status
        # Sleep for 1 minutes
        time.sleep(60)
        retries = 16
        while retries > 0:
            agent, error = self.na_helper.get_occm_agent_by_id(self.rest_api, client_id)
            if error is not None:
                self.module.fail_json(
                    msg="Error: Not able to get occm status: %s, %s" % (str(error), str(agent)),
                    client_id=client_id, changed=True)
            if agent['status'] == "active":
                break
            else:
                time.sleep(30)
            retries -= 1
        if retries == 0:
            # Taking too long for status to be active
            msg = "Connector VM is created and registered.  Taking too long for OCCM agent to be active or not properly setup."
            msg += '  Latest status: %s' % agent
            self.module.fail_json(msg=msg, client_id=client_id, changed=True)

        return response, client_id, error

    def create_occm_gcp(self):
        '''
        Create Cloud Manager connector for GCP
        '''
        # check proxy configuration
        if 'proxy_user_name' in self.parameters and 'proxy_url' not in self.parameters:
            self.module.fail_json(msg="Error: missing proxy_url")
        if 'proxy_password' in self.parameters and 'proxy_url' not in self.parameters:
            self.module.fail_json(msg="Error: missing proxy_url")

        proxy_certificates = []
        if 'proxy_certificates' in self.parameters:
            for c_file in self.parameters['proxy_certificates']:
                proxy_certificate, error = self.na_helper.encode_certificates(c_file)
                # add to proxy_certificates list
                if error is not None:
                    self.module.fail_json(msg="Error: not able to read certificate file %s" % c_file)
                proxy_certificates.append(proxy_certificate)
        # region is the super class of zone. For example, zone us-east4-b is one of the zone in region us-east4
        self.parameters['region'] = self.parameters['zone'][:-2]
        # deploy GCP VM
        response, client_id, error = self.deploy_gcp_vm(proxy_certificates)
        if error is not None:
            self.module.fail_json(
                msg="Error: create_occm_gcp: %s, %s" % (str(error), str(response)))
        return client_id

    def delete_occm_gcp(self):
        '''
        Delete Cloud Manager connector for GCP
        '''
        api_url = GCP_DEPLOYMENT_MANAGER + '/deploymentmanager/v2/projects/%s/global/deployments/%s%s' % (
            self.parameters['project_id'],
            self.parameters['name'],
            self.gcp_common_suffix_name)
        headers = {
            "X-User-Token": self.rest_api.token_type + " " + self.rest_api.token,
            'Authorization': self.rest_api.token_type + " " + self.rest_api.gcp_token,
            'X-Tenancy-Account-Id': self.parameters['account_id'],
            'Content-type': "application/json",
            'Referer': "Ansible_NetApp",
        }

        response, error, dummy = self.rest_api.delete(api_url, None, header=headers)
        if error is not None:
            return "Error: unexpected response on deleting VM: %s, %s" % (str(error), str(response))
        # sleep for 30 sec
        time.sleep(30)
        if 'client_id' not in self.parameters:
            return None
        # check occm status
        retries = 30
        while retries > 0:
            agent, error = self.na_helper.get_occm_agent_by_id(self.rest_api, self.parameters['client_id'])
            if error is not None:
                return "Error: Not able to get occm status after deleting VM: %s, %s" % (str(error), str(agent))
            if agent['status'] != ["active", "pending"]:
                break
            else:
                time.sleep(10)
            retries -= 1 if agent['status'] == "active" else 5
        if retries == 0 and agent['status'] == "active":
            # Taking too long for terminating OCCM
            return "Taking too long for instance to finish terminating. Latest status: %s" % str(agent)
        return None

    def delete_occm_agents(self, agents):
        error = self.na_helper.delete_occm_agents(self.rest_api, agents)
        if error:
            return "Error: deleting OCCM agent(s): %s" % error
        return None

    def get_occm_agents(self):
        if 'client_id' in self.parameters and self.parameters['state'] == 'absent':
            agent, error = self.na_helper.get_occm_agent_by_id(self.rest_api, self.parameters['client_id'])
            if error == '403' and b'Action not allowed for user' in agent:
                # assume the agent does not exist anymore
                agents, error = [], None
                self.module.warn('Client Id %s was not found for this account.' % self.parameters['client_id'])
            else:
                agents = [agent]
        else:
            agents, error = self.na_helper.get_occm_agents_by_name(self.rest_api, self.parameters['account_id'],
                                                                   self.parameters['name'], 'GCP')
        if error:
            self.module.fail_json(
                msg="Error: getting OCCM agents: %s, %s" % (str(error), str(agents)))
        return agents

    def set_client_id(self, agents):
        client_id = ""
        client_ids = [agent['agentId'] for agent in agents if 'agentId' in agent]
        if len(client_ids) == 1:
            client_id = client_ids[0]
            self.parameters['client_id'] = client_ids[0]
        elif 'client_id' in self.parameters and self.parameters['client_id'] in client_ids:
            client_id = self.parameters['client_id']
        return client_id, client_ids

    def apply(self):
        """
        Apply action to the Cloud Manager connector for GCP
        :return: None
        """
        client_id = ""
        agents, client_ids = [], []
        current_vm = self.get_deploy_vm()
        if current_vm and current_vm['operation']['status'] == 'terminated':
            current_vm = None
        current = current_vm
        if self.parameters['state'] == 'absent' or current:
            agents = self.get_occm_agents()
            client_id, client_ids = self.set_client_id(agents)
            if agents and current is None:
                current = {}
        if agents:
            current['agents'] = agents

        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == 'create':
                client_id = self.create_occm_gcp()
            elif cd_action == 'delete':
                errors = []
                if current_vm:
                    error = self.delete_occm_gcp()
                    if error:
                        errors.append(error)
                if agents:
                    error = self.delete_occm_agents(agents)
                    if error:
                        errors.append(error)
                if errors:
                    self.module.fail_json(msg='.  '.join(errors))

        self.module.exit_json(changed=self.na_helper.changed, client_id=client_id, client_ids=client_ids)


def main():
    """
    Create Cloud Manager connector for GCP class instance and invoke apply
    :return: None
    """
    obj_store = NetAppCloudManagerConnectorGCP()
    obj_store.apply()


if __name__ == '__main__':
    main()
