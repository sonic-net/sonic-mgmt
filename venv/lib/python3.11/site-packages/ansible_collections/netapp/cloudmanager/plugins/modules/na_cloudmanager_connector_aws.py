#!/usr/bin/python

# (c) 2021, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

'''
na_cloudmanager_connector_aws
'''

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''

module: na_cloudmanager_connector_aws
short_description: NetApp Cloud Manager connector for AWS
extends_documentation_fragment:
    - netapp.cloudmanager.netapp.cloudmanager
version_added: '21.3.0'
author: NetApp Ansible Team (@carchi8py) <ng-ansibleteam@netapp.com>

description:
  - Create or delete Cloud Manager connector for AWS.
  - This module requires to be authenticated with AWS.  This can be done with C(aws configure).

options:

  state:
    description:
      - Whether the specified Cloud Manager connector for AWS should exist or not.
    choices: ['present', 'absent']
    default: 'present'
    type: str

  name:
    required: true
    description:
      - The name of the Cloud Manager connector for AWS to manage.
    type: str

  instance_type:
    description:
      - The type of instance (for example, t3.xlarge). At least 4 CPU and 16 GB of memory are required.
    type: str
    default: t3.xlarge

  key_name:
    description:
      - The name of the key pair to use for the Connector instance.
    type: str

  subnet_id:
    description:
      - The ID of the subnet for the instance.
    type: str

  region:
    required: true
    description:
      - The region where the Cloud Manager Connector will be created.
    type: str

  instance_id:
    description:
      - The ID of the EC2 instance used for delete.
    type: str

  client_id:
    description:
      - The unique client ID of the Connector.
      - The connector ID.
    type: str

  ami:
    description:
      - The image ID.
    type: str

  company:
    description:
      - The name of the company of the user.
    type: str

  security_group_ids:
    description:
      - The IDs of the security groups for the instance, multiple security groups can be provided separated by ','.
    type: list
    elements: str

  iam_instance_profile_name:
    description:
      - The name of the instance profile for the Connector.
    type: str

  enable_termination_protection:
    description:
      - Indicates whether to enable termination protection on the instance.
    type: bool
    default: false

  associate_public_ip_address:
    description:
      - Indicates whether to associate a public IP address to the instance. If not provided, the association will be done based on the subnet's configuration.
    type: bool
    default: true

  account_id:
    description:
      - The NetApp tenancy account ID.
    type: str

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
      - The proxy certificates, a list of certificate file names.
    type: list
    elements: str
    version_added: 21.5.0

  aws_tag:
    description:
      - Additional tags for the AWS EC2 instance.
    type: list
    elements: dict
    suboptions:
      tag_key:
        description: The key of the tag.
        type: str
      tag_value:
        description: The tag value.
        type: str

notes:
- Support check_mode.
'''

EXAMPLES = """
- name: Create NetApp Cloud Manager connector for AWS
  netapp.cloudmanager.na_cloudmanager_connector_aws:
    state: present
    refresh_token: "{{ xxxxxxxxxxxxxxx }}"
    name: bsuhas_ansible_occm
    region: us-west-1
    key_name: dev_automation
    subnet_id: subnet-xxxxx
    security_group_ids: [sg-xxxxxxxxxxx]
    iam_instance_profile_name: OCCM_AUTOMATION
    account_id: "{{ account-xxxxxxx }}"
    company: NetApp
    proxy_url: abc.com
    proxy_user_name: xyz
    proxy_password: abcxyz
    proxy_certificates: [abc.crt.txt, xyz.crt.txt]
    aws_tag: [
        {tag_key: abc,
        tag_value: a123}]

- name: Delete NetApp Cloud Manager connector for AWS
  netapp.cloudmanager.na_cloudmanager_connector_aws:
    state: absent
    name: ansible
    region: us-west-1
    account_id: "{{ account-xxxxxxx }}"
    instance_id: i-xxxxxxxxxxxxx
    client_id: xxxxxxxxxxxxxxxxxxx
"""

RETURN = """
ids:
  description: Newly created AWS client ID in cloud manager, instance ID and account ID.
  type: dict
  returned: success
"""

import traceback
import uuid
import time

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.cloudmanager.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.cloudmanager.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.cloudmanager.plugins.module_utils.netapp import CloudManagerRestAPI
IMPORT_EXCEPTION = None

try:
    import boto3
    from botocore.exceptions import ClientError
    HAS_AWS_LIB = True
except ImportError as exc:
    HAS_AWS_LIB = False
    IMPORT_EXCEPTION = exc

UUID = str(uuid.uuid4())


class NetAppCloudManagerConnectorAWS(object):
    ''' object initialize and class methods '''

    def __init__(self):
        self.use_rest = False
        self.argument_spec = netapp_utils.cloudmanager_host_argument_spec()
        self.argument_spec.update(dict(
            name=dict(required=True, type='str'),
            state=dict(required=False, choices=['present', 'absent'], default='present'),
            instance_type=dict(required=False, type='str', default='t3.xlarge'),
            key_name=dict(required=False, type='str'),
            subnet_id=dict(required=False, type='str'),
            region=dict(required=True, type='str'),
            instance_id=dict(required=False, type='str'),
            client_id=dict(required=False, type='str'),
            ami=dict(required=False, type='str'),
            company=dict(required=False, type='str'),
            security_group_ids=dict(required=False, type='list', elements='str'),
            iam_instance_profile_name=dict(required=False, type='str'),
            enable_termination_protection=dict(required=False, type='bool', default=False),
            associate_public_ip_address=dict(required=False, type='bool', default=True),
            account_id=dict(required=False, type='str'),
            proxy_url=dict(required=False, type='str'),
            proxy_user_name=dict(required=False, type='str'),
            proxy_password=dict(required=False, type='str', no_log=True),
            proxy_certificates=dict(required=False, type='list', elements='str'),
            aws_tag=dict(required=False, type='list', elements='dict', options=dict(
                tag_key=dict(type='str', no_log=False),
                tag_value=dict(type='str')
            )),
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            required_if=[
                ['state', 'present', ['company', 'iam_instance_profile_name', 'key_name', 'security_group_ids', 'subnet_id']],
            ],
            required_one_of=[['refresh_token', 'sa_client_id']],
            required_together=[['sa_client_id', 'sa_secret_key']],
            supports_check_mode=True
        )

        if HAS_AWS_LIB is False:
            self.module.fail_json(msg="the python AWS packages boto3 and botocore are required. Command is pip install boto3."
                                      "Import error: %s" % str(IMPORT_EXCEPTION))

        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)

        self.rest_api = CloudManagerRestAPI(self.module)

    def get_instance(self):
        """
        Get Cloud Manager connector for AWS
        :return:
            Dictionary of current details if Cloud Manager connector for AWS
            None if Cloud Manager connector for AWS is not found
        """

        response = None
        client = boto3.client('ec2', region_name=self.parameters['region'])
        filters = [{'Name': 'tag:Name', 'Values': [self.parameters['name']]},
                   {'Name': 'tag:OCCMInstance', 'Values': ['true']}]

        kwargs = {'Filters': filters} if self.parameters.get('instance_id') is None else {'InstanceIds': [self.parameters['instance_id']]}

        try:
            response = client.describe_instances(**kwargs)

        except ClientError as error:
            self.module.fail_json(msg=to_native(error), exception=traceback.format_exc())

        if len(response['Reservations']) == 0:
            return None

        actives = [instance for reservation in response['Reservations'] for instance in reservation['Instances'] if instance['State']['Name'] != 'terminated']
        if len(actives) == 1:
            return actives[0]
        if not actives:
            return None
        self.module.fail_json(msg="Error: found multiple instances for name=%s: %s" % (self.parameters['name'], str(actives)))

    def get_ami(self):
        """
        Get AWS EC2 Image
        :return:
            Latest AMI
        """

        instance_ami = None
        client = boto3.client('ec2', region_name=self.parameters['region'])

        try:
            instance_ami = client.describe_images(
                Filters=[
                    {
                        'Name': 'name',
                        'Values': [
                            self.rest_api.environment_data['AMI_FILTER'],
                        ]
                    },
                ],
                Owners=[
                    self.rest_api.environment_data['AWS_ACCOUNT'],
                ],
            )
        except ClientError as error:
            self.module.fail_json(msg=to_native(error), exception=traceback.format_exc())

        latest_date = instance_ami['Images'][0]['CreationDate']
        latest_ami = instance_ami['Images'][0]['ImageId']

        for image in instance_ami['Images']:
            if image['CreationDate'] > latest_date:
                latest_date = image['CreationDate']
                latest_ami = image['ImageId']

        return latest_ami

    def create_instance(self):
        """
        Create Cloud Manager connector for AWS
        :return: client_id, instance_id
        """

        if self.parameters.get('ami') is None:
            self.parameters['ami'] = self.get_ami()

        user_data, client_id = self.register_agent_to_service()

        ec2 = boto3.client('ec2', region_name=self.parameters['region'])

        tags = [
            {
                'Key': 'Name',
                'Value': self.parameters['name']
            },
            {
                'Key': 'OCCMInstance',
                'Value': 'true'
            },
        ]

        if self.parameters.get('aws_tag') is not None:
            for each_tag in self.parameters['aws_tag']:
                tag = {
                    'Key': each_tag['tag_key'],
                    'Value': each_tag['tag_value']
                }

                tags.append(tag)

        instance_input = {
            'BlockDeviceMappings': [
                {
                    'DeviceName': '/dev/sda1',
                    'Ebs': {
                        'Encrypted': True,
                        'VolumeSize': 100,
                        'VolumeType': 'gp2',
                    },
                },
            ],
            'ImageId': self.parameters['ami'],
            'MinCount': 1,
            'MaxCount': 1,
            'KeyName': self.parameters['key_name'],
            'InstanceType': self.parameters['instance_type'],
            'DisableApiTermination': self.parameters['enable_termination_protection'],
            'TagSpecifications': [
                {
                    'ResourceType': 'instance',
                    'Tags': tags
                },
            ],
            'IamInstanceProfile': {
                'Name': self.parameters['iam_instance_profile_name']
            },
            'UserData': user_data
        }

        if self.parameters.get('associate_public_ip_address') is True:
            instance_input['NetworkInterfaces'] = [
                {
                    'AssociatePublicIpAddress': self.parameters['associate_public_ip_address'],
                    'DeviceIndex': 0,
                    'SubnetId': self.parameters['subnet_id'],
                    'Groups': self.parameters['security_group_ids']
                }
            ]
        else:
            instance_input['SubnetId'] = self.parameters['subnet_id']
            instance_input['SecurityGroupIds'] = self.parameters['security_group_ids']

        try:
            result = ec2.run_instances(**instance_input)
        except ClientError as error:
            self.module.fail_json(msg=to_native(error), exception=traceback.format_exc())

        # Sleep for 2 minutes
        time.sleep(120)
        retries = 16
        while retries > 0:
            agent, error = self.na_helper.get_occm_agent_by_id(self.rest_api, client_id)
            if error is not None:
                self.module.fail_json(
                    msg="Error: not able to get occm status: %s, %s" % (str(error), str(agent)),
                    client_id=client_id, instance_id=result['Instances'][0]['InstanceId'])
            if agent['status'] == "active":
                break
            else:
                time.sleep(30)
            retries -= 1
        if retries == 0:
            # Taking too long for status to be active
            return self.module.fail_json(msg="Error: taking too long for OCCM agent to be active or not properly setup")

        return client_id, result['Instances'][0]['InstanceId']

    def get_vpc(self):
        """
        Get vpc
        :return: vpc ID
        """

        vpc_result = None
        ec2 = boto3.client('ec2', region_name=self.parameters['region'])

        vpc_input = {'SubnetIds': [self.parameters['subnet_id']]}

        try:
            vpc_result = ec2.describe_subnets(**vpc_input)
        except ClientError as error:
            self.module.fail_json(msg=to_native(error), exception=traceback.format_exc())

        return vpc_result['Subnets'][0]['VpcId']

    def set_account_id(self):
        if self.parameters.get('account_id') is None:
            response, error = self.na_helper.get_or_create_account(self.rest_api)
            if error is not None:
                return error
            self.parameters['account_id'] = response
        return None

    def register_agent_to_service(self):
        """
        Register agent to service and collect userdata by setting up connector
        :return: UserData, ClientID
        """

        vpc = self.get_vpc()

        if self.parameters.get('account_id') is None:
            error = self.set_account_id()
            if error is not None:
                self.module.fail_json(msg="Error: failed to get account: %s." % str(error))

        headers = {
            "X-User-Token": self.rest_api.token_type + " " + self.rest_api.token,
            "X-Service-Request-Id": "111"
        }
        body = {
            "accountId": self.parameters['account_id'],
            "name": self.parameters['name'],
            "company": self.parameters['company'],
            "placement": {
                "provider": "AWS",
                "region": self.parameters['region'],
                "network": vpc,
                "subnet": self.parameters['subnet_id'],
            },
            "extra": {
                "proxy": {
                    "proxyUrl": self.parameters.get('proxy_url'),
                    "proxyUserName": self.parameters.get('proxy_user_name'),
                    "proxyPassword": self.parameters.get('proxy_password')
                }
            }
        }

        register_api = '/agents-mgmt/connector-setup'
        response, error, dummy = self.rest_api.post(register_api, body, header=headers)
        if error is not None:
            self.module.fail_json(msg="Error: unexpected response on connector setup: %s, %s" % (str(error), str(response)))
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
                              },
            'localAgent': True
        }

        if self.parameters.get('proxy_certificates') is not None:
            proxy_certificates = []
            for certificate_file in self.parameters['proxy_certificates']:
                encoded_certificate, error = self.na_helper.encode_certificates(certificate_file)
                if error:
                    self.module.fail_json(msg="Error: could not open/read file '%s' of proxy_certificates: %s" % (certificate_file, error))
                proxy_certificates.append(encoded_certificate)

            if proxy_certificates:
                u_data['proxySettings']['proxyCertificates'] = proxy_certificates

        user_data = self.na_helper.convert_data_to_tabbed_jsonstring(u_data)

        return user_data, client_id

    def delete_instance(self):
        """
        Delete OCCM instance
        :return:
            None
        """

        ec2 = boto3.client('ec2', region_name=self.parameters['region'])
        try:
            ec2.terminate_instances(
                InstanceIds=[
                    self.parameters['instance_id'],
                ],
            )
        except ClientError as error:
            self.module.fail_json(msg=to_native(error), exception=traceback.format_exc())

        if 'client_id' not in self.parameters:
            return None

        retries = 30
        while retries > 0:
            agent, error = self.na_helper.get_occm_agent_by_id(self.rest_api, self.parameters['client_id'])
            if error is not None:
                return "Error: not able to get occm agent status after deleting instance: %s, %s." % (str(error), str(agent))
            if agent['status'] != "active":
                break
            else:
                time.sleep(10)
            retries -= 1
        if retries == 0:
            # Taking too long for terminating OCCM
            return "Error: taking too long for instance to finish terminating."
        return None

    def get_occm_agents(self):
        if 'client_id' in self.parameters:
            agent, error = self.na_helper.get_occm_agent_by_id(self.rest_api, self.parameters['client_id'])
            if str(error) == '403' and 'Action not allowed for user' in str(agent):
                # assume the agent does not exist anymore
                agents, error = [], None
                self.module.warn('Client Id %s was not found for this account.' % self.parameters['client_id'])
            else:
                agents = [agent]
        else:
            self.set_account_id()
            if 'account_id' in self.parameters:
                agents, error = self.na_helper.get_occm_agents_by_name(self.rest_api, self.parameters['account_id'],
                                                                       self.parameters['name'], 'AWS')
            else:
                self.module.warn('Without account_id, some agents may still exist.')
                agents, error = [], None
        if error:
            self.module.fail_json(
                msg="Error: getting OCCM agents: %s, %s" % (str(error), str(agents)))
        return agents

    def set_client_id(self):
        agents = self.get_occm_agents()
        client_id = self.parameters.get('client_id')
        if client_id is None:
            active_client_ids = [agent['agentId'] for agent in agents if 'agentId' in agent and agent['status'] == 'active']
            if len(active_client_ids) == 1:
                client_id = active_client_ids[0]
                self.parameters['client_id'] = client_id
        return client_id, agents

    def delete_occm_agents(self, agents):
        error = self.na_helper.delete_occm_agents(self.rest_api, agents)
        if error:
            return "Error: deleting OCCM agent(s): %s" % error
        return None

    def apply(self):
        """
        Apply action to the Cloud Manager connector for AWS
        :return: None
        """
        results = {
            'account_id': None,
            'client_id': None,
            'instance_id': None
        }
        agents = None
        current = self.get_instance()
        if current or self.parameters['state'] == 'absent':
            if self.parameters.get('instance_id') is None and current:
                self.parameters['instance_id'] = current['InstanceId']
            results['instance_id'] = self.parameters.get('instance_id')
            results['client_id'], agents = self.set_client_id()
            if current is None and agents:
                # it's possible the VM instance does not exist, but the clients are still present.
                current = agents

        cd_action = self.na_helper.get_cd_action(current, self.parameters)
        if cd_action is None and self.parameters['state'] == 'present':
            results['modify'] = 'Note: modifying an existing connector is not supported at this time.'

        if not self.module.check_mode and self.na_helper.changed:
            if cd_action == 'create':
                results['client_id'], results['instance_id'] = self.create_instance()
            elif cd_action == 'delete':
                errors = []
                if self.parameters.get('instance_id'):
                    errors.append(self.delete_instance())
                if agents:
                    errors.append(self.delete_occm_agents(agents))
                errors = [error for error in errors if error]
                if errors:
                    self.module.fail_json(msg='Errors deleting instance or client: %s' % ', '.join(errors))

        results['account_id'] = self.parameters.get('account_id')
        results['changed'] = self.na_helper.changed
        self.module.exit_json(**results)


def main():
    """
    Create Cloud Manager connector for AWS class instance and invoke apply
    :return: None
    """
    obj_store = NetAppCloudManagerConnectorAWS()
    obj_store.apply()


if __name__ == '__main__':
    main()
