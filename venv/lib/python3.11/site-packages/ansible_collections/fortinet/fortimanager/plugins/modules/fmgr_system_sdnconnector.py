#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2019-2024 Fortinet, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fmgr_system_sdnconnector
short_description: Configure connection to SDN Connector.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.0.0"
author:
    - Xinwei Du (@dux-fortinet)
    - Xing Li (@lix-fortinet)
    - Jie Xue (@JieX19)
    - Link Zheng (@chillancezen)
    - Frank Shen (@fshen01)
    - Hongbin Lu (@fgtdev-hblu)
notes:
    - Starting in version 2.4.0, all input arguments are named using the underscore naming convention (snake_case).
      Please change the arguments such as "var-name" to "var_name".
      Old argument names are still available yet you will receive deprecation warnings.
      You can ignore this warning by setting deprecation_warnings=False in ansible.cfg.
    - Running in workspace locking mode is supported in this FortiManager module, the top
      level parameters workspace_locking_adom and workspace_locking_timeout help do the work.
    - To create or update an object, use state present directive.
    - To delete an object, use state absent directive.
    - Normally, running one module can fail when a non-zero rc is returned. you can also override
      the conditions to fail or succeed with parameters rc_failed and rc_succeeded
options:
    access_token:
        description: The token to access FortiManager without using username and password.
        type: str
    bypass_validation:
        description: Only set to True when module schema diffs with FortiManager API structure, module continues to execute without validating parameters.
        type: bool
        default: false
    enable_log:
        description: Enable/Disable logging for task.
        type: bool
        default: false
    forticloud_access_token:
        description: Authenticate Ansible client with forticloud API access token.
        type: str
    proposed_method:
        description: The overridden method for the underlying Json RPC request.
        type: str
        choices:
          - update
          - set
          - add
    rc_succeeded:
        description: The rc codes list with which the conditions to succeed will be overriden.
        type: list
        elements: int
    rc_failed:
        description: The rc codes list with which the conditions to fail will be overriden.
        type: list
        elements: int
    state:
        description: The directive to create, update or delete an object.
        type: str
        required: true
        choices:
          - present
          - absent
    revision_note:
        description: The change note that can be specified when an object is created or updated.
        type: str
    workspace_locking_adom:
        description: The adom to lock for FortiManager running in workspace mode, the value can be global and others including root.
        type: str
    workspace_locking_timeout:
        description: The maximum time in seconds to wait for other user to release the workspace lock.
        type: int
        default: 300
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    system_sdnconnector:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            _local_cert:
                type: str
                description: Local cert.
            access_key:
                aliases: ['access-key']
                type: str
                description: AWS access key ID.
            azure_region:
                aliases: ['azure-region']
                type: str
                description: Azure server region.
                choices:
                    - 'global'
                    - 'china'
                    - 'germany'
                    - 'usgov'
                    - 'local'
            client_id:
                aliases: ['client-id']
                type: str
                description: Azure client ID
            client_secret:
                aliases: ['client-secret']
                type: raw
                description: (list) Azure client secret
            compartment_id:
                aliases: ['compartment-id']
                type: str
                description: Compartment ID.
            external_ip:
                aliases: ['external-ip']
                type: list
                elements: dict
                description: External ip.
                suboptions:
                    name:
                        type: str
                        description: External IP name.
            gcp_project:
                aliases: ['gcp-project']
                type: str
                description: GCP project name.
            key_passwd:
                aliases: ['key-passwd']
                type: raw
                description: (list) Private key password.
            login_endpoint:
                aliases: ['login-endpoint']
                type: str
                description: Azure Stack login enpoint.
            name:
                type: str
                description: SDN connector name.
                required: true
            nic:
                type: list
                elements: dict
                description: Nic.
                suboptions:
                    ip:
                        type: list
                        elements: dict
                        description: Ip.
                        suboptions:
                            name:
                                type: str
                                description: IP configuration name.
                            public_ip:
                                aliases: ['public-ip']
                                type: str
                                description: Public IP name.
                            resource_group:
                                aliases: ['resource-group']
                                type: str
                                description: Resource group of Azure public IP.
                            private_ip:
                                aliases: ['private-ip']
                                type: str
                                description: Private IP address.
                    name:
                        type: str
                        description: Network interface name.
                    peer_nic:
                        aliases: ['peer-nic']
                        type: str
                        description: Peer network interface name.
            nsx_cert_fingerprint:
                aliases: ['nsx-cert-fingerprint']
                type: str
                description: NSX certificate fingerprint.
            oci_cert:
                aliases: ['oci-cert']
                type: str
                description: OCI certificate.
            oci_fingerprint:
                aliases: ['oci-fingerprint']
                type: str
                description: Oci fingerprint.
            oci_region:
                aliases: ['oci-region']
                type: str
                description: OCI server region.
                choices:
                    - 'phoenix'
                    - 'ashburn'
                    - 'frankfurt'
                    - 'london'
                    - 'toronto'
            password:
                type: raw
                description: (list) Password of the remote SDN connector as login credentials.
            private_key:
                aliases: ['private-key']
                type: str
                description: Private key of GCP service account.
            region:
                type: str
                description: AWS region name.
            resource_group:
                aliases: ['resource-group']
                type: str
                description: Azure resource group.
            resource_url:
                aliases: ['resource-url']
                type: str
                description: Azure Stack resource URL.
            rest_interface:
                aliases: ['rest-interface']
                type: str
                description: Interface name for REST service to listen on.
                choices:
                    - 'mgmt'
                    - 'sync'
            rest_password:
                aliases: ['rest-password']
                type: raw
                description: (list) Password for REST service.
            rest_sport:
                aliases: ['rest-sport']
                type: int
                description: REST service access port
            rest_ssl:
                aliases: ['rest-ssl']
                type: str
                description: Rest ssl.
                choices:
                    - 'disable'
                    - 'enable'
            route:
                type: list
                elements: dict
                description: Route.
                suboptions:
                    name:
                        type: str
                        description: Route name.
            route_table:
                aliases: ['route-table']
                type: list
                elements: dict
                description: Route table.
                suboptions:
                    name:
                        type: str
                        description: Route table name.
                    route:
                        type: list
                        elements: dict
                        description: Route.
                        suboptions:
                            name:
                                type: str
                                description: Route name.
                            next_hop:
                                aliases: ['next-hop']
                                type: str
                                description: Next hop address.
                    resource_group:
                        aliases: ['resource-group']
                        type: str
                        description: Resource group of Azure route table.
                    subscription_id:
                        aliases: ['subscription-id']
                        type: str
                        description: Subscription ID of Azure route table.
            secret_key:
                aliases: ['secret-key']
                type: raw
                description: (list) AWS secret access key.
            server:
                type: str
                description: Server address of the remote SDN connector.
            server_port:
                aliases: ['server-port']
                type: int
                description: Port number of the remote SDN connector.
            service_account:
                aliases: ['service-account']
                type: str
                description: GCP service account email.
            status:
                type: str
                description: Enable/disable connection to the remote SDN connector.
                choices:
                    - 'disable'
                    - 'enable'
            subscription_id:
                aliases: ['subscription-id']
                type: str
                description: Azure subscription ID.
            tenant_id:
                aliases: ['tenant-id']
                type: str
                description: Tenant ID
            type:
                type: str
                description: Type of SDN connector.
                choices:
                    - 'aci'
                    - 'aws'
                    - 'nsx'
                    - 'nuage'
                    - 'azure'
                    - 'gcp'
                    - 'oci'
                    - 'openstack'
                    - 'kubernetes'
                    - 'vmware'
                    - 'acs'
                    - 'alicloud'
                    - 'sepm'
                    - 'aci-direct'
                    - 'ibm'
                    - 'nutanix'
                    - 'sap'
            update_interval:
                aliases: ['update-interval']
                type: int
                description: Dynamic object update interval
            use_metadata_iam:
                aliases: ['use-metadata-iam']
                type: str
                description: Enable/disable using IAM role from metadata to call API.
                choices:
                    - 'disable'
                    - 'enable'
            user_id:
                aliases: ['user-id']
                type: str
                description: User ID.
            username:
                type: str
                description: Username of the remote SDN connector as login credentials.
            vmx_image_url:
                aliases: ['vmx-image-url']
                type: str
                description: URL of web-hosted VMX image.
            vmx_service_name:
                aliases: ['vmx-service-name']
                type: str
                description: VMX Service name.
            vpc_id:
                aliases: ['vpc-id']
                type: str
                description: AWS VPC ID.
            domain:
                type: str
                description: Openstack domain.
            ha_status:
                aliases: ['ha-status']
                type: str
                description: Enable/disable use for FortiGate HA service.
                choices:
                    - 'disable'
                    - 'enable'
            last_update:
                aliases: ['last-update']
                type: int
                description: Last update.
            oci_region_type:
                aliases: ['oci-region-type']
                type: str
                description: OCI region type.
                choices:
                    - 'commercial'
                    - 'government'
            secret_token:
                aliases: ['secret-token']
                type: str
                description: Secret token of Kubernetes service account.
            updating:
                type: int
                description: Updating.
            server_ip:
                aliases: ['server-ip']
                type: str
                description: IP address of the remote SDN connector.
            group_name:
                aliases: ['group-name']
                type: str
                description: Group name of computers.
            api_key:
                aliases: ['api-key']
                type: raw
                description: (list) IBM cloud API key or service ID API key.
            compute_generation:
                aliases: ['compute-generation']
                type: int
                description: Compute generation for IBM cloud infrastructure.
            ibm_region:
                aliases: ['ibm-region']
                type: str
                description: IBM cloud region name.
                choices:
                    - 'us-south'
                    - 'us-east'
                    - 'germany'
                    - 'great-britain'
                    - 'japan'
                    - 'australia'
                    - 'dallas'
                    - 'washington-dc'
                    - 'london'
                    - 'frankfurt'
                    - 'sydney'
                    - 'tokyo'
                    - 'osaka'
                    - 'toronto'
                    - 'sao-paulo'
                    - 'dallas-private'
                    - 'washington-dc-private'
                    - 'london-private'
                    - 'frankfurt-private'
                    - 'sydney-private'
                    - 'tokyo-private'
                    - 'osaka-private'
                    - 'toronto-private'
                    - 'sao-paulo-private'
                    - 'madrid'
                    - 'madrid-private'
            ibm_region_gen1:
                aliases: ['ibm-region-gen1']
                type: str
                description: Ibm region gen1.
                choices:
                    - 'us-south'
                    - 'us-east'
                    - 'germany'
                    - 'great-britain'
                    - 'japan'
                    - 'australia'
            ibm_region_gen2:
                aliases: ['ibm-region-gen2']
                type: str
                description: Ibm region gen2.
                choices:
                    - 'us-south'
                    - 'us-east'
                    - 'great-britain'
            vcenter_password:
                aliases: ['vcenter-password']
                type: raw
                description: (list) VCenter server password for NSX quarantine.
            vcenter_server:
                aliases: ['vcenter-server']
                type: str
                description: VCenter server address for NSX quarantine.
            vcenter_username:
                aliases: ['vcenter-username']
                type: str
                description: VCenter server username for NSX quarantine.
            server_list:
                aliases: ['server-list']
                type: raw
                description: (list) Server address list of the remote SDN connector.
            external_account_list:
                aliases: ['external-account-list']
                type: list
                elements: dict
                description: External account list.
                suboptions:
                    region_list:
                        aliases: ['region-list']
                        type: raw
                        description: (list) AWS region name list.
                    role_arn:
                        aliases: ['role-arn']
                        type: str
                        description: AWS role ARN to assume.
                    external_id:
                        aliases: ['external-id']
                        type: str
                        description: AWS external ID.
            forwarding_rule:
                aliases: ['forwarding-rule']
                type: list
                elements: dict
                description: Forwarding rule.
                suboptions:
                    rule_name:
                        aliases: ['rule-name']
                        type: str
                        description: Forwarding rule name.
                    target:
                        type: str
                        description: Target instance name.
            gcp_project_list:
                aliases: ['gcp-project-list']
                type: list
                elements: dict
                description: Gcp project list.
                suboptions:
                    gcp_zone_list:
                        aliases: ['gcp-zone-list']
                        type: raw
                        description: (list) Configure GCP zone list.
                    id:
                        type: str
                        description: GCP project ID.
            verify_certificate:
                aliases: ['verify-certificate']
                type: str
                description: Enable/disable server certificate verification.
                choices:
                    - 'disable'
                    - 'enable'
            alt_resource_ip:
                aliases: ['alt-resource-ip']
                type: str
                description: Enable/disable AWS alternative resource IP.
                choices:
                    - 'disable'
                    - 'enable'
            server_ca_cert:
                aliases: ['server-ca-cert']
                type: str
                description: Trust only those servers whose certificate is directly/indirectly signed by this certificate.
            server_cert:
                aliases: ['server-cert']
                type: str
                description: Trust servers that contain this certificate only.
            compartment_list:
                aliases: ['compartment-list']
                type: list
                elements: dict
                description: Compartment list.
                suboptions:
                    compartment_id:
                        aliases: ['compartment-id']
                        type: str
                        description: OCI compartment ID.
            oci_region_list:
                aliases: ['oci-region-list']
                type: list
                elements: dict
                description: Oci region list.
                suboptions:
                    region:
                        type: str
                        description: OCI region.
            proxy:
                type: str
                description: SDN proxy.
            message_server_port:
                aliases: ['message-server-port']
                type: int
                description: HTTP port number of the SAP message server.
            microsoft_365:
                aliases: ['microsoft-365']
                type: str
                description: Enable to use as Microsoft 365 connector.
                choices:
                    - 'disable'
                    - 'enable'
            vdom:
                type: raw
                description: (list) Virtual domain name of the remote SDN connector.
'''

EXAMPLES = '''
- name: Example playbook
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Configure connection to SDN Connector.
      fortinet.fortimanager.fmgr_system_sdnconnector:
        bypass_validation: false
        adom: ansible
        state: present
        system_sdnconnector:
          azure_region: global # <value in [global, china, germany, ...]>
          # compartment_id: 1
          name: ansible-test-sdn
          password: fortinet
          server: ALL
          status: disable
          type: aws # <value in [aci, aws, nsx, ...]>

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the connections to SDN Connector
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "system_sdnconnector"
          params:
            adom: "ansible"
            sdn_connector: "your_value"
'''

RETURN = '''
meta:
    description: The result of the request.
    type: dict
    returned: always
    contains:
        request_url:
            description: The full url requested.
            returned: always
            type: str
            sample: /sys/login/user
        response_code:
            description: The status of api request.
            returned: always
            type: int
            sample: 0
        response_data:
            description: The api response.
            type: list
            returned: always
        response_message:
            description: The descriptive message of the api response.
            type: str
            returned: always
            sample: OK.
        system_information:
            description: The information of the target system.
            type: dict
            returned: always
rc:
    description: The status the request.
    type: int
    returned: always
    sample: 0
version_check_warning:
    description: Warning if the parameters used in the playbook are not supported by the current FortiManager version.
    type: list
    returned: complex
'''
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import NAPIManager, check_galaxy_version, check_parameter_bypass
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import get_module_arg_spec


def main():
    urls_list = [
        '/pm/config/adom/{adom}/obj/system/sdn-connector',
        '/pm/config/global/obj/system/sdn-connector'
    ]
    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'system_sdnconnector': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                '_local_cert': {'type': 'str'},
                'access-key': {'no_log': True, 'type': 'str'},
                'azure-region': {'choices': ['global', 'china', 'germany', 'usgov', 'local'], 'type': 'str'},
                'client-id': {'type': 'str'},
                'client-secret': {'no_log': True, 'type': 'raw'},
                'compartment-id': {'type': 'str'},
                'external-ip': {'type': 'list', 'options': {'name': {'type': 'str'}}, 'elements': 'dict'},
                'gcp-project': {'type': 'str'},
                'key-passwd': {'no_log': True, 'type': 'raw'},
                'login-endpoint': {'type': 'str'},
                'name': {'required': True, 'type': 'str'},
                'nic': {
                    'type': 'list',
                    'options': {
                        'ip': {
                            'type': 'list',
                            'options': {
                                'name': {'type': 'str'},
                                'public-ip': {'type': 'str'},
                                'resource-group': {'v_range': [['6.2.3', '']], 'type': 'str'},
                                'private-ip': {'v_range': [['7.4.4', '7.4.7'], ['7.6.2', '']], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'name': {'type': 'str'},
                        'peer-nic': {'v_range': [['7.4.4', '7.4.7'], ['7.6.2', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'nsx-cert-fingerprint': {'type': 'str'},
                'oci-cert': {'type': 'str'},
                'oci-fingerprint': {'type': 'str'},
                'oci-region': {'choices': ['phoenix', 'ashburn', 'frankfurt', 'london', 'toronto'], 'type': 'str'},
                'password': {'no_log': True, 'type': 'raw'},
                'private-key': {'no_log': True, 'type': 'str'},
                'region': {'type': 'str'},
                'resource-group': {'type': 'str'},
                'resource-url': {'type': 'str'},
                'rest-interface': {'choices': ['mgmt', 'sync'], 'type': 'str'},
                'rest-password': {'no_log': True, 'type': 'raw'},
                'rest-sport': {'type': 'int'},
                'rest-ssl': {'choices': ['disable', 'enable'], 'type': 'str'},
                'route': {'type': 'list', 'options': {'name': {'type': 'str'}}, 'elements': 'dict'},
                'route-table': {
                    'type': 'list',
                    'options': {
                        'name': {'type': 'str'},
                        'route': {'type': 'list', 'options': {'name': {'type': 'str'}, 'next-hop': {'type': 'str'}}, 'elements': 'dict'},
                        'resource-group': {'v_range': [['6.2.3', '']], 'type': 'str'},
                        'subscription-id': {'v_range': [['6.2.6', '6.2.13'], ['6.4.1', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'secret-key': {'no_log': True, 'type': 'raw'},
                'server': {'type': 'str'},
                'server-port': {'type': 'int'},
                'service-account': {'type': 'str'},
                'status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'subscription-id': {'type': 'str'},
                'tenant-id': {'type': 'str'},
                'type': {
                    'choices': [
                        'aci', 'aws', 'nsx', 'nuage', 'azure', 'gcp', 'oci', 'openstack', 'kubernetes', 'vmware', 'acs', 'alicloud', 'sepm',
                        'aci-direct', 'ibm', 'nutanix', 'sap'
                    ],
                    'type': 'str'
                },
                'update-interval': {'type': 'int'},
                'use-metadata-iam': {'choices': ['disable', 'enable'], 'type': 'str'},
                'user-id': {'type': 'str'},
                'username': {'type': 'str'},
                'vmx-image-url': {'type': 'str'},
                'vmx-service-name': {'type': 'str'},
                'vpc-id': {'type': 'str'},
                'domain': {'v_range': [['6.2.0', '']], 'type': 'str'},
                'ha-status': {'v_range': [['6.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'last-update': {'v_range': [['6.2.1', '7.2.0']], 'type': 'int'},
                'oci-region-type': {'v_range': [['6.2.1', '']], 'choices': ['commercial', 'government'], 'type': 'str'},
                'secret-token': {'v_range': [['6.2.0', '']], 'no_log': True, 'type': 'str'},
                'updating': {'v_range': [['6.2.1', '7.2.0']], 'type': 'int'},
                'server-ip': {'v_range': [['6.2.0', '6.4.15']], 'type': 'str'},
                'group-name': {'v_range': [['6.2.2', '']], 'type': 'str'},
                'api-key': {'v_range': [['6.4.1', '']], 'no_log': True, 'type': 'raw'},
                'compute-generation': {'v_range': [['6.4.1', '']], 'type': 'int'},
                'ibm-region': {
                    'v_range': [['6.4.2', '']],
                    'choices': [
                        'us-south', 'us-east', 'germany', 'great-britain', 'japan', 'australia', 'dallas', 'washington-dc', 'london', 'frankfurt',
                        'sydney', 'tokyo', 'osaka', 'toronto', 'sao-paulo', 'dallas-private', 'washington-dc-private', 'london-private',
                        'frankfurt-private', 'sydney-private', 'tokyo-private', 'osaka-private', 'toronto-private', 'sao-paulo-private', 'madrid',
                        'madrid-private'
                    ],
                    'type': 'str'
                },
                'ibm-region-gen1': {
                    'v_range': [['6.4.1', '']],
                    'choices': ['us-south', 'us-east', 'germany', 'great-britain', 'japan', 'australia'],
                    'type': 'str'
                },
                'ibm-region-gen2': {'v_range': [['6.4.1', '']], 'choices': ['us-south', 'us-east', 'great-britain'], 'type': 'str'},
                'vcenter-password': {'v_range': [['6.4.1', '']], 'no_log': True, 'type': 'raw'},
                'vcenter-server': {'v_range': [['6.4.1', '']], 'type': 'str'},
                'vcenter-username': {'v_range': [['6.4.1', '']], 'type': 'str'},
                'server-list': {'v_range': [['6.4.4', '']], 'type': 'raw'},
                'external-account-list': {
                    'v_range': [['7.0.3', '']],
                    'type': 'list',
                    'options': {
                        'region-list': {'v_range': [['7.0.3', '']], 'type': 'raw'},
                        'role-arn': {'v_range': [['7.0.3', '']], 'type': 'str'},
                        'external-id': {'v_range': [['7.0.5', '7.0.14'], ['7.2.1', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'forwarding-rule': {
                    'v_range': [['7.0.2', '']],
                    'type': 'list',
                    'options': {'rule-name': {'v_range': [['7.0.2', '']], 'type': 'str'}, 'target': {'v_range': [['7.0.2', '']], 'type': 'str'}},
                    'elements': 'dict'
                },
                'gcp-project-list': {
                    'v_range': [['6.4.7', '6.4.15'], ['7.0.2', '']],
                    'type': 'list',
                    'options': {
                        'gcp-zone-list': {'v_range': [['6.4.7', '6.4.15'], ['7.0.2', '']], 'type': 'raw'},
                        'id': {'v_range': [['6.4.7', '6.4.15'], ['7.0.2', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'verify-certificate': {'v_range': [['6.4.8', '6.4.15'], ['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'alt-resource-ip': {'v_range': [['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'server-ca-cert': {'v_range': [['7.2.2', '']], 'type': 'str'},
                'server-cert': {'v_range': [['7.2.2', '']], 'type': 'str'},
                'compartment-list': {
                    'v_range': [['7.4.0', '']],
                    'type': 'list',
                    'options': {'compartment-id': {'v_range': [['7.4.0', '']], 'type': 'str'}},
                    'elements': 'dict'
                },
                'oci-region-list': {
                    'v_range': [['7.4.0', '']],
                    'type': 'list',
                    'options': {'region': {'v_range': [['7.4.0', '']], 'type': 'str'}},
                    'elements': 'dict'
                },
                'proxy': {'v_range': [['7.4.0', '']], 'type': 'str'},
                'message-server-port': {'v_range': [['7.6.2', '']], 'type': 'int'},
                'microsoft-365': {'v_range': [['7.6.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'vdom': {'v_range': [['7.6.3', '']], 'type': 'raw'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_sdnconnector'),
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list, module_primary_key, url_params,
                       module, connection, top_level_schema_name='data')
    fmgr.validate_parameters(params_validation_blob)
    fmgr.process_crud()

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
