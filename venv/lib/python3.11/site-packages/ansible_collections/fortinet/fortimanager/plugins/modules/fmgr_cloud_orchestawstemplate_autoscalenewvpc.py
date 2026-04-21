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
module: fmgr_cloud_orchestawstemplate_autoscalenewvpc
short_description: Cloud orchest awstemplate autoscale new vpc
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.2.0"
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
    cloud_orchestawstemplate_autoscalenewvpc:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            availability_zones:
                aliases: ['availability-zones']
                type: str
                description: Availability zones.
            custom_asset_container:
                aliases: ['custom-asset-container']
                type: str
                description: Custom asset container.
            custom_asset_directory:
                aliases: ['custom-asset-directory']
                type: str
                description: Custom asset directory.
            custom_identifier:
                aliases: ['custom-identifier']
                type: str
                description: Custom identifier.
            faz_autoscale_admin_password:
                aliases: ['faz-autoscale-admin-password']
                type: raw
                description: (list) Faz autoscale admin password.
            faz_autoscale_admin_username:
                aliases: ['faz-autoscale-admin-username']
                type: str
                description: Faz autoscale admin username.
            faz_custom_private_ipaddress:
                aliases: ['faz-custom-private-ipaddress']
                type: str
                description: Faz custom private ipaddress.
            faz_instance_type:
                aliases: ['faz-instance-type']
                type: str
                description: Faz instance type.
                choices:
                    - 'h1.2xlarge'
                    - 'h1.4xlarge'
                    - 'h1.8xlarge'
                    - 'm5.large'
                    - 'm5.xlarge'
                    - 'm5.2xlarge'
                    - 'm5.4xlarge'
                    - 'm5.12xlarge'
                    - 't2.medium'
                    - 't2.large'
                    - 't2.xlarge'
            faz_integration_options:
                aliases: ['faz-integration-options']
                type: str
                description: Faz integration options.
                choices:
                    - 'no'
                    - 'yes'
            faz_version:
                aliases: ['faz-version']
                type: str
                description: Faz version.
            fgt_admin_cidr:
                aliases: ['fgt-admin-cidr']
                type: str
                description: Fgt admin cidr.
            fgt_admin_port:
                aliases: ['fgt-admin-port']
                type: int
                description: Fgt admin port.
            fgt_instance_type:
                aliases: ['fgt-instance-type']
                type: str
                description: Fgt instance type.
                choices:
                    - 't2.small'
                    - 'c5.large'
                    - 'c5.xlarge'
                    - 'c5.2xlarge'
                    - 'c5.4xlarge'
                    - 'c5.9xlarge'
            fgt_psk_secret:
                aliases: ['fgt-psk-secret']
                type: str
                description: Fgt psk secret.
            fgtasg_cool_down:
                aliases: ['fgtasg-cool-down']
                type: int
                description: Fgtasg cool down.
            fgtasg_desired_capacity_byol:
                aliases: ['fgtasg-desired-capacity-byol']
                type: int
                description: Fgtasg desired capacity byol.
            fgtasg_desired_capacity_payg:
                aliases: ['fgtasg-desired-capacity-payg']
                type: int
                description: Fgtasg desired capacity payg.
            fgtasg_health_check_grace_period:
                aliases: ['fgtasg-health-check-grace-period']
                type: int
                description: Fgtasg health check grace period.
            fgtasg_max_size_byol:
                aliases: ['fgtasg-max-size-byol']
                type: int
                description: Fgtasg max size byol.
            fgtasg_max_size_payg:
                aliases: ['fgtasg-max-size-payg']
                type: int
                description: Fgtasg max size payg.
            fgtasg_min_size_byol:
                aliases: ['fgtasg-min-size-byol']
                type: int
                description: Fgtasg min size byol.
            fgtasg_min_size_payg:
                aliases: ['fgtasg-min-size-payg']
                type: int
                description: Fgtasg min size payg.
            fgtasg_scale_in_threshold:
                aliases: ['fgtasg-scale-in-threshold']
                type: int
                description: Fgtasg scale in threshold.
            fgtasg_scale_out_threshold:
                aliases: ['fgtasg-scale-out-threshold']
                type: int
                description: Fgtasg scale out threshold.
            fos_version:
                aliases: ['fos-version']
                type: str
                description: Fos version.
            get_license_grace_period:
                aliases: ['get-license-grace-period']
                type: int
                description: Get license grace period.
            heartbeat_delay_allowance:
                aliases: ['heartbeat-delay-allowance']
                type: int
                description: Heartbeat delay allowance.
            heartbeat_interval:
                aliases: ['heartbeat-interval']
                type: int
                description: Heartbeat interval.
            heartbeat_loss_count:
                aliases: ['heartbeat-loss-count']
                type: int
                description: Heartbeat loss count.
            internal_balancer_dns_name:
                aliases: ['internal-balancer-dns-name']
                type: str
                description: Internal balancer dns name.
            internal_balancing_options:
                aliases: ['internal-balancing-options']
                type: str
                description: Internal balancing options.
                choices:
                    - 'add a new internal load balancer'
                    - 'use a load balancer specified below'
                    - 'do not need one'
            internal_target_group_health_check_path:
                aliases: ['internal-target-group-health-check-path']
                type: str
                description: Internal target group health check path.
            key_pair_name:
                aliases: ['key-pair-name']
                type: str
                description: Key pair name.
            lifecycle_hook_timeout:
                aliases: ['lifecycle-hook-timeout']
                type: int
                description: Lifecycle hook timeout.
            loadbalancing_health_check_threshold:
                aliases: ['loadbalancing-health-check-threshold']
                type: int
                description: Loadbalancing health check threshold.
            loadbalancing_traffic_port:
                aliases: ['loadbalancing-traffic-port']
                type: int
                description: Loadbalancing traffic port.
            loadbalancing_traffic_protocol:
                aliases: ['loadbalancing-traffic-protocol']
                type: str
                description: Loadbalancing traffic protocol.
                choices:
                    - 'HTTPS'
                    - 'HTTP'
                    - 'TCP'
            name:
                type: str
                description: Name.
                required: true
            notification_email:
                aliases: ['notification-email']
                type: str
                description: Notification email.
            primary_election_timeout:
                aliases: ['primary-election-timeout']
                type: int
                description: Primary election timeout.
            private_subnet1_cidr:
                aliases: ['private-subnet1-cidr']
                type: str
                description: Private subnet1 cidr.
            private_subnet2_cidr:
                aliases: ['private-subnet2-cidr']
                type: str
                description: Private subnet2 cidr.
            public_subnet1_cidr:
                aliases: ['public-subnet1-cidr']
                type: str
                description: Public subnet1 cidr.
            public_subnet2_cidr:
                aliases: ['public-subnet2-cidr']
                type: str
                description: Public subnet2 cidr.
            resource_tag_prefix:
                aliases: ['resource-tag-prefix']
                type: str
                description: Resource tag prefix.
            s3_bucket_name:
                aliases: ['s3-bucket-name']
                type: str
                description: S3 bucket name.
            s3_key_prefix:
                aliases: ['s3-key-prefix']
                type: str
                description: S3 key prefix.
            sync_recovery_count:
                aliases: ['sync-recovery-count']
                type: int
                description: Sync recovery count.
            terminate_unhealthy_vm:
                aliases: ['terminate-unhealthy-vm']
                type: str
                description: Terminate unhealthy vm.
                choices:
                    - 'no'
                    - 'yes'
            use_custom_asset_location:
                aliases: ['use-custom-asset-location']
                type: str
                description: Use custom asset location.
                choices:
                    - 'no'
                    - 'yes'
            vpc_cidr:
                aliases: ['vpc-cidr']
                type: str
                description: Vpc cidr.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Cloud orchest awstemplate autoscale new vpc
      fortinet.fortimanager.fmgr_cloud_orchestawstemplate_autoscalenewvpc:
        # bypass_validation: false
        # workspace_locking_adom: <global or your adom name>
        # workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: present # <value in [present, absent]>
        cloud_orchestawstemplate_autoscalenewvpc:
          name: "your value" # Required variable, string
          # availability_zones: <string>
          # custom_asset_container: <string>
          # custom_asset_directory: <string>
          # custom_identifier: <string>
          # faz_autoscale_admin_password: <list or string>
          # faz_autoscale_admin_username: <string>
          # faz_custom_private_ipaddress: <string>
          # faz_instance_type: <value in [h1.2xlarge, h1.4xlarge, h1.8xlarge, ...]>
          # faz_integration_options: <value in [no, yes]>
          # faz_version: <string>
          # fgt_admin_cidr: <string>
          # fgt_admin_port: <integer>
          # fgt_instance_type: <value in [t2.small, c5.large, c5.xlarge, ...]>
          # fgt_psk_secret: <string>
          # fgtasg_cool_down: <integer>
          # fgtasg_desired_capacity_byol: <integer>
          # fgtasg_desired_capacity_payg: <integer>
          # fgtasg_health_check_grace_period: <integer>
          # fgtasg_max_size_byol: <integer>
          # fgtasg_max_size_payg: <integer>
          # fgtasg_min_size_byol: <integer>
          # fgtasg_min_size_payg: <integer>
          # fgtasg_scale_in_threshold: <integer>
          # fgtasg_scale_out_threshold: <integer>
          # fos_version: <string>
          # get_license_grace_period: <integer>
          # heartbeat_delay_allowance: <integer>
          # heartbeat_interval: <integer>
          # heartbeat_loss_count: <integer>
          # internal_balancer_dns_name: <string>
          # internal_balancing_options: <value in [add a new internal load balancer, use a load balancer specified below, do not need one]>
          # internal_target_group_health_check_path: <string>
          # key_pair_name: <string>
          # lifecycle_hook_timeout: <integer>
          # loadbalancing_health_check_threshold: <integer>
          # loadbalancing_traffic_port: <integer>
          # loadbalancing_traffic_protocol: <value in [HTTPS, HTTP, TCP]>
          # notification_email: <string>
          # primary_election_timeout: <integer>
          # private_subnet1_cidr: <string>
          # private_subnet2_cidr: <string>
          # public_subnet1_cidr: <string>
          # public_subnet2_cidr: <string>
          # resource_tag_prefix: <string>
          # s3_bucket_name: <string>
          # s3_key_prefix: <string>
          # sync_recovery_count: <integer>
          # terminate_unhealthy_vm: <value in [no, yes]>
          # use_custom_asset_location: <value in [no, yes]>
          # vpc_cidr: <string>
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
        '/pm/config/adom/{adom}/obj/cloud/orchest-awstemplate/autoscale-new-vpc',
        '/pm/config/global/obj/cloud/orchest-awstemplate/autoscale-new-vpc'
    ]
    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'cloud_orchestawstemplate_autoscalenewvpc': {
            'type': 'dict',
            'v_range': [['7.4.0', '']],
            'options': {
                'availability-zones': {'v_range': [['7.4.0', '']], 'type': 'str'},
                'custom-asset-container': {'v_range': [['7.4.0', '']], 'type': 'str'},
                'custom-asset-directory': {'v_range': [['7.4.0', '']], 'type': 'str'},
                'custom-identifier': {'v_range': [['7.4.0', '']], 'type': 'str'},
                'faz-autoscale-admin-password': {'v_range': [['7.4.0', '']], 'no_log': True, 'type': 'raw'},
                'faz-autoscale-admin-username': {'v_range': [['7.4.0', '']], 'type': 'str'},
                'faz-custom-private-ipaddress': {'v_range': [['7.4.0', '']], 'type': 'str'},
                'faz-instance-type': {
                    'v_range': [['7.4.0', '']],
                    'choices': [
                        'h1.2xlarge', 'h1.4xlarge', 'h1.8xlarge', 'm5.large', 'm5.xlarge', 'm5.2xlarge', 'm5.4xlarge', 'm5.12xlarge', 't2.medium',
                        't2.large', 't2.xlarge'
                    ],
                    'type': 'str'
                },
                'faz-integration-options': {'v_range': [['7.4.0', '']], 'choices': ['no', 'yes'], 'type': 'str'},
                'faz-version': {'v_range': [['7.4.0', '']], 'type': 'str'},
                'fgt-admin-cidr': {'v_range': [['7.4.0', '']], 'type': 'str'},
                'fgt-admin-port': {'v_range': [['7.4.0', '']], 'type': 'int'},
                'fgt-instance-type': {
                    'v_range': [['7.4.0', '']],
                    'choices': ['t2.small', 'c5.large', 'c5.xlarge', 'c5.2xlarge', 'c5.4xlarge', 'c5.9xlarge'],
                    'type': 'str'
                },
                'fgt-psk-secret': {'v_range': [['7.4.0', '']], 'no_log': True, 'type': 'str'},
                'fgtasg-cool-down': {'v_range': [['7.4.0', '']], 'type': 'int'},
                'fgtasg-desired-capacity-byol': {'v_range': [['7.4.0', '']], 'type': 'int'},
                'fgtasg-desired-capacity-payg': {'v_range': [['7.4.0', '']], 'type': 'int'},
                'fgtasg-health-check-grace-period': {'v_range': [['7.4.0', '']], 'type': 'int'},
                'fgtasg-max-size-byol': {'v_range': [['7.4.0', '']], 'type': 'int'},
                'fgtasg-max-size-payg': {'v_range': [['7.4.0', '']], 'type': 'int'},
                'fgtasg-min-size-byol': {'v_range': [['7.4.0', '']], 'type': 'int'},
                'fgtasg-min-size-payg': {'v_range': [['7.4.0', '']], 'type': 'int'},
                'fgtasg-scale-in-threshold': {'v_range': [['7.4.0', '']], 'type': 'int'},
                'fgtasg-scale-out-threshold': {'v_range': [['7.4.0', '']], 'type': 'int'},
                'fos-version': {'v_range': [['7.4.0', '']], 'type': 'str'},
                'get-license-grace-period': {'v_range': [['7.4.0', '']], 'type': 'int'},
                'heartbeat-delay-allowance': {'v_range': [['7.4.0', '']], 'type': 'int'},
                'heartbeat-interval': {'v_range': [['7.4.0', '']], 'type': 'int'},
                'heartbeat-loss-count': {'v_range': [['7.4.0', '']], 'type': 'int'},
                'internal-balancer-dns-name': {'v_range': [['7.4.0', '']], 'type': 'str'},
                'internal-balancing-options': {
                    'v_range': [['7.4.0', '']],
                    'choices': ['add a new internal load balancer', 'use a load balancer specified below', 'do not need one'],
                    'type': 'str'
                },
                'internal-target-group-health-check-path': {'v_range': [['7.4.0', '']], 'type': 'str'},
                'key-pair-name': {'v_range': [['7.4.0', '']], 'no_log': True, 'type': 'str'},
                'lifecycle-hook-timeout': {'v_range': [['7.4.0', '']], 'type': 'int'},
                'loadbalancing-health-check-threshold': {'v_range': [['7.4.0', '']], 'type': 'int'},
                'loadbalancing-traffic-port': {'v_range': [['7.4.0', '']], 'type': 'int'},
                'loadbalancing-traffic-protocol': {'v_range': [['7.4.0', '']], 'choices': ['HTTPS', 'HTTP', 'TCP'], 'type': 'str'},
                'name': {'v_range': [['7.4.0', '']], 'required': True, 'type': 'str'},
                'notification-email': {'v_range': [['7.4.0', '']], 'type': 'str'},
                'primary-election-timeout': {'v_range': [['7.4.0', '']], 'type': 'int'},
                'private-subnet1-cidr': {'v_range': [['7.4.0', '']], 'type': 'str'},
                'private-subnet2-cidr': {'v_range': [['7.4.0', '']], 'type': 'str'},
                'public-subnet1-cidr': {'v_range': [['7.4.0', '']], 'type': 'str'},
                'public-subnet2-cidr': {'v_range': [['7.4.0', '']], 'type': 'str'},
                'resource-tag-prefix': {'v_range': [['7.4.0', '']], 'type': 'str'},
                's3-bucket-name': {'v_range': [['7.4.0', '']], 'type': 'str'},
                's3-key-prefix': {'v_range': [['7.4.0', '']], 'no_log': True, 'type': 'str'},
                'sync-recovery-count': {'v_range': [['7.4.0', '']], 'type': 'int'},
                'terminate-unhealthy-vm': {'v_range': [['7.4.0', '']], 'choices': ['no', 'yes'], 'type': 'str'},
                'use-custom-asset-location': {'v_range': [['7.4.0', '']], 'choices': ['no', 'yes'], 'type': 'str'},
                'vpc-cidr': {'v_range': [['7.4.0', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'cloud_orchestawstemplate_autoscalenewvpc'),
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
