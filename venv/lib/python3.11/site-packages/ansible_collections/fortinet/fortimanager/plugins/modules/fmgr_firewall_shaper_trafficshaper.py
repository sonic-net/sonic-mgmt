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
module: fmgr_firewall_shaper_trafficshaper
short_description: Configure shared traffic shaper.
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
    firewall_shaper_trafficshaper:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            bandwidth_unit:
                aliases: ['bandwidth-unit']
                type: str
                description: Unit of measurement for guaranteed and maximum bandwidth for this shaper
                choices:
                    - 'kbps'
                    - 'mbps'
                    - 'gbps'
            diffserv:
                type: str
                description: Enable/disable changing the DiffServ setting applied to traffic accepted by this shaper.
                choices:
                    - 'disable'
                    - 'enable'
            diffservcode:
                type: str
                description: DiffServ setting to be applied to traffic accepted by this shaper.
            guaranteed_bandwidth:
                aliases: ['guaranteed-bandwidth']
                type: int
                description: Amount of bandwidth guaranteed for this shaper
            maximum_bandwidth:
                aliases: ['maximum-bandwidth']
                type: int
                description: Upper bandwidth limit enforced by this shaper
            name:
                type: str
                description: Traffic shaper name.
                required: true
            per_policy:
                aliases: ['per-policy']
                type: str
                description: Enable/disable applying a separate shaper for each policy.
                choices:
                    - 'disable'
                    - 'enable'
            priority:
                type: str
                description: Higher priority traffic is more likely to be forwarded without delays and without compromising the guaranteed bandwidth.
                choices:
                    - 'high'
                    - 'medium'
                    - 'low'
            dscp_marking_method:
                aliases: ['dscp-marking-method']
                type: str
                description: Select DSCP marking method.
                choices:
                    - 'multi-stage'
                    - 'static'
            exceed_bandwidth:
                aliases: ['exceed-bandwidth']
                type: int
                description: Exceed bandwidth used for DSCP multi-stage marking.
            exceed_class_id:
                aliases: ['exceed-class-id']
                type: int
                description: Class ID for traffic in [guaranteed-bandwidth, maximum-bandwidth].
            exceed_dscp:
                aliases: ['exceed-dscp']
                type: str
                description: DSCP mark for traffic in [guaranteed-bandwidth, exceed-bandwidth].
            maximum_dscp:
                aliases: ['maximum-dscp']
                type: str
                description: DSCP mark for traffic in [exceed-bandwidth, maximum-bandwidth].
            overhead:
                type: int
                description: Per-packet size overhead used in rate computations.
            cos:
                type: str
                description: VLAN CoS mark.
            cos_marking:
                aliases: ['cos-marking']
                type: str
                description: Enable/disable VLAN CoS marking.
                choices:
                    - 'disable'
                    - 'enable'
            cos_marking_method:
                aliases: ['cos-marking-method']
                type: str
                description: Select VLAN CoS marking method.
                choices:
                    - 'multi-stage'
                    - 'static'
            exceed_cos:
                aliases: ['exceed-cos']
                type: str
                description: VLAN CoS mark for traffic in [guaranteed-bandwidth, exceed-bandwidth].
            maximum_cos:
                aliases: ['maximum-cos']
                type: str
                description: VLAN CoS mark for traffic in [exceed-bandwidth, maximum-bandwidth].
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
    - name: Configure shared traffic shaper.
      fortinet.fortimanager.fmgr_firewall_shaper_trafficshaper:
        bypass_validation: false
        adom: ansible
        state: present
        firewall_shaper_trafficshaper:
          bandwidth_unit: mbps # <value in [kbps, mbps, gbps]>
          diffserv: disable
          name: "ansible"
          per_policy: disable
          priority: medium # <value in [high, medium, low]>

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the shared traffic shapers
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "firewall_shaper_trafficshaper"
          params:
            adom: "ansible"
            traffic_shaper: "your_value"
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
        '/pm/config/adom/{adom}/obj/firewall/shaper/traffic-shaper',
        '/pm/config/global/obj/firewall/shaper/traffic-shaper'
    ]
    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'firewall_shaper_trafficshaper': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'bandwidth-unit': {'choices': ['kbps', 'mbps', 'gbps'], 'type': 'str'},
                'diffserv': {'choices': ['disable', 'enable'], 'type': 'str'},
                'diffservcode': {'type': 'str'},
                'guaranteed-bandwidth': {'type': 'int'},
                'maximum-bandwidth': {'type': 'int'},
                'name': {'required': True, 'type': 'str'},
                'per-policy': {'choices': ['disable', 'enable'], 'type': 'str'},
                'priority': {'choices': ['high', 'medium', 'low'], 'type': 'str'},
                'dscp-marking-method': {'v_range': [['6.2.1', '']], 'choices': ['multi-stage', 'static'], 'type': 'str'},
                'exceed-bandwidth': {'v_range': [['6.2.1', '']], 'type': 'int'},
                'exceed-class-id': {'v_range': [['6.2.1', '']], 'type': 'int'},
                'exceed-dscp': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'maximum-dscp': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'overhead': {'v_range': [['6.2.1', '']], 'type': 'int'},
                'cos': {'v_range': [['7.4.0', '']], 'type': 'str'},
                'cos-marking': {'v_range': [['7.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cos-marking-method': {'v_range': [['7.4.0', '']], 'choices': ['multi-stage', 'static'], 'type': 'str'},
                'exceed-cos': {'v_range': [['7.4.0', '']], 'type': 'str'},
                'maximum-cos': {'v_range': [['7.4.0', '']], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_shaper_trafficshaper'),
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
